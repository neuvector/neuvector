package rest

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
)

type tCspAdapterErrors struct {
	CspErrors      []string `json:"csp_errors,omitempty"`
	NvError        *string  `json:"nv_error,omitempty"`
	DataExpireTime *int64   `json:"billing_data_expire_time,omitempty"` // in seconds
}

func handlerCspSupportExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}

	var notSupported string = "No support package available for download"

	// do not support on standalone cluster on no csp
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleNone {
		if nvUsage := cacher.GetNvUsage(fedRole); nvUsage.LocalClusterUsage.CspType == "" {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, notSupported)
			return
		}
	}

	var err error
	var nvUsageData []byte
	var resp api.RESTFedCspSupportResp

	accReadAll := access.NewReaderAccessControl()
	fedRole := cacher.GetFedMembershipRoleNoAuth()
	nvUsage := cacher.GetNvUsage(fedRole)
	if fedRole == api.FedRoleJoint {
		// request csp-config data from master cluster
		reqTo := api.RESTFedCspSupportReq{
			FedKvVersion: kv.GetFedKvVer(),
			RestVersion:  kv.GetRestVer(),
		}
		masterCluster := cacher.GetFedMasterCluster(accReadAll)
		jointCluster := cacher.GetFedLocalJointCluster(accReadAll)
		if masterCluster.ID == "" || jointCluster.ID == "" {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}

		reqTo.ID = jointCluster.ID
		reqTo.JointTicket = jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife)
		bodyTo, _ := json.Marshal(&reqTo)
		var data []byte
		urlStr := fmt.Sprintf("https://%s:%d/v1/fed/csp_support_internal", masterCluster.RestInfo.Server, masterCluster.RestInfo.Port)
		if data, _, _, err = sendRestRequest("", http.MethodPost, urlStr, "", "", "", "", nil, bodyTo, false, nil, accReadAll); err == nil {
			if err = json.Unmarshal(data, &resp); err == nil {
				resp.CspConfigFrom = "primary cluster"
			}
		} else {
			// master cluster is unreachable from this joint cluster
			resp = resource.GetCspConfig()
		}
	} else {
		resp = resource.GetCspConfig()
	}

	query := restParseQuery(r)
	if f, ok := query.pairs["data"]; ok && f == "adapter_versions" {
		restRespSuccess(w, r, &api.RESTCspAdapterInfo{AdapterVersions: resp.AdapterVersions}, acc, login, nil, "Get csp adapter versions")
		return
	}

	var cspAdapterErrors tCspAdapterErrors
	if len(resp.CspErrors) > 0 {
		cspAdapterErrors.CspErrors = resp.CspErrors
	}
	if resp.NvError != "" {
		cspAdapterErrors.NvError = &resp.NvError
	}
	if resp.ExpireTime != 0 {
		cspAdapterErrors.DataExpireTime = &resp.ExpireTime
	}
	if data, err := json.Marshal(&cspAdapterErrors); err == nil {
		errHeader := base64.StdEncoding.EncodeToString(data)
		w.Header().Set("X-Nv-Csp-Adapter-Errors", errHeader)
	}
	if err != nil || resp.CspConfigData == "" || resp.CspConfigData == "{}" {
		log.WithFields(log.Fields{"error": err, "cspConfig": resp.CspConfigData}).Error("no data")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, notSupported)
		return
	} else {
		nvUsage.CspConfigFrom = resp.CspConfigFrom
		nvUsageData, _ = json.MarshalIndent(&nvUsage, "", "    ")
	}

	type tFileContent struct {
		data     []byte
		filename string
	}
	fileContent := []*tFileContent{
		{
			data:     []byte(resp.CspConfigData),
			filename: "neuvector/cspSupportConfig.json",
		},
		{
			data:     nvUsageData,
			filename: "neuvector/neuvectorUsage.json",
		},
		{
			data:     []byte(resp.MeteringArchiveData),
			filename: "neuvector/csp_billing_adapter_metering_archive.json",
		},
	}
	w.Header().Set("Content-Disposition", "Attachment; filename=suse_supportconfig.tar.gz")
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)

	gzw := gzip.NewWriter(w)
	defer gzw.Close()

	tarw := tar.NewWriter(gzw)
	defer tarw.Close()

	now := time.Now()
	hdr := &tar.Header{
		Name:     "neuvector/",
		Mode:     int64(0744),
		Typeflag: tar.TypeDir,
		ModTime:  now,
	}
	if err = tarw.WriteHeader(hdr); err == nil {
		for _, f := range fileContent {
			hdr := &tar.Header{
				Name:     f.filename,
				Mode:     int64(0644),
				Size:     int64(len(f.data)),
				Typeflag: tar.TypeReg,
				ModTime:  now,
			}
			if err = tarw.WriteHeader(hdr); err == nil {
				_, err = tarw.Write(f.data)
			}
			if err != nil {
				log.WithFields(log.Fields{"name": f.filename, "error": err}).Error()
				break
			}
		}
	}
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailExport, err.Error())
	}
}

// func handlerHealthCheck(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
// 	defer r.Body.Close()

// 	restRespSuccess(w, r, nil, nil, nil, nil, "")
// }
