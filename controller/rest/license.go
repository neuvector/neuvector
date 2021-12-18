package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/licenseinfo"
	"github.com/neuvector/neuvector/share/utils"
)

func validateLicenseReq(req *api.RESTLicenseRequest) error {
	/* Todo: more input validation */
	if req.Email == "" {
		return fmt.Errorf("Missing required field")
	}
	return nil
}

func reqLicense(req *api.RESTLicenseRequest) string {
	log.WithFields(log.Fields{"req": req}).Debug()

	info := &api.RESTLicenseInfo{
		Name:  req.Name,
		Email: req.Email,
		Phone: req.Phone,
		ID:    localDev.Host.ID,
	}

	val, _ := json.Marshal(info)
	if ret, err := licenseinfo.EncryptToBase64(utils.GetLicenseSymKey(), val); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("encrypt error")
		return ""
	} else {
		return ret
	}
}

func handlerLicenseShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	reply := &api.RESTLicenseShowData{}
	curLicense := cacher.GetCurrentLicense(acc)
	reply.License = &api.RESTLicenseShow{
		Info: &curLicense,
	}
	restRespSuccess(w, r, reply, acc, login, nil, "Get license code")
}

func updateLicense(license string, init, checkCurrent bool) (*api.RESTLicenseInfo, error) {
	if checkCurrent {
		if cur, err := cluster.Get(share.CLUSConfigLicenseKey); err == nil {
			if string(cur) == license {
				return nil, fmt.Errorf("License is already applied")
			}
		}
	}
	val, err := utils.GetLicenseInfo(license)
	if err != nil {
		return nil, err
	}

	var info api.RESTLicenseInfo
	if json.Unmarshal([]byte(val), &info) != nil {
		return nil, fmt.Errorf("Invalid license format")
	}

	if !common.OEMLicenseValidate(&info) {
		return nil, fmt.Errorf("Invalid OEM license")
	}

	if err := cluster.Put(share.CLUSConfigLicenseKey, []byte(license)); err != nil {
		return nil, fmt.Errorf("License store error")
	}
	return &info, nil
}

func handlerLicenseUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !acc.Authorize(&api.RESTLicenseInfo{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	var req api.RESTLicenseKey
	err := json.Unmarshal(body, &req)
	if err != nil || req.LicenseKey == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	newInfo, err := updateLicense(req.LicenseKey, false, true)
	if newInfo == nil || err != nil {
		log.WithFields(log.Fields{"err": err}).Error("License update failed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
	} else {
		newInfo.ID = ""
		newInfo.IDType = ""
		newInfo.InstallationID, _ = clusHelper.GetInstallationID()
		reply := &api.RESTLicenseShowData{License: &api.RESTLicenseShow{
			Info: newInfo,
		}}
		restRespSuccess(w, r, reply, acc, login, &req, "Update license")
	}
}

func handlerLicenseDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !acc.Authorize(&api.RESTLicenseInfo{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if cur, err := cluster.Get(share.CLUSConfigLicenseKey); err == nil && len(cur) == 0 {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"No license to delete")
		return
	}

	if err := cluster.Put(share.CLUSConfigLicenseKey, []byte("")); err != nil {
		log.Error("cluster error")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"Fail to delete old license")
	} else {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete license")
	}
}

func licenseAllowScan() bool {
	return true
}

func licenseAllowEnforce() bool {
	return true
}

func licenseAllowFed(minLic int) bool {
	return true
}

func licenseInit() {
}
