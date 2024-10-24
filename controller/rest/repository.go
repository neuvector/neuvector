package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

const (
	repositoryDefaultTag      = "latest"
	maxRepoScanTasks          = 32
	repoScanTimeout           = time.Minute * 20
	repoScanLingeringDuration = time.Second * 30
	repoScanLongPollTimeout   = time.Second * 30
)

var repoScanMgr *longpollOnceMgr

type repoScanKey struct {
	api.RESTScanRepoReq
	token string
}

type repoScanResult struct {
	errCode int
	errMsg  string
	report  *api.RESTScanRepoReport
}

func getImageName(req *api.RESTScanRepoReq) string {
	return fmt.Sprintf("%s:%s", req.Repository, req.Tag)
}

func newRepoScanMgr() {
	repoScanMgr = NewLongPollOnceMgr(repoScanLongPollTimeout, repoScanLingeringDuration, maxRepoScanTasks)
}

type repoScanTask struct {
}

func (r *repoScanTask) Run(arg interface{}) interface{} {
	req := arg.(*api.RESTScanRepoReq)

	log.WithFields(log.Fields{
		"registry": req.Registry, "image": getImageName(req),
	}).Info("Scan repository start")

	var rsr repoScanResult

	var proxy string
	var err error

	// if local image, no need proxy
	if req.Registry != "" {
		proxy = scan.GetProxy(req.Registry)
	}

	// default: always scan secrets
	scanSecrets := true

	ctx, cancel := context.WithTimeout(context.Background(), repoScanTimeout)
	defer cancel()

	scanReq := &share.ScanImageRequest{
		Registry:    req.Registry,
		Username:    req.Username,
		Password:    req.Password,
		Repository:  req.Repository,
		Tag:         req.Tag,
		Proxy:       proxy,
		ScanLayers:  req.ScanLayers,
		ScanSecrets: scanSecrets,
		BaseImage:   req.BaseImage,
	}
	scanReq.RootsOfTrust, err = getScanReqRootsOfTrust()
	if err != nil {
		rsr.errCode = api.RESTErrFailReadCluster
		rsr.errMsg = fmt.Sprintf("could not retrieve sigstore roots of trust: %s", err.Error())
	}
	result, err := rpc.ScanImage("", ctx, scanReq)

	if result == nil {
		// rpc request not made
		rsr.errCode = api.RESTErrClusterRPCError
		rsr.errMsg = err.Error()

		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req), "error": rsr.errMsg,
		}).Error("RPC request fail")
	} else if result.Error != share.ScanErrorCode_ScanErrNone {
		rsr.errCode = api.RESTErrFailRepoScan
		rsr.errMsg = scanUtils.ScanErrorToStr(result.Error)

		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req), "error": rsr.errMsg,
		}).Error("Failed to scan repository")
	} else {
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req),
		}).Info("Scan repository finish")

		// store the scan result so it can be used by admission control
		scan.FixRegRepoForAdmCtrl(result)
		scanner.StoreRepoScanResult(result)

		// build image compliance list and filter the list
		cpf := &complianceProfileFilter{filter: make(map[string][]string)}
		if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
			log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
		} else {
			cpf = &complianceProfileFilter{
				disableSystem: cp.DisableSystem, filter: filter, object: &share.CLUSRegistryImageSummary{ImageID: result.ImageID},
			}
		}

		rpt := scanUtils.ScanRepoResult2REST(result, cpf.filter)
		rpt.Checks = filterComplianceChecks(rpt.Checks, cpf)

		vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
		rpt.Vuls = vpf.FilterVulREST(rpt.Vuls, []api.RESTIDName{{DisplayName: fmt.Sprintf("%s:%s", rpt.Repository, rpt.Tag)}}, "")

		rsr.report = rpt
	}

	return &rsr
}

func handlerScanRepositoryReq(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSCIScanDummy{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var data api.RESTScanRepoReqData
	err := json.Unmarshal(body, &data)
	if err != nil || data.Request == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	// reg.Request.Registry == "", scan local image
	req := data.Request
	if req.Registry != "" {
		u, err := scanUtils.ParseRegistryURI(req.Registry)
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
				"Invalid Registry URL")
			return
		}
		req.Registry = u
	}
	if req.Repository == "" {
		log.WithFields(log.Fields{"error": err}).Error("No repository name provided")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"No repository name provided")
		return
	}
	// Add "library" for dockerhub if not exist
	if dockerRegistries.Contains(req.Registry) && strings.Index(req.Repository, "/") == -1 {
		req.Repository = fmt.Sprintf("library/%s", req.Repository)
	}
	if req.Tag == "" {
		req.Tag = repositoryDefaultTag
	}

	// If request is from a different login session, a new scan is triggered even for the same image.
	var task repoScanTask
	key := repoScanKey{
		RESTScanRepoReq: *req,
		token:           login.getToken(),
	}

	job, err := repoScanMgr.NewJob(key, &task, req)
	switch err {
	case errTooManyJobs:
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFailRepoScan,
			fmt.Sprintf("Maximum concurrent scan limit (%v) reached.", maxRepoScanTasks))
		return
	case errDuplicateJob:
		// If a request is already polling the scan, reject the new request from the same session.
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFailRepoScan,
			"Duplicated repository scan request.")
		return
	}

	result, _ := job.Poll()
	if result == nil {
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req),
		}).Debug("Keep waiting ...")
		w.WriteHeader(http.StatusNotModified)
	} else {
		ret := result.(*repoScanResult)
		// Clear password field for registry data
		data.Request.Password = ""
		if ret.errCode == api.RESTErrClusterRPCError {
			restRespError(w, http.StatusInternalServerError, ret.errCode)
		} else if ret.errCode != 0 {
			restRespErrorMessage(w, http.StatusInternalServerError, ret.errCode, ret.errMsg)
		} else {
			resp := &api.RESTScanRepoReportData{Report: ret.report}
			restRespSuccess(w, r, resp, acc, login, &data, "Request repository scan")
		}
	}
}

func handlerScanRepositorySubmit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSCIScanDummy{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var data api.RESTScanRepoSubmitData
	err := json.Unmarshal(body, &data)
	if err != nil || data.Result == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	result := data.Result

	// Sanity check
	if result.ImageID == "" || result.Digest == "" || result.Repository == "" || result.Tag == "" {
		log.Error("Missing image metadate in the request")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing image metadate in the request")
		return
	}
	if result.Vuls == nil {
		result.Vuls = make([]*share.ScanVulnerability, 0)
	}
	if result.Modules == nil {
		result.Modules = make([]*share.ScanModule, 0)
	}
	if result.SetIdPerms == nil {
		result.SetIdPerms = make([]*share.ScanSetIdPermLog, 0)
	}
	if result.Envs == nil {
		result.Envs = make([]string, 0)
	}
	if result.Cmds == nil {
		result.Cmds = make([]string, 0)
	}
	if result.Labels == nil {
		result.Labels = make(map[string]string)
	}

	if err := scanner.StoreRepoScanResult(result); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Store repo scan result error")
	}

	restRespSuccess(w, r, nil, acc, login, &data, "Summit repository scan result")
}

func getScanReqRootsOfTrust() (scanReqRootsOfTrust []*share.SigstoreRootOfTrust, err error) {
	clusRootsOfTrust, err := clusHelper.GetAllSigstoreRootsOfTrust()
	if err != nil {
		return nil, fmt.Errorf("could not retrieve roots of trust from kv store: %s", err.Error())
	}

	for _, clusRoot := range clusRootsOfTrust {
		scanRoot := &share.SigstoreRootOfTrust{
			Name:                 clusRoot.Name,
			RekorPublicKey:       clusRoot.RekorPublicKey,
			RootCert:             clusRoot.RootCert,
			SCTPublicKey:         clusRoot.SCTPublicKey,
			RootlessKeypairsOnly: clusRoot.RootlessKeypairsOnly,
		}

		verifiers, err := clusHelper.GetAllSigstoreVerifiersForRoot(clusRoot.Name)
		if err != nil {
			return scanReqRootsOfTrust, fmt.Errorf("could not retrieve verifiers for root \"%s\": %s", clusRoot.Name, err.Error())
		}

		for _, verifier := range verifiers {
			scanVerifier := &share.SigstoreVerifier{
				Name: verifier.Name,
				Type: verifier.VerifierType,
				KeypairOptions: &share.SigstoreKeypairOptions{
					PublicKey: verifier.PublicKey,
				},
				KeylessOptions: &share.SigstoreKeylessOptions{
					CertIssuer:  verifier.CertIssuer,
					CertSubject: verifier.CertSubject,
				},
			}
			scanRoot.Verifiers = append(scanRoot.Verifiers, scanVerifier)
		}

		scanReqRootsOfTrust = append(scanReqRootsOfTrust, scanRoot)
	}

	return scanReqRootsOfTrust, nil
}
