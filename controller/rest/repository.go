package rest

import (
	"context"
	"encoding/json"
	"errors"
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
	repoScanTimeout           = time.Minute * 20
	repoScanLingeringDuration = time.Second * 30
)

var RepoScanMgr *longpollOnceMgr

// var scanJobQueueCapacity, scanJobFailRetryMax, maxConcurrentRepoScanTasks int
// var staleScanJobCleanupIntervalHour time.Duration

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

type repoScanTask struct {
}

// The ShouldRetry method determines whether a repository scan task should be retried based on the error encountered.
// - Retry is allowed for specific error codes related to timeouts, registry API issues, file system errors, network problems, and container API errors.
// - If the error code indicates that the image was not found, it logs this information and returns false, as retrying would be futile.
// - For any other error codes not explicitly handled, the method defaults to returning false, indicating no retry.
func (t *repoScanTask) ShouldRetry(arg interface{}) bool {
	jobErr, ok := arg.(*JobError)
	if !ok {
		log.Error("ShouldRetry: arg is not of type *JobError")
		return false
	}

	// Check error codes that allow retries
	switch jobErr.Detail {
	case share.ScanErrorCode_ScanErrTimeout,
		share.ScanErrorCode_ScanErrRegistryAPI,
		share.ScanErrorCode_ScanErrFileSystem,
		share.ScanErrorCode_ScanErrNetwork,
		share.ScanErrorCode_ScanErrContainerAPI,
		share.ScanErrorCode_ScanErrAcquireScannerTimeout:
		return true

	case share.ScanErrorCode_ScanErrImageNotFound:
		log.Error("ShouldRetry: image not found, no retry needed")
		return false

	default:
		return false
	}
}

// Run executes the repository scan task and returns the result along with any error encountered.
func (r *repoScanTask) Run(arg interface{}) (interface{}, *JobError) {
	req, ok := arg.(*api.RESTScanRepoReq)
	if !ok || req == nil {
		log.Error("Invalid argument passed to Run")
		return nil, NewJobError(api.RESTErrInvalidRequest, errors.New("invalid argument passed to Run"), nil)
	}
	var scanErr *JobError

	log.WithFields(log.Fields{
		"registry": req.Registry, "image": getImageName(req),
	}).Info("Scan repository start")

	var rsr repoScanResult

	var proxy string
	var err error

	// Determine if a proxy is needed based on the registry
	if req.Registry != "" {
		proxy = scan.GetProxy(req.Registry)
	}

	// Default behavior: always scan for secrets
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
		// RPC request failed
		scanErr = NewJobError(api.RESTErrClusterRPCError, err, nil)
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req), "error": err,
		}).Error("RPC request fail")
	} else if result.Error != share.ScanErrorCode_ScanErrNone {
		// Include the error code in Detail to enable ShouldRetry logic
		scanErr = NewJobError(api.RESTErrFailRepoScan, err, result.Error)
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req), "error": scanUtils.ScanErrorToStr(result.Error),
		}).Error("Failed to scan repository")
	} else {
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req),
		}).Info("Scan repository finish")

		// Store the scan result for use in admission control
		scan.FixRegRepoForAdmCtrl(result)
		if err := scanner.StoreRepoScanResult(result); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("StoreRepoScanResult")
		}

		// Build and filter the image compliance list
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

	return &rsr, scanErr
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
	if dockerRegistries.Contains(req.Registry) && !strings.Contains(req.Repository, "/") {
		req.Repository = fmt.Sprintf("library/%s", req.Repository)
	}
	if req.Tag == "" {
		req.Tag = repositoryDefaultTag
	}

	// If request is from a different login session, a new scan is triggered even for the same image.
	task := &repoScanTask{}
	key := repoScanKey{
		RESTScanRepoReq: *req,
		token:           login.getToken(), // Keep it for backward compatibility
	}

	// Create a new job for the repository scan
	_, err = RepoScanMgr.NewJob(key, task, req)
	switch err {
	case errTooManyJobs:
		restRespErrorMessage(w, http.StatusTooManyRequests, api.RESTErrFailRepoScan,
			fmt.Sprintf("Maximum concurrent scan limit (%v) reached.", RepoScanMgr.maxConcurrentRepoScanTasks))
		return
	case errMaxRetryReached:
		// maximum job retry attempts reached
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFailRepoScan,
			fmt.Sprintf("Maximum job retry attempts (%v) reached.", RepoScanMgr.jobFailRetryMax))
		return
	}

	// The Poll method returns an error only if the job has failed.
	// For jobs that are retrying or pending, it returns nil for both result and error.
	// If the job is complete, it returns the result and nil for the error.
	result, scanErr := RepoScanMgr.Poll(key)

	if scanErr != nil {
		data.Request.Password = ""
		if scanErr.Code != 0 && scanErr.Code != api.RESTErrClusterRPCError {
			restRespErrorMessage(w, http.StatusInternalServerError, scanErr.Code, scanErr.Error())
		} else {
			restRespError(w, http.StatusInternalServerError, scanErr.Code)
		}
		return
	}

	if result == nil {
		log.WithFields(log.Fields{
			"registry": req.Registry, "image": getImageName(req),
		}).Debug("Scan is still in progress, waiting for completion...")
		w.WriteHeader(http.StatusNotModified)
	} else {
		ret := result.(*repoScanResult)
		// Clear password field for registry data
		data.Request.Password = ""
		resp := &api.RESTScanRepoReportData{Report: ret.report}
		restRespSuccess(w, r, resp, acc, login, &data, "Repository scan request completed successfully")
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
