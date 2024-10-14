package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	// manifestV1 "github.com/docker/distribution/manifest/schema1"
	// manifestV2 "github.com/docker/distribution/manifest/schema2"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerDebugRegistryImage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	name := ps.ByName("name")

	query := restParseQuery(r)

	var resp api.RESTRegistryDebugImageData
	resp.Images = make([]*api.RESTRegistryDebugImage, 0)

	images := scanner.GetRegistryDebugImages(name)

	// Sort
	sort.Slice(images, func(i, j int) bool {
		if images[i].Domain < images[j].Domain {
			return true
		} else if images[i].Domain > images[j].Domain {
			return false
		} else if images[i].Repository < images[j].Repository {
			return true
		} else {
			return false
		}
	})

	// Filter
	if len(images) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get registry debug image list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTRegistryDebugImage
		rf := restNewFilter(&dummy, query.filters)

		for _, image := range images[query.start:] {
			if !rf.Filter(image) {
				continue
			}

			resp.Images = append(resp.Images, image)

			if query.limit > 0 && len(resp.Images) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Images = images[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(images) {
			end = len(images)
		} else {
			end = query.start + query.limit
		}
		resp.Images = images[query.start:end]
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry debug image list")
}

// -- registry test

const (
	tidLength                = 16
	maxRegTestTasks          = 8
	maxMessageSize           = 1024
	regTestTimeout           = time.Minute * 20
	regTestLingeringDuration = time.Second * 30
	regTestLongPollTimeout   = time.Second * 30
)

// type imageSchema struct {
// 	Version int `json:"schemaVersion"`
// }

var regTestMgr *longpollManyMgr
var regTestMap map[string]*regTestTask
var regTestLock sync.RWMutex

func newRegTestMgr() {
	regTestMgr = NewLongPollManyMgr(regTestLongPollTimeout, regTestLingeringDuration, maxRegTestTasks)
	regTestMap = make(map[string]*regTestTask)
}

type regTracer struct {
	signal     SignalFunc
	steps      []*api.RESTRegistryTestStep
	isManifest bool
}

// func (t regTracer) format(m string) string {
// 	return fmt.Sprintf("%.[2]*[1]s", m, maxMessageSize)
// }

func (t *regTracer) SetPhase(message string) {
	t.steps = append(t.steps, &api.RESTRegistryTestStep{
		Step: api.HTTPTestStepStage, Content: message,
	})
	// log.WithFields(log.Fields{"step": len(t.steps), "message": message}).Debug()
	t.signal()
}

func (t *regTracer) AddComment(step, comment string) {
	t.steps = append(t.steps, &api.RESTRegistryTestStep{
		Step: step, Content: comment,
	})
	// log.WithFields(log.Fields{"step": len(t.steps), "comment": comment}).Debug()
	t.signal()
}

func (t *regTracer) SendRequest(method, url string) {
	t.steps = append(t.steps, &api.RESTRegistryTestStep{
		Step: api.HTTPTestStepURL, Content: fmt.Sprintf("%s %s", method, url),
	})

	a := strings.Index(url, "/v2/")
	b := strings.Index(url, "/manifests/")
	if a+3 < b {
		t.isManifest = true
	} else {
		t.isManifest = false
	}

	// log.WithFields(log.Fields{"step": len(t.steps), "method": method, "url": url}).Debug()
	t.signal()
}

func (t *regTracer) GotResponse(statusCode int, status string, header http.Header, body io.ReadCloser) io.Reader {
	c, _ := io.ReadAll(body)
	body.Close()

	t.steps = append(t.steps, &api.RESTRegistryTestStep{
		Step: api.HTTPTestStepResponse, Content: string(c[:]),
	})

	// log.WithFields(log.Fields{"step": len(t.steps), "status": statusCode, "body": string(c[:])}).Debug()
	t.signal()

	return bytes.NewReader(c)
}

func (t *regTracer) GotError(message string) {
	t.steps = append(t.steps, &api.RESTRegistryTestStep{
		Step: api.HTTPTestStepError, Content: message,
	})
	// log.WithFields(log.Fields{"step": len(t.steps), "message": message}).Debug()
	t.signal()
}

type regTestTask struct {
	tracer *regTracer
	cancel context.CancelFunc
	tid    string
	config *share.CLUSRegistryConfig
}

func (r regTestTask) Read() interface{} {
	return r.tracer.steps
}

func (r *regTestTask) Run(arg interface{}, signal SignalFunc) {
	config := arg.(*share.CLUSRegistryConfig)

	log.WithFields(log.Fields{"registry": config.Registry}).Info("Scan repository start")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.cancel = cancel
	r.tracer = &regTracer{
		signal: signal,
		steps:  make([]*api.RESTRegistryTestStep, 0),
	}

	scanner.TestRegistry(ctx, config, r.tracer)
}

func (r *regTestTask) Delete() {
	regTestLock.Lock()
	delete(regTestMap, r.tid)
	regTestLock.Unlock()
}

func handlerRegistryTest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	var data api.RESTRegistryTestData
	body, _ := io.ReadAll(r.Body)
	var err error

	if getRequestApiVersion(r) == ApiVersion2 {
		var v2data api.RESTRegistryTestDataV2
		err := json.Unmarshal(body, &v2data)
		if err != nil || v2data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		data = registryTestV2ToV1(v2data)
	} else {
		err := json.Unmarshal(body, &data)
		if err != nil || data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	var task *regTestTask

	tid := r.Header.Get("X-Transaction-ID")
	if tid != "" {
		var ok bool

		regTestLock.RLock()
		task, ok = regTestMap[tid]
		regTestLock.RUnlock()

		if !ok {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unable to locate the transaction")
			return
		} else if !acc.AuthorizeOwn(task.config, nil) { // [2021/05] To support RegistryTypeOpenShift type in the future, we need to use a temp config with nil ParsedFilters for AuthorizeOwn() !
			restRespAccessDenied(w, login)
			return
		}
	} else {
		var config share.CLUSRegistryConfig

		// validate registry config
		{
			rconf := data.Config
			if rconf.Type == share.RegistryTypeJFrog || rconf.Type == share.RegistryTypeDocker {
				config.Type = rconf.Type
			} else {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unsupported registry type")
				return
			}

			// Verify config
			config.Registry, err = scanUtils.ParseRegistryURI(rconf.Registry)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("Invalid registry URL")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid registry URL")
				return
			}

			config.Name = rconf.Name
			config.Username = rconf.Username
			config.Password = rconf.Password
			config.AuthToken = rconf.AuthToken
			config.AuthWithToken = rconf.AuthWithToken
			config.CreaterDomains = acc.GetAdminDomains(share.PERM_REG_SCAN)
			config.IgnoreProxy = rconf.IgnoreProxy

			if config.AuthWithToken && config.AuthToken == "" {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing authentication token")
				return
			}

			// Jfrog config
			if rconf.Type == share.RegistryTypeJFrog {
				if rconf.JfrogMode != share.JFrogModeRepositoryPath &&
					rconf.JfrogMode != share.JFrogModeSubdomain &&
					rconf.JfrogMode != share.JFrogModePort {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid Jfrog mode")
					return
				}

				config.JfrogMode = rconf.JfrogMode
				config.JfrogAQL = rconf.JfrogAQL
			}

			// Parse filters
			if rconf.Filters != nil {
				filters := rconf.Filters
				sort.Slice(filters, func(i, j int) bool { return filters[i] < filters[j] })
				rfilters, err := parseFilter(filters, config.Type)
				if err != nil {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
					return
				}

				config.Filters = filters
				config.ParsedFilters = rfilters
			} else {
				config.Filters = make([]string, 0)
				config.ParsedFilters = make([]*share.CLUSRegistryFilter, 0)
			}

			// [2021/05] To support RegistryTypeOpenShift type in the future, we need to use a temp config with nil ParsedFilters for AuthorizeOwn() !
			if !acc.AuthorizeOwn(&config, nil) {
				restRespAccessDenied(w, login)
				return
			}
		}

		tid = utils.GetRandomID(tidLength, "")

		task = &regTestTask{tid: tid, config: &config}
		regTestLock.Lock()
		regTestMap[tid] = task
		regTestLock.Unlock()
	}

	job, err := regTestMgr.NewJob(tid, task, task.config)
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

	result, done, _ := job.Poll()
	w.Header().Set("X-Transaction-ID", tid)
	if result == nil {
		log.WithFields(log.Fields{"transaction": tid}).Debug("Keep waiting ...")
		w.WriteHeader(http.StatusNotModified)
	} else {
		steps := result.([]*api.RESTRegistryTestStep)
		resp := &api.RESTRegistryTestStepData{Steps: steps}
		if !done {
			log.WithFields(log.Fields{"transaction": tid, "steps": len(steps)}).Debug("Partial data ...")
			restRespPartial(w, r, resp)
		} else {
			log.WithFields(log.Fields{"transaction": tid, "steps": len(steps)}).Debug("Done")
			restRespSuccess(w, r, resp, acc, login, &data, "Request registry test")
		}
	}
}

func handlerRegistryTestCancel(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	if tid == "" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "No transaction id in the request")
	}

	regTestLock.RLock()
	task, ok := regTestMap[tid]
	regTestLock.RUnlock()

	if !ok {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unable to locate the transaction")
		return
	} else if !acc.AuthorizeOwn(task.config, nil) { // [2021/05] To support RegistryTypeOpenShift type in the future, we need to use a temp config with nil ParsedFilters for AuthorizeOwn() !
		restRespAccessDenied(w, login)
		return
	}

	if task.cancel == nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Task is not running yet")
		return
	}

	task.cancel()

	restRespSuccess(w, r, nil, acc, login, nil, "Cancel registry test")
}

func registryTestV2ToV1(v2data api.RESTRegistryTestDataV2) api.RESTRegistryTestData {
	v1data := api.RESTRegistryTestData{
		Config: &api.RESTRegistry{},
	}

	if v2data.Config != nil {
		v1data.Config.Name = v2data.Config.Name
		v1data.Config.Type = v2data.Config.Type
		v1data.Config.Registry = v2data.Config.Registry
		v1data.Config.Domains = v2data.Config.Domains
		v1data.Config.Filters = v2data.Config.Filters
		v1data.Config.CfgType = v2data.Config.CfgType

		// auth
		v1data.Config.Username = v2data.Config.Auth.Username
		v1data.Config.Password = v2data.Config.Auth.Password
		v1data.Config.AuthToken = v2data.Config.Auth.AuthToken
		v1data.Config.AuthWithToken = v2data.Config.Auth.AuthWithToken
		v1data.Config.AwsKey = &v2data.Config.Auth.AwsKey
		v1data.Config.GcrKey = &v2data.Config.Auth.GcrKey

		// scan
		v1data.Config.RescanImage = v2data.Config.Scan.RescanImage
		v1data.Config.ScanLayers = v2data.Config.Scan.ScanLayers
		v1data.Config.RepoLimit = v2data.Config.Scan.RepoLimit
		v1data.Config.TagLimit = v2data.Config.Scan.TagLimit
		v1data.Config.Schedule = v2data.Config.Scan.Schedule
		v1data.Config.IgnoreProxy = v2data.Config.Scan.IgnoreProxy

		// integrations
		v1data.Config.JfrogMode = v2data.Config.Integrations.JfrogMode
		v1data.Config.JfrogAQL = v2data.Config.Integrations.JfrogAQL
		v1data.Config.GitlabApiUrl = v2data.Config.Integrations.GitlabApiUrl
		v1data.Config.GitlabPrivateToken = v2data.Config.Integrations.GitlabPrivateToken
		v1data.Config.IBMCloudTokenURL = v2data.Config.Integrations.IBMCloudTokenURL
		v1data.Config.IBMCloudAccount = v2data.Config.Integrations.IBMCloudAccount
	}

	return v1data
}
