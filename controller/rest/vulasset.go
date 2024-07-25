package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share/utils"
)

var TESTDbPerf bool

func createVulAssetSessionV2(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	queryStat := &api.RESTVulQueryStats{
		PerfStats: make([]string, 0),
	}

	// check permission
	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	// fetch advanced filters
	queryFilter, err := db.GetVulnerabilityQuery(r)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	// For performance testing
	if TESTDbPerf && queryFilter.CreateDummyAsset_Enable == 1 {
		err = perf_createDummyVulAssets(queryFilter)
		restRespSuccess(w, r, "done.", acc, login, nil, "CreateDummyAsset done.")
		return
	}

	// save the data to querystat table (do this before put request to Consul)
	queryFilter.QueryToken = utils.GetRandomID(6, "") // do not change the length

	queryFilterb, err := json.Marshal(queryFilter)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("json.Marshal error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	err = createQueryStat(login, db.QueryStateType_Vul, queryFilter.QueryToken, string(queryFilterb))
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("createQueryStat error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	// put to Consul to signal other controllers to build the same query session
	err = createRequestInConsul(acc, login, 0, queryFilter.QueryToken, queryFilter.Filters, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Write create session request to consul error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	// use acc.Authorize() to filter allowed resources
	start := time.Now()
	allowed := getAllAllowedResourceId(acc)
	elapsed := time.Since(start)

	// For performance testing, when enabled it will treat all workload ID as allowed.
	//if TESTDbPerf && queryFilter.PerfTest == 1 {
	if TESTDbPerf {
		db.Perf_getAllWorkloadIDs(allowed)
	}

	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("1/4, get allowed resources, workloads_count=%d, took=%v", allowed[db.AssetWorkload].Cardinality(), elapsed))

	// get vul records in vulAssets table
	start = time.Now()
	vulAssets, nTotalCVE, perf, err := db.FilterVulAssetsV2(allowed, queryFilter)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("FilterVulAssets error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("2/4, get filtered vulasset from db, took=%v", elapsed))
	queryStat.PerfStats = append(queryStat.PerfStats, perf...)

	// get [top_image] and [top_nodes] summary,
	// it's static data (don't interact with filter)
	start = time.Now()
	top5Images, _ := db.GetTopAssets(allowed, db.AssetImage, 5)
	top5Nodes, _ := db.GetTopAssets(allowed, db.AssetNode, 5)
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("3/4, get summary top_image and top_node, took=%v", elapsed))

	// get [count_distribution] summary,
	// it's dynamic data, the result is derived from filtered dataset.
	CVEDist, nMatchedRecordCount := getCVEDistribution(vulAssets)
	CVEDist.Critical = -1 // temporarily revert critical cve logic

	// save to session temp table
	start = time.Now()
	err = db.CeateSessionVulAssetTable(queryFilter.QueryToken, true)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("CeateSessionVulAssetTable error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	err = db.PopulateSessionVulAssets(queryFilter.QueryToken, vulAssets, true)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("PopulateSessionVulAssets error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("4/4, populate result to tmp session table, took=%v", elapsed))

	// get statistics and return to caller
	queryStat.TotalRecordCount = nTotalCVE
	queryStat.TotalMatchedRecordCount = nMatchedRecordCount
	queryStat.QueryToken = queryFilter.QueryToken
	queryStat.Summary = &api.VulAssetSessionSummary{}
	queryStat.Summary.CountDist = CVEDist
	queryStat.Summary.TopImages = top5Images
	queryStat.Summary.TopNodes = top5Nodes

	log.WithFields(log.Fields{"PerfStats": strings.Join(queryStat.PerfStats, ";"), "querytoken": queryStat.QueryToken}).Debug("createVulAssetSession")

	if queryFilter.Debug == 0 {
		queryStat.PerfStats = nil
	}

	// delete exceeded sessions
	records, err := db.GetExceededSessions(login.fullname, login.id, login.loginType)
	if err == nil {
		for _, token := range records {
			clusHelper.DeleteQuerySessionRequest(token)
		}
		log.WithFields(log.Fields{"records": records}).Debug("Delete exceeded sessions")
	}

	restRespSuccess(w, r, queryStat, acc, login, nil, "Create asset report session")

	// populate the result to file-based database
	go func() {
		err = db.PopulateSessionToFile(queryFilter.QueryToken, vulAssets)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("PopulateSessionToFile error")
		}
	}()
}

func createRequestInConsul(acc *access.AccessControl, login *loginSession, reqType int, queryToken string, filterVul *api.VulQueryFilterViewModel, filterAsset *api.AssetQueryFilterViewModel) error {
	loginType := login.loginType

	// for backward compatiable
	if filterVul == nil {
		filterVul = &api.VulQueryFilterViewModel{}
	}

	if filterAsset == nil {
		filterAsset = &api.AssetQueryFilterViewModel{}
	}

	// write to Consul to signal other controllers build the same query
	userAccess := acc.ExportAccessControl()
	userAccess.LoginName = login.fullname
	userAccess.LoginID = login.id
	userAccess.LoginType = loginType
	qsr := &api.QuerySessionRequest{
		Type:         reqType,
		QueryToken:   queryToken,
		UserAccess:   userAccess,
		Filters:      filterVul,
		FiltersAsset: filterAsset,
	}
	qsr.CreationTime = time.Now().UTC().Unix()
	if err := clusHelper.CreateQuerySessionRequest(qsr); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("CreateQuerySessionRequest error")
		return err
	}
	log.WithFields(log.Fields{"qsr": qsr}).Debug("create query session to Consul")

	return nil
}

func createQueryStat(login *loginSession, nType int, queryToken, data1 string) error {
	loginType := login.loginType
	qs := &db.QueryStat{
		Token:        queryToken,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    loginType,
		LoginID:      login.id,
		LoginName:    login.fullname,
		Data1:        data1,
		Type:         nType,
	}

	_, err := db.PopulateQueryStat(qs)
	if err != nil {
		return err
	}

	return nil
}

func getVulAssetSession(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")

	// get access control
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	// get query parameters
	queryObj, err := db.GetVulnerabilityQuery(r)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("GetVulnerabilityQuery fail")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if queryObj.QueryToken != "" {
		resp, allAssets, err := db.GetVulAssetSessionV2(queryObj)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("GetVulAssetSessionV2 fail")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, fmt.Sprintf("get session vuls error %s", err))
			return
		}

		start := time.Now()
		assetMaps, err := db.GetAssetsMeta(allAssets)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("GetAssetsMeta fail")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, fmt.Sprintf("get assets error %s", err))
			return
		}

		for _, vul := range resp.Vuls {
			db.FillAssets(vul, assetMaps)
		}

		elapsed := time.Since(start)
		resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("4/4, get asset meta, took=%v", elapsed))

		log.WithFields(log.Fields{"PerfStats": strings.Join(resp.PerfStats, ";"), "querytoken": queryObj.QueryToken}).Debug("getVulAssetSession returns")

		if queryObj.Debug == 0 {
			resp.PerfStats = nil
		}

		restRespSuccess(w, r, resp, nil, nil, nil, "get vulasset session")
		return
	}
	restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidQueryToken, "invalid request, no query token provided")
}

// called by KV watcher when a query session request being added
func CreateQuerySession(qsr *api.QuerySessionRequest) error {
	log.WithFields(log.Fields{"qsr": qsr}).Debug("rest.CreateQuerySession(), execute qsr here")

	// check the table already exist, use qsr.QueryToken to check
	_, err := db.GetQueryStat(qsr.QueryToken)
	if err == nil {
		log.WithFields(log.Fields{"qsr": qsr}).Debug("rest.CreateQuerySession(), session temp table exist. skip.")
		return err
	}

	// ignore old request
	now := time.Now().UTC().Unix()
	if (now - qsr.CreationTime) > 180 {
		log.WithFields(log.Fields{"qsr": qsr, "now": now}).Debug("skip old request")
		return nil
	}

	// create query session
	if qsr.Type == 0 {
		err = _createVulQuerySession(qsr)
		if err != nil {
			log.WithFields(log.Fields{"qsr": qsr, "err": err}).Error("_createVulQuerySession() error")
			return err
		}
	} else if qsr.Type == 1 {
		// asset pagination
		err = _createAssetQuerySession(qsr)
		if err != nil {
			log.WithFields(log.Fields{"qsr": qsr, "err": err}).Error("_createAssetQuerySession() error")
			return err
		}
	}
	log.WithFields(log.Fields{"qsr": qsr}).Debug("rest.CreateQuerySession(), done.")

	return nil
}

func DeleteQuerySession(queryToken string) error {
	log.WithFields(log.Fields{"queryToken": queryToken}).Debug("rest.DeleteQuerySession(), delete query session")
	return db.DeleteQuerySessionByToken(queryToken)
}

func _createVulQuerySession(qsr *api.QuerySessionRequest) error {
	// create access control
	acc := access.ImportAccessControl(qsr.UserAccess)

	// create advanced filters
	queryFilter := &db.VulQueryFilter{
		QueryToken: qsr.QueryToken,
		Filters:    qsr.Filters,
	}

	if queryFilter.Filters == nil {
		return errors.New("invalid query session request")
	}

	// use acc.Authorize() to filter allowed resources
	allowed := getAllAllowedResourceId(acc)

	// get all records in vulAssets table which represent the complete data
	vulAssets, _, _, err := db.FilterVulAssetsV2(allowed, queryFilter)
	if err != nil {
		return err
	}

	// save to session temp table
	err = db.CeateSessionVulAssetTable(queryFilter.QueryToken, true)
	if err != nil {
		return err
	}

	err = db.PopulateSessionVulAssets(queryFilter.QueryToken, vulAssets, true)
	if err != nil {
		return err
	}

	// save the data to querystat table
	queryFilterb, err := json.Marshal(queryFilter)
	if err != nil {
		return err
	}

	qs := &db.QueryStat{
		Token:        queryFilter.QueryToken,
		CreationTime: qsr.CreationTime, // for Consul restore, use the timestamp in the qsr, not current time.
		LoginType:    qsr.UserAccess.LoginType,
		LoginID:      qsr.UserAccess.LoginID,
		LoginName:    qsr.UserAccess.LoginName,
		Data1:        string(queryFilterb),
		Type:         db.QueryStateType_Vul,
	}
	_, err = db.PopulateQueryStat(qs)
	if err != nil {
		return err
	}

	records, err := db.GetExceededSessions(qsr.UserAccess.LoginName, qsr.UserAccess.LoginID, qsr.UserAccess.LoginType)
	if err == nil {
		for _, token := range records {
			clusHelper.DeleteQuerySessionRequest(token)
		}
	}

	// populate the result to file-based database
	go func() {
		err := db.PopulateSessionToFile(queryFilter.QueryToken, vulAssets)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("PopulateSessionToFile error")
		}
	}()

	return nil
}

func _createAssetQuerySession(qsr *api.QuerySessionRequest) error {
	acc := access.ImportAccessControl(qsr.UserAccess)

	queryFilter := &db.AssetQueryFilter{
		QueryToken: qsr.QueryToken,
		Filters:    qsr.FiltersAsset,
	}

	if queryFilter.Filters == nil {
		return errors.New("invalid query session request")
	}

	if queryFilter.Filters.Type != "image" {
		return errors.New("unsupported type")
	}

	allowed := getAllAllowedResourceId(acc)

	_, _, err := db.CreateImageAssetSession(allowed, queryFilter)
	if err != nil {
		return err
	}

	queryFilterb, _ := json.Marshal(queryFilter)
	qs := &db.QueryStat{
		Token:        queryFilter.QueryToken,
		CreationTime: qsr.CreationTime,
		LoginType:    qsr.UserAccess.LoginType,
		LoginID:      qsr.UserAccess.LoginID,
		LoginName:    qsr.UserAccess.LoginName,
		Data1:        string(queryFilterb),
		Type:         db.QueryStateType_Asset,
	}
	_, err = db.PopulateQueryStat(qs)
	if err != nil {
		return err
	}

	// delete exceeded sessions
	records, err := db.GetExceededSessions(qsr.UserAccess.LoginName, qsr.UserAccess.LoginID, qsr.UserAccess.LoginType)
	if err == nil {
		for _, token := range records {
			clusHelper.DeleteQuerySessionRequest(token)
		}
		log.WithFields(log.Fields{"records": records}).Debug("Delete exceeded sessions")
	}

	// populate the result to file-based database
	go func() {
		err = db.DupAssetSessionTableToFile(queryFilter.QueryToken)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("PopulateSessionToFile error")
		}
	}()

	return nil
}

func getCVEDistribution(vulAssets []*db.DbVulAsset) (*api.VulAssetCountDist, int) {
	dist := &api.VulAssetCountDist{}

	nMatchedRecordCount := 0
	for _, r := range vulAssets {
		if !r.MeetSearch {
			continue
		}
		nMatchedRecordCount++

		if r.Severity == "High" {
			dist.High++
		} else if r.Severity == "Medium" {
			dist.Medium++
		} else {
			dist.Low++
		}

		if len(r.WorkloadItems) > 0 {
			dist.Containers++
		}

		if len(r.NodeItems) > 0 {
			dist.Nodes++
		}

		if len(r.ImageItems) > 0 {
			dist.Images++
		}

		if len(r.PlatformItems) > 0 {
			dist.Platforms++
		}
	}

	return dist, nMatchedRecordCount
}

func getAssetViewSession(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	queryStat := &api.RESTVulQueryStats{
		PerfStats: make([]string, 0),
	}

	// check permission
	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	// combine incoming request with existing advanced filters.
	queryFilter, err := combineQueryFilter(r)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, err.Error())
		return
	}

	allowed := getAllAllowedResourceId(acc)

	// apply cve based filter (last modified time)
	start := time.Now()
	vulMap, assetsMap, err := db.GetSessionMatchedVuls(allowed, queryFilter.QueryToken, queryFilter.Filters.LastModifiedTime)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, err.Error())
		return
	}
	elapsed := time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("1/2, get vul from db, took=%v", elapsed))

	// apply asset filtering to get data from [assetvuls] table, only return matched assets
	start = time.Now()
	resp, err := db.GetMatchedAssets(vulMap, assetsMap, queryFilter) // queryFilter *VulQueryFilter
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, err.Error())
		return
	}
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("2/2, get assets from db, poolSize=%v, took=%v", queryFilter.ThreadCount, elapsed))

	if queryFilter.Debug == 1 {
		resp.QueryStat = queryStat
	}

	restRespSuccess(w, r, resp, acc, login, nil, "getAssetViewSession")
}

func combineQueryFilter(r *http.Request) (*db.VulQueryFilter, error) {
	// combine
	// 1. QueryToken and LastModifiedTime from incoming request
	// 2. advanced filter belong to the QueryToken
	qf, err := db.GetVulnerabilityQuery(r)
	if err != nil {
		return nil, err
	}

	queryStat, err := db.GetQueryStat(qf.QueryToken)
	if err != nil {
		return nil, err
	}

	queryFilter := &db.VulQueryFilter{
		QueryToken: qf.QueryToken,
		Debug:      qf.Debug,
	}

	vulQF := &db.VulQueryFilter{}
	err = json.Unmarshal([]byte(queryStat.Data1), &vulQF)
	if err != nil {
		return nil, err
	}
	queryFilter.Filters = vulQF.Filters
	queryFilter.Filters.LastModifiedTime = qf.Filters.LastModifiedTime

	return queryFilter, nil
}

func createAssetSession(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	queryStat := &api.RESTAssetQueryStats{
		PerfStats: make([]string, 0),
	}

	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	queryFilter, err := db.GetAssetQuery(r)
	if err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if queryFilter.Filters.Type != "image" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "invalid asset type")
		return
	}

	// create a query session
	queryFilter.QueryToken = utils.GetRandomID(6, "") // do not change the length

	queryFilterb, _ := json.Marshal(queryFilter)
	err = createQueryStat(login, db.QueryStateType_Asset, queryFilter.QueryToken, string(queryFilterb))
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("createQueryStat error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	// notify other controllers via Consul
	err = createRequestInConsul(acc, login, 1, queryFilter.QueryToken, nil, queryFilter.Filters)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Write create session request to consul error")
	}

	start := time.Now()
	allowed := getAllAllowedResourceId(acc)
	elapsed := time.Since(start)

	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("1/4, get allowed resources, asset_count=%d, took=%v", allowed[db.AssetWorkload].Cardinality(), elapsed))

	assetCount, top5, err := db.CreateImageAssetSession(allowed, queryFilter)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	// get statistics and return to caller
	queryStat.TotalRecordCount = assetCount
	queryStat.QueryToken = queryFilter.QueryToken
	queryStat.Summary = &api.AssetSessionSummary{}
	queryStat.Summary.TopImages = top5

	log.WithFields(log.Fields{"PerfStats": strings.Join(queryStat.PerfStats, ";"), "querytoken": queryStat.QueryToken}).Debug("createAssetSession")

	if queryFilter.Debug == 0 {
		queryStat.PerfStats = nil
	}

	records, err := db.GetExceededSessions(login.fullname, login.id, login.loginType)
	if err == nil {
		for _, token := range records {
			clusHelper.DeleteQuerySessionRequest(token)
		}
		log.WithFields(log.Fields{"records": records}).Debug("Delete exceeded sessions")
	}

	restRespSuccess(w, r, queryStat, acc, login, nil, "Create asset session")

	// populate the result to file-based database
	go func() {
		err = db.DupAssetSessionTableToFile(queryFilter.QueryToken)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("PopulateSessionToFile error")
		}
	}()
}

func getAssetSession(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	queryObj, err := db.GetAssetQuery(r)
	if err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	queryStat, err := db.GetQueryStat(queryObj.QueryToken)
	if err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidQueryToken, err.Error())
		return
	}

	queryFilter := &db.AssetQueryFilter{}
	err = json.Unmarshal([]byte(queryStat.Data1), &queryFilter)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("query stat not found")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidQueryToken, err.Error())
		return
	}

	if queryFilter.Filters.Type == "image" {
		assets, quickFilterMatched, err := db.GetImageAssetSession(queryObj)
		if err != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
			return
		}

		resp := struct {
			Type               string                      `json:"type"`
			Data               []*api.RESTImageAssetViewV2 `json:"data"`
			QuickFilterMatched int                         `json:"qf_matched_records"`
		}{
			Type:               "image",
			Data:               assets,
			QuickFilterMatched: quickFilterMatched,
		}
		restRespSuccess(w, r, resp, nil, nil, nil, "get asset session")
		return
	}

	restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "invalid asset type")
}
