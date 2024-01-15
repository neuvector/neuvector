package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share/utils"
)

var TESTDbPerf bool

func createVulAssetSession(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	queryStat := &api.RESTScanAssetQueryStats{
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

	// use acc.Authorize() to filter allowed resources
	start := time.Now()
	allowed, filteredMap := getAllAllowedResourceId(acc)
	elapsed := time.Since(start)

	// For performance testing, when enabled it will treat all workload ID as allowed.
	//if TESTDbPerf && queryFilter.PerfTest == 1 {
	if TESTDbPerf {
		db.Perf_getAllWorkloadIDs(allowed)
	}

	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("1/4, get allowed resources, workloads_count=%d, took=%v", allowed[db.AssetWorkload].Cardinality(), elapsed))

	// get vul records in vulAssets table
	start = time.Now()
	vulAssets, nTotalCVE, err := db.FilterVulAssets(allowed, queryFilter, filteredMap)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("FilterVulAssets error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("2/4, get filtered vulasset from db, took=%v", elapsed))

	// get [top_image] and [top_nodes] summary,
	// it's static data (don't interact with filter)
	start = time.Now()
	top5Images, err := db.GetTopAssets(allowed, db.AssetImage, 5)
	top5Nodes, err := db.GetTopAssets(allowed, db.AssetNode, 5)
	elapsed = time.Since(start)
	queryStat.PerfStats = append(queryStat.PerfStats, fmt.Sprintf("3/4, get summary top_image and top_node, took=%v", elapsed))

	// get [count_distribution] summary,
	// it's dynamic data, the result is derived from filtered dataset.
	CVEDist, nMatchedRecordCount := getCVEDistribution(vulAssets)

	// save the data to querystat table (do this before put request to Consul)
	queryFilter.QueryToken = utils.GetRandomID(6, "") // do not change the length
	err = createQueryStat(login, queryFilter)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("createQueryStat error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

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

	// put to Consul to signal other controllers to build the same query session
	err = createRequestInConsul(acc, login, queryFilter)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Write create session request to consul error")
	}

	// get statistics and return to caller
	queryStat.TotalRecordCount = nTotalCVE
	queryStat.TotalMatchedRecordCount = nMatchedRecordCount
	queryStat.QueryToken = queryFilter.QueryToken
	queryStat.Summary = &api.VulAssetSessionSummary{}
	queryStat.Summary.CountDist = CVEDist
	queryStat.Summary.TopImages = top5Images
	queryStat.Summary.TopNodes = top5Nodes

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

	restRespSuccess(w, r, queryStat, acc, login, nil, "Create createAssetVulnerabilitySession5 asset report session")

	// populate the result to file-based database
	go func() {
		err = db.PopulateSessionToFile(queryFilter.QueryToken, vulAssets)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("PopulateSessionToFile error")
		}
	}()
}

func createRequestInConsul(acc *access.AccessControl, login *loginSession, queryFilter *db.VulQueryFilter) error {
	loginType := login.loginType

	// write to Consul to signal other controllers build the same query
	userAccess := acc.ExportAccessControl()
	userAccess.LoginName = login.fullname
	userAccess.LoginID = login.id
	userAccess.LoginType = loginType
	qsr := &api.QuerySessionRequest{
		QueryToken: queryFilter.QueryToken,
		UserAccess: userAccess,
		Filters:    queryFilter.Filters,
	}
	qsr.CreationTime = time.Now().UTC().Unix()
	if err := clusHelper.CreateQuerySessionRequest(qsr); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("CreateQuerySessionRequest error")
		return err
	}
	log.WithFields(log.Fields{"qsr": qsr}).Debug("create query session to Consul")

	return nil
}

func createQueryStat(login *loginSession, queryFilter *db.VulQueryFilter) error {
	loginType := login.loginType

	queryFilterb, _ := json.Marshal(queryFilter)

	qs := &db.QueryStat{
		Token:        queryFilter.QueryToken,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    loginType,
		LoginID:      login.id,
		LoginName:    login.fullname,
		Data1:        string(queryFilterb),
	}

	_, err := db.PopulateQueryStat(qs)
	if err != nil {
		return err
	}

	return nil
}

func getVulAssetSession(w http.ResponseWriter, r *http.Request) {
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
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if queryObj.QueryToken != "" {
		resp, allAssets, err := db.GetVulAssetSession(queryObj)
		if err != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, fmt.Sprintf("get session vuls error %s", err))
			return
		}

		start := time.Now()
		assetMaps, err := db.GetAssetsMeta(allAssets)
		if err != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, fmt.Sprintf("get assets error %s", err))
			return
		}

		for _, vul := range resp.Vuls {
			db.FillAssets(vul, assetMaps)
		}

		elapsed := time.Since(start)
		resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("2/2, get asset meta, took=%v", elapsed))
		resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("mem tables: [%s]", db.GetAllTableInMemoryDb()))

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
	err = _createQuerySession(qsr)
	if err != nil {
		log.WithFields(log.Fields{"qsr": qsr, "err": err}).Error("_createQuerySession() error")
		return err
	}

	return nil
}

func DeleteQuerySession(queryToken string) error {
	log.WithFields(log.Fields{"queryToken": queryToken}).Debug("rest.DeleteQuerySession(), delete query session")
	return db.DeleteQuerySessionByToken(queryToken)
}

func _createQuerySession(qsr *api.QuerySessionRequest) error {
	queryStat := &api.RESTScanAssetQueryStats{
		PerfStats: make([]string, 0),
	}

	// create access control
	acc := access.ImportAccessControl(qsr.UserAccess)

	// create advanced filters
	queryFilter := &db.VulQueryFilter{
		QueryToken: qsr.QueryToken,
		Filters:    qsr.Filters,
	}

	// use acc.Authorize() to filter allowed resources
	allowed, filteredMapVul := getAllAllowedResourceId(acc)

	// get all records in vulAssets table which represent the complete data
	vulAssets, _, err := db.FilterVulAssets(allowed, queryFilter, filteredMapVul)
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
	queryFilterb, _ := json.Marshal(queryFilter)
	perfStatsb, _ := json.Marshal(queryStat.PerfStats)

	qs := &db.QueryStat{
		Token:        queryFilter.QueryToken,
		CreationTime: qsr.CreationTime, // for Consul restore, use the timestamp in the qsr, not current time.
		LoginType:    qsr.UserAccess.LoginType,
		LoginID:      qsr.UserAccess.LoginID,
		LoginName:    qsr.UserAccess.LoginName,
		Data1:        string(queryFilterb),
		Data2:        string(perfStatsb),
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

	perfStat := &api.RESTScanAssetQueryStats{
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

	// apply cve based filter (last modified time)
	start := time.Now()
	vulMap, assetsMap, err := db.GetSessionMatchedVuls(queryFilter.QueryToken, queryFilter.Filters.LastModifiedTime)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, err.Error())
		return
	}
	elapsed := time.Since(start)
	perfStat.PerfStats = append(perfStat.PerfStats, fmt.Sprintf("1/2, get vul from db, took=%v", elapsed))

	// apply asset filtering to get data from [assetvuls] table, only return matched assets
	start = time.Now()
	resp, err := db.GetMatchedAssets(vulMap, assetsMap, queryFilter) // queryFilter *VulQueryFilter
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidQueryToken, err.Error())
		return
	}
	elapsed = time.Since(start)
	perfStat.PerfStats = append(perfStat.PerfStats, fmt.Sprintf("2/2, get assets from db, took=%v", elapsed))

	if queryFilter.Debug == 1 {
		resp.QueryStat = perfStat
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

	qsr := &api.QuerySessionRequest{}
	err = json.Unmarshal([]byte(queryStat.Data1), &qsr)
	if err != nil {
		return nil, err
	}
	queryFilter.Filters = qsr.Filters
	queryFilter.Filters.LastModifiedTime = qf.Filters.LastModifiedTime

	return queryFilter, nil
}
