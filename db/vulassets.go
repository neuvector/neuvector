package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alitto/pond"
	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

func GetVulnerabilityQuery(r *http.Request) (*VulQueryFilter, error) {
	q := &VulQueryFilter{
		Filters: &api.VulQueryFilterViewModel{},
	}
	q.QueryToken = r.URL.Query().Get("token")
	q.QueryStart = getQueryParamInteger(r, startQueryParam, defaultStart)
	q.QueryCount = getQueryParamInteger(r, rowQueryParam, defaultRowCount)
	q.Debug = getQueryParamInteger(r, "debug", defaultDebugMode)
	q.PerfTest = getQueryParamInteger(r, "perftest", defaultDebugMode)
	q.Filters.DebugCVEName = r.URL.Query().Get("debugcve")
	q.ThreadCount = getQueryParamInteger(r, "threadcount", 10)

	// for performance test
	q.CreateDummyAsset_Enable = getQueryParamInteger(r, "createdummyasset", 0)
	if q.CreateDummyAsset_Enable == 1 {
		q.CreateDummyAsset_CVE = getQueryParamInteger(r, "howmany_cve", 0)
		q.CreateDummyAsset_Asset = getQueryParamInteger(r, "howmany_asset", 0)
		q.CreateDummyAsset_CVE_per_asset = getQueryParamInteger(r, "howmany_cve_per_asset", 0)
	}

	if r.Method == http.MethodPatch || r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		bodyStr := string(body)
		if len(bodyStr) > 0 {
			if err := json.Unmarshal(body, &q.Filters); err != nil {
				return nil, err
			}
		}
	}

	q.Filters.ScoreType = validateOrDefault(q.Filters.ScoreType, []string{"v2", "v3"}, "v3")
	q.Filters.ViewType = validateOrDefault(q.Filters.ViewType, []string{"all", "containers", "infrastructure", "registry"}, "all")
	q.Filters.SeverityType = validateOrDefault(q.Filters.SeverityType, []string{"all", "high", "medium", "low"}, "all")
	q.Filters.PackageType = validateOrDefault(q.Filters.PackageType, []string{"all", "withFix", "withoutFix"}, "all")
	q.Filters.PublishedType = validateOrDefault(q.Filters.PublishedType, []string{"all", "before", "after"}, "all")

	q.Filters.ServiceNameMatchType = validateOrDefault(q.Filters.ServiceNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.ImageNameMatchType = validateOrDefault(q.Filters.ImageNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.NodeNameMatchType = validateOrDefault(q.Filters.NodeNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.ContainerNameMatchType = validateOrDefault(q.Filters.ContainerNameMatchType, []string{"equals", "contains"}, "")

	q.Filters.OrderByColumn = validateOrDefault(q.Filters.OrderByColumn, []string{"name", "score", "score_v3", "published_timestamp", "impact"}, "name")
	q.Filters.OrderByType = validateOrDefault(q.Filters.OrderByType, []string{"asc", "desc"}, "desc")

	if r.Method == http.MethodGet {
		// For the GET request to /v1/vulasset, users have the ability to modify the sorting column during pagination.
		q.Filters.OrderByColumn = r.URL.Query().Get("orderbyColumn")
		q.Filters.OrderByType = r.URL.Query().Get("orderby")

		q.Filters.OrderByColumn = validateOrDefault(q.Filters.OrderByColumn, []string{"name", "score", "score_v3", "published_timestamp", "impact"}, "")
		q.Filters.OrderByType = validateOrDefault(q.Filters.OrderByType, []string{"asc", "desc"}, "")

		q.Filters.LastModifiedTime = getQueryParamInteger64(r, "lastmtime", 0)

		// quick filter
		q.Filters.QuickFilter = r.URL.Query().Get("qf")
		if q.Filters.QuickFilter != "" {
			q.Filters.ScoreType = r.URL.Query().Get("scoretype")
			q.Filters.ScoreType = validateOrDefault(q.Filters.ScoreType, []string{"v2", "v3"}, "v3")
		}
	}

	return q, nil
}

func (q *VulQueryFilter) GetAssestBasedFilters() map[string]int {
	stats := make(map[string]int)

	if (q.Filters.MatchType4Ns == "equals" || q.Filters.MatchType4Ns == "contains") && len(q.Filters.SelectedDomains) > 0 {
		stats[AssetRuleDomain] = 1
	}

	if (q.Filters.ServiceNameMatchType == "equals" || q.Filters.ServiceNameMatchType == "contains") && q.Filters.ServiceName != "" {
		stats[AssetRuleService] = 1
	}

	if (q.Filters.NodeNameMatchType == "equals" || q.Filters.NodeNameMatchType == "contains") && q.Filters.NodeName != "" {
		stats[AssetRuleNode] = 1
	}

	if (q.Filters.ImageNameMatchType == "equals" || q.Filters.ImageNameMatchType == "contains") && q.Filters.ImageName != "" {
		stats[AssetRuleImage] = 1
	}

	if (q.Filters.ContainerNameMatchType == "equals" || q.Filters.ContainerNameMatchType == "contains") && q.Filters.ContainerName != "" {
		stats[AssetRuleContainer] = 1
	}

	stats[AssetRulePlatform] = 1

	return stats
}

func FilterVulAssetsV2(allowed map[string]utils.Set, queryFilter *VulQueryFilter) ([]*DbVulAsset, int, []string, error) {
	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	perf := make([]string, 0)
	columns := []interface{}{"id", "type", "assetid", "idns", "vulsb"}

	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildAssetFilterWhereClause(queryFilter.Filters)).Prepared(true).ToSQL()
	log.WithFields(log.Fields{"statement": statement, "args": args}).Debug("GetVulAssetSessionV2, fetch assets")
	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, 0, perf, err
	}
	defer rows.Close()

	poolSize := queryFilter.ThreadCount
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))

	// key=cve_name
	start := time.Now()
	assetCount := 0
	dbVulAssets := make(map[string]*DbVulAsset, 0)
	var mux sync.Mutex
	for rows.Next() {
		var dbId int
		var assetType, assetid, idnsStr string
		var vulsBytes []byte
		err = rows.Scan(&dbId, &assetType, &assetid, &idnsStr, &vulsBytes)
		if err != nil {
			pool.StopAndWait()
			return nil, 0, perf, err
		}

		assetCount++

		switch assetType {
		case AssetPlatform:
			if !allowed[AssetPlatform].Contains(assetid) {
				continue
			}
		case AssetNode:
			if !allowed[AssetNode].Contains(assetid) {
				continue
			}
		case AssetWorkload:
			if !allowed[AssetWorkload].Contains(assetid) {
				continue
			}
		case AssetImage:
			if !allowed[AssetImage].Contains(assetid) {
				continue
			}
		}

		batchProcessVulAsset(pool, &mux, dbVulAssets, assetid, assetType, idnsStr, vulsBytes)
	}

	// Stop the pool and wait for all submitted tasks to complete
	pool.StopAndWait()

	elapsed := time.Since(start)
	perf = append(perf, fmt.Sprintf("2a, derive vuls from assets, assetCount=%d, dbVulAssets=%d, poolSize=%v, took=%v", assetCount, len(dbVulAssets), poolSize, elapsed))

	// foreach vulassset
	start = time.Now()
	nTotalCVE := 0
	var dataSlice []*DbVulAsset
	for _, vulasset := range dbVulAssets {
		if len(vulasset.WorkloadItems) == 0 && len(vulasset.NodeItems) == 0 &&
			len(vulasset.ImageItems) == 0 && len(vulasset.PlatformItems) == 0 {
			continue
		}

		nTotalCVE++

		// CVE details might be incomplete during Consul restore, do this first
		fillCVERecordV2(vulasset)

		// CVE based filter
		if !meetCVEBasedFilter(vulasset, queryFilter) {
			vulasset.MeetSearch = false // for static data summary
			dataSlice = append(dataSlice, vulasset)
			continue
		}

		// check viewType
		applyViewTypeFilter(vulasset, queryFilter)
		if vulasset.Skip {
			continue
		}

		vulasset.Workloads, _ = convertToJSON(vulasset.WorkloadItems)
		vulasset.Nodes, _ = convertToJSON(vulasset.NodeItems)
		vulasset.Images, _ = convertToJSON(vulasset.ImageItems)
		vulasset.Platforms, _ = convertToJSON(vulasset.PlatformItems)

		vulasset.MeetSearch = true
		vulasset.ImpactWeight = len(vulasset.WorkloadItems) + len(vulasset.NodeItems) + len(vulasset.ImageItems) + len(vulasset.PlatformItems)
		dataSlice = append(dataSlice, vulasset)
	}

	elapsed = time.Since(start)
	perf = append(perf, fmt.Sprintf("2c, process vuls, took=%v", elapsed))

	return dataSlice, nTotalCVE, perf, nil
}

func batchProcessVulAsset(pool *pond.WorkerPool, mu *sync.Mutex, dbVulAssets map[string]*DbVulAsset, assetid, assetType, idnsStr string, vulsBytes []byte) {
	pool.Submit(func() {
		cveList := funcGetCVEList(vulsBytes, idnsStr) // this function will do VPF and remove filtered data..
		for _, c := range cveList {
			name, dbkey, fix := parseCVEDbKey(c)

			mu.Lock()
			if _, ok := dbVulAssets[name]; !ok {
				dbVulAssets[name] = &DbVulAsset{
					Name:          name,
					WorkloadItems: make([]string, 0),
					NodeItems:     make([]string, 0),
					ImageItems:    make([]string, 0),
					PlatformItems: make([]string, 0),
					DBKey:         dbkey,
				}
			}
			dbVulAsset := dbVulAssets[name]

			switch assetType {
			case AssetPlatform:
				dbVulAsset.PlatformItems = append(dbVulAsset.PlatformItems, assetid)
			case AssetNode:
				dbVulAsset.NodeItems = append(dbVulAsset.NodeItems, assetid)
			case AssetWorkload:
				dbVulAsset.WorkloadItems = append(dbVulAsset.WorkloadItems, assetid)
			case AssetImage:
				dbVulAsset.ImageItems = append(dbVulAsset.ImageItems, assetid)
			}

			if fix == "wf" {
				dbVulAsset.F_withFix = 1
			}

			mu.Unlock()
		}
	})
}

func catchMeViewType() {
	fmt.Println()
}

func applyViewTypeFilter(vulAsset *DbVulAsset, queryFilter *VulQueryFilter) {
	vt := queryFilter.Filters.ViewType

	// DEBUG
	if queryFilter.Filters.DebugCVEName != "" {
		if strings.Contains(strings.ToLower(vulAsset.Name), strings.ToLower(queryFilter.Filters.DebugCVEName)) {
			catchMeViewType()
		}
	}

	keep := false
	if vt == "all" {
		keep = true
	} else if vt == "containers" && len(vulAsset.WorkloadItems) > 0 {
		keep = true
	} else if vt == "infrastructure" && (len(vulAsset.NodeItems) > 0 || len(vulAsset.PlatformItems) > 0) {
		keep = true
	} else if vt == "registry" && len(vulAsset.ImageItems) > 0 {
		keep = true
	}

	vulAsset.Skip = !keep
}

func GetSessionMatchedVuls(allowed map[string]utils.Set, sessionToken string, LastModifiedTime int64) (map[string]*DbVulAsset, map[string][]string, error) {
	sessionTemp := formatSessionTempTableName(sessionToken)

	dialect := goqu.Dialect("sqlite3")
	columns := []interface{}{"name", "severity", "description", "packages", "link", "score",
		"vectors", "score_v3", "vectors_v3", "published_timestamp", "last_modified_timestamp",
		"workloads", "nodes", "images", "platforms"}

	statement, args, _ := dialect.From(sessionTemp).Select(columns...).Prepared(true).ToSQL()

	queryStat, err := GetQueryStat(sessionToken)
	if err != nil {
		return nil, nil, err
	}

	db := memoryDbHandle
	if queryStat.FileDBReady == 1 {
		db, err = openSessionFileDb(sessionToken)
		if err != nil {
			return nil, nil, err
		}
		defer db.Close() // close it after done
	}

	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	workloadSet := utils.NewSet()
	nodeSet := utils.NewSet()
	imageSet := utils.NewSet()
	platformSet := utils.NewSet()

	assets := make(map[string][]string, 0)

	records := make(map[string]*DbVulAsset)
	for rows.Next() {
		vulasset := &DbVulAsset{}
		err = rows.Scan(&vulasset.Name, &vulasset.Severity, &vulasset.Description, &vulasset.Packages, &vulasset.Link, &vulasset.Score,
			&vulasset.Vectors, &vulasset.ScoreV3, &vulasset.VectorsV3, &vulasset.PublishedTS, &vulasset.LastModTS,
			&vulasset.Workloads, &vulasset.Nodes, &vulasset.Images, &vulasset.Platforms)
		if err != nil {
			return nil, nil, err
		}

		// this fitler (CVE based) is specific to asset view
		if (LastModifiedTime == 0) || vulasset.LastModTS > LastModifiedTime {
			records[vulasset.Name] = vulasset

			addAssetsToSet(vulasset.Workloads, workloadSet)
			addAssetsToSet(vulasset.Nodes, nodeSet)
			addAssetsToSet(vulasset.Images, imageSet)
			addAssetsToSet(vulasset.Platforms, platformSet)
		}
	}

	assets[AssetWorkload] = allowed[AssetWorkload].Intersect(workloadSet).ToStringSlice()
	assets[AssetNode] = allowed[AssetNode].Intersect(nodeSet).ToStringSlice()
	assets[AssetImage] = allowed[AssetImage].Intersect(imageSet).ToStringSlice()
	assets[AssetPlatform] = allowed[AssetPlatform].Intersect(platformSet).ToStringSlice()

	return records, assets, nil
}

func addAssetsToSet(assetsIDStr string, assetSet utils.Set) {
	items := make([]string, 0)
	err := json.Unmarshal([]byte(assetsIDStr), &items)
	if err == nil {
		for _, v := range items {
			assetSet.Add(v)
		}
	}
}

func PopulateSessionToFile(sessionToken string, vulAssets []*DbVulAsset) error {
	// create a new db file using the sessionToken as filename
	db, err := createSessionFileDb(sessionToken)
	if err != nil {
		return err
	}
	defer db.Close()

	err = createSessionVulAssetTable(db, sessionToken)
	if err != nil {
		return err
	}

	err = populateSession(db, sessionToken, vulAssets)
	if err != nil {
		return err
	}

	// update the queryState.FileDb_Ready = 1 in the nvdb.db
	err = setFileDbState(sessionToken, 1)
	if err != nil {
		return err
	}

	// delete session table in memory, allow some time for the ongoing read operation to complete before proceeding
	time.Sleep(30 * time.Second)
	deleteSessionTempTableInMemDb(sessionToken)

	return nil
}

func PopulateSessionVulAssets(sessionToken string, vulAssets []*DbVulAsset, memoryDb bool) error {
	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
	}

	return populateSession(db, sessionToken, vulAssets)
}

func GetVulAssetSessionV2(requesetQuery *VulQueryFilter) (*api.RESTVulnerabilityAssetDataV2, utils.Set, error) {
	getOrderColumn := func(filters *api.VulQueryFilterViewModel) exp.OrderedExpression {
		column := "name"
		if filters.OrderByColumn == "name" || filters.OrderByColumn == "score" || filters.OrderByColumn == "score_v3" || filters.OrderByColumn == "published_timestamp" {
			column = filters.OrderByColumn
		}

		if filters.OrderByColumn == "impact" {
			column = "impact_weight"
		}

		if filters.OrderByType == "desc" { // asc, desc
			return goqu.I(column).Desc()
		}
		return goqu.I(column).Asc()
	}

	buildQuickFilterWhereClause := func(queryFilter *VulQueryFilter) exp.ExpressionList {
		if queryFilter.Filters.QuickFilter != "" {
			nameExp := goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))

			scoreColumn := "score_str"
			if queryFilter.Filters.ScoreType == "v3" {
				scoreColumn = "scorev3_str"
			}

			scoreExp := goqu.C(scoreColumn).Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			return goqu.Or(nameExp, scoreExp)
		}

		return goqu.And(goqu.Ex{})
	}

	sessionToken := requesetQuery.QueryToken
	start := requesetQuery.QueryStart
	row := requesetQuery.QueryCount
	threadCount := requesetQuery.ThreadCount

	sessionTemp := formatSessionTempTableName(sessionToken)

	columns := []interface{}{"name", "severity", "description", "link", "score",
		"vectors", "score_v3", "vectors_v3", "published_timestamp", "last_modified_timestamp",
		"workloads", "nodes", "images", "platforms"}

	queryStat, err := GetQueryStat(sessionToken)
	if err != nil {
		return nil, nil, err
	}

	queryFilter := &VulQueryFilter{}
	err = json.Unmarshal([]byte(queryStat.Data1), &queryFilter)
	if err != nil {
		return nil, nil, err
	}

	// check if we need to overwrite sort column
	if requesetQuery.Filters.OrderByColumn != "" && requesetQuery.Filters.OrderByType != "" {
		queryFilter.Filters.OrderByColumn = requesetQuery.Filters.OrderByColumn
		queryFilter.Filters.OrderByType = requesetQuery.Filters.OrderByType
	}

	quickFilterExp := buildQuickFilterWhereClause(requesetQuery)

	dialect := goqu.Dialect("sqlite3")
	var statement string
	var args []interface{}
	if row == -1 {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Where(quickFilterExp).Order(getOrderColumn(queryFilter.Filters)).Prepared(true).ToSQL() // select all
	} else {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Where(quickFilterExp).Order(getOrderColumn(queryFilter.Filters)).Limit(uint(row)).Offset(uint(start)).Prepared(true).ToSQL()
	}

	// if file db is ready, use it..
	tStart := time.Now()
	// db := memoryDbHandle
	var db *sql.DB
	if queryStat.FileDBReady == 1 {
		db, err = openSessionFileDb(sessionToken)
		if err != nil {
			return nil, nil, err
		}
		defer db.Close() // close it after done

		memTables := GetAllTableInMemoryDb()
		log.WithFields(log.Fields{"memTables": memTables}).Debug("GetVulAssetSessionV2, use filedb")
	} else {
		db = memoryDbHandle
		memTables := GetAllTableInMemoryDb()
		log.WithFields(log.Fields{"memTables": memTables}).Debug("GetVulAssetSessionV2, use memdb")
	}

	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	allAssets := utils.NewSet()

	resp := &api.RESTVulnerabilityAssetDataV2{
		Vuls:               make([]*api.RESTVulnerabilityAssetV2, 0),
		PerfStats:          make([]string, 0),
		QuickFilterMatched: 0,
	}

	cvePackages := make(map[string]map[string]utils.Set) // primary key = cve name

	// step-1: get the CVEs for this batch
	for rows.Next() {
		record := &api.RESTVulnerabilityAssetV2{}

		var workloads, nodes, platforms, images string
		var score, scorev3 int
		err := rows.Scan(&record.Name, &record.Severity, &record.Description, &record.Link, &score,
			&record.Vectors, &scorev3, &record.VectorsV3, &record.PublishedTS, &record.LastModTS,
			&workloads, &nodes, &images, &platforms)
		if err != nil {
			return nil, nil, err
		}

		// for vul printout
		if requesetQuery.Filters.LastModifiedTime > 0 && record.LastModTS < requesetQuery.Filters.LastModifiedTime {
			continue
		}

		record.Score = float32(score) / 10.0
		record.ScoreV3 = float32(scorev3) / 10.0

		record.WorkloadIDs = parseJsonStrToSlice(workloads)
		record.NodesIDs = parseJsonStrToSlice(nodes)
		record.ImagesIDs = parseJsonStrToSlice(images)
		record.PlatformsIDs = parseJsonStrToSlice(platforms)

		assets := utils.NewSet()
		assets = assets.Union(utils.NewSetFromSliceKind(record.WorkloadIDs))
		assets = assets.Union(utils.NewSetFromSliceKind(record.NodesIDs))
		assets = assets.Union(utils.NewSetFromSliceKind(record.ImagesIDs))
		assets = assets.Union(utils.NewSetFromSliceKind(record.PlatformsIDs))

		// keep all assets
		allAssets = allAssets.Union(assets)
		resp.Vuls = append(resp.Vuls, record)

		cvePackages[record.Name] = make(map[string]utils.Set) // key = cve name
	}
	elapsed := time.Since(tStart)
	resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("1/4: get %d vuls from session (file=%d), took=%v", len(resp.Vuls), queryStat.FileDBReady, elapsed))

	// step-2: fetch assets to compile package information
	tStart = time.Now()
	assets := allAssets.ToStringSlice()
	expAssets := goqu.Ex{"assetid": assets}
	columns = []interface{}{"idns", "vulsb"}

	statement, args, _ = dialect.From(Table_assetvuls).Select(columns...).Where(goqu.And(expAssets)).Prepared(true).ToSQL()
	rows, err = dbHandle.Query(statement, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	poolSize := threadCount
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))
	var mux sync.Mutex

	var nAssets int
	for rows.Next() {
		var vulsBytes []byte
		var idnsStr string
		err = rows.Scan(&idnsStr, &vulsBytes)
		if err != nil {
			pool.StopAndWait()
			return nil, nil, err
		}

		nAssets++
		batchProessFillVulPackages(pool, &mux, cvePackages, vulsBytes, idnsStr, nil)
	}

	// Stop the pool and wait for all submitted tasks to complete
	pool.StopAndWait()

	elapsed = time.Since(tStart)
	resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("2/4: get %d assets for packages, poolSize=%v, took=%v", nAssets, poolSize, elapsed))

	// step-3: foreach CVE, consolidate packages info
	tStart = time.Now()
	for _, vul := range resp.Vuls {
		vul.Packages = make(map[string][]api.RESTVulnPackageVersion)
		for pkg, vers := range cvePackages[vul.Name] {
			if _, ok := vul.Packages[pkg]; !ok {
				vul.Packages[pkg] = make([]api.RESTVulnPackageVersion, vers.Cardinality()) // not exist..
			}

			j := 0
			for v := range vers.Iter() {
				vul.Packages[pkg][j] = v.(api.RESTVulnPackageVersion)
				j++
			}
		}
	}
	elapsed = time.Since(tStart)
	resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("3/4: consolidate packages, took=%v", elapsed))

	// get quick filter count for navigation
	if requesetQuery.Filters.QuickFilter != "" {
		sql, _, _ := goqu.From(sessionTemp).Select(goqu.COUNT("*").As("count")).Where(quickFilterExp).ToSQL()

		rows, err := db.Query(sql)
		if err != nil {
			return nil, nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var nCount int
			err := rows.Scan(&nCount)
			if err != nil {
				return nil, nil, err
			}
			resp.QuickFilterMatched = nCount
		}
	}

	return resp, allAssets, nil
}

func CeateSessionVulAssetTable(sessionToken string, memoryDb bool) error {
	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
	}

	err := createSessionVulAssetTable(db, sessionToken)
	if err != nil {
		return err
	}

	// Check the presence of the recently created table.
	// If the table does not exist, recreate it to workaround a [potential bug] in SQLite library,
	// where table creation may fail without raising any error.
	if memoryDb {
		memTables := GetAllTableInMemoryDb()
		if !strings.Contains(memTables, sessionToken) {
			reopenMemoryDb()

			log.WithFields(log.Fields{"sessionToken": sessionToken}).Error("CeateSessionVulAssetTable error, missing session table in memdb. Recreate it.")
			err := createSessionVulAssetTable(memoryDbHandle, sessionToken)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func CreateSessionAssetTable(sessionToken string, memoryDb bool) error {
	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
	}

	err := createSessionAssetTable(db, sessionToken)
	if err != nil {
		return err
	}

	return nil
}

func meetCVEBasedFilter(vulasset *DbVulAsset, qf *VulQueryFilter) bool {
	expectedMeetCount := 0
	meetCount := 0

	q := qf.Filters

	if q.PackageType == "withFix" || q.PackageType == "withoutFix" {
		expectedMeetCount += 1

		if q.PackageType == "withFix" && vulasset.F_withFix == 1 {
			meetCount += 1
		}

		if q.PackageType == "withoutFix" && vulasset.F_withFix == 0 {
			meetCount += 1
		}
	}

	if (q.PublishedType == "before" || q.PublishedType == "after") && q.PublishedTime > 0 {
		expectedMeetCount += 1

		if q.PublishedType == "before" && q.PublishedTime >= vulasset.PublishedTS {
			meetCount += 1
		}

		if q.PublishedType == "after" && q.PublishedTime < vulasset.PublishedTS {
			meetCount += 1
		}
	}

	// ScoreV2 and ScoreV3 can be used together
	if len(q.ScoreV2) == 2 && q.ScoreV2[0] <= q.ScoreV2[1] {
		expectedMeetCount += 1
		if vulasset.Score <= q.ScoreV2[1]*10 && vulasset.Score >= q.ScoreV2[0]*10 {
			meetCount += 1
		}
	}

	if len(q.ScoreV3) == 2 && q.ScoreV3[0] <= q.ScoreV3[1] {
		expectedMeetCount += 1
		if vulasset.ScoreV3 <= q.ScoreV3[1]*10 && vulasset.ScoreV3 >= q.ScoreV3[0]*10 {
			meetCount += 1
		}
	}

	// profile, ==  severityType, possible values are [all/high/medium/low]
	if q.SeverityType == "high" {
		expectedMeetCount += 1

		if vulasset.Severity == "High" {
			meetCount += 1
		}
	} else if q.SeverityType == "medium" {
		expectedMeetCount += 1

		if vulasset.Severity == "Medium" {
			meetCount += 1
		}
	} else if q.SeverityType == "low" {
		expectedMeetCount += 1

		if vulasset.Severity == "Low" {
			meetCount += 1
		}
	}

	if q.LastModifiedTime > 0 {
		expectedMeetCount += 1

		if vulasset.LastModTS > q.LastModifiedTime {
			meetCount += 1
		}
	}

	return expectedMeetCount == meetCount
}

func createSessionFileDb(sessionToken string) (*sql.DB, error) {
	tableName := formatSessionTempTableName(sessionToken)
	dbfile := fmt.Sprintf("%s/%s", dbFile_Folder, tableName)

	os.Remove(dbfile)

	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func openSessionFileDb(sessionToken string) (*sql.DB, error) {
	tableName := formatSessionTempTableName(sessionToken)
	dbfile := fmt.Sprintf("%s/%s", dbFile_Folder, tableName)

	if _, err := os.Stat(dbfile); err == nil {
		db, err := sql.Open("sqlite3", dbfile)
		if err != nil {
			return nil, err
		}
		return db, nil
	}
	return nil, errors.New("db file doesn't exist")
}

func deleteSessionFileDb(sessionToken string) error {
	tableName := formatSessionTempTableName(sessionToken)
	dbfile := fmt.Sprintf("%s/%s", dbFile_Folder, tableName)

	err := os.Remove(dbfile)
	if err != nil {
		return err
	}
	return nil
}

func createSessionVulAssetTable(db *sql.DB, sessionToken string) error {
	tableName := formatSessionTempTableName(sessionToken)

	columns := getVulassetSchema()
	sql := fmt.Sprintf("CREATE TABLE %s (%s);", tableName, strings.Join(columns, ","))

	_, err := db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

func createSessionAssetTable(db *sql.DB, sessionToken string) error {
	tableName := formatSessionTempTableName(sessionToken)

	columns := getAssetvulSchema(false)
	sql := fmt.Sprintf("CREATE TABLE %s (%s);", tableName, strings.Join(columns, ","))

	_, err := db.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

func populateSession(db *sql.DB, sessionToken string, vulAssets []*DbVulAsset) error {
	tableName := formatSessionTempTableName(sessionToken)

	columns := []string{"name", "severity", "description", "packages", "link", "score", "vectors", "score_v3", "vectors_v3",
		"published_timestamp", "last_modified_timestamp", "workloads", "nodes", "images", "platforms", "cve_sources", "f_withFix", "f_profile", "debuglog", "score_str", "scorev3_str", "impact_weight"}

	varSlice := make([]string, len(columns))
	for i := range varSlice {
		varSlice[i] = "?"
	}

	sql := fmt.Sprintf("insert into %s (%s) values (%s);", tableName, strings.Join(columns, ","), strings.Join(varSlice, ","))

	stmt, err := db.Prepare(sql)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, vulAsset := range vulAssets {
		if !vulAsset.MeetSearch {
			continue
		}

		debugLog := ""
		vulAsset.CVESources = ""

		_, err = stmt.Exec(vulAsset.Name, vulAsset.Severity, vulAsset.Description, vulAsset.Packages,
			vulAsset.Link, vulAsset.Score, vulAsset.Vectors, vulAsset.ScoreV3, vulAsset.VectorsV3, vulAsset.PublishedTS, vulAsset.LastModTS,
			vulAsset.Workloads, vulAsset.Nodes, vulAsset.Images, vulAsset.Platforms, vulAsset.CVESources,
			vulAsset.F_withFix, vulAsset.F_profile, debugLog,
			formatScoreToStr(vulAsset.Score), formatScoreToStr(vulAsset.ScoreV3), vulAsset.ImpactWeight)
		if err != nil {
			return err
		}
	}

	return nil
}

func fillCVERecordV2(record *DbVulAsset) error {
	// if it's already valid then skip
	if record.Description != "" && record.PublishedTS != 0 {
		return nil
	}

	vulAsset := funcGetCveRecord(record.Name, record.DBKey, "")
	if vulAsset != nil {
		record.Severity = vulAsset.Severity
		record.Description = vulAsset.Description
		record.Link = vulAsset.Link
		record.Score = vulAsset.Score
		record.Vectors = vulAsset.Vectors
		record.ScoreV3 = vulAsset.ScoreV3
		record.VectorsV3 = vulAsset.VectorsV3
		record.PublishedTS = vulAsset.PublishedTS
		record.LastModTS = vulAsset.LastModTS
	}

	return nil
}

func GetTopAssets(allowed map[string]utils.Set, assetType string, topN int) ([]*api.AssetCVECount, error) {
	allowedAssets := []string{}

	buildWhereClause := func(assetType string, allowedID []string) exp.ExpressionList {
		part1_type := goqu.Ex{
			"type": assetType,
		}

		part2_allowed := goqu.Ex{}
		if len(allowedID) > 0 {
			part2_allowed = goqu.Ex{
				"assetid": allowedID,
			}
		}
		return goqu.And(part1_type, part2_allowed)
	}

	if assetType == AssetImage || assetType == AssetNode {
		allowedAssets = allowed[assetType].ToStringSlice()
	} else {
		return nil, errors.New("unsupport type")
	}

	tops := make([]*api.AssetCVECount, 0)

	if len(allowedAssets) == 0 {
		return tops, nil
	}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select("assetid", "name", "cve_high", "cve_medium", "cve_low").Where(buildWhereClause(assetType, allowedAssets)).Order(goqu.C("cve_count").Desc()).Limit(5).Prepared(true).ToSQL()

	db := dbHandle
	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		record := &api.AssetCVECount{
			Critical: -1,
		}
		err = rows.Scan(&record.ID, &record.DisplayName, &record.High, &record.Medium, &record.Low)

		if err != nil {
			return nil, err
		}

		tops = append(tops, record)
	}

	return tops, nil
}

func DeleteAssetByID(assetType string, assetid string) error {
	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	// delete asset in assetvul table
	sql, args, _ := dialect.Delete(Table_assetvuls).Where(goqu.Ex{"type": assetType, "assetid": assetid}).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return err
	}
	return nil
}

func shouleRetry(err error) bool {
	// ref: https://sourcegraph.com/github.com/juicedata/juicefs/-/blob/pkg/meta/sql.go
	// case "sqlite3":
	// 	return errors.Is(err, errBusy) || strings.Contains(msg, "database is locked")

	msg := strings.ToLower(err.Error())
	return errors.Is(err, sqlite3.ErrBusy) || strings.Contains(msg, "database is locked")
}

func buildAssetFilterWhereClause(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {

	if hasNamespaceFilter(queryFilter) {
		return buildWhereClauseForWorkload(nil, queryFilter)
	}

	exp1 := buildWhereClauseForImage(nil, queryFilter)
	exp2 := buildWhereClauseForWorkload(nil, queryFilter)
	exp3 := buildWhereClauseForNode(nil, queryFilter)
	exp4 := buildWhereClauseForPlatform(nil, queryFilter)

	return goqu.Or(exp1, exp2, exp3, exp4)
}

func batchProessFillVulPackages(pool *pond.WorkerPool, mu *sync.Mutex, cvePackages map[string]map[string]utils.Set, vulsBytes []byte, idnsStr string, cveList *[]string) {
	pool.Submit(func() {
		funcFillVulPackages(mu, cvePackages, vulsBytes, idnsStr, cveList, nil)
	})
}
