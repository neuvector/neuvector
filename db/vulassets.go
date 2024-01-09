package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
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

	// for performance test
	q.CreateDummyAsset_Enable = getQueryParamInteger(r, "createdummyasset", 0)
	if q.CreateDummyAsset_Enable == 1 {
		q.CreateDummyAsset_CVE = getQueryParamInteger(r, "howmany_cve", 0)
		q.CreateDummyAsset_Asset = getQueryParamInteger(r, "howmany_asset", 0)
		q.CreateDummyAsset_CVE_per_asset = getQueryParamInteger(r, "howmany_cve_per_asset", 0)
	}

	if r.Method == http.MethodPatch || r.Method == http.MethodPost {
		body, err := ioutil.ReadAll(r.Body)
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
	q.Filters.PackageType = validateOrDefault(q.Filters.PackageType, []string{"all", "withfix", "withoutfix"}, "all")
	q.Filters.PublishedType = validateOrDefault(q.Filters.PublishedType, []string{"all", "before", "after"}, "all")

	q.Filters.ServiceNameMatchType = validateOrDefault(q.Filters.ServiceNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.ImageNameMatchType = validateOrDefault(q.Filters.ImageNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.NodeNameMatchType = validateOrDefault(q.Filters.NodeNameMatchType, []string{"equals", "contains"}, "")
	q.Filters.ContainerNameMatchType = validateOrDefault(q.Filters.ContainerNameMatchType, []string{"equals", "contains"}, "")

	q.Filters.OrderByColume = validateOrDefault(q.Filters.OrderByColume, []string{"name", "score", "score_v3", "published_timestamp"}, "name")
	q.Filters.OrderByType = validateOrDefault(q.Filters.OrderByType, []string{"asc", "desc"}, "desc")

	return q, nil
}

func (q *VulQueryFilter) GetAssestBasedFilters() map[string]int {
	stats := make(map[string]int)

	if q.Filters.MatchType4Ns == "equals" || q.Filters.MatchType4Ns == "contains" && len(q.Filters.SelectedDomains) > 0 {
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

func catchMeGetAll() {
	fmt.Println()
}

func FilterVulAssets(allowed map[string]utils.Set, queryFilter *VulQueryFilter, filteredMap map[string]bool) ([]*DbVulAsset, int, error) {
	dialect := goqu.Dialect("sqlite3")

	columns := getVulassetColumns()

	// limitation: CVE content might be empty due to Consul restore process, so we cannot do CVS based filter directly on db
	statement, args, _ := dialect.From(Table_vulassets).Select(columns...).Prepared(true).ToSQL()
	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// execute asset-based filter
	matchedAssets, err := applyAssetBasedFilters(allowed, queryFilter)
	if err != nil {
		return nil, 0, err
	}

	nTotalCVE := 0
	records := make([]*DbVulAsset, 0)
	for rows.Next() {
		nTotalCVE++
		vulasset := &DbVulAsset{
			DebugLog: make([]string, 0),
		}

		var dummy_debuglog, dummy_scoreStr, dummy_scorev3Str string
		err = rows.Scan(&vulasset.Db_ID, &vulasset.Name, &vulasset.Severity, &vulasset.Description, &vulasset.Packages,
			&vulasset.Link, &vulasset.Score, &vulasset.Vectors, &vulasset.ScoreV3, &vulasset.VectorsV3,
			&vulasset.PublishedTS, &vulasset.LastModTS,
			&vulasset.Workloads, &vulasset.Nodes, &vulasset.Images, &vulasset.Platforms,
			&vulasset.CVESources,
			&vulasset.F_withFix, &vulasset.F_profile, &dummy_debuglog, &dummy_scoreStr, &dummy_scorev3Str)

		if err != nil {
			return nil, 0, err
		}

		// DEBUG
		if queryFilter.Filters.DebugCVEName != "" {
			if strings.Contains(strings.ToLower(vulasset.Name), strings.ToLower(queryFilter.Filters.DebugCVEName)) {
				catchMeGetAll()
			}
		}

		// CVE details might be incomplete, do this first
		fillCVERecord(vulasset)

		// do CVE based filter
		if !meetCVEBasedFilter(vulasset, queryFilter) {
			vulasset.MeetSearch = false // for static data summary
			records = append(records, vulasset)
			continue
		}

		// check allowed and VPF
		filterAllowedAssets(vulasset, allowed, filteredMap)
		if vulasset.Skip {
			continue // if no any asset left, then we can skip this CVE.
		}

		// asset-based filter
		evaluateAssetBasedFilters(vulasset, matchedAssets, queryFilter)
		if vulasset.Skip {
			vulasset.MeetSearch = false
			records = append(records, vulasset)
			continue
		}

		// check viewType, if not matched view type, then we can skip this CVE.
		applyViewTypeFilter(vulasset, queryFilter)
		if vulasset.Skip {
			continue
		}

		vulasset.MeetSearch = true
		records = append(records, vulasset)
	}

	return records, nTotalCVE, nil
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

func GetSessionMatchedVuls(sessionToken string, LastModifiedTime int64) (map[string]*DbVulAsset, map[string][]string, error) {
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

	allowed := make(map[string][]string, 0)

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

	allowed[AssetWorkload] = workloadSet.ToStringSlice()
	allowed[AssetNode] = nodeSet.ToStringSlice()
	allowed[AssetImage] = imageSet.ToStringSlice()
	allowed[AssetPlatform] = platformSet.ToStringSlice()

	return records, allowed, nil
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

	// delete session table in memory
	// do not delete at this moment, let the cleanup mechanism do it
	// deleteSessionTempTableInMemDb(sessionToken)

	return nil
}

func PopulateSessionVulAssets(sessionToken string, vulAssets []*DbVulAsset, memoryDb bool) error {
	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
		memdbMutex.Lock()
		defer memdbMutex.Unlock()
	}

	return populateSession(db, sessionToken, vulAssets)
}

func PopulateVulAsset(resType ResourceType, resourceID string, vul *api.RESTVulnerability, baseOS string) error {
	if dbHandle == nil {
		return errors.New("db is not initialized")
	}

	vulasset, err := getVulAssetByName(vul.Name)
	if err != nil {
		// not exist, need to create a new one
		vulasset = &DbVulAsset{
			Name:        vul.Name,
			Severity:    vul.Severity,
			Description: vul.Description,
			Link:        vul.Link,
			Score:       int(vul.Score * 10),
			Vectors:     vul.Vectors,
			ScoreV3:     int(vul.ScoreV3 * 10),
			VectorsV3:   vul.VectorsV3,
			PublishedTS: vul.PublishedTS,
			LastModTS:   vul.LastModTS,
		}
	}

	err = addVulProperties(resType, resourceID, vul, vulasset, baseOS)
	if err != nil {
		return err
	}

	_, err = updateVulAsset(vulasset, "", false)
	if err != nil {
		return err
	}

	return nil
}

func GetVulAssetSession(start, row int, sessionToken string) (*api.RESTVulnerabilityAssetDataV2, utils.Set, error) {
	sessionTemp := formatSessionTempTableName(sessionToken)

	columns := []interface{}{"name", "severity", "description", "packages", "link", "score",
		"vectors", "score_v3", "vectors_v3", "published_timestamp", "last_modified_timestamp",
		"workloads", "nodes", "images", "platforms", "cve_sources"}

	queryStat, err := GetQueryStat(sessionToken)
	if err != nil {
		return nil, nil, err
	}

	queryFilter := &api.QuerySessionRequest{}
	err = json.Unmarshal([]byte(queryStat.Data1), &queryFilter)
	if err != nil {
		return nil, nil, err
	}

	dialect := goqu.Dialect("sqlite3")
	var statement string
	args := make([]interface{}, 0)
	if row == -1 {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Order(getOrderColumn(queryFilter.Filters)).Prepared(true).ToSQL() // select all
	} else {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Order(getOrderColumn(queryFilter.Filters)).Limit(uint(row)).Offset(uint(start)).Prepared(true).ToSQL()
	}

	// if file db is ready, use it..
	tStart := time.Now()
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

	allAssets := utils.NewSet()

	resp := &api.RESTVulnerabilityAssetDataV2{
		Vuls:      make([]*api.RESTVulnerabilityAssetV2, 0),
		PerfStats: make([]string, 0),
	}

	for rows.Next() {
		record := &api.RESTVulnerabilityAssetV2{}

		var packages, workloads, nodes, platforms, images, cve_sources string
		var score, scorev3 int
		err := rows.Scan(&record.Name, &record.Severity, &record.Description, &packages, &record.Link, &score,
			&record.Vectors, &scorev3, &record.VectorsV3, &record.PublishedTS, &record.LastModTS,
			&workloads, &nodes, &images, &platforms, &cve_sources)
		if err != nil {
			return nil, nil, err
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

		// handle package
		distinctPackages := make(map[string]utils.Set)

		packages2 := make(map[string][]DbVulnResourcePackageVersion)
		if packages != "" {
			err := json.Unmarshal([]byte(packages), &packages2)
			if err != nil {
				return nil, nil, err
			}
		}

		record.Packages = make(map[string][]api.RESTVulnPackageVersion, 0)
		for packageName, items := range packages2 {
			if _, ok := record.Packages[packageName]; !ok {
				record.Packages[packageName] = make([]api.RESTVulnPackageVersion, 0) // not exist..
			}

			if _, ok := distinctPackages[packageName]; !ok {
				distinctPackages[packageName] = utils.NewSet()
			}

			for _, item := range items {
				// remove package if its asset-id is not in assets the final assets
				// we postpone it here for better performance..
				if !assets.Contains(item.ResourceID) {
					continue
				}

				// get distinct packages (under the same package key)
				if !distinctPackages[packageName].Contains(item.PackageVersion + item.FixedVersion) {
					distinctPackages[packageName].Add(item.PackageVersion + item.FixedVersion)

					record.Packages[packageName] = append(record.Packages[packageName], api.RESTVulnPackageVersion{
						PackageVersion: item.PackageVersion,
						FixedVersion:   item.FixedVersion,
					})
				}
			}
		}

		// keep all assets
		allAssets = allAssets.Union(assets)
		resp.Vuls = append(resp.Vuls, record)
	}

	elapsed := time.Since(tStart)
	resp.PerfStats = append(resp.PerfStats, fmt.Sprintf("1/2: get %d vuls from session (file=%d), took=%v", len(resp.Vuls), queryStat.FileDBReady, elapsed))

	return resp, allAssets, nil
}

func CeateSessionVulAssetTable(sessionToken string, memoryDb bool) error {
	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
		memdbMutex.Lock()
		defer memdbMutex.Unlock()
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

func getVulAssetByName(cveName string) (*DbVulAsset, error) {
	columns := []interface{}{"id", "name", "packages", "workloads", "nodes", "images", "platforms", "cve_sources"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From("vulassets").Select(columns...).Where(goqu.C("name").Eq(cveName)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vulasset := &DbVulAsset{
		Name: cveName,
	}
	for rows.Next() {
		err = rows.Scan(&vulasset.Db_ID, &vulasset.Name, &vulasset.Packages, &vulasset.Workloads, &vulasset.Nodes,
			&vulasset.Images, &vulasset.Platforms, &vulasset.CVESources)
		if err != nil {
			return nil, err
		}

		return vulasset, nil
	}
	return nil, errors.New("no such cve name")
}

func meetCVEBasedFilter(vulasset *DbVulAsset, qf *VulQueryFilter) bool {
	expectedMeetCount := 0
	meetCount := 0

	q := qf.Filters

	if q.PackageType == "withfix" || q.PackageType == "withoutfix" {
		expectedMeetCount += 1

		if q.PackageType == "withfix" && vulasset.F_withFix == 1 {
			meetCount += 1
		}

		if q.PackageType == "withoutfix" && vulasset.F_withFix == 0 {
			meetCount += 1
		}
	}

	if q.PublishedType == "before" || q.PublishedType == "after" {
		expectedMeetCount += 1

		if q.PublishedType == "before" && q.PublishedTime < vulasset.PublishedTS {
			meetCount += 1
		}

		if q.PublishedType == "after" && q.PublishedTime >= vulasset.PublishedTS {
			meetCount += 1
		}
	}

	//TODO: do we have scorev3 filter?
	if q.Scorev3_max > 0 {
		expectedMeetCount += 1
		// note the score range does NOT not have equal !
		if vulasset.ScoreV3 < int(q.Scorev3_max*10) && vulasset.ScoreV3 > int(q.Scorev3_min*10) {
			meetCount += 1
		}
	}

	// score v2
	if q.Scorev2_max > 0 {
		expectedMeetCount += 1
		if vulasset.Score < int(q.Scorev2_max*10) && vulasset.Score > int(q.Scorev2_min*10) {
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

	if q.QuickFilter != "" {
		expectedMeetCount += 1

		var scoreStr string
		if q.ScoreType == "v2" {
			scoreStr = formatScoreToStr(vulasset.Score)
		} else if q.ScoreType == "v3" {
			scoreStr = formatScoreToStr(vulasset.ScoreV3)
		}

		if strings.Contains(strings.ToLower(vulasset.Name), strings.ToLower(q.QuickFilter)) ||
			strings.Contains(scoreStr, q.QuickFilter) {
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

func populateSession(db *sql.DB, sessionToken string, vulAssets []*DbVulAsset) error {
	tableName := formatSessionTempTableName(sessionToken)

	columns := []string{"name", "severity", "description", "packages", "link", "score", "vectors", "score_v3", "vectors_v3",
		"published_timestamp", "last_modified_timestamp", "workloads", "nodes", "images", "platforms", "cve_sources", "f_withFix", "f_profile", "debuglog", "score_str", "scorev3_str"}

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

		debugLog := strings.Join(vulAsset.DebugLog, ";")

		_, err = stmt.Exec(vulAsset.Name, vulAsset.Severity, vulAsset.Description, vulAsset.Packages,
			vulAsset.Link, vulAsset.Score, vulAsset.Vectors, vulAsset.ScoreV3, vulAsset.VectorsV3, vulAsset.PublishedTS, vulAsset.LastModTS,
			vulAsset.Workloads, vulAsset.Nodes, vulAsset.Images, vulAsset.Platforms, vulAsset.CVESources,
			vulAsset.F_withFix, vulAsset.F_profile, debugLog,
			formatScoreToStr(vulAsset.Score), formatScoreToStr(vulAsset.ScoreV3))
		if err != nil {
			return err
		}
	}

	return nil
}

func filterVpf(vulAsset *DbVulAsset, assets utils.Set, filteredMap map[string]bool) {
	items := assets.ToStringSlice()
	for _, id := range items {
		key := fmt.Sprintf("%s;%s", id, vulAsset.Name)
		if _, ok := filteredMap[key]; ok {
			assets.Remove(id)
		}
	}
}

func filterAllowedAssets(vulAsset *DbVulAsset, allowed map[string]utils.Set, filteredMap map[string]bool) {
	// filter allowed assets
	filtered_workloads := parseJsonStrToSet(vulAsset.Workloads).Intersect(allowed[AssetWorkload])
	filtered_nodes := parseJsonStrToSet(vulAsset.Nodes).Intersect(allowed[AssetNode])
	filtered_images := parseJsonStrToSet(vulAsset.Images).Intersect(allowed[AssetImage])
	filtered_platforms := parseJsonStrToSet(vulAsset.Platforms).Intersect(allowed[AssetPlatform])

	// do vpf
	// filteredMap contains two kind of key. (1) CVEName (2) assetid;CVEName
	if _, exist := filteredMap[vulAsset.Name]; exist {
		filterVpf(vulAsset, filtered_workloads, filteredMap)
		filterVpf(vulAsset, filtered_nodes, filteredMap)
		filterVpf(vulAsset, filtered_images, filteredMap)
		filterVpf(vulAsset, filtered_platforms, filteredMap)
	}

	// save back
	vulAsset.WorkloadItems = filtered_workloads.ToStringSlice()
	vulAsset.NodeItems = filtered_nodes.ToStringSlice()
	vulAsset.ImageItems = filtered_images.ToStringSlice()
	vulAsset.PlatformItems = filtered_platforms.ToStringSlice()

	vulAsset.Workloads, _ = convertToJSON(vulAsset.WorkloadItems)
	vulAsset.Nodes, _ = convertToJSON(vulAsset.NodeItems)
	vulAsset.Images, _ = convertToJSON(vulAsset.ImageItems)
	vulAsset.Platforms, _ = convertToJSON(vulAsset.PlatformItems)

	if len(vulAsset.WorkloadItems) == 0 && len(vulAsset.NodeItems) == 0 &&
		len(vulAsset.ImageItems) == 0 && len(vulAsset.PlatformItems) == 0 {
		vulAsset.Skip = true
	}
}

func addVulProperties(resType ResourceType, resourceID string, vul *api.RESTVulnerability, dbVulAsset *DbVulAsset, baseOS string) error {
	// add package info
	packages2 := make(map[string][]DbVulnResourcePackageVersion)
	if dbVulAsset.Packages != "" {
		err := json.Unmarshal([]byte(dbVulAsset.Packages), &packages2)
		if err != nil {
			return err
		}
	}

	packageName := vul.PackageName

	if _, ok := packages2[packageName]; !ok {
		packages2[packageName] = make([]DbVulnResourcePackageVersion, 0) // not exist..
	}

	packages2[packageName] = append(packages2[packageName], DbVulnResourcePackageVersion{
		PackageVersion: vul.PackageVersion,
		FixedVersion:   vul.FixedVersion,
		ResourceID:     resourceID,
	})
	jsonBytes, err := json.Marshal(packages2)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	if dbVulAsset.F_withFix == 0 {
		if vul.FixedVersion != "" {
			dbVulAsset.F_withFix = 1
		}
	}

	dbVulAsset.Packages = string(jsonBytes)

	// add asset id
	if resType == TypeWorkload {
		appendedData, err := addAssetId(dbVulAsset.Workloads, resourceID)
		if err == nil {
			dbVulAsset.Workloads = appendedData
		}
	} else if resType == TypeNode {
		appendedData, err := addAssetId(dbVulAsset.Nodes, resourceID)
		if err == nil {
			dbVulAsset.Nodes = appendedData
		}
	} else if resType == TypeImage {
		appendedData, err := addAssetId(dbVulAsset.Images, resourceID)
		if err == nil {
			dbVulAsset.Images = appendedData
		}
	} else if resType == TypePlatform {
		appendedData, err := addAssetId(dbVulAsset.Platforms, resourceID)
		if err == nil {
			dbVulAsset.Platforms = appendedData
		}
	}

	// add CVESources
	cvesources := make([]DbCVESource, 0)
	if dbVulAsset.CVESources != "" {
		err := json.Unmarshal([]byte(dbVulAsset.CVESources), &cvesources)
		if err != nil {
			return err
		}
	}

	if !isCVESourceExist(cvesources, resourceID, vul.DbKey, baseOS) {
		cvesources = append(cvesources, DbCVESource{
			ResourceID: resourceID,
			BaseOS:     baseOS,
			DbKey:      vul.DbKey,
		})

		jsonBytes, err = json.Marshal(cvesources)
		if err != nil {
			return err
		}
		dbVulAsset.CVESources = string(jsonBytes)
	}

	return nil
}

func updateVulAsset(vulAsset *DbVulAsset, tableName string, memoryDb bool) (int, error) {
	targetTable := Table_vulassets
	if tableName != "" {
		targetTable = tableName
	}

	db := dbHandle
	if memoryDb {
		db = memoryDbHandle
	}

	dialect := goqu.Dialect("sqlite3")
	if vulAsset.Db_ID == 0 {
		ds := dialect.Insert(targetTable)
		sql, args, _ := ds.Rows(goqu.Record{
			"name":                    vulAsset.Name,
			"severity":                vulAsset.Severity,
			"description":             vulAsset.Description,
			"packages":                vulAsset.Packages,
			"link":                    vulAsset.Link,
			"score":                   vulAsset.Score,
			"vectors":                 vulAsset.Vectors,
			"score_v3":                vulAsset.ScoreV3,
			"vectors_v3":              vulAsset.VectorsV3,
			"published_timestamp":     vulAsset.PublishedTS,
			"last_modified_timestamp": vulAsset.LastModTS,
			"workloads":               vulAsset.Workloads,
			"nodes":                   vulAsset.Nodes,
			"images":                  vulAsset.Images,
			"platforms":               vulAsset.Platforms,
			"cve_sources":             vulAsset.CVESources,
			"f_withFix":               vulAsset.F_withFix,
			"f_profile":               vulAsset.F_profile,
			"debuglog":                "",
			"score_str":               formatScoreToStr(vulAsset.Score),
			"scorev3_str":             formatScoreToStr(vulAsset.ScoreV3),
		}).Prepared(true).ToSQL()

		result, err := db.Exec(sql, args...)
		if err != nil {
			return 0, err
		}

		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}

		return int(lastInsertID), nil
	}

	sql, args, _ := dialect.Update(targetTable).Where(goqu.C("id").Eq(vulAsset.Db_ID)).Set(
		goqu.Record{
			"packages":    vulAsset.Packages,
			"workloads":   vulAsset.Workloads,
			"nodes":       vulAsset.Nodes,
			"images":      vulAsset.Images,
			"platforms":   vulAsset.Platforms,
			"cve_sources": vulAsset.CVESources,
		},
	).Prepared(true).ToSQL()

	_, err := db.Exec(sql, args...)
	if err != nil {
		return 0, err
	}

	return vulAsset.Db_ID, nil
}

func addAssetId(jsonStr string, newElement string) (string, error) {
	if jsonStr == "" {
		data := []string{newElement}
		updatedJSON, _ := json.Marshal(data)
		return string(updatedJSON), nil
	}

	if strings.Contains(jsonStr, newElement) {
		return jsonStr, nil // exist, no need to add
	}

	var data []string
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return "", err
	}
	data = append(data, newElement)
	updatedJSON, _ := json.Marshal(data)
	return string(updatedJSON), nil
}

func fillCVERecord(record *DbVulAsset) error {
	//	CVESources string `json:"cve_sources"`	// []DbCVESource  (in json)
	// need to fetch the data from

	// convert the cve_sources(string) to []DbCVESource
	// if multiple items available, need to decide which one to use
	// for [CVE-2015-8865], it has several sources like below
	// 		ubuntu:CVE-2015-8865
	// 		upstream:CVE-2015-8865
	// 		CVE-2015-8865
	// 		centos:CVE-2015-8865
	// 		debian:CVE-2015-8865

	//TODO: Gary mentioned we can use NVD's as first choise
	// for now, try to use the first one

	// if it's already valid then skip
	if record.Description != "" && record.Link != "" && record.PublishedTS != 0 {
		return nil
	}

	cvesources := make([]DbCVESource, 0)
	if record.CVESources != "" {
		err := json.Unmarshal([]byte(record.CVESources), &cvesources)
		if err != nil {
			return err
		}
	}

	if len(cvesources) == 0 {
		return nil // ??
	}

	vulAsset := GetCveRecordFunc(record.Name, cvesources[0].DbKey, cvesources[0].BaseOS)
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

func isCVESourceExist(cveSources []DbCVESource, resourceID, dbKey, baseOS string) bool {
	for _, element := range cveSources {
		if element.ResourceID == resourceID && element.DbKey == dbKey && element.BaseOS == baseOS {
			return true
		}
	}

	return false
}

func GetTopAssets(allowed map[string]utils.Set, assetType string, topN int) ([]*api.AssetCVECount, error) {
	allowedAssets := []string{}

	if assetType == AssetImage || assetType == AssetNode {
		allowedAssets = allowed[assetType].ToStringSlice()
	} else {
		return nil, errors.New("unsupport type.")
	}

	// step-1: format query statement
	// SELECT "assetid", "name", "cve_high", "cve_medium", "cve_low" FROM "assetvuls" WHERE ("type" = 'image') ORDER BY "cve_count" DESC LIMIT 3
	// SELECT "assetid", "name", "cve_high", "cve_medium", "cve_low" FROM "assetvuls" WHERE (("type" = 'image') AND ("assetid" IN ('dc00f1198a444104617989bde31132c22d7527c65e825b9de4bbe6313f22637f', '9a48168d5ab29a332e14541be713b0be76f330c035f2dfbf115f2583c74edd33'))) ORDER BY "cve_count" DESC LIMIT 3
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From("assetvuls").Select("assetid", "name", "cve_high", "cve_medium", "cve_low").Where(buildTopAssetWhereClause(assetType, allowedAssets)).Order(goqu.C("cve_count").Desc()).Limit(5).Prepared(true).ToSQL()

	// step-2: execute it and fetch the data
	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tops := make([]*api.AssetCVECount, 0)
	for rows.Next() {
		record := &api.AssetCVECount{}
		err = rows.Scan(&record.ID, &record.DisplayName, &record.High, &record.Medium, &record.Low)

		if err != nil {
			return nil, err
		}

		tops = append(tops, record)
	}

	return tops, nil
}

func DeleteAssetByID(assetType string, assetid string, cveNames []string) error {
	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	if len(cveNames) > 0 {
		// fetch CVEs with cveNames, foreach cve, remove the assetid
		columns := []interface{}{"id", "workloads", "nodes", "images"}
		sql, args, _ := dialect.From(Table_vulassets).Select(columns...).Where(goqu.Ex{"name": cveNames}).Prepared(true).ToSQL()

		rows, err := db.Query(sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		records := make([]*DbVulAsset, 0)
		for rows.Next() {
			vulasset := &DbVulAsset{}
			err = rows.Scan(&vulasset.Db_ID, &vulasset.Workloads, &vulasset.Nodes, &vulasset.Images)
			if err != nil {
				return err
			}
			records = append(records, vulasset)
		}

		// remove the id in all these CVEs
		for _, vulasset := range records {
			removeAssetID(assetType, assetid, vulasset)
		}
	}

	// delete asset in assetvul table
	sql, args, _ := dialect.Delete(Table_assetvuls).Where(goqu.Ex{"type": assetType, "assetid": assetid}).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return err
	}
	return nil
}

func removeAssetID(assetType string, assetid string, vulasset *DbVulAsset) error {
	// remove the assetid
	var record *goqu.Record
	if assetType == AssetImage {
		assets := deleteItemInSlice(vulasset.Images, assetid)
		record = &goqu.Record{"images": assets}
	} else if assetType == AssetWorkload {
		assets := deleteItemInSlice(vulasset.Workloads, assetid)
		record = &goqu.Record{"workloads": assets}
	} else if assetType == AssetNode {
		assets := deleteItemInSlice(vulasset.Nodes, assetid)
		record = &goqu.Record{"nodes": assets}
	} else {
		return nil
	}

	// update it
	db := dbHandle
	dialect := goqu.Dialect("sqlite3")
	sql, args, _ := dialect.Update(Table_vulassets).Where(goqu.C("id").Eq(vulasset.Db_ID)).Set(record).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return err
	}
	return nil
}

// sql builder
func buildTopAssetWhereClause(assetType string, allowedID []string) exp.ExpressionList {
	part1_typeImage := goqu.Ex{
		"type": assetType,
	}

	part2_allowed := goqu.Ex{}
	if len(allowedID) > 0 {
		part2_allowed = goqu.Ex{
			"assetid": allowedID,
		}
	}

	return goqu.And(part1_typeImage, part2_allowed)
}

func getOrderColumn(filters *api.VulQueryFilterViewModel) exp.OrderedExpression {
	column := "name"
	if filters.OrderByColume == "name" || filters.OrderByColume == "score" || filters.OrderByColume == "score_v3" || filters.OrderByColume == "published_timestamp" {
		column = filters.OrderByColume
	}

	if filters.OrderByType == "desc" { // asc, desc
		return goqu.I(column).Desc()
	}
	return goqu.I(column).Asc()
}
