package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	_ "github.com/mattn/go-sqlite3"
)

type BuildWhereClauseFunc func(allowedID []string, queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList
type BuildWhereClauseAllFunc func(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList

func GetAssetVulIDByAssetID(assetID string) (*DbAssetVul, error) {
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select("id").Where(goqu.C("assetid").Eq(assetID)).Prepared(true).ToSQL()

	var lastErr error
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(statement, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			assetVul := &DbAssetVul{
				AssetID: assetID,
			}

			err = rows.Scan(&assetVul.Db_ID)
			if err != nil {
				return nil, err
			}

			return assetVul, nil
		}
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return nil, errors.New("no such asset id")
}

func PopulateAssetVul(assetVul *DbAssetVul) error {
	if dbHandle == nil {
		return errors.New("db is not initialized")
	}

	assetID := assetVul.AssetID

	existingAsset, err := GetAssetVulIDByAssetID(assetID)
	if err != nil {
		assetVul.Db_ID = 0 // not exist, need to create a new one
	} else {
		assetVul.Db_ID = existingAsset.Db_ID
	}

	// update/insert
	_, err = UpdateAssetVul(assetVul)
	if err != nil {
		return err
	}
	return nil
}

func UpdateAssetVul(assetVul *DbAssetVul) (int, error) {
	targetTable := Table_assetvuls

	db := dbHandle
	dialect := goqu.Dialect("sqlite3")

	// Insert case
	if assetVul.Db_ID == 0 {
		ds := dialect.Insert(targetTable).Rows(getCompiledRecord(assetVul))
		sql, args, _ := ds.Prepared(true).ToSQL()

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

	// Update case
	sql, args, _ := dialect.Update(targetTable).Where(goqu.C("id").Eq(assetVul.Db_ID)).Set(getCompiledRecord(assetVul)).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return 0, err
	}

	return assetVul.Db_ID, nil
}

func UpdateHostContainers(id string, containers int) error {
	assetVul, err := GetAssetVulIDByAssetID(id)
	if err != nil {
		return err
	}
	assetVul.N_containers = containers

	db := dbHandle

	dialect := goqu.Dialect("sqlite3")
	record := &goqu.Record{"n_containers": assetVul.N_containers}
	sql, args, _ := dialect.Update(Table_assetvuls).Where(goqu.C("id").Eq(assetVul.Db_ID)).Set(record).Prepared(true).ToSQL()
	_, err = db.Exec(sql, args...)
	if err != nil {
		return err
	}
	return err
}

func applyAssetBasedFilters(allowed map[string]utils.Set, queryFilter *VulQueryFilter) (map[string]utils.Set, error) {
	matchedAssets := map[string]utils.Set{
		AssetRuleDomain:    utils.NewSet(),
		AssetRuleService:   utils.NewSet(),
		AssetRuleNode:      utils.NewSet(),
		AssetRuleContainer: utils.NewSet(),
		AssetRuleImage:     utils.NewSet(),
		AssetRulePlatform:  utils.NewSet(),
	}

	stats := queryFilter.GetAssestBasedFilters()
	if len(stats) > 0 {
		if stats[AssetRuleNode] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetNode], buildWhereClauseForNode_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRuleNode] = assets
			}
		}

		if stats[AssetRuleImage] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetImage], buildWhereClauseForImage_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRuleImage] = assets
			}
		}

		if stats[AssetRuleDomain] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetWorkload], buildWhereClauseForDomain_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRuleDomain] = assets
			}
		}

		if stats[AssetRuleService] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetWorkload], buildWhereClauseForService_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRuleService] = assets
			}
		}

		if stats[AssetRuleContainer] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetWorkload], buildWhereClauseForContainer_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRuleContainer] = assets
			}
		}

		if stats[AssetRulePlatform] > 0 {
			assets, err := _applyAssetBaseFilter(queryFilter, allowed[AssetPlatform], buildWhereClauseForPlatform_All)
			if err != nil {
				return nil, err
			} else {
				matchedAssets[AssetRulePlatform] = assets
			}
		}
	}

	return matchedAssets, nil
}

func _applyAssetBaseFilter(q *VulQueryFilter, allowed utils.Set, buildWhereFunc BuildWhereClauseAllFunc) (utils.Set, error) {
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select("assetid").Where(buildWhereFunc(q.Filters)).Prepared(true).ToSQL()
	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := utils.NewSet()
	for rows.Next() {
		var assetId string
		err = rows.Scan(&assetId)
		if err != nil {
			return nil, err
		}

		if allowed.Contains(assetId) {
			results.Add(assetId)
		}
	}

	return results, nil
}

func isOneAssetMatch(matchedAssets utils.Set, assets []string) bool {
	for _, t := range assets {
		if matchedAssets.Contains(t) {
			return true
		}
	}
	return false
}

func evaluateAssetBasedFilters(vulasset *DbVulAsset, matchedAssets map[string]utils.Set, queryFilter *VulQueryFilter) {

	//	all the assets under this CVE need to meet ALL the count, not just one.
	stats := queryFilter.GetAssestBasedFilters()

	stats[AssetRulePlatform] = 0 // no need to check platform

	if len(stats) > 0 {
		if stats[AssetRuleNode] > 0 {
			if isOneAssetMatch(matchedAssets[AssetRuleNode], vulasset.NodeItems) {
				stats[AssetRuleNode] = 0
			}
		}

		if stats[AssetRuleImage] > 0 {
			if isOneAssetMatch(matchedAssets[AssetRuleImage], vulasset.ImageItems) {
				stats[AssetRuleImage] = 0
			}
		}

		if stats[AssetRuleDomain] > 0 {
			if isOneAssetMatch(matchedAssets[AssetRuleDomain], vulasset.WorkloadItems) {
				stats[AssetRuleDomain] = 0
			}
		}

		if stats[AssetRuleService] > 0 {
			if isOneAssetMatch(matchedAssets[AssetRuleService], vulasset.WorkloadItems) {
				stats[AssetRuleService] = 0
			}
		}

		if stats[AssetRuleContainer] > 0 {
			if isOneAssetMatch(matchedAssets[AssetRuleContainer], vulasset.WorkloadItems) {
				stats[AssetRuleContainer] = 0
			}
		}

		// check stats
		result := 0
		for _, value := range stats {
			result += value
		}

		if result != 0 {
			// not all filters are matched, need to skip this CVE
			vulasset.Skip = true
		}
	}
}

// for REST[asset]AssetView, used in /v1/assetvul
func GetMatchedAssets(vulMap map[string]*DbVulAsset, assetsMap map[string][]string, queryFilter *VulQueryFilter) (*api.RESTAssetView, error) {
	var err error
	assetView := &api.RESTAssetView{}

	allCVE := utils.NewSet()
	allAssets := utils.NewSet()

	// part 1: assets
	assetView.Workloads, err = getWorkloadAssetView(vulMap, assetsMap[AssetWorkload], queryFilter, allCVE, allAssets)
	if err != nil {
		return nil, err
	}

	assetView.Nodes, err = getHostAssetView(vulMap, assetsMap[AssetNode], queryFilter, allCVE, allAssets)
	if err != nil {
		return nil, err
	}

	assetView.Images, err = getImageAssetView(vulMap, assetsMap[AssetImage], queryFilter, allCVE, allAssets)
	if err != nil {
		return nil, err
	}

	assetView.Platforms, err = getPlatformAssetView(vulMap, assetsMap[AssetPlatform], queryFilter, allCVE, allAssets)
	if err != nil {
		return nil, err
	}

	// part 2: vulnerablities
	// the packages in vulasset table contains packages from ALL impacts assets
	// in assetview, we only need package info belong to assetss within to this report
	cveItems := allCVE.ToStringSlice()
	assetView.Vuls = make([]*api.RESTVulnerabilityAssetV2, 0)
	for _, c := range cveItems {
		if s, ok := vulMap[c]; ok {
			record := &api.RESTVulnerabilityAssetV2{
				Name:        s.Name,
				Severity:    s.Severity,
				Description: s.Description,
				Link:        s.Link,
				Score:       float32(s.Score) / 10.0,
				Vectors:     s.Vectors,
				ScoreV3:     float32(s.ScoreV3) / 10.0,
				VectorsV3:   s.VectorsV3,
				PublishedTS: s.PublishedTS,
				LastModTS:   s.LastModTS,
			}

			packages := s.Packages
			distinctPackages := make(map[string]utils.Set)

			packages2 := make(map[string][]DbVulnResourcePackageVersion)
			if packages != "" {
				err := json.Unmarshal([]byte(packages), &packages2)
				if err != nil {
					return nil, err
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
					if !allAssets.Contains(item.ResourceID) {
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

			assetView.Vuls = append(assetView.Vuls, record)
		}
	}

	return assetView, nil
}

func getWorkloadAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, allCVE utils.Set, allAssets utils.Set) ([]*api.RESTWorkloadAssetView, error) {
	records := make([]*api.RESTWorkloadAssetView, 0)

	columns := []interface{}{"assetid", "name", "w_domain", "w_applications", "policy_mode", "w_service_group",
		"cve_high", "cve_medium", "cve_low", "cve_lists", "scanned_at"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForWorkload(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		av := &api.RESTWorkloadAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, cveStr, apps string
		err = rows.Scan(&assetId, &av.Name, &av.Domain, &apps, &av.PolicyMode, &av.ServiceGroup, &av.High, &av.Medium, &av.Low, &cveStr, &av.ScannedAt)

		if err != nil {
			return nil, err
		}

		av.Applications = parseJsonStrToSlice(apps)

		// keep only CVE exist vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			if v, exist := vulMap[c]; exist {
				allCVE.Add(c)
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(c, v.Severity))
			}
		}

		av.ID = assetId // TODO: for debug, remove later
		allAssets.Add(assetId)
		records = append(records, av)
	}
	return records, nil
}

func getHostAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, allCVE utils.Set, allAssets utils.Set) ([]*api.RESTHostAssetView, error) {
	records := make([]*api.RESTHostAssetView, 0)

	columns := []interface{}{"assetid", "name", "policy_mode",
		"cve_high", "cve_medium", "cve_low", "cve_lists", "scanned_at",
		"n_os", "n_kernel", "n_cpus", "n_memory", "n_containers"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForNode(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		av := &api.RESTHostAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, cveStr string
		err = rows.Scan(&assetId, &av.Name, &av.PolicyMode,
			&av.High, &av.Medium, &av.Low, &cveStr, &av.ScannedAt,
			&av.OS, &av.Kernel, &av.CPUs, &av.Memory, &av.Containers)
		if err != nil {
			return nil, err
		}

		// keep only CVE exist vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			if v, exist := vulMap[c]; exist {
				allCVE.Add(c)
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(c, v.Severity))
			}
		}

		av.ID = assetId // TODO: for debug, remove later
		allAssets.Add(assetId)
		records = append(records, av)
	}
	return records, nil
}

func getImageAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, allCVE utils.Set, allAssets utils.Set) ([]*api.RESTImageAssetView, error) {
	records := make([]*api.RESTImageAssetView, 0)

	columns := []interface{}{"assetid", "name",
		"cve_high", "cve_medium", "cve_low", "cve_lists"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForImage(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		av := &api.RESTImageAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, cveStr string
		err = rows.Scan(&assetId, &av.Name, &av.High, &av.Medium, &av.Low, &cveStr)

		if err != nil {
			return nil, err
		}

		// keep only CVE exist vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			if v, exist := vulMap[c]; exist {
				allCVE.Add(c)
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(c, v.Severity))
			}
		}

		av.ID = assetId // TODO: for debug, remove later
		allAssets.Add(assetId)
		records = append(records, av)
	}
	return records, nil
}

func getPlatformAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, allCVE utils.Set, allAssets utils.Set) ([]*api.RESTPlatformAssetView, error) {
	records := make([]*api.RESTPlatformAssetView, 0)

	columns := []interface{}{"assetid", "name",
		"cve_high", "cve_medium", "cve_low", "cve_lists",
		"p_version", "p_base_os"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForPlatform(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		av := &api.RESTPlatformAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, cveStr string
		err = rows.Scan(&assetId, &av.Name, &av.High, &av.Medium, &av.Low, &cveStr, &av.Version, &av.BaseOS)

		if err != nil {
			return nil, err
		}

		// keep only CVE exist vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			if v, exist := vulMap[c]; exist {
				allCVE.Add(c)
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(c, v.Severity))
			}
		}

		av.ID = assetId // TODO: for debug, remove later
		allAssets.Add(assetId)
		records = append(records, av)
	}
	return records, nil
}

func formatCVEName(name, severity string) string {
	prefix := "L"
	switch severity {
	case "High":
		prefix = "H"
	case "Medium":
		prefix = "M"
	}

	return fmt.Sprintf("%s_%s", prefix, name)
}

// for REST[asset]Asset, used for /v1/vulasset
func GetAssetsMeta(allAssets utils.Set) (*AssetMaps, error) {
	amap := &AssetMaps{}

	var err error
	amap.workloads, err = _getWorkloadsMeta(allAssets)
	if err != nil {
		return nil, err
	}

	amap.hosts, err = _getNodesMeta(allAssets)
	if err != nil {
		return nil, err
	}

	amap.platforms, err = _getPlatformsMeta(allAssets)
	if err != nil {
		return nil, err
	}

	amap.images, err = _getImagesMeta(allAssets)
	if err != nil {
		return nil, err
	}

	return amap, nil
}

func FillAssets(vul *api.RESTVulnerabilityAssetV2, assetMaps *AssetMaps) {
	for _, id := range vul.WorkloadIDs {
		if v, ok := assetMaps.workloads[id]; ok {
			vul.Workloads = append(vul.Workloads, v)
		}
	}

	for _, id := range vul.NodesIDs {
		if v, ok := assetMaps.hosts[id]; ok {
			vul.Nodes = append(vul.Nodes, v)
		}
	}

	for _, id := range vul.PlatformsIDs {
		if v, ok := assetMaps.platforms[id]; ok {
			vul.Platforms = append(vul.Platforms, v)
		}
	}

	for _, id := range vul.ImagesIDs {
		if v, ok := assetMaps.images[id]; ok {
			vul.Images = append(vul.Images, v)
		}
	}
}

func _getWorkloadsMeta(allAssets utils.Set) (map[string]*api.RESTWorkloadAsset, error) {
	columns := []interface{}{"assetid", "name", "w_domain", "policy_mode", "w_service_group", "w_image"}

	dialect := goqu.Dialect("sqlite3")
	assets := allAssets.ToStringSlice()

	expAssetType := goqu.Ex{"type": "workload"}
	expAssets := goqu.Ex{"assetid": assets}
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.And(expAssetType, expAssets)).Prepared(true).ToSQL()

	var lastErr error
	records := make(map[string]*api.RESTWorkloadAsset, 0)
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(statement, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var domain string
			as := &api.RESTWorkloadAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &domain, &as.PolicyMode, &as.Service, &as.Image)

			if err != nil {
				return nil, err
			}

			if domain != "" {
				as.Domains = []string{domain}
			}

			records[as.ID] = as
		}
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return records, nil
}

func _getNodesMeta(allAssets utils.Set) (map[string]*api.RESTHostAsset, error) {
	columns := []interface{}{"assetid", "name", "w_domain", "policy_mode"}

	dialect := goqu.Dialect("sqlite3")
	assets := allAssets.ToStringSlice()

	expAssetType := goqu.Ex{"type": "host"}
	expAssets := goqu.Ex{"assetid": assets}
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.And(expAssetType, expAssets)).Prepared(true).ToSQL()

	var lastErr error
	records := make(map[string]*api.RESTHostAsset, 0)
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(statement, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var domain string
			as := &api.RESTHostAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &domain, &as.PolicyMode)
			if err != nil {
				return nil, err
			}

			if domain != "" {
				as.Domains = []string{domain}
			}
			records[as.ID] = as
		}
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return records, nil
}

func _getPlatformsMeta(allAssets utils.Set) (map[string]*api.RESTPlatformAsset, error) {
	columns := []interface{}{"assetid", "name", "w_domain", "policy_mode"}

	dialect := goqu.Dialect("sqlite3")
	assets := allAssets.ToStringSlice()

	expAssetType := goqu.Ex{"type": "platform"}
	expAssets := goqu.Ex{"assetid": assets}
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.And(expAssetType, expAssets)).Prepared(true).ToSQL()

	var lastErr error
	records := make(map[string]*api.RESTPlatformAsset, 0)
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(statement, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var domain string
			as := &api.RESTPlatformAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &domain, &as.PolicyMode)
			if err != nil {
				return nil, err
			}

			if domain != "" {
				as.Domains = []string{domain}
			}

			records[as.ID] = as
		}
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return records, nil
}

func _getImagesMeta(allAssets utils.Set) (map[string]*api.RESTImageAsset, error) {
	columns := []interface{}{"assetid", "name", "w_domain", "policy_mode"}

	dialect := goqu.Dialect("sqlite3")
	assets := allAssets.ToStringSlice()

	expAssetType := goqu.Ex{"type": "image"}
	expAssets := goqu.Ex{"assetid": assets}
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.And(expAssetType, expAssets)).Prepared(true).ToSQL()

	var lastErr error
	records := make(map[string]*api.RESTImageAsset, 0)
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(statement, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var domain string
			as := &api.RESTImageAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &domain, &as.PolicyMode)
			if err != nil {
				return nil, err
			}

			if domain != "" {
				as.Domains = []string{domain}
			}
			records[as.ID] = as
		}
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return records, nil
}

// sql builders
func buildWhereClauseForWorkload(allowedID []string, queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "workload",
	}

	part2_allowed := goqu.Ex{}
	if len(allowedID) > 0 {
		part2_allowed = goqu.Ex{
			"assetid": allowedID,
		}
	}

	// domains
	part3_domain_equals := goqu.Ex{}
	domain_contains := make([]exp.Expression, 0)
	if queryFilter.MatchType4Ns != "" && len(queryFilter.SelectedDomains) > 0 {
		if queryFilter.MatchType4Ns == "equals" {
			part3_domain_equals = goqu.Ex{
				"w_domain": queryFilter.SelectedDomains,
			}
		} else if queryFilter.MatchType4Ns == "contains" {
			for _, d := range queryFilter.SelectedDomains {
				domain_contains = append(domain_contains, goqu.C("w_domain").Like(fmt.Sprintf("%%%s%%", d)))
			}
		}
	}

	// service
	part_service_equal := goqu.Ex{}
	part_service_contains := make([]exp.Expression, 0)
	if queryFilter.ServiceNameMatchType != "" && queryFilter.ServiceName != "" {
		if queryFilter.ServiceNameMatchType == "equals" {
			part_service_equal = goqu.Ex{
				"w_service_group": queryFilter.ServiceName,
			}
		} else if queryFilter.ServiceNameMatchType == "contains" {
			part_service_contains = append(part_service_contains, goqu.C("w_service_group").Like(fmt.Sprintf("%%%s%%", queryFilter.ServiceName)))
		}
	}

	// container
	part_container_equal := goqu.Ex{}
	part_container_contains := make([]exp.Expression, 0)
	if queryFilter.ContainerNameMatchType != "" && queryFilter.ContainerName != "" {
		if queryFilter.ContainerNameMatchType == "equals" {
			part_container_equal = goqu.Ex{
				"name": queryFilter.ContainerName,
			}
		} else if queryFilter.ContainerNameMatchType == "contains" {
			part_container_contains = append(part_container_contains, goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.ContainerName)))
		}
	}

	return goqu.And(part1_assetType, part2_allowed,
		part3_domain_equals, goqu.Or(domain_contains...),
		part_service_equal, goqu.Or(part_service_contains...),
		part_container_equal, goqu.Or(part_container_contains...))
}

func buildWhereClauseForImage(allowedID []string, queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "image",
	}

	part2_allowed := goqu.Ex{}
	if len(allowedID) > 0 {
		part2_allowed = goqu.Ex{
			"assetid": allowedID,
		}
	}

	part_image_equal := goqu.Ex{}
	part_image_contains := make([]exp.Expression, 0)
	if queryFilter.ImageNameMatchType != "" && queryFilter.ImageName != "" {
		if queryFilter.ImageNameMatchType == "equals" {
			part_image_equal = goqu.Ex{
				"name": queryFilter.ImageName,
			}
		} else if queryFilter.ImageNameMatchType == "contains" {
			part_image_contains = append(part_image_contains, goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.ImageName)))
		}
	}

	return goqu.And(part1_assetType, part2_allowed,
		part_image_equal, goqu.Or(part_image_contains...))
}

func buildWhereClauseForNode(allowedID []string, queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "host",
	}

	part2_allowed := goqu.Ex{}
	if len(allowedID) > 0 {
		part2_allowed = goqu.Ex{
			"assetid": allowedID,
		}
	}

	// node
	part_node_equal := goqu.Ex{}
	part_node_contains := make([]exp.Expression, 0)
	if queryFilter.NodeNameMatchType != "" && queryFilter.NodeName != "" {
		if queryFilter.NodeNameMatchType == "equals" {
			part_node_equal = goqu.Ex{
				"name": queryFilter.NodeName,
			}
		} else if queryFilter.NodeNameMatchType == "contains" {
			part_node_contains = append(part_node_contains, goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.NodeName)))
		}
	}

	return goqu.And(part1_assetType, part2_allowed,
		part_node_equal, goqu.Or(part_node_contains...))
}

func buildWhereClauseForPlatform(allowedID []string, queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "platform",
	}

	part2_allowed := goqu.Ex{}
	if len(allowedID) > 0 {
		part2_allowed = goqu.Ex{
			"assetid": allowedID,
		}
	}

	return goqu.And(part1_assetType, part2_allowed)
}

func buildWhereClauseForNode_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	return buildWhereClauseForNode([]string{}, queryFilter)
}

func buildWhereClauseForImage_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	return buildWhereClauseForImage([]string{}, queryFilter)
}

func buildWhereClauseForDomain_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "workload",
	}

	// domains
	part3_domain_equals := goqu.Ex{}
	domain_contains := make([]exp.Expression, 0)
	if queryFilter.MatchType4Ns != "" && len(queryFilter.SelectedDomains) > 0 {
		if queryFilter.MatchType4Ns == "equals" {
			part3_domain_equals = goqu.Ex{
				"w_domain": queryFilter.SelectedDomains,
			}
		} else if queryFilter.MatchType4Ns == "contains" {
			for _, d := range queryFilter.SelectedDomains {
				domain_contains = append(domain_contains, goqu.C("w_domain").Like(fmt.Sprintf("%%%s%%", d)))
			}
		}
	}

	return goqu.And(part1_assetType, part3_domain_equals, goqu.Or(domain_contains...))
}

func buildWhereClauseForService_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "workload",
	}

	// service
	part_service_equal := goqu.Ex{}
	part_service_contains := make([]exp.Expression, 0)
	if queryFilter.ServiceNameMatchType != "" && queryFilter.ServiceName != "" {
		if queryFilter.ServiceNameMatchType == "equals" {
			part_service_equal = goqu.Ex{
				"w_service_group": queryFilter.ServiceName,
			}
		} else if queryFilter.ServiceNameMatchType == "contains" {
			// goqu.C("a").Like("%a%")
			// goqu.Op{"like": "a%"},
			part_service_contains = append(part_service_contains, goqu.C("w_service_group").Like(fmt.Sprintf("%%%s%%", queryFilter.ServiceName)))
		}
	}

	return goqu.And(part1_assetType, part_service_equal, goqu.Or(part_service_contains...))
}

func buildWhereClauseForContainer_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "workload",
	}

	// container
	part_container_equal := goqu.Ex{}
	part_container_contains := make([]exp.Expression, 0)
	if queryFilter.ContainerNameMatchType != "" && queryFilter.ContainerName != "" {
		if queryFilter.ContainerNameMatchType == "equals" {
			part_container_equal = goqu.Ex{
				"name": queryFilter.ContainerName,
			}
		} else if queryFilter.ContainerNameMatchType == "contains" {
			part_container_contains = append(part_container_contains, goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.ContainerName)))
		}
	}

	return goqu.And(part1_assetType, part_container_equal, goqu.Or(part_container_contains...))
}

func buildWhereClauseForPlatform_All(queryFilter *api.VulQueryFilterViewModel) exp.ExpressionList {
	part1_assetType := goqu.Ex{
		"type": "platform",
	}

	return goqu.And(part1_assetType)
}

func getCompiledRecord(assetVul *DbAssetVul) *exp.Record {
	record := &goqu.Record{
		"type":    assetVul.Type,
		"assetid": assetVul.AssetID,
		"name":    assetVul.Name,

		"w_domain":        assetVul.W_domain,
		"w_applications":  assetVul.W_applications,
		"policy_mode":     assetVul.Policy_mode,
		"w_service_group": assetVul.W_service_group,
		"w_image":         assetVul.W_workload_image,

		"cve_high":   assetVul.CVE_high,
		"cve_medium": assetVul.CVE_medium,
		"cve_low":    assetVul.CVE_low,
		"cve_count":  assetVul.CVE_high + assetVul.CVE_medium + assetVul.CVE_low,
		"cve_lists":  assetVul.CVE_lists,
		"scanned_at": assetVul.Scanned_at,

		"n_os":     assetVul.N_os,
		"n_kernel": assetVul.N_kernel,
		"n_cpus":   assetVul.N_cpus,
		"n_memory": assetVul.N_memory,

		"n_containers": assetVul.N_containers,
		"p_version":    assetVul.P_version,
		"p_base_os":    assetVul.P_base_os}

	return record
}

// for perf testing
func Perf_getAllWorkloadIDs(allowed map[string]utils.Set) error {
	// select assetid from assetvuls where type='workload'
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select("assetid").Where(goqu.C("type").Eq("workload")).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var assetID string

		err = rows.Scan(&assetID)
		if err != nil {
			return err
		}

		allowed[AssetWorkload].Add(assetID)
	}

	return nil
}
