package db

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// for REST[asset]AssetView, used in /v1/assetvul
func GetMatchedAssets(vulMap map[string]*DbVulAsset, assetsMap map[string][]string, queryFilter *VulQueryFilter) (*api.RESTAssetView, error) {
	var err error
	assetView := &api.RESTAssetView{}

	cvePackages := make(map[string]map[string]utils.Set)
	for name := range vulMap {
		cvePackages[name] = make(map[string]utils.Set)
	}

	// part 1: assets
	assetView.Workloads, err = getWorkloadAssetView(vulMap, assetsMap[AssetWorkload], queryFilter, cvePackages)
	if err != nil {
		return nil, err
	}

	assetView.Nodes, err = getHostAssetView(vulMap, assetsMap[AssetNode], queryFilter, cvePackages)
	if err != nil {
		return nil, err
	}

	assetView.Images, err = getImageAssetView(vulMap, assetsMap[AssetImage], queryFilter, cvePackages)
	if err != nil {
		return nil, err
	}

	assetView.Platforms, err = getPlatformAssetView(vulMap, assetsMap[AssetPlatform], queryFilter, cvePackages)
	if err != nil {
		return nil, err
	}

	// part 2: vulnerablities
	// extract packages belong to matched assets
	assetView.Vuls = make([]*api.RESTVulnerabilityAssetV2, 0)
	for _, vul := range vulMap {
		record := &api.RESTVulnerabilityAssetV2{
			Name:        vul.Name,
			Severity:    vul.Severity,
			Description: vul.Description,
			Link:        vul.Link,
			Score:       float32(vul.Score) / 10.0,
			Vectors:     vul.Vectors,
			ScoreV3:     float32(vul.ScoreV3) / 10.0,
			VectorsV3:   vul.VectorsV3,
			PublishedTS: vul.PublishedTS,
			LastModTS:   vul.LastModTS,
		}

		// compile all the packages belong to this CVE
		record.Packages = make(map[string][]api.RESTVulnPackageVersion, 0)
		for pkg, vers := range cvePackages[vul.Name] {
			if _, ok := record.Packages[pkg]; !ok {
				record.Packages[pkg] = make([]api.RESTVulnPackageVersion, vers.Cardinality())
			}

			j := 0
			for v := range vers.Iter() {
				record.Packages[pkg][j] = v.(api.RESTVulnPackageVersion)
				j++
			}
		}

		assetView.Vuls = append(assetView.Vuls, record)
	}

	return assetView, nil
}

func getWorkloadAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTWorkloadAssetView, error) {
	records := make([]*api.RESTWorkloadAssetView, 0)

	columns := []interface{}{"assetid", "name", "w_domain", "w_applications", "policy_mode", "w_service_group",
		"cve_high", "cve_medium", "cve_low", "cve_lists", "scanned_at", "packagesb"}

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
		var packagesBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.Domain, &apps, &av.PolicyMode, &av.ServiceGroup, &av.High, &av.Medium, &av.Low, &cveStr, &av.ScannedAt, &packagesBytes)

		if err != nil {
			return nil, err
		}

		av.Applications = parseJsonStrToSlice(apps)

		// keep only CVE exist in vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			name, _, _ := parseCVEDbKey(c)
			if v, exist := vulMap[name]; exist {
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(name, v.Severity))
			}
		}

		// fetch the packages from matched assets
		fillCvePackages(cvePackages, packagesBytes)

		av.ID = assetId // TODO: for debug, remove later
		records = append(records, av)
	}
	return records, nil
}

func getHostAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTHostAssetView, error) {
	records := make([]*api.RESTHostAssetView, 0)

	columns := []interface{}{"assetid", "name", "policy_mode",
		"cve_high", "cve_medium", "cve_low", "cve_lists", "scanned_at",
		"n_os", "n_kernel", "n_cpus", "n_memory", "n_containers", "packagesb"}

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
		var packagesBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.PolicyMode,
			&av.High, &av.Medium, &av.Low, &cveStr, &av.ScannedAt,
			&av.OS, &av.Kernel, &av.CPUs, &av.Memory, &av.Containers, &packagesBytes)
		if err != nil {
			return nil, err
		}

		// keep only CVE exist in vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			name, _, _ := parseCVEDbKey(c)
			if v, exist := vulMap[name]; exist {
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(name, v.Severity))
			}
		}

		// fetch the packages from matched assets
		fillCvePackages(cvePackages, packagesBytes)

		av.ID = assetId // TODO: for debug, remove later
		records = append(records, av)
	}
	return records, nil
}

func getImageAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTImageAssetView, error) {
	records := make([]*api.RESTImageAssetView, 0)

	columns := []interface{}{"assetid", "name",
		"cve_high", "cve_medium", "cve_low", "cve_lists", "packagesb"}

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
		var packagesBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.High, &av.Medium, &av.Low, &cveStr, &packagesBytes)

		if err != nil {
			return nil, err
		}

		// keep only CVE exist in vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			name, _, _ := parseCVEDbKey(c)
			if v, exist := vulMap[name]; exist {
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(name, v.Severity))
			}
		}

		// fetch the packages from matched assets
		fillCvePackages(cvePackages, packagesBytes)

		av.ID = assetId // TODO: for debug, remove later
		records = append(records, av)
	}
	return records, nil
}

func getPlatformAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTPlatformAssetView, error) {
	records := make([]*api.RESTPlatformAssetView, 0)

	columns := []interface{}{"assetid", "name",
		"cve_high", "cve_medium", "cve_low", "cve_lists",
		"p_version", "p_base_os", "packagesb"}

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
		var packagesBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.High, &av.Medium, &av.Low, &cveStr, &av.Version, &av.BaseOS, &packagesBytes)

		if err != nil {
			return nil, err
		}

		// keep only CVE exist in vulMap
		var cveList []string
		err := json.Unmarshal([]byte(cveStr), &cveList)
		if err != nil {
			return nil, err
		}

		for _, c := range cveList {
			name, _, _ := parseCVEDbKey(c)
			if v, exist := vulMap[name]; exist {
				av.Vulnerabilities = append(av.Vulnerabilities, formatCVEName(name, v.Severity))
			}
		}

		// fetch the packages from matched assets
		fillCvePackages(cvePackages, packagesBytes)

		av.ID = assetId // TODO: for debug, remove later
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
		break
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
		break
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
		break
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
		break
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

func getCompiledRecord(assetVul *DbAssetVul) *exp.Record {
	var zipBytes []byte
	if len(assetVul.Packages) > 0 {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(&assetVul.Packages); err == nil {
			zipBytes = utils.GzipBytes(buf.Bytes())
		}
	}

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
		"p_base_os":    assetVul.P_base_os,
		"packagesb":    zipBytes,
	}

	return record
}

func parseCVEDbKey(cvedbkey string) (string, string, string) {
	name := cvedbkey
	dbkey := cvedbkey
	fix := "nf"
	parts := strings.Split(cvedbkey, ";")
	if len(parts) >= 3 {
		name = parts[0]
		dbkey = parts[1]
		fix = parts[2]
	}
	return name, dbkey, fix
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

func hasNamespaceFilter(queryFilter *api.VulQueryFilterViewModel) bool {
	if queryFilter.MatchType4Ns != "" && len(queryFilter.SelectedDomains) > 0 {
		return true
	}
	return false
}
