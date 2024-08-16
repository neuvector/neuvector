package db

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alitto/pond"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"

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
		ds := dialect.Insert(targetTable).Rows(getCompiledAssetVulRecord(assetVul))
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
	sql, args, _ := dialect.Update(targetTable).Where(goqu.C("id").Eq(assetVul.Db_ID)).Set(getCompiledAssetVulRecord(assetVul)).Prepared(true).ToSQL()
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

	if len(assets) == 0 {
		return records, nil
	}

	columns := []interface{}{"assetid", "name", "w_domain", "w_applications", "policy_mode", "w_service_group",
		"scanned_at", "idns", "vulsb", "w_image"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForWorkload(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	poolSize := queryFilter.ThreadCount
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))
	var mux sync.Mutex

	for rows.Next() {
		av := &api.RESTWorkloadAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, apps, idnsStr string
		var vulsBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.Domain, &apps, &av.PolicyMode, &av.ServiceGroup, &av.ScannedAt, &idnsStr, &vulsBytes, &av.Image)

		if err != nil {
			pool.StopAndWait()
			return nil, err
		}

		av.Applications = parseJsonStrToSlice(apps)

		cveStats := map[string]*int{
			"High":   &av.High,
			"Medium": &av.Medium,
			"Low":    &av.Low,
		}

		batchProcessAssetView(pool, &mux, cvePackages, vulsBytes, idnsStr, &av.Vulnerabilities, vulMap, cveStats)

		av.ID = assetId
		records = append(records, av)
	}
	pool.StopAndWait()

	return records, nil
}

func getHostAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTHostAssetView, error) {
	records := make([]*api.RESTHostAssetView, 0)

	if len(assets) == 0 {
		return records, nil
	}

	columns := []interface{}{"assetid", "name", "policy_mode",
		"scanned_at", "n_os", "n_kernel", "n_cpus", "n_memory", "n_containers", "idns", "vulsb"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForNode(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	poolSize := queryFilter.ThreadCount
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))
	var mux sync.Mutex

	for rows.Next() {
		av := &api.RESTHostAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, idnsStr string
		var vulsBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.PolicyMode,
			&av.ScannedAt, &av.OS, &av.Kernel, &av.CPUs, &av.Memory, &av.Containers, &idnsStr, &vulsBytes)
		if err != nil {
			pool.StopAndWait()
			return nil, err
		}

		cveStats := map[string]*int{
			"High":   &av.High,
			"Medium": &av.Medium,
			"Low":    &av.Low,
		}
		batchProcessAssetView(pool, &mux, cvePackages, vulsBytes, idnsStr, &av.Vulnerabilities, vulMap, cveStats)

		av.ID = assetId
		records = append(records, av)
	}
	pool.StopAndWait()

	return records, nil
}

func getImageAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTImageAssetView, error) {
	records := make([]*api.RESTImageAssetView, 0)

	if len(assets) == 0 {
		return records, nil
	}

	columns := []interface{}{"assetid", "name", "idns", "vulsb"}
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForImage(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	poolSize := queryFilter.ThreadCount
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))
	var mux sync.Mutex

	for rows.Next() {
		av := &api.RESTImageAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, idnsStr string
		var vulsBytes []byte
		err = rows.Scan(&assetId, &av.Name, &idnsStr, &vulsBytes)

		if err != nil {
			pool.StopAndWait()
			return nil, err
		}

		cveStats := map[string]*int{
			"High":   &av.High,
			"Medium": &av.Medium,
			"Low":    &av.Low,
		}
		batchProcessAssetView(pool, &mux, cvePackages, vulsBytes, idnsStr, &av.Vulnerabilities, vulMap, cveStats)

		av.ID = assetId
		records = append(records, av)
	}
	pool.StopAndWait()

	return records, nil
}

func getPlatformAssetView(vulMap map[string]*DbVulAsset, assets []string, queryFilter *VulQueryFilter, cvePackages map[string]map[string]utils.Set) ([]*api.RESTPlatformAssetView, error) {
	records := make([]*api.RESTPlatformAssetView, 0)

	if len(assets) == 0 {
		return records, nil
	}

	columns := []interface{}{"assetid", "name", "p_version", "p_base_os", "idns", "vulsb"}
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(buildWhereClauseForPlatform(assets, queryFilter.Filters)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	poolSize := 1
	pool := pond.New(poolSize, 0, pond.MinWorkers(poolSize))
	var mux sync.Mutex
	for rows.Next() {
		av := &api.RESTPlatformAssetView{}
		av.Vulnerabilities = make([]string, 0)

		var assetId, idnsStr string
		var vulsBytes []byte
		err = rows.Scan(&assetId, &av.Name, &av.Version, &av.BaseOS, &idnsStr, &vulsBytes)

		if err != nil {
			pool.StopAndWait()
			return nil, err
		}

		cveStats := map[string]*int{
			"High":   &av.High,
			"Medium": &av.Medium,
			"Low":    &av.Low,
		}
		batchProcessAssetView(pool, &mux, cvePackages, vulsBytes, idnsStr, &av.Vulnerabilities, vulMap, cveStats)
		av.ID = assetId
		records = append(records, av)
	}
	pool.StopAndWait()

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
			as := &api.RESTWorkloadAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &as.Domain, &as.PolicyMode, &as.Service, &as.Image)

			if err != nil {
				return nil, err
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
	columns := []interface{}{"assetid", "name", "policy_mode"}

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
			as := &api.RESTHostAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &as.PolicyMode)
			if err != nil {
				return nil, err
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
	columns := []interface{}{"assetid", "name", "policy_mode"}

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
			as := &api.RESTPlatformAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &as.PolicyMode)
			if err != nil {
				return nil, err
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
	columns := []interface{}{"assetid", "name", "policy_mode"}

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
			as := &api.RESTImageAsset{}
			err = rows.Scan(&as.ID, &as.DisplayName, &as.PolicyMode)
			if err != nil {
				return nil, err
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

func encodeAndCompress(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}
	return utils.GzipBytes(buf.Bytes()), nil
}

func getCompiledAssetVulRecord(assetVul *DbAssetVul) *exp.Record {
	var vulsBytes, modulesBytes []byte
	if len(assetVul.Vuls) > 0 {
		vulsBytes, _ = encodeAndCompress(assetVul.Vuls)
	}

	if len(assetVul.Modules) > 0 {
		modulesBytes, _ = encodeAndCompress(assetVul.Modules)
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

		"cve_critical": assetVul.CVE_critical,
		"cve_high":     assetVul.CVE_high,
		"cve_medium":   assetVul.CVE_medium,
		"cve_low":      assetVul.CVE_low,
		"cve_count":    assetVul.CVE_high + assetVul.CVE_medium + assetVul.CVE_low + assetVul.CVE_critical,
		"scanned_at":   assetVul.Scanned_at,

		"n_os":     assetVul.N_os,
		"n_kernel": assetVul.N_kernel,
		"n_cpus":   assetVul.N_cpus,
		"n_memory": assetVul.N_memory,

		"n_containers": assetVul.N_containers,
		"p_version":    assetVul.P_version,
		"p_base_os":    assetVul.P_base_os,
		"idns":         assetVul.Idns,
		"vulsb":        vulsBytes,
		"modulesb":     modulesBytes,

		"I_created_at":      assetVul.I_created_at,
		"I_scanned_at":      assetVul.I_scanned_at,
		"I_digest":          assetVul.I_digest,
		"I_base_os":         assetVul.I_base_os,
		"I_repository_name": assetVul.I_repository_name,
		"I_repository_url":  assetVul.I_repository_url,
		"I_size":            assetVul.I_size,
		"I_images":          assetVul.I_images,
		"I_tag":             assetVul.I_tag,
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

func batchProcessAssetView(pool *pond.WorkerPool, mu *sync.Mutex, cvePackages map[string]map[string]utils.Set, vulsBytes []byte, idnsStr string, vulnerabilities *[]string, vulMap map[string]*DbVulAsset, cveStat map[string]*int) {
	pool.Submit(func() {
		cveList := make([]string, 0)
		funcFillVulPackages(mu, cvePackages, vulsBytes, idnsStr, &cveList, cveStat)

		for _, c := range cveList {
			name, _, _ := parseCVEDbKey(c)
			if v, exist := vulMap[name]; exist {
				*vulnerabilities = append(*vulnerabilities, formatCVEName(name, v.Severity))
			}
		}
	})
}

func GetAssetQuery(r *http.Request) (*AssetQueryFilter, error) {
	q := &AssetQueryFilter{
		Filters: &api.AssetQueryFilterViewModel{},
	}

	q.QueryToken = r.URL.Query().Get("token")
	q.QueryStart = getQueryParamInteger(r, startQueryParam, defaultStart)
	q.QueryCount = getQueryParamInteger(r, rowQueryParam, defaultRowCount)
	q.Debug = getQueryParamInteger(r, "debug", defaultDebugMode)

	if r.Method == http.MethodPost {
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

	if r.Method == http.MethodGet {
		q.Filters.OrderByColumn = r.URL.Query().Get("orderbyColumn")
		q.Filters.OrderByType = r.URL.Query().Get("orderby")

		q.Filters.OrderByColumn = validateOrDefault(q.Filters.OrderByColumn, []string{"repository", "imageid", "imageid", "createdat", "os", "size", "scannedat", "cvecount"}, "repository")
		q.Filters.OrderByType = validateOrDefault(q.Filters.OrderByType, []string{"asc", "desc"}, "asc")

		q.Filters.QuickFilter = r.URL.Query().Get("qf")
	}

	return q, nil
}

func CreateImageAssetSession(allowed map[string]utils.Set, queryFilter *AssetQueryFilter) (int, []*api.AssetCVECount, error) {
	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	columns := []interface{}{"type", "assetid", "name",
		"cve_critical", "cve_high", "cve_medium", "cve_low",
		"I_created_at", "I_scanned_at", "I_digest", "I_base_os", "I_repository_name", "I_repository_url", "I_size", "I_images"}

	statement, args, _ := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.Ex{"type": "image"}).Prepared(true).ToSQL()
	log.WithFields(log.Fields{"statement": statement, "args": args}).Debug("CreateImageAssetSession, fetch assets")
	rows, err := db.Query(statement, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	queryToken := queryFilter.QueryToken

	err = CreateSessionAssetTable(queryToken, true)
	if err != nil {
		return 0, nil, err
	}

	assetCount := 0
	for rows.Next() {
		asset := &DbAssetVul{}

		err = rows.Scan(&asset.Type, &asset.AssetID, &asset.Name,
			&asset.CVE_critical, &asset.CVE_high, &asset.CVE_medium, &asset.CVE_low,
			&asset.I_created_at, &asset.I_scanned_at, &asset.I_digest, &asset.I_base_os,
			&asset.I_repository_name, &asset.I_repository_url, &asset.I_size, &asset.I_images)
		if err != nil {
			return 0, nil, err
		}

		if !allowed[AssetImage].Contains(asset.AssetID) {
			continue
		}

		//
		var images []share.CLUSImage
		err = json.Unmarshal([]byte(asset.I_images), &images)
		if err != nil {
			log.WithFields(log.Fields{"I_images": asset.I_images, "err": err}).Error("invalid I_images data")
			continue
		}

		// insert into session table
		for _, imgObj := range images {
			assetCount++
			asset.Name = imgObj.Repo
			asset.I_tag = imgObj.Tag

			// get cve count as it is VPF dependent
			criticalCount, highCount, medCount, err := funcGetImageCVECount(asset.I_repository_name, asset.AssetID)
			if err == nil {
				asset.CVE_critical = criticalCount
				asset.CVE_high = highCount
				asset.CVE_medium = medCount
			}

			_, err = insertSessionAssetRecord(memoryDbHandle, queryToken, asset)
			if err != nil {
				return 0, nil, err
			}
		}
	}

	// do summary - top5 and others
	sessionTable := formatSessionTempTableName(queryToken)
	statement, args, _ = dialect.From(sessionTable).Select("assetid", "name", "cve_critical", "cve_high", "cve_medium", "cve_low").Where(goqu.Ex{"type": "image"}).Order(goqu.C("cve_count").Desc()).Prepared(true).ToSQL()

	rows, err = memoryDbHandle.Query(statement, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	tops := make([]*api.AssetCVECount, 0)
	other := &api.AssetCVECount{
		DisplayName: "others",
		ID:          "",
	}
	for rows.Next() {
		record := &api.AssetCVECount{}
		err = rows.Scan(&record.ID, &record.DisplayName, &record.Critical, &record.High, &record.Medium, &record.Low)
		if err != nil {
			return 0, nil, err
		}

		if len(tops) < 5 {
			// temporarily revert critical cve logic
			record.Critical = -1
			tops = append(tops, record)
		} else {
			other.Critical += record.Critical
			other.High += record.High
			other.Medium += record.Medium
			other.Low += record.Low
		}
	}

	// temporarily revert critical cve logic
	other.Critical = -1

	tops = append(tops, other) // the 6th record is for other

	return assetCount, tops, nil
}

func insertSessionAssetRecord(db *sql.DB, sessionToken string, assetVul *DbAssetVul) (int, error) {
	tableName := formatSessionTempTableName(sessionToken)

	record := getCompiledAssetVulRecord(assetVul)

	dialect := goqu.Dialect("sqlite3")
	ds := dialect.Insert(tableName).Rows(record)
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

func DupAssetSessionTableToFile(sessionToken string) error {
	dialect := goqu.Dialect("sqlite3")
	sessionDb, err := createSessionFileDb(sessionToken)
	if err != nil {
		return err
	}
	defer sessionDb.Close()

	err = createSessionAssetTable(sessionDb, sessionToken)
	if err != nil {
		return err
	}

	columns := []interface{}{"type", "assetid", "name",
		"cve_critical", "cve_high", "cve_medium", "cve_low",
		"I_created_at", "I_scanned_at", "I_digest", "I_base_os",
		"I_repository_name", "I_repository_url", "I_size", "I_tag"}

	tableName := formatSessionTempTableName(sessionToken)
	statement, args, _ := dialect.From(tableName).Select(columns...).Prepared(true).ToSQL()
	rows, err := memoryDbHandle.Query(statement, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		asset := &DbAssetVul{}

		err = rows.Scan(&asset.Type, &asset.AssetID, &asset.Name,
			&asset.CVE_critical, &asset.CVE_high, &asset.CVE_medium, &asset.CVE_low,
			&asset.I_created_at, &asset.I_scanned_at, &asset.I_digest, &asset.I_base_os,
			&asset.I_repository_name, &asset.I_repository_url, &asset.I_size, &asset.I_tag)
		if err != nil {
			return err
		}

		_, err := insertSessionAssetRecord(sessionDb, sessionToken, asset)
		if err != nil {
			return err
		}
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

func GetImageAssetSession(queryFilter *AssetQueryFilter) ([]*api.RESTImageAssetViewV2, int, error) {

	getOrderColumn := func(queryFilter *AssetQueryFilter) []exp.OrderedExpression {
		if queryFilter.Filters.OrderByColumn == "cvecount" {
			if queryFilter.Filters.OrderByType == "desc" {
				return []exp.OrderedExpression{goqu.C("cve_critical").Desc(), goqu.C("cve_high").Desc(), goqu.C("cve_medium").Desc()}
			}
			return []exp.OrderedExpression{goqu.C("cve_critical").Asc(), goqu.C("cve_high").Asc(), goqu.C("cve_medium").Asc()}
		}

		column := "name"
		switch queryFilter.Filters.OrderByColumn {
		case "repository":
			column = "name"
		case "imageid":
			column = "assetid"
		case "createdat":
			column = "I_created_at"
		case "os":
			column = "I_base_os"
		case "size":
			column = "I_size"
		case "scannedat":
			column = "I_scanned_at"
		}

		if queryFilter.Filters.OrderByType == "desc" { // asc, desc
			return []exp.OrderedExpression{goqu.I(column).Desc()}
		}
		return []exp.OrderedExpression{goqu.I(column).Asc()}
	}

	buildWhereClause := func(queryFilter *AssetQueryFilter) exp.ExpressionList {
		if queryFilter.Filters.QuickFilter != "" {
			repo_exp := goqu.C("name").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			id_exp := goqu.C("assetid").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			os_exp := goqu.C("I_base_os").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			createat_exp := goqu.C("I_created_at").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			scanned_exp := goqu.C("I_scanned_at").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))

			repo_name_exp := goqu.C("I_repository_name").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))
			repo_url_exp := goqu.C("I_repository_url").Like(fmt.Sprintf("%%%s%%", queryFilter.Filters.QuickFilter))

			return goqu.Or(repo_exp, id_exp, os_exp, createat_exp, scanned_exp, repo_name_exp, repo_url_exp)
		}

		return goqu.And(goqu.Ex{})
	}

	columns := []interface{}{"assetid", "name",
		"cve_critical", "cve_high", "cve_medium",
		"I_created_at", "I_scanned_at", "I_digest", "I_base_os",
		"I_repository_name", "I_repository_url", "I_size", "I_tag"}

	sessionToken := queryFilter.QueryToken
	start := queryFilter.QueryStart
	row := queryFilter.QueryCount

	sessionTemp := formatSessionTempTableName(sessionToken)

	dialect := goqu.Dialect("sqlite3")
	var statement string
	var args []interface{}
	if row == -1 {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Where(buildWhereClause(queryFilter)).Order(getOrderColumn(queryFilter)...).Prepared(true).ToSQL() // select all
	} else {
		statement, args, _ = dialect.From(sessionTemp).Select(columns...).Where(buildWhereClause(queryFilter)).Order(getOrderColumn(queryFilter)...).Limit(uint(row)).Offset(uint(start)).Prepared(true).ToSQL()
	}

	queryStat, err := GetQueryStat(sessionToken)
	if err != nil {
		return nil, 0, err
	}

	// fetch data
	var db *sql.DB
	if queryStat.FileDBReady == 1 {
		db, err = openSessionFileDb(sessionToken)
		if err != nil {
			return nil, 0, err
		}
		defer db.Close() // close it after done
	} else {
		db = memoryDbHandle
	}

	log.WithFields(log.Fields{"statement": statement, "args": args, "db-file": queryStat.FileDBReady}).Debug("fetch assets")

	// execute the query
	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	assets := make([]*api.RESTImageAssetViewV2, 0)
	for rows.Next() {
		asset := &api.RESTImageAssetViewV2{}

		err = rows.Scan(&asset.ID, &asset.Name,
			&asset.Critical, &asset.High, &asset.Medium,
			&asset.CreatedAt, &asset.ScannedAt, &asset.Digest, &asset.BaseOS,
			&asset.RegName, &asset.Registry, &asset.Size, &asset.Tag)
		if err != nil {
			return nil, 0, err
		}
		asset.Registry = fmt.Sprintf("%s%s:%s", asset.Registry, asset.Name, asset.Tag)

		asset.Critical = -1 // temporarily revert critical cve logic
		assets = append(assets, asset)
	}

	// expected behavior
	// 1. when no quick filter, return all assets count
	// 2. has quick filter, return the matched assets count
	quickFilterMatched := 0
	sql, _, _ := goqu.From(sessionTemp).Select(goqu.COUNT("*").As("count")).Where(buildWhereClause(queryFilter)).ToSQL()

	rows, err = db.Query(sql)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&quickFilterMatched)
		if err != nil {
			return nil, 0, err
		}
	}

	return assets, quickFilterMatched, nil
}
