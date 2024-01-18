package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

type DbVulAsset struct {
	Db_ID       int
	Name        string
	Severity    string
	Description string
	Packages    string
	Link        string
	Score       int
	Vectors     string
	ScoreV3     int
	VectorsV3   string
	PublishedTS int64
	LastModTS   int64

	Workloads string
	Nodes     string
	Images    string
	Platforms string

	WorkloadItems []string
	NodeItems     []string
	ImageItems    []string
	PlatformItems []string

	CVESources string

	F_withFix int
	F_profile int

	DebugLog []string

	Skip       bool
	MeetSearch bool // for static data which needs all data even not within search result
}

type DbCVESource struct {
	ResourceID string `json:"resource_id"`
	DbKey      string `json:"dbkey"`
	BaseOS     string `json:"baseos"`
}

type DbVulnResourcePackageVersion struct {
	ResourceID     string `json:"id"`
	PackageVersion string `json:"pv"`
	FixedVersion   string `json:"fv"`
}

type VulQueryFilter struct {
	QueryToken                     string
	QueryStart                     int
	QueryCount                     int
	Debug                          int
	PerfTest                       int
	CreateDummyAsset_Enable        int
	CreateDummyAsset_CVE           int
	CreateDummyAsset_Asset         int
	CreateDummyAsset_CVE_per_asset int
	Filters                        *api.VulQueryFilterViewModel
}

type DbAssetVul struct {
	Db_ID   int
	Type    string
	AssetID string
	Name    string

	W_domain         string
	W_applications   string
	Policy_mode      string
	W_service_group  string
	W_workload_image string

	CVE_high   int
	CVE_medium int
	CVE_low    int
	CVE_lists  string
	Scanned_at string

	N_os         string
	N_kernel     string
	N_cpus       int
	N_memory     int64
	N_containers int

	P_version string
	P_base_os string
}

type AssetMaps struct {
	workloads map[string]*api.RESTWorkloadAsset
	hosts     map[string]*api.RESTHostAsset
	platforms map[string]*api.RESTPlatformAsset
	images    map[string]*api.RESTImageAsset
}

type ResourceType int

const (
	TypeWorkload ResourceType = iota
	TypeNode
	TypeImage
	TypePlatform
)

const (
	startQueryParam  = "start"
	rowQueryParam    = "row"
	defaultStart     = 0
	defaultRowCount  = 100
	defaultDebugMode = 0
)

const (
	AssetImage    string = "image"
	AssetWorkload string = "workload"
	AssetPlatform string = "platform"
	AssetNode     string = "host"
)

const (
	AssetRuleDomain    = "domain"
	AssetRuleService   = "service"
	AssetRuleNode      = "node"
	AssetRuleContainer = "container"
	AssetRuleImage     = "image"
	AssetRulePlatform  = "platform"
)

const (
	dbFile_Vulassets      string = "/tmp/vulasset.db"
	dbFile_VulassetsLocal string = "./vulasset.db"
	dbFile_Folder         string = "/tmp"
	memoryDbFile          string = ":memory:"

	Table_vulassets  = "vulassets"
	Table_assetvuls  = "assetvuls"
	Table_querystats = "querystats"
)

var dbHandle *sql.DB = nil
var memoryDbHandle *sql.DB = nil
var GetCveRecordFunc func(string, string, string) *DbVulAsset
var memdbMutex sync.RWMutex
var vulassetdbMutex sync.RWMutex

func CreateVulAssetDb(useLocal bool) error {
	dbFile := dbFile_Vulassets
	if useLocal {
		dbFile = dbFile_VulassetsLocal
	}

	// delete existing file
	if _, err := os.Stat(dbFile); err == nil {
		err := os.Remove(dbFile)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "file": dbFile}).Debug("delete existing db file")
		}
	}

	// create file based db
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return err
	}
	dbHandle = db

	// create memory db
	db, err = sql.Open("sqlite3", memoryDbFile)
	if err != nil {
		return err
	}
	memoryDbHandle = db

	statements := make([]string, 0)

	// create vulasset table
	columns := getVulassetSchema()
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", Table_vulassets, strings.Join(columns, ",")))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_name_idx on %s (name)", Table_vulassets, Table_vulassets))

	// querystats table
	columns = []string{"id INTEGER NOT NULL PRIMARY KEY", "token TEXT", "create_timestamp INTEGER", "login_type TEXT", "login_id TEXT", "login_name TEXT", "data1 TEXT", "data2 TEXT", "data3 TEXT", "filedb_ready INTEGER"}
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS querystats (%s)", strings.Join(columns, ",")))

	// assetvuls table
	columns = getAssetvulSchema()
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", Table_assetvuls, strings.Join(columns, ",")))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_assetid_idx on %s (assetid)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_w_domain_idx on %s (w_domain)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_w_service_group_idx on %s (w_service_group)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_name_idx on %s (name)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_type_idx on %s (type)", Table_assetvuls, Table_assetvuls))

	for _, oneSql := range statements {
		_, err = dbHandle.Exec(oneSql)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "oneSql": oneSql}).Debug("exec sql")
			return err
		}
	}

	return nil
}

func reopenMemoryDb() error {
	if memoryDbHandle != nil {
		memoryDbHandle.Close()
	}

	db, err := sql.Open("sqlite3", memoryDbFile)
	if err != nil {
		return err
	}
	memoryDbHandle = db
	return nil
}

func GetAllTableInMemoryDb() string {
	names := make([]string, 0)
	rows, err := memoryDbHandle.Query("SELECT name FROM sqlite_master WHERE type='table';")
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return ""
		}
		names = append(names, tableName)
	}

	return strings.Join(names, ";")
}

func InitGetCVERecord(getCVERecord func(string, string, string) *DbVulAsset) {
	GetCveRecordFunc = getCVERecord
}

func getVulassetSchema() []string {
	schema := []string{"id INTEGER NOT NULL PRIMARY KEY", "name TEXT", "severity TEXT", "description TEXT", "packages TEXT",
		"link TEXT", "score INTEGER", "vectors TEXT", "score_v3 INTEGER", "vectors_v3 TEXT",
		"published_timestamp INTEGER", "last_modified_timestamp INTEGER", "workloads TEXT",
		"nodes TEXT", "images TEXT", "platforms TEXT",
		"cve_sources TEXT",
		"f_withFix INTEGER", "f_profile INTEGER", "debuglog TEXT",
		"score_str TEXT", "scorev3_str TEXT"}
	return schema
}

func getVulassetColumns() []interface{} {
	schema := getVulassetSchema()

	var interfaceSlice []interface{}
	for _, s := range schema {
		parts := strings.Split(s, " ")
		if len(parts) > 0 {
			interfaceSlice = append(interfaceSlice, parts[0])
		}
	}
	return interfaceSlice
}

func getAssetvulSchema() []string {
	schema := []string{"id INTEGER NOT NULL PRIMARY KEY", "type TEXT", "assetid TEXT UNIQUE", "name TEXT",
		"w_domain TEXT", "w_applications TEXT", "policy_mode TEXT", "w_service_group TEXT", "w_image TEXT",
		"cve_high INTEGER", "cve_medium INTEGER", "cve_low INTEGER", "cve_count INTEGER", "cve_lists TEXT", "scanned_at TEXT",
		"n_os TEXT", "n_kernel TEXT", "n_cpus INTEGER", "n_memory INTEGER",
		"n_containers INTEGER", "p_version TEXT", "p_base_os TEXT"}
	return schema
}

func formatSessionTempTableName(queryToken string) string {
	return fmt.Sprintf("tmp_session_%s", queryToken)
}

func getQueryParamInteger(r *http.Request, name string, defaultValue int) int {
	param := r.URL.Query().Get(name)

	intValue, err := strconv.Atoi(param)
	if err != nil {
		intValue = defaultValue
	}
	return intValue
}

func getQueryParamInteger64(r *http.Request, name string, defaultValue int64) int64 {
	param := r.URL.Query().Get(name)

	intValue, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		intValue = defaultValue
	}
	return intValue
}

func formatScoreToStr(score int) string {
	f := float32(score) / 10.0
	return fmt.Sprintf("%.1f", f)
}

func validateOrDefault(value string, possibleValues []string, defaultValue string) string {
	for _, v := range possibleValues {
		if value == v {
			return value
		}
	}
	return defaultValue
}

func parseJsonStrToSlice(jsonStr string) []string {
	results := make([]string, 0)
	err := json.Unmarshal([]byte(jsonStr), &results)
	if err != nil {
		return []string{}
	}
	return results
}

func parseJsonStrToSet(jsonStr string) utils.Set {
	resourceSet := utils.NewSet()

	items := make([]string, 0)
	err := json.Unmarshal([]byte(jsonStr), &items)
	if err != nil {
		return resourceSet
	}

	for _, r := range items {
		resourceSet.Add(r)
	}
	return resourceSet
}

func convertToJSON(input interface{}) (string, error) {
	jsonData, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func deleteItemInSlice(assetsInJson string, itemToDelete string) string {
	slice := parseJsonStrToSlice(assetsInJson)

	indexToDelete := -1
	for i, item := range slice {
		if item == itemToDelete {
			indexToDelete = i
			break
		}
	}

	if indexToDelete != -1 {
		slice = append(slice[:indexToDelete], slice[indexToDelete+1:]...)
	}

	str, err := convertToJSON(slice)
	if err != nil {
		return assetsInJson // delete fail
	}
	return str
}
