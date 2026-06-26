package db

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/doug-martin/goqu/v9"
	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	QueryStateType_Vul   = iota
	QueryStateType_Asset = iota
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

	Skip         bool
	MeetSearch   bool // for static data which needs all data even not within search result
	DBKey        string
	ImpactWeight int
	FeedRating   string

	HasNonFixPackage bool
}

type DbCVESource struct {
	ResourceID string `json:"resource_id"`
	DbKey      string `json:"dbkey"`
	BaseOS     string `json:"baseos"`
}

type VulQueryFilter struct {
	QueryToken                     string
	QueryStart                     int
	QueryCount                     int
	Debug                          int
	PerfTest                       int
	ThreadCount                    int
	CreateDummyAsset_Enable        int
	CreateDummyAsset_CVE           int
	CreateDummyAsset_Asset         int
	CreateDummyAsset_CVE_per_asset int
	Filters                        *api.VulQueryFilterViewModel
}

type AssetQueryFilter struct {
	QueryToken string
	QueryStart int
	QueryCount int
	Debug      int
	Filters    *api.AssetQueryFilterViewModel
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

	CVE_critical     int
	CVE_high         int
	CVE_medium       int
	CVE_low          int
	Vuls             []*share.ScanVulnerability
	Modules          []*share.ScanModule
	Scanned_at       string
	CVEDB_version    string
	CVEDB_createtime string

	N_os         string
	N_kernel     string
	N_cpus       int
	N_memory     int64
	N_containers int

	P_version string
	P_base_os string

	I_repository_name string
	I_repository_url  string
	I_base_os         string
	I_os_scan_status  string
	I_size            int64
	I_created_at      string
	I_scanned_at      string
	I_digest          string
	I_images          string
	I_tag             string

	Idns string
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
	dbFile_CVE            string = "/tmp/cve.db"
	dbFile_Folder         string = "/tmp"
	// https://github.com/mattn/go-sqlite3?tab=readme-ov-file#faq
	memoryDbFile string = "file::memory:?cache=shared"

	Table_vulassets  = "vulassets"
	Table_assetvuls  = "assetvuls"
	Table_querystats = "querystats"
	Table_bench      = "bench"
	Table_cvedb      = "cvedb"
)

var dbHandle *sql.DB = nil
var dbCVEHandle *sql.DB = nil
var memoryDbHandle *sql.DB = nil

var funcGetCveRecord func(string, string, string) *DbVulAsset
var funcGetCVEList func([]byte, string) []string
var funcFillVulPackages func(*sync.Mutex, map[string]map[string]utils.Set, []byte, string, *[]string, map[string]*int) error
var funcGetImageCVECount func(string, string) (int, int, int, error) // funcGetImageCVECount
var memdbMutex sync.RWMutex

// deleteDBAndWAL removes a SQLite database file and its WAL auxiliary files (-shm, -wal).
// Non-existence is silently ignored; other errors are logged at debug level.
func deleteDBAndWAL(path string) {
	for _, suffix := range []string{"", "-shm", "-wal"} {
		f := path + suffix
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.WithFields(log.Fields{"err": err, "file": f}).Debug("delete existing db file")
		}
	}
}

func CreateVulAssetDb(useLocal bool) error {
	dbFile := dbFile_Vulassets
	if useLocal {
		dbFile = dbFile_VulassetsLocal
	}

	// Delete the database file and its SQLite WAL auxiliary files so that stale
	// WAL data (e.g. from a previous run or from source control) cannot corrupt
	// the freshly created database.
	deleteDBAndWAL(dbFile)

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

	// Refer to the official documentation for guidance on avoiding this issue:
	// Error: database is locked
	// https://github.com/mattn/go-sqlite3
	memoryDbHandle.SetMaxOpenConns(1)

	statements := make([]string, 0)

	// create vulasset table
	// columns := getVulassetSchema()
	// statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", Table_vulassets, strings.Join(columns, ",")))
	// statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_name_idx on %s (name)", Table_vulassets, Table_vulassets))

	// querystats table
	columns := []string{"id INTEGER NOT NULL PRIMARY KEY", "token TEXT", "create_timestamp INTEGER", "login_type TEXT", "login_id TEXT", "login_name TEXT", "data1 TEXT", "data2 TEXT", "data3 TEXT", "filedb_ready INTEGER", "type INTEGER"}
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS querystats (%s)", strings.Join(columns, ",")))

	// assetvuls table
	columns = getAssetvulSchema(true)
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", Table_assetvuls, strings.Join(columns, ",")))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_assetid_idx on %s (assetid)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_w_domain_idx on %s (w_domain)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_w_service_group_idx on %s (w_service_group)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_name_idx on %s (name)", Table_assetvuls, Table_assetvuls))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_type_idx on %s (type)", Table_assetvuls, Table_assetvuls))

	// bench table
	columns = getBenchSchema()
	statements = append(statements, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", Table_bench, strings.Join(columns, ",")))
	statements = append(statements, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_assetid_idx on %s (assetid)", Table_bench, Table_bench))

	for _, oneSql := range statements {
		_, err = dbHandle.Exec(oneSql)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "oneSql": oneSql}).Debug("exec sql")
			return err
		}
	}

	return nil
}

// CreateCVEDb creates (or recreates) the dedicated cve.db SQLite database that holds
// CVEDB data separately from vulasset.db to avoid write-lock contention.
func CreateCVEDb() error {
	dbFile := dbFile_CVE

	// Delete the database file and its SQLite WAL auxiliary files so that stale
	// WAL data (e.g. from a previous run or from source control) cannot corrupt
	// the freshly created database.
	deleteDBAndWAL(dbFile)

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return err
	}
	dbCVEHandle = db

	statements := []string{
		// cvedb: one row per CVE lookup key (e.g. "ubuntu:CVE-2021-1234", "apps:foo", "CVE-2021-1234").
		// The prefix column holds the baseOS portion of the key and is indexed so that all entries
		// for one baseOS can be fetched with a single equality query.
		`CREATE TABLE IF NOT EXISTS cvedb (
			name               TEXT NOT NULL PRIMARY KEY,
			prefix             TEXT NOT NULL DEFAULT '',
			score              REAL DEFAULT 0,
			score_v3           REAL DEFAULT 0,
			severity           TEXT,
			description        TEXT,
			link               TEXT,
			vectors            TEXT,
			vectors_v3         TEXT,
			published_date     TEXT,
			last_modified_date TEXT,
			package_name       TEXT,
			fixed_version      TEXT,
			feed_rating        TEXT,
			in_base            INTEGER DEFAULT 0,
			db_key             TEXT,
			cpes               TEXT,
			cves               TEXT
		)`,
		"CREATE INDEX IF NOT EXISTS cvedb_prefix_idx ON cvedb (prefix)",
		"CREATE INDEX IF NOT EXISTS cvedb_db_key_idx ON cvedb (db_key)",
		// cvedb_meta: single row with current CVEDB version and create time.
		`CREATE TABLE IF NOT EXISTS cvedb_meta (
			id              INTEGER NOT NULL PRIMARY KEY,
			db_version      TEXT,
			db_create_time  TEXT
		)`,
	}

	for _, oneSql := range statements {
		if _, err = dbCVEHandle.Exec(oneSql); err != nil {
			log.WithFields(log.Fields{"err": err, "oneSql": oneSql}).Debug("exec sql")
			return err
		}
	}

	// Enable WAL mode so readers see the last-committed snapshot during a write transaction.
	// SQLite never returns a SQL error when WAL is unsupported (e.g. NFS); it silently falls
	// back to DELETE mode. We scan the returned mode string to detect that silent fallback.
	var journalMode string
	if err = dbCVEHandle.QueryRow("PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		log.WithFields(log.Fields{"err": err}).Warn("cvedb: failed to set WAL mode on cve.db")
	} else if journalMode != "wal" {
		log.WithFields(log.Fields{"mode": journalMode}).Warn("cvedb: WAL mode not active on cve.db; concurrent reads during writes will block")
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

func SetGetCVERecordFunc(funcObj func(string, string, string) *DbVulAsset) {
	funcGetCveRecord = funcObj
}

func SetGetCVEListFunc(funcObj func([]byte, string) []string) {
	funcGetCVEList = funcObj
}

func SetFillVulPackagesFunc(funcObj func(*sync.Mutex, map[string]map[string]utils.Set, []byte, string, *[]string, map[string]*int) error) {
	funcFillVulPackages = funcObj
}

func SetGetCVECountFunc(getImageCVECount func(string, string) (int, int, int, error)) {
	funcGetImageCVECount = getImageCVECount
}

func getVulassetSchema() []string {
	schema := []string{"id INTEGER NOT NULL PRIMARY KEY", "name TEXT", "severity TEXT", "description TEXT", "packages TEXT",
		"link TEXT", "score INTEGER", "vectors TEXT", "score_v3 INTEGER", "vectors_v3 TEXT",
		"published_timestamp INTEGER", "last_modified_timestamp INTEGER", "workloads TEXT",
		"nodes TEXT", "images TEXT", "platforms TEXT",
		"cve_sources TEXT",
		"f_withFix INTEGER", "f_profile INTEGER", "debuglog TEXT",
		"score_str TEXT", "scorev3_str TEXT", "impact_weight INTEGER",
		"feed_rating TEXT"}
	return schema
}

func getAssetvulSchema(uniqueAssetId bool) []string {
	assetIdColumn := "assetid TEXT"
	if uniqueAssetId {
		assetIdColumn = "assetid TEXT UNIQUE"
	}

	schema := []string{"id INTEGER NOT NULL PRIMARY KEY", "type TEXT", assetIdColumn, "name TEXT",
		"w_domain TEXT", "w_applications TEXT", "policy_mode TEXT", "w_service_group TEXT", "w_image TEXT",
		"cve_critical INTEGER", "cve_high INTEGER", "cve_medium INTEGER", "cve_low INTEGER", "cve_count INTEGER",
		"cvedb_version TEXT DEFAULT ''", "cvedb_createtime TEXT DEFAULT ''", "scanned_at TEXT",
		"n_os TEXT", "n_kernel TEXT", "n_cpus INTEGER", "n_memory INTEGER",
		"n_containers INTEGER", "p_version TEXT", "p_base_os TEXT", "idns TEXT", "vulsb BLOB", "modulesb BLOB",
		"I_created_at TEXT", "I_scanned_at TEXT", "I_digest TEXT", "I_base_os TEXT", "I_os_scan_status TEXT DEFAULT ''",
		"I_repository_name TEXT", "I_repository_url TEXT", "I_size INTEGER", "I_tag TEXT", "I_images TEXT"}

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

func convertToJSON(input interface{}) (string, error) {
	jsonData, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

const (
	COL_VULS    = 0x01
	COL_MODULES = 0x02
	// COL_ENVS    = 0x04
)

func GetVulnerability(assetid string) ([]*share.ScanVulnerability, error) {
	mapsb, err := getBytesColumns(assetid, COL_VULS)
	if err != nil {
		return nil, err
	}
	return UnzipVuls(mapsb[COL_VULS])
}

func GetVulnerabilityModule(assetid string) ([]*share.ScanVulnerability, []*share.ScanModule, error) {
	mapsb, err := getBytesColumns(assetid, COL_VULS|COL_MODULES)
	if err != nil {
		return nil, nil, err
	}

	vuls, err := UnzipVuls(mapsb[COL_VULS])
	if err != nil {
		return nil, nil, err
	}

	modules, err := UnzipModules(mapsb[COL_MODULES])
	if err != nil {
		return nil, nil, err
	}

	return vuls, modules, nil
}

func unzipAndDecode(data []byte, target interface{}) error {
	uzb := utils.GunzipBytes(data)
	if uzb == nil {
		return errors.New("failed to unzip data")
	}
	buf := bytes.NewBuffer(uzb)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(target); err != nil {
		return err
	}
	return nil
}

func UnzipModules(sb []byte) ([]*share.ScanModule, error) {
	var modules []*share.ScanModule

	if len(sb) == 0 {
		return modules, nil
	}

	err := unzipAndDecode(sb, &modules)
	return modules, err
}

func UnzipVuls(vulsb []byte) ([]*share.ScanVulnerability, error) {
	var vuls []*share.ScanVulnerability

	if len(vulsb) == 0 {
		return vuls, nil
	}

	err := unzipAndDecode(vulsb, &vuls)
	return vuls, err
}

func getBytesColumns(assetid string, columnFlags int) (map[int][]byte, error) {
	if dbHandle == nil {
		return nil, errors.New("db is not initialized")
	}

	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	results := make(map[int][]byte, 0)
	columns := []interface{}{}
	paramMaps := make([]int, 0)
	if columnFlags&COL_VULS != 0 {
		columns = append(columns, "vulsb")
		paramMaps = append(paramMaps, COL_VULS)
	}
	if columnFlags&COL_MODULES != 0 {
		columns = append(columns, "modulesb")
		paramMaps = append(paramMaps, COL_MODULES)
	}

	statement, args, err := dialect.From(Table_assetvuls).Select(columns...).Where(goqu.Ex{"assetid": assetid}).Prepared(true).ToSQL()
	if err != nil {
		return results, fmt.Errorf("failed to build asset vuls query: %w", err)
	}
	rows, err := db.Query(statement, args...)
	if err != nil {
		return results, err
	}
	defer rows.Close()
	for rows.Next() {
		params := make([]*[]byte, len(columns))
		scanArgs := make([]interface{}, len(columns))
		for i := range params {
			scanArgs[i] = &params[i]
		}
		err = rows.Scan(scanArgs...)
		if err != nil {
			return results, err
		}
		for i, param := range params {
			if param != nil {
				key := paramMaps[i]
				results[key] = *param
			}
		}
	}
	return results, nil
}
