package common

// #include "../../defs.h"
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	syslog "github.com/RackSec/srslog"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/utils"
)

const DefaultIdleTimeout uint32 = 300
const DefaultAdminUser string = "admin"
const DefaultAdminPass string = "admin"

const ScanPlatformID = "platform"

type LocalDevice struct {
	Host   *share.CLUSHost
	Ctrler *share.CLUSController
}

type WorkloadFilter struct {
	ID           string
	PodName      string
	ImageID      string
	PlatformRole string
	Domain       string
	PolicyMode   string
	Children     []*WorkloadFilter
}

type RPCEndpoint struct {
	ID            string
	Leader        bool
	ClusterIP     string
	RPCServerPort uint16
}

type CacheEventFunc func(ev share.TLogEvent, msg string) error

var ErrObjectNotFound error = errors.New("Object not found")
var ErrObjectAccessDenied error = errors.New("Access denied")
var ErrObjectExists error = errors.New("Object exists")
var ErrAtomicWriteFail error = errors.New("Atomic write failed")
var ErrUnsupported error = errors.New("Unsupported action")

var defaultWebhookCategory []string = []string{}
var defaultSyslogCategory []string = []string{
	api.CategoryEvent, api.CategoryRuntime, api.CategoryAudit,
}

const defaultClusterName string = "cluster.local"

var DefaultSystemConfig = share.CLUSSystemConfig{
	NewServicePolicyMode:      share.PolicyModeLearn,
	NewServiceProfileBaseline: share.ProfileBasic,
	UnusedGroupAging:          share.UnusedGroupAgingDefault,
	CLUSSyslogConfig: share.CLUSSyslogConfig{
		SyslogIP:         nil,
		SyslogServer:     "",
		SyslogIPProto:    syscall.IPPROTO_UDP,
		SyslogPort:       api.SyslogDefaultUDPPort,
		SyslogLevel:      api.LogLevelINFO,
		SyslogEnable:     false,
		SyslogCategories: defaultSyslogCategory,
		SyslogInJSON:     false,
	},
	AuthOrder:       []string{},
	ClusterName:     defaultClusterName,
	Webhooks:        []share.CLUSWebhook{},
	ControllerDebug: []string{},
	TapProxymesh:    true,
	XffEnabled:      true,
}

func ActionString(action uint8) string {
	switch action {
	case C.DPI_ACTION_NONE:
		return "NONE"
	case C.DPI_ACTION_ALLOW:
		return "ALLOW"
	case C.DPI_ACTION_DROP:
		return "DROP"
	case C.DPI_ACTION_RESET:
		return "RESET"
	case C.DPI_ACTION_BYPASS:
		return "BYPASS"
	case C.DPI_ACTION_BLOCK:
		return "BLOCK"
	default:
		return "NONE"
	}
}

func PolicyActionString(action uint8) string {
	switch action {
	case C.DP_POLICY_ACTION_OPEN:
		return share.PolicyActionOpen
	case C.DP_POLICY_ACTION_LEARN:
		return share.PolicyActionLearn
	case C.DP_POLICY_ACTION_ALLOW:
		return share.PolicyActionAllow
	case C.DP_POLICY_ACTION_DENY:
		return share.PolicyActionDeny
	case C.DP_POLICY_ACTION_VIOLATE:
		return share.PolicyActionViolate
	case C.DP_POLICY_ACTION_CHECK_APP:
		return share.PolicyActionCheckApp
	default:
		return share.PolicyActionAllow
	}
}

func PolicyActionRESTString(action uint8) string {
	switch action {
	case C.DP_POLICY_ACTION_OPEN:
		return share.PolicyActionOpen
	case C.DP_POLICY_ACTION_LEARN:
		return share.PolicyActionAllow
	case C.DP_POLICY_ACTION_ALLOW:
		return share.PolicyActionAllow
	case C.DP_POLICY_ACTION_DENY:
		return share.PolicyActionDeny
	case C.DP_POLICY_ACTION_VIOLATE:
		return share.PolicyActionViolate
	case C.DP_POLICY_ACTION_CHECK_APP:
		return share.PolicyActionCheckApp
	default:
		return share.PolicyActionAllow
	}
}

func SeverityString(severity uint8) (string, string) {
	switch severity {
	case C.THRT_SEVERITY_INFO:
		return api.SeverityInfo, api.LogLevelINFO
	case C.THRT_SEVERITY_LOW:
		return api.SeverityLow, api.LogLevelNOTICE
	case C.THRT_SEVERITY_MEDIUM:
		return api.SeverityMedium, api.LogLevelWARNING
	case C.THRT_SEVERITY_HIGH:
		return api.SeverityHigh, api.LogLevelERR
	case C.THRT_SEVERITY_CRITICAL:
		return api.SeverityCritical, api.LogLevelCRIT
	default:
		return "", ""
	}
}

// For name match in response rule
const NetworkViolation string = "Network.Violation"
const DlpPrefix string = "DLP."
const WafPrefix string = "WAF."

// Threat attributes are separated into two places. Eventually they will be generated from a single source
type LogThreatInfo struct {
	Name string
}

var LogThreatMap = map[uint32]LogThreatInfo{
	C.THRT_ID_SYN_FLOOD:         {"TCP.SYN.Flood"},
	C.THRT_ID_ICMP_FLOOD:        {"ICMP.Flood"},
	C.THRT_ID_IP_SRC_SESSION:    {"Source.IP.Session.Limit"},
	C.THRT_ID_BAD_PACKET:        {"Invalid.Packet.Format"},
	C.THRT_ID_IP_TEARDROP:       {"IP.Fragment.Teardrop"},
	C.THRT_ID_TCP_SYN_DATA:      {"TCP.SYN.With.Data"},
	C.THRT_ID_TCP_SPLIT_HDSHK:   {"TCP.Split.Handshake"},
	C.THRT_ID_TCP_NODATA:        {"TCP.No.Client.Data"},
	C.THRT_ID_TCP_SMALL_WINDOW:  {"TCP.Small.Window"},
	C.THRT_ID_TCP_SMALL_MSS:     {"TCP.SACK.DDoS.With.Small.MSS"},
	C.THRT_ID_PING_DEATH:        {"Ping.Death"},
	C.THRT_ID_DNS_LOOP_PTR:      {"DNS.Loop.Pointer"},
	C.THRT_ID_SSH_VER_1:         {"SSH.Version.1"},
	C.THRT_ID_SSL_HEARTBLEED:    {"SSL.Heartbleed"},
	C.THRT_ID_SSL_CIPHER_OVF:    {"SSL.Cipher.Overflow"},
	C.THRT_ID_SSL_VER_2OR3:      {"SSL.Version.2or3"},
	C.THRT_ID_SSL_TLS_1DOT0:     {"SSL.TLS1.0"},
	C.THRT_ID_HTTP_NEG_LEN:      {"HTTP.Negative.Body.Length"},
	C.THRT_ID_HTTP_SMUGGLING:    {"HTTP.Request.Smuggling"},
	C.THRT_ID_HTTP_SLOWLORIS:    {"HTTP.Request.Slowloris"},
	C.THRT_ID_DNS_OVERFLOW:      {"DNS.Stack.Overflow"},
	C.THRT_ID_MYSQL_ACCESS_DENY: {"MySQL.Access.Deny"},
	C.THRT_ID_DNS_ZONE_TRANSFER: {"DNS.Zone.Transfer"},
	C.THRT_ID_ICMP_TUNNELING:    {"ICMP.Tunneling"},
	C.THRT_ID_DNS_TYPE_NULL:     {"DNS.Type.Null"},
	C.THRT_ID_SQL_INJECTION:     {"SQL.Injection"},
	C.THRT_ID_APACHE_STRUTS_RCE: {"Apache.Struts.Remote.Code.Execution"},
	C.THRT_ID_DNS_TUNNELING:     {"DNS.Tunneling"},
	C.THRT_ID_K8S_EXTIP_MITM:    {"K8S.externalIPs.MitM"},
}

func ThreatName(id uint32) string {
	if id == 0 {
		return ""
	}
	if info, ok := LogThreatMap[id]; !ok {
		return fmt.Sprintf("#%v", id)
	} else {
		return info.Name
	}
}

type LogEventInfo struct {
	Name     string
	Category string
	Level    string
}

var LogEventMap = map[share.TLogEvent]LogEventInfo{
	share.CLUSEvWorkloadStart:               {api.EventNameContainerStart, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvWorkloadStop:                {api.EventNameContainerStop, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvWorkloadSecured:             {api.EventNameContainerSecured, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvWorkloadRemove:              {api.EventNameContainerRemove, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvAgentStart:                  {api.EventNameAgentStart, api.EventCatAgent, api.LogLevelINFO},
	share.CLUSEvAgentStop:                   {api.EventNameAgentStop, api.EventCatAgent, api.LogLevelINFO},
	share.CLUSEvAgentJoin:                   {api.EventNameAgentJoin, api.EventCatAgent, api.LogLevelINFO},
	share.CLUSEvAgentDisconnect:             {api.EventNameAgentDisconnect, api.EventCatAgent, api.LogLevelNOTICE},
	share.CLUSEvAgentConnect:                {api.EventNameAgentConnect, api.EventCatAgent, api.LogLevelNOTICE},
	share.CLUSEvAgentKicked:                 {api.EventNameAgentKicked, api.EventCatAgent, api.LogLevelWARNING},
	share.CLUSEvControllerStart:             {api.EventNameControllerStart, api.EventCatController, api.LogLevelINFO},
	share.CLUSEvControllerStop:              {api.EventNameControllerStop, api.EventCatController, api.LogLevelINFO},
	share.CLUSEvControllerJoin:              {api.EventNameControllerJoin, api.EventCatController, api.LogLevelINFO},
	share.CLUSEvControllerDisconnect:        {api.EventNameControllerDisconnect, api.EventCatController, api.LogLevelNOTICE},
	share.CLUSEvControllerConnect:           {api.EventNameControllerConnect, api.EventCatController, api.LogLevelNOTICE},
	share.CLUSEvControllerLeadLost:          {api.EventNameControllerLeadLost, api.EventCatController, api.LogLevelWARNING},
	share.CLUSEvControllerLeadElect:         {api.EventNameControllerLeadElect, api.EventCatController, api.LogLevelNOTICE},
	share.CLUSEvAuthLogin:                   {api.EventNameAuthLogin, api.EventCatAuth, api.LogLevelINFO},
	share.CLUSEvAuthLogout:                  {api.EventNameAuthLogout, api.EventCatAuth, api.LogLevelINFO},
	share.CLUSEvAuthTimeout:                 {api.EventNameAuthTimeout, api.EventCatAuth, api.LogLevelNOTICE},
	share.CLUSEvAuthLoginFailed:             {api.EventNameAuthLoginFailed, api.EventCatAuth, api.LogLevelWARNING},
	share.CLUSEvAuthLoginBlocked:            {api.EventNameAuthLoginBlocked, api.EventCatAuth, api.LogLevelNOTICE},
	share.CLUSEvAuthLoginUnblocked:          {api.EventNameAuthLoginUnblocked, api.EventCatAuth, api.LogLevelINFO},
	share.CLUSEvAuthUserPwdResetByAdmin:     {api.EventNameAuthUserPwdRestByAdmin, api.EventCatAuth, api.LogLevelINFO},
	share.CLUSEvAuthAccessDenied:            {api.EventNameAuthAccessDenied, api.EventCatAuth, api.LogLevelWARNING},
	share.CLUSEvRESTWrite:                   {api.EventNameRESTWrite, api.EventCatREST, api.LogLevelINFO},
	share.CLUSEvRESTRead:                    {api.EventNameRESTRead, api.EventCatREST, api.LogLevelINFO},
	share.CLUSEvScannerJoin:                 {api.EventNameScannerJoin, api.EventCatScan, api.LogLevelINFO},
	share.CLUSEvScannerUpdate:               {api.EventNameScannerUpdate, api.EventCatScan, api.LogLevelINFO},
	share.CLUSEvScannerLeave:                {api.EventNameScannerLeave, api.EventCatScan, api.LogLevelINFO},
	share.CLUSEvScanFail:                    {api.EventNameScanFail, api.EventCatScan, api.LogLevelNOTICE},
	share.CLUSEvScanSucceed:                 {api.EventNameScanSucceed, api.EventCatScan, api.LogLevelINFO},
	share.CLUSEvBenchDockerFail:             {api.EventNameBenchDockerFail, api.EventCatBench, api.LogLevelNOTICE},
	share.CLUSEvBenchKubeFail:               {api.EventNameBenchKubeFail, api.EventCatBench, api.LogLevelNOTICE},
	share.CLUSEvLicenseUpdate:               {api.EventNameLicenseUpdate, api.EventCatLicense, api.LogLevelINFO},
	share.CLUSEvLicenseExpire:               {api.EventNameLicenseExpire, api.EventCatLicense, api.LogLevelWARNING},
	share.CLUSEvLicenseRemove:               {api.EventNameLicenseRemove, api.EventCatLicense, api.LogLevelWARNING},
	share.CLUSEvLicenseEnforcerLimitReached: {api.EventNameLicenseEnforcerLimitReached, api.EventCatLicense, api.LogLevelWARNING},
	share.CLUSEvWorkloadQuarantined:         {api.EventNameContainerQuarantined, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvWorkloadUnquarantined:       {api.EventNameContainerUnquarantined, api.EventCatWorkload, api.LogLevelINFO},
	share.CLUSEvAdmCtrlK8sConfigured:        {api.EventNameAdmCtrlK8sConfigured, api.EventCatAdmCtrl, api.LogLevelNOTICE}, // for admission control
	share.CLUSEvAdmCtrlK8sConfigFailed:      {api.EventNameAdmCtrlK8sConfigFailed, api.EventCatAdmCtrl, api.LogLevelCRIT}, // for admission control
	share.CLUSEvInitCfgMapDone:              {api.EventNameInitCfgMapDone, api.EventCatConfigMap, api.LogLevelINFO},
	share.CLUSEvInitCfgMapError:             {api.EventNameInitCfgMapError, api.EventCatConfigMap, api.LogLevelERR},
	share.CLUSEvCrdImported:                 {api.EventNameCrdImported, api.EventCatCrd, api.LogLevelINFO},
	share.CLUSEvCrdRemoved:                  {api.EventNameCrdRemoved, api.EventCatCrd, api.LogLevelINFO},
	share.CLUSEvCrdErrDetected:              {api.EventNameCrdErrDetected, api.EventCatCrd, api.LogLevelERR},
	share.CLUSEvFedPromote:                  {api.EventNameFedPromote, api.EventCatFed, api.LogLevelINFO},    // for multi-clusters
	share.CLUSEvFedDemote:                   {api.EventNameFedDemote, api.EventCatFed, api.LogLevelINFO},     // for multi-clusters
	share.CLUSEvFedJoin:                     {api.EventNameFedJoin, api.EventCatFed, api.LogLevelINFO},       // for multi-clusters
	share.CLUSEvFedLeave:                    {api.EventNameFedLeave, api.EventCatFed, api.LogLevelNOTICE},    // for multi-clusters
	share.CLUSEvFedKick:                     {api.EventNameFedKick, api.EventCatFed, api.LogLevelINFO},       // for multi-clusters
	share.CLUSEvFedPolicySync:               {api.EventNameFedPolicySync, api.EventCatFed, api.LogLevelINFO}, // for multi-clusters
	share.CLUSEvImport:                      {api.EventNameImport, api.EventCatConfig, api.LogLevelNOTICE},
	share.CLUSEvExport:                      {api.EventNameExport, api.EventCatConfig, api.LogLevelNOTICE},
	share.CLUSEvImportFail:                  {api.EventNameImportFail, api.EventCatConfig, api.LogLevelERR},
	share.CLUSEvExportFail:                  {api.EventNameExportFail, api.EventCatConfig, api.LogLevelERR},
	share.CLUSEvCloudScanRet:                {api.EventNameCloudScanNormal, api.EventCatCloud, api.LogLevelINFO},
	share.CLUSEvCloudScanAlert:              {api.EventNameCloudScanAlert, api.EventCatCloud, api.LogLevelWARNING},
	share.CLUSEvCloudScanFail:               {api.EventNameCloudScanFail, api.EventCatCloud, api.LogLevelERR},
	share.CLUSEvGroupAutoRemove:             {api.EventNameGroupAutoRemove, api.EventCatGroup, api.LogLevelINFO},
	share.CLUSEvMemoryPressureAgent:         {api.EventNameMemoryPressureAgent, api.EventCatAgent, api.LogLevelWARNING},
	share.CLUSEvMemoryPressureController:    {api.EventNameMemoryPressureController, api.EventCatController, api.LogLevelWARNING},
	share.CLUSEvK8sNvRBAC:                   {api.EventNameK8sNvRBAC, api.EventCatConfig, api.LogLevelWARNING},
}

type LogIncidentInfo struct {
	Name  string
	Level string
}

var LogIncidentMap = map[share.TLogIncident]LogIncidentInfo{
	share.CLUSIncidHostPrivilEscalate:           {api.EventNameHostPrivilEscalate, api.LogLevelCRIT},
	share.CLUSIncidContainerPrivilEscalate:      {api.EventNameContainerPrivilEscalate, api.LogLevelCRIT},
	share.CLUSIncidHostSuspiciousProcess:        {api.EventNameHostSuspiciousProcess, api.LogLevelWARNING},
	share.CLUSIncidContainerSuspiciousProcess:   {api.EventNameContainerSuspiciousProcess, api.LogLevelWARNING},
	share.CLUSIncidHostFileAccessViolation:      {api.EventNameHostFileAccessViolation, api.LogLevelWARNING},
	share.CLUSIncidContainerFileAccessViolation: {api.EventNameContainerFileAccessViolation, api.LogLevelWARNING},
	share.CLUSIncidHostPackageUpdated:           {api.EventNameHostPackageUpdated, api.LogLevelWARNING},
	share.CLUSIncidContainerPackageUpdated:      {api.EventNameContainerPackageUpdated, api.LogLevelWARNING},
	share.CLUSIncidHostTunnel:                   {api.EventNameHostTunnelDetected, api.LogLevelWARNING},
	share.CLUSIncidContainerTunnel:              {api.EventNameContainerTunnelDetected, api.LogLevelWARNING},
	share.CLUSIncidContainerProcessViolation:    {api.EventNameProcessProfileViolation, api.LogLevelWARNING},
	share.CLUSIncidHostProcessViolation:         {api.EventNameHostProcessProfileViolation, api.LogLevelWARNING},
}

type LogAuditInfo struct {
	Name  string
	Level string
}

var LogAuditMap = map[share.TLogAudit]LogAuditInfo{
	share.CLUSAuditComplianceContainerBenchViolation:       {api.EventNameComplianceContainerBenchViolation, api.LogLevelWARNING},
	share.CLUSAuditComplianceContainerFileBenchViolation:   {api.EventNameComplianceContainerFileBenchViolation, api.LogLevelWARNING},
	share.CLUSAuditComplianceHostBenchViolation:            {api.EventNameComplianceHostBenchViolation, api.LogLevelWARNING},
	share.CLUSAuditAdmCtrlK8sReqAllowed:                    {api.EventNameAdmCtrlK8sReqAllowed, api.LogLevelINFO},      // for admission control
	share.CLUSAuditAdmCtrlK8sReqViolation:                  {api.EventNameAdmCtrlK8sReqViolation, api.LogLevelWARNING}, // for admission control
	share.CLUSAuditAdmCtrlK8sReqDenied:                     {api.EventNameAdmCtrlK8sReqDenied, api.LogLevelCRIT},       // for admission control
	share.CLUSAuditComplianceContainerCustomCheckViolation: {api.EventNameComplianceContainerCustomCheckViolation, api.LogLevelWARNING},
	share.CLUSAuditComplianceHostCustomCheckViolation:      {api.EventNameComplianceHostCustomCheckViolation, api.LogLevelWARNING},
	share.CLUSAuditAwsLambdaScanWarning:                    {api.EventNameAwsLambdaScan, api.LogLevelWARNING},
	share.CLUSAuditAwsLambdaScanNormal:                     {api.EventNameAwsLambdaScan, api.LogLevelINFO},
	share.CLUSAuditComplianceImageBenchViolation:           {api.EventNameComplianceImageBenchViolation, api.LogLevelWARNING},
}

func LevelToPrio(level string) (syslog.Priority, bool) {
	switch level {
	case api.LogLevelEMERG:
		return syslog.LOG_EMERG, true
	case api.LogLevelALERT:
		return syslog.LOG_ALERT, true
	case api.LogLevelCRIT:
		return syslog.LOG_CRIT, true
	case api.LogLevelERR:
		return syslog.LOG_ERR, true
	case api.LogLevelWARNING:
		return syslog.LOG_WARNING, true
	case api.LogLevelNOTICE:
		return syslog.LOG_NOTICE, true
	case api.LogLevelINFO:
		return syslog.LOG_INFO, true
	case api.LogLevelDEBUG:
		return syslog.LOG_DEBUG, true
	}
	return syslog.LOG_INFO, false
}

func LevelToString(level string) string {
	switch level {
	case api.LogLevelEMERG:
		return "emergence"
	case api.LogLevelALERT:
		return "alert"
	case api.LogLevelCRIT:
		return "critical"
	case api.LogLevelERR:
		return "error"
	case api.LogLevelWARNING:
		return "warning"
	case api.LogLevelNOTICE:
		return "notice"
	case api.LogLevelINFO:
		return "informational"
	case api.LogLevelDEBUG:
		return "debug"
	}
	return ""
}

func PriorityToString(prio syslog.Priority) string {
	switch prio {
	case syslog.LOG_EMERG:
		return "emergence"
	case syslog.LOG_ALERT:
		return "alert"
	case syslog.LOG_CRIT:
		return "critical"
	case syslog.LOG_ERR:
		return "error"
	case syslog.LOG_WARNING:
		return "warning"
	case syslog.LOG_NOTICE:
		return "notice"
	case syslog.LOG_INFO:
		return "informational"
	case syslog.LOG_DEBUG:
		return "debug"
	}
	return ""
}

var AppNameMap map[uint32]string = map[uint32]string{
	C.DPI_APP_HTTP:          "HTTP",
	C.DPI_APP_SSL:           "SSL",
	C.DPI_APP_SSH:           "SSH",
	C.DPI_APP_DNS:           "DNS",
	C.DPI_APP_DHCP:          "DHCP",
	C.DPI_APP_NTP:           "NTP",
	C.DPI_APP_TFTP:          "TFTP",
	C.DPI_APP_ECHO:          "Echo",
	C.DPI_APP_RTSP:          "RTSP",
	C.DPI_APP_SIP:           "SIP",
	C.DPI_APP_MYSQL:         "MySQL",
	C.DPI_APP_REDIS:         "Redis",
	C.DPI_APP_ZOOKEEPER:     "ZooKeeper",
	C.DPI_APP_CASSANDRA:     "Cassandra",
	C.DPI_APP_MONGODB:       "MongoDB",
	C.DPI_APP_POSTGRESQL:    "PostgreSQL",
	C.DPI_APP_KAFKA:         "Kafka",
	C.DPI_APP_COUCHBASE:     "Couchbase",
	C.DPI_APP_WORDPRESS:     "Wordpress",
	C.DPI_APP_ACTIVEMQ:      "ActiveMQ",
	C.DPI_APP_COUCHDB:       "CouchDB",
	C.DPI_APP_ELASTICSEARCH: "ElasticSearch",
	C.DPI_APP_MEMCACHED:     "Memcached",
	C.DPI_APP_RABBITMQ:      "RabbitMQ",
	C.DPI_APP_RADIUS:        "Radius",
	C.DPI_APP_VOLTDB:        "VoltDB",
	C.DPI_APP_CONSUL:        "Consul",
	C.DPI_APP_SYSLOG:        "Syslog",
	C.DPI_APP_ETCD:          "etcd",
	C.DPI_APP_SPARK:         "Spark",
	C.DPI_APP_APACHE:        "Apache",
	C.DPI_APP_NGINX:         "nginx",
	C.DPI_APP_JETTY:         "Jetty",
	C.DPI_APP_TNS:           "Oracle",
	C.DPI_APP_TDS:           "MSSQL",
	C.DPI_APP_GRPC:          "GRPC",
}

var appName2IDMap map[string]uint32
var appMutex sync.RWMutex

func GetAppIDByName(name string) uint32 {
	appMutex.Lock()
	if appName2IDMap == nil {
		appName2IDMap = make(map[string]uint32)
		for id, app := range AppNameMap {
			appName2IDMap[strings.ToUpper(app)] = id
		}
	}
	appMutex.Unlock()

	if id, ok := appName2IDMap[strings.ToUpper(name)]; ok {
		return id
	}

	return 0
}

func TCPStateString(state uint8) string {
	switch state {
	case C.SESS_STATE_ESTABLISHED:
		return "established"
	case C.SESS_STATE_SYN_SENT:
		return "syn_sent"
	case C.SESS_STATE_SYN_RECV:
		return "syn_recv"
	case C.SESS_STATE_FIN_WAIT1:
		return "fin_wait1"
	case C.SESS_STATE_FIN_WAIT2:
		return "fin_wait2"
	case C.SESS_STATE_TIME_WAIT:
		return "time_wait"
	case C.SESS_STATE_CLOSE:
		return "close"
	case C.SESS_STATE_CLOSE_WAIT:
		return "close_wait"
	case C.SESS_STATE_LAST_ACK:
		return "last_ack"
	case C.SESS_STATE_LISTEN:
		return "listen"
	case C.SESS_STATE_CLOSING:
		return "closing"
	default:
		return "unknown"
	}
}

// ---

func compareProcField(s1, s2 string) int {
	ret := strings.Compare(s1, s2)
	if ret != 0 {
		if s1 == "" {
			return 1
		} else if s2 == "" {
			return -1
		}
	}
	return ret
}

func compareProc(p1, p2 *share.CLUSProcessProfileEntry) int {
	ret := compareProcField(p1.Name, p2.Name)
	if ret == 0 {
		ret = compareProcField(p1.Path, p2.Path)
		if ret == 0 { // comparing cfgFlag: learned has the lowest priority
			if p1.CfgType == share.GroundCfg || p2.CfgType == share.GroundCfg {
				if p1.CfgType == p2.CfgType {
					return 0
				} else if p1.CfgType > p2.CfgType {
					return 1
				}
				return -1
			}
		}
	}
	return ret
}

func FindProcessInProfile(list []*share.CLUSProcessProfileEntry, p *share.CLUSProcessProfileEntry) (int, bool) {
	var low int = 0
	var high int = len(list)

	for low < high {
		mid := (low + high) / 2
		c := compareProc(p, list[mid])
		if c == 0 {
			return mid, true
		} else if c > 0 {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low, false
}

func MergeProcess(list []*share.CLUSProcessProfileEntry, p *share.CLUSProcessProfileEntry, bForcedUpdate bool) ([]*share.CLUSProcessProfileEntry, bool) {
	insert, found := FindProcessInProfile(list, p)
	if found {
		pp := list[insert]
		changed := false

		if pp.Action != p.Action {
			pp.Action = p.Action
			changed = true
		}
		if len(p.Hash) > 0 && string(pp.Hash) != string(p.Hash) {
			pp.Hash = p.Hash
			changed = true
		}

		// from CRD or REST api
		if bForcedUpdate {
			if pp.AllowFileUpdate != p.AllowFileUpdate {
				pp.AllowFileUpdate = p.AllowFileUpdate
				changed = true
			}
		}

		//  New data, exclude from comparing different UID(s) to avoid duplicate entries
		//	if p.Uid > 0 && p.Uid != pp.Uid {
		//		pp.Uid = p.Uid
		//		changed = true
		//	}

		if changed {
			// update entry
			pp.UpdatedAt = time.Now().UTC()
			pp.Uuid = p.Uuid
		}
		return list, changed
	}

	var ret []*share.CLUSProcessProfileEntry
	if insert > 0 {
		ret = append(ret, list[0:insert]...)
	}

	// new entry or old entry from deleted entry in a transaction
	p.UpdatedAt = time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}
	ret = append(ret, p)
	ret = append(ret, list[insert:]...)
	return ret, true
}

var DefaultFileMonitorConfig share.CLUSFileMonitorProfile = share.CLUSFileMonitorProfile{
	Filters:    fsmon.ImportantFiles,
	FiltersCRD: make([]share.CLUSFileMonitorFilter, 0),
}

func FsmonFilterToRest(path, regex string) string {
	regex = strings.Replace(regex, ".*", "*", -1)
	regex = strings.Replace(regex, "\\.", ".", -1)
	regex = strings.TrimRight(regex, "$")
	path = strings.Replace(path, "\\.", ".", -1)
	path = strings.Replace(path, ".*", "*", -1)
	var flt string
	if regex != "" {
		flt = fmt.Sprintf("%s/%s", path, regex)
	} else {
		flt = path
	}
	return flt
}

func compareDlpSensor(p1, p2 *share.CLUSDlpSetting) int {
	return strings.Compare(p1.Name, p2.Name)
}

func FindSensorInDlpGroup(list []*share.CLUSDlpSetting, p *share.CLUSDlpSetting) (int, bool) {
	var low int = 0
	var high int = len(list)

	for low < high {
		mid := (low + high) / 2
		c := compareDlpSensor(p, list[mid])
		if c == 0 {
			return mid, true
		} else if c > 0 {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low, false
}

func MergeDlpSensors(list []*share.CLUSDlpSetting, p *share.CLUSDlpSetting) ([]*share.CLUSDlpSetting, bool) {
	insert, found := FindSensorInDlpGroup(list, p)
	if found {
		pp := list[insert]
		changed := false

		if pp.Action != p.Action {
			pp.Action = p.Action
			changed = true
		}
		return list, changed
	}

	var ret []*share.CLUSDlpSetting
	if insert > 0 {
		ret = append(ret, list[0:insert]...)
	}

	// new entry
	ret = append(ret, p)
	ret = append(ret, list[insert:]...)
	return ret, true
}

// First try to find the next largest policy ID of unlearned policies. If it cannot be located,
// try to find the smallest one. Return 0 if all IDs are used.
func GetAvailablePolicyID(ids utils.Set, cfgType share.TCfgType) uint32 {
	var id, max uint32
	var idMax, idMin uint32
	if cfgType == share.GroundCfg {
		idMax = api.PolicyGroundRuleIDMax
		idMin = api.PolicyGroundRuleIDBase + 1
	} else if cfgType == share.FederalCfg {
		idMax = api.PolicyFedRuleIDMax
		idMin = api.PolicyFedRuleIDBase + 1
	} else if cfgType == share.Learned {
		idMin = api.PolicyLearnedIDBase + 1
		idMax = api.PolicyFedRuleIDBase
	} else {
		idMax = api.PolicyLearnedIDBase
		idMin = 1
	}
	max = idMin - 1
	// Find the largest
	for mid := range ids.Iter() {
		id = mid.(uint32)
		if id < idMax && id > max {
			max = id
		}
	}
	if max < idMax-1 {
		return max + 1
	}

	// Find the smallest
	for id = idMin; id < idMax; id++ {
		if !ids.Contains(id) {
			return id
		}
	}

	return 0
}

func PolicyRuleIdToCfgType(id uint32) share.TCfgType {
	if id >= api.PolicyGroundRuleIDBase {
		return share.GroundCfg
	} else if id >= api.PolicyFedRuleIDBase {
		return share.FederalCfg
	} else if id < api.PolicyLearnedIDBase {
		return share.UserCreated
	} else {
		return share.Learned
	}
}

const DLPRuleTag string = "_nvCtR."

func GetInternalDlpRuleName(rulename, sensorname string) string {
	newname := fmt.Sprintf("%s%s%s", sensorname, DLPRuleTag, rulename)
	return newname
}

func GetOrigDlpRuleName(rulename string) string {
	origname := rulename
	if index := strings.LastIndex(origname, DLPRuleTag); index != -1 {
		index += len(DLPRuleTag)
		origname = origname[index:]
		return origname
	}
	return origname
}

const WAFRuleTag string = "_nVwAfCtR."

func GetInternalWafRuleName(rulename, sensorname string) string {
	newname := fmt.Sprintf("%s%s%s", sensorname, WAFRuleTag, rulename)
	return newname
}

func GetOrigWafRuleName(rulename string) string {
	origname := rulename
	if index := strings.LastIndex(origname, WAFRuleTag); index != -1 {
		index += len(WAFRuleTag)
		origname = origname[index:]
		return origname
	}
	return origname
}

func compareWafSensor(p1, p2 *share.CLUSWafSetting) int {
	return strings.Compare(p1.Name, p2.Name)
}

func FindSensorInWafGroup(list []*share.CLUSWafSetting, p *share.CLUSWafSetting) (int, bool) {
	var low int = 0
	var high int = len(list)

	for low < high {
		mid := (low + high) / 2
		c := compareWafSensor(p, list[mid])
		if c == 0 {
			return mid, true
		} else if c > 0 {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low, false
}

func MergeWafSensors(list []*share.CLUSWafSetting, p *share.CLUSWafSetting) ([]*share.CLUSWafSetting, bool) {
	insert, found := FindSensorInWafGroup(list, p)
	if found {
		pp := list[insert]
		changed := false

		if pp.Action != p.Action {
			pp.Action = p.Action
			changed = true
		}
		return list, changed
	}

	var ret []*share.CLUSWafSetting
	if insert > 0 {
		ret = append(ret, list[0:insert]...)
	}

	// new entry
	ret = append(ret, p)
	ret = append(ret, list[insert:]...)
	return ret, true
}
