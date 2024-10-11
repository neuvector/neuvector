package api

import (
	"time"

	"github.com/neuvector/neuvector/share"
)

const (
	CategoryEvent     = "event"
	CategoryViolation = "violation" // merged into CategoryRuntime in config, stil used in log category
	CategoryThreat    = "threat"    // merged into CategoryRuntime in config, stil used in log category
	CategoryIncident  = "incident"  // merged into CategoryRuntime in config, stil used in log category
	CategoryRuntime   = "security-event"
	CategoryAudit     = "audit"
)

// syslog related
const SyslogDefaultUDPPort uint16 = 514

// For upgrade to v2.0.0
var logLevelUpgradeMap map[string]string = map[string]string{
	"EMERG":   LogLevelEMERG,
	"ALERT":   LogLevelALERT,
	"CRIT":    LogLevelCRIT,
	"ERR":     LogLevelERR,
	"WARNING": LogLevelWARNING,
	"NOTICE":  LogLevelNOTICE,
	"INFO":    LogLevelINFO,
	"DEBUG":   LogLevelDEBUG,
}

func UpgradeLogLevel(level string) string {
	if lvl, ok := logLevelUpgradeMap[level]; ok {
		return lvl
	}
	return level
}

const (
	LogLevelEMERG   = "Emergency"
	LogLevelALERT   = "Alert"
	LogLevelCRIT    = "Critical"
	LogLevelERR     = "Error"
	LogLevelWARNING = "Warning"
	LogLevelNOTICE  = "Notice"
	LogLevelINFO    = "Info"
	LogLevelDEBUG   = "Debug"
)

var LogLevelList []string = []string{
	LogLevelEMERG,
	LogLevelALERT,
	LogLevelCRIT,
	LogLevelERR,
	LogLevelWARNING,
	LogLevelNOTICE,
	LogLevelINFO,
	LogLevelDEBUG,
}

const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

var ThreatLevelList []string = []string{
	LogLevelCRIT,
	LogLevelERR,
	LogLevelWARNING,
	LogLevelNOTICE,
	LogLevelINFO,
}

type LogCommon struct {
	Name              string `json:"name,omitempty"`
	Level             string `json:"level"`
	ReportedTimeStamp int64  `json:"reported_timestamp"`
	ReportedAt        string `json:"reported_at"`
	ClusterName       string `json:"cluster_name"`
	ResponseRuleID    int    `json:"response_rule_id,omitempty"`
	HostID            string `json:"host_id"`
	HostName          string `json:"host_name"`
	AgentID           string `json:"enforcer_id"`
	AgentName         string `json:"enforcer_name"`
}

const (
	EventNameContainerStart              = "Container.Start"
	EventNameContainerStop               = "Container.Stop"
	EventNameContainerRemove             = "Container.Remove"
	EventNameContainerSecured            = "Container.Secured"
	EventNameContainerUnsecured          = "Container.Unsecured"
	EventNameAgentStart                  = "Enforcer.Start"
	EventNameAgentJoin                   = "Enforcer.Join"
	EventNameAgentStop                   = "Enforcer.Stop"
	EventNameAgentDisconnect             = "Enforcer.Disconnect"
	EventNameAgentConnect                = "Enforcer.Connect"
	EventNameAgentKicked                 = "Enforcer.Kicked"
	EventNameControllerStart             = "Controller.Start"
	EventNameControllerJoin              = "Controller.Join"
	EventNameControllerLeave             = "Controller.Leave"
	EventNameControllerStop              = "Controller.Stop"
	EventNameControllerDisconnect        = "Controller.Disconnect"
	EventNameControllerConnect           = "Controller.Connect"
	EventNameControllerLeadLost          = "Controller.Lead.Lost"
	EventNameControllerLeadElect         = "Controller.Lead.Elected"
	EventNameAuthLogin                   = "User.Login"
	EventNameAuthLogout                  = "User.Logout"
	EventNameAuthTimeout                 = "User.Timeout"
	EventNameAuthLoginFailed             = "User.Login.Failed"
	EventNameAuthLoginBlocked            = "User.Login.Blocked"
	EventNameAuthLoginUnblocked          = "User.Login.Unblocked"
	EventNameAuthUserPwdRestByAdmin      = "User.Password.Reset"
	EventNameAuthAccessDenied            = "User.Resource.Access.Denied"
	EventNameRESTWrite                   = "RESTful.Write"
	EventNameRESTRead                    = "RESTful.Read"
	EventNameScannerJoin                 = "Scanner.Join"
	EventNameScannerUpdate               = "Scanner.Update"
	EventNameScannerLeave                = "Scanner.Leave"
	EventNameScanFail                    = "Scan.Failed"
	EventNameScanSucceed                 = "Scan.Succeeded"
	EventNameBenchDockerFail             = "Docker.CIS.Benchmark.Failed"
	EventNameBenchKubeFail               = "Kubenetes.CIS.Benchmark.Failed"
	EventNameLicenseUpdate               = "License.Update"
	EventNameLicenseExpire               = "License.Expire"
	EventNameLicenseRemove               = "License.Remove"
	EventNameLicenseEnforcerLimitReached = "License.EnforcerLimitReached"
	EventNameAdmCtrlK8sConfigured        = "Admission.Control.Configured"   // for admission control
	EventNameAdmCtrlK8sConfigFailed      = "Admission.Control.ConfigFailed" // for admission control
	EventNameInitCfgMapDone              = "ConfigMap.Load"                 // for initial Config
	EventNameInitCfgMapError             = "ConfigMap.Failed"               // for initial Config failure
	EventNameCrdImported                 = "Crd.Import"                     // for crd Config import
	EventNameCrdRemoved                  = "Crd.Remove"                     // for crd Config remove due to k8s miss
	EventNameCrdErrDetected              = "Crd.Error"                      // for remove error crd
	EventNameCrdSkipped                  = "Crd.Skipped"                    // for crd skip ('kubectl create -f' on existing crd resource)
	EventNameFedPromote                  = "Federation.Promote"             // for multi-clusters
	EventNameFedDemote                   = "Federation.Demote"              // for multi-clusters
	EventNameFedJoin                     = "Federation.Join"                // for joint cluster in multi-clusters
	EventNameFedLeave                    = "Federation.Leave"               // for multi-clusters
	EventNameFedKick                     = "Federation.Kick"                // for multi-clusters
	EventNameFedPolicySync               = "Federation.Policy.Sync"         // for multi-clusters
	EventNameImport                      = "Configuration.Import"
	EventNameExport                      = "Configuration.Export"
	EventNameImportFail                  = "Configuration.Import.Failed"
	EventNameExportFail                  = "Configuration.Export.Failed"
	EventNameCloudScanNormal             = "Cloud.Scan.Normal" // for cloud scan nomal ret
	EventNameCloudScanAlert              = "Cloud.Scan.Alert"  // for cloud scan ret with alert
	EventNameCloudScanFail               = "Cloud.Scan.Fail"   // for cloud scan fail
	EventNameGroupAutoRemove             = "Group.Auto.Remove"
	EventNameMemoryPressureAgent         = "Agent.Memory.Pressure"
	EventNameMemoryPressureController    = "Controller.Memory.Pressure"
	EventNameK8sNvRBAC                   = "Kubenetes.NeuVector.RBAC"
	EventNameGroupAutoPromote            = "Group.Auto.Promote"
	EventNameAuthDefAdminPwdUnchanged    = "User.Password.Alert"
	EventNameScannerAutoScaleDisabled    = "Configuration.ScannerAutoScale.Disabled"
	EventNameK8sAdmissionWebhookChange   = "Kubenetes.Admission.Webhook.Change" // for admission control
	EventNameGroupMetricViolation        = "Group.Metric.Violation"
	EventNameKvRestored                  = "Configuration.Restore"
	EventNameScanDataRestored            = "Scan.Data.Restore"
)

// TODO: these are not events but incidents
const (
	EventNameHostPrivilEscalate           = "Host.Privilege.Escalation"
	EventNameContainerPrivilEscalate      = "Container.Privilege.Escalation"
	EventNameHostSuspiciousProcess        = "Host.Suspicious.Process"
	EventNameContainerSuspiciousProcess   = "Container.Suspicious.Process"
	EventNameContainerQuarantined         = "Container.Quarantined"
	EventNameContainerUnquarantined       = "Container.Unquarantined"
	EventNameHostFileAccessViolation      = "Host.FileAccess.Violation"
	EventNameContainerFileAccessViolation = "Container.FileAccess.Violation"
	EventNameHostPackageUpdated           = "Host.Package.Updated"
	EventNameContainerPackageUpdated      = "Container.Package.Updated"
	EventNameHostTunnelDetected           = "Host.Tunnel.Detected"
	EventNameContainerTunnelDetected      = "Container.Tunnel.Detected"
	EventNameProcessProfileViolation      = "Process.Profile.Violation" // container
	EventNameHostProcessProfileViolation  = "Host.Process.Violation"    // host
)

// TODO: these are audit related
const (
	EventNameComplianceContainerBenchViolation       = "Compliance.Container.Violation"
	EventNameComplianceContainerFileBenchViolation   = "Compliance.ContainerFile.Violation"
	EventNameComplianceHostBenchViolation            = "Compliance.Host.Violation"
	EventNameComplianceImageBenchViolation           = "Compliance.Image.Violation"
	EventNameContainerScanReport                     = "Container.Scan.Report"
	EventNameHostScanReport                          = "Host.Scan.Report"
	EventNameRegistryScanReport                      = "Registry.Scan.Report"
	EventNamePlatformScanReport                      = "Platform.Scan.Report"
	EventNameAdmCtrlK8sReqAllowed                    = "Admission.Control.Allowed"   // for admission control
	EventNameAdmCtrlK8sReqViolation                  = "Admission.Control.Violation" // for admission control
	EventNameAdmCtrlK8sReqDenied                     = "Admission.Control.Denied"    // for admission control
	EventNameComplianceContainerCustomCheckViolation = "Compliance.ContainerCustomCheck.Violation"
	EventNameComplianceHostCustomCheckViolation      = "Compliance.HostCustomCheck.Violation"
	EventNameAwsLambdaScan                           = "AwsLambda.Scan"
)

// var incidentNameList []string = []string{
// 	EventNameHostPrivilEscalate,
// 	EventNameContainerPrivilEscalate,
// 	EventNameHostSuspiciousProcess,
// 	EventNameContainerSuspiciousProcess,
// 	EventNameHostFileAccessViolation,
// 	EventNameContainerFileAccessViolation,
// 	EventNameHostPackageUpdated,
// 	EventNameContainerPackageUpdated,
// 	EventNameHostTunnelDetected,
// 	EventNameProcessProfileViolation,
// 	EventNameHostProcessProfileViolation,
// }

const (
	EventCatREST       = "RESTFUL"
	EventCatAuth       = "AUTH"
	EventCatWorkload   = "WORKLOAD"
	EventCatAgent      = "ENFORCER"
	EventCatController = "CONTROLLER"
	EventCatScan       = "SCANNER"
	EventCatBench      = "CIS.BENCHMARK"
	EventCatLicense    = "LICENSE"
	EventCatConfigMap  = "CONFIGMAP"
	EventCatCrd        = "CRD"
	EventCatAdmCtrl    = "ADMISSION.CONTROL"
	EventCatFed        = "FEDERATION"
	EventCatConfig     = "CONFIGURATION"
	EventCatCloud      = "CLOUD"
	EventCatGroup      = "GROUP"
)

type Event struct {
	LogCommon
	ControllerID    string            `json:"controller_id"`
	ControllerName  string            `json:"controller_name"`
	WorkloadID      string            `json:"workload_id"`
	WorkloadName    string            `json:"workload_name"`
	WorkloadDomain  string            `json:"workload_domain"`
	WorkloadImage   string            `json:"workload_image"`
	WorkloadService string            `json:"workload_service"`
	Category        string            `json:"category"`
	User            string            `json:"user"`
	UserRoles       map[string]string `json:"user_roles"` // domain -> role
	UserAddr        string            `json:"user_addr"`
	UserSession     string            `json:"user_session"`
	RESTMethod      string            `json:"rest_method,omitempty"`
	RESTRequest     string            `json:"rest_request,omitempty"`
	RESTBody        string            `json:"rest_body,omitempty"`
	EnforcerLimit   int               `json:"enforcer_limit,omitempty"`
	LicenseExpire   string            `json:"license_expire,omitempty"`
	Msg             string            `json:"message"`
}

const (
	ThreatActionMonitor = "alert"
	ThreatActionAllow   = "allow"
	ThreatActionBlock   = "deny"
	ThreatActionReset   = "reset"
)

const (
	TargetServer = "server"
	TargetClient = "client"
)

type Threat struct {
	LogCommon
	ID              string `json:"id"`
	ThreatID        uint32 `json:"threat_id"`
	ClientWL        string `json:"client_workload_id"`
	ClientWLName    string `json:"client_workload_name"`
	ClientWLDomain  string `json:"client_workload_domain,omitempty"`
	ClientWLImage   string `json:"client_workload_image,omitempty"`
	ClientWLService string `json:"client_workload_service,omitempty"`
	ServerWL        string `json:"server_workload_id"`
	ServerWLName    string `json:"server_workload_name"`
	ServerWLDomain  string `json:"server_workload_domain,omitempty"`
	ServerWLImage   string `json:"server_workload_image,omitempty"`
	ServerWLService string `json:"server_workload_service,omitempty"`
	Severity        string `json:"severity"`
	Action          string `json:"action"`
	Count           uint32 `json:"count"`
	EtherType       uint16 `json:"ether_type"`
	ClientPort      uint16 `json:"client_port"`
	ServerPort      uint16 `json:"server_port"`
	ServerConnPort  uint16 `json:"server_conn_port"`
	ICMPCode        uint8  `json:"icmp_code"`
	ICMPType        uint8  `json:"icmp_type"`
	IPProto         uint8  `json:"ip_proto"`
	ClientIP        string `json:"client_ip"`
	ServerIP        string `json:"server_ip"`
	Application     string `json:"application"`
	Sensor          string `json:"sensor"`
	Group           string `json:"group"`
	Target          string `json:"target"`
	Monitor         bool   `json:"monitor"`
	CapLen          uint16 `json:"cap_len,omitempty"`
	Packet          string `json:"packet,omitempty"`
	Msg             string `json:"message"`
}

type Violation struct {
	LogCommon
	ID            string   `json:"id"`
	ClientWL      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	ClientDomain  string   `json:"client_domain,omitempty"`
	ClientImage   string   `json:"client_image,omitempty"`
	ClientService string   `json:"client_service,omitempty"`
	ServerWL      string   `json:"server_id"`
	ServerName    string   `json:"server_name"`
	ServerDomain  string   `json:"server_domain,omitempty"`
	ServerImage   string   `json:"server_image,omitempty"`
	ServerService string   `json:"server_service,omitempty"`
	ServerPort    uint16   `json:"server_port"`
	IPProto       uint8    `json:"ip_proto"`
	Applications  []string `json:"applications"`
	Servers       []string `json:"servers"`
	Sessions      uint32   `json:"sessions"`
	PolicyAction  string   `json:"policy_action"`
	PolicyID      uint32   `json:"policy_id"`
	ClientIP      string   `json:"client_ip"`
	ServerIP      string   `json:"server_ip"`
	FQDN          string   `json:"fqdn"`
	Xff           bool     `json:"xff"`
	Nbe           bool     `json:"nbe"`
}

const (
	IncidentActionAlert  = "Alert"
	IncidentActionDenied = "Denied"
)

type Incident struct {
	LogCommon
	ID              string   `json:"id"`
	WorkloadID      string   `json:"workload_id,omitempty"`
	WorkloadName    string   `json:"workload_name,omitempty"`
	WorkloadDomain  string   `json:"workload_domain,omitempty"`
	WorkloadImage   string   `json:"workload_image,omitempty"`
	WorkloadService string   `json:"workload_service,omitempty"`
	RemoteWL        string   `json:"remote_workload_id,omitempty"`
	RemoteWLName    string   `json:"remote_workload_name,omitempty"`
	RemoteWLDomain  string   `json:"remote_workload_domain,omitempty"`
	RemoteWLImage   string   `json:"remote_workload_image,omitempty"`
	RemoteWLService string   `json:"remote_workload_service,omitempty"`
	ProcName        string   `json:"proc_name,omitempty"`
	ProcPath        string   `json:"proc_path,omitempty"`
	ProcCmd         string   `json:"proc_cmd,omitempty"`
	ProcRealUID     int      `json:"proc_real_uid,omitempty"`
	ProcEffUID      int      `json:"proc_effective_uid,omitempty"`
	ProcRealUser    string   `json:"proc_real_user,omitempty"`
	ProcEffUser     string   `json:"proc_effective_user,omitempty"`
	FilePath        string   `json:"file_path,omitempty"`
	Files           []string `json:"file_name,omitempty"`
	ClientIP        string   `json:"client_ip,omitempty"`
	ServerIP        string   `json:"server_ip,omitempty"`
	ClientPort      uint16   `json:"client_port,omitempty"`
	ServerPort      uint16   `json:"server_port,omitempty"`
	ServerConnPort  uint16   `json:"server_conn_port,omitempty"`
	EtherType       uint16   `json:"ether_type,omitempty"`
	IPProto         uint8    `json:"ip_proto,omitempty"`
	ConnIngress     bool     `json:"conn_ingress,omitempty"`
	ProcPName       string   `json:"proc_parent_name,omitempty"`
	ProcPPath       string   `json:"proc_parent_path,omitempty"`
	Action          string   `json:"action"`
	Group           string   `json:"group,omitempty"`
	RuleID          string   `json:"rule_id"`
	AggregationFrom int64    `json:"aggregation_from,omitempty"`
	Count           int      `json:"count,omitempty"`
	Msg             string   `json:"message"`
}

type Audit struct {
	LogCommon
	WorkloadID      string   `json:"workload_id,omitempty"`
	WorkloadName    string   `json:"workload_name,omitempty"`
	WorkloadDomain  string   `json:"workload_domain,omitempty"`
	WorkloadImage   string   `json:"workload_image,omitempty"`
	WorkloadService string   `json:"workload_service,omitempty"`
	Image           string   `json:"image,omitempty"`         // workload
	ImageID         string   `json:"image_id,omitempty"`      // workload
	Registry        string   `json:"registry,omitempty"`      // image
	RegistryName    string   `json:"registry_name,omitempty"` // image
	Repository      string   `json:"repository,omitempty"`    // image
	Tag             string   `json:"tag,omitempty"`           // image
	BaseOS          string   `json:"base_os,omitempty"`
	CriticalCnt     int      `json:"critical_vul_cnt"`
	HighCnt         int      `json:"high_vul_cnt"`
	MediumCnt       int      `json:"medium_vul_cnt"`
	CriticalVuls    []string `json:"critical_vuls,omitempty"`
	HighVuls        []string `json:"high_vuls,omitempty"`
	MediumVuls      []string `json:"medium_vuls,omitempty"`
	CVEDBVersion    string   `json:"cvedb_version,omitempty"`
	Message         string   `json:"message"`
	User            string   `json:"user,omitempty"`
	Error           string   `json:"error,omitempty"`
	AggregationFrom int64    `json:"aggregation_from,omitempty"`
	Count           uint32   `json:"count,omitempty"`
	Items           []string `json:"items,omitempty"`
	Group           string   `json:"group,omitempty"`
	Platform        string   `json:"platform,omitempty"`
	PlatformVersion string   `json:"platform_version,omitempty"`
	// cloud
	Region      string `json:"region,omitempty"`
	ProjectName string `json:"project_name,omitempty"`
	// one vuln. per log
	Packages       []string `json:"packages,omitempty"`
	PackageVersion string   `json:"package_ver,omitempty"`
	FixedVersion   string   `json:"fixed_ver,omitempty"`
	Score          float32  `json:"score,omitempty"`
	ScoreV3        float32  `json:"score_v3,omitempty"`
	Vectors        string   `json:"vectors,omitempty"`
	VectorsV3      string   `json:"vectors_v3,omitempty"`
	Link           string   `json:"link,omitempty"`
	Description    string   `json:"description,omitempty"`
	Published      string   `json:"pub_date,omitempty"`
	LastMod        string   `json:"last_mod_date,omitempty"`
	// report vuln. in layer
	ImageLayerDigest string `json:"image_layer_digest,omitempty"`
	Cmds             string `json:"cmds,omitempty"`
	// intermediate data
	Vuls                map[string]*share.ScanVulnerability `json:"-"`
	Layers              []Audit                             `json:"-"`
	PVCName             string                              `json:"pvc_name,omitempty"`
	PVCStorageClassName string                              `json:"pvc_storageclass_name,omitempty"`
}

type IBMSAFinding struct {
	ID          string
	Name        string
	Level       string
	EventType   string
	At          time.Time
	Protocol    uint8
	Direction   string
	ProtoName   string
	ClientIP    string
	ClientPort  uint16
	ClientPkts  int32
	ClientBytes int32
	ServerIP    string
	ServerPort  uint16
	ServerPkts  int32
	ServerBytes int32
}
