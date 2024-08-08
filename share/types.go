package share

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/endpoints"
)

const DefaultCVEDBName = "cvedb"
const CompactCVEDBName = "cvedb.compact"
const RegularCVEDBName = "cvedb.regular"
const CVEDatabaseFolder = "/etc/neuvector/db/"

const ProfileFolder string = "/var/nv_debug/profile"
const SnaphotFolder string = "/var/nv_debug/snapshot"
const ProfileMemoryFileFmt string = "%smemory.prof"
const ProfileGoroutineFileFmt string = "%sgoroutine.prof"
const ProfileCPUFileFmt string = "%scpu.prof"

const CustomScriptFailedPrefix string = "Failed to run the custom check"

const (
	NeuVectorLabelImage string = "neuvector.image"
	NeuVectorLabelRole  string = "neuvector.role"

	NeuVectorRoleController string = "controller"
	NeuVectorRoleEnforcer   string = "enforcer"
	NeuVectorRoleManager    string = "manager"
)

const UnusedGroupAgingDefault uint8 = 24 //aging time in Hour
const UnusedGroupAgingMax uint8 = 168    //aging time in Hour,24*7
const (
	PolicyModeLearn       string = "Discover"
	PolicyModeEvaluate    string = "Monitor"
	PolicyModeEnforce     string = "Protect"
	PolicyModeUnavailable string = "N/A"
)

const (
	ProfileDefault_UNUSED string = "default" // (obsolete) it's equal to "zero-drift"
	ProfileShield_UNUSED  string = "shield"  // (obsolete) it's equal to "zero-drift"
	ProfileBasic          string = "basic"
	ProfileZeroDrift      string = "zero-drift"
)

const (
	PolicyActionOpen     string = "open" // Policy is not enforced
	PolicyActionLearn    string = "learn"
	PolicyActionAllow    string = "allow"
	PolicyActionDeny     string = "deny"
	PolicyActionViolate  string = "violate"
	PolicyActionCheckApp string = "check_app"
	PolicyActionCheckVh  string = "check_vh"
)

const (
	VulnSeverityCritical string = "Critical"
	VulnSeverityHigh     string = "High"
	VulnSeverityMedium   string = "Medium"
	VulnSeverityLow      string = "Low"
)

const (
	DlpRuleActionAllow   string = "allow"
	DlpRuleActionDrop    string = "deny"
	DlpRuleStatusEnable  string = "enable"
	DlpRuleStatusDisable string = "disable"
	DlpRuleSeverityInfo  string = "info"
	DlpRuleSeverityLow   string = "low"
	DlpRuleSeverityMed   string = "medium"
	DlpRuleSeverityHigh  string = "high"
	DlpRuleSeverityCrit  string = "critical"
)

const ContainerRuntimeDocker string = "docker"
const DomainDelimiter string = "."

const (
	PlatformDocker     = "Docker"
	PlatformAmazonECS  = "Amazon-ECS"
	PlatformAmazonEKS  = "Amazon-EKS"
	PlatformAzureAKS   = "Azure-AKS"
	PlatformGoogleGKE  = "Google-GKE"
	PlatformKubernetes = "Kubernetes"
	PlatformRancher    = "Rancher"
	PlatformAliyun     = "Aliyun"

	FlavorSwarm     = "Swarm"
	FlavorUCP       = "UCP"
	FlavorOpenShift = "OpenShift"
	FlavorRancher   = "Rancher"
	FlavorIKE       = "IKE"

	CloudGKE = "GKE"
	CloudAKS = "AKS"
	CloudEKS = "EKS"

	NetworkFlannel   = "Flannel"
	NetworkCalico    = "Calico"
	NetworkDefault   = "Default"
	NetworkProxyMesh = "ProxyMeshLo"
)

const (
	ENV_PLATFORM_INFO = "NV_PLATFORM_INFO"
	ENV_SYSTEM_GROUPS = "NV_SYSTEM_GROUPS"
	ENV_DISABLE_PCAP  = "DISABLE_PACKET_CAPTURE"
)

const (
	ENV_PLT_PLATFORM    = "platform"
	ENV_PLT_INTF_PREFIX = "if-"
	ENV_PLT_INTF_HOST   = "host"
	ENV_PLT_INTF_GLOBAL = "global"
)

// Registry
const DefaultOpenShiftRegistryURL = "docker-registry.default.svc"

const (
	RegistryTypeAWSECR           = "Amazon ECR Registry"
	RegistryTypeAzureACR         = "Azure Container Registry"
	RegistryTypeDocker           = "Docker Registry"
	RegistryTypeGCR              = "Google Container Registry"
	RegistryTypeJFrog            = "JFrog Artifactory"
	RegistryTypeOpenShift        = "OpenShift Registry"
	RegistryTypeRedhat_Deprecate = "Red Hat/OpenShift Registry"
	RegistryTypeRedhat           = "Red Hat Public Registry"
	RegistryTypeSonatypeNexus    = "Sonatype Nexus"
	RegistryTypeGitlab           = "Gitlab"
	RegistryTypeIBMCloud         = "IBM Cloud Container Registry"
)

const (
	JFrogModeRepositoryPath = "Repository Path"
	JFrogModeSubdomain      = "Subdomain"
	JFrogModePort           = "Port"
)

// Response rule
const (
	EventRuntime          string = "security-event" // EventThreat + EventIncident + EventViolation + EventDlp +EventWaf
	EventEvent            string = "event"
	EventActivity         string = "activity"
	EventCVEReport        string = "cve-report"
	EventThreat           string = "threat"
	EventIncident         string = "incident"
	EventViolation        string = "violation"
	EventBenchmark_UNUSED string = "benchmark"
	EventCompliance       string = "compliance"
	EventAdmCtrl          string = "admission-control"
	EventDlp              string = "dlp"
	EventServerless       string = "serverless"
	EventWaf              string = "waf"
)

const (
	RuleAttribGroup    string = "group"
	RuleAttribCriteria string = "criteria"
	RuleAttribAction   string = "action"
	RuleAttribLogLevel string = "log-level"
)

const (
	EventCondTypeName    string = "name"
	EventCondTypeCVEName string = "cve-name"
	// EventCondTypeCVECritical        string = "cve-critical" // NVSHAS-8242: temporary reversion
	EventCondTypeCVEHigh   string = "cve-high"
	EventCondTypeCVEMedium string = "cve-medium"
	// EventCondTypeCVECriticalWithFix string = "cve-critical-with-fix" // NVSHAS-8242: temporary reversion
	EventCondTypeCVEHighWithFix string = "cve-high-with-fix"
	EventCondTypeLevel          string = "level"
	EventCondTypeProc           string = "process"
	EventCondTypeBenchNumber    string = "number"
)

const (
	EventActionQuarantine  string = "quarantine"
	EventActionSuppressLog string = "suppress-log"
	EventActionWebhook     string = "webhook"
)

const (
	FileAccessBehaviorBlock   = "block_access"
	FileAccessBehaviorMonitor = "monitor_change"
)

type ProbeContainerStart struct {
	Id          string
	RootPid_alt int
}

const GroupNVProtect string = "NV.Protect"
const AwsNvSecKey string = "nvsecKey"
const (
	// show only
	CloudResDataLost = "data_lost"
	// transient state
	CloudResScheduled  = "scheduled"
	CloudResScanning   = "scanning"
	CloudResSuspending = "suspending"
	// final state
	CloudResSuspend = "suspend"
	CloudResReady   = "ready"
	CloudResError   = "error"
)

var AwsRegionAll = []string{
	endpoints.ApEast1RegionID,
	endpoints.ApNortheast1RegionID,
	endpoints.ApNortheast2RegionID,
	endpoints.ApSouth1RegionID,
	endpoints.ApSoutheast1RegionID,
	endpoints.ApSoutheast2RegionID,
	endpoints.CaCentral1RegionID,
	endpoints.EuCentral1RegionID,
	endpoints.EuNorth1RegionID,
	endpoints.EuWest1RegionID,
	endpoints.EuWest2RegionID,
	endpoints.EuWest3RegionID,
	endpoints.MeSouth1RegionID,
	endpoints.SaEast1RegionID,
	endpoints.UsEast1RegionID,
	endpoints.UsEast2RegionID,
	endpoints.UsWest1RegionID,
	endpoints.UsWest2RegionID,
}

const (
	CloudAws   = "aws_cloud"
	CloudAzure = "azure_cloud"
)

const (
	AwsLambdaFunc  = "aws_lambda_func"
	AwsLambdaLayer = "aws_lambda_layer"
	AwsLambdaApp   = "aws_lambda_app"
	AwsLambdaRt    = "aws_lambda_runtime"
)

const NV_VBR_PORT_MTU int = 2048       //2k
const NV_VBR_PORT_MTU_JUMBO int = 9216 //9k

// Stats
const ContainerStatsSlots uint = 60 // 5s * 60 = 3m

type ContainerStats struct {
	PrevCPU       uint64
	PrevCPUSystem uint64
	ReadAt        time.Time
	CurSlot       uint
	Cpu           [ContainerStatsSlots]float64
	Memory        [ContainerStatsSlots]uint64
}
