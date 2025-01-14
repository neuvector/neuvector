package share

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/log"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
)

const CLUSObjectStore string = "object/"
const CLUSLockStore string = "lock/"
const CLUSNetworkStore string = "network/"
const CLUSWorkloadProfileStore string = "profiles/"
const CLUSStateStore string = "state/"
const CLUSScanStore string = "scan/"
const CLUSBenchStore string = "bench/"
const CLUSRecalculateStore string = "recalculate/" //not to be watched by consul
const CLUSFqdnStore string = "fqdn/"               //not to be watched by consul
const CLUSNodeStore string = "node/"
const CLUSNodeRuleStore string = "noderule/"

// lock
const CLUSLockConfigKey string = CLUSLockStore + "all"
const CLUSLockUserKey string = CLUSLockStore + "user"
const CLUSLockPolicyKey string = CLUSLockStore + "policy"
const CLUSLockServerKey string = CLUSLockStore + "server"
const CLUSLockUpgradeKey string = CLUSLockStore + "upgrade"
const CLUSLockRestoreKey string = CLUSLockStore + "restore"
const CLUSLockAdmCtrlKey string = CLUSLockStore + "adm_ctrl"
const CLUSLockFedKey string = CLUSLockStore + "federation"
const CLUSLockScannerKey string = CLUSLockStore + "scanner"
const CLUSLockCrdQueueKey string = CLUSLockStore + "crd_queue"
const CLUSLockCloudKey string = CLUSLockStore + "cloud"
const CLUSLockFedScanDataKey string = CLUSLockStore + "fed_scan_data"
const CLUSLockApikeyKey string = CLUSLockStore + "apikey"
const CLUSLockVulnKey string = CLUSLockStore + "vulnerability"
const CLUSLockCompKey string = CLUSLockStore + "compliance"

//const CLUSLockResponseRuleKey string = CLUSLockStore + "response_rule"

// config
// TODO: Should we move config/ out of object/, currently handling object/ and config/ is
//       synchronized in one watcher thread
// !!! NOTE: When adding new config items, update the import/export list as well !!!

const (
	CFGEndpointSystem               = "system"
	CFGEndpointEULA                 = "eula_oss"
	CFGEndpointScan                 = "scan"
	CFGEndpointUser                 = "user"
	CFGEndpointServer               = "server"
	CFGEndpointGroup                = "group"
	CFGEndpointPolicy               = "policy"
	CFGEndpointLicense              = "license"
	CFGEndpointResponseRule         = "response_rule"
	CFGEndpointProcessProfile       = "process_profile"
	CFGEndpointRegistry             = "registry"
	CFGEndpointDomain               = "domain"
	CFGEndpointFileMonitor          = "file_monitor"
	CFGEndpointFileAccessRule       = "file_rule"
	CFGEndpointAdmissionControl     = "admission_control"
	CFGEndpointCrd                  = "crd"
	CFGEndpointFederation           = "federation"
	CFGEndpointDlpRule              = "dlp_rule"
	CFGEndpointDlpGroup             = "dlp_group"
	CFGEndpointWafRule              = "waf_rule"
	CFGEndpointWafGroup             = "waf_group"
	CFGEndpointScript               = "script"
	CFGEndpointCloud                = "cloud"
	CFGEndpointCompliance           = "compliance"
	CFGEndpointVulnerability        = "vulnerability"
	CFGEndpointUserRole             = "user_role"
	CFGEndpointPwdProfile           = "pwd_profile"
	CFGEndpointApikey               = "apikey"
	CFGEndpointSigstoreRootsOfTrust = "sigstore_roots_of_trust"
	CFGEndpointQuerySession         = "querysession"
)
const CLUSConfigStore string = CLUSObjectStore + "config/"
const CLUSConfigSystemKey string = CLUSConfigStore + CFGEndpointSystem
const CLUSConfigEULAKey string = CLUSConfigStore + CFGEndpointEULA
const CLUSConfigScanKey string = CLUSConfigStore + CFGEndpointScan
const CLUSConfigUserStore string = CLUSConfigStore + CFGEndpointUser + "/"
const CLUSConfigServerStore string = CLUSConfigStore + CFGEndpointServer + "/"
const CLUSConfigGroupStore string = CLUSConfigStore + CFGEndpointGroup + "/"
const CLUSConfigPolicyStore string = CLUSConfigStore + CFGEndpointPolicy + "/"
const CLUSConfigLicenseKey string = CLUSConfigStore + CFGEndpointLicense
const CLUSConfigResponseRuleStore string = CLUSConfigStore + CFGEndpointResponseRule + "/"
const CLUSConfigProcessProfileStore string = CLUSConfigStore + CFGEndpointProcessProfile + "/"
const CLUSConfigRegistryStore string = CLUSConfigStore + CFGEndpointRegistry + "/"
const CLUSConfigFileMonitorStore string = CLUSConfigStore + CFGEndpointFileMonitor + "/"
const CLUSConfigFileAccessRuleStore string = CLUSConfigStore + CFGEndpointFileAccessRule + "/"
const CLUSConfigAdmissionControlStore string = CLUSConfigStore + CFGEndpointAdmissionControl + "/"
const CLUSConfigCrdStore string = CLUSConfigStore + CFGEndpointCrd + "/"
const CLUSConfigFederationStore string = CLUSConfigStore + CFGEndpointFederation + "/"
const CLUSConfigDlpRuleStore string = CLUSConfigStore + CFGEndpointDlpRule + "/"
const CLUSConfigDlpGroupStore string = CLUSConfigStore + CFGEndpointDlpGroup + "/"
const CLUSConfigWafRuleStore string = CLUSConfigStore + CFGEndpointWafRule + "/"
const CLUSConfigWafGroupStore string = CLUSConfigStore + CFGEndpointWafGroup + "/"
const CLUSConfigScriptStore string = CLUSConfigStore + CFGEndpointScript + "/"
const CLUSConfigCloudStore string = CLUSConfigStore + CFGEndpointCloud + "/"
const CLUSConfigComplianceStore string = CLUSConfigStore + CFGEndpointCompliance + "/"
const CLUSConfigVulnerabilityStore string = CLUSConfigStore + CFGEndpointVulnerability + "/"
const CLUSConfigDomainStore string = CLUSConfigStore + CFGEndpointDomain + "/"
const CLUSConfigUserRoleStore string = CLUSConfigStore + CFGEndpointUserRole + "/"
const CLUSConfigPwdProfileStore string = CLUSConfigStore + CFGEndpointPwdProfile + "/"
const CLUSConfigApikeyStore string = CLUSConfigStore + CFGEndpointApikey + "/"
const CLUSConfigSigstoreRootsOfTrust string = CLUSConfigStore + CFGEndpointSigstoreRootsOfTrust + "/"
const CLUSConfigQuerySessionStore string = CLUSConfigStore + CFGEndpointQuerySession + "/"

// !!! NOTE: When adding new config items, update the import/export list as well !!!

const CLUSUniconfStore string = CLUSObjectStore + "uniconf/" // Target both controller and specific enforcer

// object
const CLUSHostStore string = CLUSObjectStore + "host/"
const CLUSAgentStore string = CLUSObjectStore + "agent/"
const CLUSControllerStore string = CLUSObjectStore + "controller/"
const CLUSWorkloadStore string = CLUSObjectStore + "workload/"
const CLUSNetworkEPStore string = CLUSObjectStore + "networkep/"
const CLUSThreatLogStore string = CLUSObjectStore + "threatlog/"
const CLUSEventLogStore string = CLUSObjectStore + "eventlog/"
const CLUSIncidentLogStore string = CLUSObjectStore + "incidentlog/"
const CLUSAuditLogStore string = CLUSObjectStore + "auditlog/"
const CLUSCloudStore string = CLUSObjectStore + "cloud/"
const CLUSCrdProcStore string = "crdcontent/"
const CLUSCertStore string = CLUSObjectStore + "cert/"
const CLUSLicenseStore string = CLUSObjectStore + "license/"
const CLUSTelemetryStore string = CLUSObjectStore + "telemetry/"
const CLUSThrottledEventStore string = CLUSObjectStore + "throttled/"

// network
const PolicyIPRulesDefaultName string = "GroupIPRules"
const PolicyIPRulesVersionID string = "NeuVectorPolicyVersion" // used for indicate policy version changed
const DlpRulesVersionID string = "NeuVectorDlpVersion"         // used for indicate dlp version changed
const DlpRulesDefaultName string = "DlpWorkloadRules"
const DlpRuleName string = "dlprule"
const DlpRuleStore string = CLUSNetworkStore + DlpRuleName + "/"
const WafRuleName string = "wafrule"
const WafRuleStore string = CLUSNetworkStore + WafRuleName + "/"
const NetworkSystemKey string = CLUSNetworkStore + CFGEndpointSystem

// profiles
const ProfileCommonGroup string = "common" // nodes
const ProfileGroup string = "group"
const ProfileProcess string = "process"
const ProfileFileMonitor string = "file"
const ProfileFileAccess string = "fileAccess"
const ProfileScript string = "script"
const ProfileGroupStore string = CLUSWorkloadProfileStore + ProfileGroup + "/"
const ProfileProcessStore string = CLUSWorkloadProfileStore + ProfileProcess + "/"
const ProfileFileMonitorStore string = CLUSWorkloadProfileStore + ProfileFileMonitor + "/"
const ProfileFileAccessStore string = CLUSWorkloadProfileStore + ProfileFileAccess + "/"
const ProfileFileScriptStore string = CLUSWorkloadProfileStore + ProfileScript + "/"
const CLUSNodeCommonStoreKey string = CLUSNodeStore + ProfileCommonGroup + "/"
const CLUSNodeCommonProfileStore string = CLUSNodeCommonStoreKey + CLUSWorkloadProfileStore

// state
const CLUSCtrlEnabledValue string = "ok"

// cluster key represent one installation, which will remain unchanged when controllers
// come and go, and rolling upgrade. It is not part of system configuration.
const CLUSCtrlInstallationKey string = CLUSStateStore + "installation"
const CLUSCtrlNodeAdmissionKey string = CLUSStateStore + "ctrl_ready" // node admission
const CLUSCtrlConfigLoadedKey string = CLUSStateStore + "ctrl_cfg_load"
const CLUSCtrlDistLockStore string = CLUSStateStore + "dist_lock/"
const CLUSCtrlUsageReportStore string = CLUSStateStore + "usage_report/"
const CLUSCtrlVerKey string = CLUSStateStore + "ctrl_ver"
const CLUSKvRestoreKey string = CLUSStateStore + "kv_restore"
const CLUSExpiredTokenStore string = CLUSStateStore + "expired_token/"
const CLUSImportStore string = CLUSStateStore + "import/"

func CLUSExpiredTokenKey(token string) string {
	return fmt.Sprintf("%s%s", CLUSExpiredTokenStore, token)
}

func CLUSCtrlDistLockKey(lock string) string {
	return strings.Replace(lock, CLUSLockStore, CLUSCtrlDistLockStore, 1)
}

func CLUSCtrlUsageReportKey(ts int64) string {
	return fmt.Sprintf("%s%d", CLUSCtrlUsageReportStore, ts)
}

func CLUSCtrlUsageReportKey2TS(key string) int64 {
	v := keyLastToken(key)
	if s, err := strconv.ParseInt(v, 10, 64); err == nil {
		return s
	}
	return 0
}

// multi-clusters
const CLUSConfigFedResponseRuleKey string = CLUSConfigResponseRuleStore + "fed/"
const CLUSConfigFedAdmCtrlKey string = CLUSConfigAdmissionControlStore + "fed/"

const (
	GroupKindContainer string = "container"
	GroupKindAddress   string = "address"
	GroupKindIPService string = "ip_service"
	GroupKindExternal  string = "external"
	GroupKindNode      string = "node"
)

// scan
const CLUSScanStateStore string = CLUSScanStore + "state/"
const CLUSScanDataStore string = CLUSScanStore + "data/"
const CLUSScannerStore string = CLUSScanStore + "scanner/"
const CLUSScannerStatsStore string = CLUSScanStore + "scanner_stats/"
const CLUSScannerDBVersionID string = "NeuVectorCVEDBVersion" // used for indicate db version changed
const CLUSScannerDBStore string = CLUSScanStore + "database/"

// recalculate
const CLUSRecalPolicyStore string = CLUSRecalculateStore + "policy/" //not to be watched by consul
const CLUSRecalDlpStore string = CLUSRecalculateStore + "dlp/"       //not to be watched by consul

func CLUSPolicyIPRulesKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSNetworkStore, name)
}

func CLUSPolicyIPRulesKeyNode(name, nodeid string) string {
	return fmt.Sprintf("%s%s/%s", CLUSNodeRuleStore, nodeid, name)
}

func CLUSNodeRulesKey(nodeID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSNodeRuleStore, nodeID, PolicyIPRulesVersionID)
}

func CLUSRecalPolicyIPRulesKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSRecalPolicyStore, name)
}

func CLUSRecalDlpWlRulesKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSRecalDlpStore, name)
}

// fqdn
const CLUSFqdnIpStore string = CLUSFqdnStore + "ip/" //not to be watched by consul

func CLUSFqdnIpKey(hostID string, fqdname string) string {
	return fmt.Sprintf("%s%s/%s", CLUSFqdnIpStore, hostID, fqdname)
}

const InternalIPNetDefaultName string = "InternalIPNet"
const SpecialIPNetDefaultName string = "SpecialIPNet"
const NsBoundaryKey string = "NeuvectorNamespaceBoundary"
const NsBoundaryValEnable string = "enabled"

func CLUSInternalIPNetsKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSNetworkStore, name)
}

// uniconf
func CLUSUniconfTargetStore(target string) string {
	return fmt.Sprintf("%s%s", CLUSUniconfStore, target)
}

func CLUSUniconfControllerKey(target, id string) string {
	return fmt.Sprintf("%s/controller/%s", CLUSUniconfTargetStore(target), id)
}

func CLUSUniconfAgentKey(target, id string) string {
	return fmt.Sprintf("%s/agent/%s", CLUSUniconfTargetStore(target), id)
}

func CLUSUniconfWorkloadKey(target, id string) string {
	return fmt.Sprintf("%s/workload/%s", CLUSUniconfTargetStore(target), id)
}

func CLUSUniconfKey2Subject(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSUniconfKey2ID(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSUserKey(username string) string {
	return fmt.Sprintf("%s%s", CLUSConfigUserStore, username)
}

func CLUSPwdProfileKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigPwdProfileStore, name)
}

func CLUSDomainKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigDomainStore, name)
}

func CLUSServerKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigServerStore, name)
}

func CLUSHostKey(hostID string, by string) string {
	return fmt.Sprintf("%s%s/%s", CLUSHostStore, by, hostID)
}

func CLUSAgentKey(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSAgentStore, hostID, devID)
}

func CLUSControllerKey(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSControllerStore, hostID, devID)
}

func CLUSWorkloadKey(hostID string, wlID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSWorkloadStore, hostID, wlID)
}

func CLUSNetworkEPKey(hostID string, epID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSNetworkEPStore, hostID, epID)
}

func eventLogStore(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSEventLogStore, hostID, devID)
}

func CLUSThreatLogKey(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSThreatLogStore, hostID, devID)
}

func CLUSIncidentLogKey(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSIncidentLogStore, hostID, devID)
}

func CLUSAuditLogKey(hostID string, devID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSAuditLogStore, hostID, devID)
}

func CLUSAgentEventLogKey(hostID string, devID string) string {
	return fmt.Sprintf("%s/agent", eventLogStore(hostID, devID))
}

func CLUSControllerEventLogKey(hostID string, devID string) string {
	return fmt.Sprintf("%s/controller", eventLogStore(hostID, devID))
}

func CLUSGroupKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigGroupStore, name)
}

func CLUSGroupNetworkKey(name string) string {
	return fmt.Sprintf("%s%s", ProfileGroupStore, name)
}

func CLUSPolicyRuleKey(name string, id uint32) string {
	return fmt.Sprintf("%s%s/rule/%v", CLUSConfigPolicyStore, name, id)
}

func CLUSPolicyRuleListKey(name string) string {
	return fmt.Sprintf("%s%s/rules", CLUSConfigPolicyStore, name)
}

func CLUSPolicyZipRuleListKey(name string) string {
	return fmt.Sprintf("%s%s/ziprules", CLUSConfigPolicyStore, name)
}

func CLUSScanDataHostKey(id string) string {
	return fmt.Sprintf("%sreport/host/%s", CLUSScanDataStore, id)
}

func CLUSScanDataWorkloadKey(id string) string {
	return fmt.Sprintf("%sreport/workload/%s", CLUSScanDataStore, id)
}

func CLUSScanDataPlatformKey(id string) string {
	return fmt.Sprintf("%sreport/platform/%s", CLUSScanDataStore, id)
}

func CLUSBenchStateHostKey(id string) string {
	return fmt.Sprintf("%sbench/host/%s", CLUSScanStateStore, id)
}

func CLUSBenchStateWorkloadKey(id string) string {
	return fmt.Sprintf("%sbench/workload/%s", CLUSScanStateStore, id)
}

func CLUSScanStateHostKey(id string) string {
	return fmt.Sprintf("%sreport/host/%s", CLUSScanStateStore, id)
}

func CLUSScanStateWorkloadKey(id string) string {
	return fmt.Sprintf("%sreport/workload/%s", CLUSScanStateStore, id)
}

func CLUSScanStatePlatformKey(id string) string {
	return fmt.Sprintf("%sreport/platform/%s", CLUSScanStateStore, id)
}

func CLUSBenchKey(id string) string {
	return fmt.Sprintf("%s%s", CLUSBenchStore, id)
}

func CLUSBenchReportKey(id string, bench BenchType) string {
	return fmt.Sprintf("%s/report/%s", CLUSBenchKey(id), bench)
}

func CLUSCustomCheckConfigKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigScriptStore, name)
}

func CLUSCustomCheckNetworkKey(name string) string {
	return fmt.Sprintf("%s%s", ProfileFileScriptStore, name)
}

const CLUSConfigComplianceProfileStore string = CLUSConfigComplianceStore + "profile/"
const CLUSConfigVulnerabilityProfileStore string = CLUSConfigVulnerabilityStore + "profile/"

func CLUSComplianceProfileKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigComplianceProfileStore, name)
}

func CLUSVulnerabilityProfileKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigVulnerabilityProfileStore, name)
}

func CLUSDomainConfigKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigDomainStore, name)
}

func CLUSRegistryConfigKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigRegistryStore, name)
}

func CLUSScanStateKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSScanStateStore, name)
}

func CLUSRegistryStateKey(name string) string {
	return fmt.Sprintf("%sregistry/%s", CLUSScanStateStore, name)
}

func CLUSRegistryImageStateKey(name, id string) string {
	return fmt.Sprintf("%simage/%s/%s", CLUSScanStateStore, name, id)
}

func CLUSRegistryImageDataKey(name, id string) string {
	return fmt.Sprintf("%simage/%s/%s", CLUSScanDataStore, name, id)
}

func CLUSRegistryImageStateStore(name string) string {
	return fmt.Sprintf("%simage/%s", CLUSScanStateStore, name)
}

func CLUSRegistryImageDataStore(name string) string {
	return fmt.Sprintf("%simage/%s", CLUSScanDataStore, name)
}

func CLUSScannerKey(id string) string {
	return fmt.Sprintf("%s%s", CLUSScannerStore, id)
}

func CLUSScannerStatsKey(id string) string {
	return fmt.Sprintf("%s%s", CLUSScannerStatsStore, id)
}

func CLUSFileMonitorKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigFileMonitorStore, name)
}

func CLUSFileMonitorNetworkKey(name string) string {
	return fmt.Sprintf("%s%s", ProfileFileMonitorStore, name)
}

func CLUSFileAccessRuleKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigFileAccessRuleStore, name)
}

func CLUSFileAccessRuleNetworkKey(name string) string {
	return fmt.Sprintf("%s%s", ProfileFileAccessStore, name)
}

func CLUSApikeyKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigApikeyStore, name)
}

func CLUSQuerySessionKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigQuerySessionStore, name)
}

// Host ID is included in the workload key to helps us retrieve all workloads on a host
// quickly. Without it, we have to loop through all workload keys; using agent ID is
// also problematic, as a new agent has no idea of the agent ID when the workload
// was created.
func CLUSWorkloadHostStore(hostID string) string {
	return fmt.Sprintf("%sworkload/%s/", CLUSObjectStore, hostID)
}

func CLUSNetworkEPHostStore(hostID string) string {
	return fmt.Sprintf("%snetworkep/%s/", CLUSObjectStore, hostID)
}

func CLUSKeyLength(key string) int {
	tokens := strings.Split(key, "/")
	return len(tokens)
}

func CLUSKeyNthToken(key string, nth int) string {
	tokens := strings.Split(key, "/")
	if len(tokens) > nth {
		return tokens[nth]
	}
	return ""
}

func keyLastToken(key string) string {
	if n := strings.LastIndexByte(key, '/'); n != -1 {
		return key[n+1:]
	}
	return key
}

func CLUSKey2Target(key string) string {
	return CLUSKeyNthToken(key, 0)
}

func CLUSObjectKey2Object(key string) string {
	return CLUSKeyNthToken(key, 1)
}

func CLUSConfigKey2Config(key string) string {
	return CLUSKeyNthToken(key, 2)
}

func CLUSCloudKey2Type(key string) string {
	return CLUSKeyNthToken(key, 2)
}

func CLUSHostKey2ID(key string) string {
	return keyLastToken(key)
}

func CLUSDeviceKey2ID(key string) string {
	return keyLastToken(key)
}

func CLUSWorkloadKey2ID(key string) string {
	return keyLastToken(key)
}

func CLUSNetworkEPKey2ID(key string) string {
	return keyLastToken(key)
}

func CLUSGroupKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSProfileKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSDlpRuleKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSDlpGroupKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSWafRuleKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSWafGroupKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSPolicyRuleKey2ID(key string) uint32 {
	s := keyLastToken(key)
	id, _ := strconv.Atoi(s)
	return uint32(id)
}

func CLUSKeyLastToken(key string) string {
	return keyLastToken(key)
}

const (
	CLUSResCfgRule     = "rule"
	CLUSResCfgRuleList = "rules"
)

func CLUSPolicyKey2ResPolicySubkey(key string) (string, string) { // returns policy name(like "default"/"fed") & "rule"/"rules"
	return CLUSKeyNthToken(key, 3), CLUSKeyNthToken(key, 4)
}

func CLUSIsPolicyRuleKey(key string) bool {
	return CLUSKeyNthToken(key, 4) == "rule"
}

func CLUSIsPolicyRuleListKey(key string) bool {
	return CLUSKeyNthToken(key, 4) == "rules"
}

func CLUSIsPolicyZipRuleListKey(key string) bool {
	return CLUSKeyNthToken(key, 4) == "ziprules"
}

func CLUSNetworkKey2Subject(key string) string {
	return CLUSKeyNthToken(key, 1)
}

func CLUSNodeRuleKey2Subject(key string) string {
	return CLUSKeyNthToken(key, 2)
}

func CLUSScannerKey2ID(key string) string {
	return CLUSKeyNthToken(key, 2)
}

func CLUSScanKey2Subject(key string) string {
	return CLUSKeyNthToken(key, 2)
}

func CLUSScanStateKey2Type(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSScanStateKey2ID(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSBenchStateKey2Type(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSBenchStateKey2ID(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSComplianceKey2Type(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSComplianceProfileKey2Name(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSVulnerabilityKey2Type(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSVulnerabilityProfileKey2Name(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSDomainKey2Name(key string) string {
	return keyLastToken(key)
}

func CLUSFileMonitorKey2Group(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSGroupKey2GroupName(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSRootOfTrustKey2RootOfTrustName(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSVerifierKey2VerifierName(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSSigstoreRootOfTrustKey(rootName string) string {
	return fmt.Sprintf("%s%s", CLUSConfigSigstoreRootsOfTrust, rootName)
}

func CLUSSigstoreVerifierKey(rootName string, verifierName string) string {
	return fmt.Sprintf("%s/%s", CLUSSigstoreRootOfTrustKey(rootName), verifierName)
}

func CLUSSigstoreTimestampKey() string {
	return fmt.Sprintf("%s%s", CLUSConfigStore, "sigstore_timestamp")
}

type CLUSDistLocker struct {
	LockedBy string    `json:"locked_by"`
	LockedAt time.Time `json:"locked_at"`
	Caller   string    `json:"caller"`
}

// ScanResult is used for local RPC so the structure can be stored in the cluster
type CLUSScanReport struct {
	ScannedAt time.Time `json:"scanned_at"`
	ScanResult
}

type CLUSScanState struct {
	ScannedAt time.Time `json:"scanned_at"`
	Status    string    `json:"status"`
}

type CLUSScanConfig struct {
	AutoScan bool `json:"auto_scan"`
}

type CLUSCtrlVersion struct {
	CtrlVersion string `json:"version"`
	KVVersion   string `json:"kv_version"`
}

type CLUSKvRestore struct {
	StartAt  time.Time `json:"start_at"`
	CtrlerID string    `json:"controller_id"`
}

type CLUSSyslogConfig struct {
	SyslogIP          net.IP   `json:"syslog_ip"`
	SyslogServer      string   `json:"syslog_server"`
	SyslogIPProto     uint8    `json:"syslog_ip_proto"`
	SyslogPort        uint16   `json:"syslog_port"`
	SyslogLevel       string   `json:"syslog_level"`
	SyslogEnable      bool     `json:"syslog_enable"`
	SyslogCategories  []string `json:"syslog_categories"`
	SyslogInJSON      bool     `json:"syslog_in_json"`
	SyslogServerCert  string   `json:"syslog_server_cert"`
	OutputEventToLogs bool     `json:"output_event_to_logs"`
}

type CLUSSystemUsageReport struct {
	Signature      string    `json:"signature"`
	ReportedAt     time.Time `json:"reported"`
	Platform       string    `json:"platform"`
	Hosts          int       `json:"hosts"`
	CPUCores       int       `json:"cores"`
	Controllers    int       `json:"controllers"`
	Agents         int       `json:"enforcers"`
	Scanners       int       `json:"scanners"`
	CVEDBVersion   string    `json:"cvedb_version"`
	Registries     int       `json:"registries"`
	Domains        int       `json:"domains"`
	RunningPods    int       `json:"running_pods"`
	Groups         int       `json:"groups"`
	MonitorGroups  int       `json:"moinitor_groups"`
	ProtectGroups  int       `json:"protect_groups"`
	PolicyRules    int       `json:"policy_rules"`
	AdmCtrlRules   int       `json:"adm_ctrl_rules"`
	RespRules      int       `json:"response_rules"`
	CRDRules       int       `json:"crd_rules"`
	Clusters       int       `json:"clusters"`
	SLessProjs     int       `json:"sl_projs"`
	InstallationID string    `json:"installation_id"`
}

type CLUSProxy struct {
	Enable   bool   `json:"enable"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password,cloak"`
}

type CLUSIBMSAConfigNV struct {
	EpEnabled      bool      `json:"ep_enabled"`
	EpStart        uint32    `json:"ep_start"` // set to 1 after /v1/partner/ibm_sa/setup/test return 200
	EpDashboardURL string    `json:"ep_dashboard_url"`
	EpConnectedAt  time.Time `json:"ep_connected_at"`
}

type CLUSIBMSAConfig struct {
	AccountID   string `json:"accountID,cloak"`
	APIKey      string `json:"apikey,cloak"`
	ProviderID  string `json:"providerId,cloak"` // service-id
	FindingsURL string `json:"findingsURL"`
	TokenURL    string `json:"tokenURL"`
}

type CLUSIBMSAOnboardData struct {
	NoteName   string `json:"note_name"`
	ID         string `json:"id,cloak"` // service-id ?
	ProviderID string `json:"provider_id"`
}

type CLUSWebhook struct {
	Name     string   `json:"name"`
	Url      string   `json:"url"`
	Enable   bool     `json:"enable"`
	UseProxy bool     `json:"use_proxy"`
	Type     string   `json:"type"`
	CfgType  TCfgType `json:"cfg_type"`
}

type CLUSSystemConfig struct {
	NewServicePolicyMode      string `json:"new_service_policy_mode"`
	NewServiceProfileMode     string `json:"new_service_profile_mode"`
	NewServiceProfileBaseline string `json:"new_service_profile_baseline"`
	UnusedGroupAging          uint8  `json:"unused_group_aging"`
	CLUSSyslogConfig
	SingleCVEPerSyslog    bool                      `json:"single_cve_per_syslog"`
	SyslogCVEInLayers     bool                      `json:"syslog_cve_in_layers"`
	AuthOrder             []string                  `json:"auth_order"`
	AuthByPlatform        bool                      `json:"auth_by_platform"`
	RancherEP             string                    `json:"rancher_ep"`
	InternalSubnets       []string                  `json:"configured_internal_subnets,omitempty"`
	WebhookEnable_UNUSED  bool                      `json:"webhook_enable"`
	WebhookUrl_UNUSED     string                    `json:"webhook_url"`
	Webhooks              []CLUSWebhook             `json:"webhooks"`
	ClusterName           string                    `json:"cluster_name"`
	ControllerDebug       []string                  `json:"controller_debug"`
	TapProxymesh          bool                      `json:"tap_proxymesh"`
	RegistryHttpProxy     CLUSProxy                 `json:"registry_http_proxy"`
	RegistryHttpsProxy    CLUSProxy                 `json:"registry_https_proxy"`
	IBMSAConfigNV         CLUSIBMSAConfigNV         `json:"ibmsa_config_nv"`
	IBMSAConfig           CLUSIBMSAConfig           `json:"ibmsa_config"`
	IBMSAOnboardData      CLUSIBMSAOnboardData      `json:"ibmsa_onboard_data"`
	XffEnabled            bool                      `json:"xff_enabled"`
	CfgType               TCfgType                  `json:"cfg_type"`
	NetServiceStatus      bool                      `json:"net_service_status"`
	NetServicePolicyMode  string                    `json:"net_service_policy_mode"`
	DisableNetPolicy      bool                      `json:"disable_net_policy"`
	DetectUnmanagedWl     bool                      `json:"detect_unmanaged_wl"`
	EnableIcmpPolicy      bool                      `json:"enable_icmp_policy"`
	ModeAutoD2M           bool                      `json:"mode_auto_d2m"`
	ModeAutoD2MDuration   int64                     `json:"mode_auto_d2m_duration"`
	ModeAutoM2P           bool                      `json:"mode_auto_m2p"`
	ModeAutoM2PDuration   int64                     `json:"mode_auto_m2p_duration"`
	ScannerAutoscale      CLUSSystemConfigAutoscale `json:"scanner_autoscale"`
	NoTelemetryReport     bool                      `json:"no_telemetry_report,omitempty"`
	RemoteRepositories    []CLUSRemoteRepository    `json:"remote_repositories"`
	EnableTLSVerification bool                      `json:"enable_tls_verification"`
	GlobalCaCerts         []string                  `json:"cacerts"`
}

type CLUSSystemConfigAutoscale struct {
	Strategy         string `json:"strategy"`
	MinPods          uint32 `json:"min_pods"`
	MaxPods          uint32 `json:"max_pods"`
	DisabledByOthers bool   `json:"disabled_by_others"` // true when autoscale is disabled because controller detects 3rd-party tool keeps reverting our autoscale
}

type CLUSEULA struct {
	Accepted bool `json:"accepted"`
}

type NvFedPermissions struct {
	Local  NvPermissions `json:"local"`
	Remote NvPermissions `json:"remote"`
}

func (p *NvFedPermissions) IsEmpty() bool {
	return p.Local.IsEmpty() && p.Remote.IsEmpty()
}

type NvPermissions struct {
	ReadValue  uint32 `json:"read_value"`
	WriteValue uint32 `json:"write_value"`
}

func (p *NvPermissions) IsEmpty() bool {
	return (p.ReadValue == 0 && p.WriteValue == 0)
}
func (p *NvPermissions) Reset() {
	p.ReadValue = 0
	p.WriteValue = 0
}

func (p *NvPermissions) HasPermFed() bool {
	return ((p.ReadValue&PERM_FED) != 0 || (p.WriteValue&PERM_FED) != 0)
}

func (p *NvPermissions) HasPermFedForReadOnly() bool {
	return ((p.ReadValue&PERM_FED) != 0 && (p.WriteValue&PERM_FED) == 0)
}

func (p *NvPermissions) FilterPermits(domain, scope, fedRole string) {
	if domain != "" {
		// fed access for namespace is not supported yet
		p.ReadValue &= PERMS_DOMAIN_READ
		p.WriteValue &= PERMS_DOMAIN_WRITE
	} else {
		if scope == "local" && fedRole == "master" {
			p.ReadValue &= PERMS_FED_READ
			p.WriteValue &= PERMS_FED_WRITE
		} else if scope == "remote" && fedRole != "master" {
			p.ReadValue = 0
			p.WriteValue = 0
		} else {
			p.ReadValue &= PERMS_CLUSTER_READ
			p.WriteValue &= PERMS_CLUSTER_WRITE
		}
	}
}

func (p *NvPermissions) Union(other NvPermissions) {
	p.ReadValue |= other.ReadValue
	p.WriteValue |= other.WriteValue
}

func (p *NvPermissions) ResetIfSubsetOf(other NvPermissions) {
	if (p.ReadValue | other.ReadValue) == other.ReadValue {
		// if p's read permissions is subset of other's read permissions, reset p's read permissions to 0 (duplicate)
		p.ReadValue = 0
	}
	if (p.WriteValue | other.WriteValue) == other.WriteValue {
		// if p's write permissions is subset of other's write permissions, reset p's write permissions to 0 (duplicate)
		p.WriteValue = 0
	}
}

func (p *NvPermissions) IsSubsetOf(other NvPermissions) bool {
	return ((other.ReadValue | p.ReadValue) == other.ReadValue) && ((other.WriteValue | p.WriteValue) == other.WriteValue)
}

type CLUSPermitsAssigned struct {
	Permits NvPermissions `json:"permissions"`
	Domains []string      `json:"domains"` // all domains in this slice have the same permissions assigned
}

type CLUSRemoteRolePermits struct {
	DomainRole   map[string]string        `json:"domain_role"`       // domain -> role
	ExtraPermits map[string]NvPermissions `json:"extra_permissions"` // domain -> extra permissions(other than in 'DomainRole')
}

type CLUSUser struct {
	Fullname            string                 `json:"fullname"`
	Username            string                 `json:"username"`
	PasswordHash        string                 `json:"password_hash"`
	PwdResetTime        time.Time              `json:"pwd_reset_time"`
	PwdHashHistory      []string               `json:"pwd_hash_history"` // not including the current password's hash
	Domain              string                 `json:"domain"`           // This is not used. Other 'domain' maps to namespace, this is not.
	Server              string                 `json:"server"`
	EMail               string                 `json:"email"`
	Role                string                 `json:"role"`
	RoleOverride        bool                   `json:"role_oride"` // Used for shadow user
	Timeout             uint32                 `json:"timeout"`
	Locale              string                 `json:"locale"`
	RoleDomains         map[string][]string    `json:"role_domains"`
	ExtraPermits        NvPermissions          `json:"extra_permits"`                 // extra permissions(other than 'Role') for global domain on local cluster. only for Rancher SSO
	ExtraPermitsDomains []CLUSPermitsAssigned  `json:"extra_permits_domains"`         // list of extra permissions(other than 'RoleDomains') for namespaces on local cluster. only for Rancher SSO
	RemoteRolePermits   *CLUSRemoteRolePermits `json:"remote_role_permits,omitempty"` // role/permissions on managed clusters in fed. only for Rancher SSO
	LastLoginAt         time.Time              `json:"last_login_at"`
	LoginCount          uint32                 `json:"login_count"`
	FailedLoginCount    uint32                 `json:"failed_login_count"` // failed consecutive login failure. reset to 0 after a successful login
	BlockLoginSince     time.Time              `json:"block_login_since"`  // reset to 0 after a successful login
	AcceptedAlerts      []string               `json:"accepted_alerts,omitempty"`
	ResetPwdInNextLogin bool                   `json:"reset_password_in_next_login"`
	UseBootstrapPwd     bool                   `json:"use_bootstrap_password"`
}

type GroupRoleMapping struct {
	Group       string              `json:"group"`                  // mapped group
	GlobalRole  string              `json:"global_role"`            // group's mapped role on global domain
	RoleDomains map[string][]string `json:"role_domains,omitempty"` // group's mapped role -> domains
}

type CLUSServerAuth struct {
	DefaultRole      string              `json:"default_role"`
	RoleGroups       map[string][]string `json:"groups"`             // role -> groups. obsolete since 4.2
	GroupMappedRoles []*GroupRoleMapping `json:"group_mapped_roles"` // group -> (role -> domains). supported since 4.2
}

type CLUSServerLDAP struct {
	CLUSServerAuth
	Type            string `json:"type"`
	Hostname        string `json:"hostname"`
	Port            uint16 `json:"port"`
	SSL             bool   `json:"ssl"`
	BaseDN          string `json:"base_dn"`
	GroupDN         string `json:"group_dn"`
	BindDN          string `json:"bind_dn"` // Must handle upgrade if it is cloaked
	BindPasswd      string `json:"bind_password,cloak"`
	GroupMemberAttr string `json:"group_member_attr"`
	UserNameAttr    string `json:"username_attr"`
}

type CLUSServerSAML struct {
	CLUSServerAuth
	SSOURL              string   `json:"sso_url"`
	Issuer              string   `json:"issuer"`
	X509Cert            string   `json:"x509_cert,cloak"`
	GroupClaim          string   `json:"group_claim"`
	X509CertExtra       []string `json:"x509_cert_extra"`
	AuthnSigningEnabled bool     `json:"authn_signing_enabled,omitempty"`
	SigningCert         string   `json:"signing_cert,cloak,omitempty"`
	SigningKey          string   `json:"signing_key,cloak,omitempty"`
	SLOEnabled          bool     `json:"slo_enabled,omitempty"`
	SLOURL              string   `json:"slo_url,omitempty"`
}

type CLUSServerOIDC struct {
	CLUSServerAuth
	Issuer       string   `json:"issuer"`
	AuthURL      string   `json:"authorization_endpoint"`
	TokenURL     string   `json:"token_endpoint"`
	UserInfoURL  string   `json:"user_info_endpoint"`
	JWKSURL      string   `json:"jwks_endpoint"`
	ClientID     string   `json:"client_id"` // Must handle upgrade if it is cloaked
	ClientSecret string   `json:"client_secret,cloak"`
	Scopes       []string `json:"scopes"`
	GroupClaim   string   `json:"group_claim"`
	UseProxy     bool     `json:"use_proxy"`
}

type CLUSServer struct {
	Name   string          `json:"name"`
	Enable bool            `json:"enable"`
	LDAP   *CLUSServerLDAP `json:"ldap,omitempty"`
	SAML   *CLUSServerSAML `json:"saml,omitempty"`
	OIDC   *CLUSServerOIDC `json:"oidc,omitempty"`
}

const (
	// host: address is meaningful only on local host. Native container IP has this scope.
	CLUSIPAddrScopeLocalhost = "host"
	// global: address is global
	CLUSIPAddrScopeGlobal = "global"
	// nat: address for NAT access. Typically, this the address of the host.
	CLUSIPAddrScopeNAT = "nat"
)

type CLUSIPAddr struct {
	IPNet       net.IPNet `json:"ipnet"`
	Gateway     string    `json:"gateway"`
	Scope       string    `json:"scope"`
	NetworkID   string    `json:"net_id"`
	NetworkName string    `json:"net_name"`
}

type CLUSHost struct {
	ID             string                  `json:"id"`
	Name           string                  `json:"name"`
	Runtime        string                  `json:"runtime"`
	Platform       string                  `json:"platform"`
	Flavor         string                  `json:"flavor"`         // platform flavor
	CloudPlatform  string                  `json:"cloud_platform"` // cloud_platform
	Network        string                  `json:"network"`
	RuntimeVer     string                  `json:"runtime_version"`
	RuntimeAPIVer  string                  `json:"runtime_api_version"`
	OS             string                  `json:"os"`
	Kernel         string                  `json:"kernel"`
	CPUs           int64                   `json:"cpus"`
	Memory         int64                   `json:"memory"`
	Ifaces         map[string][]CLUSIPAddr `json:"interfaces"`
	TunnelIP       []net.IPNet             `json:"tunnel_ips"`
	CapDockerBench bool                    `json:"cap_docker_bench"`
	CapKubeBench   bool                    `json:"cap_kube_bench"`
	StorageDriver  string                  `json:"storage_driver"`
	CgroupVersion  int                     `json:"cgroup_version"`
}

type CLUSDevice struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	SelfHostname  string                  `json:"self_hostname"`
	HostName      string                  `json:"host_name"`
	HostID        string                  `json:"host_id"`
	Domain        string                  `json:"domain"`
	NetworkMode   string                  `json:"network_mode"`
	PidMode       string                  `json:"pid_mode"`
	Ver           string                  `json:"version"`
	Labels        map[string]string       `json:"labels"`
	CreatedAt     time.Time               `json:"created_at"`
	StartedAt     time.Time               `json:"started_at"`
	JoinedAt      time.Time               `json:"joined_at"`
	MemoryLimit   int64                   `json:"memory_limit"`
	CPUs          string                  `json:"cpus"`
	ClusterIP     string                  `json:"cluster_ip"`
	RPCServerPort uint16                  `json:"rpc_server_port"`
	Pid           int                     `json:"pid"`
	Ifaces        map[string][]CLUSIPAddr `json:"interfaces"`
}

type CLUSAgent struct {
	CLUSDevice
}

type CLUSController struct {
	CLUSDevice
	Leader            bool   `json:"leader"`
	OrchConnStatus    string `json:"orch_conn_status"`
	OrchConnLastError string `json:"orch_conn_last_error"`
	ReadPrimeConfig   bool   `json:"read_prime_config"`
}

type CLUSProtoPort struct {
	IPProto uint8  `json:"ip_proto"`
	Port    uint16 `json:"port"`
}

type CLUSIPPort struct {
	IPNet net.IPNet `json:"ipnet"`
	Port  uint16    `json:"port"`
}

type CLUSMappedPort struct {
	CLUSProtoPort
	HostIP   net.IP `json:"host_ip"`
	HostPort uint16 `json:"host_port"`
}

type CLUSApp struct {
	CLUSProtoPort
	Proto       uint32 `json:"protocol"`
	Server      uint32 `json:"server"`
	Application uint32 `json:"application"`
}

const (
	NEPTypeLB = "netlb"
)

type CLUSNetworkEP struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	NetworkID string   `json:"net_id"`
	IP        []net.IP `json:"ip"`
}

type CLUSGroupMetric struct {
	GroupName      string                   `json:"group_name"`
	GroupSessCurIn uint32                   `json:"group_sess_cur_in"`
	GroupSessIn12  uint32                   `json:"group_sess_in12"`
	GroupByteIn12  uint64                   `json:"group_byte_in12"`
	WlMetric       map[string]*CLUSWlMetric `json:"wl_metric"`
}

type CLUSWlMetric struct {
	WlID        string `json:"wlid"`
	WlSessCurIn uint32 `json:"wl_sess_cur_in"`
	WlSessIn12  uint32 `json:"wl_sess_in12"`
	WlByteIn12  uint64 `json:"wl_byte_in12"`
}

type CLUSNetPolicyMetric struct {
	ID          uint32 `json:"id"`
	MatchCntr   uint64 `json:"match_cntr"`
	LastMatchAt uint32 `json:"last_match_at"`
}

type CLUSWorkload struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	AgentID      string                    `json:"agent_id"`
	SelfHostname string                    `json:"self_hostname"`
	HostName     string                    `json:"host_name"`
	HostID       string                    `json:"host_id"`
	Image        string                    `json:"image"`
	ImageID      string                    `json:"image_id"`
	ImgCreateAt  time.Time                 `json:"image_created_at"`
	Privileged   bool                      `json:"privileged"`
	RunAsRoot    bool                      `json:"run_as_root"`
	NetworkMode  string                    `json:"network_mode"`
	ShareNetNS   string                    `json:"share_netns"`
	Service      string                    `json:"service"`
	Domain       string                    `json:"domain"`
	Author       string                    `json:"author"`
	PlatformRole string                    `json:"platform_role"`
	CreatedAt    time.Time                 `json:"created_at"`
	StartedAt    time.Time                 `json:"started_at"`
	FinishedAt   time.Time                 `json:"finished_at"`
	Running      bool                      `json:"running"`
	CapIntcp     bool                      `json:"cap_intcp"`
	CapSniff     bool                      `json:"cap_sniff"`
	HasDatapath  bool                      `json:"has_datapath"`
	Inline       bool                      `json:"inline"`
	Quarantine   bool                      `json:"quarantine"`
	SecuredAt    time.Time                 `json:"secured_at"`
	ExitCode     int                       `json:"exit_code"`
	Pid          int                       `json:"pid"`
	Ifaces       map[string][]CLUSIPAddr   `json:"interfaces"`
	Ports        map[string]CLUSMappedPort `json:"ports"`
	Labels       map[string]string         `json:"labels"`
	Apps         map[string]CLUSApp        `json:"apps"`
	MemoryLimit  int64                     `json:"memory_limit"`
	CPUs         string                    `json:"cpus"`
	ProxyMesh    bool                      `json:"proxymesh"`
	Sidecar      bool                      `json:"sidecar"`
}

type CLUSDomain struct {
	Name    string            `json:"name"`
	Dummy   bool              `json:"dummy"`
	Disable bool              `json:"disable"`
	Tags    []string          `json:"tags"`   // compliance tags
	Labels  map[string]string `json:"labels"` // from k8s
}

type CLUSCriteriaEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Op    string `json:"op"`
}

type CLUSFqdnIp struct {
	FqdnName string   `json:"fqdn_name"`
	FqdnIP   []net.IP `json:"fqdn_ip"`
	Vhost    bool     `json:"vhost,omitempty"`
}

type TCfgType int

const (
	Learned = iota + 1
	UserCreated
	GroundCfg
	FederalCfg
	SystemDefined
)

type CLUSGroup struct {
	Name            string              `json:"name"`
	Comment         string              `json:"comment"`
	Learned_UNUSED  bool                `json:"learned"`
	Reserved        bool                `json:"reserved"`
	Criteria        []CLUSCriteriaEntry `json:"criteria"`
	Domain          string              `json:"domain"`
	CreaterDomains  []string            `json:"creater_domains"`
	PolicyMode      string              `json:"policy_mode,omitempty"`
	ProfileMode     string              `json:"profile_mode,omitempty"`
	NotScored       bool                `json:"not_scored,omitempty"`
	Kind            string              `json:"kind,omitempty"`
	PlatformRole    string              `json:"platform_role"`
	CapIntcp        bool                `json:"cap_intcp"`
	CfgType         TCfgType            `json:"cfg_type"`
	BaselineProfile string              `json:"baseline_profile"`
	MonMetric       bool                `json:"monitor_metric,omitempty"`
	GrpSessCur      uint32              `json:"group_sess_cur,omitempty"`
	GrpSessRate     uint32              `json:"group_sess_rate,omitempty"`
	GrpBandWidth    uint32              `json:"group_band_width,omitempty"`
}

type CLUSPolicyRule struct {
	ID             uint32    `json:"id"`
	Comment        string    `json:"comment"`
	From           string    `json:"from"` // group name
	To             string    `json:"to"`   // group name
	FromHost       string    `json:"from_host"`
	ToHost         string    `json:"to_host"`
	Ports          string    `json:"ports"` // free-style port list
	Applications   []uint32  `json:"applications"`
	Action         string    `json:"action"`
	Learned_UNUSED bool      `json:"learned"`
	Disable        bool      `json:"Disable"`
	CreatedAt      time.Time `json:"created_at"`
	LastModAt      time.Time `json:"last_modified_at"`
	CfgType        TCfgType  `json:"cfg_type"`
	Priority       uint32    `json:"priority"`
	MatchCntr      uint64    `json:"match_cntr"`
	LastMatchAt    time.Time `json:"last_match_at"`
}

type CLUSRuleHead struct {
	ID             uint32   `json:"id"`
	Priority       uint32   `json:"priority"`
	Learned_UNUSED bool     `json:"learned"`
	CfgType        TCfgType `json:"cfg_type"`
}

const (
	WireInline  string = "inline"
	WireDefault string = "default"
)

// QuarantineReason:
const QuarantineReasonUser string = "user-configured"

func QuarantineReasonEvent(event string, id uint32) string {
	return fmt.Sprintf("%s (rule %d)", event, id)
}

type CLUSWorkloadConfig struct {
	Wire       string `json:"wire,omitempty"`
	Quarantine bool   `json:"quarantine,omitempty"`
	QuarReason string `json:"quarantine_reason,omitempty"`
}

type CLUSAgentConfig struct {
	Debug                []string `json:"debug,omitempty"`
	DisableNvProtectMode bool     `json:"disable_nvprotect"`
	DisableKvCongestCtl  bool     `json:"disable_kvcctl"`
	LogLevel             string   `json:"log_level,omitempty"`
}

type CLUSControllerConfig struct {
	Debug    []string `json:"debug,omitempty"`
	LogLevel string   `json:"log_level,omitempty"`
}

type CLUSVolume struct {
	Bytes    uint64 `json:"bytes"`
	Sessions uint32 `json:"sessions"`
}

var CLUSIPExternal net.IP = net.IPv4zero
var CLUSWLExternal string = "nv.external"
var CLUSWLAddress string = "nv.address"
var CLUSWLService string = "nv.service"
var CLUSWLModeGroup string = "nv.mode_group"
var CLUSWLAddressGroup string = "nv.address_group"
var CLUSHostAddrGroup string = "nv.hostaddr_group" //used as wlid for "nodes" in policy calculation
var CLUSWLFqdnPrefix string = "fqdn:"
var CLUSWLFqdnVhPrefix string = "vh:"
var CLUSLearnedHostPrefix string = "Host:"
var CLUSLearnedWorkloadPrefix string = "Workload:"
var CLUSEndpointIngress string = "ingress"
var CLUSWLAllContainer string = "nv.allcontainer"
var CLUSPlatformContainerCore string = "core"

const DefaultGroupRuleID uint32 = 0
const PolicyLearnedIDBase = 10000
const PolicyFedRuleIDBase = 100000
const PolicyFedRuleIDMax = 110000 // exclusive
const PolicyGroundRuleIDBase = 110000
const PolicyGroundRuleIDMax = 120000

// Special internal subnet IP
const (
	SpecInternalTunnelIP = "tunnelip"
	SpecInternalSvcIP    = "svcip"
	SpecInternalHostIP   = "hostip"
	SpecInternalDevIP    = "devip"
	SpecInternalUwlIP    = "uwlip"
	SpecInternalExtIP    = "extip"
)

type CLUSPortApp struct {
	Ports       string `json:"port"`
	Application uint32 `json:"application"`
	CheckApp    bool   `json:"check_app"`
}

type CLUSWorkloadAddr struct {
	WlID         string                    `json:"workload_id"`
	PolicyMode   string                    `json:"mode,omitempty"`
	Domain       string                    `json:"domain,omitempty"`
	PlatformRole string                    `json:"platform_role,omitempty"`
	LocalIP      []net.IP                  `json:"local_ip,omitempty"`
	GlobalIP     []net.IP                  `json:"global_ip,omitempty"`
	NatIP        []net.IP                  `json:"nat_ip,omitempty"`
	LocalPortApp []CLUSPortApp             `json:"local_port_app,omitempty"`
	NatPortApp   []CLUSPortApp             `json:"nat_port_app,omitempty"`
	Ports        map[string]CLUSMappedPort `json:"ports,omitempty"`
	Apps         map[string]CLUSApp        `json:"apps,omitempty"`
}

type CLUSGroupIPPolicy struct {
	ID     uint32              `json:"policy_id"`
	From   []*CLUSWorkloadAddr `json:"from_addr"`
	To     []*CLUSWorkloadAddr `json:"to_addr,omitempty"`
	Action uint8               `json:"action"`
}

type CLUSGroupIPPolicyVer struct {
	Key                  string `json:"key"`
	PolicyIPRulesVersion string `json:"pol_version"`
	NodeId               string `json:"node_id"`
	CommonSlotNo         int    `json:"common_slot_no"`
	CommonRulesLen       int    `json:"common_rules_len"`
	SlotNo               int    `json:"slot_no"`
	RulesLen             int    `json:"rules_len"`
	WorkloadSlot         int    `json:"workload_slot,omitempty"`
	WorkloadLen          int    `json:"workload_len,omitempty"`
}

type CLUSDlpRuleVer struct {
	Key             string `json:"key"`
	DlpRulesVersion string `json:"dlp_version"`
	SlotNo          int    `json:"slot_no"`
	RulesLen        int    `json:"rules_len"`
	WorkloadLen     int    `json:"workload_len"`
}

type CLUSSubnet struct {
	Subnet net.IPNet `json:"subnet"`
	Scope  string    `json:"scope"`
}

type CLUSSpecSubnet struct {
	Subnet net.IPNet `json:"subnet"`
	Scope  string    `json:"scope"`
	IpType string    `json:"iptype"`
}

type CLUSLogFilter struct {
	Tail int `json:"tail"`
}

// This value is stored in the cluster, so should not change the order
type TLogEvent uint
type TLogIncident uint
type TLogAudit uint

const (
	CLUSEvWorkloadStart TLogEvent = iota
	CLUSEvWorkloadStop
	CLUSEvWorkloadRemove
	CLUSEvWorkloadSecured
	CLUSEvWorkloadUnsecured_UNUSED
	CLUSEvAgentStart
	CLUSEvAgentStop
	CLUSEvAgentJoin
	CLUSEvAgentDisconnect
	CLUSEvAgentConnect
	CLUSEvAgentKicked
	CLUSEvControllerStart
	CLUSEvControllerStop
	CLUSEvControllerJoin
	CLUSEvControllerDisconnect
	CLUSEvControllerConnect
	CLUSEvAuthLogin
	CLUSEvAuthLogout
	CLUSEvAuthTimeout
	CLUSEvAuthLoginFailed
	CLUSEvRESTWrite
	CLUSEvRESTRead
	CLUSEvScannerJoin
	CLUSEvScannerUpdate
	CLUSEvScannerLeave
	CLUSEvScanFail
	CLUSEvScanSucceed
	CLUSEvBenchDockerFail
	CLUSEvBenchKubeFail
	CLUSEvLicenseUpdate
	CLUSEvLicenseExpire
	CLUSEvLicenseRemove
	CLUSEvLicenseEnforcerLimitReached
	CLUSEvHostPrivilEscalate_UNUSED
	CLUSEvHostSuspiciousProcess_UNUSED
	CLUSEvContainerPrivilEscalate_UNUSED
	CLUSEvContainerSuspiciousProcess_UNUSED
	CLUSEvWorkloadQuarantined
	CLUSEvWorkloadUnquarantined
	CLUSEvAuthAccessDenied
	CLUSEvAdmCtrlK8sConfigured   // for admission control
	CLUSEvAdmCtrlK8sConfigFailed // for admission control
	CLUSEvInitCfgMapDone         // for initial Config
	CLUSEvInitCfgMapError        // for initial Config
	CLUSEvCrdImported            // for crd Config import
	CLUSEvCrdRemoved             // for crd Config remove due to k8s miss
	CLUSEvCrdErrDetected         // for remove error crd
	CLUSEvFedPromote             // for multi-clusters
	CLUSEvFedDemote              // for multi-clusters
	CLUSEvFedJoin                // for multi-clusters
	CLUSEvFedLeave               // for multi-clusters
	CLUSEvFedKick                // for multi-clusters
	CLUSEvFedPolicySync          // for multi-clusters
	CLUSEvImport
	CLUSEvImportFail
	CLUSEvExport
	CLUSEvExportFail
	CLUSEvControllerLeadLost
	CLUSEvControllerLeadElect
	CLUSEvCloudScanRet
	CLUSEvCloudScanAlert
	CLUSEvCloudScanFail
	CLUSEvGroupAutoRemove
	CLUSEvLicenseStatusInvalid
	CLUSEvLicenseStatusRevoked
	CLUSEvLicenseValidationError
	CLUSEvLicenseUsageReportError
	CLUSEvLicenseUsageServerError
	CLUSEvAuthLoginBlocked        // temporarily block user login (too many consecutive login failures)
	CLUSEvAuthLoginUnblocked      // unblock user login
	CLUSEvAuthUserPwdResetByAdmin // user password reset not by the owner user
	CLUSEvMemoryPressureAgent
	CLUSEvMemoryPressureController
	CLUSEvK8sNvRBAC
	CLUSEvGroupAutoPromote
	CLUSEvAuthDefAdminPwdUnchanged   // default admin's password is not changed yet. reported every 24 hours
	CLUSEvScannerAutoScaleDisabled   // when scanner autoscale is disabled by controller
	CLUSEvCrdSkipped                 // for crd Config import
	CLUSEvK8sAdmissionWebhookCChange // for admission control
	CLUSEvGroupMetricViolation       //network metric violation per group level
	CLUSEvKvRestored                 // kv is restored from pvc
	CLUSEvScanDataRestored           // scan data is restored from pvc
)

const (
	CLUSIncidHostPrivilEscalate TLogIncident = iota
	CLUSIncidHostSuspiciousProcess
	CLUSIncidContainerPrivilEscalate
	CLUSIncidContainerSuspiciousProcess
	CLUSIncidHostFileAccessViolation
	CLUSIncidHostPackageUpdated
	CLUSIncidContainerFileAccessViolation
	CLUSIncidContainerPackageUpdated
	CLUSIncidHostTunnel
	CLUSIncidContainerTunnel
	CLUSIncidHostProcessViolation
	CLUSIncidContainerProcessViolation
)

const (
	CLUSAuditComplianceContainerBenchViolation TLogAudit = iota
	CLUSAuditComplianceHostBenchViolation
	CLUSAuditAdmCtrlK8sReqAllowed   // for admission control
	CLUSAuditAdmCtrlK8sReqViolation // for admission control
	CLUSAuditAdmCtrlK8sReqDenied    // for admission control
	CLUSAuditComplianceHostCustomCheckViolation
	CLUSAuditComplianceContainerCustomCheckViolation
	CLUSAuditAwsLambdaScanWarning
	CLUSAuditAwsLambdaScanNormal
	CLUSAuditComplianceImageBenchViolation
	CLUSAuditComplianceContainerFileBenchViolation
)

type CLUSEventLog struct {
	Event          TLogEvent                `json:"event"`
	HostID         string                   `json:"host_id"`
	HostName       string                   `json:"host_name"`
	ControllerID   string                   `json:"controller_id"`
	ControllerName string                   `json:"controller_name"`
	AgentID        string                   `json:"agent_id"`
	AgentName      string                   `json:"agent_name"`
	WorkloadID     string                   `json:"workload_id"`
	WorkloadName   string                   `json:"workload_name"`
	ReportedAt     time.Time                `json:"reported_at"`
	User           string                   `json:"user"`
	UserRoles      map[string]string        `json:"user_roles"`       // domain -> role
	UserPermits    map[string]NvPermissions `json:"user_permissions"` // domain -> permissions
	UserAddr       string                   `json:"user_addr"`
	UserSession    string                   `json:"user_session"`
	RESTMethod     string                   `json:"rest_method,omitempty"`
	RESTRequest    string                   `json:"rest_request,omitempty"`
	RESTBody       string                   `json:"rest_body,omitempty"`
	EnforcerLimit  int                      `json:"enforcer_limit,omitempty"`
	LicenseExpire  time.Time                `json:"license_expire,omitempty"`
	GroupName      string                   `json:"group_name"`
	Msg            string                   `json:"message"`
}

type CLUSThreatLog struct {
	ID           string    `json:"id"`
	ThreatID     uint32    `json:"threat_id"`
	Severity     uint8     `json:"severity"`
	Action       uint8     `json:"action"`
	CapLen       uint16    `json:"cap_len"`
	Count        uint32    `json:"count"`
	HostID       string    `json:"host_id"`
	HostName     string    `json:"host_name"`
	AgentID      string    `json:"agent_id"`
	AgentName    string    `json:"agent_name"`
	WorkloadID   string    `json:"workload_id"`
	WorkloadName string    `json:"workload_name"`
	ReportedAt   time.Time `json:"reported_at"`
	SrcIP        net.IP    `json:"src_ip"`
	DstIP        net.IP    `json:"dst_ip"`
	EtherType    uint16    `json:"ether_type"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	IPProto      uint8     `json:"ip_proto"`
	ICMPCode     uint8     `json:"icmp_code"`
	ICMPType     uint8     `json:"icmp_type"`
	LocalPeer    bool      `json:"local_peer"` // Local host connection
	PktIngress   bool      `json:"pkt_ingress"`
	SessIngress  bool      `json:"sess_ingress"`
	Tap          bool      `json:"tap"`
	Application  uint32    `json:"application"`
	Msg          string    `json:"message"`
	Packet       string    `json:"packet"`
}

type CLUSIncidentLog struct {
	LogUID       string       `json:"log_uid"`
	ID           TLogIncident `json:"id"`
	HostID       string       `json:"host_id"`
	HostName     string       `json:"host_name"`
	AgentID      string       `json:"agent_id"`
	AgentName    string       `json:"agent_name"`
	WorkloadID   string       `json:"workload_id"`
	WorkloadName string       `json:"workload_name"`
	ReportedAt   time.Time    `json:"reported_at"`
	ProcName     string       `json:"process_name,omitempty"`
	ProcPath     string       `json:"process_path,omitempty"`
	ProcCmds     []string     `json:"process_cmd,omitempty"`
	ProcRealUID  int          `json:"proc_real_uid,omitempty"`
	ProcEffUID   int          `json:"proc_eff_uid,omitempty"`
	ProcRealUser string       `json:"proc_real_user,omitempty"`
	ProcEffUser  string       `json:"proc_eff_user,omitempty"`
	FilePath     string       `json:"file_path,omitempty"`
	Files        []string     `json:"file_name,omitempty"`
	LocalIP      net.IP       `json:"local_ip,omitempty"`
	RemoteIP     net.IP       `json:"remote_ip,omitempty"`
	EtherType    uint16       `json:"ether_type"`
	LocalPort    uint16       `json:"local_port,omitempty"`
	RemotePort   uint16       `json:"remote_port,omitempty"`
	IPProto      uint8        `json:"ip_proto,omitempty"`
	ConnIngress  bool         `json:"conn_ingress"`
	LocalPeer    bool         `json:"local_peer"`
	ProcPName    string       `json:"process_parent_name,omitempty"`
	ProcPPath    string       `json:"process_parent_path,omitempty"`
	Count        int          `json:"count,omitempty"`
	StartAt      time.Time    `json:"start_at,omitempty"`
	Action       string       `json:"action"`
	RuleID       string       `json:"rule_id"`
	Group        string       `json:"group"`
	Msg          string       `json:"message"`
}

type CLUSAuditBenchItem struct {
	Level     string `json:"level"`
	TestNum   string `json:"test_num"`
	Msg       string `json:"message"`
	Group     string `json:"group"`
	Profile   string `json:"profile"`
	Scored    bool   `json:"scored"`
	Automated bool   `json:"automated"`
}

type CLUSAuditLog struct {
	ID           TLogAudit            `json:"id"`
	HostID       string               `json:"host_id"`
	HostName     string               `json:"host_name"`
	AgentID      string               `json:"agent_id"`
	AgentName    string               `json:"agent_name"`
	WorkloadID   string               `json:"workload_id"`
	WorkloadName string               `json:"workload_name"`
	Count        uint32               `json:"count"`
	ReportedAt   time.Time            `json:"reported_at"`
	Items        []CLUSAuditBenchItem `json:"items"`
	Props        map[string]string    `json:"props"`
	Region       string               `json:"region,omitempty"`
	ProjectName  string               `json:"project_name,omitempty"`
}

const SnifferIdAgentField = 12

type TagDetail struct {
	ID              string `yaml:"id" json:"id"`
	Title           string `yaml:"title" json:"title"`
	Description     string `yaml:"description" json:"description"`
	CIS_Sub_Control string `yaml:"cis-sub-control"`
}

type TagDetails []TagDetail

type CLUSComplianceProfileEntry struct {
	TestNum string   `json:"test_num"`
	Tags    []string `json:"tags"`
}

type CLUSComplianceProfile struct {
	Name          string                                `json:"name"`
	DisableSystem bool                                  `json:"disable_system"`
	Entries       map[string]CLUSComplianceProfileEntry `json:"entries"`
	CfgType       TCfgType                              `json:"cfg_type"`
}

type CLUSVulnerabilityProfileEntry struct {
	ID         uint32   `json:"id"`
	Name       string   `json:"name"`
	NameFilter string   `json:"name_f"`
	Comment    string   `json:"comment"`
	Days       uint     `json:"days"` // Only used for 'recent' vuln entries
	Domains    []string `json:"domains"`
	Images     []string `json:"images"`
}

type CLUSVulnerabilityProfile struct {
	Name    string                           `json:"name"`
	Entries []*CLUSVulnerabilityProfileEntry `json:"entries"`
	CfgType TCfgType                         `json:"cfg_type"`
}

type CLUSBenchItem struct {
	Level       string   `json:"level"`
	TestNum     string   `json:"test_number"`
	Header      string   `json:"header"`
	Message     []string `json:"message"`
	Remediation string   `json:"remediation"`
	Scored      bool     `json:"scored"`
	Automated   bool     `json:"automated"`
	Profile     string   `json:"profile"`
	Group       string   `json:"group"`
}

type CLUSBenchState struct {
	RunAt time.Time `json:"run_at"`
}

type CLUSBenchReport struct {
	Status  BenchStatus      `json:"status"`
	RunAt   time.Time        `json:"run_at"`
	Version string           `json:"version"`
	Items   []*CLUSBenchItem `json:"items"`
}

type BenchType string
type BenchStatus int

const (
	BenchDockerHost      BenchType = "docker_host"
	BenchDockerContainer BenchType = "docker_container" // all containers report
	BenchKubeMaster      BenchType = "kube_master"
	BenchKubeWorker      BenchType = "kube_worker"
	BenchContainer       BenchType = "container" // per-container report
	BenchCustomHost      BenchType = "custom_host"
	BenchCustomContainer BenchType = "custom_container"
	BenchContainerSecret BenchType = "container_secret"
	BenchContainerSetID  BenchType = "container_setid"
)

const (
	BenchStatusIdle BenchStatus = iota
	BenchStatusScheduled
	BenchStatusRunning
	BenchStatusFinished
	BenchStatusNotSupport
	BenchStatusDockerHostFail
	BenchStatusDockerContainerFail
	BenchStatusKubeMasterFail
	BenchStatusKubeWorkerFail
	BenchStatusMax
)

const (
	BenchLevelPass   = "PASS"
	BenchLevelInfo   = "INFO"
	BenchLevelWarn   = "WARN"
	BenchLevelManual = "MANUAL"
	BenchLevelHigh   = "HIGH"
	BenchLevelNote   = "NOTE"
	BenchLevelError  = "ERROR"
	BenchProfileL1   = "Level 1"
	BenchProfileL2   = "Level 2"
)

const (
	CustomCheckControl_Disable = "disable"
	CustomCheckControl_Strict  = "strict"
	CustomCheckControl_Loose   = "loose"
)

const (
	LogLevel_Error = "error"
	LogLevel_Warn  = "warn"
	LogLevel_Info  = "info"
	LogLevel_Debug = "debug"
)

func CLUSGetLogLevel(logLevel string) log.Level {
	switch logLevel {
	case LogLevel_Error:
		return log.ErrorLevel
	case LogLevel_Warn:
		return log.WarnLevel
	case LogLevel_Info:
		return log.InfoLevel
	case LogLevel_Debug:
		return log.DebugLevel
	default:
		return log.InfoLevel
	}
}

type CLUSCustomCheck struct {
	Name   string `json:"name"`
	Script string `json:"script"`
}

type CLUSCustomCheckGroup struct {
	Scripts []*CLUSCustomCheck `json:"scripts"`
}

type CLUSEventCondition struct {
	CondType  string `json:"type,omitempty"`
	CondValue string `json:"value,omitempty"`
}

type CLUSResponseRule struct {
	ID         uint32               `json:"id"`
	Event      string               `json:"event"`
	Comment    string               `json:"comment,omitempty"`
	Group      string               `json:"group,omitempty"`
	Conditions []CLUSEventCondition `json:"conditions,omitempty"`
	Actions    []string             `json:"actions"`
	Webhooks   []string             `json:"webhooks"`
	Disable    bool                 `json:"disable,omitempty"`
	CfgType    TCfgType             `json:"cfg_type"`
}

func CLUSResponseRuleKey(policyName string, id uint32) string {
	return fmt.Sprintf("%s%s/rule/%v", CLUSConfigResponseRuleStore, policyName, id)
}

func CLUSResponseRuleListKey(name string) string {
	return fmt.Sprintf("%s%s/rules", CLUSConfigResponseRuleStore, name)
}

func CLUSProfileKey(group string) string {
	return fmt.Sprintf("%s%s", ProfileProcessStore, group)
}

func CLUSProfileConfigKey(group string) string {
	return fmt.Sprintf("%s%s", CLUSConfigProcessProfileStore, group)
}

type CLUSProcessProfileEntry struct {
	Name            string    `json:"name"`
	Path            string    `json:"path"`
	User            string    `json:"user"`
	Uid             int32     `json:"uid"`
	Hash            []byte    `json:"hash"`
	Action          string    `json:"action"`
	CfgType         TCfgType  `json:"cfg_type"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Uuid            string    `json:"uuid"`
	DerivedGroup    string    `json:"dgroup"`
	AllowFileUpdate bool      `json:"allow_update"`
	ProbeCmds       []string  `json:"probe_cmds"`
}

type CLUSProcessProfile struct {
	Group        string                     `json:"group"`
	AlertDisable bool                       `json:"alert_disabled"`
	HashEnable   bool                       `json:"hash_enabled"`
	Mode         string                     `json:"mode"`
	Baseline     string                     `json:"baseline"`
	Process      []*CLUSProcessProfileEntry `json:"process"`
	CfgType      TCfgType                   `json:"cfg_type"`
}

type CLUSRegistryFilter struct {
	Org  string `json:"organization"`
	Repo string `json:"repository"`
	Tag  string `json:"tag"`
}

type CLUSRegistryState struct {
	Status    string `json:"status"`
	ErrMsg    string `json:"error_message"`
	ErrDetail string `json:"error_detail"`
	StartedAt int64  `json:"started_at"`
}

type CLUSAWSAccountKey struct {
	ID              string `json:"id"`
	AccessKeyID     string `json:"access_key_id,cloak"`
	SecretAccessKey string `json:"secret_access_key,cloak"`
	Region          string `json:"region"`
}

type CLUSGCRKey struct {
	JsonKey string `json:"json_key,cloak"`
}

type CLUSRegistryConfig struct {
	Registry           string                `json:"registry"`
	Name               string                `json:"name"`
	Type               string                `json:"type"`
	Username           string                `json:"username"`
	Password           string                `json:"password,cloak"`
	AuthToken          string                `json:"auth_token,cloak"`
	AuthWithToken      bool                  `json:"auth_with_token"`
	Domains            []string              `json:"domains"`
	CreaterDomains     []string              `json:"creater_domains"`
	Filters            []string              `json:"filters"`
	ParsedFilters      []*CLUSRegistryFilter `json:"parsed_filters"`
	RescanImage        bool                  `json:"rescan_image"`
	ScanLayers         bool                  `json:"scan_layers"`
	DisableFiles       bool                  `json:"disable_files"`
	RepoLimit          int                   `json:"repo_limit"`
	TagLimit           int                   `json:"tag_limit"`
	Schedule           string                `json:"schedule"`
	PollPeriod         int                   `json:"poll_period"`
	AwsKey             *CLUSAWSAccountKey    `json:"aws_key"`
	GcrKey             *CLUSGCRKey           `json:"gcr_key"`
	JfrogMode          string                `json:"jfrog_mode"`
	JfrogAQL           bool                  `json:"jfrog_aql"`
	GitlabApiUrl       string                `json:"gitlab_api_url"`
	GitlabPrivateToken string                `json:"gitlab_private_token,cloak"`
	IBMCloudAccount    string                `json:"ibmcloud_account"`
	IBMCloudTokenURL   string                `json:"ibmcloud_token_url"`
	CfgType            TCfgType              `json:"cfg_type"`
	IgnoreProxy        bool                  `json:"ignore_proxy"`
}

type CLUSImage struct {
	Domain string `json:"domain"`
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	RegMod string `json:"reg_mod"`
}

// This flag can be used to force rescan with the new controller
const (
	ScanFlagCVE    = 0x01
	ScanFlagLayers = 0x02
	ScanFlagFiles  = 0x04
)

type CLUSRegistryImageSummary struct {
	ImageID           string        `json:"image_id"`
	Registry          string        `json:"registry"`
	RegName           string        `json:"reg_name"`
	Images            []CLUSImage   `json:"repo_tag"`
	Digest            string        `json:"digest"`
	ScannedAt         time.Time     `json:"scanned_at"`
	CreatedAt         time.Time     `json:"created_at"`
	BaseOS            string        `json:"base_os"`
	Version           string        `json:"version"`
	Result            ScanErrorCode `json:"result"`
	Status            string        `json:"status"`
	Author            string        `json:"author"`
	RunAsRoot         bool          `json:"run_as_root"`
	Signed            bool          `json:"signed"` // [2019.Apr] comment out until we can accurately tell it
	ScanFlags         uint32        `json:"scan_flags"`
	Provider          ScanProvider  `json:"provider"`
	Size              int64         `json:"size"`
	Verifiers         []string      `json:"verifiers"`
	SignatureDigest   string        `json:"signature_digest"`
	SigstoreTimestamp string        `json:"sigstore_timestamp"`
	SignatureResult   ScanErrorCode `json:"signature_result"`
	SignatureStatus   string        `json:"signature_status"`
}

type CLUSScanner struct {
	ID              string    `json:"id"`
	CVEDBVersion    string    `json:"db_version"`
	CVEDBCreateTime string    `json:"db_create_time"`
	JoinedAt        time.Time `json:"joined_at"`
	RPCServer       string    `json:"rpc_server"`
	RPCServerPort   uint16    `json:"rpc_port"`
	BuiltIn         bool      `json:"builtin"`
	CVEDBEntries    int       `json:"db_entries"`
}

type CLUSScannerStats struct {
	ID                string `json:"id"`
	TotalContainers   int    `json:"total_containers"`
	TotalHosts        int    `json:"total_hosts"`
	TotalImages       int    `json:"total_images"`
	TotalServerless   int    `json:"total_serverless"`
	ScannedContainers int    `json:"scanned_containers"`
	ScannedHosts      int    `json:"scanned_hosts"`
	ScannedImages     int    `json:"scanned_images"`
	ScannedServerless int    `json:"scanned_serverless"`
}

type CLUSScannerDB struct {
	CVEDBVersion    string                        `json:"db_version"`
	CVEDBCreateTime string                        `json:"db_create_time"`
	CVEDB           map[string]*ScanVulnerability `json:"db"`
}

type CLUSScannedVulInfo struct {
	PublishDate int64   `json:"publish_date"`
	WithFix     bool    `json:"with_fix"`
	Score       float32 `json:"score"`
}

type CLUSScannedVulInfoSimple struct {
	Score float32 `json:"score"`
}

// Admission control
const (
	AdmCtrlModeMonitor = "monitor"
	AdmCtrlModeProtect = "protect"

	AdmClientModeSvc = "service"
	AdmClientModeUrl = "url"

	AdmCtrlActionAllow = PolicyActionAllow
	AdmCtrlActionDeny  = PolicyActionDeny
)

type CLUSAdmissionCert struct {
	CN         string `json:"cn"`
	CaKeyPath  string `json:"ca_key_path"`
	CaKey      []byte `json:"ca_key"`
	CaCertPath string `json:"ca_cert_path"`
	CaCert     []byte `json:"ca_cert"`
	KeyPath    string `json:"key_path"`
	Key        []byte `json:"key"`
	CertPath   string `json:"cert_path"`
	Cert       []byte `json:"cert"`
}

type CLUSAdmissionCertCloaked struct { // a superset of CLUSAdmissionCert
	CN         string `json:"cn"`
	CaKeyPath  string `json:"ca_key_path"`       // obsolete, use const AdmCAKeyPath
	CaKey      []byte `json:"ca_key"`            // not written to kv
	CaCertPath string `json:"ca_cert_path"`      // obsolete, use const AdmCACertPath
	CaCert     []byte `json:"ca_cert"`           // not written to kv
	KeyPath    string `json:"key_path"`          // obsolete, calc at runtime like "neuvector-svc-admission-webhook.{ns}.svc.key.pem"
	Key        []byte `json:"key"`               // not written to kv
	CertPath   string `json:"cert_path"`         // obsolete, calc at runtime like "neuvector-svc-admission-webhook.{ns}.svc.cert.pem"
	Cert       []byte `json:"cert"`              // not written to kv
	CaKeyNew   string `json:"ca_key_new,cloak"`  // for v.3.0
	CaCertNew  string `json:"ca_cert_new,cloak"` // for v.3.0
	KeyNew     string `json:"key_new,cloak"`     // for v.3.0
	CertNew    string `json:"cert_new,cloak"`    // for v.3.0, cert for webhook server
	Cloaked    bool   `json:"cloaked"`
}

type CLUSX509Cert struct {
	CN            string        `json:"cn"`
	Key           string        `json:"key,cloak"`
	Cert          string        `json:"cert,cloak"`
	OldCert       *CLUSX509Cert `json:"oldcert,omitempty"`
	GeneratedTime string        `json:"generated_time,omitempty"`
	ExpiredTime   string        `json:"expired_time,omitempty"`
}

func (c *CLUSX509Cert) IsEmpty() bool {
	if c == nil || len(c.Key) == 0 || len(c.Cert) == 0 {
		return true
	}
	return false
}

type CLUSAdmCtrlState struct {
	Enable      bool   `json:"enable"`
	Uri         string `json:"uri"`           // for neuvector-validating-admission-webhook.neuvector.svc webhook
	NvStatusUri string `json:"nv_status_uri"` // for neuvector-validating-status-webhook.neuvector.svc webhook
}

// NvDeployStatus field is only for object/config/admission_control/default/state only
type CLUSAdmissionState struct {
	Enable         bool                         `json:"enable"`
	Mode           string                       `json:"mode"`
	DefaultAction  string                       `json:"default_action"`
	AdmClientMode  string                       `json:"adm_client_mode"`
	FailurePolicy  string                       `json:"failure_policy"`  // empty means "Ignore". it's only for neuvector-svc-admission-webhook
	TimeoutSeconds int32                        `json:"timeout_seconds"` // 0 means 30
	NvDeployStatus map[string]bool              `json:"nvDeployStatus"`  // key is NvDeploymentName/NvAdmSvcName/NvCrdSvcName. value being true means the k8s resource exists
	CtrlStates     map[string]*CLUSAdmCtrlState `json:"ctrl_states"`     // key is NvAdmValidateType
	CfgType        TCfgType                     `json:"cfg_type"`
}

type CLUSAdmissionStats struct { // see type RESTAdmissionStats
	K8sAllowedRequests       uint64 `json:"k8s_allowed_requests"`
	K8sDeniedRequests        uint64 `json:"k8s_denied_requests"`
	K8sErroneousRequests     uint64 `json:"k8s_erroneous_requests"`
	K8sIgnoredRequests       uint64 `json:"k8s_ignored_requests"`
	K8sProcessingRequests    int64  `json:"k8s_processing_requests"`
	JenkinsAllowedRequests   uint64 `json:"jenkins_allowed_requests"`   // obsolete
	JenkinsDeniedRequests    uint64 `json:"jenkins_denied_requests"`    // obsolete
	JenkinsErroneousRequests uint64 `json:"jenkins_erroneous_requests"` // obsolete
}

type CLUSAdmRuleCriterion struct { // see type RESTAdmRuleCriterion
	Name        string                  `json:"name"`
	Op          string                  `json:"op"`
	Value       string                  `json:"value"`
	ValueSlice  []string                `json:"value_slice"`
	SubCriteria []*CLUSAdmRuleCriterion `json:"sub_criteria,omitempty"`
	Type        string                  `json:"type,omitempty"`
	Kind        string                  `json:"template_kind,omitempty"`
	Path        string                  `json:"path,omitempty"`
	ValueType   string                  `json:"value_type,omitempty"`
}

type CLUSAdmissionRule struct { // see type RESTAdmissionRule
	ID                uint32                  `json:"id"`
	Category          string                  `json:"category"`
	Comment           string                  `json:"comment"`
	Criteria          []*CLUSAdmRuleCriterion `json:"criteria"`
	Disable           bool                    `json:"disable"`
	Critical          bool                    `json:"critical"`
	CfgType           TCfgType                `json:"cfg_type"`
	RuleType          string                  `json:"rule_type"` // "exception", "deny"
	UseAsRiskyRoleTag bool                    `json:"use_as_risky_role_tag"`
	RuleMode          string                  `json:"rule_mode"`  // "", "monitor", "protect"
	Containers        uint8                   `json:"containers"` // 0 for all containers, 1 for containers, 2 for initContainers, 4 for ephemeralContainers (OR of supported types)
}

type CLUSAdmissionRules struct {
	RuleMap   map[uint32]*CLUSAdmissionRule `json:"rule_map"` // key is rule ID
	RuleHeads []*CLUSRuleHead               `json:"rule_heads"`
}

const (
	CLUSAdmissionCfgCert     = "cert"
	CLUSAdmissionCfgState    = "state"
	CLUSAdmissionCfgRule     = "rule"
	CLUSAdmissionCfgRuleList = "rules"
	CLUSAdmissionStatistics  = "statistics"
)

const (
	AdmCtrlRuleContainersN          = 1 // for containers
	AdmCtrlRuleInitContainersN      = 2 // for init_containers
	AdmCtrlRuleEphemeralContainersN = 4 // for ephemeral_containers

	AdmCtrlRuleContainers          = "containers"
	AdmCtrlRuleInitContainers      = "init_containers"
	AdmCtrlRuleEphemeralContainers = "ephemeral_containers"
)

const (
	CLUSRootCAKey = "rootCA"
	CLUSJWTKey    = "neuvector-jwt-signing"
	CLUSTLSCert   = "neuvector"
)

func CLUSObjectCertKey(cn string) string {
	// ex: r object/cert/rootCA or object/cert/neuvector-svc-admission-webhook.neuvector.svc
	return fmt.Sprintf("%s%s", CLUSCertStore, cn)
}

func CLUSAdmissionCertKey(store, policyName string) string { // obsolete
	// ex: object/config/admission_control/cert
	return fmt.Sprintf("%s%s/%s", store, policyName, CLUSAdmissionCfgCert)
}

func CLUSAdmissionStateKey(store, policyName string) string {
	// ex: object/config/admission_control/default/state
	return fmt.Sprintf("%s%s/%s", store, policyName, CLUSAdmissionCfgState)
}

func CLUSAdmissionRuleKey(policyName, admType, ruleType string, id uint32) string {
	// ex: object/config/admission_control/default/rule/{admType}/{ruleType}/{id} - admType: [mutate|validate], ruleType: deny
	return fmt.Sprintf("%s%s/%s/%s/%s/%v", CLUSConfigAdmissionControlStore, policyName, CLUSAdmissionCfgRule, admType, ruleType, id)
}

func CLUSAdmissionRuleListKey(policyName, admType, ruleType string) string {
	// ex: object/config/admission_control/default/rules/{admType}/{ruleType} - admType: [mutate|validate], ruleType: deny
	return fmt.Sprintf("%s%s/%s/%s/%s", CLUSConfigAdmissionControlStore, policyName, CLUSAdmissionCfgRuleList, admType, ruleType)
}

func CLUSAdmissionStatsKey(policyName string) string {
	// ex: object/config/admission_control/default/statistics
	return fmt.Sprintf("%s%s/%s", CLUSConfigAdmissionControlStore, policyName, CLUSAdmissionStatistics)
}

func CLUSPolicyKey2AdmCfgPolicySubkey(key string, last bool) string {
	if last {
		tokens := strings.Split(key, "/")
		if len(tokens) != 4 {
			return ""
		}
		return tokens[3]
	} else {
		return CLUSKeyNthToken(key, 3)
	}
}

func CLUSPolicyKey2AdmCfgSubkey(key string) string {
	return CLUSKeyNthToken(key, 4)
}

func CLUSCrdKey(crdType, name string) string {
	return fmt.Sprintf("%s%s/%s", CLUSConfigCrdStore, crdType, name)
}

const (
	CLUSCrdContentCount = "crdcontent_count"
)

func CLUSCrdContentCountKey() string {
	return fmt.Sprintf("%sdefault/%s", CLUSConfigCrdStore, CLUSCrdContentCount)
}

func CLUSPolicyRuleKey2AdmRuleType(key, cfgType string) (string, string) {
	cfgSubKey := CLUSPolicyKey2AdmCfgSubkey(key)
	if cfgSubKey == cfgType {
		return CLUSKeyNthToken(key, 5), CLUSKeyNthToken(key, 6)
	} else {
		return "", ""
	}
}

type CLUSFileAccessFilterRule struct {
	Apps        []string  `json:"apps"`
	Behavior    string    `json:"behavior"`
	CustomerAdd bool      `json:"customer_add"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CLUSFileAccessRule struct {
	Group      string
	Filters    map[string]*CLUSFileAccessFilterRule `json:"filters"`
	FiltersCRD map[string]*CLUSFileAccessFilterRule `json:"filters_crd"`
}

type CLUSFileMonitorFilter struct {
	Filter       string `json:"filter"`
	Path         string `json:"path"`
	Regex        string `json:"regex"`
	Recursive    bool   `json:"recursive"`
	CustomerAdd  bool   `json:"customer_add"`
	Behavior     string `json:"behavior"`
	DerivedGroup string `json:"dgroup,omitempty"`
}

type CLUSFileMonitorProfile struct {
	Group      string
	Mode       string
	CfgType    TCfgType                `json:"cfg_type"`
	Filters    []CLUSFileMonitorFilter `json:"filters"`
	FiltersCRD []CLUSFileMonitorFilter `json:"filters_crd"`
}

type CLUSCrdProcessRule struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Action          string `json:"action"`
	AllowFileUpdate bool   `json:"allow_update"`
}

type CLUSCrdFileRule struct {
	Filter    string   `json:"filter"`
	Recursive bool     `json:"recursive"`
	Behavior  string   `json:"behavior"`
	App       []string `json:"app"`
}

type CLUSCrdProcessProfile struct {
	Baseline string `json:"baseline"` // "basic" & "zero-drift" for process profile. "default"/"shield" are obsolete and both mean "zero-drift"
}

type CLUSCrdVulnProfile struct {
	Name string `json:"name"`
}

type CLUSCrdCompProfile struct {
	Name string `json:"name"`
}

type CLUSCrdSecurityRule struct {
	Name            string                 `json:"name"` // crd record name in the format {crd kind}-{ns}-{metadata.name}
	MetadataName    string                 `json:"metadata_name"`
	Groups          []string               `json:"groups,omitempty"`
	Rules           map[string]uint32      `json:"rules,omitempty"`
	PolicyMode      string                 `json:"policy_mode,omitempty"`
	ProfileName     string                 `json:"profile_name,omitempty"`
	ProfileMode     string                 `json:"profile_mode,omitempty"`
	ProcessProfile  *CLUSCrdProcessProfile `json:"process_profile,omitempty"`
	ProcessRules    []CLUSCrdProcessRule   `json:"process_rules,omitempty"`
	FileRules       []CLUSCrdFileRule      `json:"file_rules,omitempty"`
	DlpGroupSensors []string               `json:"dlp_group_sensors,omitempty"` // dlp sensors associated with the target group
	WafGroupSensors []string               `json:"waf_group_sensors,omitempty"` // waf sensors associated with the target group
	AdmCtrlRules    map[string]uint32      `json:"admctrl_rules,omitempty"`     // map key is the generated name of admission control rule, valud is assigned rule id
	DlpSensor       string                 `json:"dlp_sensor,omitempty"`        // dlp sensor defined in this crd security rule
	WafSensor       string                 `json:"waf_sensor,omitempty"`        // waf sensor defined in this crd security rule
	VulnProfile     string                 `json:"vuln_profile,omitempty"`      // vulnerability profile defined in this crd security rule
	CompProfile     string                 `json:"comp_profile,omitempty"`      // compliance profile defined in this crd security rule
	Uid             string                 `json:"uid"`                         // metadata.uid in admissionreview CREATE request
	CrdMD5          string                 `json:"md5"`                         // md5 of k8s crd resource, for metadata, only include name/namespace
	UpdatedAt       time.Time              `json:"updated_at"`
}

// Multi-Clusters (Federation)
const (
	FedAdmCtrlExceptRulesType  = "fed_admctrl_exception"
	FedAdmCtrlDenyRulesType    = "fed_admctrl_deny"
	FedNetworkRulesType        = "fed_netwwork_rule"
	FedResponseRulesType       = "fed_response_rule"
	FedGroupType               = "fed_group"
	FedFileMonitorProfilesType = "fed_file_profile"
	FedProcessProfilesType     = "fed_process_profile"
	FedSystemConfigType        = "fed_system_config"
	FedDlpSensorGrpType        = "fed_dlp_sensor_grp"
	FedWafSensorGrpType        = "fed_waf_sensor_grp"
)

const (
	CriticalAdmCtrlExceptRulesType = "critical_allow"
	CrdAdmCtrlExceptRulesType      = "crd_allow"
	CrdAdmCtrlDenyRulesType        = "crd_deny"
)

const (
	DefaultComplianceProfileName    = "default"
	DefaultVulnerabilityProfileName = "default"
	DefaultPolicyName               = "default" // mapping of ScopeLocal
	FedPolicyName                   = "fed"     // mapping of ScopeFed
)

const (
	ScopeLocal = "local"
	ScopeFed   = "fed"
	ScopeAll   = ""
	ScopeError = "error"
)

const (
	StartPollFedMaster = iota + 1
	InstantPollFedMaster
	InstantPingFedJoints
	JointLoadOwnKeys
	MasterLoadJointKeys
	PurgeJointKeys
	MasterUnloadJointKeys
	StartPostToIBMSA
	StopPostToIBMSA
	PostToIBMSA
	RestartWebhookServer
	StartFedRestServer
	StopFedRestServer
	UpdateProxyInfo
	ReportTelemetryData
	ProcessCrdQueue
)

const (
	CLUSFedMembershipSubKey     = "membership"
	CLUSFedClustersListSubKey   = "clusters_list"
	CLUSFedClustersStatusSubKey = "clusters_status"
	CLUSFedClustersSubKey       = "clusters"
	CLUSFedRulesRevisionSubKey  = "rules_revision"
	CLUSFedToPingPollSubKey     = "ping_poll"
	CLUSFedSettingsSubKey       = "settings"
	CLUSFedScanDataRevSubKey    = "scan_revisions"
)

func CLUSEmptyFedRulesRevision() *CLUSFedRulesRevision {
	fedRev := &CLUSFedRulesRevision{
		Revisions: map[string]uint64{
			FedAdmCtrlExceptRulesType:  0,
			FedAdmCtrlDenyRulesType:    0,
			FedNetworkRulesType:        0,
			FedResponseRulesType:       0,
			FedGroupType:               0,
			FedFileMonitorProfilesType: 0,
			FedProcessProfilesType:     0,
			FedSystemConfigType:        0,
			FedDlpSensorGrpType:        0,
			FedWafSensorGrpType:        0,
		},
		LastUpdateTime: time.Now().UTC(),
	}

	return fedRev
}

func CLUSFedKey(name string) string {
	// ex: object/config/federation/{name}
	return fmt.Sprintf("%s%s", CLUSConfigFederationStore, name)
}

func CLUSFedJointClusterKey(id string) string {
	// ex: object/config/federation/clusters/{000-111-222}
	return fmt.Sprintf("%s%s/%s", CLUSConfigFederationStore, CLUSFedClustersSubKey, id)
}

func CLUSFedJointClusterStatusKey(id string) string {
	// ex: object/config/federation/clusters_status/{000-111-222}
	return fmt.Sprintf("%s%s/%s", CLUSConfigFederationStore, CLUSFedClustersStatusSubKey, id)
}

func CLUSFedKey2CfgKey(key string) string {
	return CLUSKeyNthToken(key, 3)
}

func CLUSFedKey2ClusterIdKey(key string) string {
	return CLUSKeyNthToken(key, 4)
}

type CLUSRestServerInfo struct { // provided by admin
	Server string `json:"server"`
	Port   uint   `json:"port"`
}

func (restInfo CLUSRestServerInfo) IsValid() bool {
	if restInfo.Server == "" || restInfo.Port == 0 {
		return false
	}
	return true
}

type CLUSFedMasterClusterInfo struct {
	Disabled bool               `json:"disabled"`
	Name     string             `json:"name"`
	ID       string             `json:"id"`
	Secret   string             `json:"secret,cloak"`   // used for encryoting/decrypting join_ticket issued by the master cluster
	CACert   string             `json:"ca_cert,cloak"`  // base64 encoded
	User     string             `json:"user,omitempty"` // the user who promotes this cluster to master cluster in federation
	RestInfo CLUSRestServerInfo `json:"rest_info"`
}

type CLUSFedJointClusterInfo struct {
	Disabled      bool               `json:"disabled"`
	Name          string             `json:"name"`
	ID            string             `json:"id"`
	Secret        string             `json:"secret,cloak"`           // generated by joint cluster befor joining federation
	ClientKey     string             `json:"client_key,cloak"`       // base64 encoded
	ClientCert    string             `json:"client_cert,cloak"`      // base64 encoded
	User          string             `json:"user,omitempty"`         // the user who joins this cluster to federation
	RestVersion   string             `json:"rest_version,omitempty"` // rest version in the code of joint cluster
	RestInfo      CLUSRestServerInfo `json:"rest_info"`
	ProxyRequired bool               `json:"proxy_required"` // a joint cluster may be reachable without proxy even master cluster is configured to use proxy. decided when it joins fed
}

type CLUSFedMembership struct { // stored on each cluster (master & joint cluster)
	FedRole          string                   `json:"fed_role"`                 // "", "master" or "joint"
	PingInterval     uint32                   `json:"ping_interval,omitempty"`  // in minute, for master cluster to ping joing clusters
	PollInterval     uint32                   `json:"poll_interval,omitempty"`  // in minute, for joint clusters to poll master cluster
	LocalRestInfo    CLUSRestServerInfo       `json:"local_rest_info"`          // meaningful when the role is ""
	MasterCluster    CLUSFedMasterClusterInfo `json:"master_cluster,omitempty"` // meaningful when the role is "master" or "joint"
	JointCluster     CLUSFedJointClusterInfo  `json:"joint_cluster,omitempty"`  // meaningful when the role is "joint"
	PendingDismiss   bool                     `json:"pending_dismiss"`          // set to true when the cluster is demoted/kicked & leaves fed. set to false when the fed rules cleanup is done
	PendingDismissAt time.Time                `json:"pending_dismiss_at"`
	UseProxy         string                   `json:"use_proxy"` // "" / https
}

// fed registry scan data is always deployed
type CLUSFedSettings struct { // stored on each cluster (master & joint cluster)
	DeployRepoScanData bool `json:"deploy_repo_scan_data"` // whether fed repo scan data(for _repo_scan on master cluster) deployment is enabled
}

type CLUSFedClusterStatus struct {
	Status              int       `json:"status"`                // status of a joint cluster
	SwitchToUnreachable int       `json:"switch_to_unreachable"` // counts of connected -> disconnected
	CspType             TCspType  `json:"csp_type"`
	Nodes               int       `json:"nodes"`               // total nodes count in this cluster
	LastConnectedTime   time.Time `json:"last_connected_time"` // only for master's connection status on joint cluster
}

type CLUSFedJoinedClusterList struct { // only available on master cluster
	IDs []string `json:"ids,omitempty"` // all non-master clusters' id in the federation
}

type TCspType int

const (
	CSP_NONE = iota
	CSP_EKS
	CSP_GCP
	CSP_AKS
	CSP_IBM
)

type CLUSClusterCspUsage struct {
	CspType TCspType `json:"csp_type"`
	Nodes   int      `json:"nodes"` // total nodes count in this cluster
}

// fed ruleTypes' revision data. stored under object/config/federation/rules_revision
type CLUSFedRulesRevision struct {
	Revisions      map[string]uint64 `json:"revisions"` // key is fed rules type, value is revision
	LastUpdateTime time.Time         `json:"last_update_time"`
}

type CLUSFedDoPingPoll struct {
	Cmd         uint32 `json:"cmd"`
	FullPolling uint32 `json:"full_polling"`
	Now         int64  `json:"now"`
}

type CLUSFedAdmCtrlRulesData struct {
	Revision uint64                         `json:"revision"`
	Rules    map[string]*CLUSAdmissionRules `json:"rules"` // key is fed rules type
}

type CLUSFedGroupsData struct {
	Revision uint64       `json:"revision"`
	Groups   []*CLUSGroup `json:"groups"`
}

type CLUSFedNetworkRulesData struct {
	Revision  uint64            `json:"revision"`
	Rules     []*CLUSPolicyRule `json:"rules"`
	RuleHeads []*CLUSRuleHead   `json:"rule_heads"`
}

type CLUSFedResponseRulesData struct {
	Revision  uint64                       `json:"revision"`
	Rules     map[uint32]*CLUSResponseRule `json:"rules"`
	RuleHeads []*CLUSRuleHead              `json:"rule_heads"`
}

type CLUSFedFileMonitorData struct {
	Revision    uint64                    `json:"revision"`
	Profiles    []*CLUSFileMonitorProfile `json:"profiles"`
	AccessRules []*CLUSFileAccessRule     `json:"access_rules"`
}

type CLUSFedProcessProfileData struct {
	Revision uint64                `json:"revision"`
	Profiles []*CLUSProcessProfile `json:"profiles"`
}

type CLUSFedSystemConfigData struct {
	Revision     uint64            `json:"revision"`
	SystemConfig *CLUSSystemConfig `json:"system_config"`
}

type CLUSFedRegistriesData struct {
	Revision   uint64                `json:"revision"`
	Registries []*CLUSRegistryConfig `json:"registries,omitempty"`
}

type CLUSFedScanRevisions struct {
	RegConfigRev   uint64            `json:"reg_config_rev"`   // fed registry revision
	ScannedRegRevs map[string]uint64 `json:"scanned_reg_revs"` // increases whenever the scan result of any image in a fed registry is changed (registry name : revision)
	ScannedRepoRev uint64            `json:"scanned_repo_rev"` // increases whenever there is any change in master cluster's repo scan data
	Restoring      bool              `json:"restoring"`        // fed registry revision
	RestoreAt      time.Time         `json:"restore_at"`
}

type CLUSFedDlpGroupSensorData struct {
	Revision   uint64           `json:"revision"`
	DlpSensors []*CLUSDlpSensor `json:"dlp_sensors"`
	DlpGroups  []*CLUSDlpGroup  `json:"dlp_groups"`
}

type CLUSFedWafGroupSensorData struct {
	Revision   uint64           `json:"revision"`
	WafSensors []*CLUSWafSensor `json:"waf_sensors"`
	WafGroups  []*CLUSWafGroup  `json:"waf_groups"`
}

// dlp rule
const (
	DlpRuleKeyPattern string = "pattern"
)

const (
	DlpPatternContextURI     string = "url"
	DlpPatternContextHEAD    string = "header"
	DlpPatternContextBODY    string = "body"
	DlpPatternContextPACKET  string = "packet"
	DlpPatternContextDefault string = "body"
)

const (
	CLUSDlpDefaultSensor    = "sensor.dlpdfltnv"
	CLUSFedDlpDefaultSensor = "fed.sensor.dlpdfltnv"
	CLUSFedDlpDefSyncSensor = "fed.sensor.dlpdfltsyncnv"
	CLUSDlpSsnSensor        = "sensor.ssn"
	CLUSDlpCcSensor         = "sensor.creditcard"
	CLUSFedDlpSsnSensor     = "fed.sensor.ssn"
	CLUSFedDlpCcSensor      = "fed.sensor.creditcard"
	CLUSWafDefaultSensor    = "sensor.wafdfltnv"
	CLUSWafLog4shSensor     = "sensor.log4shell"
	CLUSWafSpr4shSensor     = "sensor.spring4shell"
	CLUSWafDefaultFedSensor = "fed.sensor.wafdfltnv"
	CLUSFedWafDefSyncSensor = "fed.sensor.wafdfltsyncnv"
	CLUSWafFedLog4shSensor  = "fed.sensor.log4shell"
	CLUSWafFedSpr4shSensor  = "fed.sensor.spring4shell"
)

const (
	DlpRuleNameCreditCard    string = "rule.creditcard"
	DlpRuleNameCcAxp         string = "rule.americanexpress"
	DlpFedRuleNameCcAxp      string = "fed.rule.americanexpress"
	DlpRuleNameCcMaster      string = "rule.master"
	DlpFedRuleNameCcMaster   string = "fed.rule.master"
	DlpRuleNameCcDiscover    string = "rule.discover"
	DlpFedRuleNameCcDiscover string = "fed.rule.discover"
	DlpRuleNameCcVisa        string = "rule.visa"
	DlpFedRuleNameCcVisa     string = "fed.rule.visa"
	DlpRuleNameCcDinerV1     string = "rule.diner1"
	DlpFedRuleNameCcDinerV1  string = "fed.rule.diner1"
	DlpRuleNameCcDinerV2     string = "rule.diner2"
	DlpFedRuleNameCcDinerV2  string = "fed.rule.diner2"
	DlpRuleNameCcJcb         string = "rule.jcb"
	DlpFedRuleNameCcJcb      string = "fed.rule.jcb"
	DlpRuleNameSsn           string = "rule.ssn"
	DlpFedRuleNameSsn        string = "fed.rule.ssn"
	WafRuleNameLog4sh        string = "rule.log4shell"
	WafRuleNameSpr4sh        string = "rule.spring4shell"
)

const (
	DlpWlRuleIn  = "inside"
	DlpWlRuleOut = "outside"
	WafWlRuleIn  = "wafinside"
	WafWlRuleOut = "wafoutside"
)

func CLUSDlpRuleKey(sensor string) string {
	return fmt.Sprintf("%s%s", DlpRuleStore, sensor)
}

func CLUSDlpWorkloadRulesKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSNetworkStore, name)
}

func CLUSDlpRuleConfigKey(sensor string) string {
	return fmt.Sprintf("%s%s", CLUSConfigDlpRuleStore, sensor)
}

func CLUSDlpGroupConfigKey(group string) string {
	return fmt.Sprintf("%s%s", CLUSConfigDlpGroupStore, group)
}

func CLUSWafRuleKey(sensor string) string {
	return fmt.Sprintf("%s%s", WafRuleStore, sensor)
}

func CLUSWafRuleConfigKey(sensor string) string {
	return fmt.Sprintf("%s%s", CLUSConfigWafRuleStore, sensor)
}

func CLUSWafGroupConfigKey(group string) string {
	return fmt.Sprintf("%s%s", CLUSConfigWafGroupStore, group)
}

func CLUSCrdQueueKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSCrdProcStore, name)
}

type CLUSDlpCriteriaEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Op      string `json:"op"`
	Context string `json:"context,omitempty"`
}

type CLUSDlpRule struct {
	Name     string                 `json:"name"`
	ID       uint32                 `json:"id"`
	Patterns []CLUSDlpCriteriaEntry `json:"patterns"`
	CfgType  TCfgType               `json:"cfg_type"`
}

type CLUSDlpSensor struct {
	Name          string                    `json:"name"`
	Groups        map[string]string         `json:"groups,omitempty"` //group to action mapping,
	RuleListNames map[string]string         `json:"rule_list_names,omitempty"`
	RuleList      map[string]*CLUSDlpRule   `json:"rule_list,omitempty"`
	PreRuleList   map[string][]*CLUSDlpRule `json:"pre_rule_list,omitempty"`
	Comment       string                    `json:"comment,omitempty"`
	Predefine     bool                      `json:"predefine,omitempty"`
	CfgType       TCfgType                  `json:"cfg_type"`
}

type CLUSDlpSetting struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type CLUSDlpWorkloadRule struct {
	WorkloadId    string            `json:"workload_id"`
	PolicyMode    string            `json:"mode,omitempty"`
	RuleListNames []*CLUSDlpSetting `json:"rule_list_names"`
	RuleIds       []uint32          `json:"rule_ids"`
	RuleType      string            `json:"ruletype"`
}

type CLUSWorkloadDlpRules struct {
	DlpRuleList []*CLUSDlpRule         `json:"dlp_rule_list"`
	DlpWlRules  []*CLUSDlpWorkloadRule `json:"dlp_wl_rules"`
}

type CLUSDlpGroup struct {
	Name    string            `json:"name"`
	Status  bool              `json:"status"`
	Sensors []*CLUSDlpSetting `json:"sensors"`
	CfgType TCfgType          `json:"cfg_type"`
}

// waf
type CLUSWafCriteriaEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Op      string `json:"op"`
	Context string `json:"context,omitempty"`
}

type CLUSWafRule struct {
	Name     string                 `json:"name"` // internal waf rule name
	ID       uint32                 `json:"id"`
	Patterns []CLUSWafCriteriaEntry `json:"patterns"`
	CfgType  TCfgType               `json:"cfg_type"`
}

type CLUSWafSensor struct {
	Name          string                    `json:"name"`
	Groups        map[string]string         `json:"groups,omitempty"`          // group to action mapping, only for memory cache. it's always empty in kv
	RuleListNames map[string]string         `json:"rule_list_names,omitempty"` // key, value: internal waf rule name; for non-default sensors
	RuleList      map[string]*CLUSWafRule   `json:"rule_list,omitempty"`       // key: internal waf rule name; for default sensor only
	PreRuleList   map[string][]*CLUSWafRule `json:"pre_rule_list,omitempty"`
	Comment       string                    `json:"comment,omitempty"`
	Predefine     bool                      `json:"predefine,omitempty"`
	CfgType       TCfgType                  `json:"cfg_type"`
}

type CLUSWafSetting struct {
	Name   string `json:"name"` // unique sensor name
	Action string `json:"action"`
}

type CLUSWafWorkloadRule struct {
	WorkloadId    string            `json:"workload_id"`
	PolicyMode    string            `json:"mode,omitempty"`
	RuleListNames []*CLUSWafSetting `json:"rule_list_names"`
	RuleIds       []uint32          `json:"rule_ids"`
	RuleType      string            `json:"ruletype"`
}

type CLUSWorkloadWafRules struct {
	WafRuleList []*CLUSWafRule         `json:"waf_rule_list"`
	WafWlRules  []*CLUSWafWorkloadRule `json:"waf_wl_rules"`
}

type CLUSWafGroup struct {
	Name    string            `json:"name"`
	Status  bool              `json:"status"`
	Sensors []*CLUSWafSetting `json:"sensors"`
	CfgType TCfgType          `json:"cfg_type"`
}

type CLUSCrdRecord struct {
	CrdRecord *admissionv1beta1.AdmissionReview
}

type CLUSCrdEventRecord struct {
	CrdEventRecord []string
}

type CLUSCrdEventQueueInfo struct {
	Count int `json:"count"`
}

// //// Process UUID Rules
//
//	Reserved(256 entries): 	00000000-0000-0000-0000-0000000000XX
//	Default rules:			00000000-0000-0000-0000-00000000000X
//	Linux-specific:  		00000000-0000-0000-0000-00000000001X ans 2X
//	Windows-specific:  		00000000-0000-0000-0000-00000000003X ans 4X
const CLUSReservedUuidPrefix string = "00000000-0000-0000-0000-0000000000" // reserved the last 2 digits

// ////
const CLUSReservedUuidNotAlllowed string = "00000000-0000-0000-0000-000000000000"       // processes beyond white list
const CLUSReservedUuidRiskyApp string = "00000000-0000-0000-0000-000000000001"          // riskApp
const CLUSReservedUuidTunnelProc string = "00000000-0000-0000-0000-000000000002"        // tunnel
const CLUSReservedUuidRootEscalation string = "00000000-0000-0000-0000-000000000003"    // root privilege escallation
const CLUSReservedUuidDockerCp string = "00000000-0000-0000-0000-000000000004"          // docker cp
const CLUSReservedUuidAnchorMode string = "00000000-0000-0000-0000-000000000005"        // rejected by anchor mode
const CLUSReservedUuidShieldMode string = "00000000-0000-0000-0000-000000000006"        // rejected by non-family process
const CLUSReservedUuidShieldNotListMode string = "00000000-0000-0000-0000-000000000007" // rejected by Monitor mode for not-listed family process

type ProcRule struct {
	Active int                     `json:"active"`
	Group  string                  `json:"group"`
	Rule   CLUSProcessProfileEntry `json:"rule"`
}

type ProcRuleMap struct {
	RuleMap map[string]*ProcRule `json:"rulemap"`
}

type CLUSAwsFuncPermission struct {
	AttachedPolicy bool     `json:"aws_attached_policy"`
	AllowedDetail  []string `json:"allowed_detail"`
}

type CLUSAwsFuncScanOutput struct {
	AllowedRes map[string]CLUSAwsFuncPermission `json:"allowd_res"` // key: policyName  value: list of resource
	ReqRes     map[string][]string              `json:"req_res"`    // key: policyName  value: list of resource
	ScanState  string                           `json:"scan_state"`
	ScanError  string                           `json:"scan_error"`
	ScanResult CLUSScanReport                   `json:"scan_result"`
	Arn        string                           `json:"arn"`
	NvSecID    string                           `json:"nvsecid"`
	Version    string                           `json:"version"`
}

const MaxLambdaHistory = 3

type CLUSAwsFuncScanOutputList struct {
	AwsLambdaRecord [MaxLambdaHistory]*CLUSAwsFuncScanOutput `json:"aws_lambda_record"`
	SlsUploadOutput *CLUSAwsFuncScanOutput                   `json:"sls_upload_output"`
}

type CLUSAwsFuncScanInput struct {
	FuncName string `json:"func_name"`
	RoleName string `json:"role_name"`
	Region   string `json:"region"`
	FuncLink string `json:"func_link"`
	Arn      string `json:"arn"`
	NvSecID  string `json:"nv_sec_id"`
	Version  string `json:"version"`
}

type CLUSAwsScanInput struct {
	AccID            string                  `json:"accid,cloak"`
	AccKey           string                  `json:"acckey,cloak"`
	ProjectName      string                  `json:"projectname"`
	ScanFunctionList []*CLUSAwsFuncScanInput `json:"scanFunctionList"`
	DelFunctionList  []*CLUSAwsFuncScanInput `json:"DelFunctionList"`
}

type CLUSAwsLambdaFunc struct {
	Name        string `json:"func_name"`
	CodeSha256  string `json:"code_sha256"`
	Status      string `json:"status"`
	ScanResult  string `json:"scan_result"`
	PermitLevel string `json:"PermitLevel"`
	Role        string `json:"role"`
	Arn         string `json:"arn"`
	NvSecID     string `json:"nv_sec_id"`
	Version     string `json:"version"`
	HighVuls    int    `json:"high"`
	MedVuls     int    `json:"medium"`
}

type CLUSAwsLambdaRegionRes struct {
	Region     string                        `json:"region"`
	Status     string                        `json:"status"`
	LambdaFunc map[string]*CLUSAwsLambdaFunc `json:"lambda_func"`
}

type CLUSAwsLambdaRes struct {
	Status      string                             `json:"status"`
	ResourceMap map[string]*CLUSAwsLambdaRegionRes `json:"aws_region_resource"`
}

type CLUSAwsResource struct {
	AccID       string            `json:"accid,cloak"`
	AccKey      string            `json:"acckey,cloak"`
	ProjectName string            `json:"projectname"`
	RegionList  []string          `json:"region_list"`
	ResLambda   *CLUSAwsLambdaRes `json:"aws_lambda_resource"`
}

type CLUSAwsProjectCfg struct {
	AccID       string   `json:"accid,cloak"`
	AccKey      string   `json:"acckey,cloak"`
	ProjectName string   `json:"projectname"`
	RegionList  []string `json:"region_list"`
}

func CLUSCloudCfgKey(cloudType, projectName string) string {
	return fmt.Sprintf("%s%s/%s", CLUSConfigCloudStore, cloudType, projectName)
}

func CLUSCloudKey(cloudType, projectName string) string {
	return fmt.Sprintf("%s%s/%s", CLUSCloudStore, cloudType, projectName)
}

func CLUSCloudFuncKey(cloudType, project, region, funcName string) string {
	return fmt.Sprintf("%s%s/%s/%s/%s", CLUSCloudStore, cloudType, project, region, funcName)
}

// SecretLog provides the found secret raw data
type SecretLog struct {
	Text     string `json:"secret"`    // detected secret or signature
	Line     string `json:"line"`      // full line in the content
	File     string `json:"path"`      // file path
	RuleDesc string `json:"rule_desc"` // rule description
}

// ///// Secret Types
const (
	SecretPrivateKey string = "privatekey" // Private Key
	SecretX509       string = "x.509"      // X.509 certificates (ignored)
	SecretProgram    string = "program"    // in specific program files
	SecretRegular    string = "regular"    // in other regular files
)

// CLUSSecretLog provides reports at scanner/enforcer layer
type CLUSSecretLog struct {
	Type       string `json:"type"`       // secret type
	Text       string `json:"secret"`     // detected secret or signature
	Line       string `json:"line"`       // full line in the content
	File       string `json:"path"`       // file path
	RuleDesc   string `json:"rule_desc"`  // rule description
	Suggestion string `json:"suggestion"` // suggestion to reduce the risk
}

// CLUSBenchSecretReport provides reports at REST layer
type CLUSBenchSecretReport struct {
	Status BenchStatus     `json:"status"`
	RunAt  time.Time       `json:"run_at"`
	Items  []CLUSSecretLog `json:"items"`
}

// CLUSSetIdPermLog provides reports at scanner/enforcer layer
type CLUSSetIdPermLog struct {
	Types    string `json:"types"`    // setuid, setgid
	File     string `json:"path"`     // file path
	Evidence string `json:"evidence"` // file attributes
}

// ///// For custom roles
func CLUSUserRoleKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSConfigUserRoleStore, name)
}

type CLUSRolePermission struct {
	ID    string `json:"id"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

type CLUSUserRole struct {
	Name        string                `json:"name"`
	Comment     string                `json:"comment"`
	Reserved    bool                  `json:"reserved"` // true for pre-defined non-hidden roles: fedAdmin/admin/reader
	Permissions []*CLUSRolePermission `json:"permissions"`
}

type CLUSUserRoleInternal struct {
	Name         string `json:"name"`
	Comment      string `json:"comment"`
	Reserved     bool   `json:"reserved"`      // true for pre-defined non-hidden roles: fedAdmin/admin/reader
	ReadPermits  uint32 `json:"read_permits"`  // sum of all  read permissions of this role
	WritePermits uint32 `json:"write_permits"` // sum of all write permissions of this role
}

type CLUSCIScanDummy struct{} // dummy type just for access control checking purpose
type CLUSSnifferDummy struct {
	WorkloadDomain string `json:"workload_domain"`
}
type CLUSWorkloadScanDummy struct {
	Domain string `json:"domain"`
}
type CLUSApplicationListDummy struct{}     // dummy type just for access control checking purpose
type CLUSResponseRuleOptionsDummy struct{} // dummy type just for access control checking purpose
type CLUSRegistryTypeDummy struct{}        // dummy type just for access control checking purpose

// for password profile
const CLUSDefPwdProfileName = "default"
const CLUSSysPwdProfileName = "nvsyspwdprofile" // reserved just for referencing active password profile

type CLUSActivePwdProfileConfig struct {
	Name string `json:"name"` // name of the active password profile to use for the whole cluster
}

type CLUSPwdProfile struct {
	Name                        string `json:"name"`
	Comment                     string `json:"comment"`
	MinLen                      int    `json:"min_len"`
	MinUpperCount               int    `json:"min_uppercase_count"` // for alphabet characters
	MinLowerCount               int    `json:"min_lowercase_count"` // for alphabet characters
	MinDigitCount               int    `json:"min_digit_count"`
	MinSpecialCount             int    `json:"min_special_count"`
	EnablePwdExpiration         bool   `json:"enable_password_expiration"`
	PwdExpireAfterDays          int    `json:"password_expire_after_days"` // must be > 0 when EnablePwdExpiration is true
	EnablePwdHistory            bool   `json:"enable_password_history"`
	PwdHistoryCount             int    `json:"password_keep_history_count"`
	EnableBlockAfterFailedLogin bool   `json:"enable_block_after_failed_login"` // for "Block X minutes after N times failed attempts"
	BlockAfterFailedCount       int    `json:"block_after_failed_login_count"`  // must be > 0 when EnableBlockAfterFailedLogin is true
	BlockMinutes                int    `json:"block_minutes"`                   // must be > 0 when EnableBlockAfterFailedLogin is true
	SessionTimeout              uint32 `json:"session_timeout"`                 // for default user session timeout (in seconds)
}

// Import task
const (
	IMPORT_PREPARE     = "preparing"
	IMPORT_RUNNING     = "importing"
	IMPORT_DONE        = "done"
	IMPORT_NO_RESPONSE = "no_response"
)

const (
	PREFIX_IMPORT_CONFIG       = "import_"
	PREFIX_IMPORT_GROUP_POLICY = "group_import_"
	PREFIX_IMPORT_ADMCTRL      = "admctrl_import_"
	PREFIX_IMPORT_DLP          = "dlp_import_"
	PREFIX_IMPORT_WAF          = "waf_import_"
	PREFIX_IMPORT_VULN_PROFILE = "vul_profile_import_" // for vulnerability profile
	PREFIX_IMPORT_COMP_PROFILE = "cmp_profile_import_" // for compliance profile
)

const (
	IMPORT_TYPE_CONFIG       = ""
	IMPORT_TYPE_GROUP_POLICY = "group"
	IMPORT_TYPE_ADMCTRL      = "admctrl"
	IMPORT_TYPE_DLP          = "dlp"
	IMPORT_TYPE_WAF          = "waf"
	IMPORT_TYPE_VULN_PROFILE = "vuln_profile" // for vulnerability profile
	IMPORT_TYPE_COMP_PROFILE = "comp_profile" // for compliance profile
)

const IMPORT_QUERY_INTERVAL = 30
const CLUSImportStatusSubKey = "status"

func CLUSImportOpKey(name string) string {
	return fmt.Sprintf("%s%s", CLUSImportStore, name)
}

type CLUSImportTask struct {
	TID            string    `json:"tid"`
	ImportType     string    `json:"import_type"`
	CtrlerID       string    `json:"ctrler_id"`
	TempFilename   string    `json:"temp_filename"`
	Status         string    `json:"status"`
	Percentage     int       `json:"percentage"`
	TotalLines     int       `json:"total_lines"`
	LastUpdateTime time.Time `json:"last_update_time"`
	CallerFullname string    `json:"caller_fullname"`
	CallerRemote   string    `json:"caller_remote"`
	CallerID       string    `json:"caller_id"`
}

func CLUSNodeProfileStoreKey(nodeID string) string {
	return fmt.Sprintf("%s%s/%s", CLUSNodeStore, nodeID, CLUSWorkloadProfileStore)
}

func CLUSNodeProfileKey(nodeID, subkey string) string {
	return fmt.Sprintf("%s%s/%s", CLUSNodeStore, nodeID, subkey)
}

func CLUSNodeProfileSubkey(key string) string {
	// sample:
	// input: node/ubuntu:2YZB:5T5K:YVQL:7VNR:FRUB:N3IK:G6FQ:2E7O:UKR4:SDDN:5KQV:CMSF/profiles/process/nv.mtop
	// return: profiles/process/nv.mtop
	tokens := strings.Split(key, "/")
	if len(tokens) == 5 {
		return fmt.Sprintf("%s/%s/%s", tokens[2], tokens[3], tokens[4])
	}
	return ""
}

func CLUSNodeProfileGroupKey(nodeID, profile, group string) string {
	return fmt.Sprintf("%s%s/%s/%s/%s", CLUSNodeStore, nodeID, CLUSWorkloadProfileStore, profile, group)
}

// Import group
type TReviewType int

const (
	ReviewTypeCRD               = iota + 1
	ReviewTypeImportGroup       // interactive import
	ReviewTypeImportAdmCtrl     // interactive import
	ReviewTypeImportDLP         // interactive import
	ReviewTypeImportWAF         // interactive import
	ReviewTypeImportVulnProfile // interactive import vulnerability profile
	ReviewTypeImportCompProfile // interactive import compliance profile
)

const (
	ReviewTypeDisplayCRD         = "CRD"
	ReviewTypeDisplayGroup       = "Group Policy"                     // interactive import
	ReviewTypeDisplayAdmission   = "Admission Control Configurations" // interactive import
	ReviewTypeDisplayDLP         = "DLP Configurations"               // interactive import
	ReviewTypeDisplayWAF         = "WAF Configurations"               // interactive import
	ReviewTypeDisplayVulnProfile = "Vulnerability Profile"            // interactive import
	ReviewTypeDisplayCompProfile = "Compliance Profile"               // interactive import
)

// Telemetry (upgrade responder)
type CLUSCheckUpgradeVersion struct {
	Version     string `json:"version"`
	ReleaseDate string `json:"release_date"`
	Tag         string `json:"tag"`
}

type CLUSCheckUpgradeInfo struct {
	MinUpgradeVersion CLUSCheckUpgradeVersion `json:"min_upgrade_version"`
	MaxUpgradeVersion CLUSCheckUpgradeVersion `json:"max_upgrade_version"`
	LastUploadTime    time.Time               `json:"last_upload_time"`
}

// throttled events/logs
type CLUSThrottledEvents struct {
	LastReportTime map[TLogEvent]int64 `json:"last_report_at"` // key is event id, value is time.Unix()
}

type CLUSApikey struct {
	ExpirationType      string              `json:"expiration_type"`
	ExpirationHours     uint32              `json:"expiration_hours"`
	Name                string              `json:"name"`
	SecretKeyHash       string              `json:"secret_key_hash"`
	Description         string              `json:"description"`
	Locale              string              `json:"locale"`
	Role                string              `json:"role"`
	RoleDomains         map[string][]string `json:"role_domains"`
	ExpirationTimestamp int64               `json:"expiration_timestamp"`
	CreatedTimestamp    int64               `json:"created_timestamp"`
	CreatedByEntity     string              `json:"created_by_entity"` // it could be username or apikey (access key)
}

type CLUSSigstoreRootOfTrust struct {
	Name                 string   `json:"name"`
	IsPrivate            bool     `json:"is_private"`
	RootlessKeypairsOnly bool     `json:"rootless_keypairs_only"`
	RekorPublicKey       string   `json:"rekor_public_key"`
	RootCert             string   `json:"root_cert"`
	SCTPublicKey         string   `json:"sct_public_key"`
	CfgType              TCfgType `json:"cfg_type"`
	Comment              string   `json:"comment"`
}

type CLUSSigstoreVerifier struct {
	Name         string `json:"name"`
	VerifierType string `json:"verifier_type"`
	PublicKey    string `json:"public_key"`
	CertIssuer   string `json:"cert_issuer"`
	CertSubject  string `json:"cert_subject"`
	Comment      string `json:"comment"`
}

// alerts status
const (
	AlertNvNewVerAvailable = "1"
	AlertNvInMultiVersions = "2"
	AlertCveDbTooOld       = "3"
	AlertPwdExpiring       = "1001"
	AlertAdminHasDefPwd    = "1002"
)

// remote repositories
type RemoteRepository_GitHubConfiguration struct {
	RepositoryOwnerUsername          string `json:"repository_owner_username"`
	RepositoryName                   string `json:"repository_name"`
	RepositoryBranchName             string `json:"repository_branch_name"`
	PersonalAccessToken              string `json:"personal_access_token,cloak"`
	PersonalAccessTokenCommitterName string `json:"personal_access_token_committer_name"`
	PersonalAccessTokenEmail         string `json:"personal_access_token_email"`
}

// TODO: generalize this
func (g *RemoteRepository_GitHubConfiguration) IsValid() bool {
	isEmpty := func(s string) bool {
		return s == ""
	}
	requiredFields := []string{
		g.RepositoryOwnerUsername,
		g.RepositoryName,
		g.RepositoryBranchName,
		g.PersonalAccessToken,
		g.PersonalAccessTokenCommitterName,
		g.PersonalAccessTokenEmail,
	}
	for _, requiredField := range requiredFields {
		if isEmpty(requiredField) {
			return false
		}
	}
	return true
}

const RemoteRepositoryProvider_GitHub string = "github"

type CLUSRemoteRepository struct {
	Nickname            string                                `json:"nickname"`
	Provider            string                                `json:"provider"`
	Comment             string                                `json:"comment"`
	Enable              bool                                  `json:"enable"`
	GitHubConfiguration *RemoteRepository_GitHubConfiguration `json:"github_configuration"`
}

func (r *CLUSRemoteRepository) IsValid() bool {
	if r.Nickname != "default" {
		return false
	}
	if r.Provider == RemoteRepositoryProvider_GitHub {
		if r.GitHubConfiguration == nil {
			return false
		}
		return r.GitHubConfiguration.IsValid()
	}
	return false
}
