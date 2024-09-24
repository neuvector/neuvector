package cache

import (
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
)

type CacheInterface interface {
	GetRiskScoreMetrics(acc, accCaller *access.AccessControl) *api.RESTInternalSystemData

	GetAllHosts(acc *access.AccessControl) []*api.RESTHost
	GetAllHostsRisk(acc *access.AccessControl) []*common.WorkloadRisk
	GetHostCount(acc *access.AccessControl) int
	GetHost(id string, acc *access.AccessControl) (*api.RESTHost, error)
	CanAccessHost(id string, acc *access.AccessControl) error

	GetAllControllers(acc *access.AccessControl) []*api.RESTController
	GetControllerCount(acc *access.AccessControl) int
	GetController(id string, acc *access.AccessControl) *api.RESTController
	GetControllerConfig(id string, acc *access.AccessControl) (*api.RESTControllerConfig, error)
	GetAllControllerRPCEndpoints(acc *access.AccessControl) []*common.RPCEndpoint
	GetControllerRPCEndpoint(id string, acc *access.AccessControl) (*common.RPCEndpoint, error)

	GetPlatform() (string, string, string)
	GetComponentVersions(acc *access.AccessControl) []string

	GetDomainCount(acc *access.AccessControl) int // does not include special entries, like _images, _nodes, _containers
	GetAllDomains(acc *access.AccessControl) ([]*api.RESTDomain, bool)
	GetDomainEffectiveTags(name string, acc *access.AccessControl) ([]string, error)

	GetAllAgents(acc *access.AccessControl) []*api.RESTAgent
	GetAgentCount(acc *access.AccessControl, state string) int
	GetAgent(id string, acc *access.AccessControl) *api.RESTAgent
	GetAgentConfig(id string, acc *access.AccessControl) (*api.RESTAgentConfig, error)
	GetAgentbyWorkload(wlID string, acc *access.AccessControl) (string, error)
	GetAgentsbyHost(hostID string, acc *access.AccessControl) ([]string, error)

	GetAllWorkloads(view string, acc *access.AccessControl, idlist utils.Set) []*api.RESTWorkload
	GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief
	GetAllWorkloadsDetail(view string, acc *access.AccessControl) []*api.RESTWorkloadDetail
	GetWorkloadCount(acc *access.AccessControl) (int, int, int)
	GetWorkloadCountOnHost(hostID string, view string, acc *access.AccessControl) int
	GetWorkload(id string, view string, acc *access.AccessControl) (*api.RESTWorkload, error)
	GetWorkloadBrief(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadBrief, error)
	GetWorkloadDetail(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadDetail, error)
	GetWorkloadConfig(id string, acc *access.AccessControl) (*api.RESTWorkloadConfig, error)
	GetAllWorkloadsRisk(acc *access.AccessControl) []*common.WorkloadRisk
	GetWorkloadRisk(id string, acc *access.AccessControl) (*common.WorkloadRisk, error)
	CanAccessWorkload(id string, acc *access.AccessControl) error
	GetAllWorkloadsID(acc *access.AccessControl) []string
	GetAllHostsID(acc *access.AccessControl) []string
	GetPlatformID(acc *access.AccessControl) string

	GetAllGroups(scope, view string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroup
	GetAllGroupsBrief(scope string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroupBrief
	GetGroup(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroup, error)
	GetGroupBrief(name string, withCap bool, acc *access.AccessControl) (*api.RESTGroupBrief, error)
	GetGroupDetail(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroupDetail, error)
	DoesGroupExist(name string, acc *access.AccessControl) (bool, error)
	GetGroupCount(scope string, acc *access.AccessControl) int
	GetFedGroupsCache() []*share.CLUSGroup
	GetGroupCache(name string, acc *access.AccessControl) (*share.CLUSGroup, error)
	DeleteGroupCache(name string, acc *access.AccessControl) error
	GetFedGroupNames(acc *access.AccessControl) utils.Set
	GetServiceCount(acc *access.AccessControl) int
	IsGroupPolicyModeChangeable(name string) bool
	CreateService(svc *api.RESTServiceConfig, acc *access.AccessControl) error
	GetAllServiceCount(acc *access.AccessControl) int
	GetAllServices(view string, withCap bool, acc *access.AccessControl) []*api.RESTService
	GetService(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTService, error)
	DlpSensorInGroups(sensor string) bool
	IsGroupMember(name, id string) bool
	GetConfigKvData(key string) ([]byte, bool)

	GetAllPolicyRules(scope string, acc *access.AccessControl) []*api.RESTPolicyRule
	GetAllPolicyRulesCache(acc *access.AccessControl) []*share.CLUSPolicyRule
	GetPolicyRuleCount(acc *access.AccessControl) int
	GetPolicyRule(id uint32, acc *access.AccessControl) (*api.RESTPolicyRule, error)
	GetPolicyRuleCache(id uint32, acc *access.AccessControl) (*share.CLUSPolicyRule, error)
	PolicyRule2REST(rule *share.CLUSPolicyRule) *api.RESTPolicyRule
	GetFedNetworkRulesCache() ([]*share.CLUSPolicyRule, []*share.CLUSRuleHead)
	CheckPolicyRuleAccess(id uint32, accRead *access.AccessControl, accWrite *access.AccessControl) (bool, bool, bool)

	GetAllResponseRules(scope string, acc *access.AccessControl) []*api.RESTResponseRule
	GetResponseRuleCount(scope string, acc *access.AccessControl) int
	GetResponseRule(policyName string, id uint32, acc *access.AccessControl) (*api.RESTResponseRule, error)
	GetWorkloadResponseRules(policyName, id string, acc *access.AccessControl) ([]*api.RESTResponseRule, error)
	GetFedResponseRulesCache() (map[uint32]*share.CLUSResponseRule, []*share.CLUSRuleHead)
	ResponseRule2REST(rule *share.CLUSResponseRule) *api.RESTResponseRule

	GetConverEndpoint(name string, acc *access.AccessControl) (*api.RESTConversationEndpoint, error)
	GetAllConverEndpoints(view string, acc *access.AccessControl) []*api.RESTConversationEndpoint
	GetAllApplicationConvers(groupFilter, domainFilter string, acc *access.AccessControl) ([]*api.RESTConversationCompact, []*api.RESTConversationEndpoint)
	GetApplicationConver(src, dst string, srcList, dstList []string, acc *access.AccessControl) (*api.RESTConversationDetail, error)

	GetIP2WorkloadMap(hostID string) []*api.RESTDebugIP2Workload

	GetSystemConfig(acc *access.AccessControl) *api.RESTSystemConfig
	GetSystemConfigClusterName(acc *access.AccessControl) string
	GetIBMSAConfig(acc *access.AccessControl) (*api.RESTIBMSAConfig, error)
	GetIBMSAConfigNV(acc *access.AccessControl) (share.CLUSIBMSAConfigNV, error)
	GetFedSystemConfig(acc *access.AccessControl) *share.CLUSSystemConfig

	GetInternalSubnets() *api.RESTInternalSubnets

	GetViolations(acc *access.AccessControl) []*api.Violation
	GetViolationCount(acc *access.AccessControl) int
	GetActivities(acc *access.AccessControl) []*api.Event
	GetActivityCount(acc *access.AccessControl) int
	GetEvents(caller string, acc *access.AccessControl) []*api.Event
	GetEventCount(caller string, acc *access.AccessControl) int
	GetThreats(acc *access.AccessControl) []*api.Threat
	GetThreat(uuid string, acc *access.AccessControl) (*api.Threat, error)
	GetThreatCount(acc *access.AccessControl) int
	GetIncidents(acc *access.AccessControl) []*api.Incident
	GetIncidentCount(acc *access.AccessControl) int
	GetAudits(acc *access.AccessControl) []*api.Audit
	GetAuditCount(acc *access.AccessControl) int

	// License
	GetCurrentLicense(acc *access.AccessControl) api.RESTLicenseInfo

	// Process profile
	GetProcessProfile(group string, acc *access.AccessControl) (*api.RESTProcessProfile, error)
	GetAllProcessProfile(scope string, acc *access.AccessControl) [][]*api.RESTProcessProfile
	GetFedProcessProfileCache() []*share.CLUSProcessProfile
	CreateProcessProfile(group, mode, baseline string, cfgType share.TCfgType) bool
	CreateProcessProfileTxn(txn *cluster.ClusterTransact, group, mode, baseline string, cfgType share.TCfgType) bool

	// File monitor profile
	GetFileMonitorProfile(name string, acc *access.AccessControl, customer bool) (*api.RESTFileMonitorProfile, error)
	GetAllFileMonitorProfile(scope string, acc *access.AccessControl, customer bool) []*api.RESTFileMonitorProfile
	GetFedFileMonitorProfileCache() ([]*share.CLUSFileMonitorProfile, []*share.CLUSFileAccessRule)
	CreateGroupFileMonitor(name, mode string, cfgType share.TCfgType) bool
	CreateGroupFileMonitorTxn(txn *cluster.ClusterTransact, name, mode string, cfgType share.TCfgType) bool
	IsPrdefineFileGroup(filter string, recursive bool) (*share.CLUSFileMonitorFilter, bool)

	// Scan
	ScanWorkload(id string, acc *access.AccessControl) error
	ScanHost(id string, acc *access.AccessControl) error
	ScanPlatform(acc *access.AccessControl) error

	GetAllScanners(acc *access.AccessControl) []*api.RESTScanner
	GetScannerCount(acc *access.AccessControl) (int, string, string)
	GetScanConfig(acc *access.AccessControl) (*api.RESTScanConfig, error)
	GetScanStatus(acc *access.AccessControl) (*api.RESTScanStatus, error)
	GetScanPlatformSummary(acc *access.AccessControl) (*api.RESTScanPlatformSummary, error)
	GetVulnerabilityReport(id string, showTag string) ([]*api.RESTVulnerability, []*api.RESTScanModule, error)

	// Compliance
	GetComplianceProfile(name string, acc *access.AccessControl) (*api.RESTComplianceProfile, map[string][]string, error)
	GetAllComplianceProfiles(acc *access.AccessControl) []*api.RESTComplianceProfile

	// Vulnerability
	GetVulnerabilityProfile(name string, acc *access.AccessControl) (*api.RESTVulnerabilityProfile, error)
	GetVulnerabilityProfileInterface(name string) scanUtils.VPFInterface
	GetAllVulnerabilityProfiles(acc *access.AccessControl) []*api.RESTVulnerabilityProfile

	// Admission control - non-UI
	SyncAdmCtrlStateToK8s(svcName, nvAdmName string, updateDetected bool) (bool, error)
	WaitUntilApiPathReady() bool
	IsImageScanned(c *nvsysadmission.AdmContainerInfo) (bool, int, int)
	MatchK8sAdmissionRules(admResObject *nvsysadmission.AdmResObject, c *nvsysadmission.AdmContainerInfo,
		evalContext *nvsysadmission.AdmCtrlEvalContext, stamps *api.AdmCtlTimeStamps, ar *admissionv1beta1.AdmissionReview,
		containerType string) (*nvsysadmission.AdmCtrlAssessResult, bool)
	MatchK8sAdmissionRulesForPVC(ns, name, scName string, evalContext *nvsysadmission.AdmCtrlEvalContext) (*nvsysadmission.AdmCtrlAssessResult, bool)
	IsAdmControlEnabled(uri *string) (bool, string, int, string, string)
	UpdateLocalAdmCtrlStats(category string, stats int) error
	IncrementAdmCtrlProcessing()
	FlushAdmCtrlStats() error
	SetNvDeployStatusInCluster(resName string, value bool)
	// Admission control - UI
	GetAdmissionRuleCount(admType, ruleType string, acc *access.AccessControl) int
	GetAdmissionRule(admType, ruleType string, id uint32, acc *access.AccessControl) (*api.RESTAdmissionRule, error)
	GetAdmissionRules(admType, ruleType string, acc *access.AccessControl) []*api.RESTAdmissionRule
	GetFedAdmissionRulesCache(admType, ruleType string) (*share.CLUSAdmissionRules, error)
	GetAdmissionState(acc *access.AccessControl) (*api.RESTAdmissionState, error)
	GetAdmissionStats(acc *access.AccessControl) (*api.RESTAdmissionStats, error)
	GetAdmissionPssDesc() map[string][]string

	// Multi-Clusters (Federation) - UI
	GetFedMembershipRole(acc *access.AccessControl) (string, error)
	GetFedMember(statusMap map[int]string, acc *access.AccessControl) (*api.RESTFedMembereshipData, error)
	GetFedLocalRestInfo(acc *access.AccessControl) (share.CLUSRestServerInfo, int8)
	GetFedMasterCluster(acc *access.AccessControl) api.RESTFedMasterClusterInfo
	GetFedLocalJointCluster(acc *access.AccessControl) api.RESTFedJointClusterInfo
	GetFedJoinedClusterToken(id, mainSessionID string, acc *access.AccessControl) (string, error)
	GetFedJoinedClusterCount() int
	GetFedJoinedClusterIdMap(acc *access.AccessControl) map[string]bool // key: cluster id, value: cluster is disabled or not
	GetFedJoinedClusterNameList(acc *access.AccessControl) []string
	GetFedJoinedCluster(id string, acc *access.AccessControl) share.CLUSFedJointClusterInfo
	GetFedJoinedClusterStatus(id string, acc *access.AccessControl) share.CLUSFedClusterStatus
	// non-UI
	GetFedMembershipRoleNoAuth() string
	SetFedJoinedClusterToken(id, mainSessionID, token string)
	GetFedRules(reqRevs map[string]uint64, acc *access.AccessControl) ([]byte, map[string]uint64, error)
	GetAllFedRulesRevisions() map[string]uint64
	GetFedSettings() share.CLUSFedSettings
	GetFedScanResult(reqRegConfigRev uint64, reqScanResultMD5 map[string]map[string]string, reqIgnoreRegs, reqUpToDateRegs []string, fedRegs utils.Set) (api.RESTPollFedScanDataResp, bool)
	GetFedScanDataRevisions(getRegScanData, getRepoScanData bool) (api.RESTFedScanDataRevs, bool)
	GetFedScanResultMD5(cachedScanDataRevs, masterScanDataRevs api.RESTFedScanDataRevs) map[string]map[string]string

	// Dlp rule
	GetDlpSensor(sensor string, acc *access.AccessControl) (*api.RESTDlpSensor, error)
	GetAllDlpSensors(acc *access.AccessControl) []*api.RESTDlpSensor
	IsDlpRuleUsedBySensor(rule string, acc *access.AccessControl) bool
	GetDlpGroup(group string, acc *access.AccessControl) (*api.RESTDlpGroup, error)
	GetAllDlpGroup(acc *access.AccessControl) []*api.RESTDlpGroup
	GetDlpRule(rulename string, acc *access.AccessControl) (*api.RESTDlpRuleDetail, error)
	GetDlpRules(acc *access.AccessControl) ([]*api.RESTDlpRule, error)
	DoesDlpSensorExist(name string, acc *access.AccessControl) (bool, error)
	GetDlpRuleNames() *[]string
	GetDlpRuleSensorGroupById(id uint32) (string, string, *[]string)
	GetNewServicePolicyMode() (string, string)
	GetNewServiceProfileBaseline() string
	GetUnusedGroupAging() uint8
	GetNetServiceStatus() bool
	GetNetServicePolicyMode() string
	GetDisableNetPolicyStatus() bool

	// Waf rule
	GetAllWafSensors(acc *access.AccessControl) []*api.RESTWafSensor
	GetWafSensor(sensor string, acc *access.AccessControl) (*api.RESTWafSensor, error)
	IsWafRuleUsedBySensor(rule string, acc *access.AccessControl) (bool, share.TCfgType)
	DoesWafSensorExist(name string, acc *access.AccessControl) (bool, error)
	WafSensorInGroups(sensor string) bool
	GetAllWafGroup(acc *access.AccessControl) []*api.RESTWafGroup
	GetWafGroup(group string, acc *access.AccessControl) (*api.RESTWafGroup, error)
	GetWafRules(acc *access.AccessControl) ([]*api.RESTWafRule, error)
	GetWafRule(rulename string, acc *access.AccessControl) (*api.RESTWafRuleDetail, error)
	GetWafRuleSensorGroupById(id uint32) (string, string, *[]string)
	GetWafRuleNames() *[]string

	// Custom role
	AuthorizeCustomCheck(name string, acc *access.AccessControl) bool
	AuthorizeFileMonitorProfile(name string, acc *access.AccessControl) bool
	PutCustomRoles(roles map[string]*share.CLUSUserRole)

	// password profile
	GetPwdProfile(name string) (share.CLUSPwdProfile, error)
	GetAllPwdProfiles() (string, map[string]share.CLUSPwdProfile)

	// csp billing integration
	GetNvUsage(fedRole string) api.RESTNvUsage
}
