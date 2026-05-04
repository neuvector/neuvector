package rest

import (
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
)

// MockCache is a mock implementation of CacheInterface for testing purposes
type MockCache struct {
	// Add fields as needed for mock behavior
}

// Ensure MockCache implements CacheInterface at compile time
var _ cache.CacheInterface = (*MockCache)(nil)

func NewMockCache() *MockCache {
	return &MockCache{}
}

func (m *MockCache) GetRiskScoreMetrics(acc, accCaller *access.AccessControl) *api.RESTScoreMetricsData {
	return nil
}

func (m *MockCache) GetAllHosts(acc *access.AccessControl) []*api.RESTHost {
	return nil
}

func (m *MockCache) GetAllHostsRisk(acc *access.AccessControl) []*common.WorkloadRisk {
	return nil
}

func (m *MockCache) GetHostCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetHost(id string, acc *access.AccessControl) (*api.RESTHost, error) {
	return nil, nil
}

func (m *MockCache) CanAccessHost(id string, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) GetAllControllers(acc *access.AccessControl) []*api.RESTController {
	return nil
}

func (m *MockCache) GetControllerCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetController(id string, acc *access.AccessControl) *api.RESTController {
	return nil
}

func (m *MockCache) GetControllerConfig(id string, acc *access.AccessControl) (*api.RESTControllerConfig, error) {
	return nil, nil
}

func (m *MockCache) GetAllControllerRPCEndpoints(acc *access.AccessControl) []*common.RPCEndpoint {
	return nil
}

func (m *MockCache) GetControllerRPCEndpoint(id string, acc *access.AccessControl) (*common.RPCEndpoint, error) {
	return nil, nil
}

func (m *MockCache) GetPlatform() (string, string, string) {
	return "", "", ""
}

func (m *MockCache) GetComponentVersions(acc *access.AccessControl) []string {
	return nil
}

func (m *MockCache) GetDomainCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetAllDomains(acc *access.AccessControl) ([]*api.RESTDomain, bool) {
	return nil, false
}

func (m *MockCache) GetDomainEffectiveTags(name string, acc *access.AccessControl) ([]string, error) {
	return nil, nil
}

func (m *MockCache) GetAllAgents(acc *access.AccessControl) []*api.RESTAgent {
	return nil
}

func (m *MockCache) GetAgentCount(acc *access.AccessControl, state string) int {
	return 0
}

func (m *MockCache) GetAgent(id string, acc *access.AccessControl) *api.RESTAgent {
	return nil
}

func (m *MockCache) GetAgentConfig(id string, acc *access.AccessControl) (*api.RESTAgentConfig, error) {
	return nil, nil
}

func (m *MockCache) GetAgentbyWorkload(wlID string, acc *access.AccessControl) (string, error) {
	return "", nil
}

func (m *MockCache) GetAgentsbyHost(hostID string, acc *access.AccessControl) ([]string, error) {
	return nil, nil
}

func (m *MockCache) GetAllWorkloads(view string, acc *access.AccessControl, idlist utils.Set) []*api.RESTWorkload {
	return nil
}

func (m *MockCache) GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief {
	return nil
}

func (m *MockCache) GetAllWorkloadsDetail(view string, acc *access.AccessControl) []*api.RESTWorkloadDetail {
	return nil
}

func (m *MockCache) GetWorkloadCount(acc *access.AccessControl) (int, int, int) {
	return 0, 0, 0
}

func (m *MockCache) GetWorkloadCountOnHost(hostID string, view string, acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetWorkload(id string, view string, acc *access.AccessControl) (*api.RESTWorkload, error) {
	return nil, nil
}

func (m *MockCache) GetWorkloadBrief(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadBrief, error) {
	return nil, nil
}

func (m *MockCache) GetWorkloadDetail(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadDetail, error) {
	return nil, nil
}

func (m *MockCache) GetWorkloadConfig(id string, acc *access.AccessControl) (*api.RESTWorkloadConfig, error) {
	return nil, nil
}

func (m *MockCache) GetAllWorkloadsRisk(acc *access.AccessControl) []*common.WorkloadRisk {
	return nil
}

func (m *MockCache) GetWorkloadRisk(id string, acc *access.AccessControl) (*common.WorkloadRisk, error) {
	return nil, nil
}

func (m *MockCache) CanAccessWorkload(id string, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) GetAllWorkloadsID(acc *access.AccessControl) []string {
	return nil
}

func (m *MockCache) GetAllHostsID(acc *access.AccessControl) []string {
	return nil
}

func (m *MockCache) GetPlatformID(acc *access.AccessControl) string {
	return ""
}

func (m *MockCache) GetAllGroups(scope, view string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroup {
	return nil
}

func (m *MockCache) GetAllGroupsBrief(scope string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroupBrief {
	return nil
}

func (m *MockCache) GetGroup(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroup, error) {
	return nil, nil
}

func (m *MockCache) GetGroupBrief(name string, withCap bool, acc *access.AccessControl) (*api.RESTGroupBrief, error) {
	return nil, nil
}

func (m *MockCache) GetGroupDetail(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroupDetail, error) {
	return nil, nil
}

func (m *MockCache) DoesGroupExist(name string, acc *access.AccessControl) (bool, error) {
	return false, nil
}

func (m *MockCache) GetGroupCount(scope string, acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetFedGroupsCache() []*share.CLUSGroup {
	return nil
}

func (m *MockCache) GetGroupCache(name string, acc *access.AccessControl) (*share.CLUSGroup, error) {
	return nil, nil
}

func (m *MockCache) DeleteGroupCache(name string, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) GetFedGroupNames(acc *access.AccessControl) utils.Set {
	return nil
}

func (m *MockCache) GetServiceCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) IsGroupPolicyModeChangeable(name string) bool {
	return false
}

func (m *MockCache) CreateService(svc *api.RESTServiceConfig, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) GetAllServiceCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetAllServices(view string, withCap bool, acc *access.AccessControl) []*api.RESTService {
	return nil
}

func (m *MockCache) GetService(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTService, error) {
	return nil, nil
}

func (m *MockCache) DlpSensorInGroups(sensor string) bool {
	return false
}

func (m *MockCache) IsGroupMember(name, id string) bool {
	return false
}

func (m *MockCache) GetConfigKvData(key string) ([]byte, bool) {
	return nil, false
}

func (m *MockCache) GetAllPolicyRules(scope string, acc *access.AccessControl) []*api.RESTPolicyRule {
	return nil
}

func (m *MockCache) GetAllPolicyRulesCache(acc *access.AccessControl) []*share.CLUSPolicyRule {
	return nil
}

func (m *MockCache) GetPolicyRuleCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetPolicyRule(id uint32, acc *access.AccessControl) (*api.RESTPolicyRule, error) {
	return nil, nil
}

func (m *MockCache) GetPolicyRuleCache(id uint32, acc *access.AccessControl) (*share.CLUSPolicyRule, error) {
	return nil, nil
}

func (m *MockCache) PolicyRule2REST(rule *share.CLUSPolicyRule) *api.RESTPolicyRule {
	return nil
}

func (m *MockCache) GetFedNetworkRulesCache() ([]*share.CLUSPolicyRule, []*share.CLUSRuleHead) {
	return nil, nil
}

func (m *MockCache) CheckPolicyRuleAccess(id uint32, accRead *access.AccessControl, accWrite *access.AccessControl) (bool, bool, bool) {
	return false, false, false
}

func (m *MockCache) GetAllResponseRules(scope string, acc *access.AccessControl) []*api.RESTResponseRule {
	return nil
}

func (m *MockCache) GetResponseRuleCount(scope string, acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetResponseRule(policyName string, id uint32, acc *access.AccessControl) (*api.RESTResponseRule, error) {
	return nil, nil
}

func (m *MockCache) GetWorkloadResponseRules(policyName, id string, acc *access.AccessControl) ([]*api.RESTResponseRule, error) {
	return nil, nil
}

func (m *MockCache) GetFedResponseRulesCache() (map[uint32]*share.CLUSResponseRule, []*share.CLUSRuleHead) {
	return nil, nil
}

func (m *MockCache) ResponseRule2REST(rule *share.CLUSResponseRule) *api.RESTResponseRule {
	return nil
}

func (m *MockCache) GetConverEndpoint(name string, acc *access.AccessControl) (*api.RESTConversationEndpoint, error) {
	return nil, nil
}

func (m *MockCache) GetAllConverEndpoints(view string, acc *access.AccessControl) []*api.RESTConversationEndpoint {
	return nil
}

func (m *MockCache) GetAllApplicationConvers(groupFilter, domainFilter string, acc *access.AccessControl) ([]*api.RESTConversationCompact, []*api.RESTConversationEndpoint) {
	return nil, nil
}

func (m *MockCache) GetApplicationConver(src, dst string, srcList, dstList []string, acc *access.AccessControl) (*api.RESTConversationDetail, error) {
	return nil, nil
}

func (m *MockCache) GetIP2WorkloadMap(hostID string) []*api.RESTDebugIP2Workload {
	return nil
}

func (m *MockCache) GetSystemConfig(acc *access.AccessControl) *api.RESTSystemConfig {
	return nil
}

func (m *MockCache) GetSystemConfigClusterName(acc *access.AccessControl) string {
	return ""
}

func (m *MockCache) GetIBMSAConfig(acc *access.AccessControl) (*api.RESTIBMSAConfig, error) {
	return nil, nil
}

func (m *MockCache) GetIBMSAConfigNV(acc *access.AccessControl) (share.CLUSIBMSAConfigNV, error) {
	return share.CLUSIBMSAConfigNV{}, nil
}

func (m *MockCache) GetFedSystemConfig(acc *access.AccessControl) *share.CLUSSystemConfig {
	return nil
}

func (m *MockCache) GetInternalSubnets() *api.RESTInternalSubnets {
	return nil
}

func (m *MockCache) GetViolations(acc *access.AccessControl) []*api.Violation {
	return nil
}

func (m *MockCache) GetViolationCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetActivities(acc *access.AccessControl) []*api.Event {
	return nil
}

func (m *MockCache) GetActivityCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetEvents(caller string, acc *access.AccessControl) []*api.Event {
	return nil
}

func (m *MockCache) GetEventCount(caller string, acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetThreats(acc *access.AccessControl) []*api.Threat {
	return nil
}

func (m *MockCache) GetThreat(uuid string, acc *access.AccessControl) (*api.Threat, error) {
	return nil, nil
}

func (m *MockCache) GetThreatCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetIncidents(acc *access.AccessControl) []*api.Incident {
	return nil
}

func (m *MockCache) GetIncidentCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetAudits(acc *access.AccessControl) []*api.Audit {
	return nil
}

func (m *MockCache) GetAuditCount(acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetCurrentLicense(acc *access.AccessControl) api.RESTLicenseInfo {
	return api.RESTLicenseInfo{}
}

func (m *MockCache) GetProcessProfile(group string, acc *access.AccessControl) (*api.RESTProcessProfile, error) {
	return nil, nil
}

func (m *MockCache) GetAllProcessProfile(scope string, acc *access.AccessControl) [][]*api.RESTProcessProfile {
	return nil
}

func (m *MockCache) GetFedProcessProfileCache() []*share.CLUSProcessProfile {
	return nil
}

func (m *MockCache) CreateProcessProfile(group, mode, baseline string, cfgType share.TCfgType) bool {
	return false
}

func (m *MockCache) CreateProcessProfileTxn(txn *cluster.ClusterTransact, group, mode, baseline string, cfgType share.TCfgType) bool {
	return false
}

func (m *MockCache) GetFileMonitorProfile(name string, acc *access.AccessControl, customer bool) (*api.RESTFileMonitorProfile, error) {
	return nil, nil
}

func (m *MockCache) GetAllFileMonitorProfile(scope string, acc *access.AccessControl, customer bool) []*api.RESTFileMonitorProfile {
	return nil
}

func (m *MockCache) GetFedFileMonitorProfileCache() ([]*share.CLUSFileMonitorProfile, []*share.CLUSFileAccessRule) {
	return nil, nil
}

func (m *MockCache) CreateGroupFileMonitor(name, mode string, cfgType share.TCfgType) bool {
	return false
}

func (m *MockCache) CreateGroupFileMonitorTxn(txn *cluster.ClusterTransact, name, mode string, cfgType share.TCfgType) bool {
	return false
}

func (m *MockCache) IsPrdefineFileGroup(filter string, recursive bool) (*share.CLUSFileMonitorFilter, bool) {
	return nil, false
}

func (m *MockCache) ScanWorkload(id string, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) ScanHost(id string, acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) ScanPlatform(acc *access.AccessControl) error {
	return nil
}

func (m *MockCache) GetAllScanners(acc *access.AccessControl) []*api.RESTScanner {
	return nil
}

func (m *MockCache) GetScannerCount(acc *access.AccessControl) (int, string, string) {
	return 0, "", ""
}

func (m *MockCache) GetScanConfig(acc *access.AccessControl) (*api.RESTScanConfig, error) {
	return nil, nil
}

func (m *MockCache) GetScanStatus(acc *access.AccessControl) (*api.RESTScanStatus, error) {
	return nil, nil
}

func (m *MockCache) GetScanPlatformSummary(acc *access.AccessControl) (*api.RESTScanPlatformSummary, error) {
	return nil, nil
}

func (m *MockCache) GetVulnerabilityReport(id string, showTag string) ([]*api.RESTVulnerability, []*api.RESTScanModule, error) {
	return nil, nil, nil
}

func (m *MockCache) GetComplianceProfile(name string, acc *access.AccessControl) (*api.RESTComplianceProfile, map[string][]string, error) {
	return nil, nil, nil
}

func (m *MockCache) GetAllComplianceProfiles(acc *access.AccessControl) []*api.RESTComplianceProfile {
	return nil
}

func (m *MockCache) GetVulnerabilityProfile(name string, acc *access.AccessControl) (*api.RESTVulnerabilityProfile, error) {
	return nil, nil
}

func (m *MockCache) GetVulnerabilityProfileInterface(name string) scanUtils.VPFInterface {
	return nil
}

func (m *MockCache) GetAllVulnerabilityProfiles(acc *access.AccessControl) []*api.RESTVulnerabilityProfile {
	return nil
}

func (m *MockCache) SyncAdmCtrlStateToK8s(svcName, nvAdmName string, updateDetected bool) (bool, error) {
	return false, nil
}

func (m *MockCache) WaitUntilApiPathReady() bool {
	return false
}

func (m *MockCache) MatchK8sAdmissionRules(admResObject *nvsysadmission.AdmResObject, c *nvsysadmission.AdmContainerInfo,
	evalContext *nvsysadmission.AdmCtrlEvalContext, stamps *api.AdmCtlTimeStamps, ar *admissionv1beta1.AdmissionReview,
	containerType string) (*nvsysadmission.AdmCtrlAssessResult, bool) {
	return nil, false
}

func (m *MockCache) MatchK8sAdmissionRulesForPVC(ns, name, scName string, evalContext *nvsysadmission.AdmCtrlEvalContext) (*nvsysadmission.AdmCtrlAssessResult, bool) {
	return nil, false
}

func (m *MockCache) IsAdmControlEnabled(uri *string) (bool, string, int, string, string) {
	return false, "", 0, "", ""
}

func (m *MockCache) UpdateLocalAdmCtrlStats(category string, stats int) {}

func (m *MockCache) IncrementAdmCtrlProcessing() {}

func (m *MockCache) FlushAdmCtrlStats() error {
	return nil
}

func (m *MockCache) SetNvDeployStatusInCluster(resName string, value bool) {}

func (m *MockCache) GetAdmissionRuleCount(admType, ruleType string, acc *access.AccessControl) int {
	return 0
}

func (m *MockCache) GetAdmissionRule(admType, ruleType string, id uint32, acc *access.AccessControl) (*api.RESTAdmissionRule, error) {
	return nil, nil
}

func (m *MockCache) GetAdmissionRules(admType, ruleType string, acc *access.AccessControl) []*api.RESTAdmissionRule {
	return nil
}

func (m *MockCache) GetFedAdmissionRulesCache(admType, ruleType string) (*share.CLUSAdmissionRules, error) {
	return nil, nil
}

func (m *MockCache) GetAdmissionState(acc *access.AccessControl) (*api.RESTAdmissionState, error) {
	return nil, nil
}

func (m *MockCache) GetAdmissionStats(acc *access.AccessControl) (*api.RESTAdmissionStats, error) {
	return nil, nil
}

func (m *MockCache) GetAdmissionPssDesc() map[string][]string {
	return nil
}

func (m *MockCache) GetFedMembershipRole(acc *access.AccessControl) (string, error) {
	return "", nil
}

func (m *MockCache) GetFedMember(statusMap map[int]string, acc *access.AccessControl) (*api.RESTFedMembereshipData, error) {
	return nil, nil
}

func (m *MockCache) GetFedLocalRestInfo(acc *access.AccessControl) (share.CLUSRestServerInfo, int8) {
	return share.CLUSRestServerInfo{}, 0
}

func (m *MockCache) GetFedMasterCluster(acc *access.AccessControl) api.RESTFedMasterClusterInfo {
	return api.RESTFedMasterClusterInfo{}
}

func (m *MockCache) GetFedLocalJointCluster(acc *access.AccessControl) api.RESTFedJointClusterInfo {
	return api.RESTFedJointClusterInfo{}
}

func (m *MockCache) GetFedJoinedClusterToken(id, mainSessionID string, acc *access.AccessControl) (string, error) {
	return "", nil
}

func (m *MockCache) GetFedJoinedClusterCount() int {
	return 0
}

func (m *MockCache) GetFedJoinedClusterIdMap(acc *access.AccessControl) map[string]bool {
	return nil
}

func (m *MockCache) GetFedJoinedClusterNameList(acc *access.AccessControl) []string {
	return nil
}

func (m *MockCache) GetFedJoinedCluster(id string, acc *access.AccessControl) share.CLUSFedJointClusterInfo {
	return share.CLUSFedJointClusterInfo{}
}

func (m *MockCache) GetFedJoinedClusterStatus(id string, acc *access.AccessControl) share.CLUSFedClusterStatus {
	return share.CLUSFedClusterStatus{}
}

func (m *MockCache) GetFedMembershipRoleNoAuth() string {
	return ""
}

func (m *MockCache) SetFedJoinedClusterToken(id, mainSessionID, token string) {}

func (m *MockCache) GetFedRules(reqRevs map[string]uint64, acc *access.AccessControl) ([]byte, map[string]uint64, error) {
	return nil, nil, nil
}

func (m *MockCache) GetAllFedRulesRevisions() map[string]uint64 {
	return nil
}

func (m *MockCache) GetFedSettings() share.CLUSFedSettings {
	return share.CLUSFedSettings{}
}

func (m *MockCache) GetFedScanResult(reqRegConfigRev uint64, reqScanResultHash map[string]map[string]string, reqIgnoreRegs, reqUpToDateRegs []string, fedRegs utils.Set) (api.RESTPollFedScanDataResp, bool) {
	return api.RESTPollFedScanDataResp{}, false
}

func (m *MockCache) GetFedScanDataRevisions(getRegScanData, getRepoScanData bool) (api.RESTFedScanDataRevs, bool) {
	return api.RESTFedScanDataRevs{}, false
}

func (m *MockCache) GetFedScanResultHash(cachedScanDataRevs, masterScanDataRevs api.RESTFedScanDataRevs) map[string]map[string]string {
	return nil
}

func (m *MockCache) GetDlpSensor(sensor string, acc *access.AccessControl) (*api.RESTDlpSensor, error) {
	return nil, nil
}

func (m *MockCache) GetAllDlpSensors(scope string, acc *access.AccessControl) []*api.RESTDlpSensor {
	return nil
}

func (m *MockCache) IsDlpRuleUsedBySensor(rule string, acc *access.AccessControl) bool {
	return false
}

func (m *MockCache) GetDlpGroup(group string, acc *access.AccessControl) (*api.RESTDlpGroup, error) {
	return nil, nil
}

func (m *MockCache) GetAllDlpGroup(scope string, acc *access.AccessControl) []*api.RESTDlpGroup {
	return nil
}

func (m *MockCache) GetDlpRule(rulename string, acc *access.AccessControl) (*api.RESTDlpRuleDetail, error) {
	return nil, nil
}

func (m *MockCache) GetDlpRules(acc *access.AccessControl) ([]*api.RESTDlpRule, error) {
	return nil, nil
}

func (m *MockCache) DoesDlpSensorExist(name string, acc *access.AccessControl) (bool, error) {
	return false, nil
}

func (m *MockCache) GetDlpRuleNames() *[]string {
	return nil
}

func (m *MockCache) GetDlpRuleSensorGroupById(id uint32) (string, string, *[]string) {
	return "", "", nil
}

func (m *MockCache) GetFedDlpGroupSensorCache() ([]*share.CLUSDlpSensor, []*share.CLUSDlpGroup) {
	return nil, nil
}

func (m *MockCache) GetNewServicePolicyMode() (string, string) {
	return "", ""
}

func (m *MockCache) GetNewServiceProfileBaseline() string {
	return ""
}

func (m *MockCache) GetUnusedGroupAging() uint8 {
	return 0
}

func (m *MockCache) GetNetServiceStatus() bool {
	return false
}

func (m *MockCache) GetNetServicePolicyMode() string {
	return ""
}

func (m *MockCache) GetDisableNetPolicyStatus() bool {
	return false
}

func (m *MockCache) GetStrictGroupModeStatus() bool {
	return false
}

func (m *MockCache) GetAllWafSensors(scope string, acc *access.AccessControl) []*api.RESTWafSensor {
	return nil
}

func (m *MockCache) GetWafSensor(sensor string, acc *access.AccessControl) (*api.RESTWafSensor, error) {
	return nil, nil
}

func (m *MockCache) IsWafRuleUsedBySensor(rule string, acc *access.AccessControl) (bool, share.TCfgType) {
	return false, share.TCfgType(0)
}

func (m *MockCache) DoesWafSensorExist(name string, acc *access.AccessControl) (bool, error) {
	return false, nil
}

func (m *MockCache) WafSensorInGroups(sensor string) bool {
	return false
}

func (m *MockCache) GetAllWafGroup(scope string, acc *access.AccessControl) []*api.RESTWafGroup {
	return nil
}

func (m *MockCache) GetWafGroup(group string, acc *access.AccessControl) (*api.RESTWafGroup, error) {
	return nil, nil
}

func (m *MockCache) GetWafRules(acc *access.AccessControl) ([]*api.RESTWafRule, error) {
	return nil, nil
}

func (m *MockCache) GetWafRule(rulename string, acc *access.AccessControl) (*api.RESTWafRuleDetail, error) {
	return nil, nil
}

func (m *MockCache) GetWafRuleSensorGroupById(id uint32) (string, string, *[]string) {
	return "", "", nil
}

func (m *MockCache) GetWafRuleNames() *[]string {
	return nil
}

func (m *MockCache) GetFedWafGroupSensorCache() ([]*share.CLUSWafSensor, []*share.CLUSWafGroup) {
	return nil, nil
}

func (m *MockCache) AuthorizeCustomCheck(name string, acc *access.AccessControl) bool {
	return false
}

func (m *MockCache) AuthorizeFileMonitorProfile(name string, acc *access.AccessControl) bool {
	return false
}

func (m *MockCache) PutCustomRoles(roles map[string]*share.CLUSUserRole) {}

func (m *MockCache) GetPwdProfile(name string) (share.CLUSPwdProfile, error) {
	return share.CLUSPwdProfile{}, nil
}

func (m *MockCache) GetAllPwdProfiles() (string, map[string]share.CLUSPwdProfile) {
	return "", nil
}

func (m *MockCache) GetNvUsage(fedRole string) api.RESTNvUsage {
	return api.RESTNvUsage{}
}
