package kv

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

type mockLock struct {
}

func (l *mockLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	var ch <-chan struct{}
	return ch, nil
}

func (l *mockLock) Unlock() error {
	return nil
}

func (l *mockLock) Key() string {
	return ""
}

// --

type MockCluster struct {
	ClusterHelper

	sysconfig            share.CLUSSystemConfig
	customrolesCluster   map[string]*share.CLUSUserRole
	activePwdProfileName string
	pwdProfileCluster    map[string]*share.CLUSPwdProfile
	usersCluster         map[string]*share.CLUSUser
	apikeysCluster       map[string]*share.CLUSApikey
	serversCluster       map[string]*share.CLUSServer
	registries           map[string]*share.CLUSRegistryConfig

	rulesCluster map[uint32]*share.CLUSPolicyRule
	rulesHead    []*share.CLUSRuleHead
	ruleRev      uint64

	groupsCluster map[string]*share.CLUSGroup

	complianceProfiles map[string]*share.CLUSComplianceProfile

	awsCloudResource map[string]*share.CLUSAwsResource
	awsProjectCfg    map[string]*share.CLUSAwsProjectCfg

	ScanSums map[string]*share.CLUSRegistryImageSummary
	ScanRpts map[string]*share.CLUSScanReport

	DeletePolicyRuleCount uint

	FedMembership share.CLUSFedMembership

	mockKvRoleConfigUpdateFunc   MockKvConfigUpdateFunc
	mockKvSystemConfigUpdateFunc MockKvConfigUpdateFunc
	kv                           map[string]string
}

func (m *MockCluster) Init(rules []*share.CLUSPolicyRule, groups []*share.CLUSGroup) {
	clusHelper = m

	m.rulesCluster = make(map[uint32]*share.CLUSPolicyRule)
	m.groupsCluster = make(map[string]*share.CLUSGroup)

	for _, r := range rules {
		cr := *r
		m.rulesCluster[r.ID] = &cr
		//m.rulesHead = append(m.rulesHead, &share.CLUSRuleHead{r.ID, r.CfgType, r.GroundRule})
		m.rulesHead = append(m.rulesHead, &share.CLUSRuleHead{ID: r.ID, CfgType: r.CfgType})
	}
	for _, g := range groups {
		cg := *g
		m.groupsCluster[g.Name] = &cg
	}

	m.customrolesCluster = make(map[string]*share.CLUSUserRole)
	m.pwdProfileCluster = make(map[string]*share.CLUSPwdProfile)
	m.activePwdProfileName = share.CLUSDefPwdProfileName
	m.usersCluster = make(map[string]*share.CLUSUser)
	m.apikeysCluster = make(map[string]*share.CLUSApikey)
	m.serversCluster = make(map[string]*share.CLUSServer)
	m.registries = make(map[string]*share.CLUSRegistryConfig)

	m.ScanSums = make(map[string]*share.CLUSRegistryImageSummary, 0)
	m.ScanRpts = make(map[string]*share.CLUSScanReport, 0)

	m.complianceProfiles = map[string]*share.CLUSComplianceProfile{
		"default": {
			Name:          "default",
			DisableSystem: false,
			Entries:       make(map[string]share.CLUSComplianceProfileEntry),
		},
	}

	m.awsCloudResource = make(map[string]*share.CLUSAwsResource)
	m.awsProjectCfg = make(map[string]*share.CLUSAwsProjectCfg)
	m.kv = make(map[string]string)
}

func (m *MockCluster) AcquireLock(key string, wait time.Duration) (cluster.LockInterface, error) {
	return &mockLock{}, nil
}

func (m *MockCluster) ReleaseLock(lock cluster.LockInterface) {
}

func (m *MockCluster) GetInstallationID() (string, error) {
	return "de05813de8ef2a7dc9858394ae06ae4b", nil
}

func (m *MockCluster) GetFedMembership() *share.CLUSFedMembership {
	return &m.FedMembership
}

func (m *MockCluster) GetAllCustomRoles(acc *access.AccessControl) map[string]*share.CLUSUserRole {
	return m.customrolesCluster
}

func (m *MockCluster) GetCustomRoleRev(name string, acc *access.AccessControl) (*share.CLUSUserRole, uint64, error) {
	if role, ok := m.customrolesCluster[name]; ok {
		return role, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) PutCustomRoleRev(role *share.CLUSUserRole, rev uint64, acc *access.AccessControl) error {
	m.customrolesCluster[role.Name] = role
	if m.mockKvRoleConfigUpdateFunc != nil {
		value, _ := json.Marshal(*role)
		m.mockKvRoleConfigUpdateFunc(cluster.ClusterNotifyModify, share.CLUSUserRoleKey(role.Name), value)
	}

	return nil
}

func (m *MockCluster) CreateCustomRole(role *share.CLUSUserRole, acc *access.AccessControl) error {
	m.customrolesCluster[role.Name] = role
	if m.mockKvRoleConfigUpdateFunc != nil {
		value, _ := json.Marshal(*role)
		m.mockKvRoleConfigUpdateFunc(cluster.ClusterNotifyAdd, share.CLUSUserRoleKey(role.Name), value)
	}

	return nil
}

func (m *MockCluster) DeleteCustomRole(name string) error {
	if _, ok := m.customrolesCluster[name]; ok {
		delete(m.customrolesCluster, name)
		if m.mockKvRoleConfigUpdateFunc != nil {
			m.mockKvRoleConfigUpdateFunc(cluster.ClusterNotifyDelete, share.CLUSUserRoleKey(name), nil)
		}
		return nil
	} else {
		return errors.New("Custom role not exist.")
	}
}

func (m *MockCluster) GetAllPwdProfiles(acc *access.AccessControl) map[string]*share.CLUSPwdProfile {
	if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
		return make(map[string]*share.CLUSPwdProfile)
	}

	return m.pwdProfileCluster
}

func (m *MockCluster) GetPwdProfileRev(name string, acc *access.AccessControl) (*share.CLUSPwdProfile, uint64, error) {
	if profile, ok := m.pwdProfileCluster[name]; ok {
		if !acc.Authorize(profile, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}
		return profile, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) PutPwdProfileRev(profile *share.CLUSPwdProfile, rev uint64) error {
	m.pwdProfileCluster[profile.Name] = profile
	return nil
}

func (m *MockCluster) DeletePwdProfile(name string) error {
	if _, ok := m.pwdProfileCluster[name]; ok {
		delete(m.pwdProfileCluster, name)
		return nil
	} else {
		return errors.New("Password profile not exist.")
	}
}

func (m *MockCluster) GetActivePwdProfileName() string {
	return m.activePwdProfileName
}

func (m *MockCluster) PutActivePwdProfileName(name string) error {
	m.activePwdProfileName = name
	return nil
}

func (m *MockCluster) GetUserRev(fullname string, acc *access.AccessControl) (*share.CLUSUser, uint64, error) {
	if user, ok := m.usersCluster[fullname]; ok {
		// REST code modify the object before writing to the cluster. Create a copy to protect the original data.
		var clone share.CLUSUser
		value, _ := json.Marshal(user)
		_ = json.Unmarshal(value, &clone)
		if !acc.Authorize(&clone, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}
		return &clone, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) GetAllUsers(acc *access.AccessControl) map[string]*share.CLUSUser {
	return m.usersCluster
}

func (m *MockCluster) GetAllUsersNoAuth() map[string]*share.CLUSUser {
	return m.usersCluster
}

func (m *MockCluster) PutUserRev(user *share.CLUSUser, rev uint64) error {
	clone := *user
	m.usersCluster[user.Fullname] = &clone
	return nil
}

func (m *MockCluster) CreateUser(user *share.CLUSUser) error {
	clone := *user
	m.usersCluster[user.Fullname] = &clone
	return nil
}

func (m *MockCluster) DeleteUser(fullname string) error {
	if _, ok := m.usersCluster[fullname]; ok {
		delete(m.usersCluster, fullname)
		return nil
	} else {
		return common.ErrObjectNotFound
	}
}

func (m *MockCluster) GetSystemConfigRev(acc *access.AccessControl) (*share.CLUSSystemConfig, uint64) {
	// Make copy
	cfg := m.sysconfig
	return &cfg, 0
}

func (m *MockCluster) PutSystemConfigRev(conf *share.CLUSSystemConfig, rev uint64) error {
	m.sysconfig = *conf
	if m.mockKvSystemConfigUpdateFunc != nil {
		value, _ := json.Marshal(*conf)
		m.mockKvSystemConfigUpdateFunc(cluster.ClusterNotifyModify, share.CLUSConfigSystemKey, value)
	}
	return nil
}

func (m *MockCluster) GetRegistry(name string, acc *access.AccessControl) (*share.CLUSRegistryConfig, uint64, error) {
	if r, ok := m.registries[name]; ok {
		if !acc.Authorize(r, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}
		return r, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) GetAllRegistry(scope string) []*share.CLUSRegistryConfig {
	list := make([]*share.CLUSRegistryConfig, 0)
	for _, r := range m.registries {
		list = append(list, r)
	}
	return list
}

func (m *MockCluster) PutRegistry(config *share.CLUSRegistryConfig, rev uint64) error {
	m.registries[config.Name] = config
	return nil
}

func (m *MockCluster) PutRegistryIfNotExist(config *share.CLUSRegistryConfig) error {
	if _, ok := m.registries[config.Name]; ok {
		return common.ErrObjectExists
	}
	return m.PutRegistry(config, 0)
}

func (m *MockCluster) DeleteRegistry(txn *cluster.ClusterTransact, name string) error {
	if _, ok := m.registries[name]; ok {
		delete(m.registries, name)
		return nil
	}
	return common.ErrObjectNotFound
}

func (m *MockCluster) GetAllGroups(scope string, acc *access.AccessControl) map[string]*share.CLUSGroup {
	return m.groupsCluster
}

func (m *MockCluster) DoesGroupExist(name string, acc *access.AccessControl) bool {
	_, ok := m.groupsCluster[name]
	return ok
}

func (m *MockCluster) GetGroup(name string, acc *access.AccessControl) (*share.CLUSGroup, uint64, error) {
	if g, ok := m.groupsCluster[name]; ok {
		return g, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) PutGroup(group *share.CLUSGroup, create bool) error {
	if _, ok := m.groupsCluster[group.Name]; ok && create {
		return common.ErrObjectExists
	}
	m.groupsCluster[group.Name] = group
	return nil
}

func (m *MockCluster) DeleteGroup(name string) error {
	if _, ok := m.groupsCluster[name]; ok {
		delete(m.groupsCluster, name)
		return nil
	} else {
		return common.ErrObjectNotFound
	}
}

func (m *MockCluster) GetPolicyRuleList() []*share.CLUSRuleHead {
	return m.rulesHead
}

func (m *MockCluster) PutPolicyRuleList(crhs []*share.CLUSRuleHead) error {
	m.rulesHead = crhs
	return nil
}

func (m *MockCluster) PutPolicyRuleListTxn(txn *cluster.ClusterTransact, crhs []*share.CLUSRuleHead) error {
	return m.PutPolicyRuleList(crhs)
}

func (m *MockCluster) GetPolicyRule(id uint32) (*share.CLUSPolicyRule, uint64) {
	if r, ok := m.rulesCluster[id]; ok {
		return r, m.ruleRev
	} else {
		return nil, 0
	}
}

func (m *MockCluster) PutPolicyRule(rule *share.CLUSPolicyRule) error {
	m.rulesCluster[rule.ID] = rule
	return nil
}

func (m *MockCluster) PutPolicyRuleTxn(txn *cluster.ClusterTransact, rule *share.CLUSPolicyRule) error {
	return m.PutPolicyRule(rule)
}

func (m *MockCluster) PutPolicyRuleRev(rule *share.CLUSPolicyRule, rev uint64) error {
	if m.ruleRev == rev {
		m.rulesCluster[rule.ID] = rule
		return nil
	} else {
		return errors.New("Unmatched revision.")
	}
}

func (m *MockCluster) DeletePolicyRule(id uint32) error {
	if _, ok := m.rulesCluster[id]; ok {
		delete(m.rulesCluster, id)
		return nil
	} else {
		return common.ErrObjectNotFound
	}
}

func (m *MockCluster) DeletePolicyRuleTxn(txn *cluster.ClusterTransact, id uint32) error {
	m.DeletePolicyRuleCount++
	return m.DeletePolicyRule(id)
}

func (m *MockCluster) GetAllServers(acc *access.AccessControl) map[string]*share.CLUSServer {
	return m.serversCluster
}

func (m *MockCluster) GetServerRev(name string, acc *access.AccessControl) (*share.CLUSServer, uint64, error) {
	if s, ok := m.serversCluster[name]; ok {
		return s, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) PutServerRev(server *share.CLUSServer, rev uint64) error {
	m.serversCluster[server.Name] = server
	return nil
}

func (m *MockCluster) PutServerIfNotExist(server *share.CLUSServer) error {
	if _, ok := m.serversCluster[server.Name]; !ok {
		m.serversCluster[server.Name] = server
		return nil
	} else {
		return common.ErrObjectExists
	}
}

func (m *MockCluster) DeleteServer(name string) error {
	delete(m.serversCluster, name)
	return nil
}

func (m *MockCluster) DeleteProcessProfileTxn(txn *cluster.ClusterTransact, group string) error {
	return nil
}

func (m *MockCluster) GetResponseRuleList(policyName string) []*share.CLUSRuleHead {
	return nil
}

func (m *MockCluster) PutRegistryImageSummary(name, id string, sum *share.CLUSRegistryImageSummary) error {
	return nil
}

func (m *MockCluster) DeleteRegistryImageSummaryAndReport(name, id, fedRole string) error {
	return nil
}

func (m *MockCluster) UpdateFedRulesRevision(ruleTypes []string) bool {
	return true
}

func (m *MockCluster) GetProcessProfile(group string) *share.CLUSProcessProfile {
	return &share.CLUSProcessProfile{ // fixed content
		Group:        group,
		AlertDisable: false,
		HashEnable:   false,
		Mode:         share.PolicyActionLearn,
		Process: []*share.CLUSProcessProfileEntry{
			{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
			{Name: "sleep", Path: "/bin/sleep", Action: share.PolicyActionAllow},
		},
	}
}

func (m *MockCluster) PutProcessProfile(group string, pg *share.CLUSProcessProfile) error {
	return nil
}

func (m *MockCluster) GetAllComplianceProfiles(acc *access.AccessControl) []*share.CLUSComplianceProfile {
	list := make([]*share.CLUSComplianceProfile, 0)
	for _, cp := range m.complianceProfiles {
		list = append(list, cp)
	}
	return list
}

func (m *MockCluster) GetComplianceProfile(name string, acc *access.AccessControl) (*share.CLUSComplianceProfile, uint64, error) {
	if cp, ok := m.complianceProfiles[name]; ok {
		clone := *cp
		return &clone, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) PutComplianceProfile(cp *share.CLUSComplianceProfile, rev *uint64) error {
	m.complianceProfiles[cp.Name] = cp
	return nil
}

func (m *MockCluster) PutComplianceProfileIfNotExist(cp *share.CLUSComplianceProfile) error {
	if _, ok := m.complianceProfiles[cp.Name]; !ok {
		m.complianceProfiles[cp.Name] = cp
		return nil
	} else {
		return common.ErrObjectExists
	}
}

func (m *MockCluster) SetCacheMockCallback(keyStore string, mockFunc MockKvConfigUpdateFunc) {
	switch keyStore {
	case share.CLUSConfigUserRoleStore:
		m.mockKvRoleConfigUpdateFunc = mockFunc
	case share.CLUSConfigSystemKey:
		m.mockKvSystemConfigUpdateFunc = mockFunc
	}
}

func (m *MockCluster) GetAwsCloudResource(projectName string) (*share.CLUSAwsResource, error) {
	if r, ok := m.awsCloudResource[projectName]; ok {
		clone := *r
		return &clone, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m *MockCluster) GetAwsProjectCfg(projectName string, acc *access.AccessControl) (*share.CLUSAwsProjectCfg, error) {
	if r, ok := m.awsProjectCfg[projectName]; ok {
		clone := *r
		if !acc.Authorize(&clone, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return &clone, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m *MockCluster) GetAllCustomCheckConfig() map[string]*share.CLUSCustomCheckGroup {
	return make(map[string]*share.CLUSCustomCheckGroup)
}

func (m *MockCluster) PutRegistryImageSummaryAndReport(name, id, fedRole string, sum *share.CLUSRegistryImageSummary, report *share.CLUSScanReport) error {
	m.ScanSums[share.CLUSRegistryImageStateKey(name, id)] = sum
	m.ScanRpts[share.CLUSRegistryImageDataKey(name, id)] = report
	return nil
}

func (m *MockCluster) GetScanReport(key string) *share.CLUSScanReport {
	if rpt, ok := m.ScanRpts[key]; ok {
		return rpt
	} else {
		return nil
	}
}

func (m *MockCluster) GetApikeyRev(fullname string, acc *access.AccessControl) (*share.CLUSApikey, uint64, error) {
	if user, ok := m.apikeysCluster[fullname]; ok {
		// REST code modify the object before writing to the cluster. Create a copy to protect the original data.
		var clone share.CLUSApikey
		value, _ := json.Marshal(user)
		_ = json.Unmarshal(value, &clone)
		if !acc.Authorize(&clone, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}
		return &clone, 0, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m *MockCluster) GetAllApikeysNoAuth() map[string]*share.CLUSApikey {
	return m.apikeysCluster
}

func (m *MockCluster) CreateApikey(apikey *share.CLUSApikey) error {
	clone := *apikey
	m.apikeysCluster[apikey.Name] = &clone
	return nil
}

func (m *MockCluster) DeleteApikey(name string) error {
	if _, ok := m.apikeysCluster[name]; ok {
		delete(m.apikeysCluster, name)
		return nil
	} else {
		return common.ErrObjectNotFound
	}
}

func (m MockCluster) PutObjectCert(cn, keyPath, certPath string, cert *share.CLUSX509Cert) error {
	value, _ := json.Marshal(cert)
	m.kv[cn] = string(value)
	return nil
}

func (m MockCluster) PutObjectCertMemory(cn string, in *share.CLUSX509Cert, out *share.CLUSX509Cert, index uint64) error {
	v, ok := m.kv[cn]
	// Only use existing value when index = 0.
	// When index > 0 => force write.
	if ok && index == 0 {
		if out != nil {
			err := json.Unmarshal([]byte(v), &out)
			if err != nil {
				return err
			}
		}
		return nil
	}
	buf, err := json.Marshal(in)
	if err != nil {
		return err
	}
	m.kv[cn] = string(buf)
	if out != nil {
		*out = *in
	}
	return nil
}

func (m MockCluster) GetObjectCertRev(cn string) (*share.CLUSX509Cert, uint64, error) {
	out := share.CLUSX509Cert{}
	v, ok := m.kv[cn]
	if !ok {
		return nil, 0, cluster.ErrKeyNotFound
	}
	err := json.Unmarshal([]byte(v), &out)
	if err != nil {
		return nil, 0, errors.New("failed to unmarshal")
	}
	return &out, 1, nil
}
