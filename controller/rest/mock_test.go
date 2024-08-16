package rest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type mockResponseWriter struct {
	status int
	body   []byte
}

var ctx Context

func (m *mockResponseWriter) Header() (h http.Header) {
	return http.Header{}
}

func (m *mockResponseWriter) Write(p []byte) (n int, err error) {
	m.body = make([]byte, len(p))
	copy(m.body, p)
	return len(p), nil
}

func (m *mockResponseWriter) WriteString(s string) (n int, err error) {
	return len(s), nil
}

func (m *mockResponseWriter) WriteHeader(status int) {
	m.status = status
}

type mockScan struct {
	scan.ScanInterface
}

func (m *mockScan) GetRegistryState(name string, acc *access.AccessControl) (*share.CLUSRegistryState, error) {
	return &share.CLUSRegistryState{Status: api.RegistryStatusIdle}, nil
}

// --

type mockCache struct {
	cache.CacheInterface

	rules            map[uint32]*api.RESTPolicyRule
	ruleHeads        []*share.CLUSRuleHead
	systemConfig     api.RESTSystemConfig
	groups           map[string]*api.RESTGroup
	filters          map[string][]*api.RESTFileMonitorFilter
	profiles         map[string][]*api.RESTProcessProfileEntry
	cps              map[string]*api.RESTComplianceProfile
	pwdProfiles      map[string]*share.CLUSPwdProfile
	activePwdProfile string
}

func (m *mockCache) Group2CLUS(group *api.RESTGroup) *share.CLUSGroup {
	c := share.CLUSGroup{
		Name:           group.Name,
		Learned_UNUSED: group.Learned,
		Reserved:       group.Reserved,
		PolicyMode:     group.PolicyMode,
		NotScored:      group.NotScored,
		Domain:         group.Domain,
		CreaterDomains: make([]string, len(group.CreaterDomains)),
		Kind:           group.Kind,
		PlatformRole:   group.PlatformRole,
		Criteria:       make([]share.CLUSCriteriaEntry, len(group.Criteria)),
	}
	c.CfgType, _ = cfgTypeMapping[group.CfgType]
	for i, d := range group.CreaterDomains {
		c.CreaterDomains[i] = d
	}
	for i, crt := range group.Criteria {
		c.Criteria[i] = share.CLUSCriteriaEntry{
			Key: crt.Key, Value: crt.Value, Op: crt.Op,
		}
	}

	return &c
}

func (m *mockCache) Policy2CLUS(rule *api.RESTPolicyRule) *share.CLUSPolicyRule {
	c := share.CLUSPolicyRule{
		ID:             rule.ID,
		Comment:        rule.Comment,
		From:           rule.From,
		To:             rule.To,
		Ports:          rule.Ports,
		Action:         rule.Action,
		Learned_UNUSED: rule.Learned,
		Disable:        rule.Disable,
		CreatedAt:      time.Unix(rule.CreatedTS, 0),
		LastModAt:      time.Unix(rule.LastModTS, 0),
		Priority:       rule.Priority,
		Applications:   appNames2IDs(rule.Applications),
	}
	c.CfgType, _ = cfgTypeMapping[rule.CfgType]

	return &c
}

func (m *mockCache) GetCurrentLicense(acc *access.AccessControl) api.RESTLicenseInfo {
	return api.RESTLicenseInfo{}
}

func (m *mockCache) GetSystemConfig(acc *access.AccessControl) *api.RESTSystemConfig {
	return &m.systemConfig
}

func (m *mockCache) GetPolicyRule(id uint32, acc *access.AccessControl) (*api.RESTPolicyRule, error) {
	if r, ok := m.rules[id]; ok {
		return r, nil
	} else if !acc.Authorize(&share.CLUSPolicyRule{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) GetAllPolicyRules(scope string, acc *access.AccessControl) []*api.RESTPolicyRule {
	var getLocal, getFed bool
	switch scope {
	case share.ScopeLocal:
		getLocal = true
	case share.ScopeFed:
		getFed = true
	case share.ScopeAll:
		getLocal = true
		getFed = true
	}

	getAccessObjectFuncNoLock := func(groupName string) share.AccessObject {
		if g, ok := m.groups[groupName]; ok {
			return m.Group2CLUS(g)
		}
		return nil
	}

	rules := make([]*api.RESTPolicyRule, 0, len(m.ruleHeads))
	for _, rh := range m.ruleHeads {
		if rule, ok := m.rules[rh.ID]; ok {
			if (rule.CfgType == api.CfgTypeFederal && getFed) || (rule.CfgType != api.CfgTypeFederal && getLocal) {
				ruleCLUS := m.Policy2CLUS(rule)
				if !acc.Authorize(ruleCLUS, getAccessObjectFuncNoLock) {
					continue
				}
				rules = append(rules, rule)
			}
		}
	}

	return rules
}

func (m *mockCache) CheckPolicyRuleAccess(id uint32, accRead *access.AccessControl, accWrite *access.AccessControl) (bool, bool, bool) {
	var found bool
	var readable, writable bool

	if ruleREST, ok := m.rules[id]; ok {
		found = true
		rule := m.Policy2CLUS(ruleREST)

		getAccessObjectFuncNoLock := func(groupName string) share.AccessObject {
			if g, ok := m.groups[groupName]; ok {
				return m.Group2CLUS(g)
			}
			return nil
		}

		if accRead.Authorize(rule, getAccessObjectFuncNoLock) {
			readable = true
		}
		if accWrite.Authorize(rule, getAccessObjectFuncNoLock) {
			writable = true
		}
	}

	return found, readable, writable
}

func (m *mockCache) GetPolicyRuleCache(id uint32, acc *access.AccessControl) (*share.CLUSPolicyRule, error) {
	if rule, ok := m.rules[id]; ok {
		r := &share.CLUSPolicyRule{
			ID:           rule.ID,
			Comment:      rule.Comment,
			From:         rule.From,
			To:           rule.To,
			Ports:        rule.Ports,
			Applications: appNames2IDs(rule.Applications),
			Action:       rule.Action,
			Disable:      rule.Disable,
			CreatedAt:    time.Unix(rule.CreatedTS, 0),
			LastModAt:    time.Unix(rule.LastModTS, 0),
		}
		r.CfgType = cfgTypeMapping[rule.CfgType]
		return r, nil
	} else if !acc.Authorize(&share.CLUSPolicyRule{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) DoesGroupExist(name string, acc *access.AccessControl) (bool, error) {
	if _, ok := m.groups[name]; ok {
		return true, nil
	} else if !acc.Authorize(&share.CLUSGroup{}, nil) {
		return false, common.ErrObjectAccessDenied
	}
	return false, common.ErrObjectNotFound
}

func (m *mockCache) GetService(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTService, error) {
	gname := api.LearnedGroupPrefix + name
	if g, ok := m.groups[gname]; ok {
		idx := len(api.LearnedGroupPrefix)
		s := &api.RESTService{
			Name:       g.Name[idx:],
			PolicyMode: g.PolicyMode,
			Domain:     g.Domain,
		}

		return s, nil
	} else if !acc.Authorize(&share.CLUSGroup{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) CreateService(svc *api.RESTServiceConfig, acc *access.AccessControl) error {
	svcName := utils.MakeServiceName(svc.Domain, svc.Name)
	name := api.LearnedGroupPrefix + utils.NormalizeForURL(svcName)
	if _, ok := m.groups[name]; ok {
		return common.ErrObjectExists
	} else {
		cg := &api.RESTGroup{
			RESTGroupBrief: api.RESTGroupBrief{
				Name:    name,
				CfgType: api.CfgTypeLearned,
				Domain:  svc.Domain,
				Kind:    share.GroupKindContainer,
			},
		}
		m.groups[name] = cg

		rg := share.CLUSGroup{
			Name:    name,
			CfgType: share.Learned,
			Domain:  svc.Domain,
			Kind:    share.GroupKindContainer,
		}
		clusHelper.PutGroup(&rg, true)
		return nil
	}
}

func (m *mockCache) GetGroupBrief(name string, withCap bool, acc *access.AccessControl) (*api.RESTGroupBrief, error) {
	if g, ok := m.groups[name]; ok {
		return &g.RESTGroupBrief, nil
	} else if !acc.Authorize(&share.CLUSGroup{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) GetGroup(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroup, error) {
	if g, ok := m.groups[name]; ok {
		return g, nil
	} else if !acc.Authorize(&share.CLUSGroup{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) GetAllHosts(acc *access.AccessControl) []*api.RESTHost {
	return nil
}

func appIDs2Names(ids []uint32) []string {
	if ids == nil {
		return []string{api.PolicyAppAny}
	}

	var names []string = make([]string, 0)
	for _, id := range ids {
		if name, ok := common.AppNameMap[id]; ok {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return []string{api.PolicyAppAny}
	}

	sort.Strings(names)
	return names
}

func (m *mockCache) Group2REST(group *share.CLUSGroup) *api.RESTGroup {
	g := api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name:           group.Name,
			Domain:         group.Domain,
			CreaterDomains: make([]string, len(group.CreaterDomains)),
		},
	}
	for idx, cd := range group.CreaterDomains {
		g.CreaterDomains[idx] = cd
	}
	g.CfgType, _ = cfgTypeMap2Api[group.CfgType]
	return &g
}

func (m *mockCache) PolicyRule2RuleHead(rule *share.CLUSPolicyRule) *share.CLUSRuleHead {
	rh := &share.CLUSRuleHead{
		ID:      rule.ID,
		CfgType: rule.CfgType,
	}
	return rh
}

func (m *mockCache) PolicyRule2REST(rule *share.CLUSPolicyRule) *api.RESTPolicyRule {
	r := api.RESTPolicyRule{
		ID:           rule.ID,
		Comment:      rule.Comment,
		From:         rule.From,
		To:           rule.To,
		Ports:        rule.Ports,
		Applications: appIDs2Names(rule.Applications),
		Action:       rule.Action,
		Disable:      rule.Disable,
	}
	r.CfgType = cfgTypeMap2Api[rule.CfgType]
	return &r
}

func (m *mockCache) GetFedMembershipRole(acc *access.AccessControl) (string, error) {
	return api.FedRoleMaster, nil
}

func (m *mockCache) GetFedMembershipRoleNoAuth() string {
	return api.FedRoleMaster
}

func (m mockCache) GetFedJoinedClusterIdMap(acc *access.AccessControl) map[string]bool {
	return nil
}

func (m *mockCache) GetFedJoinedClusterNameList(acc *access.AccessControl) []string {
	return nil
}

func (m *mockCache) GetFedJoinedClusterCount() int {
	return 0
}

func (m *mockCache) DeleteResource(rt string, res interface{}) error {
	return nil
}

func (m *mockCache) GetFileMonitorProfile(name string, acc *access.AccessControl, predefined bool) (*api.RESTFileMonitorProfile, error) {
	if ff, ok := m.filters[name]; ok {
		profile := &api.RESTFileMonitorProfile{Group: name, Filters: ff}
		return profile, nil
	} else if !acc.Authorize(&share.CLUSFileMonitorProfile{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) GetProcessProfile(group string, acc *access.AccessControl) (*api.RESTProcessProfile, error) {
	if pp, ok := m.profiles[group]; ok {
		resp := &api.RESTProcessProfile{
			Group:       group,
			Mode:        share.PolicyModeLearn,
			ProcessList: pp,
		}
		return resp, nil
	} else if !acc.Authorize(&share.CLUSProcessProfile{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return nil, common.ErrObjectNotFound
}

func (m *mockCache) GetComplianceProfile(name string, acc *access.AccessControl) (*api.RESTComplianceProfile, map[string][]string, error) {
	if cp, ok := m.cps[name]; ok {
		filter := make(map[string][]string)
		// First create user override entries
		for _, e := range cp.Entries {
			filter[e.TestNum] = e.Tags
		}

		// Add checks that are not in the override list
		scanUtils.InitComplianceMeta("", "", "")
		_, metaMap := scanUtils.GetComplianceMeta(scanUtils.V1)
		for _, m := range metaMap {
			if _, ok := filter[m.TestNum]; !ok {
				var tags []string
				for _, complianceTag := range m.Tags {
					tags = append(tags, complianceTag)
				}
				filter[m.TestNum] = tags
			}
		}

		return cp, filter, nil
	} else if !acc.Authorize(&share.CLUSComplianceProfile{}, nil) {
		return nil, nil, common.ErrObjectAccessDenied
	}
	return nil, nil, common.ErrObjectNotFound
}

func (m *mockCache) GetAllComplianceProfiles(acc *access.AccessControl) []*api.RESTComplianceProfile {
	cps := make([]*api.RESTComplianceProfile, 0, len(m.cps))
	for _, cp := range m.cps {
		cps = append(cps, cp)
	}
	return cps
}

func (m *mockCache) PutCustomRoles(roles map[string]*share.CLUSUserRole) {
}

func (m *mockCache) GetPwdProfile(name string) (share.CLUSPwdProfile, error) {
	if m.pwdProfiles != nil {
		if profile, ok := m.pwdProfiles[name]; ok {
			return *profile, nil
		}
	}
	return share.CLUSPwdProfile{}, common.ErrObjectNotFound
}

func (m *mockCache) GetAllPwdProfiles() (string, map[string]share.CLUSPwdProfile) {
	profiles := make(map[string]share.CLUSPwdProfile, len(m.pwdProfiles))
	for name, pwdProfile := range m.pwdProfiles {
		profiles[name] = *pwdProfile
	}

	return m.activePwdProfile, profiles
}

func (m *mockCache) PutPwdProfiles(activeName string, profiles map[string]*share.CLUSPwdProfile) {
	pwdProfiles := make(map[string]*share.CLUSPwdProfile, len(profiles))
	for name, profile := range profiles {
		p := *profile
		pwdProfiles[name] = &p
	}
	m.pwdProfiles = pwdProfiles
	m.activePwdProfile = activeName
}

func (m *mockCache) GetAllControllerRPCEndpoints(acc *access.AccessControl) []*common.RPCEndpoint {
	return []*common.RPCEndpoint{}
}

func (m *mockCache) GetNewServicePolicyMode() (string, string) {
	return share.PolicyModeLearn, share.PolicyModeLearn
}

func (m *mockCache) GetNewServiceProfileBaseline() string {
	return share.ProfileZeroDrift
}

// --

func mockLoginUser(name, role, fedRole string, roleDomains map[string][]string) *loginSession {
	user := &share.CLUSUser{
		Fullname:    name,
		Username:    name,
		Timeout:     common.DefaultIdleTimeout,
		Role:        role,
		RoleDomains: roleDomains,
	}

	login, _ := loginUser(user, nil, nil, "", _interactiveSessionID, "", fedRole, nil)
	return login
}

// --

var router *httprouter.Router

func preTestDebug() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.DebugLevel)
	initTest()
	access.CompileUriPermitsMapping()
}

func preTest() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.FatalLevel)
	initTest()
	access.CompileUriPermitsMapping()
}

func initTest() {
	cctx = &ctx
	localDev = &common.LocalDevice{
		Host:   &share.CLUSHost{ID: "h1"},
		Ctrler: &share.CLUSController{CLUSDevice: share.CLUSDevice{ID: "c1"}},
	}
	evqueue = &cluster.MockEvQueue{}

	// Fake the jwt key pair
	jwtCertState.jwtPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	jwtCertState.jwtPublicKey = &jwtCertState.jwtPrivateKey.PublicKey

	router = httprouter.New()
	router.GET("/v1/system/config", handlerSystemGetConfig)
	router.PATCH("/v1/system/config", handlerSystemConfig)
	router.GET("/v1/system/summary", handlerSystemSummary)

	router.GET("/v1/user", handlerUserList)
	router.POST("/v1/user", handlerUserCreate)
	router.PATCH("/v1/user/:fullname", handlerUserConfig)
	router.DELETE("/v1/user/:fullname", handlerUserDelete)

	router.POST("/v1/auth", handlerAuthLogin)
	router.POST("/v1/auth/:server", handlerAuthLoginServer)
	router.DELETE("/v1/auth", handlerAuthLogout)
	router.POST("/v1/fed_auth", handlerFedAuthLogin)
	router.DELETE("/v1/fed_auth", handlerFedAuthLogout)

	router.GET("/v1/server", handlerServerList)
	router.GET("/v1/server/:name", handlerServerShow)
	router.POST("/v1/server", handlerServerCreate)
	router.PATCH("/v1/server/:name", handlerServerConfig)
	router.PATCH("/v1/server/:name/role/:role", handlerServerRoleGroupsConfig)         // For 4.2(-)
	router.PATCH("/v1/server/:name/group/:group", handlerServerGroupRoleDomainsConfig) // For 4.3(+)
	router.PATCH("/v1/server/:name/groups", handlerServerGroupsOrderConfig)            // For 4.3(+)
	router.DELETE("/v1/server/:name", handlerServerDelete)
	router.GET("/v1/token_auth_server/:server/slo", handlerGenerateSLORequest)

	router.POST("/v1/scan/registry", handlerRegistryCreate)
	router.PATCH("/v1/scan/registry/:name", handlerRegistryConfig)
	router.GET("/v1/scan/registry", handlerRegistryList)
	router.GET("/v1/scan/registry/:name", handlerRegistryShow)
	router.DELETE("/v1/scan/registry/:name", handlerRegistryDelete)

	router.GET("/v1/compliance/available_filter", handlerGetAvaiableComplianceFilter)
	router.GET("/v1/compliance/profile", handlerComplianceProfileList)
	router.GET("/v1/compliance/profile/:name", handlerComplianceProfileShow)
	router.PATCH("/v1/compliance/profile/:name", handlerComplianceProfileConfig)
	router.PATCH("/v1/compliance/profile/:name/entry/:check", handlerComplianceProfileEntryConfig)
	router.DELETE("/v1/compliance/profile/:name/entry/:check", handlerComplianceProfileEntryDelete)

	router.GET("/v1/policy/rule", handlerPolicyRuleList)
	router.GET("/v1/policy/rule/:id", handlerPolicyRuleShow)
	router.PATCH("/v1/policy/rule", handlerPolicyRuleAction)
	router.PATCH("/v1/policy/rule/:id", handlerPolicyRuleConfig)

	router.POST("/v1/service", handlerServiceCreate)
	router.GET("/v1/service/:name", handlerServiceShow)
	router.POST("/v1/group", handlerGroupCreate)
	router.PATCH("/v1/group/:name", handlerGroupConfig)
	router.DELETE("/v1/group/:name", handlerGroupDelete)

	router.GET("/v1/file_monitor/:name", handlerFileMonitorShow)
	router.GET("/v1/process_profile/:name", handlerProcessProfileShow)
	router.PATCH("/v1/process_profile/:name", handlerProcessProfileConfig)

	router.GET("/v1/user_role_permission/options", handlerGetRolePermissionOptions)
	router.GET("/v1/user_role", handlerRoleList)
	router.GET("/v1/user_role/:name", handlerRoleShow)
	router.POST("/v1/user_role", handlerRoleCreate)
	router.PATCH("/v1/user_role/:name", handlerRoleConfig)
	router.DELETE("/v1/user_role/:name", handlerRoleDelete)

	// password profile
	router.GET("/v1/password_profile", handlerPwdProfileList)
	router.GET("/v1/password_profile/:fullname", handlerPwdProfileShow)
	//router.POST("/v1/password_profile", handlerPwdProfileCreate)
	router.PATCH("/v1/password_profile/:fullname", handlerPwdProfileConfig)
	//router.DELETE("/v1/password_profile/:fullname", handlerPwdProfileDelete)

	// only for custom role unittest
	router.POST("/v1/fed/promote", handlerPromoteToMaster)
	router.POST("/v1/fed/join", handlerJoinFed)
	router.POST("/v1/fed/leave", handlerLeaveFed)
	router.POST("/v1/fed/remove_internal", handlerJointKickedInternal) // API not exposed
	router.POST("/v1/fed/command_internal", handlerFedCommandInternal) // API not exposed
	router.PATCH("/v1/fed/config", handlerConfigLocalCluster)
	router.POST("/v1/fed/demote", handlerDemoteFromMaster)
	router.DELETE("/v1/fed/cluster/:id", handlerRemoveJointCluster)
	router.POST("/v1/fed/deploy", handlerDeployFedRules)
	router.POST("/v1/fed/cluster/:id/*request", handlerFedClusterForwardPost)     // API not exposed
	router.PATCH("/v1/fed/cluster/:id/*request", handlerFedClusterForwardPatch)   // API not exposed
	router.DELETE("/v1/fed/cluster/:id/*request", handlerFedClusterForwardDelete) // API not exposed

	// only for custom role unittest
	router.GET("/v1/meter", handlerMeterList)                                       // debug
	router.POST("/v1/debug/controller/sync/:id", handlerDebugControllerSyncRequest) // debug
	router.POST("/v1/controller/:id/profiling", handlerControllerProfiling)         // debug
	router.POST("/v1/enforcer/:id/profiling", handlerAgentProfiling)
	router.DELETE("/v1/conversation_endpoint/:id", handlerConverEndpointDelete) // API not exposed
	router.DELETE("/v1/conversation", handlerConverDeleteAll)                   // API not exposed
	router.DELETE("/v1/session", handlerSessionDelete)

	// only for custom role unittest
	router.GET("/v1/scan/config", handlerScanConfigGet)
	router.GET("/v1/list/registry_type", handlerRegistryTypeList)
	router.GET("/v1/sniffer/:id", handlerSnifferShow)
	router.GET("/v1/controller/:id/config", handlerControllerGetConfig)
	router.GET("/v1/session", handlerSessionList)
	router.GET("/v1/admission/options", handlerGetAdmissionOptions)
	router.GET("/v1/custom_check", handlerCustomCheckList)
	router.GET("/v1/selfuser", handlerSelfUserShow)
	router.GET("/v1/log/threat/:id", handlerThreatShow)
	router.GET("/v1/user/:fullname", handlerUserShow)
	router.GET("/v1/fed/member", handlerGetFedMember)
	router.POST("/v1/scan/repository", handlerScanRepositoryReq)
	router.POST("/v1/sniffer", handlerSnifferStart)

	router.GET("/v1/partner/ibm_sa_ep", handlerGetIBMSASetupURL)                                    // called by NV Manager to get setup URI  like "/v1/partner/ibm_sa/{id}/setup" that is used for IBM SA integration
	router.GET("/v1/partner/ibm_sa_config", handlerGetIBMSAConfig)                                  //
	router.GET("/v1/partner/ibm_sa/:id/setup", handlerGetIBMSAEpSetupToken)                         // Skip API document, called by IBM SA to get token used by POST("/v1/partner/ibm_sa/:id/setup/:action")
	router.GET("/v1/partner/ibm_sa/:id/setup/:info", handlerGetIBMSAEpInfo)                         // Skip API document, called by IBM SA
	router.POST("/v1/partner/ibm_sa/:id/setup/:action", handlerPostIBMSAEpSetup)                    // Skip API document, called by IBM SA
	router.DELETE("/v1/partner/ibm_sa/:id/setup/:accountID/:providerID", handlerDeleteIBMSAEpSetup) // for simulating IBM SA IBM SA to delete the integration.

	// api key
	router.GET("/v1/api_key", handlerApikeyList)
	router.GET("/v1/api_key/:name", handlerApikeyShow)
	router.POST("/v1/api_key", handlerApikeyCreate)
	router.DELETE("/v1/api_key/:name", handlerApikeyDelete)
	router.GET("/v1/selfapikey", handlerSelfApikeyShow) // Skip API document
}

func postTest() {
	log.SetLevel(log.DebugLevel)
}

type jwtSessionMethod struct {
}

func (s *jwtSessionMethod) Associate(key string) error {
	return nil
}

func (s *jwtSessionMethod) Disassociate(key string) error {
	return nil
}

func newJWTExpireSession() {
	jwtLastExpiredTokenSession = new(jwtSessionMethod)
	if time.Since(jwtLastExpiredTokenSessionCreatedAt) > jwtExpiredTokenSessionWindow {
		jwtLastExpiredTokenSessionCreatedAt = time.Now()
	}
}

func restCallFed(method, url string, body []byte, role, fedRole string) *mockResponseWriter {
	w := new(mockResponseWriter)
	r, _ := http.NewRequest(method, url, bytes.NewBuffer(body))

	login := mockLoginUser("admin", role, fedRole, make(map[string][]string))
	r.Header.Add(api.RESTTokenHeader, login.token)

	router.ServeHTTP(w, r)

	newJWTExpireSession()
	login._logout()

	return w
}

func restCall(method, url string, body []byte, role string) *mockResponseWriter {
	w := new(mockResponseWriter)
	r, _ := http.NewRequest(method, url, bytes.NewBuffer(body))

	login := mockLoginUser("admin", role, api.FedRoleNone, make(map[string][]string))
	r.Header.Add(api.RESTTokenHeader, login.token)

	router.ServeHTTP(w, r)

	newJWTExpireSession()
	login._logout()

	return w
}

func restCallWithRole(method, url string, body []byte, role string, roles map[string][]string) *mockResponseWriter {
	w := new(mockResponseWriter)
	r, _ := http.NewRequest(method, url, bytes.NewBuffer(body))

	login := mockLoginUser("admin", role, api.FedRoleNone, roles)
	r.Header.Add(api.RESTTokenHeader, login.token)

	router.ServeHTTP(w, r)

	newJWTExpireSession()
	login._logout()

	return w
}

func restCallToken(method, url string, body []byte, token string) *mockResponseWriter {
	w := new(mockResponseWriter)
	r, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	r.Header.Add(api.RESTTokenHeader, token)
	router.ServeHTTP(w, r)
	return w
}

func login(username, password string) *mockResponseWriter {
	w := new(mockResponseWriter)
	data := api.RESTAuthData{Password: &api.RESTAuthPassword{Username: username, Password: password}}
	body, _ := json.Marshal(data)
	r, _ := http.NewRequest("POST", "/v1/auth", bytes.NewBuffer(body))
	router.ServeHTTP(w, r)
	return w
}

func loginServerPassword(username, password, server string) *mockResponseWriter {
	w := new(mockResponseWriter)
	data := api.RESTAuthData{Password: &api.RESTAuthPassword{Username: username, Password: password}}
	body, _ := json.Marshal(data)
	r, _ := http.NewRequest("POST", "/v1/auth/"+server, bytes.NewBuffer(body))
	router.ServeHTTP(w, r)
	return w
}

func loginServerToken(token, server string) *mockResponseWriter {
	w := new(mockResponseWriter)
	data := api.RESTAuthData{Token: &api.RESTAuthToken{Token: token}}
	body, _ := json.Marshal(data)
	r, _ := http.NewRequest("POST", "/v1/auth/"+server, bytes.NewBuffer(body))
	router.ServeHTTP(w, r)
	return w
}

func loginServerGetSLORedirectURL(token, server string) *mockResponseWriter {
	w := new(mockResponseWriter)
	data := api.RESTTokenRedirect{
		Redirect: "https://localhost/samlslo",
	}
	body, _ := json.Marshal(data)
	r, _ := http.NewRequest("GET", "/v1/token_auth_server/"+server+"/slo", bytes.NewBuffer(body))
	r.Header.Add("X-Auth-Token", token)
	router.ServeHTTP(w, r)
	return w
}

func logout(token string) *mockResponseWriter {
	w := new(mockResponseWriter)
	r, _ := http.NewRequest("DELETE", "/v1/auth", bytes.NewBuffer([]byte{}))
	r.Header.Add(api.RESTTokenHeader, token)

	newJWTExpireSession()
	router.ServeHTTP(w, r)
	return w
}
