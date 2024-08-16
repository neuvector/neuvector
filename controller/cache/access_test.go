package cache

import (
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const D1 string = "d1"
const D2 string = "d2"
const S1 string = "s1.d1"
const S2 string = "s2.d2"
const G1 string = "nv." + S1
const G2 string = "nv." + S2

func TestAccessResource(t *testing.T) {
	preTest()

	wl1 := share.CLUSWorkload{ID: "1", Name: "c1", Domain: D1, Service: S1}
	wlCacheMap[wl1.ID] = &workloadCache{workload: &wl1, displayName: "container1"}
	wl2 := share.CLUSWorkload{ID: "2", Name: "c2", Domain: D2, Service: S2}
	wlCacheMap[wl2.ID] = &workloadCache{workload: &wl2, displayName: "container2"}

	r, _ := http.NewRequest(http.MethodGet, "https://10.1.1.1/v1/workload", nil)
	acc := access.NewAccessControl(r, access.AccessOPRead, map[string]string{D1: api.UserRoleAdmin}, nil)
	accReadAll := access.NewReaderAccessControl()

	idlist := utils.NewSet()
	wls := cacher.GetAllWorkloads("", accReadAll, idlist)
	if len(wls) != 2 {
		t.Errorf("Expecte 2 containers, but returned %d \n", len(wls))
	}

	wls = cacher.GetAllWorkloads("", acc, idlist)
	if len(wls) != 1 {
		t.Errorf("Expected 1 container, but returned %d \n", len(wls))
	} else if wls[0].ID != "1" {
		t.Errorf("Expected container 1, but returned container %s \n", wls[0].ID)
	}

	wlCacheMap = make(map[string]*workloadCache, 0)
	postTest()
}

func TestAccessGroup(t *testing.T) {
	preTest()

	g1 := share.CLUSGroup{Name: G1, Domain: D1, CfgType: share.Learned}
	groupCacheMap[g1.Name] = &groupCache{
		group:               &g1,
		usedByPolicy:        utils.NewSet(),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(G1),
	}
	g2 := share.CLUSGroup{Name: G2, Domain: D2, CfgType: share.Learned}
	groupCacheMap[g2.Name] = &groupCache{
		group:               &g2,
		usedByPolicy:        utils.NewSet(),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(G2),
	}

	r, _ := http.NewRequest(http.MethodGet, "https://10.1.1.1/v1/group", nil)
	acc := access.NewAccessControl(r, access.AccessOPRead, map[string]string{D1: api.UserRoleAdmin}, nil)
	accReadAll := access.NewReaderAccessControl()

	gpsSlice := cacher.GetAllGroups(share.ScopeLocal, "", false, accReadAll)
	if len(gpsSlice) != 1 {
		t.Errorf("Expected 1 group list, but returned %d \n", len(gpsSlice))
	}
	gps := gpsSlice[0]
	if len(gps) != 2 {
		t.Errorf("Expecte 2 groups, but returned %d \n", len(gps))
	}

	gpsSlice = cacher.GetAllGroups(share.ScopeLocal, "", false, acc)
	if len(gpsSlice) != 1 {
		t.Errorf("Expected 1 group list, but returned %d \n", len(gpsSlice))
	} else {
		gps = gpsSlice[0]
		if gps[0].Name != G1 {
			t.Errorf("Expected group %s, but returned group %s \n", G1, gps[0].Name)
		}
	}

	groupCacheMap = make(map[string]*groupCache, 0)
	postTest()
}

func TestAccessPolicy(t *testing.T) {
	preTest()

	g1 := share.CLUSGroup{Name: "g1", Domain: "d1", CfgType: share.Learned}
	groupCacheMap[g1.Name] = &groupCache{
		group:               &g1,
		usedByPolicy:        utils.NewSet(10001, 10002, 1),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(),
	}
	g2 := share.CLUSGroup{Name: "g2", Domain: "d2", CfgType: share.Learned}
	groupCacheMap[g2.Name] = &groupCache{
		group:               &g2,
		usedByPolicy:        utils.NewSet(10001),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(),
	}
	g3 := share.CLUSGroup{Name: "nv.external", Domain: "", CfgType: share.UserCreated}
	groupCacheMap[g3.Name] = &groupCache{
		group:               &g3,
		usedByPolicy:        utils.NewSet(10002),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(),
	}
	g4 := share.CLUSGroup{Name: "g4", Domain: "", CfgType: share.UserCreated, CreaterDomains: []string{"d2", "d3"}}
	groupCacheMap[g4.Name] = &groupCache{
		group:               &g4,
		usedByPolicy:        utils.NewSet(1),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(),
	}

	r1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	r2 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "nv.external", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	r3 := share.CLUSPolicyRule{
		ID: 1, From: "g1", To: "g4", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}

	rhs := []*share.CLUSRuleHead{
		&share.CLUSRuleHead{ID: r1.ID, CfgType: r1.CfgType},
		&share.CLUSRuleHead{ID: r2.ID, CfgType: r2.CfgType},
		&share.CLUSRuleHead{ID: r3.ID, CfgType: r3.CfgType},
	}
	policyCache.ruleMap[r1.ID] = &r1
	policyCache.ruleMap[r2.ID] = &r2
	policyCache.ruleMap[r3.ID] = &r3
	policyCache.ruleHeads = rhs
	policyCache.ruleOrderMap = ruleHeads2OrderMap(rhs)

	r, _ := http.NewRequest(http.MethodGet, "https://10.1.1.1/v1/policy/rule", nil)
	// test
	acc := access.NewAccessControl(r, access.AccessOPRead, map[string]string{"d1": api.UserRoleAdmin}, nil)
	n := cacher.GetPolicyRuleCount(acc)
	if n != 3 {
		t.Errorf("Expected group count 3, but got %d\n", n)
	}

	acc = access.NewAccessControl(r, access.AccessOPRead, map[string]string{"d2": api.UserRoleAdmin}, nil)
	n = cacher.GetPolicyRuleCount(acc)
	if n != 2 {
		t.Errorf("Expected group count 2, but got %d\n", n)
	}

	acc = access.NewAccessControl(r, access.AccessOPRead, map[string]string{"d3": api.UserRoleAdmin}, nil)
	n = cacher.GetPolicyRuleCount(acc)
	if n != 1 {
		t.Errorf("Expected group count 1, but got %d\n", n)
	}

	acc = access.NewAccessControl(r, access.AccessOPRead, map[string]string{"d4": api.UserRoleAdmin}, nil)
	n = cacher.GetPolicyRuleCount(acc)
	if n != 0 {
		t.Errorf("Expected group count 0, but got %d\n", n)
	}

	// cleanup
	groupCacheMap = make(map[string]*groupCache, 0)
	policyCache = policyCacheType{
		ruleMap:      make(map[uint32]*share.CLUSPolicyRule),
		ruleHeads:    make([]*share.CLUSRuleHead, 0),
		ruleOrderMap: make(map[uint32]int, 0),
	}

	postTest()
}
