package rest

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

func TestProcessProfilePath(t *testing.T) {
	var good = []string{
		"/bin/opt/chmod",
		"/mkdir",
		"/usr/bin/ls",
		"/usr/bin/*",
		"*",
		"/unknown/ssh.ko",
		"",
		"/../../.././usr/bin/elfReader",
		"/../../ping",
		"/bin/../../chmod",
		"/bin/../sbin/ws",
		"        ",
		"    /../../pingSpace   "}

	var bad = []string{
		"/bin/",
		"usr/bin",
		"usr/bin/",
		"/*/*",
		"/../../ping/",
		"/*/*",
		"../",
		"/</ls",
		"/",
		"../../ping",
		"/a<div>/xyz/</div>/zzz",
		"    ../../pingSpaceWithoutStartBackSlash   "}

	t.Logf("\n\n\n good: \n\n\n")
	for _, path := range good {
		norm, ok := ValidProcessProfilePath(path)
		if !ok {
			t.Errorf("good: %v [%v] but failed\n", path, norm)
		} else {
			t.Logf("good: path=%v, norm=%v\n", path, norm)
		}
	}

	t.Logf("\n\n\n bad: \n\n\n")
	for _, path := range bad {
		norm, ok := ValidProcessProfilePath(path)
		if ok {
			t.Errorf("bad: %v [%v] but passed\n", path, norm)
		} else {
			t.Logf("bad: path=%v\n", path)
		}
	}
}

func TestProcessProfileShow(t *testing.T) {
	preTest()

	mc := mockCache{
		groups:   make(map[string]*api.RESTGroup),
		profiles: make(map[string][]*api.RESTProcessProfileEntry),
	}

	mc.groups["external"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "external",
			Kind: share.GroupKindExternal,
		},
	}

	mc.groups["containers"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "contrainers",
			Kind: share.GroupKindContainer,
		},
	}

	mc.groups["nodes"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "nodes",
			Kind: share.GroupKindNode,
		},
	}

	mp := &api.RESTProcessProfileEntry{
		Name:   "sleep",
		Path:   "/bin/sleep",
		Action: share.PolicyActionAllow,
	}

	pp := make([]*api.RESTProcessProfileEntry, 0)
	pp = append(pp, mp)
	mc.profiles["external"] = pp
	mc.profiles["containers"] = pp
	mc.profiles["nodes"] = pp

	//
	cacher = &mc

	// Read existing group
	{
		w := restCall("GET", "/v1/process_profile/containers", nil, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			var resp api.RESTProcessProfileData
			_ = json.Unmarshal(w.body, &resp)
			if !reflect.DeepEqual(resp.Profile.ProcessList, pp) {
				t.Errorf("Status is OK but a wrong content")
				t.Logf("  Resp: %+v\n", resp.Profile.ProcessList)
			}
		} else {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read non-existing group
	{
		w := restCall("GET", "/v1/process_profile/nv.nothing", nil, api.UserRoleAdmin)
		if w.status != http.StatusNotFound {
			t.Errorf("Read non-existing group but Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read an invalid-type group
	{
		w := restCall("GET", "/v1/process_profile/external", nil, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Read an invalid-type group but Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read existing group
	{
		w := restCall("GET", "/v1/process_profile/nodes", nil, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			var resp api.RESTProcessProfileData
			_ = json.Unmarshal(w.body, &resp)
			if !reflect.DeepEqual(resp.Profile.ProcessList, pp) {
				t.Errorf("Status is OK but a wrong content")
				t.Logf("  Resp: %+v\n", resp.Profile.ProcessList)
			}
		} else {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}

func TestProcessProfileConfigAdd(t *testing.T) {
	preTest()

	mc := mockCache{
		groups:   make(map[string]*api.RESTGroup),
		profiles: make(map[string][]*api.RESTProcessProfileEntry),
	}

	mc.groups["external"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "external",
			Kind: share.GroupKindExternal,
		},
	}

	mc.groups["containers"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "contrainers",
			Kind: share.GroupKindContainer,
		},
	}

	mc.groups["nodes"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "nodes",
			Kind: share.GroupKindNode,
		},
	}

	mp := &api.RESTProcessProfileEntry{ // not used: the data-store was referenced to mock cluster, not cacher
		Name:   "sleep",
		Path:   "/bin/sleep",
		Action: share.PolicyActionAllow,
	}

	pp := make([]*api.RESTProcessProfileEntry, 0)
	pp = append(pp, mp)
	mc.profiles["external"] = pp
	mc.profiles["containers"] = pp
	mc.profiles["nodes"] = pp
	cacher = &mc

	//////
	add := api.RESTProcessProfileEntryConfig{
		Name:   "top",
		Path:   "/bin/top",
		Action: share.PolicyActionAllow,
	}

	ppc := make([]api.RESTProcessProfileEntryConfig, 0)
	ppc = append(ppc, add)
	conf := api.RESTProcessProfileConfig{ProcessChgList: &ppc}
	data := api.RESTProcessProfileConfigData{Config: &conf}
	body, _ := json.Marshal(data)

	// Add into an existing group
	{
		w := restCall("PATCH", "/v1/process_profile/containers", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Add into a non-existing group
	{
		w := restCall("PATCH", "/v1/process_profile/nv.nothing", body, api.UserRoleAdmin)
		if w.status != http.StatusNotFound {
			t.Errorf("Read non-existing group but Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read an invalid-type group
	{
		w := restCall("GET", "/v1/process_profile/external", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Read an invalid-type group but Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Add into a "nodes" group
	{
		w := restCall("PATCH", "/v1/process_profile/nodes", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}

func TestProcessProfileConfigDelete(t *testing.T) {
	preTest()

	mc := mockCache{
		groups:   make(map[string]*api.RESTGroup),
		profiles: make(map[string][]*api.RESTProcessProfileEntry),
	}

	mc.groups["containers"] = &api.RESTGroup{
		RESTGroupBrief: api.RESTGroupBrief{
			Name: "contrainers",
			Kind: share.GroupKindContainer,
		},
	}

	mp := &api.RESTProcessProfileEntry{ // not used: the data-store was referenced to mock cluster, not cacher
		Name:   "sleep",
		Path:   "/bin/sleep",
		Action: share.PolicyActionAllow,
	}

	pp := make([]*api.RESTProcessProfileEntry, 0)
	pp = append(pp, mp)
	mc.profiles["containers"] = pp
	cacher = &mc

	//////
	del := api.RESTProcessProfileEntryConfig{
		Name:   "sleep",
		Path:   "/bin/sleep",
		Action: share.PolicyActionAllow,
	}

	ppc := make([]api.RESTProcessProfileEntryConfig, 0)
	ppc = append(ppc, del)
	conf := api.RESTProcessProfileConfig{ProcessDelList: &ppc}
	data := api.RESTProcessProfileConfigData{Config: &conf}
	body, _ := json.Marshal(data)

	// Del existed entry an existing group
	{
		w := restCall("PATCH", "/v1/process_profile/containers", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	//////
	del = api.RESTProcessProfileEntryConfig{
		Name:   "top",
		Path:   "/bin/top",
		Action: share.PolicyActionAllow,
	}

	ppc = make([]api.RESTProcessProfileEntryConfig, 0)
	ppc = append(ppc, del)
	conf = api.RESTProcessProfileConfig{ProcessDelList: &ppc}
	data = api.RESTProcessProfileConfigData{Config: &conf}
	body, _ = json.Marshal(data)

	// Del non-existed entry an existing group
	{
		w := restCall("PATCH", "/v1/process_profile/containers", body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Add into a non-existing group
	{
		w := restCall("PATCH", "/v1/process_profile/nv.nothing", body, api.UserRoleAdmin)
		if w.status != http.StatusNotFound {
			t.Errorf("Read non-existing group but Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}
