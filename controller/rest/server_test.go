package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
)

func TestServerCreate(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	s, _, _ := clusHelper.GetServerRev("s1", accAdmin)
	if s == nil {
		t.Errorf("Failed to get created server.")
		return
	}

	if s.Enable {
		t.Errorf("Server is created disabled.")
	}
	if s.LDAP == nil {
		t.Errorf("Failed to get created LDAP server.")
	}
	if s.LDAP.DefaultRole != "" {
		t.Errorf("Server is created with incorrect role. role=%s", s.LDAP.DefaultRole)
	}

	w = restCall("POST", "/v1/server", body, api.UserRoleAdmin)
	if w.status != http.StatusBadRequest {
		t.Errorf("Cannot create existing server: %v", w.status)
	}

	postTest()
}

func TestServerRole(t *testing.T) { // for 4.2(-)
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people", DefaultRole: "ciops"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN, DefaultRole: &ldap.DefaultRole}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	s, _, _ := clusHelper.GetServerRev("s1", accAdmin)
	if s == nil {
		t.Errorf("Failed to get created server.")
		return
	}

	if s.LDAP == nil {
		t.Errorf("Failed to get LDAP server.")
	}
	if s.LDAP.DefaultRole != api.UserRoleCIOps {
		t.Errorf("Server is created with incorrect role. role=%s", s.LDAP.DefaultRole)
	}

	// Config default role to empty
	ldap.DefaultRole = ""
	lcfg = api.RESTServerLDAPConfig{DefaultRole: &ldap.DefaultRole}
	data = api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Configuring server failed: %v", w.status)
	}

	// Config role mapping with ciops
	ldap.RoleGroups = map[string][]string{"ciops": {"g1", "g2"}}
	lcfg = api.RESTServerLDAPConfig{RoleGroups: &ldap.RoleGroups}
	data = api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Configuring server failed: %v", w.status)
	}

	s, _, _ = clusHelper.GetServerRev("s1", accAdmin)
	if s == nil {
		t.Errorf("Failed to get server.")
		return
	}
	if s.LDAP == nil {
		t.Errorf("Failed to get LDAP server.")
	}
	if len(s.LDAP.GroupMappedRoles) != 2 {
		t.Errorf("Incorrect configuration of role mapping. len=%+v", len(s.LDAP.GroupMappedRoles))
	}
	mappedRoles := s.LDAP.GroupMappedRoles[0]
	if mappedRoles.Group != "g1" || mappedRoles.GlobalRole != "ciops" {
		t.Errorf("Incorrect configuration of role mapping. [0]=%+v", mappedRoles)
	}
	mappedRoles = s.LDAP.GroupMappedRoles[1]
	if mappedRoles.Group != "g2" || mappedRoles.GlobalRole != "ciops" {
		t.Errorf("Incorrect configuration of role mapping. [0]=%+v", mappedRoles)
	}

	postTest()
}

func TestServerRoleNew(t *testing.T) { // for 4.3(+)
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people", DefaultRole: "ciops"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN, DefaultRole: &ldap.DefaultRole}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	s, _, _ := clusHelper.GetServerRev("s1", accAdmin)
	if s == nil {
		t.Errorf("Failed to get created server.")
		return
	}

	if s.LDAP == nil {
		t.Errorf("Failed to get LDAP server.")
	}
	if s.LDAP.DefaultRole != api.UserRoleCIOps {
		t.Errorf("Server is created with incorrect role. role=%s", s.LDAP.DefaultRole)
	}

	// Config default role to empty
	ldap.DefaultRole = ""
	lcfg = api.RESTServerLDAPConfig{DefaultRole: &ldap.DefaultRole}
	data = api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Configuring server failed: %v", w.status)
	}

	// Config role mapping with ciops
	ldap.GroupMappedRoles = []*share.GroupRoleMapping{
		{
			Group:      "g2",
			GlobalRole: "ciops",
		},
		{
			Group:      "g1",
			GlobalRole: "ciops",
		},
	}
	lcfg = api.RESTServerLDAPConfig{GroupMappedRoles: &ldap.GroupMappedRoles}
	data = api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Configuring server failed: %v", w.status)
	}

	s, _, _ = clusHelper.GetServerRev("s1", accAdmin)
	if s == nil {
		t.Errorf("Failed to get server.")
		return
	}
	if s.LDAP == nil {
		t.Errorf("Failed to get LDAP server.")
		return
	}
	if len(s.LDAP.GroupMappedRoles) != 2 {
		t.Errorf("Incorrect configuration of role mapping. len=%+v", len(s.LDAP.GroupMappedRoles))
	}
	mappedRoles := s.LDAP.GroupMappedRoles[0]
	if mappedRoles.Group != "g2" || mappedRoles.GlobalRole != "ciops" {
		t.Errorf("Incorrect configuration of role mapping. [0]=%+v", mappedRoles)
	}
	mappedRoles = s.LDAP.GroupMappedRoles[1]
	if mappedRoles.Group != "g1" || mappedRoles.GlobalRole != "ciops" {
		t.Errorf("Incorrect configuration of role mapping. [1]=%+v", mappedRoles)
	}

	postTest()
}

func TestServerConfig(t *testing.T) { // for 4.2-)
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	// Add admin group map
	{
		url := fmt.Sprintf("/v1/server/%v/role/%v", data.Config.Name, api.UserRoleAdmin)
		cfg := api.RESTServerRoleGroupsConfig{Name: data.Config.Name, Role: api.UserRoleAdmin, Groups: []string{"g1"}}
		cfgdata := api.RESTServerRoleGroupsConfigData{Config: &cfg}
		body, _ := json.Marshal(cfgdata)
		w := restCall("PATCH", url, body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Configuring server failed: %v", w.status)
		}

		var sdata api.RESTServerData
		w = restCall("GET", fmt.Sprintf("/v1/server/%v", data.Config.Name), nil, api.UserRoleAdmin)
		_ = json.Unmarshal(w.body, &sdata)
		if len(sdata.Server.LDAP.GroupMappedRoles) != 1 {
			t.Errorf("Incorrect configuration of group role mapping. len=%+v", len(sdata.Server.LDAP.GroupMappedRoles))
		}
		mappedRoles := sdata.Server.LDAP.GroupMappedRoles[0]
		if mappedRoles.Group != "g1" || mappedRoles.GlobalRole != api.UserRoleAdmin {
			t.Errorf("Server group role mapping is not configured correctly: %v", *mappedRoles)
		}
	}

	postTest()
}

func TestServerConfig2(t *testing.T) { // for 4.2(-)
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	lcfg.RoleGroups = &map[string][]string{
		"ciops":  {"g5", "g4"},
		"admin":  {"g95", "g94"},
		"reader": {"g23"},
	}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	var sdata api.RESTServerData
	w = restCall("GET", fmt.Sprintf("/v1/server/%v", data.Config.Name), nil, api.UserRoleAdmin)
	_ = json.Unmarshal(w.body, &sdata)
	groupRoleMappings := sdata.Server.LDAP.GroupMappedRoles
	expects := []*share.GroupRoleMapping{
		{
			Group:      "g94",
			GlobalRole: "admin",
		},
		{
			Group:      "g95",
			GlobalRole: "admin",
		},
		{
			Group:      "g23",
			GlobalRole: "reader",
		},
		{
			Group:      "g4",
			GlobalRole: "ciops",
		},
		{
			Group:      "g5",
			GlobalRole: "ciops",
		},
	}
	if len(expects) != len(groupRoleMappings) {
		t.Errorf("result len=%v, expect len=%v", len(groupRoleMappings), len(expects))
	} else {
		for idx, groupRoleMapping := range groupRoleMappings {
			expect := expects[idx]
			if groupRoleMapping.Group != expect.Group {
				t.Errorf("[%d] result group=%v, expect group=%v", idx, groupRoleMapping.Group, expect.Group)
			} else if groupRoleMapping.GlobalRole != expect.GlobalRole {
				t.Errorf("[%d] result group global role=%v, expect group global role=%v", idx, groupRoleMapping.GlobalRole, expect.GlobalRole)
			}
		}
	}

	postTest()
}

func TestServerConfigNew(t *testing.T) { // for 4.3(+)
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)

	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	// Add admin group map
	{
		url := fmt.Sprintf("/v1/server/%v/group/%v", data.Config.Name, "g1")
		cfg := api.RESTServerGroupRoleDomainsConfig{
			Name: data.Config.Name,
			GroupRoleMapping: &share.GroupRoleMapping{
				Group:      "g1",
				GlobalRole: api.UserRoleAdmin,
			},
		}
		cfgdata := api.RESTServerGroupRoleDomainsConfigData{Config: &cfg}
		body, _ := json.Marshal(cfgdata)
		w := restCall("PATCH", url, body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Configuring server failed: %v", w.status)
		}

		var sdata api.RESTServerData
		w = restCall("GET", fmt.Sprintf("/v1/server/%v", data.Config.Name), nil, api.UserRoleAdmin)
		_ = json.Unmarshal(w.body, &sdata)
		if len(sdata.Server.LDAP.GroupMappedRoles) != 1 {
			t.Errorf("Incorrect configuration of group role mapping. len=%+v", len(sdata.Server.LDAP.GroupMappedRoles))
		}
		mappedRoles := sdata.Server.LDAP.GroupMappedRoles[0]
		if mappedRoles.Group != "g1" || mappedRoles.GlobalRole != api.UserRoleAdmin {
			t.Errorf("Server group role mapping is not configured correctly: %v", *mappedRoles)
		}

		// case: global domain("") is not supported for role -> domains mapping
		cfgdata.Config.GroupRoleMapping.GlobalRole = api.UserRoleReader
		cfgdata.Config.GroupRoleMapping.RoleDomains = map[string][]string{
			"role-a": {""},
		}
		body, _ = json.Marshal(cfgdata)
		w = restCall("PATCH", url, body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeded. Expect failure")
		}

		// case: None role("") is not supported for role -> domain mapping
		cfgdata.Config.GroupRoleMapping.RoleDomains = map[string][]string{
			"": {"nv-99"},
		}
		body, _ = json.Marshal(cfgdata)
		w = restCall("PATCH", url, body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeded. Expect failure")
		}

		// case: if a specified group has only None global role and no domain role mapped, delete that group's mapping entry
		cfgdata.Config.GroupRoleMapping.GlobalRole = api.UserRoleNone
		cfgdata.Config.GroupRoleMapping.RoleDomains = map[string][]string{}
		body, _ = json.Marshal(cfgdata)
		w = restCall("PATCH", url, body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Configuring server failed. Expect success: %v", w.status)
		}
		var sdata2 api.RESTServerData
		w = restCall("GET", fmt.Sprintf("/v1/server/%v", data.Config.Name), nil, api.UserRoleAdmin)
		_ = json.Unmarshal(w.body, &sdata2)
		if len(sdata2.Server.LDAP.GroupMappedRoles) != 0 {
			t.Errorf("Incorrect configuration of group role mapping. result len=%+v, expect 0", len(sdata2.Server.LDAP.GroupMappedRoles))
		}
	}

	postTest()
}

func TestServerConfigNew2(t *testing.T) { // for 4.3(+)
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
	lcfg.GroupMappedRoles = &[]*share.GroupRoleMapping{
		{
			Group:      "g1",
			GlobalRole: "role-1",
			RoleDomains: map[string][]string{
				"role-a": {"ns1"},
				"role-b": {"ns4", "ns8", "ns7"},
				"role-c": {"ns3", "ns2"},
			},
		},
		{
			Group:      "g1",
			GlobalRole: "role-1",
			RoleDomains: map[string][]string{
				"role-a": {"ns1"},
				"role-b": {"ns4", "ns8", "ns7"},
				"role-c": {"ns3", "ns2"},
			},
		},
	}
	body, _ := json.Marshal(data)
	// case: multiple entries for one group's role mapping
	w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)
	if w.status == http.StatusOK {
		t.Errorf("Creating server succeeded. Expect failure")
	}

	postTest()
}

func compareGroupMappedData(caller string, result, expected []*share.GroupRoleMapping, t *testing.T) {
	if len(result) != len(expected) {
		t.Errorf("[%s] Incorrect configuration of group role mapping. len=%+v, expected=%+v", caller, len(result), len(expected))
	} else {
		for idx, m1 := range result {
			m2 := expected[idx]
			if m1.Group != m2.Group {
				t.Errorf("[%s][idx=%d] Incorrect configuration of group role mapping. Group=%+v, expected=%+v", caller, idx, m1.Group, m2.Group)
			} else if m1.GlobalRole != m2.GlobalRole {
				t.Errorf("[%s][idx=%d] Incorrect configuration of group role mapping. GlobalRole=%+v, expected=%+v", caller, idx, m1.GlobalRole, m2.GlobalRole)
			} else if len(m1.RoleDomains) != len(m2.RoleDomains) {
				t.Errorf("[%s][idx=%d] Incorrect configuration of group role mapping. RoleDomains len=%+v, expected=%+v", caller, idx, len(m1.RoleDomains), len(m2.RoleDomains))
			} else {
				for r1, domains1 := range m1.RoleDomains {
					if domains2, ok := m2.RoleDomains[r1]; !ok {
						t.Errorf("[%s][role] Incorrect configuration of group role mapping. Role=%+v", caller, r1)
					} else {
						if !reflect.DeepEqual(domains1, domains2) {
							t.Errorf("[%s][role=%s] Incorrect configuration of group role mapping. domains=%+v, expected=%+v", caller, r1, domains1, domains2)
						}
					}
				}
			}
		}
	}
}

func TestServerConfigNewForFed(t *testing.T) { // for 4.3(+), for a mpped-to-fedAdmin/fedReader group role on master cluster
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cacher = &mockCache{}

	role := &share.CLUSUserRoleInternal{
		ReadPermits:  share.PERMS_RUNTIME_SCAN,
		WritePermits: share.PERMS_RUNTIME_SCAN,
	}
	access.AddRole("role-1", role)
	access.AddRole("role-2", role)
	access.AddRole("role-3", role)
	access.AddRole("role-a", role)
	access.AddRole("role-b", role)
	access.AddRole("role-c", role)
	access.AddRole("role-d", role)
	access.UpdateUserRoleForFedRoleChange(api.FedRoleMaster)

	ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
	lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
	data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}

	// case: fedAdmin/fedReader are not supported for server's default role
	for _, r := range []string{api.UserRoleFedAdmin, api.UserRoleFedReader} {
		lcfg.DefaultRole = &r
		body, _ := json.Marshal(data)
		w := restCall("POST", "/v1/server", body, api.UserRoleFedAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Creating server with default role %s succeeded. Expect failure: %v", r, http.StatusBadRequest)
		}
	}

	lcfg.GroupMappedRoles = &[]*share.GroupRoleMapping{
		{
			Group:      "g1",
			GlobalRole: "role-1",
			RoleDomains: map[string][]string{
				"role-a": {"ns1"},
				"role-b": {"ns4", "ns8", "ns7"},
				"role-c": {"ns3", "ns2"},
			},
		},
		{
			Group:      "g2",
			GlobalRole: "fedAdmin",
			RoleDomains: map[string][]string{
				"role-a": {"ns1"},
				"role-b": {"ns4"},
				"role-c": {"ns2", "ns3"},
			},
		},
		{
			Group:      "g3",
			GlobalRole: "fedReader",
			RoleDomains: map[string][]string{
				"admin":  {"ns22", "ns1"},
				"role-b": {},
				"role-c": {"ns3", "ns2", "ns3"},
			},
		},
	}

	// case: user with admin role can not create server with group roles mapping that has fedAdmin/fedReader roles mapped
	lcfg.DefaultRole = nil
	for _, r := range []string{api.UserRoleFedAdmin, api.UserRoleFedReader} {
		(*lcfg.GroupMappedRoles)[1].GlobalRole = r
		body, _ := json.Marshal(data)
		w := restCall("POST", "/v1/server", body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Creating server with mapping to %s role succeeded. Expect failure: %v", r, http.StatusBadRequest)
		}

		// user with feadAdmin role can create server with group roles mapping that has fedAdmin/fedReader roles mapped
		w = restCall("POST", "/v1/server", body, api.UserRoleFedAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Creating server failed: %v", w.status)
		}

		// user with admin role can delete server with group roles mapping that has fedAdmin/fedReader roles mapped
		w = restCall("DELETE", "/v1/server/s1", nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Server should be allowed to be deleted: %v", w.status)
		}
	}

	(*lcfg.GroupMappedRoles)[1].GlobalRole = api.UserRoleFedAdmin
	body, _ := json.Marshal(data)
	// case: user with feadAdmin role can create server with group roles mapping that has fedAdmin/fedReader roles mapped
	w := restCall("POST", "/v1/server", body, api.UserRoleFedAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Creating server failed: %v", w.status)
	}

	{
		expectedGroupMappedRoles := []*share.GroupRoleMapping{
			{
				Group:      "g2",
				GlobalRole: "fedAdmin",
			},
			{
				Group:      "g3",
				GlobalRole: "fedReader",
				RoleDomains: map[string][]string{
					"admin":  {"ns1", "ns22"},
					"role-c": {"ns2", "ns3"},
				},
			},
			{
				Group:      "g1",
				GlobalRole: "role-1",
				RoleDomains: map[string][]string{
					"role-a": {"ns1"},
					"role-b": {"ns4", "ns7", "ns8"},
					"role-c": {"ns2", "ns3"},
				},
			},
		}

		// case: user with admin role can read server groups' roles mapping even there is fedAdmin/fedReader roles mapped
		var sdata api.RESTServerData
		w = restCall("GET", fmt.Sprintf("/v1/server/%v", data.Config.Name), nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Get server failed: %v", w.status)
		}
		_ = json.Unmarshal(w.body, &sdata)
		if sdata.Server == nil {
			t.Errorf("No server data")
		} else if sdata.Server.LDAP == nil {
			t.Errorf("No server ldap data")
		} else if sdata.Server.LDAP.GroupMappedRoles == nil {
			t.Errorf("No server ldap group role mapping data")
		} else {
			compareGroupMappedData("1", sdata.Server.LDAP.GroupMappedRoles, expectedGroupMappedRoles, t)
		}

		// case: as long as fedAdmin/fedReader mapping(if any) in groups' roles mapping is not changed, admin is allowd to patch a server's group role mapping
		new2 := []*share.GroupRoleMapping{
			{
				Group:      "dev",
				GlobalRole: "role-2",
				RoleDomains: map[string][]string{
					"role-d": {"ns1"},
					"role-c": {"ns11", "ns3", "ns2"},
				},
			},
			expectedGroupMappedRoles[0], // for g2 -> fedAdmin
			expectedGroupMappedRoles[1], // for g3 -> fedReader
		}
		expected2 := []*share.GroupRoleMapping{
			new2[1], // for g2 -> fedAdmin
			new2[2], // for g3 -> fedReader
			{
				Group:      "dev",
				GlobalRole: "role-2",
				RoleDomains: map[string][]string{
					"role-d": {"ns1"},
					"role-c": {"ns11", "ns2", "ns3"},
				},
			},
		}

		cfgdata := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &api.RESTServerLDAPConfig{GroupMappedRoles: &new2}}}
		body, _ := json.Marshal(cfgdata)
		// case: user with feadAdmin role can patch server with any group roles mapping
		w := restCall("PATCH", "/v1/server/s1", body, api.UserRoleFedAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Configuring server failed: %v", w.status)
		}
		var sdataRet api.RESTServerData
		w = restCall("GET", "/v1/server/s1", nil, api.UserRoleAdmin)
		_ = json.Unmarshal(w.body, &sdataRet)
		compareGroupMappedData("2", sdataRet.Server.LDAP.GroupMappedRoles, expected2, t)
	}

	{
		new3 := []*share.GroupRoleMapping{
			{
				Group:      "g1",
				GlobalRole: "role-1",
				RoleDomains: map[string][]string{
					"role-a": {"ns1"},
					"role-b": {"ns7", "ns4", "ns8"},
					"role-c": {"ns3", "ns2"},
				},
			},
			{
				Group:      "dev",
				GlobalRole: "role-2",
				RoleDomains: map[string][]string{
					"role-d": {"ns1"},
					"role-c": {"ns3", "ns2", "ns11"},
				},
			},
			{
				Group:      "g1",
				GlobalRole: "fedReader",
				RoleDomains: map[string][]string{
					"admin":  {"ns1"},
					"role-a": {"ns2"},
				},
			},
			{
				Group:      "g3",
				GlobalRole: "fedAdmin",
			},
		}
		expected3 := []*share.GroupRoleMapping{
			new3[2], // for g1 -> fedReader
			new3[3], // for g3 -> fedAdmin
			{
				Group:      "g1",
				GlobalRole: "role-1",
				RoleDomains: map[string][]string{
					"role-a": {"ns1"},
					"role-b": {"ns4", "ns7", "ns8"},
					"role-c": {"ns2", "ns3"},
				},
			},
			{
				Group:      "dev",
				GlobalRole: "role-2",
				RoleDomains: map[string][]string{
					"role-d": {"ns1"},
					"role-c": {"ns11", "ns2", "ns3"},
				},
			},
		}

		cfgdata3 := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &api.RESTServerLDAPConfig{GroupMappedRoles: &new3}}}
		body, _ := json.Marshal(cfgdata3)
		// case: multiple entries for one group's role mapping(group g1) is not allowed
		w := restCall("PATCH", "/v1/server/s1", body, api.UserRoleFedAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeded. Expect failure")
		}

		// case: groups with fedAdmin/fedReader-mapped role for global domain are always moved to front after sorting
		new3[2].Group = "g-fed-11"
		new3[3].Group = "g-fed-22"
		body, _ = json.Marshal(cfgdata3)
		w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleFedAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Configuring server failed: %v", w.status)
		}
		var sdataRet api.RESTServerData
		w = restCall("GET", "/v1/server/s1", nil, api.UserRoleAdmin)
		_ = json.Unmarshal(w.body, &sdataRet)
		compareGroupMappedData("3", sdataRet.Server.LDAP.GroupMappedRoles, expected3, t)

		/*
			now expected3(kv) has {
				g-fed-11 -> fedReader
				g-fed-22 -> fedAdmin
				g1 -> role-1
				dev -> role-2
			}
		*/

		// case: admin cannot change the order of groups that have fedAdmin/fedReader-mapped role for global domain
		new4 := []*share.GroupRoleMapping{
			expected3[3], // dev -> role-2
			expected3[2], // g1 -> role-1
			expected3[1], // g-fed-22 -> fedAdmin
			expected3[0], // g-fed-11 -> fedReader
		}
		cfgdata4 := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &api.RESTServerLDAPConfig{GroupMappedRoles: &new4}}}
		body, _ = json.Marshal(cfgdata4)
		w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeds. Expect failure")
		}

		/*
			now kv has the same {
				g-fed-11 -> fedReader, domainRoles=map[admin:[ns1] role-a:[ns2]]
				g-fed-22 -> fedAdmin, domainRoles=map[]
				g1 -> role-1, domainRoles=map[role-a:[ns1] role-b:[ns4 ns7 ns8] role-c:[ns2 ns3]]
				dev -> role-2
			}
		*/

		// case: as long as fedAdmin/fedReader mapping(if any) in groups' roles mapping/location is not changed, admin is allowd to patch a server's group role mapping
		new4 = []*share.GroupRoleMapping{
			expected3[0], // g-fed-11 -> fedReader
			expected3[1], // g-fed-22 -> fedAdmin
			expected3[3], // dev -> role-2
			{
				Group:      "qa",
				GlobalRole: "role-3",
				RoleDomains: map[string][]string{
					"role-d": {"ns1, ns2"}, // space character is not allowed in k8s namespace !
					"role-c": {"ns11"},
				},
			},
		}
		body, _ = json.Marshal(cfgdata4)
		w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeded, expect: %v", w.status)
		}

		/*
			now kv has {
				g-fed-11 -> fedReader
				g-fed-22 -> fedAdmin
				dev -> role-2
				qa -> role-3
			}
		*/

		new5 := []*share.GroupRoleMapping{
			new4[0], // g-fed-11 -> fedReader
			new4[1], // g-fed-22 -> fedAdmin
			new4[3],
		}
		// case: fedReader user cannot change server's group roles mapping
		cfgdata5 := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &api.RESTServerLDAPConfig{GroupMappedRoles: &new5}}}
		body, _ = json.Marshal(cfgdata5)
		w = restCall("PATCH", "/v1/server/s1", body, api.UserRoleFedReader)
		if w.status == http.StatusOK {
			t.Errorf("Configuring server succeeded. Expect failure")
		}
	}

	postTest()
}

func TestServerDelete(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	clusHelper = &mockCluster

	s1 := share.CLUSServer{
		Name: "s1",
		LDAP: &share.CLUSServerLDAP{Hostname: "1.2.3.4", BaseDN: "ou=people"},
	}

	// Used by auth order
	mockCluster.Init(nil, nil)
	_ = mockCluster.PutServerRev(&s1, 0)
	sysc := share.CLUSSystemConfig{AuthOrder: []string{"s1", "local"}}
	_ = mockCluster.PutSystemConfigRev(&sysc, 0)
	clusHelper = &mockCluster

	w := restCall("DELETE", "/v1/server/s1", nil, api.UserRoleAdmin)
	if w.status != http.StatusConflict {
		t.Errorf("Inused server shouldn't be allow deleted: %v", w.status)
	}

	// Not used
	mockCluster.Init(nil, nil)
	_ = mockCluster.PutServerRev(&s1, 0)
	sysc = share.CLUSSystemConfig{AuthOrder: []string{"local"}}
	_ = mockCluster.PutSystemConfigRev(&sysc, 0)

	w = restCall("DELETE", "/v1/server/s1", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Server should be allowed deleted: %v", w.status)
	}
}

func TestOIDCUpdate(t *testing.T) {
	cs := share.CLUSServer{
		OIDC: &share.CLUSServerOIDC{
			Scopes: auth.DefaultOIDCScopes,
		},
	}
	accAdmin := access.NewAdminAccessControl()
	oidc := api.RESTServerOIDCConfig{}
	_ = updateOIDCServer(&cs, &oidc, accAdmin, nil)
	if !reflect.DeepEqual(cs.OIDC.Scopes, auth.DefaultOIDCScopes) {
		t.Errorf("Invalid OIDC scopes update: %v", cs.OIDC.Scopes)
	}

	scopes := []string{"one"}
	oidc = api.RESTServerOIDCConfig{Scopes: &scopes}
	_ = updateOIDCServer(&cs, &oidc, accAdmin, nil)
	if len(cs.OIDC.Scopes) != 2 || cs.OIDC.Scopes[0] != "openid" || cs.OIDC.Scopes[1] != "one" {
		t.Errorf("Invalid OIDC scopes update: %v", cs.OIDC.Scopes)
	}

	scopes = []string{"openid", "two"}
	oidc = api.RESTServerOIDCConfig{Scopes: &scopes}
	_ = updateOIDCServer(&cs, &oidc, accAdmin, nil)
	if len(cs.OIDC.Scopes) != 2 || cs.OIDC.Scopes[0] != "openid" || cs.OIDC.Scopes[1] != "two" {
		t.Errorf("Invalid OIDC scopes update: %v", cs.OIDC.Scopes)
	}
}
