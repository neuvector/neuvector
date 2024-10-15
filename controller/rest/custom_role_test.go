package rest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

func verifyCustomRole(testID string, data *api.RESTUserRoleConfigData, acc *access.AccessControl, t *testing.T) {
	// Check configured role in cluster
	crole, _, _ := clusHelper.GetCustomRoleRev(data.Config.Name, acc)
	if crole == nil {
		t.Fatalf("Failed to locate role in cluster")
	}
	if crole.Name != data.Config.Name || crole.Comment != data.Config.Comment || crole.Reserved {
		t.Fatalf("Incorrect role in cluster: role=%v", data.Config.Name)
	} else {
		if len(crole.Permissions) != len(data.Config.Permissions) {
			t.Fatalf("Incorrect role in cluster: role=%v, expected permissions: %v, value=%v", data.Config.Name, len(data.Config.Permissions), len(crole.Permissions))
		} else if len(data.Config.Permissions) > 0 {
			dataMap := make(map[string]*api.RESTRolePermission, len(data.Config.Permissions))
			for _, p := range data.Config.Permissions {
				dataMap[p.ID] = p
			}
			croleMap := make(map[string]*share.CLUSRolePermission, len(crole.Permissions))
			for _, p := range crole.Permissions {
				croleMap[p.ID] = p
			}
			for id, p := range croleMap {
				if p2, ok := dataMap[id]; ok {
					if p.Read != p2.Read || p.Write != p2.Write {
						t.Fatalf("Incorrect role in cluster: role=%v, permission=%v, expected=%v", data.Config.Name, *p, *p2)
					}
				}
			}
		}
	}

	// Check configured role by REST
	var resp api.RESTUserRoleData
	w := restCall("GET", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get role: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if resp.Role.Name != data.Config.Name || resp.Role.Comment != data.Config.Comment || resp.Role.Reserved {
		t.Fatalf("Incorrect role by REST: role=%v", data.Config.Name)
	} else {
		if len(resp.Role.Permissions) != len(data.Config.Permissions) {
			t.Fatalf("Incorrect role by REST: role=%v, expected permissions: %v, value=%v", data.Config.Name, len(data.Config.Permissions), len(resp.Role.Permissions))
		} else if len(data.Config.Permissions) > 0 {
			dataMap := make(map[string]*api.RESTRolePermission, len(data.Config.Permissions))
			for _, p := range data.Config.Permissions {
				dataMap[p.ID] = p
			}
			restMap := make(map[string]*api.RESTRolePermission, len(resp.Role.Permissions))
			for _, p := range resp.Role.Permissions {
				restMap[p.ID] = p
			}
			for id, p := range restMap {
				if p2, ok := dataMap[id]; ok {
					if p.Read != p2.Read || p.Write != p2.Write {
						t.Fatalf("Incorrect role by REST: role=%v, permission=%v. expected=%v", data.Config.Name, *p, *p2)
					}
				}
			}
		}
	}
}

func TestRoleCreateDelete(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	// Check reserved roles existence
	names := []string{api.UserRoleAdmin, api.UserRoleReader, api.UserRoleNone, api.UserRoleCIOps} // not including api.UserRoleFedAdmin, api.UserRoleFedReader, api.UserRoleIBMSA
	for _, name := range names {
		role := access.GetRoleDetails(name)
		if role == nil {
			t.Fatalf("Failed to locate reserved role in cluster: %s", name)
		}
		if role.Name != name {
			t.Fatalf("Incorrect reserved role: role name=%v, expected=%v", role.Name, name)
		}
	}

	// Create role - fails because of no permission enabled
	data := api.RESTUserRoleConfigData{
		Config: &api.RESTUserRoleConfig{
			Name:        "custom-role-1",
			Comment:     "for viewing audit logs",
			Permissions: nil,
		},
	}

	body, _ := json.Marshal(data)
	w := restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
	if w.status != http.StatusBadRequest {
		t.Fatalf("Surprised to create role %s(no permission): status=%v.", data.Config.Name, w.status)
	}

	// Create role with permission
	data.Config.Permissions = []*api.RESTRolePermission{
		{ID: "authentication", Write: true},
	}
	body, _ = json.Marshal(data)
	w = restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create role: status=%v.", w.status)
	}

	data.Config.Permissions[0].Read = true // read permission is enabled as well when write permission is enabled
	// Check created role in cluster
	verifyCustomRole("1", &data, accAdmin, t)

	// Check created role in all roles by REST
	var resp api.RESTUserRolesData
	w = restCall("GET", "/v1/user_role", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get roles: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if len(resp.Roles) != 4 { // 4 reserved roles(not including None) + created custom role
		t.Fatalf("Incorrect role count in rest: count=%v expected=5", len(resp.Roles))
	}
	foundRole := false
	for _, crole := range resp.Roles {
		if crole.Name == data.Config.Name {
			foundRole = true
			if crole.Comment != data.Config.Comment || crole.Reserved || len(crole.Permissions) != 1 || *crole.Permissions[0] != *data.Config.Permissions[0] {
				t.Fatalf("Incorrect role by REST: role=%v", crole)
			}
		}
	}
	if !foundRole {
		t.Fatalf("Created role not found: %v by REST.", data.Config.Name)
	}

	// Delete role
	w = restCall("DELETE", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete role: status=%v.", w.status)
	}

	// Check role in cluster
	crole, _, _ := clusHelper.GetCustomRoleRev(data.Config.Name, accAdmin)
	if crole != nil {
		t.Fatalf("Role is not deleted in cluster")
	}

	// Check deleted role by REST
	w = restCall("GET", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
	if w.status != http.StatusNotFound {
		t.Fatalf("Suprised to get role: status=%v.", w.status)
	}

	names = []string{api.UserRoleAdmin, api.UserRoleReader, api.UserRoleFedAdmin, api.UserRoleFedReader, api.UserRoleIBMSA, api.UserRoleCIOps, api.UserRoleNone}
	for _, name := range names {
		data.Config.Name = name
		body, _ = json.Marshal(data)
		// Create role with reserved role name
		w = restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Fatalf("Successful to create role %v: status=%v.", name, w.status)
		}

		// Config role with reserved role name
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if (name == api.UserRoleNone && w.status != http.StatusNotFound) || (name != api.UserRoleNone && w.status != http.StatusBadRequest) {
			t.Fatalf("Successful to delete role %v: status=%v.", name, w.status)
		}

		// Delete role with reserved role name
		w = restCall("DELETE", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
		if (name == api.UserRoleNone && w.status != http.StatusNotFound) || (name != api.UserRoleNone && w.status != http.StatusBadRequest) {
			t.Fatalf("Successful to delete role %v: status=%v.", name, w.status)
		}
	}

	postTest()
}

func TestRoleAllPermissionsEnabledCustomRole(t *testing.T) {
	// no custom role can be as powerful as admin role!
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	var obj share.CLUSAgent
	nvURIs := map[string][]string{ // key is http verb, value is URIs with the sme verb
		"GET": {
			"/v1/meter", // test this API as all the following handlers call authDebugCaller(w, acc, login) too
			/*"/v1/enforcer/:id/probe_summary",
			"/v1/enforcer/:id/probe_processes",
			"/v1/enforcer/:id/probe_containers",
			"/v1/debug/ip2workload",
			"/v1/debug/internal_subnets",
			"/v1/debug/policy/rule",
			"/v1/debug/dlp/wlrule",
			"/v1/debug/dlp/rule",
			"/v1/debug/dlp/mac",
			"/v1/debug/system/stats",
			"/v1/debug/controller/sync",
			"/v1/debug/workload/intercept",
			"/v1/debug/registry/image/:name",
			"/v1/session/summary",
			"/v1/file_monitor_file",*/
		},
		/*"POST": {
			"/v1/debug/controller/sync/:id",
			"/v1/controller/:id/profiling",
			"/v1/enforcer/:id/profiling",
		},
		"DELETE": {
			"/v1/conversation_endpoint/:id",
			"/v1/conversation",
			"/v1/session",
		},*/
	}

	fedURIs1 := map[string][]string{ // key is http verb, value is URIs with the sme verb
		// all the following APIs require admin role
		"POST": {
			"/v1/fed/promote",
			"/v1/fed/join",
			"/v1/fed/leave",
			"/v1/fed/remove_internal",
			"/v1/fed/command_internal",
		},
		"PATCH": {
			"/v1/fed/config",
		},
		"DELETE": {
			"/v1/fed_auth",
		},
	}

	fedURIs2 := map[string][]string{ // key is http verb, value is URIs with the sme verb
		// the following APIs require fedAdmin role
		"POST": {
			"/v1/fed/demote",
			"/v1/fed/deploy",
			"/v1/fed/cluster/:id/*request",
		},
		"PATCH": {
			"/v1/fed/cluster/:id/*request",
		},
		"DELETE": {
			"/v1/fed/cluster/:id",
			"/v1/fed/cluster/:id/*request",
		},
	}

	// Create all-configurable-write-permissions-enabled role & all-configurable-read-permissions-enabled role & other role
	permitsAllConfigurableWrite := make([]*api.RESTRolePermission, 0, len(access.PermissionOptions))
	permitsAllConfigurableRead := make([]*api.RESTRolePermission, 0, len(access.PermissionOptions))
	permitsOther := make([]*api.RESTRolePermission, 0, len(access.PermissionOptions))
	skippedOneRwPermission := false
	for _, option := range access.PermissionOptions {
		if access.HiddenPermissions.Contains(option.ID) {
			continue
		}
		restP := &api.RESTRolePermission{ID: option.ID}
		if option.ReadSupported && !option.WriteSupported {
			restP.Read = true
		} else if !option.ReadSupported && option.WriteSupported {
			restP.Write = true
		} else if option.ReadSupported && option.WriteSupported {
			restP.Read = true
			restP.Write = true
		}

		permitsAllConfigurableWrite = append(permitsAllConfigurableWrite, restP)
		if option.ReadSupported {
			permitsAllConfigurableRead = append(permitsAllConfigurableRead, restP)
		}

		if option.ReadSupported && option.WriteSupported {
			if !skippedOneRwPermission {
				skippedOneRwPermission = true
			} else {
				permitsOther = append(permitsOther, restP)
			}
		} else {
			permitsOther = append(permitsOther, restP)
		}
	}

	// Create the role to have all configurable permission enabled. however, no custom role can have the same permissions as admin
	dataAllConfigurableWriteRole := api.RESTUserRoleConfigData{
		Config: &api.RESTUserRoleConfig{
			Name:        "custom-role-1",
			Comment:     "all configurable write enabled role",
			Permissions: permitsAllConfigurableWrite,
		},
	}
	body, _ := json.Marshal(dataAllConfigurableWriteRole)
	w := restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create role: status=%v.", w.status)
	}

	// Create the all configurable read role & other roles to not having all configurable modify permission enabled. however, no custom role can have the same permissions as reader
	dataNonAdminRoles := []*api.RESTUserRoleConfigData{
		{
			Config: &api.RESTUserRoleConfig{
				Name:        "custom-role-2",
				Comment:     "all configurable read enabled role",
				Permissions: permitsAllConfigurableRead,
			},
		},
		{
			Config: &api.RESTUserRoleConfig{
				Name:        "custom-role-3",
				Comment:     "other role",
				Permissions: permitsOther,
			},
		},
	}
	dataNonAdminUsers := []*api.RESTUserData{
		{
			User: &api.RESTUser{
				Fullname: "reader-jack",
				Password: "123456",
				Role:     dataNonAdminRoles[0].Config.Name,
			},
		},
		{
			User: &api.RESTUser{
				Fullname: "other-jane",
				Password: "123456",
				Role:     dataNonAdminRoles[1].Config.Name,
			},
		},
	}

	r, _ := http.NewRequest(http.MethodGet, "https://10.1.1.1/v1/enforcer", nil)
	for idx, data := range dataNonAdminRoles {
		body, _ := json.Marshal(*data)
		w := restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to create role: status=%v.", w.status)
		}
		// Create the user to have the role
		body, _ = json.Marshal(*dataNonAdminUsers[idx])
		w = restCall("POST", "/v1/user", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to create user: status=%v.", w.status)
		}

		accRead := access.NewAccessControl(r, access.AccessOPRead, access.DomainRole{
			"": data.Config.Name,
		}, nil)
		accWrite := access.NewAccessControl(r, access.AccessOPWrite, access.DomainRole{
			"": data.Config.Name,
		}, nil)
		// CLUSAgent requires PERM_NV_RESOURCE permission and the custom role should not be able to access it
		authz := accRead.Authorize(&obj, nil)
		if idx == 0 {
			// idx 0 entry has all selectable read permissions
			// custom role with all selectable read permissions is given nv_resource(r) intentionally since 5.3.3
			if !authz { // expect to read cluster successfully
				t.Fatalf("Surpirsed authz failed for read")
			}
		} else {
			if authz { // can not read cluster expected
				t.Fatalf("Surpirsed authz successfully for read")
			}
		}
		authz = accWrite.Authorize(&obj, nil) // can not write cluster
		if authz {
			t.Fatalf("Surpirsed authz successfully for write")
		}

		// Login as custom role user
		w = login(dataNonAdminUsers[idx].User.Fullname, dataNonAdminUsers[idx].User.Password)
		token2 := getLoginToken(w)
		adminURIs := []map[string][]string{nvURIs, fedURIs1, fedURIs2}
		mockCluster.FedMembership.FedRole = "master"
		for _, mapURIs := range adminURIs {
			for verb, uris := range mapURIs {
				for _, uri := range uris {
					uriStr := strings.Replace(uri, ":", "", -1)
					uriStr = strings.Replace(uriStr, "*", "", -1)
					w = restCallToken(verb, uriStr, nil, token2)
					if w.status != http.StatusForbidden {
						t.Fatalf("Surprised to authorize successfully: user=%s, verb=%s, URI=%v, status=%+v.", dataNonAdminUsers[idx].User.Fullname, verb, uriStr, w.status)
					}
				}
			}
		}
		mockCluster.FedMembership.FedRole = ""

		logout(token2)
	}

	// Create a user to have the all configurable write role
	dataUserAllConfigurableWrite := api.RESTUserData{
		User: &api.RESTUser{
			Fullname: "admin-joe",
			Password: "123456",
			Role:     dataAllConfigurableWriteRole.Config.Name,
		},
	}
	body, _ = json.Marshal(dataUserAllConfigurableWrite)
	w = restCall("POST", "/v1/user", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create user: status=%v.", w.status)
	}

	accRead := access.NewAccessControl(r, access.AccessOPRead, access.DomainRole{
		"": dataAllConfigurableWriteRole.Config.Name,
	}, nil)
	accWrite := access.NewAccessControl(r, access.AccessOPWrite, access.DomainRole{
		"": dataAllConfigurableWriteRole.Config.Name,
	}, nil)
	// CLUSAgent requires PERM_NV_RESOURCE permission and no custom role can access it
	authz := accRead.Authorize(&obj, nil)
	if !authz { // custom role with all selectable read permissions is given nv_resource(r) intentionally since 5.3.3
		t.Fatalf("Surprised to authorize failed for read")
	}
	authz = accWrite.Authorize(&obj, nil)
	if authz {
		t.Fatalf("Surprised to authorize successfully for write")
	}

	// Login as the all-configurable-permissions-enabled-custom-role user. But still gets 403 for those only-for-admin APIs
	w = login(dataUserAllConfigurableWrite.User.Fullname, dataUserAllConfigurableWrite.User.Password)
	token1 := getLoginToken(w)
	for verb, uris := range nvURIs {
		for _, uri := range uris {
			uriStr := strings.Replace(uri, ":", "", -1)
			w = restCallToken(verb, uriStr, nil, token1)
			if w.status != http.StatusForbidden {
				t.Fatalf("Surprised to authorize successfully: user=%s, verb=%s, URI=%v.", dataUserAllConfigurableWrite.User.Fullname, verb, uriStr)
			}
		}
	}
	mockCluster.FedMembership.FedRole = "master"
	for verb, uris := range fedURIs2 { // these APIs require fedAdmin role
		for _, uri := range uris {
			uriStr := strings.Replace(uri, ":", "", -1)
			uriStr = strings.Replace(uriStr, "*", "", -1)
			w = restCallToken(verb, uriStr, nil, token1)
			if w.status != http.StatusForbidden {
				t.Fatalf("Surprised to authorize successfully: user=%s, verb=%s, URI=%v, status=%+v.", dataUserAllConfigurableWrite.User.Fullname, verb, uriStr, w.status)
			}
		}
	}
	mockCluster.FedMembership.FedRole = ""
	logout(token1)

	// Delete user
	for _, name := range []string{dataUserAllConfigurableWrite.User.Fullname, dataNonAdminUsers[0].User.Fullname, dataNonAdminUsers[1].User.Fullname} {
		w = restCall("DELETE", "/v1/user/"+name, nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to delete user %s: status=%v.", name, w.status)
		}
	}

	// Delete role
	for _, name := range []string{dataAllConfigurableWriteRole.Config.Name, dataNonAdminRoles[0].Config.Name, dataNonAdminRoles[1].Config.Name} {
		w = restCall("DELETE", "/v1/user_role/"+name, nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to delete role %s: status=%v.", name, w.status)
		}
	}

	postTest()
}

func TestRoleConfig(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	data := api.RESTUserRoleConfigData{
		Config: &api.RESTUserRoleConfig{
			Name:    "custom-role-1",
			Comment: "for testing",
			Permissions: []*api.RESTRolePermission{
				{ID: "audit_events", Read: true},
			},
		},
	}

	// Create role
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create role: status=%v.", w.status)
	}

	// Config role with valid view-only permission
	viewOnlyPermissionIDs := []string{"audit_events", "security_events", "events"}
	for _, viewOnlyPermitID := range viewOnlyPermissionIDs {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: viewOnlyPermitID, Read: true},
		}

		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to modify role %s(view-only permission %s): status=%v.", data.Config.Name, viewOnlyPermitID, w.status)
		}
		// Check configured role in cluster
		verifyCustomRole("11", &data, accAdmin, t)
	}

	// Config role with multiple valid view-only permissions
	data.Config.Permissions = make([]*api.RESTRolePermission, 0)
	for _, viewOnlyPermitID := range viewOnlyPermissionIDs {
		data.Config.Permissions = append(data.Config.Permissions, &api.RESTRolePermission{ID: viewOnlyPermitID, Read: true})
	}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to modify role %s(all view-only permissions): status=%v.", data.Config.Name, w.status)
	}
	// Check configured role in cluster
	verifyCustomRole("12", &data, accAdmin, t)

	// Config role with valid modify-only permission
	modifyOnlyPermissionIDs := []string{"ci_scan"}
	for _, modifyOnlyPermitID := range modifyOnlyPermissionIDs {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: modifyOnlyPermitID, Write: true},
		}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to modify role %s(modify-only permission %s): status=%v.", data.Config.Name, modifyOnlyPermitID, w.status)
		}
		// Check configured role in cluster
		verifyCustomRole("13", &data, accAdmin, t)
	}

	// Config role with valid view/modify permission
	rwPermissionIDs := []string{"rt_scan", "reg_scan", "rt_policy", "admctrl", "compliance", "authentication", "authorization", "config"}
	for _, rwPermitID := range rwPermissionIDs {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: rwPermitID, Read: true, Write: true},
		}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to modify role %s(r/w permission %s): status=%v.", data.Config.Name, rwPermitID, w.status)
		}
		// Check configured role in cluster
		verifyCustomRole("14", &data, accAdmin, t)
	}

	// Prepare all view-configurable permissions
	allViewPermissions := make([]*api.RESTRolePermission, 0, len(viewOnlyPermissionIDs)+len(rwPermissionIDs))
	for _, viewOnlyPermitID := range viewOnlyPermissionIDs {
		allViewPermissions = append(allViewPermissions, &api.RESTRolePermission{ID: viewOnlyPermitID, Read: true})
	}
	for _, rwPermissionIDs := range rwPermissionIDs {
		allViewPermissions = append(allViewPermissions, &api.RESTRolePermission{ID: rwPermissionIDs, Read: true})
	}
	// Prepare all modify-configurable permissions
	allModifyPermissions := make([]*api.RESTRolePermission, 0, 1+len(rwPermissionIDs))
	allModifyPermissions = append(allModifyPermissions, &api.RESTRolePermission{ID: "ci_scan", Write: true})
	for _, rwPermissionIDs := range rwPermissionIDs {
		allModifyPermissions = append(allModifyPermissions, &api.RESTRolePermission{ID: rwPermissionIDs, Write: true})
	}
	// Prepare all r/w-configurable permissions
	allPermissions := make([]*api.RESTRolePermission, 0, 1+len(viewOnlyPermissionIDs)+len(rwPermissionIDs))
	allPermissions = append(allPermissions, &api.RESTRolePermission{ID: "ci_scan", Write: true})
	for _, viewOnlyPermitID := range viewOnlyPermissionIDs {
		allPermissions = append(allPermissions, &api.RESTRolePermission{ID: viewOnlyPermitID, Read: true})
	}
	for _, rwPermissionIDs := range rwPermissionIDs {
		allPermissions = append(allPermissions, &api.RESTRolePermission{ID: rwPermissionIDs, Read: true, Write: true})
	}
	// Config with different configurable permissions
	configPermissions := [][]*api.RESTRolePermission{allViewPermissions, allModifyPermissions, allPermissions}
	for _, configPermission := range configPermissions {
		data.Config.Permissions = configPermission
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to modify role %s(all read permissions): status=%v.", data.Config.Name, w.status)
		}
		// Check configured role in cluster
		for _, p := range data.Config.Permissions {
			if p.Write && p.ID != "ci_scan" {
				p.Read = true // read permission is enabled as well when write permission is enabled, except for ci_scan which only supports modify
			}
		}
		verifyCustomRole("15", &data, accAdmin, t)
	}

	// Delete role
	w = restCall("DELETE", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete role: status=%v.", w.status)
	}

	postTest()
}

func TestRoleConfigNegative(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	data := api.RESTUserRoleConfigData{
		Config: &api.RESTUserRoleConfig{
			Name:    "custom-role-1",
			Comment: "for viewing audit logs",
			Permissions: []*api.RESTRolePermission{
				{ID: "audit_events", Read: true},
			},
		}}

	// Try to config non-configurable roles
	names := []string{api.UserRoleAdmin, api.UserRoleReader, api.UserRoleCIOps, api.UserRoleFedAdmin, api.UserRoleFedReader, api.UserRoleIBMSA}
	for _, name := range names {
		data.Config.Name = name
		body, _ := json.Marshal(data)
		w := restCall("PATCH", "/v1/user_role/"+name, body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Fatalf("Surprised to modify reserved role %s: status=%v.", name, w.status)
		}
	}

	// Create role
	data.Config.Name = "custom-role-1"
	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create role: status=%v.", w.status)
	}

	verifyCustomRole("21", &data, access.NewAdminAccessControl(), t)

	// Config role with no permission enabled
	data.Config.Permissions = []*api.RESTRolePermission{}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
	if w.status != http.StatusBadRequest {
		t.Fatalf("Surprised to modify role %s(no permission): status=%v.", data.Config.Name, w.status)
	}

	// Config role with duplicate permission id
	data.Config.Permissions = []*api.RESTRolePermission{
		{ID: "audit_events", Read: true},
		{ID: "audit_events", Read: true},
	}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
	if w.status != http.StatusBadRequest {
		t.Fatalf("Surprised to modify role %s(duplicate permission): status=%v.", data.Config.Name, w.status)
	}

	// Config role with invalid modify permission
	viewOnlyPermissionIDs := []string{"audit_events", "security_events", "events"}
	for _, viewOnlyPermitID := range viewOnlyPermissionIDs {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: viewOnlyPermitID, Write: true},
		}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Fatalf("Surprised to modify role %s(view-only permission %s): status=%v.", data.Config.Name, viewOnlyPermitID, w.status)
		}
	}

	// Config role with invalid view permission
	modifyOnlyPermissions := []string{"ci_scan"}
	for _, modifyOnlyPermitID := range modifyOnlyPermissions {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: modifyOnlyPermitID, Read: true},
		}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Fatalf("Surprised to modify role %s(modify-only permission %s): status=%v.", data.Config.Name, modifyOnlyPermitID, w.status)
		}
	}

	// Config role with hidden permission
	hiddenPermissionIDs := []string{"ibmsa", "fed", "adm_basic"} // "fed" is hidden until the cluster is promoted
	for _, hiddenOnlyPermitID := range hiddenPermissionIDs {
		data.Config.Permissions = []*api.RESTRolePermission{
			{ID: hiddenOnlyPermitID},
		}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Fatalf("Surprised to modify role %s(hidden permission %s): status=%v.", data.Config.Name, hiddenPermissionIDs, w.status)
		}
	}

	// Config role with invalid permission id
	data.Config.Permissions = []*api.RESTRolePermission{
		{ID: "audit_events_bad", Read: true},
	}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/user_role/"+data.Config.Name, body, api.UserRoleAdmin)
	if w.status != http.StatusBadRequest {
		t.Fatalf("Surprised to modify role %s(invalid permission audit_events_bad): status=%v.", data.Config.Name, w.status)
	}

	// Delete role
	data.Config.Name = "custom-role-1"
	w = restCall("DELETE", "/v1/user_role/"+data.Config.Name, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete role: status=%v.", w.status)
	}

	postTest()
}

func TestUserWithCustomRole(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	// Create role with permission
	dataRoles := []api.RESTUserRoleConfigData{
		{
			Config: &api.RESTUserRoleConfig{
				Name:    "custom-role-1", // has view/modify authorization permission
				Comment: "modify authorization",
				Permissions: []*api.RESTRolePermission{
					{ID: "authorization", Write: true},
				},
			},
		},
		{
			Config: &api.RESTUserRoleConfig{
				Name:    "custom-role-2", // has only view authorization permission
				Comment: "view authorization",
				Permissions: []*api.RESTRolePermission{
					{ID: "authorization", Read: true},
				},
			},
		},
	}

	for _, dataRole := range dataRoles {
		body, _ := json.Marshal(dataRole)
		w := restCall("POST", "/v1/user_role", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to create role: status=%v.", w.status)
		}
	}

	// Create user with "custom-role-1"(has view/modify authorization permission)
	userData := api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: dataRoles[0].Config.Name,
	}}
	body, _ := json.Marshal(userData)
	w := restCall("POST", "/v1/user", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create user with custom role: status=%v.", w.status)
	}

	// Check user in cluster
	cuser, _, _ := clusHelper.GetUserRev(userData.User.Fullname, accAdmin)
	if cuser == nil {
		t.Fatalf("Failed to locate user in cluster")
	}
	if cuser.Fullname != userData.User.Fullname || cuser.Username != userData.User.Fullname || cuser.Role != userData.User.Role {
		t.Fatalf("Incorrect user in cluster: user=%v", cuser)
	}

	// Delete role "custom-role-1" while user "joe" is assigned "custom-role-1" role. Should fail
	w = restCall("DELETE", "/v1/user_role/"+dataRoles[0].Config.Name, nil, api.UserRoleAdmin)
	if w.status == http.StatusOK {
		t.Fatalf("Surprised to delete role: status=%v.", w.status)
	}

	w = login(userData.User.Fullname, userData.User.Password)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	// Change user's global role to "custom-role-2" that only has view authorization permission
	token := getLoginToken(w)
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: userData.User.Fullname, Role: &dataRoles[1].Config.Name}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+userData.User.Fullname, body, token)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to change custom user role: status=%+v.", w.status)
	}
	// in unittest, we can check if the user login is kicked only by checking the size of loginSessions
	if len(loginSessions) != 0 {
		t.Fatalf("Not kicked after chaning its own user role: len=%+v.", len(loginSessions))
	}

	w = login(userData.User.Fullname, userData.User.Password)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	// Current role is "custom-role-2"(has view authorization permission). Change user's global role back to "custom-role-1" should fail
	token = getLoginToken(w)
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: userData.User.Fullname, Role: &dataRoles[0].Config.Name}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+userData.User.Fullname, body, token)
	if w.status != http.StatusForbidden {
		t.Fatalf("Surprised to change custom user role: status=%+v.", w.status)
	}
	logout(token)

	// Delete myself user. Should fail
	w = restCallToken("DELETE", "/v1/user/"+userData.User.Fullname, nil, token)
	if w.status != http.StatusForbidden {
		t.Fatalf("Surprised to delete user: status=%v.", w.status)
	}

	// Delete user as admin
	w = restCall("DELETE", "/v1/user/"+userData.User.Fullname, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete user: status=%v.", w.status)
	}

	// Check user in cluster
	cuser, _, _ = clusHelper.GetUserRev(userData.User.Fullname, accAdmin)
	if cuser != nil {
		t.Fatalf("User is not deleted in cluster")
	}

	// Delete role
	for _, dataRole := range dataRoles {
		w = restCall("DELETE", "/v1/user_role/"+dataRole.Config.Name, nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to delete role: status=%v.", w.status)
		}
	}

	postTest()
}
