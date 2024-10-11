package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share/utils"
)

func TestUserCreateDelete(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	data := api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleReader,
	}}

	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/user", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create user: status=%v.", w.status)
	}

	// Check user in cluster
	cuser, _, _ := clusHelper.GetUserRev("joe", accAdmin)
	if cuser == nil {
		t.Fatalf("Failed to locate user in cluster")
	}
	if cuser.Fullname != "joe" || cuser.Username != "joe" || cuser.Role != api.UserRoleReader {
		t.Errorf("Incorrect user in cluster: user=%v", cuser)
	}

	// Check get users by REST
	var resp api.RESTUsersData
	w = restCall("GET", "/v1/user", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get user: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if len(resp.Users) != 1 {
		t.Errorf("Incorrect user count in rest: count=%v expect=1", len(resp.Users))
	}
	user := resp.Users[0]
	if user.Fullname != "joe" || user.Username != "joe" || user.Role != api.UserRoleReader {
		t.Errorf("Incorrect user in rest: user=%v", *user)
	}

	// Delete user
	w = restCall("DELETE", "/v1/user/joe", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete user: status=%v.", w.status)
	}

	// Check user in cluster
	cuser, _, _ = clusHelper.GetUserRev("joe", accAdmin)
	if cuser != nil {
		t.Errorf("User is not deleted in cluster")
	}

	// Check get users by REST
	w = restCall("GET", "/v1/user", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get user: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if len(resp.Users) != 0 {
		t.Errorf("Incorrect user count in rest: count=%v expect=0", len(resp.Users))
	}

	postTest()
}

func TestUserConfig(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	user1 := makeLocalUser("user1", "111111", api.UserRoleAdmin)
	user2 := makeLocalUser("user2", "222222", api.UserRoleReader)
	_ = clusHelper.CreateUser(user1)
	_ = clusHelper.CreateUser(user2)

	// Login as admin
	w := login("user1", "111111")
	token1 := getLoginToken(w)

	// Modify self email
	email1 := "user1@example.com"
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", EMail: &email1}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change email: status=%v.", w.status)
	}

	// Modify user2's timeout
	var timeout uint32 = 120
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user2", Timeout: &timeout}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user2", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout: status=%v.", w.status)
	}

	// Check user2's timeout
	cuser2, _, _ := clusHelper.GetUserRev("user2", accAdmin)
	if cuser2 == nil {
		t.Fatalf("Failed to locate user user2 in cluster")
	}
	if cuser2.Fullname != "user2" || cuser2.Timeout != 120 {
		t.Errorf("Incorrect user in cluster: user=%v", *cuser2)
	}

	logout(token1)

	postTest()
}

func TestUserConfigKick(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cacher = &mockCache{}

	user1 := makeLocalUser("user1", "111111", api.UserRoleAdmin)
	user2 := makeLocalUser("user2", "222222", api.UserRoleReader)
	_ = clusHelper.CreateUser(user1)
	_ = clusHelper.CreateUser(user2)

	// Login both
	w := login("user1", "111111")
	token1 := getLoginToken(w)

	// Modify user1 password
	pass1 := "111111"
	pass1New := "1.1.1."
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", Password: &pass1, NewPassword: &pass1New}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change password: status=%v.", w.status)
	}

	// Check if user in cluster is modified
	cuser1, _, _ := clusHelper.GetUserRev("user1", accAdmin)
	if cuser1 == nil {
		t.Fatalf("Failed to locate user user1 in cluster")
	}
	if cuser1.Fullname != "user1" || cuser1.PasswordHash != utils.HashPassword(pass1New) {
		t.Errorf("Incorrect user in cluster: user=%v", *cuser1)
	}

	// Check if user is kicked
	if len(loginSessions) != 0 {
		t.Errorf("User1 is not kicked after changing password")
		for _, u := range loginSessions {
			t.Errorf("%+v\n", u)
		}
	}

	// Log back in
	w = login("user1", "1.1.1.")
	token1 = getLoginToken(w)
	// Login user2
	w = login("user2", "222222")
	_ = getLoginToken(w)

	// Modify user2's role as user1
	role2 := api.UserRoleAdmin
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user2", Role: &role2}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user2", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change user2's role: status=%v.", w.status)
	}

	// Check user2's role is modified
	cuser2, _, _ := clusHelper.GetUserRev("user2", accAdmin)
	if cuser2 == nil {
		t.Fatalf("Failed to locate user user2 in cluster")
	}
	if cuser2.Fullname != "user2" || cuser2.Role != api.UserRoleAdmin {
		t.Errorf("Incorrect user role in cluster: user=%v", *cuser2)
	}

	// Check if user2 is kicked, user1 should still login
	if len(loginSessions) != 1 {
		t.Errorf("Incorrect login user count: #login=%v", len(loginSessions))
	}
	for _, login := range loginSessions {
		if login.fullname != "user1" {
			t.Errorf("Incorrect login users: login=%v", *login)
		}
	}

	// Login back in user2
	w = login("user2", "222222")
	token2 := getLoginToken(w)

	// Modify user2 self's password
	pass2 := "222222"
	pass2New := "2.2.2."
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user2", Password: &pass2, NewPassword: &pass2New}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user2", body, token2)
	if w.status != http.StatusOK {
		t.Errorf("Failed to modify password: status=%v.", w.status)
	}

	// Check if user2 is kicked
	if len(loginSessions) != 1 {
		t.Errorf("Incorrect login user count: #login=%v", len(loginSessions))
	}
	for _, login := range loginSessions {
		if login.fullname != "user1" {
			t.Errorf("Incorrect login users: login=%v", *login)
		}
	}

	// Modify user1 self's role
	role1 := api.UserRoleReader
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", Role: &role1}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change role: status=%v.", w.status)
	}

	// Check if user is kicked
	if len(loginSessions) != 0 {
		t.Errorf("User1 is not kicked after changing role")
	}

	// Login back in user1
	w = login("user1", "1.1.1.")
	token1 = getLoginToken(w)

	// Modify user1 self's password as reader
	pass1 = "1.1.1."
	pass1New = "111111"
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", Password: &pass1, NewPassword: &pass1New}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to modify password: status=%v.", w.status)
	}

	// Check if user is kicked
	if len(loginSessions) != 0 {
		t.Errorf("User1 is not kicked after changing password")
	}

	postTest()
}

func TestUserConfigNegative(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	user1 := makeLocalUser("user1", "111111", api.UserRoleAdmin)
	user2 := makeLocalUser("user2", "222222", api.UserRoleReader)
	_ = clusHelper.CreateUser(user1)
	_ = clusHelper.CreateUser(user2)

	// Login as admin
	w := login("user1", "111111")
	token1 := getLoginToken(w)

	// Modify self email with different name
	email1 := "user1@example.com"
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "any", EMail: &email1}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusBadRequest {
		t.Errorf("Failed to change email: status=%v.", w.status)
	}

	// Modify other's password
	pass2 := "222222"
	pass2New := "2.2.2."
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user2", Password: &pass2, NewPassword: &pass2New}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user2", body, token1)
	if w.status != http.StatusForbidden {
		t.Errorf("Modify other's password should not be allowed: status=%v.", w.status)
	}

	// Make sure user2's password is not changed
	cuser2, _, _ := clusHelper.GetUserRev("user2", accAdmin)
	if cuser2 == nil {
		t.Fatalf("Failed to locate user user2 in cluster")
	}
	if cuser2.Fullname != "user2" || cuser2.PasswordHash != utils.HashPassword("222222") {
		t.Errorf("Incorrect user in cluster: user=%v", *cuser2)
	}

	logout(token1)

	// Login as reader
	w = login("user2", "222222")
	token2 := getLoginToken(w)

	// Modify other's timeout
	var timeout uint32 = 120
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", Timeout: &timeout}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token2)
	if w.status != http.StatusForbidden {
		t.Errorf("Modify other's timeout as reader should not be allowed: status=%v.", w.status)
	}

	logout(token2)

	postTest()
}

func TestUserRoleOther(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	// domainRoles := map[string]string{"ns1": api.UserRoleAdmin, "ns2": api.UserRoleAdmin, "ns3": api.UserRoleReader}
	roleDomains := map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}, api.UserRoleReader: {"ns3"}}

	data := api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleReader,
	}}
	body, _ := json.Marshal(data)
	w := restCallWithRole("POST", "/v1/user", body, "", roleDomains)
	if w.status != http.StatusForbidden {
		t.Fatalf("Create user shouldn't be allowed: status=%v.", w.status)
	}

	// --
	data = api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleNone,
	}}
	body, _ = json.Marshal(data)
	w = restCallWithRole("POST", "/v1/user", body, "", roleDomains)
	if w.status == http.StatusOK {
		t.Fatalf("Create user without any global/domain role is not allowed: status=%v.", w.status)
	}

	// --
	data = api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleNone,
		RoleDomains: map[string][]string{api.UserRoleAdmin: {"ns1"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallWithRole("POST", "/v1/user", body, "", roleDomains)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create user: status=%v.", w.status)
	}

	w = restCall("DELETE", "/v1/user/joe", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete user: status=%v.", w.status)
	}

	// --
	data = api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleNone,
		RoleDomains: map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}, api.UserRoleReader: {"ns3"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallWithRole("POST", "/v1/user", body, "", roleDomains)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to create user: status=%v.", w.status)
	}

	// -- modify other
	data = api.RESTUserData{User: &api.RESTUser{
		Fullname: "joe", Password: "123456", Role: api.UserRoleNone,
		RoleDomains: map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallWithRole("POST", "/v1/user", body, "", roleDomains)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create user: status=%v.", w.status)
	}

	// config
	cfgData := api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "joe",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1"}},
	}}
	body, _ = json.Marshal(cfgData)
	w = restCallWithRole("PATCH", "/v1/user/joe", body, "", roleDomains)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to modify user: status=%v.", w.status)
	}

	cfgData = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "joe",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1", "ns3"}},
	}}
	body, _ = json.Marshal(cfgData)
	w = restCallWithRole("PATCH", "/v1/user/joe", body, "", roleDomains)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to modify user: status=%v.", w.status)
	}

	// ciops
	cfgData = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "joe",
		RoleDomains: &map[string][]string{api.UserRoleCIOps: {"ns4"}},
	}}
	body, _ = json.Marshal(cfgData)
	w = restCallWithRole("PATCH", "/v1/user/joe", body, "", roleDomains)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to modify user with ciops namespace role: status=%v.", w.status)
	}

	w = restCall("DELETE", "/v1/user/joe", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete user: status=%v.", w.status)
	}

	postTest()
}

func TestUserRoleSelf(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// -- make user as global reader & ns1, ns2 admin
	user1 := makeLocalUserWithRole("user1", "111111", api.UserRoleReader,
		map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}},
	)
	_ = clusHelper.CreateUser(user1)

	w := login("user1", "111111")
	token1 := getLoginToken(w)

	// Modify self email
	email1 := "user1@example.com"
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: "user1", EMail: &email1}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change email: status=%v.", w.status)
	}

	// -- now we are global reader & ns1, ns2 admin
	// Modify self domain role, cannot change other ns
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "user1",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1", "ns3"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to modify user domain role: status=%v.", w.status)
	}

	// -- now we are global reader & ns1 admin (ns2 reader implicitly)
	// Should return OK if domain roles are not modified.
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "user1",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1"}, api.UserRoleReader: {"ns2"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to modify user domain role: status=%v.", w.status)
	}

	// Now we should be kicked. Re-login.
	w = login("user1", "111111")
	token1 = getLoginToken(w)

	// -- now we are global reader & ns1 admin (ns2 reader implicitly)
	// We are a reader on 'ns2', so it cannot touch anything on ns2
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "user1",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to modify user domain role: status=%v.", w.status)
	}

	// -- now we are global reader & ns1 admin (ns2 reader implicitly)
	// Should return OK if domain roles are not modified.
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "user1",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1"}, api.UserRoleReader: {"ns2"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to modify user domain role: status=%v.", w.status)
	}

	// -- now we are global reader & ns1 admin (ns2 reader implicitly)
	// This case is arguable, because we are global reader, modify ns2 role to reader should be allowed.
	// Current logic returns ok because we think it's not changed
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname:    "user1",
		RoleDomains: &map[string][]string{api.UserRoleAdmin: {"ns1"}, api.UserRoleReader: {"ns2"}},
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Fatalf("Attempt to modify namespace role that is same as global role is not allowed: status=%v.", w.status)
	}

	// We should not be kicked.

	// Should return OK if reader send a modify request without modify the global role
	newRole := api.UserRoleReader
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname: "user1", Role: &newRole,
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to modify user domain role: status=%v.", w.status)
	}

	// Should reject if reader tries to modify the global role
	newRole = ""
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{
		Fullname: "user1", Role: &newRole,
	}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/user1", body, token1)
	if w.status != http.StatusForbidden {
		t.Fatalf("Shouldn't allow to modify user global role: status=%v.", w.status)
	}

	logout(token1)

	postTest()
}

func TestApikeyCreateDelete(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	data := api.RESTApikeyCreationData{Apikey: &api.RESTApikeyCreation{
		ExpirationType: "never",
		Description:    "unit-test",
		Name:           "token-12345",
		Role:           api.UserRoleReader,
	}}

	body, _ := json.Marshal(data)
	w := restCall("POST", "/v1/api_key", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to create apikey: status=%v.", w.status)
	}

	// Check apikey in cluster
	apikey, _, _ := clusHelper.GetApikeyRev("token-12345", accAdmin)
	if apikey == nil {
		t.Fatalf("Failed to locate apikey in cluster")
	}
	if apikey.Name != "token-12345" || apikey.Role != api.UserRoleReader {
		t.Errorf("Incorrect apikey in cluster: user=%v", apikey)
	}

	// Check get users by REST
	// var resp api.RESTUsersData
	var resp api.RESTApikeysData
	w = restCall("GET", "/v1/api_key", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get apikey: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if len(resp.Apikeys) != 1 {
		t.Errorf("Incorrect apikey count in rest: count=%v expect=1", len(resp.Apikeys))
	}
	user := resp.Apikeys[0]
	if user.Name != "token-12345" || user.Role != api.UserRoleReader {
		t.Errorf("Incorrect apikey in rest: user=%v", *user)
	}

	// Delete user
	w = restCall("DELETE", "/v1/api_key/token-12345", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete apikey: status=%v.", w.status)
	}

	// Check user in cluster
	apikey, _, _ = clusHelper.GetApikeyRev("token-12345", accAdmin)
	if apikey != nil {
		t.Errorf("User is not deleted in cluster")
	}

	// Check get users by REST
	w = restCall("GET", "/v1/api_key", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to get user: status=%v.", w.status)
	}
	_ = json.Unmarshal(w.body, &resp)
	if len(resp.Apikeys) != 0 {
		t.Errorf("Incorrect apikey count in rest: count=%v expect=0", len(resp.Apikeys))
	}

	postTest()
}
