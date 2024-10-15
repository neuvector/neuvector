package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/utils"
)

type passwordUser struct {
	username string
	password string
	groups   []string
}

type samlUser struct {
	attrs map[string][]string
}

type oidcUser struct {
	claims map[string]interface{}
}

type mockRemoteAuth struct {
	auth.RemoteAuthInterface

	users     map[string]*passwordUser
	samlUsers map[string]*samlUser
	oidcUsers map[string]*oidcUser
}

func (a *mockRemoteAuth) addPasswordUser(username, password string, groups []string) {
	user := &passwordUser{username: username, password: password, groups: groups}
	a.users[username] = user
}

func (a *mockRemoteAuth) addSAMLUser(token string, attrs map[string][]string) {
	a.samlUsers[token] = &samlUser{attrs: attrs}
}

func (a *mockRemoteAuth) addOIDCUser(token string, claims map[string]interface{}) {
	a.oidcUsers[token] = &oidcUser{claims: claims}
}

func (a *mockRemoteAuth) LDAPAuth(ldap *share.CLUSServerLDAP, username, password string) (map[string]string, []string, error) {
	if user, ok := a.users[username]; !ok {
		return nil, nil, errors.New("Authentication failed")
	} else if user.password != password {
		return nil, nil, errors.New("Authentication failed")
	} else {
		return make(map[string]string), user.groups, nil
	}
}

func (a *mockRemoteAuth) SAMLSPAuth(csaml *share.CLUSServerSAML, tokenData *api.RESTAuthToken) (string, string, map[string][]string, error) {
	if user, ok := a.samlUsers[tokenData.Token]; ok {
		return "nameID", "sessionIndex", user.attrs, nil
	} else {
		return "", "", nil, errors.New("Authentication failed")
	}
}

func (a *mockRemoteAuth) OIDCDiscover(issuer string, proxy string) (string, string, string, string, error) {
	return "", "", "", "", nil
}

func (a *mockRemoteAuth) OIDCAuth(coidc *share.CLUSServerOIDC, tokenData *api.RESTAuthToken) (map[string]interface{}, error) {
	if user, ok := a.oidcUsers[tokenData.Token]; ok {
		return user.claims, nil
	} else {
		return nil, errors.New("Authentication failed")
	}
}

func makeLocalUser(username, password, role string) *share.CLUSUser {
	return &share.CLUSUser{
		Fullname:     username,
		Username:     username,
		PasswordHash: utils.HashPassword(password),
		Role:         role,
		Timeout:      common.DefaultIdleTimeout,
	}
}

func makeLocalUserWithRole(username, password, role string, roleDomains map[string][]string) *share.CLUSUser {
	return &share.CLUSUser{
		Fullname:     username,
		Username:     username,
		PasswordHash: utils.HashPassword(password),
		Role:         role,
		Timeout:      common.DefaultIdleTimeout,
		RoleDomains:  roleDomains,
	}
}

func getLoginToken(w *mockResponseWriter) string {
	var data api.RESTTokenData
	_ = json.Unmarshal(w.body, &data)
	return data.Token.Token
}

func checkUserAttrs(w *mockResponseWriter, server, user, role string, tmo uint32) error {
	// Check returned User attributes
	var data api.RESTTokenData
	_ = json.Unmarshal(w.body, &data)
	if data.Token.Server != server || data.Token.Username != user || data.Token.Role != role {
		return fmt.Errorf("Error in user attributes: %+v", *data.Token)
	}

	// Check login user attributes
	if login, ok := loginSessions[data.Token.Token]; !ok {
		return fmt.Errorf("Cannot find login user: %+v", loginSessions)
	} else if login.fullname != utils.MakeUserFullname(server, user) {
		return fmt.Errorf("Error in login user attributes: %+v", login.fullname)
	} else if r, ok := login.domainRoles[""]; !ok || r != role {
		return fmt.Errorf("Error in login user role: %+v", login.fullname)
	} else if tmo != 0 && login.timeout != tmo {
		return fmt.Errorf("Error in login user timeout: %+v", login.fullname)
	}

	return nil
}

func TestLocalLogin(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	user := makeLocalUser("user", "pass", api.UserRoleReader)
	_ = clusHelper.CreateUser(user)

	cacher = &mockCache{}

	w := login("user", "pass")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "", "user", api.UserRoleReader, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	/*
		w = login("user", "wrong")
		if w.status != http.StatusUnauthorized {
			t.Errorf("Login should fail: status=%v.", w.status)
		}
	*/

	postTest()
}

func TestLDAPLogin(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := share.CLUSServer{
		Name: "ldap1", Enable: true,
		LDAP: &share.CLUSServerLDAP{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
		},
	}
	_ = clusHelper.PutServerRev(&ldap, 0)

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group2"})
	remoteAuther = &mockAuther

	// Explictly set auth-order
	cacher = &mockCache{
		systemConfig: api.RESTSystemConfig{AuthOrder: []string{"ldap1"}},
	}

	// Role group mapping doesn't match, no default role => should fail
	w := login("user", "pass")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no matched role: status=%v.", w.status)
	}

	// Set user group membership to match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})

	w = login("user", "pass")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "ldap1", "user", api.UserRoleReader, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	// Revert user group membership, add default role to server
	mockAuther.addPasswordUser("user", "pass", []string{"group2"})
	ldap.LDAP.DefaultRole = api.UserRoleAdmin
	_ = clusHelper.PutServerRev(&ldap, 0)

	w = login("user", "pass")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "ldap1", "user", api.UserRoleAdmin, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	postTest()
}

/* TODO: Shadow User
func TestLDAPLoginShadowUser(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := share.CLUSServer{
		Name: "ldap1", Enable: true,
		LDAP: &share.CLUSServerLDAP{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					&share.GroupRoleMapping{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
		},
	}
	clusHelper.PutServerRev(&ldap, 0)

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group2"})
	remoteAuther = &mockAuther

	// Explictly set auth-order
	cacher = &mockCache{
		systemConfig: api.RESTSystemConfig{AuthOrder: []string{"ldap1"}},
	}

	w := login("user", "wrong")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, wrong password: status=%v.", w.status)
	}
	if _, authz := lookupShadowUser(ldap.Name, "", "user", ""); authz {
		t.Errorf("No shadow user should be created.")
	}

	// Role group mapping doesn't match, no default role => should fail
	w = login("user", "pass")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no matched role: status=%v.", w.status)
	}
	if user, authz := lookupShadowUser(ldap.Name, "", "user", ""); user == nil {
		t.Errorf("Shadow user should be created.")
	} else if authz {
		t.Errorf("Shadow user should not be authorized.")
	} else if user.Username != "user" || user.Server != ldap.Name {
		t.Errorf("Invalid shadow user: user=%+v.", user)
	}

	fullname := utils.MakeUserFullname(ldap.Name, "user")

	// Modify user's timeout and role by admin
	admin := makeLocalUser("admin", "admin", api.UserRoleAdmin)
	clusHelper.CreateUser(admin)
	w = login("admin", "admin")
	tokenAdmin := getLoginToken(w)

	var timeout uint32 = 600
	var role string = api.UserRoleReader
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Timeout: &timeout, Role: &role}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout and role: status=%+v.", w.status)
	}

	// User should be able to login now
	w = login("user", "pass")
	if w.status != http.StatusOK {
		t.Errorf("Login should succeed: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, ldap.Name, "user", api.UserRoleReader, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Reset the shadow user role
	role = ""
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Role: &role}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout and role: status=%+v.", w.status)
	}
	logout(tokenAdmin)

	// Set user group membership to match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})

	w = login("user", "pass")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, "ldap1", "user", api.UserRoleReader, timeout); err != nil {
		t.Error(err.Error())
	}

	// Change timeout as the user
	token := getLoginToken(w)
	timeout = 150
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Timeout: &timeout}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, token)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout as user self: status=%+v.", w.status)
	}
	logout(token)

	// Verify timeout indeed changed
	w = login("user", "pass")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, "ldap1", "user", api.UserRoleReader, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Try to login with the fullname, should fail
	w = login(fullname, "")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login with fullname should fail: status=%v.", w.status)
	}

	// Delete the shadow user
	w = restCall("DELETE", "/v1/user/"+fullname, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete the shadow user: status=%v.", w.status)
	}

	postTest()
}
*/

func TestLocalLoginServer(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	user := makeLocalUser("user", "pass", api.UserRoleAdmin)
	_ = clusHelper.CreateUser(user)

	cacher = &mockCache{}

	w := loginServerPassword("user", "pass", "local")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v", w.status)
	}

	if err := checkUserAttrs(w, "", "user", api.UserRoleAdmin, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	if len(loginSessions) != 0 {
		t.Errorf("Incorrect number of login users: %v", len(loginSessions))
	}

	w = loginServerPassword("user", "wrong", "local")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail: status=%v", w.status)
	}

	w = loginServerPassword("user", "", "local")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login with empty password should fail: status=%v", w.status)
	}

	postTest()
}

func TestLDAPLoginServer(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	ldap := share.CLUSServer{
		Name: "ldap1", Enable: true,
		LDAP: &share.CLUSServerLDAP{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
		},
	}
	_ = clusHelper.PutServerRev(&ldap, 0)

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})
	mockAuther.addPasswordUser("empty", "", []string{"group2"})
	remoteAuther = &mockAuther

	w := loginServerPassword("user", "pass", "ldap1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "ldap1", "user", api.UserRoleReader, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	// event the record exists, the empty password login should be blocked
	w = loginServerPassword("empty", "", "ldap1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login with empty password should fail: status=%v", w.status)
	}
	postTest()
}

func TestSAMLLogin(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// Add both ldap and saml
	ldap := share.CLUSServer{
		Name: "ldap1", Enable: true,
		LDAP: &share.CLUSServerLDAP{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
		},
	}
	_ = clusHelper.PutServerRev(&ldap, 0)

	// Not enabled
	saml := share.CLUSServer{
		Name: "saml1",
		SAML: &share.CLUSServerSAML{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
			SSOURL:   "sso",
			Issuer:   "issuer",
			X509Cert: "cert",
		},
	}
	_ = clusHelper.PutServerRev(&saml, 0)

	mockAuther := mockRemoteAuth{samlUsers: make(map[string]*samlUser)}
	mockAuther.addSAMLUser("token", map[string][]string{"Email": {"joe@example.com"}})
	remoteAuther = &mockAuther

	w := loginServerToken("token", "saml1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, server not enable: status=%v.", w.status)
	}
	w = loginServerToken("token", "ldap1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, smal login to ldap: status=%v.", w.status)
	}

	// Enable saml server
	saml.Enable = true
	w = loginServerToken("token", "saml1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no role or username: status=%v.", w.status)
	}

	// Set default role
	saml.SAML.DefaultRole = api.UserRoleAdmin
	w = loginServerToken("token", "saml1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "saml1", "joe@example.com", api.UserRoleAdmin, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	postTest()
}

func TestSAMLLoginShadowUser(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cacher = &mockCache{}

	// Not enabled
	saml := share.CLUSServer{
		Name: "saml1",
		SAML: &share.CLUSServerSAML{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
			SSOURL:   "sso",
			Issuer:   "issuer",
			X509Cert: "cert",
		},
	}
	_ = clusHelper.PutServerRev(&saml, 0)

	username := "joe"
	mockAuther := mockRemoteAuth{samlUsers: make(map[string]*samlUser)}
	mockAuther.addSAMLUser("joe-token", map[string][]string{"Username": {username}})
	remoteAuther = &mockAuther

	w := loginServerToken("joe-token", "saml1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, server not enable: status=%v.", w.status)
	}
	if _, authz := lookupShadowUser(saml.Name, "", username, "", "", "", make(map[string][]string), share.NvPermissions{}, nil, nil); authz {
		t.Errorf("No shadow user should be created.")
	}

	fullname := utils.MakeUserFullname(saml.Name, username)

	// Enable saml server
	saml.Enable = true
	w = loginServerToken("joe-token", "saml1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no role or username: status=%v.", w.status)
	}
	if user, _, _ := clusHelper.GetUserRev(fullname, access.NewReaderAccessControl()); user != nil {
		t.Errorf("Shadow user should not be created.")
	}

	// Add default role to SAML server. Login again, should be allowed
	saml.SAML.DefaultRole = api.UserRoleCIOps
	w = loginServerToken("joe-token", "saml1")
	if w.status != http.StatusOK {
		t.Errorf("Login should succeed: status=%v.", w.status)
	}
	if user, _, _ := clusHelper.GetUserRev(fullname, access.NewReaderAccessControl()); user == nil {
		t.Errorf("Shadow user should be created.")
	} else if user.Username != username || user.Server != saml.Name {
		t.Errorf("Invalid shadow user: user=%+v.", user)
	}
	logout(getLoginToken(w))

	// Modify user's timeout and role by admin
	admin := makeLocalUser("admin", "admin", api.UserRoleAdmin)
	_ = clusHelper.CreateUser(admin)
	w = login("admin", "admin")
	tokenAdmin := getLoginToken(w)

	// Set user timeout
	var timeout uint32 = 600
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Timeout: &timeout}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout: status=%+v.", w.status)
	}

	// User timeout should be updated
	w = loginServerToken("joe-token", "saml1")
	if w.status != http.StatusOK {
		t.Errorf("Login should succeed: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, saml.Name, username, api.UserRoleCIOps, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Set default role in saml
	saml.SAML.DefaultRole = api.UserRoleAdmin

	w = loginServerToken("joe-token", "saml1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, saml.Name, username, api.UserRoleAdmin, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Set user role
	role := api.UserRoleReader
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Role: &role}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change role: status=%+v.", w.status)
	}

	// Try login again and check user role
	w = loginServerToken("joe-token", "saml1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, saml.Name, username, api.UserRoleReader, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Try to login with the fullname, should fail
	w = login(fullname, "")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login with fullname should fail: status=%v.", w.status)
	}

	// Delete the shadow user
	w = restCall("DELETE", "/v1/user/"+fullname, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete the shadow user: status=%v.", w.status)
	}

	logout(tokenAdmin)

	postTest()
}

func samlAuthz(cs *share.CLUSServer, attrs map[string][]string) (*share.CLUSUser, string, error) {
	username, email, groups := getSAMLUserFromAttrs(attrs, "")
	if username == "" {
		return nil, "", errors.New("Unable to locate username")
	} else {
		user, err := tokenServerAuthz(cs, username, email, groups)
		return user, username, err
	}
}

func TestSAMLAttrs(t *testing.T) {
	preTest()

	cs1 := &share.CLUSServer{Name: "saml1", Enable: true,
		SAML: &share.CLUSServerSAML{},
	}
	cs2 := &share.CLUSServer{Name: "saml1", Enable: true,
		SAML: &share.CLUSServerSAML{CLUSServerAuth: share.CLUSServerAuth{
			DefaultRole: api.UserRoleAdmin,
		}},
	}
	cs3 := &share.CLUSServer{Name: "saml1", Enable: true,
		SAML: &share.CLUSServerSAML{CLUSServerAuth: share.CLUSServerAuth{
			GroupMappedRoles: []*share.GroupRoleMapping{
				{
					Group:       "admin_group1",
					GlobalRole:  api.UserRoleAdmin,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "admin_group2",
					GlobalRole:  api.UserRoleAdmin,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "reader_group1",
					GlobalRole:  api.UserRoleReader,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "reader_group2",
					GlobalRole:  api.UserRoleReader,
					RoleDomains: make(map[string][]string),
				},
			},
		}},
	}
	cs4 := &share.CLUSServer{Name: "saml1", Enable: true,
		SAML: &share.CLUSServerSAML{CLUSServerAuth: share.CLUSServerAuth{
			DefaultRole: api.UserRoleReader,
			GroupMappedRoles: []*share.GroupRoleMapping{
				{
					Group:       "admin_group1",
					GlobalRole:  api.UserRoleAdmin,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "admin_group2",
					GlobalRole:  api.UserRoleAdmin,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "reader_group1",
					GlobalRole:  api.UserRoleReader,
					RoleDomains: make(map[string][]string),
				},
				{
					Group:       "reader_group2",
					GlobalRole:  api.UserRoleReader,
					RoleDomains: make(map[string][]string),
				},
			},
		}},
	}
	attr1 := map[string][]string{
		"Username": {"joe"},
	}
	attr2 := map[string][]string{
		"NVRoleGroup": {"test_group"},
	}
	attr3 := map[string][]string{
		"NVRoleGroup": {"test_group", "reader_group2"}, "Username": {"paul"},
	}
	attr4 := map[string][]string{
		"NVRoleGroup": {"test_group", "admin_group1"}, "Email": {"jane@example.com"},
	}

	if user, username, err := samlAuthz(cs4, nil); err == nil {
		t.Errorf("Should fail, nil attrs: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs1, attr4); err == nil {
		t.Errorf("Should fail, no role: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs2, attr1); err != nil {
		t.Errorf("Should succeed: error=%v", err)
	} else if user.Role != api.UserRoleAdmin || user.Username != "joe" || user.Fullname != "saml1:joe" {
		t.Errorf("Incorrect user: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs2, attr2); err == nil {
		t.Errorf("Should fail, no user: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs2, attr4); err != nil {
		t.Errorf("Should succeed: error=%v", err)
	} else if user.Role != api.UserRoleAdmin || user.Username != "jane@example.com" || user.Fullname != "saml1:jane@example.com" {
		t.Errorf("Incorrect user: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs3, attr2); err == nil {
		t.Errorf("Should fail, no role: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs3, attr3); err != nil {
		t.Errorf("Should succeed: error=%v", err)
	} else if user.Role != api.UserRoleReader || user.Username != "paul" || user.Fullname != "saml1:paul" {
		t.Errorf("Incorrect user: user=%v username=%v", user, username)
	}
	if user, username, err := samlAuthz(cs4, attr4); err != nil {
		t.Errorf("Should succeed: error=%v", err)
	} else if user.Role != api.UserRoleAdmin || user.Username != "jane@example.com" || user.Fullname != "saml1:jane@example.com" {
		t.Errorf("Incorrect user: user=%v username=%v", user, username)
	}

	postTest()
}

func TestOIDCLogin(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// Add both ldap and oidc
	ldap := share.CLUSServer{
		Name: "ldap1", Enable: true,
		LDAP: &share.CLUSServerLDAP{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
		},
	}
	_ = clusHelper.PutServerRev(&ldap, 0)

	// Not enabled
	oidc := share.CLUSServer{
		Name: "oidc1",
		OIDC: &share.CLUSServerOIDC{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
			Issuer: "issuer",
		},
	}
	_ = clusHelper.PutServerRev(&oidc, 0)

	mockAuther := mockRemoteAuth{oidcUsers: make(map[string]*oidcUser)}
	mockAuther.addOIDCUser("token", map[string]interface{}{oidcPreferredNameKey: "joe@example.com"})
	remoteAuther = &mockAuther

	w := loginServerToken("token", "oidc1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, server not enable: status=%v.", w.status)
	}
	w = loginServerToken("token", "ldap1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, smal login to ldap: status=%v.", w.status)
	}

	// Enable oidc server
	oidc.Enable = true
	w = loginServerToken("token", "oidc1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no role or username: status=%v.", w.status)
	}

	// Set default role
	oidc.OIDC.DefaultRole = api.UserRoleAdmin
	w = loginServerToken("token", "oidc1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}

	if err := checkUserAttrs(w, "oidc1", "joe@example.com", api.UserRoleAdmin, 0); err != nil {
		t.Error(err.Error())
	}

	logout(getLoginToken(w))

	postTest()
}

/* TODO: Shadow User
func TestOIDCLoginShadowUser(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// Not enabled
	oidc := share.CLUSServer{
		Name: "oidc1",
		OIDC: &share.CLUSServerOIDC{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: []*share.GroupRoleMapping{
					&share.GroupRoleMapping{
						Group:       "group1",
						GlobalRole:  api.UserRoleReader,
						RoleDomains: make(map[string][]string),
					},
				},
			},
			Issuer: "issuer",
		},
	}
	clusHelper.PutServerRev(&oidc, 0)

	username := "joe"
	mockAuther := mockRemoteAuth{oidcUsers: make(map[string]*oidcUser)}
	mockAuther.addOIDCUser("token", &auth.OIDCClaims{PreferredName: username})
	remoteAuther = &mockAuther

	w := loginServerToken("token", "oidc1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, server not enable: status=%v.", w.status)
	}
	if _, authz := lookupShadowUser(oidc.Name, "", username, ""); authz {
		t.Errorf("No shadow user should be created.")
	}

	// Enable oidc server
	oidc.Enable = true
	w = loginServerToken("token", "oidc1")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login should fail, no role or username: status=%v.", w.status)
	}
	if user, authz := lookupShadowUser(oidc.Name, "", username, ""); user == nil {
		t.Errorf("Shadow user should be created.")
	} else if authz {
		t.Errorf("Shadow user should not be authorized.")
	} else if user.Username != username || user.Server != oidc.Name {
		t.Errorf("Invalid shadow user: user=%+v.", user)
	}

	fullname := utils.MakeUserFullname(oidc.Name, username)

	// Modify user's timeout and role by admin
	admin := makeLocalUser("admin", "admin", api.UserRoleAdmin)
	clusHelper.CreateUser(admin)
	w = login("admin", "admin")
	tokenAdmin := getLoginToken(w)

	var timeout uint32 = 600
	var role string = api.UserRoleReader
	data := api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Timeout: &timeout, Role: &role}}
	body, _ := json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout and role: status=%+v.", w.status)
	}

	// User should be able to login now
	w = loginServerToken("token", "oidc1")
	if w.status != http.StatusOK {
		t.Errorf("Login should succeed: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, oidc.Name, username, api.UserRoleReader, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Reset the shadow user role
	role = ""
	data = api.RESTUserConfigData{Config: &api.RESTUserConfig{Fullname: fullname, Role: &role}}
	body, _ = json.Marshal(data)
	w = restCallToken("PATCH", "/v1/user/"+fullname, body, tokenAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Failed to change timeout and role: status=%+v.", w.status)
	}
	logout(tokenAdmin)

	// Set default role in oidc
	oidc.OIDC.DefaultRole = api.UserRoleAdmin

	w = loginServerToken("token", "oidc1")
	if w.status != http.StatusOK {
		t.Fatalf("Failed to login user: status=%v.", w.status)
	}
	if err := checkUserAttrs(w, oidc.Name, username, api.UserRoleAdmin, timeout); err != nil {
		t.Error(err.Error())
	}
	logout(getLoginToken(w))

	// Try to login with the fullname, should fail
	w = login(fullname, "")
	if w.status != http.StatusUnauthorized {
		t.Errorf("Login with fullname should fail: status=%v.", w.status)
	}

	// Delete the shadow user
	w = restCall("DELETE", "/v1/user/"+fullname, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete the shadow user: status=%v.", w.status)
	}

	postTest()
}
*/

func TestJWTSignValidate(t *testing.T) {
	preTest()

	user := &share.CLUSUser{
		Fullname: "gary",
		Username: "gary",
		EMail:    "gary@example.com",
		Timeout:  300,
	}
	roles := access.DomainRole{
		"":    api.UserRoleReader,
		"ns1": api.UserRoleAdmin,
	}
	remote := "10.1.2.3"

	_, tokenString, _ := jwtGenerateToken(user, roles, nil, remote, "", "", nil)

	token, _ := jwtValidateToken(tokenString, "", nil)
	if token.Fullname != user.Fullname {
		t.Errorf("Token doesn't match: user=%+v token=%+v", user, token)
	}

	postTest()
}

func TestGroupMapping(t *testing.T) {
	preTest()

	/*defaultRole := ""
	memberof := []string{"Marketing", "Finance", "Sales"}
	roleGroups := map[string][]string{
		api.UserRoleAdmin:  []string{"finance", "R&D"},
		api.UserRoleReader: []string{"Sales", "it"},
	}

	role := getRoleFromGroupMapping(memberof, roleGroups, defaultRole, true) //->
	if role != api.UserRoleReader {
		t.Errorf("Incorrect role mapping in case of case-sensitive")
	}

	role = getRoleFromGroupMapping(memberof, roleGroups, defaultRole, false)
	if role != api.UserRoleAdmin {
		t.Errorf("Incorrect role mapping in case of case-insensitive")
	}*/

	postTest()
}
