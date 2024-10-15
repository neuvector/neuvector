package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
)

func TestRoles(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	{
		ldap := api.RESTServerLDAP{Type: "OpenLDAP", Hostname: "1.2.3.4", BaseDN: "ou=people"}
		lcfg := api.RESTServerLDAPConfig{Type: &ldap.Type, Hostname: &ldap.Hostname, BaseDN: &ldap.BaseDN}
		data := api.RESTServerConfigData{Config: &api.RESTServerConfig{Name: "s1", LDAP: &lcfg}}
		body, _ := json.Marshal(data)
		w := restCall("POST", "/v1/server", body, api.UserRoleCIOps)

		if w.status != http.StatusForbidden && w.status != http.StatusBadRequest {
			t.Errorf("Creating server as CIOps should not be allowed: %v", w.status)
		}
	}

	{
		// Create a user
		data := api.RESTUserData{User: &api.RESTUser{
			Fullname: "joe", Password: "123456", Role: api.UserRoleReader,
		}}
		body, _ := json.Marshal(data)
		_ = restCall("POST", "/v1/user", body, api.UserRoleAdmin)

		// Get as reader
		var resp api.RESTUsersData
		w := restCall("GET", "/v1/user", nil, api.UserRoleReader)
		if w.status != http.StatusOK {
			t.Errorf("Get user failed: %v", w.status)
		}
		_ = json.Unmarshal(w.body, &resp)
		if len(resp.Users) != 1 {
			t.Errorf("Incorrect user count in rest: count=%v expect=1", len(resp.Users))
		}

		// Get as ciops
		w = restCall("GET", "/v1/user", nil, api.UserRoleCIOps)
		if w.status != http.StatusOK {
			t.Errorf("Get user failed: %v", w.status)
		}
		if w.status != http.StatusOK {
			t.Errorf("Get user failed: %v", w.status)
		}
		_ = json.Unmarshal(w.body, &resp)
		if len(resp.Users) != 0 {
			t.Errorf("CIOps user should not be able to get user list: count=%v expect=0", len(resp.Users))
		}
	}

	postTest()
}
