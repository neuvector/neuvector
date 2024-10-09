package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

func TestIBMSAIntegration(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &cache.CacheMethod{}
	cache.MockCacheInit()
	clusHelper.SetCacheMockCallback(share.CLUSConfigSystemKey, cache.MockSystemConfigUpdate)
	clusHelper.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	ibmSAEpEnabled := true
	ibmSAEpDashboardURL := _testingFindingURL
	// Config system to enable IBM SA integration
	data := api.RESTSystemConfigConfigData{
		Config: &api.RESTSystemConfigConfig{
			IBMSAEpEnabled:      &ibmSAEpEnabled,
			IBMSAEpDashboardURL: &ibmSAEpDashboardURL,
		},
	}

	body, _ := json.Marshal(data)
	w := restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to enable IBM SA integration: status=%v.", w.status)
	}

	// Check configured role by REST
	var resp api.RESTSystemConfigData
	if w := restCall("GET", "/v1/system/config", nil, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to get IBM SA integration config: status=%v.", w.status)
	} else {
		json.Unmarshal(w.body, &resp)
		if resp.Config == nil {
			t.Fatalf("Nil IBM SA integration config by REST")
		} else {
			if !resp.Config.IBMSAEpEnabled || resp.Config.IBMSAEpStart != 0 || resp.Config.IBMSAEpDashboardURL != ibmSAEpDashboardURL {
				t.Fatalf("Incorrect IBM SA integration config by REST: IBMSAEpEnabled=%v, IBMSAEpStart=%v, IBMSAEpDashboardURL=%v",
					resp.Config.IBMSAEpEnabled, resp.Config.IBMSAEpStart, resp.Config.IBMSAEpDashboardURL)
			}
		}
	}

	{
		// Custom role with permission
		dataRoles := []api.RESTUserRoleConfigData{
			api.RESTUserRoleConfigData{
				Config: &api.RESTUserRoleConfig{
					Name:    "custom-role-1", // has view configuration permission
					Comment: "modify configuration",
					Permissions: []*api.RESTRolePermission{
						&api.RESTRolePermission{ID: "config", Read: true},
					},
				},
			},
			api.RESTUserRoleConfigData{
				Config: &api.RESTUserRoleConfig{
					Name:    "custom-role-2", // has view/modify configuration permission
					Comment: "modify configuration",
					Permissions: []*api.RESTRolePermission{
						&api.RESTRolePermission{ID: "config", Write: true},
					},
				},
			},
		}
		usersData := make([]*api.RESTUserData, 2)
		for idx, dataRole := range dataRoles {
			// Create custom role
			body1, _ := json.Marshal(dataRole)
			w := restCall("POST", "/v1/user_role", body1, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Fatalf("Failed to create role: status=%v.", w.status)
			}
			// Create user with the custom role
			userData := api.RESTUserData{User: &api.RESTUser{
				Fullname: fmt.Sprintf("joe-%d", idx), Password: "123456", Role: dataRole.Config.Name,
				RoleDomains: map[string][]string{},
			}}
			body2, _ := json.Marshal(userData)
			w = restCall("POST", "/v1/user", body2, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Fatalf("Failed to create user with custom role: status=%v.", w.status)
			}
			usersData[idx] = &userData
		}

		ibmsaEpUri := "/v1/partner/ibm_sa_ep"
		expectedStatus := []int{http.StatusForbidden, http.StatusOK} // config:r is forbidden. config:w is allowed.
		for idx, userData := range usersData {
			// Login as the user with config:r permission and get token. should fail
			w = login(userData.User.Fullname, userData.User.Password)
			if w.status != http.StatusOK {
				t.Fatalf("Failed to login user: status=%v.", w.status)
			}
			token := getLoginToken(w)
			// Users with any non-admin role cannot get IBM SA setup URL
			if w = restCallToken("GET", ibmsaEpUri, nil, token); w.status != expectedStatus[idx] {
				t.Fatalf("Unexpected authorization result(%+v): URI=%v, expected=%+v.", w.status, ibmsaEpUri, expectedStatus[idx])
			}
		}
		for idx, dataRole := range dataRoles {
			// Delete the created user with custom role
			w = restCall("DELETE", "/v1/user/"+usersData[idx].User.Fullname, nil, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Fatalf("Failed to delete user: status=%v.", w.status)
			}
			// Delete custom role
			w = restCall("DELETE", "/v1/user_role/"+dataRole.Config.Name, nil, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Fatalf("Failed to delete role: status=%v.", w.status)
			}
		}
	}

	var ibmID string
	// Simulate Manager to get IBM SA setup URL in NV
	var respIBMSASetupUrl api.RESTIBMSASetupUrl
	if w := restCall("GET", "/v1/partner/ibm_sa_ep", nil, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to get IBM SA setup URL: status=%v.", w.status)
	} else {
		json.Unmarshal(w.body, &respIBMSASetupUrl)
		if i := strings.Index(respIBMSASetupUrl.URL, "/v1/partner/ibm_sa/"); i < 0 {
			t.Fatalf("Invalid IBM SA Endpoint URL in NV")
		} else {
			temp := respIBMSASetupUrl.URL[i+len("/v1/partner/ibm_sa/"):]
			ss := strings.Split(temp, "/")
			ibmID = ss[0]
		}
	}
	// fmt.Printf("ibmID=%s\n", ibmID)
	setupURI := fmt.Sprintf("/v1/partner/ibm_sa/%s/setup", ibmID)
	cfgURI := fmt.Sprintf("/v1/partner/ibm_sa/%s/setup/configuration", ibmID)
	testURI := fmt.Sprintf("/v1/partner/ibm_sa/%s/setup/test", ibmID)
	infoURIs := []string{"/v1/partner/ibm_sa/%s/setup/dashboard", "/v1/partner/ibm_sa/%s/setup/metadata"}
	for idx, infoURI := range infoURIs {
		infoURIs[idx] = fmt.Sprintf(infoURI, ibmID)
	}

	// Simulate IBM SA to get dashboard info from NV. Because ibmsa integration setup is not done yet, it should fail
	for _, infoURI := range infoURIs {
		if w := restCall("GET", infoURI, nil, api.UserRoleAdmin); w.status == http.StatusOK {
			t.Fatalf("Surprised to get IBM SA info from NV")
		}
	}

	if len(loginSessions) != 0 {
		t.Fatalf("Incorrect number of login users: %v", len(loginSessions))
	}

	// GET("/v1/partner/ibm_sa/%s/setup") requires default admin user in kv as a user template for generating a token for the reserved ibmsa user
	user := &share.CLUSUser{
		Fullname:     common.ReservedUserNameIBMSA,
		Username:     common.ReservedUserNameIBMSA,
		PasswordHash: "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec",
		Role:         api.UserRoleIBMSA,
		RoleDomains:  map[string][]string{},
		Locale:       "en",
		Timeout:      300,
		LoginCount:   1,
	}
	clusHelper.PutUserRev(user, 0)
	// Get a login token(with IBMSA role/permission only) from NV. This token generation makes loginSessions size to increase by 1
	var respIBMSASetupToken api.RESTIBMSASetupToken
	if w := restCall("GET", setupURI, nil, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to get login token: status=%v.", w.status)
	} else {
		json.Unmarshal(w.body, &respIBMSASetupToken)
		if respIBMSASetupToken.AccessToken == "" {
			t.Fatalf("Invalid NV login token")
		}
	}
	clusHelper.DeleteUser(common.ReservedUserNameIBMSA)
	if len(loginSessions) != 1 {
		t.Fatalf("Incorrect number of login users: %v", len(loginSessions))
	}

	k8sPlatform = true                // so that we could test admission control's handler
	nvURIs403 := map[string][]string{ // key is http verb, value is URIs with the sme verb
		"GET": []string{
			"/v1/meter",
			"/v1/scan/config",
			"/v1/list/registry_type",
			"/v1/sniffer/:id",
			"/v1/admission/options",
			//"/v1/session", 			// this is actually a LIST API. So ibmsa token always gets an empty list instead of 403
			//"/v1/custom_check/g1",	// this is actually a LIST API. So ibmsa token always gets an empty list instead of 403
			"/v1/system/config",
			"/v1/fed/member",
		},
		"POST": []string{
			"/v1/debug/controller/sync/:id",
			"/v1/controller/:id/profiling",
			"/v1/enforcer/:id/profiling",
			"/v1/scan/repository",
			"/v1/sniffer",
		},
		"DELETE": []string{
			"/v1/conversation_endpoint/:id",
			"/v1/conversation",
			"/v1/session",
		},
	}
	nvURIs404 := map[string][]string{ // key is http verb, value is URIs with the sme verb
		"GET": []string{
			"/v1/controller/:id/config", // this is gets 404 because the specified controller is not found
			"/v1/log/threat/abc",        // this returns 404 because we don't return 403 for those objects, like Threat, that support domain permission
			"/v1/user/alex",             // this returns 404 because we don't return 403 for those objects, like CLUSUser, that support domain permission
			"/v1/server/:name",
		},
	}

	nvURIsAll := map[int]map[string][]string{ // key is http status code
		http.StatusForbidden: nvURIs403,
		http.StatusNotFound:  nvURIs404,
	}
	// Check if this token for ibmsa user can access any resource in NV (expection: NO)
	for statusCode, nvURIs := range nvURIsAll {
		for verb, URIs := range nvURIs {
			for _, uri := range URIs {
				ss := strings.Split(uri, "/")
				for idx, s := range ss {
					if len(s) > 0 && s[0] == ':' {
						ss[idx] = "1234567"
					}
				}
				uriStr := strings.Join(ss, "/")
				//uriStr := strings.Replace(uri, ":", "", -1)
				w = restCallToken(verb, uriStr, nil, respIBMSASetupToken.AccessToken)
				if w.status != statusCode {
					t.Fatalf("Surprised to authorize successfully: verb=%s, URI=%v, status=%+v.", verb, uriStr, w.status)
				}
			}
		}
	}

	k8sPlatform = false
	w = restCallToken("GET", "/v1/selfuser", nil, respIBMSASetupToken.AccessToken) // We temporarily give authorization permission in "/v1/selfuser" handler.
	if w.status != http.StatusNotFound {                                           // However, we don't allow ibmsa token being used to query the user info of the special token. In this special case handler returns 404.
		t.Fatalf("Surprised to authorize GET(/v1/selfuser) with unexpected result: status=%+v.", w.status)
	}

	// Simulate IBM SA to get dashboard info from NV. Because integration setup is not finished yet, it should fail
	for _, infoURI := range infoURIs {
		if w := restCall("GET", infoURI, nil, api.UserRoleAdmin); w.status == http.StatusOK {
			t.Fatalf("Surprised to get IBM SA info(%s) from NV.", infoURI)
		}
	}

	cfg := share.CLUSIBMSAConfig{
		AccountID:   "FAKE_AccountID_VALUE",
		APIKey:      "FAKE_APIKey_VALUE",
		ProviderID:  "FAKE_ServiceId_VALUE", // "ServiceId-...............",
		FindingsURL: _testingFindingURL,
		TokenURL:    "https://10.1.1.1/identity/token",
	}
	body, _ = json.Marshal(cfg)
	// Even admin cannot configure only-known-by-IBMSA resource
	if w := restCall("POST", cfgURI, body, api.UserRoleAdmin); w.status != http.StatusForbidden {
		t.Fatalf("Surprised for admin to authorize successfully: URI=%v, status=%+v.", cfgURI, w.status)
	}

	{
		// Custom role with permission
		dataRole := api.RESTUserRoleConfigData{
			Config: &api.RESTUserRoleConfig{
				Name:    "custom-role-1", // has view/modify authorization permission
				Comment: "modify rt_scan",
				Permissions: []*api.RESTRolePermission{
					&api.RESTRolePermission{ID: "rt_scan", Write: true},
				},
			},
		}
		// Create custom role
		body1, _ := json.Marshal(dataRole)
		w := restCall("POST", "/v1/user_role", body1, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to create role: status=%v.", w.status)
		}
		// Create user with the custom role
		userData := api.RESTUserData{User: &api.RESTUser{
			Fullname: "joe23", Password: "123456", Role: "", RoleDomains: map[string][]string{
				dataRole.Config.Name: []string{"neuvector-1"},
			},
		}}
		body2, _ := json.Marshal(userData)
		w = restCall("POST", "/v1/user", body2, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to create user with custom role: status=%v.", w.status)
		}
		// Login as the new user and get token
		w = login(userData.User.Fullname, userData.User.Password)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to login user: status=%v.", w.status)
		}
		token := getLoginToken(w)
		// Users with any custom role cannot configure only-known-by-IBMSA resource
		if w = restCallToken("POST", cfgURI, body, token); w.status != http.StatusForbidden {
			t.Fatalf("Surprised for admin to authorize successfully: URI=%v, status=%+v.", cfgURI, w.status)
		}
		// Delete the created user with custom role
		w = restCall("DELETE", "/v1/user/"+userData.User.Fullname, nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to delete user: status=%v.", w.status)
		}
		// Delete custom role
		w = restCall("DELETE", "/v1/user_role/"+dataRole.Config.Name, nil, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Fatalf("Failed to delete role: status=%v.", w.status)
		}
	}

	// Simulate IBM SA to post setup configuration to NV
	if w := restCallToken("POST", cfgURI, body, respIBMSASetupToken.AccessToken); w.status != http.StatusOK {
		t.Fatalf("Failed to post ibmsa setup configuration: status=%v.", w.status)
	}

	// Only admin/fedAdmin can get configuration of IBM SA integration
	if w := restCallToken("GET", "/v1/partner/ibm_sa_config", nil, respIBMSASetupToken.AccessToken); w.status != http.StatusForbidden {
		t.Fatalf("Surprised to authorize successfully as ibmsa for getting ibmsa setup configuration: status=%v.", w.status)
	}
	if w := restCall("GET", "/v1/partner/ibm_sa_config", nil, api.UserRoleReader); w.status != http.StatusForbidden {
		t.Fatalf("Surprised to authorize successfully as reader for getting ibmsa setup configuration: status=%v.", w.status)
	}

	// Check IBM SA setup configuration post to NV by REST
	var setupConfig api.RESTIBMSAConfig
	if w := restCall("GET", "/v1/partner/ibm_sa_config", nil, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to check IBM SA setup configuration: status=%v.", w.status)
	} else {
		json.Unmarshal(w.body, &setupConfig)
		if setupConfig.AccountID != cfg.AccountID || setupConfig.APIKey != cfg.APIKey || setupConfig.ProviderID != cfg.ProviderID ||
			setupConfig.FindingsURL != cfg.FindingsURL || setupConfig.TokenURL != cfg.TokenURL {
			t.Fatalf("Invalid IBM SA Endpoint setup configuration in NV: %v", setupConfig)
		}
	}

	// simulate IBM SA to post setup test to NV
	testData := ibmsaOccurrences{
		NoteName:   "29104aa4ec94471284be7d33bf1b1391/providers/security-advisor/notes/onboarding-bp",
		Kind:       "FINDING",
		ID:         "FAKE_ServiceId_VALUE", // "ServiceId-..........",
		Context:    ibmsaContext{},
		ProviderID: "security-advisor",
		Finding:    &ibmsaFinding{Severity: "LOW"},
	}
	body, _ = json.Marshal(testData)
	if w = restCallToken("POST", testURI, body, respIBMSASetupToken.AccessToken); w.status != http.StatusOK {
		t.Fatalf("Failed to post ibmsa setup test: status=%v.", w.status)
	}

	// Check IBM SA setup configuration post to NV cache
	if cacheCfg := cacher.GetSystemConfig(accAdmin); cacheCfg == nil {
		t.Fatalf("Failed to check IBM SA setup configuration in cache")
	} else if cacheCfg.IBMSAEpStart != 1 || cacheCfg.IBMSAEpDashboardURL != _testingFindingURL {
		t.Fatalf("Invalid IBM SA Endpoint setup configuration in system cache")
	}

	// Simulate IBM SA to get dashboard info from NV
	for _, infoURI := range infoURIs {
		if w := restCall("GET", infoURI, nil, api.UserRoleNone); w.status != http.StatusOK {
			t.Fatalf("Failed to get IBM SA info(%s) from NV: status=%v.", infoURI, w.status)
		}
	}

	// Simulate IBM SA to delete setup configuration in NV
	uri := fmt.Sprintf("/v1/partner/ibm_sa/%s/setup/%s/%s", ibmID, setupConfig.AccountID, setupConfig.ProviderID) // this URI is not supported by NV/IBMSA yet
	w = restCall("DELETE", uri, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("Failed to delete IBM SA setup configuration: status=%v.", w.status)
	}

	if len(loginSessions) != 1 {
		t.Fatalf("Incorrect number of login users: %v", len(loginSessions))
	} else {
		loginSessions = make(map[string]*loginSession)
	}

	ibmSAEpEnabled = false
	ibmSAEpDashboardURL = ""
	body, _ = json.Marshal(data)
	if w := restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to disable IBM SA integration: status=%v.", w.status)
	}

	// Check cleared IBM SA setup configuration in cache
	if cacheCfg := cacher.GetSystemConfig(accAdmin); cacheCfg == nil {
		t.Fatalf("Failed to check IBM SA setup configuration in cache")
	} else if cacheCfg.IBMSAEpStart != 0 || cacheCfg.IBMSAEpDashboardURL != "" {
		t.Fatalf("Invalid IBM SA Endpoint setup configuration in system cache(%v, %v)", cacheCfg.IBMSAEpStart, cacheCfg.IBMSAEpDashboardURL)
	}

	// Check configured role by REST
	resp = api.RESTSystemConfigData{}
	if w := restCall("GET", "/v1/system/config", nil, api.UserRoleAdmin); w.status != http.StatusOK {
		t.Fatalf("Failed to get IBM SA integration config: status=%v.", w.status)
	} else {
		json.Unmarshal(w.body, &resp)
		if resp.Config == nil {
			t.Fatalf("Nil IBM SA integration config by REST")
		} else {
			if resp.Config.IBMSAEpEnabled || resp.Config.IBMSAEpStart == 1 || resp.Config.IBMSAEpDashboardURL != "" {
				t.Fatalf("Incorrect IBM SA integration config by REST: IBMSAEpEnabled=%v, IBMSAEpStart=%v, IBMSAEpDashboardURL=%v",
					resp.Config.IBMSAEpEnabled, resp.Config.IBMSAEpStart, resp.Config.IBMSAEpDashboardURL)
			}
		}
	}

	postTest()
}
