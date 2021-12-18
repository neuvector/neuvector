package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
)

func TestRegProxy(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cacher = &mockCache{
		systemConfig: api.RESTSystemConfig{},
	}

	enable := true
	proxy := api.RESTProxy{URL: "http://1.2.3.4:8088"}

	conf := api.RESTSystemConfigConfig{RegistryHttpProxyEnable: &enable}
	data := api.RESTSystemConfigConfigData{Config: &conf}
	body, _ := json.Marshal(data)
	w := restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status == http.StatusOK {
		t.Errorf("Enable proxy without URL should not be allowed: status=%v.", w.status)
	}

	conf = api.RESTSystemConfigConfig{RegistryHttpsProxyEnable: &enable, RegistryHttpsProxy: &proxy}
	data = api.RESTSystemConfigConfigData{Config: &conf}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Fail to enable proxy without URL: status=%v.", w.status)
	}

	proxy = api.RESTProxy{URL: ""}

	conf = api.RESTSystemConfigConfig{RegistryHttpsProxy: &proxy}
	data = api.RESTSystemConfigConfigData{Config: &conf}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status == http.StatusOK {
		t.Errorf("Should not allow unset proxy URL if proxy is enabled: status=%v.", w.status)
	}

	enable = false
	conf = api.RESTSystemConfigConfig{RegistryHttpsProxyEnable: &enable}
	data = api.RESTSystemConfigConfigData{Config: &conf}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Fail to disable proxy with URL: status=%v.", w.status)
	}

	conf = api.RESTSystemConfigConfig{RegistryHttpsProxy: &proxy}
	data = api.RESTSystemConfigConfigData{Config: &conf}
	body, _ = json.Marshal(data)
	w = restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Should allow unset proxy URL if proxy is enabled: status=%v.", w.status)
	}

	postTest()
}

func TestClusterName(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cacher = &mockCache{
		systemConfig: api.RESTSystemConfig{ClusterName: "old-cluster-name"},
	}

	newClusterName := "new-cluster-name"
	conf := api.RESTSystemConfigConfig{ClusterName: &newClusterName}
	data := api.RESTSystemConfigConfigData{Config: &conf}
	body, _ := json.Marshal(data)
	restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)

	cfg, _ := clusHelper.GetSystemConfigRev(accAdmin)
	if cfg.ClusterName != newClusterName {
		t.Errorf("Cluster name is not set.")
	}

	newClusterName = ""
	conf = api.RESTSystemConfigConfig{ClusterName: &newClusterName}
	data = api.RESTSystemConfigConfigData{Config: &conf}
	body, _ = json.Marshal(data)
	restCall("PATCH", "/v1/system/config", body, api.UserRoleAdmin)

	cfg, _ = clusHelper.GetSystemConfigRev(accAdmin)
	if cfg.ClusterName != common.DefaultSystemConfig.ClusterName {
		t.Errorf("Cluster name is not reset.")
	}
	postTest()
}
