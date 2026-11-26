package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSystemCfgAuthByPlatform(t *testing.T) {
	cases := []struct {
		name      string
		persisted bool
		yaml      string
		expected  bool
	}{
		{name: "persisted true, requested false", persisted: true, yaml: "Auth_By_Platform: false\n", expected: false},
		{name: "persisted false, requested true", persisted: false, yaml: "Auth_By_Platform: true\n", expected: true},
		{name: "persisted true, requested true", persisted: true, yaml: "Auth_By_Platform: true\n", expected: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			preTest()
			defer postTest()

			var mockCluster kv.MockCluster
			mockCluster.Init(nil, nil)
			clusHelper = &mockCluster
			cacher = &mockCache{}
			require.NoError(t, mockCluster.PutSystemConfigRev(&share.CLUSSystemConfig{AuthByPlatform: c.persisted}, 0))

			var skip bool
			context := configMapHandlerContext{platform: share.PlatformKubernetes}
			require.NotPanics(t, func() {
				assert.NoError(t, handlesystemcfg([]byte(c.yaml), true, &skip, &context))
			})

			cfg, _ := mockCluster.GetSystemConfigRev(access.NewReaderAccessControl())
			require.NotNil(t, cfg)
			assert.Equal(t, c.expected, cfg.AuthByPlatform)
		})
	}
}

func TestConfigSystemConfigAuthByPlatform(t *testing.T) {
	cases := []struct {
		name        string
		loginServer string
		expectErr   bool
		expectKick  bool
		expected    bool
	}{
		{name: "rancher login cannot disable", loginServer: share.FlavorRancher + "-sso", expectErr: true, expectKick: false, expected: true},
		{name: "local login can disable", loginServer: "", expectErr: false, expectKick: true, expected: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			preTest()
			defer postTest()

			var mockCluster kv.MockCluster
			mockCluster.Init(nil, nil)
			clusHelper = &mockCluster
			cacher = &mockCache{}
			require.NoError(t, mockCluster.PutSystemConfigRev(&share.CLUSSystemConfig{AuthByPlatform: true}, 0))

			disable := false
			rconf := api.RESTSystemConfigConfigData{
				Config: &api.RESTSystemConfigConfig{AuthByPlatform: &disable},
			}
			w := httptest.NewRecorder()
			login := &loginSession{server: c.loginServer}

			kick, err := configSystemConfig(w, access.NewAdminAccessControl(), login, "rest", share.ScopeLocal, share.PlatformKubernetes, &rconf)
			if c.expectErr {
				require.Error(t, err)
				assert.Equal(t, http.StatusBadRequest, w.Code)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.expectKick, kick)

			cfg, _ := mockCluster.GetSystemConfigRev(access.NewReaderAccessControl())
			require.NotNil(t, cfg)
			assert.Equal(t, c.expected, cfg.AuthByPlatform)
		})
	}
}
