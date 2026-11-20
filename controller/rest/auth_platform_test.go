package rest

import (
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type platformRolesK8s struct {
	*resource.MockK8s
	roles map[string]string
	err   error
}

func (d *platformRolesK8s) GetUserRoles(user string, subType uint8) (map[string]string, map[string]share.NvFedPermissions, error) {
	return d.roles, nil, d.err
}

func TestTokenServerAuthz(t *testing.T) {
	groupMappings := []*share.GroupRoleMapping{
		{
			Group:       "owner-group",
			GlobalRole:  api.UserRoleNone,
			RoleDomains: map[string][]string{api.UserRoleAdmin: {"tenant-b"}},
		},
	}
	oidcServer := &share.CLUSServer{
		Name:   "openId1",
		Enable: true,
		OIDC: &share.CLUSServerOIDC{
			CLUSServerAuth: share.CLUSServerAuth{GroupMappedRoles: groupMappings},
		},
	}
	oidcServerNoMapping := &share.CLUSServer{
		Name:   "openId1",
		Enable: true,
		OIDC:   &share.CLUSServerOIDC{},
	}
	oidcServerDefaultRole := &share.CLUSServer{
		Name:   "openId1",
		Enable: true,
		OIDC: &share.CLUSServerOIDC{
			CLUSServerAuth: share.CLUSServerAuth{DefaultRole: api.UserRoleReader},
		},
	}
	samlServer := &share.CLUSServer{
		Name:   "saml1",
		Enable: true,
		SAML: &share.CLUSServerSAML{
			CLUSServerAuth: share.CLUSServerAuth{GroupMappedRoles: groupMappings},
		},
	}
	groupMapped := map[string][]string{api.UserRoleAdmin: {"tenant-b"}}

	cases := []struct {
		name              string
		server            *share.CLUSServer
		authByPlatform    bool
		platformRoles     map[string]string
		platformErr       error
		expectErr         error
		expectRole        string
		expectRoleDomains map[string][]string
	}{
		{
			name:              "platform auth disabled uses group mapping",
			server:            oidcServer,
			authByPlatform:    false,
			platformRoles:     map[string]string{"": api.UserRoleAdmin},
			expectRole:        api.UserRoleNone,
			expectRoleDomains: groupMapped,
		},
		{
			name:              "user unknown to platform uses group mapping",
			server:            oidcServer,
			authByPlatform:    true,
			platformErr:       resource.ErrUserNotFound,
			expectRole:        api.UserRoleNone,
			expectRoleDomains: groupMapped,
		},
		{
			name:              "platform role not mappable falls back to group mapping",
			server:            oidcServer,
			authByPlatform:    true,
			platformRoles:     map[string]string{"": api.UserRoleNone},
			expectRole:        api.UserRoleNone,
			expectRoleDomains: groupMapped,
		},
		{
			name:              "platform namespace role wins over group mapping",
			server:            oidcServer,
			authByPlatform:    true,
			platformRoles:     map[string]string{"": api.UserRoleNone, "tenant-a": api.UserRoleReader},
			expectRole:        api.UserRoleNone,
			expectRoleDomains: map[string][]string{api.UserRoleReader: {"tenant-a"}},
		},
		{
			name:              "platform global role wins over group mapping",
			server:            oidcServer,
			authByPlatform:    true,
			platformRoles:     map[string]string{"": api.UserRoleReader},
			expectRole:        api.UserRoleReader,
			expectRoleDomains: map[string][]string{},
		},
		{
			name:           "no usable platform role and no group mapping is rejected",
			server:         oidcServerNoMapping,
			authByPlatform: true,
			platformRoles:  map[string]string{"": api.UserRoleNone},
			expectErr:      errNoRoleMapped,
		},
		{
			name:              "platform role not mappable falls back to default role",
			server:            oidcServerDefaultRole,
			authByPlatform:    true,
			platformRoles:     map[string]string{"": api.UserRoleNone},
			expectRole:        api.UserRoleReader,
			expectRoleDomains: map[string][]string{},
		},
		{
			name:              "saml platform role not mappable falls back to group mapping",
			server:            samlServer,
			authByPlatform:    true,
			platformRoles:     map[string]string{"": api.UserRoleNone},
			expectRole:        api.UserRoleNone,
			expectRoleDomains: groupMapped,
		},
	}

	preTest()
	defer postTest()

	oldOrch, oldCacher, oldClusHelper := global.ORCH, cacher, clusHelper
	defer func() {
		global.ORCH = oldOrch
		cacher = oldCacher
		clusHelper = oldClusHelper
	}()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mockCluster kv.MockCluster
			mockCluster.Init(nil, nil)
			clusHelper = &mockCluster
			cacher = &mockCache{systemConfig: api.RESTSystemConfig{AuthByPlatform: c.authByPlatform}}

			global.SetPseudoOrchHub_UnitTest("pseudo_k8s", share.FlavorOpenShift, "1.24", "", func(platform, flavor, network string) orchAPI.ResourceDriver {
				return &platformRolesK8s{
					MockK8s: resource.NewMockKK8sDriver(platform, flavor, network),
					roles:   c.platformRoles,
					err:     c.platformErr,
				}
			})

			user, err := tokenServerAuthz(c.server, "user@example.com", "user@example.com", []string{"owner-group", "user-group"})
			if c.expectErr != nil {
				require.ErrorIs(t, err, c.expectErr)
				assert.Nil(t, user)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, user)
			assert.Equal(t, c.server.Name, user.Server)
			assert.Equal(t, c.expectRole, user.Role)
			assert.Equal(t, c.expectRoleDomains, user.RoleDomains)
		})
	}
}
