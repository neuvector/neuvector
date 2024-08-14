// [20220809] this is a simplified version of controller/resource/noop.go
package resource

import (
	"sync"

	"github.com/neuvector/neuvector/share"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
)

type resourceCache map[string]interface{}
type noop struct {
	platform, flavor string
	lock             sync.RWMutex
}

func newNoopDriver(platform, flavor, network string) *noop {
	return &noop{
		platform: platform,
		flavor:   flavor,
	}
}

func (d *noop) GetOEMVersion() (string, error) {
	return "", ErrMethodNotSupported
}

func (d *noop) Login(username, password string) (string, string, error) {
	return "", "", ErrMethodNotSupported
}

func (d *noop) Logout(username, token string) error {
	return ErrMethodNotSupported
}

func (d *noop) GetAuthServerAlias() string {
	return ""
}

func (d *noop) GetUserRoles(username string, subjType uint8) (map[string]string, map[string]share.NvFedPermissions, error) {
	return nil, nil, ErrMethodNotSupported
}

func (d *noop) ListUsers() []orchAPI.UserRBAC {
	return []orchAPI.UserRBAC{}
}

func (d *noop) RegisterResource(rt string) error {
	return ErrMethodNotSupported
}

func (d *noop) ListResource(rt, namespace string) ([]interface{}, error) {
	return nil, ErrMethodNotSupported
}

func (d *noop) StartWatchResource(rt, ns string, wcb orchAPI.WatchCallback, scb orchAPI.StateCallback) error {
	return ErrMethodNotSupported
}

func (d *noop) StopWatchResource(rt string) error {
	return ErrMethodNotSupported
}

func (d *noop) StopWatchAllResources() error {
	return ErrMethodNotSupported
}

func (d *noop) GetResource(rt, namespace, name string) (interface{}, error) {
	return nil, ErrMethodNotSupported
}

func (d *noop) AddResource(rt string, res interface{}) error {
	return ErrMethodNotSupported
}

func (d *noop) UpdateResource(rt string, res interface{}) error {
	return ErrMethodNotSupported
}

func (d *noop) DeleteResource(rt string, res interface{}) error {
	return ErrMethodNotSupported
}

func (d *noop) SetFlavor(flavor string) error {
	return ErrMethodNotSupported
}

func (d *noop) GetPlatformUserGroups(token string) ([]string, error) {
	return nil, ErrMethodNotSupported
}

func Register(platform, flavor, network string) orchAPI.ResourceDriver {
	switch platform {
	case share.PlatformKubernetes:
		return newKubernetesDriver(platform, flavor, network)
	default:
		driver := &noop{}
		return driver
	}
}
