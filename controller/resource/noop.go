package resource

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
)

type resourceCache map[string]interface{}
type noop struct {
	platform, flavor string
	resCaches        map[string]resourceCache
	lock             sync.RWMutex
}

// func (d *noop) locateResourceCache(rt string, id string) interface{} {
// 	d.lock.RLock()
// 	defer d.lock.RUnlock()
// 	if cache, ok := d.resCaches[rt]; !ok {
// 		return nil
// 	} else if old, ok := cache[id]; !ok {
// 		return nil
// 	} else {
// 		return old
// 	}
// }

// Return if object is created or modified, and the old object if exists.
func (d *noop) updateResourceCache(rt string, id string, obj interface{}) (string, interface{}) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if cache, ok := d.resCaches[rt]; !ok {
		d.resCaches[rt] = make(resourceCache)
		d.resCaches[rt][id] = obj
		return WatchEventAdd, nil
	} else if old, ok := cache[id]; !ok {
		cache[id] = obj
		return WatchEventAdd, nil
	} else if !reflect.DeepEqual(obj, old) {
		cache[id] = obj
		return WatchEventModify, old
	} else if rt == RscTypeValidatingWebhookConfiguration {
		// For validatingwebhookconfiguration, we only translate the resource for neuvector-validating-admission-webhook.
		// So no matter the new obj has the same id or not, we treat it as modified if we got a translated obj
		cache[id] = obj
		return WatchEventModify, old
	} else {
		return "", old
	}
}

// Return if object is deleted, and the old object if exists.
func (d *noop) deleteResourceCache(rt string, id string) (string, interface{}) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if cache, ok := d.resCaches[rt]; !ok {
		return "", nil
	} else if old, ok := cache[id]; !ok {
		return "", nil
	} else {
		delete(cache, id)
		return WatchEventDelete, old
	}
}

func newNoopDriver(platform, flavor, network string) *noop {
	return &noop{
		resCaches: make(map[string]resourceCache),
		platform:  platform,
		flavor:    flavor,
	}
}

func (d *noop) GetOEMVersion() (string, error) {
	url := common.OEMPlatformVersionURL()
	if url == "" {
		return "", nil
	}
	return "", fmt.Errorf("Unsupported platform")
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
		_k8sFlavor = flavor
		return newKubernetesDriver(platform, flavor, network)
	case share.PlatformDocker:
		return newSwarmDriver(platform, flavor, network)
	default:
		driver := &noop{}
		return driver
	}
}
