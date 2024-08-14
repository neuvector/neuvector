package orchestration

import (
	"errors"
	"net"
	"os"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/system"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
)

var ErrMethodNotSupported = errors.New("Method not supported")
var ErrUnknownResource = errors.New("Unknown resource")
var ErrResourceNotSupported = errors.New("Method on resource not supported")

type Service struct {
	Name   string
	Domain string
}

type Driver interface {
	GetVersion(reGetK8sVersion, reGetOcVersion bool) (string, string)
	SetIPAddrScope(ports map[string][]share.CLUSIPAddr, meta *container.ContainerMeta, nets map[string]*container.Network)
	GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service
	GetService(meta *container.ContainerMeta, node string) *Service
	GetPlatformRole(meta *container.ContainerMeta) (string, bool) // return platform type and if container should be secured
	GetDomain(labels map[string]string) string
	GetServiceSubnet(envs []string) *net.IPNet
	GetHostTunnelIP(links map[string]sk.NetIface) []net.IPNet
	IgnoreConnectFromManagedHost() bool
	ConsiderHostsAsInternal() bool
	ApplyPolicyAtIngress() bool
	SupportKubeCISBench() bool
	CleanupHostPorts(hostPorts map[string][]share.CLUSIPAddr) error
	SetFlavor(flavor string) error // for Openshift & Rancher
}

// --

type WatchCallback func(rt string, event string, object interface{}, old interface{})
type StateCallback func(state string, err error)

type UserRBAC struct {
	Name   string
	Domain string
	RBAC   map[string]string                 // domain -> nv role
	RBAC2  map[string]share.NvFedPermissions // domain -> nv permissions
}

type ResourceDriver interface {
	GetOEMVersion() (string, error)
	Login(username, password string) (string, string, error)
	Logout(username, token string) error
	GetAuthServerAlias() string
	GetUserRoles(username string, subjType uint8) (map[string]string, map[string]share.NvFedPermissions, error)
	ListUsers() []UserRBAC
	RegisterResource(rt string) error
	ListResource(rt, namespace string) ([]interface{}, error)
	StartWatchResource(rt, ns string, wcb WatchCallback, scb StateCallback) error
	StopWatchResource(rt string) error
	StopWatchAllResources() error
	GetResource(rt, namespace, name string) (interface{}, error)
	AddResource(rt string, res interface{}) error
	UpdateResource(rt string, res interface{}) error
	DeleteResource(rt string, res interface{}) error
	SetFlavor(flavor string) error                        // for Openshift & Rancher
	GetPlatformUserGroups(token string) ([]string, error) // for OpenShift
}

// --

var baseDriver *base

func GetDriver(platform, flavor, network string, ver1, ver2 string,
	sys *system.SystemTools, rt container.Runtime,
) Driver {
	baseDriver = &base{noop: noop{platform: platform, flavor: flavor, network: network}}

	switch platform {
	case share.PlatformKubernetes:
		driver := &kubernetes{
			noop: noop{platform: platform, flavor: flavor, network: network},
			sys:  sys, k8sVer: ver1, ocVer: ver2,
			envParser: utils.NewEnvironParser(os.Environ()),
		}
		return driver
	case share.PlatformRancher:
		driver := &rancher{noop: noop{platform: platform, flavor: flavor, network: network}}
		return driver
	case share.PlatformAliyun:
		driver := &aliyun{noop: noop{platform: platform, flavor: flavor, network: network}}
		return driver
	case share.PlatformAmazonECS:
		driver := &ecs{noop: noop{platform: platform, flavor: flavor, network: network}}
		return driver
	case share.PlatformDocker:
		driver := &docker{
			noop:      noop{platform: platform, flavor: flavor, network: network},
			rt:        rt,
			envParser: utils.NewEnvironParser(os.Environ()),
		}
		return driver
	default:
		driver := &unknown{
			noop:      noop{platform: platform, flavor: flavor, network: network},
			envParser: utils.NewEnvironParser(os.Environ()),
		}
		return driver
	}
}
