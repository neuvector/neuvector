package orchestration

import (
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

type aliyun struct {
	noop
}

func (d *aliyun) GetService(meta *container.ContainerMeta, node string) *Service {
	return baseDriver.GetService(meta, node)
}

func (d *aliyun) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	if v, ok := m.Labels[container.AliyunSystem]; ok {
		if v == "true" {
			return container.PlatformContainerAliyunAgent, false
		}
	}
	if _, ok := m.Labels[container.AliyunAddon]; ok {
		return container.PlatformContainerAliyunAddon, true
	}
	return "", true
}

func (d *aliyun) GetDomain(labels map[string]string) string {
	return baseDriver.GetDomain(labels)
}

func (d *aliyun) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	// Best effort, set eth0 as overlay IP
	for name, addrs := range ports {
		if name == "eth0" {
			for j := range addrs {
				addrs[j].Scope = share.CLUSIPAddrScopeGlobal
			}
		}
	}
}
