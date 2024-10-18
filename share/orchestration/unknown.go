package orchestration

import (
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/utils"
)

type unknown struct {
	noop

	envParser *utils.EnvironParser
}

func (d *unknown) GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service {
	return nil
}

func (d *unknown) GetService(meta *container.ContainerMeta, node string) *Service {
	return baseDriver.GetService(meta, node)
}

func (d *unknown) GetDomain(labels map[string]string) string {
	return baseDriver.GetDomain(labels)
}

func (d *unknown) SetIPAddrScope(ports map[string][]share.CLUSIPAddr, meta *container.ContainerMeta, nets map[string]*container.Network) {
	for name, addrs := range ports {
		cfgs := d.envParser.GetPlatformIntf(name)
		for j := range addrs {
			if len(cfgs) > j {
				switch cfgs[j] {
				case share.ENV_PLT_INTF_GLOBAL:
					addrs[j].Scope = share.CLUSIPAddrScopeGlobal
				case share.ENV_PLT_INTF_HOST:
					addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
				}
			} else {
				addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
			}
		}
	}
}
