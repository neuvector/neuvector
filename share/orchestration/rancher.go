package orchestration

import (
	"strconv"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

/* Container labels - Rancher 1.5

   "Labels": {
       "io.rancher.cni.network": "ipsec",
       "io.rancher.cni.wait": "true",
       "io.rancher.container.ip": "10.42.42.220/16",
       "io.rancher.container.mac_address": "02:d0:b4:1e:19:e1",
       "io.rancher.container.name": "wordpress-wordpress-1",
       "io.rancher.container.uuid": "cdf22c86-e5c6-418e-a38d-1f3837ce51ff",
       "io.rancher.project.name": "wordpress",
       "io.rancher.project_service.name": "wordpress/wordpress",
       "io.rancher.service.deployment.unit": "01410429-94d9-4c07-b84d-033439e954b9",
       "io.rancher.service.hash": "50a3d1b3dbd60e81179afe430e658edc93f16083",
       "io.rancher.service.launch.config": "io.rancher.service.primary.launch.config",
       "io.rancher.stack.name": "wordpress",
       "io.rancher.stack_service.name": "wordpress/wordpress"
   }
*/

type rancher struct {
	noop
}

// Check of container is deployed by Rancher or simply "docker run"
func (d *rancher) isDeployedBy(meta *container.ContainerMeta) bool {
	if _, ok := meta.Labels[container.RancherKeyContainerName]; ok {
		return true
	}
	if _, ok := meta.Labels[container.RancherContainerNetwork]; ok {
		return true
	}
	return false
}

func (d *rancher) GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service {
	return nil
}

func (d *rancher) GetService(meta *container.ContainerMeta, node string) *Service {
	if service := meta.Labels[container.RancherKeyStackServiceName]; service != "" {
		return &Service{Name: service}
	}

	return baseDriver.GetService(meta, node)
}

func (d *rancher) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	if v, ok := m.Labels[container.RancherKeyContainerSystem]; ok {
		switch v {
		case "rancher-agent":
			return container.PlatformContainerRancherAgent, false
		case "NetworkAgent":
			return container.PlatformContainerRancherNetworkAgent, false
		default:
			return container.PlatformContainerRancherInfra, false
		}
	}
	return "", true
}

func (d *rancher) GetDomain(labels map[string]string) string {
	return baseDriver.GetDomain(labels)
}

func (d *rancher) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	// In 'default' mode, the interface is plugged by docker, not Rancher.
	if !d.isDeployedBy(meta) || meta.NetMode == "default" {
		baseDriver.SetIPAddrScope(ports, meta, nets)
		return
	}

	// We've seen case that "io.rancher.container.ip" value is wrong or missing,
	// in those cases, no match will be found in the following section.
	key := container.RancherKeyContainerIP
	if v, ok := meta.Labels[key]; ok {
		for _, addrs := range ports {
			for j, addr := range addrs {
				if addr.IPNet.String() == v {
					addrs[j].Scope = share.CLUSIPAddrScopeGlobal
					addrs[j].NetworkID = container.RancherOverlayNetworkName
					addrs[j].NetworkName = container.RancherOverlayNetworkName
					return
				}
			}
		}
	}
	// If container run with "docker run -l io.rancher.container.network=true"
	key = container.RancherContainerNetwork
	if v, ok := meta.Labels[key]; ok {
		if rn, _ := strconv.ParseBool(v); rn {
			for name, addrs := range ports {
				if name == "eth0" && len(addrs) >= 2 {
					addrs[1].Scope = share.CLUSIPAddrScopeGlobal
					addrs[1].NetworkID = container.RancherOverlayNetworkName
					addrs[1].NetworkName = container.RancherOverlayNetworkName
					return
				}
			}
		}
	}

	// As of 2019.2.21, rarely users still use Rancher 1.6. One user reports workload:<container_ip>
	// endpoint presents in the graph. Add this to see if the issue can be fixed.
	key = container.RancherCNINetwork
	if _, ok := meta.Labels[key]; ok {
		for _, addrs := range ports {
			for j := range addrs {
				addrs[j].Scope = share.CLUSIPAddrScopeGlobal
				addrs[j].NetworkID = container.RancherOverlayNetworkName
				addrs[j].NetworkName = container.RancherOverlayNetworkName
			}
		}
		return
	}

	// We've seen containers that missing the "io.rancher.container.ip" label when retain_ip is set.
	for name, addrs := range ports {
		if name == "eth0" && len(addrs) == 1 {
			addrs[0].Scope = share.CLUSIPAddrScopeGlobal
			addrs[0].NetworkID = container.RancherOverlayNetworkName
			addrs[0].NetworkName = container.RancherOverlayNetworkName
			return
		}
	}
}
