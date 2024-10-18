package orchestration

import (
	"net"
	"regexp"
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
)

// example: Docker Trusted Registry 2.2.5 - (Replica 543ae781fcab)
const reStrDockerRegistryReplica string = "^Docker Trusted Registry [\\d.]+ - \\(Replica "
const renameDockerRegistryReplica string = "Docker.Trusted.Registry"

// example: Docker Universal Control Plane RN3B:GP34:KHVM:LLB6:5CRA:HRTW:SCPJ:3OHZ:3DXG:W2Z2:6S76:YBTI
const reStrDockerUCP string = "^Docker Universal Control Plane ([A-Z\\d]{4}:){11}[A-Z\\d]{4}"
const renameDockerUCP string = "Docker.UCP"

var reDockerRegistryReplica, reDockerUCP *regexp.Regexp

type docker struct {
	noop

	rt        container.Runtime
	envParser *utils.EnvironParser
}

func (d *docker) GetService(meta *container.ContainerMeta, node string) *Service {
	return baseDriver.GetService(meta, node)
}

func (d *docker) GetPlatformRole(meta *container.ContainerMeta) (string, bool) {
	role, secure := baseDriver.GetPlatformRole(meta)

	if role == "" {
		svc := d.GetService(meta, "")
		for _, r := range d.envParser.GetSystemGroups() {
			if r.MatchString(svc.Name) {
				return container.PlatformContainerDockerSystem, false
			}
		}
	}

	return role, secure
}

func (d *docker) GetHostTunnelIP(links map[string]sk.NetIface) []net.IPNet {
	ep, err := d.rt.GetNetworkEndpoint(container.DockerIngressNetworkName, "", container.DockerIngressEPName)
	if err == nil {
		// ingress-sbox IP share the subnet with application containers who has link on the ingress network,
		// so indicate only the IP itself is meaningful
		ep.IPNet.Mask = net.IPv4Mask(255, 255, 255, 255)
		return []net.IPNet{*ep.IPNet}
	}
	return nil
}

func (d *docker) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	baseDriver.SetIPAddrScope(ports, meta, nets)
}

// ---

type base struct {
	noop
}

func (d *base) GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service {
	return nil
}

func (d *base) GetService(meta *container.ContainerMeta, node string) *Service {
	if seviceName, ok := meta.Labels[container.NeuvectorSetServiceName]; ok {
		return &Service{Name: seviceName}
	}

	project := meta.Labels[container.DockerComposeProjectKey]
	service := meta.Labels[container.DockerComposeServiceKey]
	if project != "" && service != "" {
		if reDockerRegistryReplica == nil || reDockerUCP == nil {
			reDockerRegistryReplica = regexp.MustCompile(reStrDockerRegistryReplica)
			reDockerUCP = regexp.MustCompile(reStrDockerUCP)
		}
		if reDockerRegistryReplica.MatchString(project) {
			project = renameDockerRegistryReplica
		} else if reDockerUCP.MatchString(project) {
			project = renameDockerUCP
		}
		return &Service{Name: project + "." + service}
	} else if service = meta.Labels[container.DockerSwarmServiceKey]; service != "" {
		return &Service{Name: service}
	}

	return &Service{Name: container.TrimContainerImageRepo(container.TrimContainerImageVersion(meta.Image))}
}

func (d *base) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	// Because stop/remove enforcer on UCP _kill_ the container (7/2016), we mark all of them
	// as platform containers.
	if _, ok := m.Labels[container.DockerUCPInstanceIDKey]; ok {
		if strings.HasPrefix(m.Image, "docker/ucp-controller") {
			return container.PlatformContainerDockerUCPCtrl, false
		} else if strings.HasPrefix(m.Image, "docker/ucp-swarm") ||
			strings.HasPrefix(m.Image, "docker/ucp-etcd") {
			return container.PlatformContainerDockerUCPSwarm, false
		} else {
			return container.PlatformContainerDockerUCPOther, false
		}
	}

	if c, ok := m.Labels[container.DockerUCPCollectionKey]; ok && c == "swarm" {
		if strings.HasPrefix(m.Image, "docker/dtr-") {
			return container.PlatformContainerDockerDTR, false
		}
	}

	return "", true
}

func (d *base) getNetworkFromAddr(addr net.IP, networks map[string]*container.Network) *container.Network {
	for _, network := range networks {
		for _, subnet := range network.Subnets {
			if subnet.Contains(addr) {
				return network
			}
		}
	}
	return nil
}

func (d *base) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	// Set an interface IP as global if it's IP belongs to 'global' network subnet
	for _, addrs := range ports {
		for j := range addrs {
			if network := d.getNetworkFromAddr(addrs[j].IPNet.IP, nets); network != nil {
				if network.Scope == container.DockerNetworkGlobal || network.Scope == container.DockerNetworkSwarm {
					addrs[j].Scope = share.CLUSIPAddrScopeGlobal
				} else {
					addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
				}
				addrs[j].NetworkID = network.ID
				addrs[j].NetworkName = network.Name
			}
		}
	}
}
