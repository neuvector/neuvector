package orchestration

import (
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

type ecs struct {
	noop
}

// for Amazon Elastic Container Service (Amazon ECS)
// var ecsDriver ecs

// Check of container is deployed by ecs or simply "docker run".
// ecs-agent has no label but it's host-mode container which has no its own interface
func (d *ecs) isDeployedBy(meta *container.ContainerMeta) bool {
	if _, ok := meta.Labels[container.ECSTaskDefinition]; ok {
		return true
	}
	return false
}

func (d *ecs) GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service {
	return nil
}

func (d *ecs) GetService(meta *container.ContainerMeta, node string) *Service {
	if seviceName, ok := meta.Labels[container.NeuvectorSetServiceName]; ok {
		return &Service{Name: seviceName}
	}

	cluster := meta.Labels[container.ECSCluster]
	task := meta.Labels[container.ECSTaskDefinition]
	container := meta.Labels[container.ECSContainerName]
	if cluster != "" && task != "" && container != "" {
		return &Service{Name: cluster + "." + task + "." + container}
	} else if task != "" {
		return &Service{Name: task + "." + container}
	}

	return baseDriver.GetService(meta, node)
}

func (d *ecs) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	if strings.HasPrefix(m.Image, container.ECSAgentImagePrefix) {
		return container.PlatformContainerECSAgent, false
	}
	return "", true
}

func (d *ecs) GetDomain(labels map[string]string) string {
	return baseDriver.GetDomain(labels)
}

func (d *ecs) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	if !d.isDeployedBy(meta) {
		baseDriver.SetIPAddrScope(ports, meta, nets)
		return
	}

	for _, addrs := range ports {
		for j := range addrs {
			addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
		}
	}
}
