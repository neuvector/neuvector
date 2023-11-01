package global

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

type orchHub struct {
	orchAPI.Driver
	orchAPI.ResourceDriver
}

var ErrEmptyContainerList = errors.New("Container list is empty")
var ErrContainerNotFound = errors.New("Failed to find container")

type RegisterDriverFunc func(platform, flavor, network string) orchAPI.ResourceDriver

var SYS *system.SystemTools
var RT container.Runtime
var ORCH *orchHub

func SetGlobalObjects(rtSocket string, regResource RegisterDriverFunc) (string, string, string, []*container.ContainerMeta, error) {
	var err error
	var containers []*container.ContainerMeta
	var platform, flavor, network string

	SYS = system.NewSystemTools()
	RT, err = container.Connect(rtSocket, SYS)
	if err == nil {
		// List only at least one running containers: 3 tries
		for i := 0; i < 3; i++ {
			if containers, err = RT.ListContainers(true); err == nil && len(containers) > 0 {
				break
			}
			time.Sleep(time.Millisecond * 50)
		}
		if len(containers) == 0 {
			return "", "", "", nil, ErrEmptyContainerList
		}
		platform, flavor, network = getPlatform(containers)
	} else {
		if container.IsPidHost() {
			return "", "", "", nil, err
		}

		if RT, err = container.InitStubRtDriver(SYS); err != nil {
			return "", "", "", nil, err
		}
		platform, flavor, network = getPlatformFromEnv()
	}

	k8sVer, ocVer := orchAPI.GetK8sVersion(true, true)
	if platform == "" && k8sVer != "" {
		platform = share.PlatformKubernetes
	}
	if flavor == "" && ocVer != "" {
		flavor = share.FlavorOpenShift
	}
	if flavor == share.FlavorOpenShift && platform == "" {
		platform = share.PlatformKubernetes
	}

	ORCH = &orchHub{Driver: orchAPI.GetDriver(platform, flavor, network, k8sVer, ocVer, SYS, RT)}
	if regResource != nil {
		ORCH.ResourceDriver = regResource(platform, flavor, network)
	}

	return platform, flavor, network, containers, nil
}

func getContainerPlatform(c *container.ContainerMeta) string {
	if _, ok := c.Labels[container.RancherKeyContainerSystem]; ok {
		return share.PlatformRancher
	}
	if _, ok := c.Labels[container.KubeKeyPodNamespace]; ok {
		return share.PlatformKubernetes
	}
	if _, ok := c.Labels[container.AliyunSystem]; ok {
		return share.PlatformAliyun
	}
	if strings.HasPrefix(c.Image, container.ECSAgentImagePrefix) {
		return share.PlatformAmazonECS
	}

	return share.PlatformDocker
}

func normalize(platform, flavor string) (string, string) {
	switch strings.ToLower(platform) {
	case strings.ToLower(share.PlatformDocker):
		platform = share.PlatformDocker
	case strings.ToLower(share.PlatformAmazonECS):
		platform = share.PlatformAmazonECS
	case strings.ToLower(share.PlatformKubernetes):
		platform = share.PlatformKubernetes
	case strings.ToLower(share.PlatformRancher):
		platform = share.PlatformRancher
	case strings.ToLower(share.PlatformAliyun):
		platform = share.PlatformAliyun
	}

	switch strings.ToLower(flavor) {
	case strings.ToLower(share.FlavorSwarm):
		flavor = share.FlavorSwarm
	case strings.ToLower(share.FlavorUCP):
		flavor = share.FlavorUCP
	case strings.ToLower(share.FlavorOpenShift):
		flavor = share.FlavorOpenShift
	case strings.ToLower(share.FlavorRancher):
		flavor = share.FlavorRancher
	case strings.ToLower(share.FlavorIKE):
		flavor = share.FlavorIKE
	case strings.ToLower(share.FlavorGKE):
		flavor = share.FlavorGKE
	}

	return platform, flavor
}

func getPlatform(containers []*container.ContainerMeta) (string, string, string) {
	network := share.NetworkDefault

	var hasOpenShiftProc bool
	if oc, err := SYS.IsOpenshift(); err == nil {
		hasOpenShiftProc = oc
	}

	// First decide the platform
	envParser := utils.NewEnvironParser(os.Environ())
	platform, flavor := normalize(envParser.GetPlatformName())
	switch platform {
	case share.PlatformDocker, share.PlatformKubernetes, share.PlatformAmazonECS, share.PlatformAliyun:
		if flavor != "" {
			return platform, flavor, network
		}
		// continue parsing flavor and network
	case "":
		for _, c := range containers {
			platform = getContainerPlatform(c)
			if platform != share.PlatformDocker {
				break
			}
		}
		// continue parsing flavor and network
	default:
		return platform, flavor, network
	}

	for _, c := range containers {
		switch platform {
		case share.PlatformDocker:
			if _, ok := c.Labels[container.DockerSwarmServiceKey]; ok {
				return share.PlatformDocker, share.FlavorSwarm, share.NetworkDefault
			}
			if _, ok := c.Labels[container.DockerUCPInstanceIDKey]; ok {
				return share.PlatformDocker, share.FlavorUCP, share.NetworkDefault
			}
		case share.PlatformKubernetes:
			if hasOpenShiftProc {
				return share.PlatformKubernetes, share.FlavorOpenShift, share.NetworkDefault
			} else if strings.Contains(c.Image, container.OpenShiftPodImage) {
				flavor = share.FlavorOpenShift
			}
		default:
			return platform, flavor, network
		}
	}

	return platform, flavor, network
}

func IdentifyK8sContainerID(id string) (string, error) {
	var podname string
	for i := 0; i < 4; i++ {
		if containers, err := RT.ListContainers(true); err == nil {
			// (1) identify it is a POD or container
			for _, c := range containers {
				if strings.HasPrefix(c.Name, "k8s_POD") {
					// parent: POD
					if c.ID == id {
						podname, _ = c.Labels[container.KubeKeyPodName]
						break
					}
				} else {
					// found: it is a child, container
					if c.ID == id {
						return c.ID, nil
					}
				}
			}

			// (2) search its child pod
			for _, c := range containers {
				if !strings.HasPrefix(c.Name, "k8s_POD") {
					if name, ok := c.Labels[container.KubeKeyPodName]; ok && (name == podname) {
						return c.ID, nil
					}
				}
			}
		}
		time.Sleep(time.Millisecond * 250)
	}
	return id, ErrContainerNotFound
}

func (d *orchHub) SetFlavor(flavor string) error {
	d.Driver.SetFlavor(flavor)
	if d.ResourceDriver != nil {
		d.ResourceDriver.SetFlavor(flavor)
	}

	return nil
}

func getPlatformFromEnv() (string, string, string) {
	network := share.NetworkDefault

	// First decide the platform
	envParser := utils.NewEnvironParser(os.Environ())
	platform, flavor := normalize(envParser.GetPlatformName())
	return platform, flavor, network
}
