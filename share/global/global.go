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

func SetGlobalObjects(rtSocket string, regResource RegisterDriverFunc) (string, string, string, string, []*container.ContainerMeta, error) {
	var err error
	var containers []*container.ContainerMeta
	var platform, flavor, network, cloudPlatform string

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
			return "", "", "", "", nil, ErrEmptyContainerList
		}
		platform, cloudPlatform, flavor, network = getPlatform(containers)
	} else {
		if container.IsPidHost() {
			return "", "", "", "", nil, err
		}

		if RT, err = container.InitStubRtDriver(SYS); err != nil {
			return "", "", "", "", nil, err
		}
		platform, cloudPlatform, flavor, network = getPlatformFromEnv()
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

	return platform, flavor, cloudPlatform, network, containers, nil
}

// Get the container platform and the cloud provider in getContainerPlatform
func getContainerPlatform(c *container.ContainerMeta) (string, string) {
	var platform, cloudPlatform string
	platform = share.PlatformDocker
	// Check for specific platform labels and conditions
	if _, ok := c.Labels[container.RancherKeyContainerSystem]; ok {
		platform = share.PlatformRancher
	} else if _, ok := c.Labels[container.KubeKeyPodNamespace]; ok {
		platform = share.PlatformKubernetes
	} else if _, ok := c.Labels[container.AliyunSystem]; ok {
		platform = share.PlatformAliyun
	} else if strings.HasPrefix(c.Image, container.ECSAgentImagePrefix) {
		platform = share.PlatformAmazonECS
	}

	// Check for specific cloud platform conditions
	if strings.Contains(c.Image, "gke") {
		cloudPlatform = share.CloudGKE
	} else if strings.Contains(c.Image, "amazonaws.com/eks") {
		cloudPlatform = share.CloudEKS
	} else if strings.Contains(c.Image, "microsoft") {
		cloudPlatform = share.CloudAKS
	}

	return platform, cloudPlatform
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
	case strings.ToLower(share.CloudGKE):
		flavor = share.CloudGKE
	}

	return platform, flavor
}

func getPlatform(containers []*container.ContainerMeta) (string, string, string, string) {
	network := share.NetworkDefault

	var hasOpenShiftProc, hasUpdatedPlatform bool
	var cloudPlatform string
	if oc, err := SYS.IsOpenshift(); err == nil {
		hasOpenShiftProc = oc
	}

	// First decide the platform
	envParser := utils.NewEnvironParser(os.Environ())
	platform, flavor := normalize(envParser.GetPlatformName())

	switch platform {
	case share.PlatformDocker, share.PlatformKubernetes, share.PlatformAmazonECS, share.PlatformAliyun:
		if flavor != "" {
			return platform, cloudPlatform, flavor, network
		}
		// continue parsing flavor and network
	case "":
		platform = share.PlatformDocker
		for _, c := range containers {
			containerPlatform, containerCloudPlatform := getContainerPlatform(c)
			// Find the first platform is not docker then update it
			if !hasUpdatedPlatform && containerPlatform != share.PlatformDocker {
				platform = containerPlatform
				hasUpdatedPlatform = true
			}

			// containerCloudPlatform should consistant, thus keep updating if it's not empty
			if cloudPlatform == "" {
				cloudPlatform = containerCloudPlatform
			}
		}
		// continue parsing flavor and network
	default:
		return platform, cloudPlatform, flavor, network
	}

	for _, c := range containers {
		switch platform {
		case share.PlatformDocker:
			if _, ok := c.Labels[container.DockerSwarmServiceKey]; ok {
				return share.PlatformDocker, cloudPlatform, share.FlavorSwarm, share.NetworkDefault
			}
			if _, ok := c.Labels[container.DockerUCPInstanceIDKey]; ok {
				return share.PlatformDocker, cloudPlatform, share.FlavorUCP, share.NetworkDefault
			}
		case share.PlatformKubernetes:
			if hasOpenShiftProc {
				return share.PlatformKubernetes, cloudPlatform, share.FlavorOpenShift, share.NetworkDefault
			} else if strings.Contains(c.Image, container.OpenShiftPodImage) {
				flavor = share.FlavorOpenShift
			}
		default:
			return platform, cloudPlatform, flavor, network
		}
	}

	return platform, cloudPlatform, flavor, network
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
						podname = c.Labels[container.KubeKeyPodName]
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
	_ = d.Driver.SetFlavor(flavor)
	if d.ResourceDriver != nil {
		_ = d.ResourceDriver.SetFlavor(flavor)
	}

	return nil
}

func SetPseudoOrchHub_UnitTest(platform, flavor, k8sVer, ocVer string, regResource RegisterDriverFunc) {
	ORCH = &orchHub{Driver: orchAPI.GetDriver(platform, flavor, "", k8sVer, ocVer, nil, nil)}
	if regResource != nil {
		ORCH.ResourceDriver = regResource(platform, flavor, "")
	}
}

func getPlatformFromEnv() (string, string, string, string) {
	network := share.NetworkDefault

	// First decide the platform
	envParser := utils.NewEnvironParser(os.Environ())
	platform, flavor := normalize(envParser.GetPlatformName())
	var cloudPlatform string

	if platform == share.PlatformGoogleGKE {
		// Follow the style of BenchLoop in bench.go
		platform = share.PlatformKubernetes
		cloudPlatform = share.CloudGKE
	}

	if platform == share.PlatformAzureAKS {
		// Follow the style of BenchLoop in bench.go
		platform = share.PlatformKubernetes
		cloudPlatform = share.CloudAKS
	}

	if platform == share.PlatformAmazonEKS {
		// Follow the style of BenchLoop in bench.go
		platform = share.PlatformKubernetes
		cloudPlatform = share.CloudEKS
	}

	return platform, cloudPlatform, flavor, network
}
