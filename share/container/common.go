package container

import (
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
)

// const defaultContainerLogPath = "/var/lib/docker/containers/%s/%s-json.log"

const (
	DockerUCPInstanceIDKey   string = "com.docker.ucp.InstanceID"
	DockerUCPVersionKey      string = "com.docker.ucp.version"
	DockerUCPCollectionKey   string = "com.docker.ucp.collection"
	DockerSwarmServiceKey    string = "com.docker.swarm.service.name"
	DockerSwarmTaskName      string = "com.docker.swarm.task.name"
	DockerSwarmTaskID        string = "com.docker.swarm.task.id"
	DockerComposeProjectKey  string = "com.docker.compose.project"
	DockerComposeServiceKey  string = "com.docker.compose.service"
	DockerIngressNetworkName string = "ingress"
	DockerIngressSandboxName string = "ingress-sbox"
	DockerIngressEPName      string = "ingress-endpoint"
)

const (
	RancherCNINetwork          string = "io.rancher.cni.network"
	RancherContainerNetwork    string = "io.rancher.container.network"
	RancherKeyContainerIP      string = "io.rancher.container.ip"
	RancherKeyContainerSystem  string = "io.rancher.container.system"
	RancherKeyContainerName    string = "io.rancher.container.name"
	RancherKeyStackName        string = "io.rancher.stack.name"
	RancherKeyStackServiceName string = "io.rancher.stack_service.name"
)

const (
	RancherOverlayNetworkName string = "rancher"
)

const (
	KubeKeyPodNamespace    string = "io.kubernetes.pod.namespace"
	KubeKeyPodName         string = "io.kubernetes.pod.name"
	KubeKeyDeployConfig    string = "deploymentconfig"
	KubeKeyPodHash         string = "pod-template-hash"
	KubeKeyComponent       string = "component"
	KubeKeyJobName         string = "job-name"
	KubeKeyContainerName   string = "io.kubernetes.container.name"
	KubeNamespaceSystem    string = "kube-system"
	KubeNamespaceCatalog   string = "kube-service-catalog"
	KubeContainerNamePod   string = "POD"
	KubeContainerNameProxy string = "kube-proxy"
	KubePodNamePrefixProxy string = "kube-proxy"
	KubeKeyAppName         string = "app"
)

const (
	KubeLinkerdProxyName        string = "linkerd-proxy"
	KubeLinkerdSysPodNamespace  string = "linkerd"
	KubeIstioProxyName          string = "istio-proxy"
	KubeProxyMeshLoMacStr       string = "6c:6b:73:74:%02x:%02x"
	KubeProxyMeshLoMacPrefix    string = "6c:6b:73:74"
	KubeIstioSystemPodNamespace string = "istio-system"
	KubeIstioSystemIngGwPrefix  string = "istio-ingressgateway"
	KubeIstioSystemEgGwPrefix   string = "istio-egressgateway"
	KubeAwsProxyName            string = "envoy"
)

const (
	OpenShiftPodImage string = "openshift/origin-pod"
	OpenShiftPodTag   string = "io.openshift.tags"
)

const (
	KubeRancherPodNamespace     string = "cattle-system"
	KubeRancherKeyStackName     string = "annotation.io.rancher.stack.name"
	KubeRancherIngressNamespace string = "ingress-nginx"
)

const (
	AliyunSystem string = "aliyun.system"
	AliyunAddon  string = "aliyun.addon"
)

const (
	ECSAgentImagePrefix string = "amazon/amazon-ecs-agent:"
	ECSTaskDefinition   string = "com.amazonaws.ecs.task-definition-family"
	ECSContainerName    string = "com.amazonaws.ecs.container-name"
	ECSCluster          string = "com.amazonaws.ecs.cluster"
)

const (
	NeuvectorSetServiceName = "io.neuvector.service.name"
)

const (
	IbmCloudProviderIP = "ibm-cloud-provider-ip"
	IbmCloudClusterID  = "clusterID"
)

const (
	PlatformContainerNone                = ""
	PlatformContainerNeuVector           = "NeuVector"
	PlatformContainerDockerUCPCtrl       = "Docker-UCP-Controller"
	PlatformContainerDockerUCPSwarm      = "Docker-UCP-Swarm"
	PlatformContainerDockerUCPOther      = "Docker-UCP-Other"
	PlatformContainerDockerDTR           = "Docker-DTR"
	PlatformContainerDockerSystem        = "Docker-System" // generic
	PlatformContainerRancherInfra        = "Rancher"
	PlatformContainerRancherAgent        = "Rancher-Agent"
	PlatformContainerRancherNetworkAgent = "Rancher-Network-Agent"
	PlatformContainerOpenshift           = "Openshift"
	PlatformContainerKubeInfra           = "Kubernetes"
	PlatformContainerKubeInfraPause      = "Kubernetes-System-POD"
	PlatformContainerAliyunAgent         = "Aliyu-Agent"
	PlatformContainerAliyunAddon         = "Aliyu-Addon"
	PlatformContainerECSAgent            = "ECS-Agent"
	PlatformContainerIstioInfra          = "Istio-System-POD"
	PlatformContainerLinkerdInfra        = "Linkerd-System-POD"
)

// var rt Runtime

const shortContainerIDLength int = 12
const clientConnectTimeout time.Duration = time.Duration(5 * time.Second)

func parsePortString(s string) (uint8, uint16) {
	tokens := strings.Split(s, "/")
	if len(tokens) < 2 {
		return 0, 0
	}

	port, _ := strconv.Atoi(tokens[0])
	if tokens[1] == "tcp" {
		return syscall.IPPROTO_TCP, uint16(port)
	} else {
		return syscall.IPPROTO_UDP, uint16(port)
	}
}

func trimContainerName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	} else {
		return name
	}
}

func ShortContainerId(id string) string {
	if len(id) <= shortContainerIDLength {
		return id
	} else {
		return id[:shortContainerIDLength]
	}
}

func TrimImageID(in string) string {
	return strings.TrimPrefix(in, "sha256:")
}

func TrimContainerImageVersion(image string) string {
	var colon, slash int

	if colon = strings.LastIndexByte(image, ':'); colon == -1 {
		return image
	}
	if slash = strings.LastIndexByte(image, '/'); slash == -1 {
		return image[:colon]
	}
	if colon > slash {
		return image[:colon]
	} else {
		return image
	}
}

func TrimContainerImageRepo(image string) string {
	var slash int

	if slash = strings.IndexByte(image, '/'); slash == -1 {
		return image
	}

	// If string before the first / has ':' or '.', consider it as registry name
	if s := strings.IndexAny(image[:slash], ":."); s == -1 {
		return image
	} else {
		return image[slash+1:]
	}
}

func SortContainers(cs []*ContainerMetaExtra) []*ContainerMetaExtra {
	sort.Slice(cs, func(i, j int) bool {
		return !cs[i].isChild && cs[j].isChild
	})
	return cs
}

func getDevice(id string, rt Runtime, sys *system.SystemTools) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	if info, err := rt.GetContainer(id); err == nil {
		dev := &share.CLUSDevice{
			ID:           info.ID,
			Name:         info.Name,
			Labels:       info.Labels,
			Pid:          info.Pid,
			SelfHostname: info.Hostname,
			MemoryLimit:  info.MemoryLimit,
			CPUs:         info.CPUs,
			NetworkMode:  info.NetMode,
			PidMode:      info.PidMode,
			CreatedAt:    info.CreatedAt,
			StartedAt:    info.StartedAt,
		}

		// Read address
		ifaces := sys.GetGlobalAddrs(false)

		dev.Ifaces = make(map[string][]share.CLUSIPAddr)
		for name, addrs := range ifaces {
			dev.Ifaces[name] = make([]share.CLUSIPAddr, len(addrs))
			for i, addr := range addrs {
				dev.Ifaces[name][i] = share.CLUSIPAddr{
					IPNet: addr,
					Scope: share.CLUSIPAddrScopeLocalhost,
				}
			}
		}

		return dev, info, nil
	} else {
		return nil, nil, err
	}
}

/*
func (s *DockerDriver) GetContainerLogs(fromDocker bool, id string, start, limit int) ([]byte, error) {
	log.WithFields(log.Fields{"fromdocker": fromDocker, "limit": limit, "id": id}).Debug("")
	if fromDocker {
		options := dockerclient.LogOptions{
			Stdout: true,
			Stderr: true,
			Tail:   int64(limit),
		}

		if r, err := s.Client.ContainerLogs(id, &options); err != nil {
			return nil, fmt.Errorf("Get container log from docker fail:%v", err)
		} else {
			defer r.Close()
			if dat, err := io.ReadAll(r); err != nil {
				return nil, fmt.Errorf("Read container log fail:%v", err)
			} else {
				return dat, nil
			}
		}
	} else {
		meta, err := s.GetContainerMeta(id)
		if err != nil {
			return nil, fmt.Errorf("Get container log path fail:%v", err)
		}
		// some version docker has no logpath field
		if meta.LogPath == "" {
			meta.LogPath = fmt.Sprintf(defaultContainerLogPath, id, id)
		}
		data, err := s.sys.ReadContainerFile(meta.LogPath, 1, start, limit)
		if err != nil {
			return nil, fmt.Errorf("ReadContainerFile return error:%v", err)
		}
		return data, nil
	}
}
*/
