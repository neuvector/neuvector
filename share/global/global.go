package global

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	"k8s.io/apimachinery/pkg/runtime"

	log "github.com/sirupsen/logrus"
)

type k8sVersion struct {
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}
type openshifVersion struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
}

type clusterOperatorSpec struct {
}

type clusterOperatorStatus struct {
	Conditions     []clusterOperatorStatusCondition `json:"conditions,omitempty"`
	Versions       []operandVersion                 `json:"versions,omitempty"`
	RelatedObjects []objectReference                `json:"relatedObjects,omitempty"`
	Extension      runtime.RawExtension             `json:"extension"`
}

type clusterOperatorStatusCondition struct {
	Type               clusterStatusConditionType `json:"type"`
	Status             conditionStatus            `json:"status"`
	LastTransitionTime metav1.Time                `json:"lastTransitionTime"`
	Reason             string                     `json:"reason,omitempty"`
	Message            string                     `json:"message,omitempty"`
}

type clusterStatusConditionType string

type operandVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type objectReference struct {
	Group     string `json:"group"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type conditionStatus string

type clusterOperator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              clusterOperatorSpec   `json:"spec"`
	Status            clusterOperatorStatus `json:"status"`
}

type orchHub struct {
	orchAPI.Driver
	orchAPI.ResourceDriver
}

type RegisterDriverFunc func(platform, flavor, network string) orchAPI.ResourceDriver

var SYS *system.SystemTools
var RT container.Runtime
var ORCH *orchHub

const k8sVersionUrl = "https://kubernetes.default/version"
const ocVersion3xUrl = "https://kubernetes.default/version/openshift"
const ocVersion4xUrl = "https://kubernetes.default/apis/config.openshift.io/v1/clusteroperators/openshift-apiserver"

func getVersion(tag, url string, useToken bool) string {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	var err error
	var req *http.Request
	var resp *http.Response

	if req, err = http.NewRequest("GET", url, nil); err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("New Request fail")
		return ""
	}
	if useToken {
		if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
			log.WithFields(log.Fields{"error": err}).Debug("Read File fail")
			return ""
		} else {
			req.Header.Set("Authorization", "Bearer "+string(data))
		}
	}
	if resp, err = client.Do(req); err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Get Version fail")
		return ""
	} else if resp != nil && resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"tag": tag, "code": resp.StatusCode}).Error()
	}
	defer resp.Body.Close()

	var data []byte
	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Read data fail")
		return ""
	}

	var version string
	switch url {
	case k8sVersionUrl:
		var ocv k8sVersion
		err = json.Unmarshal(data, &ocv)
		if err == nil {
			version = strings.TrimLeft(ocv.GitVersion, "v")
		}
	case ocVersion3xUrl:
		var ocv openshifVersion
		err = json.Unmarshal(data, &ocv)
		if err == nil {
			version = strings.TrimLeft(ocv.GitVersion, "v")
		}
	case ocVersion4xUrl:
		var ocv clusterOperator
		err = json.Unmarshal(data, &ocv)
		if err == nil {
			for _, v := range ocv.Status.Versions {
				if v.Name == "operator" {
					version = v.Version
					break
				}
			}
		}
	}
	if version != "" {
		return version
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Unmarshal fail")
	}

	return ""
}

func getK8sVersion() string {
	if version := getVersion("k8s", k8sVersionUrl, false); version != "" {
		return version
	} else {
		return getVersion("k8s", k8sVersionUrl, true)
	}
}

func getOcVersion() string {
	useToken := []bool{false, true}
	for idx, versionUrl := range []string{ocVersion3xUrl, ocVersion4xUrl} {
		if version := getVersion("oc", versionUrl, useToken[idx]); version != "" {
			return version
		}
	}

	return ""
}

func SetGlobalObjects(rtSocket string, regResource RegisterDriverFunc) (string, string, string, []*container.ContainerMeta, error) {
	var err error

	SYS = system.NewSystemTools()

	RT, err = container.Connect(rtSocket, SYS)
	if err != nil {
		return "", "", "", nil, err
	}

	// List only running containers
	containers, err := RT.ListContainers(true)
	if err != nil {
		return "", "", "", nil, err
	}

	platform, flavor, network := getPlatform(containers)
	/*-- for testing --
	if platform == share.PlatformKubernetes || flavor == share.FlavorOpenShift {
		platform = ""
		flavor = ""
		log.Debug("=> for testing")
	}
	*/

	k8sVer := getK8sVersion()
	ocVer := getOcVersion()

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
