package orchestration

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"text/template"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/system"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	kubeEnvServiceHost string = "_SERVICE_HOST"
	kubeEnvServicePort string = "_SERVICE_PORT"
)

const (
	K8S_VER = iota
	OC_VER_V3
	OC_VER_V4
)

const reStrPodNameSvc1 string = "^.*-[a-f0-9]{6,10}-[a-z0-9]{5}$"
const reStrPodNameSvc2 string = "^.*-[0-9]{1,5}-[a-z0-9]{5}$"

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

var rePodNameSvc1 *regexp.Regexp
var rePodNameSvc2 *regexp.Regexp

// https://github.com/openshift/openshift-sdn/blob/master/plugins/osdn/bin/openshift-sdn-ovs
// del_ovs_flows() and del_ovs_port()
const tmplOVSCleanup string = `
#!/bin/sh
{{range $port, $addrs := .}}
ovs-vsctl get port {{$port}} name
if [ $? -eq 0 ]; then
    {{- range $addrs}}
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst={{.IPNet.IP}}
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src={{.IPNet.IP}}
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst={{.IPNet.IP}}
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src={{.IPNet.IP}}
    {{- end}}
    ovs-vsctl --if-exists del-port {{$port}}
fi
{{end}}
`

type kubernetes struct {
	noop

	k8sVer, ocVer string
	sys           *system.SystemTools
}

func getVersion(tag string, verToGet int, useToken bool) string {
	var url string

	switch verToGet {
	case K8S_VER:
		url = "https://kubernetes.default/version"
	case OC_VER_V3:
		url = "https://kubernetes.default/version/openshift"
	case OC_VER_V4:
		url = "https://kubernetes.default/apis/config.openshift.io/v1/clusteroperators/openshift-apiserver"
	default:
		return ""
	}

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
	switch verToGet {
	case K8S_VER:
		var ocv k8sVersion
		err = json.Unmarshal(data, &ocv)
		if err == nil {
			version = strings.TrimLeft(ocv.GitVersion, "v")
		}
	case OC_VER_V3:
		var ocv openshifVersion
		err = json.Unmarshal(data, &ocv)
		if err == nil {
			version = strings.TrimLeft(ocv.GitVersion, "v")
		}
	case OC_VER_V4:
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

func GetK8sVersion(reGetK8sVersion, reGetOcVersion bool) (string, string) {
	var k8sVer string
	var ocVer string

	if reGetK8sVersion {
		if version := getVersion("k8s", K8S_VER, false); version != "" {
			k8sVer = version
		} else {
			k8sVer = getVersion("k8s", K8S_VER, true)
		}
	}

	if reGetOcVersion {
		useToken := []bool{false, true}
		for idx, verToGet := range []int{OC_VER_V3, OC_VER_V4} {
			if version := getVersion("oc", verToGet, useToken[idx]); version != "" {
				ocVer = version
				break
			}
		}
	}

	return k8sVer, ocVer
}

// Check of container is deployed by Kubernetes or simply "docker run"
func (d *kubernetes) isDeployedBy(meta *container.ContainerMeta) bool {
	if _, ok := meta.Labels[container.KubeKeyPodNamespace]; ok {
		return true
	}
	return false
}

// Environment variables
// REDIS_MASTER_SERVICE_HOST=192.168.3.58
// REDIS_MASTER_SERVICE_PORT=6379

func (d *kubernetes) getServiceIPs(envs map[string]string) []net.IP {
	if envs == nil {
		return nil
	}

	ips := make([]net.IP, 0)
	for k, v := range envs {
		if strings.HasSuffix(k, kubeEnvServiceHost) {
			if ip := net.ParseIP(v); ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	// Only update map if it's not empty. POD container doesn't have envs for service group
	if len(ips) > 0 {
		return ips
	} else {
		return nil
	}
}

func (d *kubernetes) GetVersion(reGetK8sVersion, reGetOcVersion bool) (string, string) {
	if d.flavor != share.FlavorOpenShift {
		reGetOcVersion = false
	}
	k8sVer, ocVer := GetK8sVersion(reGetK8sVersion, reGetOcVersion)
	if reGetK8sVersion {
		d.k8sVer = k8sVer
	}
	if reGetOcVersion {
		d.ocVer = ocVer
	}

	return d.k8sVer, d.ocVer
}

func (d *kubernetes) GetServiceSubnet(envs []string) *net.IPNet {
	if envs == nil {
		return nil
	}

	ips := d.getServiceIPs(utils.NewEnvironParser(envs).GetKVPairs())
	if ips == nil {
		return nil
	}

	subnet := utils.GetIPEnclosure(ips)
	if subnet == nil {
		return nil
	}

	return subnet
}

// Rancher over Kubernetes creates several services, one container on each host, whose pod name
// is of the format, "core-services-metadata-1-xxxx", "core-services-metadata-2-xxxx". ==>
// Remove the digit to put them in one group.
var rancherPodNamePrefix = []string{
	"rancher-agent-",
	"core-services-dns-",
	"core-services-metadata-",
	"core-services-healthcheck-",
	"core-services-network-manager-",
}

/*
pause-amd64:3.0 k8s_POD_frontend-3823415956-853n5_default_.....
    "io.kubernetes.container.name": "POD"
    "io.kubernetes.pod.name": "frontend-3823415956-853n5"
    "pod-template-hash": "3823415956"
       |
       |
       |--- d8f2f70211b0 gb-frontend k8s_php-redis_frontend-3823415956-853n5_default_...
       |        "io.kubernetes.container.name": "php-redis"
       |        "io.kubernetes.pod.name": "frontend-3823415956-853n5"
*/

func (d *kubernetes) GetServiceFromLabels(labels map[string]string) *Service {
	namespace, _ := labels[container.KubeKeyPodNamespace]

	if dc, _ := labels[container.KubeKeyDeployConfig]; dc != "" {
		return &Service{Domain: namespace, Name: dc}
	}

	// pod.name can take format such as, frontend-3823415956-853n5, calico-node-m308t, kube-proxy-8vbrs.
	// For the first case, the pod-template-hash is 3823415956, if the hash label exists, we remove it.
	if pod, _ := labels[container.KubeKeyPodName]; pod != "" {

		if d.flavor == share.FlavorRancher && namespace == container.KubeRancherPodNamespace {
			for _, prefix := range rancherPodNamePrefix {
				if strings.HasPrefix(pod, prefix) {
					return &Service{Domain: namespace, Name: strings.TrimSuffix(prefix, "-")}
				}
			}
		}

		// oc49, job: openshift-operator-lifecycle-manager / collect-profiles-27400290--1-4g2r
		if d.flavor == share.FlavorOpenShift {
			if job, ok := labels[container.KubeKeyJobName]; ok {
				if index := strings.LastIndex(job, "-"); index != -1 {
					job = job[:index]
				}
				return &Service{Domain: namespace, Name: job}
			}
		}

		if hash, _ := labels[container.KubeKeyPodHash]; hash != "" {
			if idx := strings.Index(pod, "-"+hash); idx != -1 {
				return &Service{Domain: namespace, Name: pod[:idx]}
			}
		}

		if rePodNameSvc1 == nil || rePodNameSvc2 == nil {
			rePodNameSvc1 = regexp.MustCompile(reStrPodNameSvc1)
			rePodNameSvc2 = regexp.MustCompile(reStrPodNameSvc2)
		}
		if rePodNameSvc1.MatchString(pod) || rePodNameSvc2.MatchString(pod) {
			if dash := strings.LastIndex(pod, "-"); dash != -1 {
				if dash = strings.LastIndex(pod[:dash], "-"); dash != -1 {
					return &Service{Domain: namespace, Name: pod[:dash]}
				}
			}
		}

		// rke2: kube-system / kube-proxy-ubuntu2110-k8123master-auto
		if namespace == container.KubeNamespaceSystem {
			if component, ok := labels[container.KubeKeyComponent]; ok {
				return &Service{Domain: namespace, Name: component}
			}
			if name, ok := labels[container.KubeKeyContainerName]; ok {
				if strings.HasPrefix(pod, name) {
					return &Service{Domain: namespace, Name: name}
				}
			}
		}

		// Remove the last tokens - not correct in some cases at all
		if first := strings.LastIndex(pod, "-"); first != -1 {
			return &Service{Domain: namespace, Name: pod[:first]}
		}

		return &Service{Domain: namespace, Name: pod}
	}

	return nil
}

func (d *kubernetes) GetService(meta *container.ContainerMeta) *Service {
	if svc := d.GetServiceFromLabels(meta.Labels); svc != nil {
		return svc
	}
	return baseDriver.GetService(meta)
}

func (d *kubernetes) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	vpodns, _ := m.Labels[container.KubeKeyPodNamespace]
	vcname, _ := m.Labels[container.KubeKeyContainerName]
	podname, _ := m.Labels[container.KubeKeyPodName]

	if vpodns == container.KubeNamespaceSystem {
		if vcname == container.KubeContainerNamePod {
			return container.PlatformContainerKubeInfraPause, false
		} else {
			return container.PlatformContainerKubeInfra, false
		}
	}

	if d.flavor == share.FlavorRancher {
		if vpodns == container.KubeRancherPodNamespace {
			// Should we check container type more specifically?
			return container.PlatformContainerRancherInfra, false
		}
		if vpodns == "" && strings.HasPrefix(m.Image, "rancher/") {
			return container.PlatformContainerRancherInfra, false
		}
		if vpodns == container.KubeRancherIngressNamespace && strings.HasPrefix(m.Image, "rancher/") {
			return container.PlatformContainerRancherInfra, false
		}
	}

	if vpodns == container.KubeIstioSystemPodNamespace &&
		!strings.HasPrefix(podname, container.KubeIstioSystemIngGwPrefix) &&
		!strings.HasPrefix(podname, container.KubeIstioSystemEgGwPrefix) {
		return container.PlatformContainerIstioInfra, false
	}

	if vpodns == container.KubeLinkerdSysPodNamespace {
		return container.PlatformContainerLinkerdInfra, false
	}

	// These are non-critical system containers. Secure them so we afford some mis-identification.
	if vpodns == container.KubeNamespaceCatalog {
		return container.PlatformContainerOpenshift, true
	}

	return "", true
}

func (d *kubernetes) GetDomain(labels map[string]string) string {
	if pod, _ := labels[container.KubeKeyPodName]; pod != "" {
		namespace, _ := labels[container.KubeKeyPodNamespace]
		return namespace
	}

	return baseDriver.GetDomain(labels)
}

func (d *kubernetes) SetIPAddrScope(ports map[string][]share.CLUSIPAddr,
	meta *container.ContainerMeta, nets map[string]*container.Network,
) {
	if !d.isDeployedBy(meta) {
		baseDriver.SetIPAddrScope(ports, meta, nets)
		return
	}

	for name, addrs := range ports {
		// This is for Diamanti
		if name == "mgmt0" {
			for j, _ := range addrs {
				addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
			}
			continue
		}

		for j, _ := range addrs {
			addrs[j].Scope = share.CLUSIPAddrScopeGlobal
		}
	}
}

func (d *kubernetes) GetHostTunnelIP(links map[string]sk.NetIface) []net.IPNet {
	log.Debug()

	var ret []net.IPNet
	for name, link := range links {
		if !d.isTunnelInterface(name, link.Type) {
			continue
		}

		for _, addr := range link.Addrs {
			//NVSHAS-5338, ubuntu with containerd in gke set up
			//has veth interface work as ingress, need to add
			//veth's ip as tunnel ip
			if link.Type == "veth" {
				ones, bits := addr.IPNet.Mask.Size()
				if ones == bits && ones == 32 && addr.Scope == syscall.RT_SCOPE_UNIVERSE {
					//log.WithFields(log.Fields{"ones": ones, "bits":bits, "scope":addr.Scope}).Debug("")
					ret = append(ret, addr.IPNet)
				}
			} else {
				ret = append(ret, addr.IPNet)
			}
		}
	}

	return ret
}

func (d *kubernetes) IgnoreConnectFromManagedHost() bool {
	return false
}

func (d *kubernetes) ConsiderHostsAsInternal() bool {
	/*
		if d.flavor == "" {
			return false
		} else {
			return true
		}
	*/
	return true
}

func (d *kubernetes) ApplyPolicyAtIngress() bool {
	// Default kubernetes or rancher
	if d.flavor != share.FlavorOpenShift {
		return true
	} else {
		return false
	}
}

func (d *kubernetes) SupportKubeCISBench() bool {
	if d.flavor != share.FlavorOpenShift {
		return true
	}

	ocVer, err := version.NewVersion(d.ocVer)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "version": d.ocVer}).Error("Failed to read Openshift version")
		return false
	}

	if ocVer.Compare(version.Must(version.NewVersion("4.3"))) >= 0 {
		return true
	}

	return false
}

func (d *kubernetes) createCleanupScript(wr io.Writer, hostPorts map[string][]share.CLUSIPAddr) error {
	tmpl := template.New("ovs")
	template.Must(tmpl.Parse(tmplOVSCleanup))
	return tmpl.Execute(wr, hostPorts)
}

func (d *kubernetes) CleanupHostPorts(hostPorts map[string][]share.CLUSIPAddr) error {
	if d.flavor == share.FlavorOpenShift {
		if f, err := ioutil.TempFile("", "ovs"); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to create file")
			return err
		} else {
			defer func() {
				f.Close()
				os.Remove(f.Name())
			}()

			if err = d.createCleanupScript(f, hostPorts); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error when generating script")
				return err
			}

			// Run cleanup script in host mount and network namespace
			args := []string{
				system.NSActRun, f.Name(), d.sys.GetMountNamespacePath(1), d.sys.GetNetNamespacePath(1),
			}

			log.WithFields(log.Fields{"args": args, "ports": hostPorts}).Debug("Run clean up script")

			cmd := exec.Command(system.ExecNSTool, args...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err = cmd.Start(); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Start")
				return err
			}
			pgid := cmd.Process.Pid
			d.sys.AddToolProcess(pgid, 1, "k8s_chgport", f.Name())
			err = cmd.Wait()
			d.sys.RemoveToolProcess(pgid, false)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Wait")
				return err
			}
		}
	}
	return nil
}

// When a nodePort service is created, k8s use a system container kube-proxy to implement it.
// kube-proxy is a host mode container and has the nodePort service port open. We don't want to
// create policies between the application container to kube-proxy, so ignore kube-proxy.
// See unitest for examples.
func (d *kubernetes) isKubeProxy(wl *share.CLUSWorkload) bool {
	ns, ok := wl.Labels[container.KubeKeyPodNamespace]
	if !ok || ns != container.KubeNamespaceSystem {
		return false
	}

	cname, ok := wl.Labels[container.KubeKeyContainerName]
	if !ok {
		return false
	}
	podname, ok := wl.Labels[container.KubeKeyPodName]
	if !ok {
		return false
	}

	if strings.HasPrefix(podname, container.KubePodNamePrefixProxy) {
		if cname == container.KubeContainerNameProxy || cname == container.KubeContainerNamePod {
			return true
		}
	}

	return false
}
