package orchestration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/system"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
const reStrJobPoNameKubxEtcdBackup string = "^kubx-etcd-backup-[a-z0-9]{20}-.*"

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
var reJobPodNameKubxEtcdBackup *regexp.Regexp

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
	envParser     *utils.EnvironParser
}

func getVersion(tag string, verToGet int, useToken bool) (string, error) {
	var url string

	switch verToGet {
	case K8S_VER:
		url = "https://kubernetes.default/version"
	case OC_VER_V3:
		url = "https://kubernetes.default/version/openshift"
	case OC_VER_V4:
		url = "https://kubernetes.default/apis/config.openshift.io/v1/clusteroperators/openshift-apiserver"
	default:
		return "", nil
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
		return "", fmt.Errorf("New Request fail - error=%s", err)
	}
	if useToken {
		if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
			return "", fmt.Errorf("Read File fail - tag=%s, error=%s", tag, err)
		} else {
			req.Header.Set("Authorization", "Bearer "+string(data))
		}
	}
	if resp, err = client.Do(req); err != nil || resp == nil {
		return "", fmt.Errorf("Get Version fail - error=%s", err)
	}

	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getVersion fail - code=%d, tag=%s, useToken=%v", resp.StatusCode, tag, useToken)
	}

	var data []byte
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Read data fail - error=%s", err)
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

	return version, err
}

func GetK8sVersion(reGetK8sVersion, reGetOcVersion bool) (string, string) {
	var k8sVer string
	var ocVer string
	var version string
	var err error

	if reGetK8sVersion {
		for _, useToken := range []bool{false, true} {
			if version, err = getVersion("k8s", K8S_VER, useToken); version != "" {
				k8sVer = version
				break
			}
		}
		if k8sVer == "" && err != nil {
			log.Error(err.Error())
		}
		err = nil
	}

	if reGetOcVersion {
		useToken := []bool{false, true}
		for idx, verToGet := range []int{OC_VER_V3, OC_VER_V4} {
			if version, err = getVersion("oc", verToGet, useToken[idx]); version != "" {
				ocVer = version
				break
			}
		}
		if ocVer == "" && err != nil {
			log.Error(err.Error())
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

// ibm-system / ibm-cloud-provider-ip-169-44-162-75-8649c8697d-hplzc / (ip) / ip-169-44-162-75
// armada / armada-cluster-store-7f4684bb88-ldnn2 / (hash) / 7f4684bb88
// kubx-etcd-04 / etcd-cdogojn20umpmuo8l540-m9wlr29r8w / (clusterID) / cdogojn20umpmuo8l540
var hashLabels = []string{
	container.IbmCloudProviderIP,
	container.IbmCloudClusterID,
	container.KubeKeyPodHash, // last
}

const reStrUuid string = "-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" // + "-"
var regexpUuid *regexp.Regexp

func hasUUIDString(u string) int {
	if regexpUuid == nil {
		regexpUuid = regexp.MustCompile(reStrUuid)
	}

	if loc := regexpUuid.FindStringIndex(u); loc != nil {
		return loc[0]
	}
	return -1
}

func (d *kubernetes) GetServiceFromPodLabels(namespace, pod, node string, labels map[string]string) *Service {
	if len(labels) == 0 {
		return nil
	}

	if seviceName, ok := labels[container.NeuvectorSetServiceName]; ok {
		return &Service{Domain: namespace, Name: utils.Dns1123NameChg(strings.ToLower(seviceName))}
	}

	// pod.name can take format such as, frontend-3823415956-853n5, calico-node-m308t, kube-proxy-8vbrs.
	// For the first case, the pod-template-hash is 3823415956, if the hash label exists, we remove it.
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

	// remove uuid-like string
	if index := hasUUIDString(pod); index > 0 {
		return &Service{Domain: namespace, Name: pod[:index]}
	}

	if jobName, ok := labels[container.KubeKeyJobName]; ok {
		if reJobPodNameKubxEtcdBackup == nil {
			reJobPodNameKubxEtcdBackup = regexp.MustCompile(reStrJobPoNameKubxEtcdBackup)
		}
		if reJobPodNameKubxEtcdBackup.MatchString(jobName) {
			// make a service package
			return &Service{Domain: namespace, Name: "kubx-etcd-backup"}
		}
	}

	// remove hash index
	for _, labl := range hashLabels {
		if hash, ok := labels[labl]; ok && hash != "" {
			if index := strings.Index(pod, hash); index > 0 {
				return &Service{Domain: namespace, Name: pod[:(index - 1)]}
			}
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

	// remove node's name
	// "kube-system" / apiserver-watcher-qalongruncluster4oc4-kxq6x-master-2
	// "openshift-kube-apiserver" / revision-pruner-10-qalongruncluster4oc4-kxq6x-master-2
	// "openshift-kube-scheduler" / installer-7-qalongruncluster4oc4-kxq6x-master-2
	if len(node) > 3 { // at least 4 characters
		if index := strings.Index(pod, "-"+node); index > 0 {
			pod = pod[:index]
			if dash := strings.LastIndex(pod, "-"); dash > 0 {
				if _, err := strconv.Atoi(pod[(dash + 1):]); err == nil {
					pod = pod[:dash] // this batch number is from the configmap
				}
			}
			return &Service{Domain: namespace, Name: pod}
		}
	}

	// Remove the last tokens - not correct in some cases at all
	if first := strings.LastIndex(pod, "-"); first != -1 {
		return &Service{Domain: namespace, Name: pod[:first]}
	}

	return &Service{Domain: namespace, Name: pod}
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
func (d *kubernetes) GetService(meta *container.ContainerMeta, node string) *Service {
	namespace := meta.Labels[container.KubeKeyPodNamespace]

	if dc := meta.Labels[container.KubeKeyDeployConfig]; dc != "" {
		return &Service{Domain: namespace, Name: dc}
	}

	// pod.name can take format such as, frontend-3823415956-853n5, calico-node-m308t, kube-proxy-8vbrs.
	// For the first case, the pod-template-hash is 3823415956, if the hash label exists, we remove it.
	if pod := meta.Labels[container.KubeKeyPodName]; pod != "" {
		return d.GetServiceFromPodLabels(namespace, pod, node, meta.Labels)
	}

	return baseDriver.GetService(meta, node)
}

func (d *kubernetes) GetPlatformRole(m *container.ContainerMeta) (string, bool) {
	vpodns := m.Labels[container.KubeKeyPodNamespace]
	vcname := m.Labels[container.KubeKeyContainerName]
	podname := m.Labels[container.KubeKeyPodName]

	svc := d.GetService(m, "")
	svcName := utils.MakeServiceName(svc.Domain, svc.Name)
	for _, r := range d.envParser.GetSystemGroups() {
		if r.MatchString(svcName) {
			return container.PlatformContainerKubeInfra, false
		}
	}

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
	if pod := labels[container.KubeKeyPodName]; pod != "" {
		namespace := labels[container.KubeKeyPodNamespace]
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
			for j := range addrs {
				addrs[j].Scope = share.CLUSIPAddrScopeLocalhost
			}
			continue
		}

		for j := range addrs {
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
				//cilium_host i/f scope is RT_SCOPE_LINK
				if ones == bits && ones == 32 && (addr.Scope == syscall.RT_SCOPE_UNIVERSE || addr.Scope == syscall.RT_SCOPE_LINK) {
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
		if f, err := os.CreateTemp("", "ovs"); err != nil {
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

func (d *kubernetes) SetFlavor(flavor string) error {
	d.flavor = flavor
	return nil
}
