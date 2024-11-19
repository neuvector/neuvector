package main

// #include "../defs.h"
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/pipe"
	"github.com/neuvector/neuvector/agent/policy"
	"github.com/neuvector/neuvector/agent/probe"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/vishvananda/netlink"
)

const containerWaitParentPeriod time.Duration = (time.Second * 1)
const containerReexamIntfMax time.Duration = (time.Second * 180)
const containerReexamIntfIPv4Min time.Duration = (time.Second * 4)
const containerTaskChanSizeMin = 256

var errHostModeUnsupported = errors.New("Host mode not supported")
var errChildUnsupported = errors.New("Child container not supported")
var errZeroPidUnsupported = errors.New("Container pid zero not supported")

var containerGracePeriod time.Duration = (time.Second * 1)
var ContainerTaskChan chan *ContainerTask

// inline: If a workload is configured to be inline (not including quarantin case)
// capIntcp: Indicate if a workload can be put inline.
//
//	Platform and host mode containers cannot be intercepted.
//	If not interceptable, the container cannot be quarantined
//
// hasDatapath: parent and non-platform-containers, could be host mode
// in the case that parent's pid==0, child's hasDatapath could be true
type containerData struct {
	id             string
	name           string
	pid            int
	info           *container.ContainerMetaExtra
	inline         bool
	blocking       bool
	quar           bool
	capIntcp       bool
	capBlock       bool
	hostMode       bool
	hasDatapath    bool
	nfq            bool
	policyMode     string
	stats          share.ContainerStats
	intcpPairs     []*pipe.InterceptPair
	ownListenPorts utils.Set                              // set of share.CLUSProtoPort. Not merged from children.
	appMap         map[share.CLUSProtoPort]*share.CLUSApp // Including merged app from children
	portMap        map[share.CLUSProtoPort]*share.CLUSMappedPort
	parentNS       string
	pods           utils.Set
	service        string
	domain         string
	role           string
	svcSubnet      *net.IPNet
	cgroupMemory   string
	cgroupCPUAcct  string
	rootFs         string
	upperDir       string
	propertyFilled bool
	benchReported  bool
	pushPHistory   bool
	examIntface    bool
	scanCache      []byte
	nvRole         string
	healthCheck    []string // docker: healthcheck commands
}

// All information inside localSystemInfo is protected by mutex,
// and is only modified by docker task thread. Sending info to DP
// needs to grab dpMsg lock, so be careful to avoid lock embedding
type localSystemInfo struct {
	mutex            sync.RWMutex
	hostScanCache    []byte
	activeContainers map[string]*containerData
	neuContainers    map[string]*containerData // separate them from normal containers
	activePid2ID     map[int]string
	allContainers    utils.Set
	macContainerMap  map[string]string
	macPortPairMap   map[string]*pipe.InterceptPair
	// network info read from docker daemon
	networks   map[string]*container.Network
	networkLBs map[string]*container.NetworkEndpoint
	// all subnets that local containers connect to, including overlay
	// and local bridge subnets
	localSubnetMap map[string]share.CLUSSubnet
	// all subnets that all containers in the cluster connect to, including
	// local subnets and subnets populated from controller
	internalSubnets   map[string]share.CLUSSubnet
	containerConfig   map[string]*share.CLUSWorkloadConfig
	policyMode        string
	agentConfig       share.CLUSAgentConfig
	agentStats        share.ContainerStats
	hostIPs           utils.Set
	tapProxymesh      bool
	jumboFrameMTU     bool
	xffEnabled        bool
	ciliumCNI         bool
	disableNetPolicy  bool
	detectUnmanagedWl bool
	enableIcmpPolicy  bool
	linkStates        map[string]bool
}

var defaultPolicyMode string = share.PolicyModeLearn
var defaultTapProxymesh bool = true

// to avoid false positive implicit violation on dp during upgrade, set XFF default to disabled
var defaultXffEnabled bool = false
var defaultDisableNetPolicy bool = false
var defaultDetectUnmanagedWl bool = false
var defaultEnableIcmpPolicy bool = false
var rtStorageDriver string

var gInfo localSystemInfo = localSystemInfo{
	networks:         make(map[string]*container.Network),
	networkLBs:       make(map[string]*container.NetworkEndpoint),
	activeContainers: make(map[string]*containerData),
	neuContainers:    make(map[string]*containerData),
	activePid2ID:     make(map[int]string),
	allContainers:    utils.NewSet(),
	macContainerMap:  make(map[string]string),
	macPortPairMap:   make(map[string]*pipe.InterceptPair),
	localSubnetMap:   make(map[string]share.CLUSSubnet),
	internalSubnets:  make(map[string]share.CLUSSubnet),
	containerConfig:  make(map[string]*share.CLUSWorkloadConfig),
	policyMode:       defaultPolicyMode,
	agentConfig:      share.CLUSAgentConfig{Debug: make([]string, 0), LogLevel: "info"},
	hostIPs:          utils.NewSet(),
	tapProxymesh:     defaultTapProxymesh,
	jumboFrameMTU:    false,
	xffEnabled:       defaultXffEnabled,
	ciliumCNI:        false,
	linkStates:       make(map[string]bool),
}

func gInfoLock() {
	//log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ")
	gInfo.mutex.Lock()
}

func gInfoUnlock() {
	//log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ")
	gInfo.mutex.Unlock()
}

func gInfoRLock() {
	//log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ")
	gInfo.mutex.RLock()
}

func gInfoRUnlock() {
	//log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ")
	gInfo.mutex.RUnlock()
}

func gInfoReadActiveContainer(id string) (*containerData, bool) {
	gInfoRLock()
	c, ok := gInfo.activeContainers[id]
	gInfoRUnlock()
	return c, ok
}

func gInfoReadNeuvectorContainer(id string) (*containerData, bool) {
	gInfoRLock()
	c, ok := gInfo.neuContainers[id]
	gInfoRUnlock()
	return c, ok
}

func getContainerByMAC(mac net.HardwareAddr) *containerData {
	gInfoRLock()
	defer gInfoRUnlock()

	if id, ok := gInfo.macContainerMap[mac.String()]; ok {
		if c, ok := gInfo.activeContainers[id]; ok {
			return c
		}
	}
	return nil
}

func isLocalHostIP(ip net.IP) bool {
	gInfoRLock()
	defer gInfoRUnlock()
	return gInfo.hostIPs.Contains(ip.String())
}

func isIPInternal(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	for _, subnet := range gInfo.internalSubnets {
		if subnet.Subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func isContainerNetHostMode(info *container.ContainerMetaExtra, parent *containerData) bool {
	if info.NetMode == "host" || (parent != nil && parent.info.NetMode == "host") {
		return true
	}
	return false
}

// TODO: add more verifications to exclude hacker containers
func nvPod2Role(pod string) string {
	// Assume the pod name must be of pattern, neuvector-controller-pod-xxxx or dss-controller-pod-xxxx (OEM)
	if !strings.HasPrefix(pod, "neuvector-") && !strings.HasPrefix(pod, "dss-") {
		return ""
	}

	role := pod
	if index := strings.LastIndex(role, "-pod"); index != -1 {
		role = role[:index]
		if index = strings.Index(role, "-"); index != -1 {
			role = role[index+1:]
			return role
		} else {
			return ""
		}
	} else {
		return ""
	}
}

func isNeuvectorFunctionRole(role string, rootPid int) bool {
	// log.WithFields(log.Fields{"role": role, "pid": rootPid}).Debug("PROC:")
	// 1st screening
	entryPtSig := ""
	// assumptions: user does not modify the production yaml
	switch role { // role or simplified podname
	case "controller+enforcer", "enforcer", "controller", "scanner":
		entryPtSig = "/usr/local/bin/monitor"
	case "manager":
		entryPtSig = "/usr/local/bin/admin-assembly-" // partial library name
	case "controller+enforcer+manager", "allinone":
		entryPtSig = "/usr/bin/supervisord" // a python app
	case "updater":
		entryPtSig = "sleep" // 4.4: "/usr/local/bin/upgrader"
	case "fetcher":
		entryPtSig = "/usr/local/bin/fetcher"
	case "csp":
		entryPtSig = "/usr/bin/csp-billing-adapter"
	case "registry-adapter":
		entryPtSig = "/usr/local/bin/adapter"
	default:
		//	log.WithFields(log.Fields{"invalid role": role}).Debug("PROC:")
		return false // exclude others
	}

	// passed the 1st screening

	// 2nd screening: handle the exited child container at the last part
	if !osutil.IsPidValid(rootPid) {
		// log.Debug("invalid root pid")
		return true // skipped the test
	}

	if cmds, err := global.SYS.ReadCmdLine(rootPid); err == nil && len(cmds) > 0 {
		//	log.WithFields(log.Fields{"role": role, "cmds": cmds}).Debug("PROC:")
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, entryPtSig) { // matched at least two criteria
				return true
			}

			if strings.HasPrefix(cmd, "/usr/local/bin/monitor") { // last matching
				return true
			}
		}
	}
	return false
}

func isNeuVectorContainer(info *container.ContainerMetaExtra) (string, bool) {
	labels := info.Labels
	if Agent.Domain != "" && Agent.Domain != global.ORCH.GetDomain(labels) { // orchestra
		return "", false
	}

	if role, ok := labels[share.NeuVectorLabelRole]; ok {
		if isNeuvectorFunctionRole(role, info.Pid) {
			return role, true
		}
	}

	// orchestra platforms
	if podname, ok := labels[container.KubeKeyPodName]; ok {
		role := nvPod2Role(podname)
		if role == "" {
			// 2nd try
			if app, ok := labels[container.KubeKeyAppName]; ok {
				role = nvPod2Role(app)
			}
			if role == "" {
				return "", false
			}
		}

		if isNeuvectorFunctionRole(role, info.Pid) {
			return role, true
		}

		// POD for neuvector
		if isChild, _ := getSharedContainer(info); !isChild {
			//	log.WithFields(log.Fields{"labels": labels, "podname": podname}).Debug("PROC: POD")
			return role, true
		} else { // a child
			if !info.Running {
				// and exited neuvector containers
				return role, true
			}
		}
	}
	return "", false
}

func getNeuVectorRole(info *container.ContainerMetaExtra) (string, bool) {
	labels := info.Labels
	if Agent.Domain != "" && Agent.Domain != global.ORCH.GetDomain(labels) { // orchestra
		return "", false
	}

	role, ok := labels[share.NeuVectorLabelRole]
	return role, ok
}

func isSidecarContainer(labels map[string]string) bool {
	//check if container is a sidecar that is linkerd-proxy or istio-proxy
	sc_containername := labels[container.KubeKeyContainerName]

	if strings.Contains(sc_containername, container.KubeLinkerdProxyName) ||
		strings.Contains(sc_containername, container.KubeIstioProxyName) ||
		strings.Contains(sc_containername, container.KubeAwsProxyName) {
		return true
	}
	return false
}

func runtimeEventCallback(ev container.Event, id string, pid int) {
	switch ev {
	case container.EventContainerStart:
		task := ContainerTask{task: TASK_ADD_CONTAINER, id: id}
		ContainerTaskChan <- &task
	case container.EventContainerStop:
		// containerd runtime report TaskExit for both process stop and container stop.
		// Here is to make sure the pid is container's pid and avoid writing event log
		if pid != 0 {
			gInfoRLock()
			_, ok := gInfo.activePid2ID[pid]
			gInfoRUnlock()
			if !ok {
				return
			}
		}

		task := ContainerTask{task: TASK_STOP_CONTAINER, id: id, pid: pid}
		ContainerTaskChan <- &task
	case container.EventContainerDelete:
		task := ContainerTask{task: TASK_DEL_CONTAINER, id: id}
		ContainerTaskChan <- &task
	case container.EventContainerCopyIn:
		if c, ok := gInfoReadActiveContainer(id); ok {
			prober.ReportDockerCp(id, c.name, true)
		} else if isAgentContainer(id) {
			prober.ReportDockerCp(id, Agent.Name, true)
		}
	case container.EventContainerCopyOut:
		if c, ok := gInfoReadActiveContainer(id); ok {
			prober.ReportDockerCp(id, c.name, false)
		} else if isAgentContainer(id) {
			prober.ReportDockerCp(id, Agent.Name, false)
		}
	case container.EventNetworkCreate:
		// ignore network creatation for now, the special lb-net endpoint is detected when new container starts
	case container.EventNetworkDelete:
		handleNetworkDelete(id)
	case container.EventSocketError:
		monitorExitChan <- nil
	}
}

// with gInfoLock held
func refreshLocalSubnets() bool {
	subnetMap := make(map[string]share.CLUSSubnet)
	addHostSubnets(Host.Ifaces, subnetMap)

	for _, c := range gInfo.activeContainers {
		addContainerSubnets(c, subnetMap)
	}
	if reflect.DeepEqual(gInfo.localSubnetMap, subnetMap) {
		return false
	} else {
		gInfo.localSubnetMap = subnetMap
		return mergeLocalSubnets(gInfo.internalSubnets)
	}
}

// with gInfoLock held
func addContainerSubnets(c *containerData, subnetMap map[string]share.CLUSSubnet) bool {
	var new bool

	// Add subnets used by containers
	for _, pair := range c.intcpPairs {
		for _, addr := range pair.Addrs {
			subnet := utils.IPNet2SubnetLoose(&addr.IPNet, addr.Scope)
			if _, ok := subnetMap[subnet.String()]; !ok {
				subnetMap[subnet.String()] = share.CLUSSubnet{Subnet: *subnet, Scope: addr.Scope}
				new = true
			}
		}
	}

	// Add all local bridge subnets. Even the subnet is not used by any containers,
	// the gateway IP (172.17.0.1) can be used to reach other containers on different
	// subnets (172.18.0.0)
	for _, network := range gInfo.networks {
		if network.Scope == container.DockerNetworkLocal {
			for _, subnet := range network.Subnets {
				if _, ok := subnetMap[subnet.String()]; !ok {
					subnetMap[subnet.String()] = share.CLUSSubnet{
						Subnet: *subnet, Scope: share.CLUSIPAddrScopeLocalhost,
					}
					new = true
				}
			}
		}
	}

	// Service IPs are in a different subnet in Kubernetes, if we don't learn it at the
	// enforcer, connections are marked as 'external' before internal subnets are pushed
	// from the controllers.
	if c.svcSubnet != nil {
		subnet := utils.IPNet2SubnetLoose(c.svcSubnet, share.CLUSIPAddrScopeGlobal)
		if _, ok := subnetMap[subnet.String()]; !ok {
			subnetMap[subnet.String()] = share.CLUSSubnet{
				Subnet: *subnet, Scope: share.CLUSIPAddrScopeGlobal,
			}
			new = true
		}
	}

	return new
}

func addHostSubnets(ifaces map[string][]share.CLUSIPAddr, subnetMap map[string]share.CLUSSubnet) {
	for _, addrs := range ifaces {
		for _, addr := range addrs {
			subnet := utils.IPNet2SubnetLoose(&addr.IPNet, share.CLUSIPAddrScopeNAT)
			if _, ok := subnetMap[subnet.String()]; !ok {
				subnetMap[subnet.String()] = share.CLUSSubnet{Subnet: *subnet, Scope: addr.Scope}
			}
		}
	}
}

func notifyDPContainerApps(c *containerData) {
	if c.hostMode || !c.hasDatapath {
		return
	}

	macs := make([]string, len(c.intcpPairs))
	for i, pair := range c.intcpPairs {
		macs[i] = pair.MAC.String()
	}
	if gInfo.tapProxymesh && isProxyMesh(c) {
		lomac_str := fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
		macs = append(macs, lomac_str)
	}
	if len(macs) == 0 {
		log.WithFields(log.Fields{"container": c.id}).Error("No interface!!")
		return
	}
	dp.DPCtrlConfigMAC(macs, nil, c.appMap)
}

func updatePods(c *containerData, quarReason *string) {
	if c.pods.Cardinality() > 0 {
		for pod := range c.pods.Iter() {
			if pc, ok := gInfoReadActiveContainer(pod.(string)); ok {
				pc.inline = c.inline
				pc.quar = c.quar
				ClusterEventChan <- &ClusterEvent{
					event: EV_UPDATE_CONTAINER, id: pc.id, inline: &pc.inline, quar: &pc.quar,
					quarReason: quarReason,
				}
			}
		}
	} else if c.parentNS != "" {
		if p, ok := gInfoReadActiveContainer(c.parentNS); ok { //parent exist
			p.inline = c.inline
			p.quar = c.quar
			ClusterEventChan <- &ClusterEvent{
				event: EV_UPDATE_CONTAINER, id: p.id, inline: &p.inline, quar: &p.quar,
				quarReason: quarReason,
			}
			for podID := range p.pods.Iter() {
				podid := podID.(string)
				if podid != c.id {
					if ch, ok1 := gInfoReadActiveContainer(podid); ok1 {
						ch.inline = c.inline
						ch.quar = c.quar
						ClusterEventChan <- &ClusterEvent{
							event: EV_UPDATE_CONTAINER, id: ch.id, inline: &ch.inline, quar: &ch.quar,
							quarReason: quarReason,
						}
					}
				}
			}
		}
	}
}

func changeContainerWire(c *containerData, inline bool, quar bool, quarReason *string) {
	// If inline and it doesn't change, and only quarantine state is chagned => only need change bridge rules
	if c.inline && inline {
		c.inline = inline
		c.quar = quar

		if driver == pipe.PIPE_NOTC {
			programBridgeNoTc(c)
		}
		programBridge(c)
	} else {
		c.inline = inline
		c.quar = quar

		_, _, _, _, err := programUpdatePairs(c, true)
		if err == nil {
			programBridge(c)
			programDP(c, false, nil)
			if gInfo.tapProxymesh {
				programProxyMeshDP(c, false, true)
				updateProxyMeshMac(c, false)
			}
		}
	}

	ClusterEventChan <- &ClusterEvent{
		event: EV_UPDATE_CONTAINER, id: c.id, inline: &c.inline,
		quar: &c.quar, quarReason: quarReason,
	}

	updatePods(c, quarReason)
}

func isProxyMesh(c *containerData) bool {
	//ProxyMesh==true also indicate it is parent,
	//but we also need to check pid since oc4.9+
	if c.info.ProxyMesh && c.pid != 0 {
		return true
	}
	//in case parent's pid is zero we need to use child's pid,
	//but we need to make sure to exclude non-mesh case.
	if c.parentNS != "" && c.hasDatapath && c.pid != 0 { //has parent
		p, ok := gInfo.activeContainers[c.parentNS]
		if ok { //parent exist
			if p.info.ProxyMesh && p.pid == 0 { //parent is mesh and pid=0
				return true
			}
		}
	}
	return false
}

func updateProxyMeshMac(c *containerData, withlock bool) {
	if !isProxyMesh(c) {
		return
	}
	//POD with proxy injection
	lomac_str := fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
	log.WithFields(log.Fields{"lomac_str": lomac_str, "pid": c.pid}).Debug("tap proxymesh's loopback intf")
	if !withlock {
		gInfoLock()
	}
	if !c.info.ProxyMesh {
		//child, map mac to parent id because in
		//network activity page parent is drawn
		gInfo.macContainerMap[lomac_str] = c.parentNS
	} else {
		gInfo.macContainerMap[lomac_str] = c.id
	}
	if !withlock {
		gInfoUnlock()
	}
}

func delProxyMeshMac(c *containerData, withlock bool) {
	if !isProxyMesh(c) {
		return
	}
	lomac_str := fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
	log.WithFields(log.Fields{"lomac_str": lomac_str, "pid": c.pid}).Debug("Delete tap proxymesh's loopback intf")
	if !withlock {
		gInfoLock()
	}
	delete(gInfo.macContainerMap, lomac_str)
	if !withlock {
		gInfoUnlock()
	}
}

func getProxyMeshAppMap(c *containerData, listenAll bool) map[share.CLUSProtoPort]*share.CLUSApp {
	if listenAll {
		return nil
	}
	proxyMeshApp := make(map[share.CLUSProtoPort]*share.CLUSApp)
	for port, app := range c.appMap {
		proxyMeshApp[port] = app
	}
	for podID := range c.pods.Iter() { //c is parent
		if pod, ok := gInfo.activeContainers[podID.(string)]; ok && !pod.info.Sidecar {
			for port, app := range pod.appMap {
				_, ok := proxyMeshApp[port]
				if !ok {
					proxyMeshApp[port] = app
				}
			}
		}
	}
	return proxyMeshApp
}

func programProxyMeshDP(c *containerData, cfgApp, restore bool) {
	if !isProxyMesh(c) {
		return
	}
	log.WithFields(log.Fields{"container": c.id}).Debug("proxymesh")

	netns := global.SYS.GetNetNamespacePath(c.pid)
	macs := make([]string, 1)
	tap := false
	//tap lo interface for POD that inject proxy
	// 6c:6b:73:74 - lkst
	var lomac_str string
	var lo_oldmac, lo_mac, lo_umac, lo_bmac net.HardwareAddr
	lomac_str = fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
	lo_mac, _ = net.ParseMAC(lomac_str)

	//pass parent containers IP to service mesh ep so that
	//when src/dst IP are both 127.0.0.x, we can replace dst
	//IP with parent containers IP to do XFF related policy match
	pAddrs := make([]net.IP, 0)
	for _, pair := range c.intcpPairs {
		for _, addr := range pair.Addrs {
			pAddrs = append(pAddrs, addr.IPNet.IP)
		}
	}
	if c.quar || c.inline {
		dp.DPCtrlDelTapPort(netns, "lo")
		for _, pair := range c.intcpPairs {
			//for proxymesh endpoint, we need pair.MAC for policy matching in DP,
			//all pair.MAC point to same policy handle in DP, use only one
			dp.DPCtrlAddMAC("lo", lo_mac, lo_umac, lo_bmac, lo_oldmac, pair.MAC, pAddrs)
			break
		}
		//traffic between sidecar proxy and app container cannot be enforced
		//as regular veth pair, we need to set up iptable rules with NFQUEUE
		//in container's namespace, and dp need to create nfq handle(nfq_open)
		proxyMeshApp := getProxyMeshAppMap(c, true)
		if !c.nfq {
			err := pipe.CreateNfqRules(c.pid, 0, true, true, "lo", proxyMeshApp)
			if err != nil {
				log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to create nfq iptable rules")
			} else {
				c.nfq = true
				jumboFrame := gInfo.jumboFrameMTU
				//create dp nfq handle
				dp.DPCtrlAddNfqPort(netns, "lo", 0, lo_mac, &jumboFrame)
			}
		} else {
			if dbgError := pipe.CreateNfqRules(c.pid, 0, false, true, "lo", proxyMeshApp); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			jumboFrame := gInfo.jumboFrameMTU
			//create dp nfq handle
			dp.DPCtrlAddNfqPort(netns, "lo", 0, lo_mac, &jumboFrame)
		}
	} else {
		if restore {
			//delete dp nfq handle first before reset iptable rules
			dp.DPCtrlDelNfqPort(netns, "lo")
		}
		dp.DPCtrlAddTapPort(netns, "lo", lo_mac)
		for _, pair := range c.intcpPairs {
			//for proxymesh endpoint, we need pair.MAC for policy matching in DP,
			//all pair.MAC point to same policy handle in DP, use only one
			dp.DPCtrlAddMAC("lo", lo_mac, lo_umac, lo_bmac, lo_oldmac, pair.MAC, pAddrs)
			break
		}
		tap = true
	}
	macs[len(macs)-1] = lo_mac.String()

	if cfgApp {
		dp.DPCtrlConfigMAC(macs, &tap, c.appMap)
	} else {
		dp.DPCtrlConfigMAC(macs, &tap, nil)
	}
}

func programDelProxyMeshDP(c *containerData, ns string) {
	if !isProxyMesh(c) {
		return
	}
	var netns string
	netns = ns
	if ns == "" {
		netns = global.SYS.GetNetNamespacePath(c.pid)
	}
	//POD with proxy injection
	// 6c:6b:73:74 - lkst
	var lomac_str string
	var lo_mac net.HardwareAddr
	lomac_str = fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
	lo_mac, _ = net.ParseMAC(lomac_str)

	if c.quar || c.inline {
		//delete dp nfq handle if any then reset iptable rules
		dp.DPCtrlDelNfqPort(netns, "lo")
		if dbgError := pipe.DeleteNfqRules(c.pid); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		c.nfq = false
		dp.DPCtrlDelMAC("lo", lo_mac)
	} else {
		if dbgError := pipe.DeleteNfqRules(c.pid); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		c.nfq = false
		dp.DPCtrlDelTapPort(netns, "lo")
		dp.DPCtrlDelMAC("lo", lo_mac)
	}
}

func enableTapProxymesh(c *containerData) {
	updateProxyMeshMac(c, false)
	programProxyMeshDP(c, false, false)
}

func disableTapProxymesh(c *containerData) {
	programDelProxyMeshDP(c, "")
	delProxyMeshMac(c, false)
}

func getContainerIDByName(name string) string {
	for id, c := range gInfo.activeContainers {
		if c.name == name {
			return id
		}
	}

	return ""
}

// Get IP scope by workload MAC and ip address
func getIPAddrScope(mac net.HardwareAddr, ip net.IP) (string, string) {
	if pair, ok := gInfo.macPortPairMap[mac.String()]; ok {
		for _, addr := range pair.Addrs {
			if ip.String() == addr.IPNet.IP.String() {
				return addr.Scope, addr.NetworkName
			}
		}
	}

	return share.CLUSIPAddrScopeLocalhost, ""
}

// Return if container is child and its parent container.
func getSharedContainerWithLock(info *container.ContainerMetaExtra) (bool, *containerData) {
	if isChild, parent_cid := global.RT.GetParent(info, gInfo.activePid2ID); parent_cid != "" {
		var parent *containerData
		var ok bool
		if parent, ok = gInfo.activeContainers[parent_cid]; !ok {
			if real_parent_cid := getContainerIDByName(parent_cid); real_parent_cid != "" {
				parent_cid = real_parent_cid
			}
			if parent, ok = gInfo.activeContainers[parent_cid]; !ok {
				log.WithFields(log.Fields{"net_mode": info.NetMode}).Debug("Skip")
				return true, nil
			}
		}

		log.WithFields(log.Fields{"with": parent_cid}).Debug("Share network namespace")
		return true, parent
	} else {
		return isChild, nil
	}
}

// Return if container is child and its parent container.
func getSharedContainer(info *container.ContainerMetaExtra) (bool, *containerData) {
	gInfoRLock()
	defer gInfoRUnlock()
	return getSharedContainerWithLock(info)
}

func intcpPairs2Ifaces(intcpPairs []*pipe.InterceptPair) map[string][]share.CLUSIPAddr {
	if intcpPairs != nil {
		ifaces := make(map[string][]share.CLUSIPAddr)
		for _, pair := range intcpPairs {
			ifaces[pair.Port] = pair.Addrs
		}
		return ifaces
	}
	return nil
}

const (
	changeInit = iota
	changeIntf
	changeApp
)

var changeName = []string{
	changeInit: "init",
	changeIntf: "intf",
	changeApp:  "app",
}

func notifyContainerChanges(c *containerData, parent *containerData, change int) {
	log.WithFields(log.Fields{"id": c.id, "change": changeName[change]}).Debug("")

	var ev ClusterEvent
	if change == changeInit {
		capSniff := !c.hostMode
		ev = ClusterEvent{
			event: EV_ADD_CONTAINER, id: c.id, info: c.info,
			service: &c.service, domain: &c.domain, role: &c.role,
			inline: &c.inline, quar: &c.quar, shareNetNS: &c.parentNS,
			capIntcp: &c.capIntcp, capSniff: &capSniff, hasDatapath: &c.hasDatapath,
		}
	} else {
		ev = ClusterEvent{
			event: EV_UPDATE_CONTAINER, id: c.id,
		}
	}

	var ifaces map[string][]share.CLUSIPAddr
	if change == changeInit || change == changeIntf {
		if c.hostMode {
			ifaces = make(map[string][]share.CLUSIPAddr)
			for name, addrs := range Host.Ifaces {
				ifaces[name] = addrs
			}
		} else {
			ifaces = intcpPairs2Ifaces(c.intcpPairs)
		}

		ev.ifaces = ifaces
	}
	if change == changeInit || change == changeApp {
		ev.apps = translateAppMap(c.appMap)
		ev.ports = translateMappedPort(c.portMap)
	}

	ClusterEventChan <- &ev

	// When event is changeInit, app/port may already be available,
	// need to inform dp because the changeApp event may never come
	if change == changeApp || change == changeInit {
		if parent == nil {
			notifyDPContainerApps(c)
		} else {
			notifyDPContainerApps(parent)
		}
	}

	if parent == nil {
		if change == changeInit || change == changeIntf {
			// Notify the children for interface change
			for podID := range c.pods.Iter() {
				podEv := ClusterEvent{
					event: EV_UPDATE_CONTAINER, id: podID.(string), ifaces: ifaces,
				}
				ClusterEventChan <- &podEv
			}
		}
	} else {
		if change == changeInit || change == changeApp {
			// App map already populated to parent, send update to cluster channel.
			parentEv := ClusterEvent{
				event:       EV_UPDATE_CONTAINER,
				id:          parent.id,
				info:        parent.info,
				apps:        translateAppMap(parent.appMap),
				ports:       translateMappedPort(parent.portMap),
				hasDatapath: &parent.hasDatapath,
			}
			ClusterEventChan <- &parentEv
		} else if change == changeIntf {
			if c.examIntface { // only if POD's pid is 0
				// Notify the children/POD for interface change
				parent.intcpPairs = c.intcpPairs
				ClusterEventChan <- &ClusterEvent{event: EV_UPDATE_CONTAINER, id: parent.id, ifaces: ifaces}
				for podID := range parent.pods.Iter() {
					ClusterEventChan <- &ClusterEvent{event: EV_UPDATE_CONTAINER, id: podID.(string), ifaces: ifaces}
				}
			}
		}
	}
}

// Calling with gInfoLock held
func setIPAddrScope(c *containerData) {
	ports := make(map[string][]share.CLUSIPAddr, len(c.intcpPairs))
	for _, pair := range c.intcpPairs {
		ports[pair.Port] = pair.Addrs
	}
	global.ORCH.SetIPAddrScope(ports, &c.info.ContainerMeta, gInfo.networks)
}

type containerTimerReq struct {
	id   string
	info *container.ContainerMetaExtra
	req  int
}

func (p *containerTimerReq) Expire() {
	log.WithFields(log.Fields{"id": p.id, "req": ContainerTaskName[p.req]}).Debug("")
	task := ContainerTask{task: p.req, id: p.id, info: p.info}
	ContainerTaskChan <- &task
}

// This function should only be called on non-host mode parent container
func programUpdatePairs(c *containerData, restore bool) (bool, bool, bool, map[string]*pipe.InterceptPair, error) {
	// Program ports and compare change should always be done together, so we won't miss port changes.
	intcpPairs, err := programPorts(c, restore)
	if err != nil {
		return false, false, false, nil, err
	}

	var intfAdded, addrChanged, subnetChanged bool
	macChangePairs := make(map[string]*pipe.InterceptPair)

	gInfoLock()
	defer gInfoUnlock()

	for _, pairOld := range c.intcpPairs {
		for _, pairNew := range intcpPairs {
			if pairOld.Port == pairNew.Port {
				if len(pairOld.Addrs) != len(pairNew.Addrs) {
					addrChanged = true
				}
				if !bytes.Equal(pairOld.MAC, pairNew.MAC) {
					delete(gInfo.macContainerMap, pairOld.MAC.String())
					delete(gInfo.macPortPairMap, pairOld.MAC.String())
					if c.parentNS != "" {
						//child, map mac to parent id because in
						//network activity page parent is drawn
						gInfo.macContainerMap[pairNew.MAC.String()] = c.parentNS
					} else {
						gInfo.macContainerMap[pairNew.MAC.String()] = c.id
					}
					gInfo.macPortPairMap[pairNew.MAC.String()] = pairNew
					macChangePairs[pairOld.Port] = pairOld
				}
				break
			}
		}
	}

	if len(c.intcpPairs) != len(intcpPairs) {
		for _, pair := range intcpPairs {
			if c.parentNS != "" {
				//child, map mac to parent id because in
				//network activity page parent is drawn
				gInfo.macContainerMap[pair.MAC.String()] = c.parentNS
			} else {
				gInfo.macContainerMap[pair.MAC.String()] = c.id
			}
			gInfo.macPortPairMap[pair.MAC.String()] = pair
		}
		intfAdded = true
	}

	// When changing between tap and inline, UC/BCMAC, in/exPort all changed. =>
	// Always take the new copy and set the scope again
	c.intcpPairs = intcpPairs
	setIPAddrScope(c)

	if intfAdded || addrChanged {
		updateContainerNetworks(c, c.info)

		if addContainerSubnets(c, gInfo.localSubnetMap) {
			subnetChanged = mergeLocalSubnets(gInfo.internalSubnets)
		}
	}

	if intfAdded || addrChanged || len(macChangePairs) > 0 {
		for podID := range c.pods.Iter() {
			if pod, ok := gInfo.activeContainers[podID.(string)]; ok {
				pod.intcpPairs = c.intcpPairs
			}
		}
	}

	return intfAdded, addrChanged, subnetChanged, macChangePairs, nil
}

func taskReexamIntfContainer(id string, info *container.ContainerMetaExtra, restartMonitor bool) {
	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		if info != nil && c.pid != info.Pid {
			return
		}

		examNeuVectorInterface(c, changeIntf)
		return
	}

	// Check if the container is the same running instance when event is scheduled.
	c, ok := gInfoReadActiveContainer(id)
	if !ok || (info != nil && c.pid != info.Pid) || !c.propertyFilled {
		return
	}

	info = c.info

	intfAdded, addrChanged, subnetChanged, macChangePairs, err := programUpdatePairs(c, false)

	log.WithFields(log.Fields{
		"id": id, "intf": intfAdded, "addr": addrChanged, "subnet": subnetChanged, "mac": len(macChangePairs) > 0,
	}).Debug("Container changes")

	if err == nil {
		if len(macChangePairs) > 0 {
			// Reprogram pipe rules (rules are always reset and re-added)
			programBridge(c)
			// AddTapPort need to be called besides AddMAC in order to update MAC in pkt ring.
			programDP(c, false, macChangePairs)
			if gInfo.tapProxymesh {
				programProxyMeshDP(c, false, false)
				updateProxyMeshMac(c, false)
			}
		} else if intfAdded {
			programBridge(c)
			programDP(c, false, nil)
			if gInfo.tapProxymesh {
				programProxyMeshDP(c, false, false)
				updateProxyMeshMac(c, false)
			}
		}

		if subnetChanged {
			dp.DPCtrlConfigInternalSubnet(gInfo.internalSubnets)
		}

		if intfAdded || addrChanged {
			_, parent := getSharedContainer(info)
			notifyContainerChanges(c, parent, changeIntf)
		}
	}
}

func updateAppPorts(c *containerData, parent *containerData) bool {

	var appChanged bool = false
	listenPorts, appMap := prober.GetContainerAppPorts(c.id)

	gInfoLock()
	// remove closed port, only those opened by myself, not those merged from children.
	for port := range c.appMap {
		if _, ok := appMap[port]; !ok && c.ownListenPorts.Contains(port) {
			delete(c.appMap, port)
			/* In service mesh's case parent POD use encrypted connection,
			 * while app/child container sees clear text traffic, update parent
			 * with child's appMap can confuse user especially in mid-stream session
			 * case, thus add additional check
			 */
			if parent != nil && !parent.info.ProxyMesh {
				delete(parent.appMap, port)
			}
			log.WithFields(log.Fields{"port": port}).Debug("remove port")
			appChanged = true
		}
	}
	// add new port, populate to parent as well
	for port, app := range appMap {
		capp, ok := c.appMap[port]
		if !ok || capp.Server != app.Server || capp.Application != app.Application {
			c.appMap[port] = app
			/* In service mesh's case parent POD use encrypted connection,
			 * while app/child container sees clear text traffic, update parent
			 * with child's appMap can confuse user especially in mid-stream session
			 * case, thus add additional check
			 */
			if parent != nil && !parent.info.ProxyMesh {
				parent.appMap[port] = app
			}
			log.WithFields(log.Fields{"port": port}).Debug("add port")
			appChanged = true
		}
	}

	if appChanged {
		c.ownListenPorts = listenPorts
		// Update portMap only for host mode container
		// For non-host mode container, the portmap is read from meta data
		// which is configured at init
		if c.hostMode {
			c.portMap = app2MappedPort(c.appMap)
			if parent != nil {
				parent.portMap = app2MappedPort(parent.appMap)
			}
		}
	}
	gInfoUnlock()
	return appChanged
}

func taskReexamProcContainer(id string, info *container.ContainerMetaExtra) {

	// Check if the container is the same running instance when event is scheduled.
	c, ok := gInfoReadActiveContainer(id)
	if !ok || (info != nil && c.pid != info.Pid) || !c.propertyFilled {
		return
	}
	info = c.info

	// log.WithFields(log.Fields{"id": id}).Debug("")
	_, parent := getSharedContainer(info)
	appChanged := updateAppPorts(c, parent)
	if appChanged {
		notifyContainerChanges(c, parent, changeApp)
		if gInfo.tapProxymesh {
			programProxyMeshDP(c, false, false)
			updateProxyMeshMac(c, false)
		}
	}
}

func scheduleTask(id string, info *container.ContainerMetaExtra, req int, delay time.Duration) error {
	task := &containerTimerReq{
		id:   id,
		info: info,
		req:  req,
	}
	if _, err := agentTimerWheel.AddTask(task, delay); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to insert timer!")
		return err
	}
	return nil
}

// ContainerLayer is a write-able layer in the storage driver system
func lookupContainerLayerPath(pid int, id string) (string, string, error) {
	switch rtStorageDriver {
	case "overlay", "overlay2", "overlayFS", "overlayfs", "overlayFs":
		return global.SYS.ReadMountedUppperLayerPath(pid, id)
	case "aufs":
		return global.SYS.ReadAufsContainerLayerPath(pid, id)
	case "btrfs":
		return global.SYS.ReadMountedBtrfsWorkingPath(pid, id)
	default: // best offer
		if d, r, err := global.SYS.ReadMountedUppperLayerPath(pid, id); err == nil {
			return d, r, err
		}
	}
	return "", "", fmt.Errorf("not support")
}

func removeContainerLayerPath(id string) {
	if rtStorageDriver == "aufs" {
		global.SYS.RemoveContainerLayerPath(id)
	}
}

func fillContainerProperties(c *containerData, parent *containerData,
	info *container.ContainerMetaExtra, hostMode bool) {

	// Not using write lock because all fields filled here are simple
	c.svcSubnet = global.ORCH.GetServiceSubnet(info.Envs)
	if parent == nil {
		svc := global.ORCH.GetService(&info.ContainerMeta, Host.Name)
		c.service = utils.MakeServiceName(svc.Domain, svc.Name)
		c.domain = svc.Domain
		c.hostMode = hostMode

		// Deprecated: (In Rancher environment, ipsec-ipsec containers act as a proxy. It causes confusion
		// on policy rules and graph, so not to inspect platform containers' traffic)
		// As of now 2018/09, most platforms are kubernetes based, we can inspect system container traffic.
		if pct, secure := global.ORCH.GetPlatformRole(&info.ContainerMeta); pct != "" {
			// Skip infrastructure containers
			c.role = pct
			// c.hasDatapath = secure
			c.hasDatapath = true
			c.capIntcp = secure && !hostMode
			c.capBlock = secure
		} else {
			c.hasDatapath = true
			c.capIntcp = !hostMode
			c.capBlock = true
		}
		if c.pid == 0 {
			c.hasDatapath = false
		}
		c.inline = isContainerInline(c)
		c.blocking = isContainerBlocking(c)
		c.quar = isContainerQuarantine(c)
	} else {
		c.service = parent.service
		c.domain = parent.domain
		c.role = parent.role
		c.parentNS = parent.id
		c.capIntcp = parent.capIntcp
		c.capBlock = parent.capBlock
		c.hostMode = parent.hostMode
		c.inline = parent.inline
		c.blocking = parent.blocking
		c.quar = parent.quar
		if parent.pid == 0 {
			//NVSHAS-7830, multiple children exist, some may not be runnig
			//when parent pid=0, need to set all child hasDatapath to true
			//NVSHAS-8406,for istio only set app container to have datapath
			info.Sidecar = isSidecarContainer(info.Labels)
			if !info.Sidecar {
				c.hasDatapath = true
			}
			parent.hasDatapath = false
		}
	}

	c.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(info.Pid, "memory")
	c.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(info.Pid, "cpuacct")

	c.upperDir, c.rootFs, _ = lookupContainerLayerPath(c.pid, c.id)
	c.propertyFilled = true
	log.WithFields(log.Fields{"uppDir": c.upperDir, "rootFs": c.rootFs, "id": c.id}).Debug()
}

func handleNetworkDelete(netID string) {
	gInfoLock()
	defer gInfoUnlock()

	if ep, ok := gInfo.networkLBs[netID]; ok {
		delete(gInfo.networkLBs, netID)
		deleteNetworkEP(ep.ID)
		log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete network endpoint")
	}
}

// with gInfoLock held
func updateContainerNetworks(c *containerData, info *container.ContainerMetaExtra) {
	// If new network is found used by container, get docker networks and local interface IPs
	for n := range info.Networks.Iter() {
		netID := n.(string)
		if _, ok := gInfo.networks[netID]; !ok {
			if networks, err := global.RT.ListNetworks(); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
			} else {
				gInfo.networks = networks
				getHostIPs()
			}
		}

		if n, ok := gInfo.networks[netID]; ok {
			cname := fmt.Sprintf("lb-%s", n.Name)
			epname := fmt.Sprintf("%s-endpoint", n.Name)
			if _, ok = gInfo.networkLBs[netID]; !ok {
				if ep, err := global.RT.GetNetworkEndpoint(netID, cname, epname); err != nil {
					// Lower the debug level. We see repeated log on this.
					log.WithFields(log.Fields{"error": err, "container": cname, "endpoint": epname}).Debug("Error reading container network endpoint")
				} else {
					gInfo.networkLBs[netID] = ep

					nep := share.CLUSNetworkEP{
						ID:        ep.ID,
						Name:      cname,
						Type:      share.NEPTypeLB,
						NetworkID: netID,
						IP:        []net.IP{ep.IPNet.IP},
					}
					putNetworkEP(&nep)

					log.WithFields(log.Fields{"endpoint": nep}).Debug("Add network endpoint")
				}
			}
		}
	}
}

func isMultiNetworkContainer(c *containerData) bool {
	if c.intcpPairs != nil {
		for _, pair := range c.intcpPairs {
			if pair.Peer == "" || pair.Vxlan {
				return true
			}
		}
	}
	return false
}

func programNfqPorts(c *containerData, restore bool) ([]*pipe.InterceptPair, error) {
	if c.hostMode {
		return nil, errHostModeUnsupported
	}
	//check container pid
	if c.pid == 0 {
		return nil, errZeroPidUnsupported
	}
	// we check parentNS
	if c.parentNS != "" && !c.examIntface {
		return nil, errChildUnsupported
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	netns := global.SYS.GetNetNamespacePath(c.pid)
	if !c.quar && !c.inline && restore {
		for _, pair := range c.intcpPairs {
			//delete dp nfq handle
			dp.DPCtrlDelNfqPort(netns, pair.Port)
		}
	}
	//for ciliumCNI we do not pull container ports, only read ports
	newPairs, err := pipe.InspectContainerPorts(c.pid, c.intcpPairs)
	if err != nil {
		log.WithFields(log.Fields{"container": c.id, "error": err}).Error("NFQ Failed to inspect port")
	}
	return newPairs, err
}

func programPorts(c *containerData, restore bool) ([]*pipe.InterceptPair, error) {
	if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
		return programNfqPorts(c, restore)
	}
	// Platform containers' interfaces should be inspected, so instead of check against hasDatapath,
	// we check parentNS
	if c.hostMode {
		return nil, errHostModeUnsupported
	}
	//check container pid
	if c.pid == 0 {
		return nil, errZeroPidUnsupported
	}
	if c.parentNS != "" && !c.examIntface {
		return nil, errChildUnsupported
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	if c.quar || c.inline {
		newPairs, err := pipe.InterceptContainerPorts(c.pid, c.intcpPairs)
		if err != nil {
			log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to intercept port")
		}
		return newPairs, err
	} else {
		if restore {
			if driver == pipe.PIPE_NOTC {
				for _, pair := range c.intcpPairs {
					dp.DPCtrlDelPortPair(pair.ExPort(), pair.InPort())
				}
			}
			if dbgError := pipe.RestoreContainer(c.pid, c.intcpPairs); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		newPairs, err := pipe.InspectContainerPorts(c.pid, c.intcpPairs)
		if err != nil && !os.IsNotExist(err) {
			log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to inspect port")
		}
		return newPairs, err
	}
}

func programBridge(c *containerData) {
	if c.hostMode || !c.hasDatapath {
		return
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	if c.quar {
		for _, pair := range c.intcpPairs {
			pipe.ResetPortPair(c.pid, pair)
		}
		if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
			err := pipe.CreateNfqQuarRules(c.pid, true)
			if err != nil {
				log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to create quarantine iptable rules")
			}
		}
	} else if c.inline {
		for _, pair := range c.intcpPairs {
			pipe.FwdPortPair(c.pid, pair)
		}
		if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
			err := pipe.CreateNfqQuarRules(c.pid, false)
			if err != nil {
				log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to delete quarantine iptable rules")
			}
		}
	} else {
		if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
			err := pipe.CreateNfqQuarRules(c.pid, false)
			if err != nil {
				log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to delete quarantine iptable rules")
			}
		}
	}
}

func programNfqDP(c *containerData, cfgApp bool, macChangePairs map[string]*pipe.InterceptPair) {
	if c.hostMode || !c.hasDatapath {
		return
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	netns := global.SYS.GetNetNamespacePath(c.pid)

	macs := make([]string, len(c.intcpPairs))
	for i, pair := range c.intcpPairs {
		macs[i] = pair.MAC.String()
	}

	var oldMAC, pMAC net.HardwareAddr
	tap := false
	//pass containers IP to ep so that ingress/egress
	//direction can be decided by comparing src/dst ip
	//with container IP, nfq packet does not have l2 mac
	pAddrs := make([]net.IP, 0)
	for _, pair := range c.intcpPairs {
		for _, addr := range pair.Addrs {
			pAddrs = append(pAddrs, addr.IPNet.IP)
		}
	}
	if c.quar || c.inline {
		proxyMeshApp := getProxyMeshAppMap(c, true)
		jumboFrame := gInfo.jumboFrameMTU
		for idx, pair := range c.intcpPairs {
			if macChangePairs != nil {
				if oldPair, ok := macChangePairs[pair.Port]; ok {
					oldMAC = oldPair.MAC
				}
			}
			dp.DPCtrlDelTapPort(netns, pair.Port)
			dp.DPCtrlAddMAC(nvSvcPort, pair.MAC, pair.UCMAC, pair.BCMAC, oldMAC, pMAC, pAddrs)
			idx++
			if !c.nfq {
				err := pipe.CreateNfqRules(c.pid, idx, true, false, pair.Port, proxyMeshApp)
				if err != nil {
					log.WithFields(log.Fields{"container": c.id, "error": err}).Error("Failed to create nfq iptable rules")
				} else {
					c.nfq = true
					//create dp nfq handle
					dp.DPCtrlAddNfqPort(netns, pair.Port, idx, pair.MAC, &jumboFrame)
				}
			} else {
				if dbgError := pipe.CreateNfqRules(c.pid, idx, false, false, pair.Port, proxyMeshApp); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
				//create dp nfq handle
				dp.DPCtrlAddNfqPort(netns, pair.Port, idx, pair.MAC, &jumboFrame)
			}
		}
	} else {
		for _, pair := range c.intcpPairs {
			if macChangePairs != nil {
				if oldPair, ok := macChangePairs[pair.Port]; ok {
					oldMAC = oldPair.MAC
				}
			}
			dp.DPCtrlAddTapPort(netns, pair.Port, pair.MAC)
			dp.DPCtrlAddMAC(nvSvcPort, pair.MAC, pair.UCMAC, pair.BCMAC, oldMAC, pMAC, nil)
		}
		tap = true
	}
	if cfgApp {
		dp.DPCtrlConfigMAC(macs, &tap, c.appMap)
	} else {
		dp.DPCtrlConfigMAC(macs, &tap, nil)
	}
}

func programBridgeNoTc(c *containerData) {
	if c.hostMode || !c.hasDatapath {
		return
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	quar := c.quar
	for _, pair := range c.intcpPairs {
		dp.DPCtrlAddPortPair(pair.ExPort(), pair.InPort(), pair.MAC, &quar)
	}
}

func programDP(c *containerData, cfgApp bool, macChangePairs map[string]*pipe.InterceptPair) {
	if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
		programNfqDP(c, cfgApp, macChangePairs)
		return
	}

	if c.hostMode || !c.hasDatapath {
		return
	}

	log.WithFields(log.Fields{"container": c.id}).Debug("")

	netns := global.SYS.GetNetNamespacePath(c.pid)

	macs := make([]string, len(c.intcpPairs))
	for i, pair := range c.intcpPairs {
		macs[i] = pair.MAC.String()
	}

	var oldMAC, pMAC net.HardwareAddr
	tap := false
	quar := c.quar
	if c.quar || c.inline {
		for _, pair := range c.intcpPairs {
			if macChangePairs != nil {
				if oldPair, ok := macChangePairs[pair.Port]; ok {
					oldMAC = oldPair.MAC
				}
			}
			dp.DPCtrlDelTapPort(netns, pair.Port)
			dp.DPCtrlAddMAC(nvSvcPort, pair.MAC, pair.UCMAC, pair.BCMAC, oldMAC, pMAC, nil)
			if driver == pipe.PIPE_NOTC {
				dp.DPCtrlAddPortPair(pair.ExPort(), pair.InPort(), pair.MAC, &quar)
			}
		}
	} else {
		for _, pair := range c.intcpPairs {
			if macChangePairs != nil {
				if oldPair, ok := macChangePairs[pair.Port]; ok {
					oldMAC = oldPair.MAC
				}
			}
			dp.DPCtrlAddTapPort(netns, pair.Port, pair.MAC)
			dp.DPCtrlAddMAC(nvSvcPort, pair.MAC, pair.UCMAC, pair.BCMAC, oldMAC, pMAC, nil)
		}

		tap = true
	}
	if cfgApp {
		dp.DPCtrlConfigMAC(macs, &tap, c.appMap)
	} else {
		dp.DPCtrlConfigMAC(macs, &tap, nil)
	}
}

// //// Per container, not for a pod
// //// TODO: differentiate policy(s) from pod and its child container(s)
func applyProcessProfilePolicy(c *containerData, service string) {
	pg, ok := pe.ObtainProcessPolicy(service, c.id) // needs to be specific to each container
	if ok {
		// system containers will not enter block mode because of its (c.capBlock==false)
		c.blocking = (pg.Mode == share.PolicyModeEnforce)
		prober.HandleProcessPolicyChange(c.id, c.pid, pg, !c.pushPHistory, c.blocking && c.capBlock)
		c.pushPHistory = true
	} else {
		log.WithFields(log.Fields{"id": c.id}).Debug("PROC: process rules not ready")
	}
}

// ////
func examNeuVectorInterface(c *containerData, change int) {
	log.WithFields(log.Fields{"id": c.id, "name": c.name, "pid": c.pid}).Info()

	intcpPairs, err := pipe.InspectContainerPorts(c.pid, c.intcpPairs)
	if err != nil {
		return
	}

	var intfAdded, addrChanged bool

	gInfoLock()

	for _, pairOld := range c.intcpPairs {
		for _, pairNew := range intcpPairs {
			if pairOld.Port == pairNew.Port {
				if len(pairOld.Addrs) != len(pairNew.Addrs) {
					addrChanged = true
				}
				break
			}
		}
	}

	if len(c.intcpPairs) != len(intcpPairs) {
		intfAdded = true
	}

	// When changing between tap and inline, UC/BCMAC, in/exPort all changed. =>
	// Always take the new copy and set the scope again
	c.intcpPairs = intcpPairs
	setIPAddrScope(c)

	gInfoUnlock()

	if change == changeInit || intfAdded || addrChanged {
		log.WithFields(log.Fields{"id": c.id, "name": c.name, "pid": c.pid}).Info("Send interface update")

		var ev ClusterEvent
		if change == changeInit {
			capSniff := false
			ev = ClusterEvent{
				event: EV_ADD_CONTAINER, id: c.id, info: c.info,
				service: &c.service, domain: &c.domain, role: &c.role,
				inline: &c.inline, quar: &c.quar, shareNetNS: &c.parentNS,
				capIntcp: &c.capIntcp, capSniff: &capSniff,
			}
		} else {
			ev = ClusterEvent{
				event: EV_UPDATE_CONTAINER, id: c.id,
			}
		}

		ev.ifaces = intcpPairs2Ifaces(c.intcpPairs)
		ClusterEventChan <- &ev
	}
}

func isNeuvectorContainerById(id string) (string, bool) {
	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		return c.nvRole, true
	}
	return "", false
}

// oc49 and above: pod process is none on the cri-o
func isEmptyProcessPod(info *container.ContainerMetaExtra) bool {
	if global.RT.String() == container.RuntimeCriO {
		return (info.Pid == 0) && info.ID == info.Sandbox
	}
	return false
}

// ////
func startNeuVectorMonitors(id, role string, info *container.ContainerMetaExtra) {
	log.WithFields(log.Fields{"id": id, "name": info.Name, "role": role, "pid": info.Pid}).Info()

	// log.WithFields(log.Fields{"container": info}).Debug("PROC:")
	if _, ok := isNeuvectorContainerById(id); ok { // existed and ignore it
		return
	}

	c := &containerData{
		id:             id,
		name:           info.Name,
		pid:            info.Pid,
		info:           info,
		role:           container.PlatformContainerNeuVector,
		intcpPairs:     make([]*pipe.InterceptPair, 0),
		appMap:         make(map[share.CLUSProtoPort]*share.CLUSApp),
		portMap:        info.MappedPorts,
		pods:           utils.NewSet(),
		ownListenPorts: utils.NewSet(),
		capBlock:       true, // intentional for process monitor
		nvRole:         role,
	}

	// Because activePid2ID doesn't have neuvector container in it, we cannot always get
	// the parent container id, but the isChild flag is correct.
	isChild, parent_cid := global.RT.GetParent(info, gInfo.activePid2ID)

	// svc:
	// (1) native runtime env.: name of the image
	// (2) k8s: namespace + name in the metadata section of its YAML
	//          like controller =>  "neuvector (Domain/Namespace) + neuvector-controller-pod (Name)""
	svc := global.ORCH.GetService(&info.ContainerMeta, Host.Name)
	c.service = utils.MakeServiceName(svc.Domain, svc.Name)
	c.domain = svc.Domain
	group := makeLearnedGroupName(utils.NormalizeForURL(c.service))

	gInfoLock() // guarding from deleting old instance
	gInfo.allContainers.Add(id)
	gInfo.neuContainers[id] = c
	parent := gInfo.neuContainers[parent_cid]
	gInfoUnlock()

	// Send event to controller
	if !isChild {
		if c.pid != 0 {
			c.examIntface = true
			prober.StartMonitorInterface(c.id, c.pid, containerReexamIntfMax)
			examNeuVectorInterface(c, changeInit)
		}
	} else {
		if parent != nil && !parent.examIntface {
			parent.examIntface = true
			c.examIntface = true
			prober.StartMonitorInterface(c.id, c.pid, containerReexamIntfMax)
			examNeuVectorInterface(c, changeInit)
		}
	}

	// process monitor : protect mode, process profiles for all neuvector containers
	if agentEnv.containerShieldMode {
		prober.BuildProcessFamilyGroups(c.id, c.pid, false, info.Privileged, nil)
		// process killer per policy: removed by evaluating other same-kind instances
		// since the same policy might be shared by several same-kind instances in a node
		pe.InsertNeuvectorProcessProfilePolicy(group, role)

		// process blocker per container: can be removed by its container id
		// applyProcessProfilePolicy(c, group)
		c.upperDir, c.rootFs, _ = lookupContainerLayerPath(c.pid, c.id)
		prober.HandleAnchorNvProtectChange(true, c.id, c.upperDir, role, c.pid)
		// file monitors : protect mode, core-definitions, only modification alerts
		fileWatcher.ContainerCleanup(info.Pid, false)
		conf := &fsmon.FsmonConfig{Profile: &fsmon.DefaultContainerConf}

		switch role {
		case "enforcer", "controller+enforcer+manager", "controller+enforcer", "allinone", "controller", "manager":
			var filters []share.CLUSFileMonitorFilter
			for _, fltr := range conf.Profile.Filters {
				switch fltr.Path {
				case "/bin", "/sbin", "/usr/bin", "/usr/sbin": // apply blocking controls
				/*
					filters = append(filters, share.CLUSFileMonitorFilter{
						Behavior:    share.FileAccessBehaviorBlock,
						Path:        fltr.Path,
						Regex:       ".*",
						Recursive:   false,
						CustomerAdd: true,
					})
				*/
				default:
					filters = append(filters, fltr)
				}
			}

			if role != "manager" {
				filters = append(filters, share.CLUSFileMonitorFilter{
					Behavior: share.FileAccessBehaviorBlock, Path: "/usr/local/bin/scripts", Regex: ".*", Recursive: true, CustomerAdd: true,
				})
			}
			conf.Profile.Filters = filters // customized
		}

		conf.Profile.Filters = append(conf.Profile.Filters, share.CLUSFileMonitorFilter{
			Behavior: share.FileAccessBehaviorMonitor, Path: "/etc/neuvector/certs", Regex: ".*", Recursive: true, CustomerAdd: true,
		})
		conf.Profile.Mode = share.PolicyModeEnforce
		conf.Profile.Group = group
		if info.Pid != 0 {
			go fileWatcher.StartWatch(id, info.Pid, conf, true, true)
		}
	}

	nvRole := container.PlatformContainerNeuVector
	ev := ClusterEvent{event: EV_ADD_CONTAINER, id: id, info: info, role: &nvRole, service: &c.service, domain: &c.domain}
	ClusterEventChan <- &ev
}

// ////
func stopNeuVectorMonitor(c *containerData) {
	if c.pid != 0 && osutil.IsPidValid(c.pid) {
		// false-positive event from cri-o
		log.WithFields(log.Fields{"container": c.id, "pid": c.pid}).Debug("live rootPid")
		return
	}

	log.WithFields(log.Fields{"id": c.id, "pid": c.pid}).Info()

	// existed and clean its file/process monitors
	bFoundGroup := false
	group := makeLearnedGroupName(utils.NormalizeForURL(c.service))

	// Because activePid2ID doesn't have neuvector container in it, we cannot always get
	// the parent container id, but the isChild flag is correct.
	isChild, _ := global.RT.GetParent(c.info, gInfo.activePid2ID)

	// For stop and delete event, whoever is received first, delete the container from the map
	// and send both STOP and DEL event, because we only care when NeuVector container is running.

	c.info.Running = false

	// cloning it to avoid GC removing the allocated memory after deleting entry from its map
	info := c.info
	info.FinishedAt = c.info.FinishedAt
	if info.FinishedAt.IsZero() {
		// fabricate a reference time
		info.FinishedAt = time.Now().UTC()
	}

	gInfoLock() // guarding from adding new instance

	delete(gInfo.neuContainers, c.id)
	gInfo.allContainers.Remove(c.id)

	for _, cn := range gInfo.neuContainers {
		grp := makeLearnedGroupName(utils.NormalizeForURL(cn.service))
		if group == grp { // still has same-kind instances
			bFoundGroup = true
			break
		}
	}

	gInfoUnlock()

	if !bFoundGroup {
		log.WithFields(log.Fields{"group": group}).Debug("PROC:")
		pe.DeleteProcessPolicy(group)
	}

	prober.HandleAnchorNvProtectChange(false, c.id, c.upperDir, "", c.pid)
	log.WithFields(log.Fields{"id": c.id, "pid": c.pid}).Debug("FMON:")
	fileWatcher.ContainerCleanup(c.pid, true)

	// Send event to controller
	if !isChild {
		prober.StopMonitorInterface(c.id)

		ev := ClusterEvent{event: EV_STOP_CONTAINER, id: c.id, info: info}
		ClusterEventChan <- &ev
		ev = ClusterEvent{event: EV_DEL_CONTAINER, id: c.id}
		ClusterEventChan <- &ev
	}
}

func examNetworkInterface(c *containerData) bool {
	if c.examIntface {
		return false
	}

	c.examIntface = true
	prober.StartMonitorInterface(c.id, c.pid, containerReexamIntfMax)
	intfAdded, _, subnetChanged, _, err := programUpdatePairs(c, false)
	if err == nil {
		if intfAdded {
			programBridge(c)
			programDP(c, false, nil)
		}

		if subnetChanged {
			dp.DPCtrlConfigInternalSubnet(gInfo.internalSubnets)
		}
		return true
	}
	return false
}

func taskInterceptContainer(id string, info *container.ContainerMetaExtra) {
	c, ok := gInfoReadActiveContainer(id)
	if !ok {
		return
	}
	// There is a window between container added and intercepted. Time between these two events
	// can be quite long when there are a lot of containers up and down. if the container is
	// stopped and then restarted in this period, it's pid will change. Ignore the first
	// scheduled intercept event.
	if c.pid != info.Pid {
		log.WithFields(log.Fields{"container": id}).Debug("Container altered")
		return
	}

	// fill RunAsRoot flag
	if !isEmptyProcessPod(info) {
		if _, ppid, ruid, _ := osutil.GetProcessUIDs(info.Pid); ppid >= 0 {
			info.RunAsRoot = ruid == 0
		} else {
			if !osutil.IsPidValid(info.Pid) {
				log.WithFields(log.Fields{"pid": info.Pid, "id": id}).Error("rootPid exited")
				return // container already exited
			}
			log.WithFields(log.Fields{"pid": info.Pid, "id": id}).Error("Failed to obtain UID")
		}
	}
	c.info = info      // update
	c.pid = c.info.Pid // update
	log.WithFields(log.Fields{"container": id, "rootPid": c.info.Pid}).Debug("")
	// The order to call this function for parent and child container is not guaranteed, wait for the parent
	// if the child comes first
	// TODO: Why check parent.service? The order is not guaranteed even when parent exists, because it is added
	//       into activeContainers in AddContainer(). When we get here, the container must be running, and
	//       service value must not be empty if parent has called taskInterceptContainer(). This shouldn't
	//       create infinite loop if container exits quickly, above checks should prevent that.
	//       ==> Need to reconsider this sequence logics.
	isChild, parent := getSharedContainer(info)
	if isChild && (parent == nil || parent.service == "") {
		log.WithFields(log.Fields{"container": id}).Debug("Wait for parent")
		if err := scheduleTask(id, info, TASK_INTERCEPT_CONTAINER, containerWaitParentPeriod); err != nil {
			log.WithFields(log.Fields{"id": id, "info": info}).Error("reschedule failed. Container ignored!")
		}
		return
	}

	hostMode := isContainerNetHostMode(info, parent)
	fillContainerProperties(c, parent, info, hostMode)
	prober.BuildProcessFamilyGroups(c.id, c.pid, parent == nil, info.Privileged, c.healthCheck)
	prober.HandleAnchorModeChange(true, c.id, c.upperDir, c.pid)

	if parent == nil {
		if !hostMode && c.pid != 0 {
			examNetworkInterface(c)
		}
	} else {
		info.Sidecar = isSidecarContainer(info.Labels)
		if info.Sidecar {
			parent.info.ProxyMesh = true
		}
		if !hostMode && parent.pid == 0 && !info.Sidecar {
			if !parent.examIntface {
				parent.examIntface = true // only monitor one child container
				if examNetworkInterface(c) {
					notifyContainerChanges(c, parent, changeIntf)
				}
			}
		}

		if gInfo.tapProxymesh {
			if parent.pid != 0 {
				if info.Sidecar {
					programProxyMeshDP(parent, false, false)
				}
			} else if c.hasDatapath { //child that has datapath
				programProxyMeshDP(c, false, false)
			} else { //find child that has datapath
				for podID := range parent.pods.Iter() {
					if ch, ok := gInfoReadActiveContainer(podID.(string)); ok && ch.hasDatapath {
						programProxyMeshDP(ch, false, false)
						break
					}
				}
			}
		}
		gInfoLock()
		if gInfo.tapProxymesh {
			if parent.pid != 0 {
				if info.Sidecar {
					updateProxyMeshMac(parent, true)
				}
			} else if c.hasDatapath { //child that has datapath
				updateProxyMeshMac(c, true)
			} else { //find child that has datapath
				for podID := range parent.pods.Iter() {
					if ch, ok := gInfo.activeContainers[podID.(string)]; ok && ch.hasDatapath {
						updateProxyMeshMac(ch, true)
						break
					}
				}
			}
		}
		c.intcpPairs = parent.intcpPairs
		parent.pods.Add(id)
		gInfoUnlock()
	}
	// entry to apply group policies
	workloadJoinGroup(c, parent)
	updateAppPorts(c, parent)
	notifyContainerChanges(c, parent, changeInit)
}

func taskAddContainer(id string, info *container.ContainerMetaExtra) {
	// This can be invoked from Docker socket and probe.
	if _, ok := gInfoReadActiveContainer(id); ok {
		return
	}

	if info == nil || info.Pid == 0 {
		// Tasks from process monitor or scan-timer-loop
		var err error
		for i := 0; i < 2; i++ {
			if info, err = global.RT.GetContainer(id); err != nil {
				// Container: too early, container information is not ready, waiting for runtime API event
				log.WithFields(log.Fields{"id": id, "err": err}).Debug("container info not ready")
				return
			}

			if info.Pid != 0 {
				break
			}

			// 2nd chance because the container info are not ready yet
			time.Sleep(time.Millisecond * 50)
			// log.Debug("2nd chance")
		}
	}

	if !isEmptyProcessPod(info) {
		if !osutil.IsPidValid(info.Pid) {
			// however, the rootPid was left, an exited container
			// it could be a late event from the slow statsLoop()'s trigger
			log.WithFields(log.Fields{"id": id, "pid": info.Pid}).Debug("container left")
			info.Running = false // update it and put a cluster record for the exited container
		} else {
			// patch undetected container pid
			go prober.PatchContainerProcess(info.Pid, false)
		}
	}

	if role, ok := isNeuVectorContainer(info); ok {
		if info.Running {
			startNeuVectorMonitors(id, role, info)
		} else {
			if info.Pid != 0 {
				log.WithFields(log.Fields{"id": id, "role": role, "pid": info.Pid}).Debug("PROC: exited NeuVector")
			}
			// Sending notification to controller for NeuVector containers is to report
			// the interface list. No need if the container is not running
		}
		return
	}

	log.WithFields(log.Fields{"name": info.Name, "id": info.ID}).Info("")
	log.WithFields(log.Fields{"container": info}).Debug("")

	/*
		// Check if container is intermediate
		// Intermediate containers are createdy by "docker build".
		if strings.HasPrefix(info.ImageHash, "sha256:") {
			if danglings, err := global.RT.Client.ListDanglingImages(); err == nil {
				for _, img := range danglings {
					if info.Image == img.Id {
						log.WithFields(log.Fields{"image": img.Id}).Info("Skip container with dangling image")
						return
					}
				}

				// Check if image exists
				if _, err = global.RT.GetImage(info.Image); err != nil {
					log.WithFields(log.Fields{"error": err}).Info("Skip container with image error")
					return
				}
			} else {
				log.WithFields(log.Fields{"error": err}).Error("Failed to get dangling images")
			}
		}
	*/

	gInfoLock()
	gInfo.allContainers.Add(id)
	gInfoUnlock()

	if !info.Running {
		// service is not reported until container is running; domain should be filled.
		// it reports the exited container as well
		svc := global.ORCH.GetService(&info.ContainerMeta, Host.Name)
		service := utils.MakeServiceName(svc.Domain, svc.Name)
		ev := ClusterEvent{event: EV_ADD_CONTAINER, id: id, info: info, service: &service, domain: &svc.Domain}
		ClusterEventChan <- &ev

		log.Debug("Container not running")
		return
	}

	c := &containerData{
		id:             id,
		name:           info.Name,
		pid:            info.Pid,
		info:           info,
		intcpPairs:     make([]*pipe.InterceptPair, 0),
		appMap:         make(map[share.CLUSProtoPort]*share.CLUSApp),
		portMap:        info.MappedPorts,
		pods:           utils.NewSet(),
		ownListenPorts: utils.NewSet(),
		healthCheck:    info.Healthcheck,
	}
	gInfoLock()
	gInfo.activeContainers[id] = c
	gInfo.activePid2ID[c.pid] = id
	gInfoUnlock()

	if c.pid != 0 {
		bench.AddContainer(id, info.Name)
	}

	since := time.Since(info.StartedAt)
	if since < containerGracePeriod {
		// Set timer to recheck if we handle the workload early
		if err := scheduleTask(id, info, TASK_INTERCEPT_CONTAINER,
			containerGracePeriod); err != nil {
			log.WithFields(log.Fields{"id": id, "info": info}).Error("schedule intercept failed!")
			taskInterceptContainer(id, info)
		}
	} else {
		taskInterceptContainer(id, info)
	}
}

func delProgramNfqDP(c *containerData, ns string) {
	log.WithFields(log.Fields{"pid": c.pid}).Debug("")

	for _, pair := range c.intcpPairs {
		//delete dp nfq handle
		dp.DPCtrlDelNfqPort(ns, pair.Port)
	}

	//delete dp nfq handle if any then reset iptable rules
	if dbgError := pipe.DeleteNfqRules(c.pid); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	c.nfq = false
}

func taskStopContainer(id string, pid int) {
	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		stopNeuVectorMonitor(c)
		return
	}

	// containerd runtime report TaskExit for both process stop and container stop.
	// Here is to make sure the pid is container's pid
	c, ok := gInfoReadActiveContainer(id)
	if !ok || (pid != 0 && pid != c.pid) {
		return
	}

	log.WithFields(log.Fields{"container": c.id, "c.pid": c.pid, "pid": pid}).Info("")
	info, dbgErr := global.RT.GetContainer(id)
	if dbgErr != nil {
		log.WithFields(log.Fields{"id": id, "dbgErr": dbgErr}).Debug("Failed to read container. Use cached info.")
		info = c.info
		info.Running = false
	} else if info.Running {
		// docker will have a catchup event to show its Exit code
		if global.RT.String() == container.RuntimeDocker {
			return
		}
		if osutil.IsPidValid(info.Pid) && info.FinishedAt.IsZero() {
			// Wait for the updated container info
			// log.WithFields(log.Fields{"info": info}).Debug()
			return
		}
		info.Running = false // update
	}

	if info.FinishedAt.IsZero() {
		// fabricate a reference time
		info.FinishedAt = time.Now().UTC()
	}

	// Container might not be intercepted yet. This could be the first event.
	ev := ClusterEvent{event: EV_STOP_CONTAINER, id: id, info: info}
	ClusterEventChan <- &ev

	// entry to leave group policies
	workloadLeaveGroup(c)
	bench.RemoveContainer(id)
	prober.HandleAnchorModeChange(false, id, c.upperDir, 0)

	netns := global.SYS.GetNetNamespacePath(c.pid)
	if !c.hostMode && c.hasDatapath {
		// Stop monitor interface change before we reconnect the ports
		prober.StopMonitorInterface(id)

		if c.inline || c.quar {
			if driver != pipe.PIPE_CLM && !isMultiNetworkContainer(c) {
				if dbgError := pipe.CleanupContainer(c.pid, c.intcpPairs); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
			for _, pair := range c.intcpPairs {
				dp.DPCtrlDelMAC(nvSvcPort, pair.MAC)
				if driver == pipe.PIPE_NOTC {
					dp.DPCtrlDelPortPair(pair.ExPort(), pair.InPort())
				}
			}
		} else {
			for _, pair := range c.intcpPairs {
				dp.DPCtrlDelTapPort(netns, pair.Port)
				dp.DPCtrlDelMAC(nvSvcPort, pair.MAC)
			}
		}
		if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
			delProgramNfqDP(c, netns)
		}
		//POD with proxy injection
		if gInfo.tapProxymesh {
			programDelProxyMeshDP(c, netns)
		}
	}

	gInfoLock()
	if !c.hostMode && ((c.parentNS == "" && c.pid != 0) || (c.parentNS != "" && c.hasDatapath)) {
		for _, pair := range c.intcpPairs {
			delete(gInfo.macContainerMap, pair.MAC.String())
			delete(gInfo.macPortPairMap, pair.MAC.String())
		}
		//POD with proxy injection
		if gInfo.tapProxymesh {
			delProxyMeshMac(c, true)
		}
	}
	delete(gInfo.activeContainers, id)
	delete(gInfo.activePid2ID, c.pid)

	subnetUpdate := refreshLocalSubnets()

	pe.DeleteNetworkPolicy(id)

	gInfoUnlock()

	if dp.Connected() {
		if subnetUpdate {
			dp.DPCtrlConfigInternalSubnet(gInfo.internalSubnets)
		}
	}

	releaseSniffer(id)
}

func taskDelContainer(id string) {
	// If the container stop event is missed, call stop first.
	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		stopNeuVectorMonitor(c)
		return
	}

	if c, ok := gInfoReadActiveContainer(id); ok {
		if c.pid != 0 && osutil.IsPidValid(c.pid) {
			// false-positive event from cri-o
			log.WithFields(log.Fields{"container": id, "pid": c.pid}).Debug("live rootPid")
			return
		}
		taskStopContainer(id, 0)
	}

	removeContainerLayerPath(id)

	gInfoLock()
	gInfo.allContainers.Remove(id)
	delete(gInfo.containerConfig, id)
	gInfoUnlock()

	ev := ClusterEvent{event: EV_DEL_CONTAINER, id: id}
	ClusterEventChan <- &ev
}

func taskDPConnect() {
	log.Info()

	// Set debug as the first thing
	debug := &dp.DPDebug{Categories: gInfo.agentConfig.Debug}
	dp.DPCtrlConfigAgent(debug)

	dp.DPCtrlConfigInternalSubnet(gInfo.internalSubnets)
	dp.DPCtrlConfigSpecialIPSubnet(policy.SpecialSubnets)

	if driver != pipe.PIPE_NOTC && driver != pipe.PIPE_CLM {
		jumboFrame := gInfo.jumboFrameMTU
		dp.DPCtrlAddSrvcPort(nvSvcPort, &jumboFrame)
	}
	for _, c := range gInfo.activeContainers {
		programDP(c, true, nil)
		if gInfo.tapProxymesh {
			programProxyMeshDP(c, false, false)
			updateProxyMeshMac(c, false)
		}
		if c.hasDatapath {
			newnbe := false
			if onbe, ok := domainNBEMap[c.domain]; ok {
				newnbe = onbe
			}
			domainConfigNbeDp(c, newnbe)
		}
	}
	pe.PushFqdnInfoToDP()
	if !gInfo.disableNetPolicy {
		pe.PushNetworkPolicyToDP()
	}

	dp.DPCtrlRefreshApp()

	//dlp
	pe.PushNetworkDlpToDP()
	//set xff
	xffenabled := gInfo.xffEnabled
	dp.DPCtrlSetSysConf(&xffenabled)
	//set disableNetPolicy
	dnp := gInfo.disableNetPolicy
	dp.DPCtrlSetDisableNetPolicy(&dnp)
	//set detectUnmanagedWl
	duw := gInfo.detectUnmanagedWl
	dp.DPCtrlSetDetectUnmanagedWl(&duw)
	//set enableIcmpPolicy
	eip := gInfo.enableIcmpPolicy
	dp.DPCtrlSetEnableIcmpPolicy(&eip)
}

var nextNetworkPolicyVer *share.CLUSGroupIPPolicyVer // incoming network ploicy version
// gInfo write should only be done in this thread; and gInfo read doesn't need to be locked
// in this thread.
func containerTaskWorker(probeChan chan *probe.ProbeMessage, fsmonChan chan *fsmon.MonitorMessage, dpStatusChan chan bool) {
	log.Debug()
	var pnpTargetTick, ticks int
	nPolicyPullPeriod := agentEnv.netPolicyPuller
	calculationTicker := time.NewTicker(time.Second * 2)
	if nPolicyPullPeriod > 0 {
		log.WithFields(log.Fields{"netPolicyPuller": nPolicyPullPeriod}).Info()
		pnpTargetTick = 1          // minimum break
		if nPolicyPullPeriod > 0 { // valid period
			if nPolicyPullPeriod > 1 {
				pnpTargetTick = nPolicyPullPeriod / 2 // maximum, per 2 seconds
			}
		}
	} else {
		calculationTicker.Stop() // no timer
	}

	for {
		if shouldExit() {
			log.Info("Exit task worker")
			break
		}

		select {
		case <-calculationTicker.C:
			ticks++
			if ticks > pnpTargetTick {
				ticks = 0
				if nextNetworkPolicyVer != nil {
					if !systemUpdatePolicy(*nextNetworkPolicyVer) {
						ticks = pnpTargetTick // version changed? trigger a quick cycle
					}
				}
				nextNetworkPolicyVer = nil
			}
		case task := <-ContainerTaskChan:
			taskName := ContainerTaskName[task.task]
			log.WithFields(log.Fields{"task": taskName, "id": task.id}).Debug("Task received")

			switch task.task {
			case TASK_ADD_CONTAINER:
				taskAddContainer(task.id, task.info)
			case TASK_STOP_CONTAINER:
				taskStopContainer(task.id, task.pid)
			case TASK_DEL_CONTAINER:
				taskDelContainer(task.id)
			case TASK_CONFIG_CONTAINER:
				taskConfigContainer(task.id, task.macConf)
			case TASK_INTERCEPT_CONTAINER:
				taskInterceptContainer(task.id, task.info)
			case TASK_REEXAM_INTF_CONTAINER:
				taskReexamIntfContainer(task.id, task.info, false)
			case TASK_REEXAM_PROC_CONTAINER:
				taskReexamProcContainer(task.id, task.info)
			case TASK_APP_UPDATE_FROM_DP:
				taskAppUpdateByMAC(task.mac, task.apps)
			case TASK_CONFIG_AGENT:
				taskConfigAgent(task.agentConf)
			case TASK_CONFIG_SYSTEM:
				task.taskData.handler()
			case TASK_EXIT:
			}

			log.WithFields(log.Fields{"task": taskName, "id": task.id}).Debug("Task done")

		case pmsg := <-probeChan:
			msgName := probe.ProbeMsgName[pmsg.Type]
			log.WithFields(log.Fields{
				"msg": msgName, "containers": pmsg.ContainerIDs,
			}).Debug("Probe message received")

			switch pmsg.Type {
			case probe.PROBE_PROCESS_CHANGE:
				for id := range pmsg.ContainerIDs.Iter() {
					if !isAgentContainer(id.(string)) { // avoid to compare session id
						taskReexamProcContainer(id.(string), nil)
					}
				}
			case probe.PROBE_CONTAINER_START:
				sorted := sortProbeContainerByNetMode(pmsg.ContainerIDs)
				for _, info := range sorted {
					taskAddContainer(info.ID, info)
				}
			case probe.PROBE_CONTAINER_STOP:
				for id := range pmsg.ContainerIDs.Iter() {
					taskStopContainer(id.(string), 0)
				}
			case probe.PROBE_CONTAINER_NEW_IP:
				for id := range pmsg.ContainerIDs.Iter() {
					taskReexamIntfContainer(id.(string), nil, true)
				}
			case probe.PROBE_HOST_NEW_IP:
				taskReexamHostIntf()
			case probe.PROBE_REPORT_ESCALATION:
				reportIncident(escalToIncidentLog(pmsg.Escalation, pmsg.Count, pmsg.StartAt))
			case probe.PROBE_REPORT_SUSPICIOUS:
				reportIncident(suspicToIncidentLog(pmsg.Process, pmsg.Count, pmsg.StartAt))
			case probe.PROBE_REPORT_TUNNEL:
				reportIncident(tunnelToIncidentLog(pmsg.Process, pmsg.Count, pmsg.StartAt))
			case probe.PROBE_REPORT_PROCESS_VIOLATION:
				reportIncident(procViolationToIncidentLog(pmsg.Process, pmsg.Count, pmsg.StartAt))
			case probe.PROBE_REPORT_PROCESS_DENIED:
				reportIncident(procDeniedToIncidentLog(pmsg.Process, pmsg.Count, pmsg.StartAt))
			}

			log.WithFields(log.Fields{"msg": msgName}).Debug("Probe message done")

		case imsg := <-fsmonChan:
			//	log.WithFields(log.Fields{ "container": imsg.ID}).Debug("File system monitor message received")
			reportIncident(fileModifiedToIncidentLog(imsg))
		case connected := <-dpStatusChan:
			if connected {
				taskDPConnect()
			}
		}
	}

	containerTaskExit()

	containerTaskExitChan <- nil
}

func containerTaskExit() {
	// Make sure the function only called once
	if !atomic.CompareAndSwapInt32(&exitingTaskFlag, 0, 1) {
		return
	}

	// As we are exiting, try to push the ports back first
	for _, c := range gInfo.activeContainers {
		if c.hostMode || !c.hasDatapath {
			continue
		}

		prober.StopMonitorInterface(c.id)
		if c.inline || c.quar {
			if driver != pipe.PIPE_CLM && !isMultiNetworkContainer(c) {
				log.WithFields(log.Fields{"id": c.id}).Debug("Restore container")
				if dbgError := pipe.RestoreContainer(c.pid, c.intcpPairs); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
		}
	}
	// The following operations are optional
	for _, c := range gInfo.activeContainers {
		if c.pid == 0 {
			continue
		}
		netns := global.SYS.GetNetNamespacePath(c.pid)
		if c.inline || c.quar {
			for _, pair := range c.intcpPairs {
				dp.DPCtrlDelMAC(nvSvcPort, pair.MAC)
				if driver == pipe.PIPE_NOTC {
					dp.DPCtrlDelPortPair(pair.ExPort(), pair.InPort())
				}
			}
		} else {
			for _, pair := range c.intcpPairs {
				dp.DPCtrlDelTapPort(netns, pair.Port)
				dp.DPCtrlDelMAC(nvSvcPort, pair.MAC)
			}
		}
		if driver == pipe.PIPE_CLM || isMultiNetworkContainer(c) {
			delProgramNfqDP(c, netns)
		}
		//POD with proxy injection
		if gInfo.tapProxymesh {
			programDelProxyMeshDP(c, netns)
		}
	}
}

func eventMonitorLoop(probeChan chan *probe.ProbeMessage, fsmonChan chan *fsmon.MonitorMessage, dpStatusChan chan bool) {

	setContainerInterceptDelay()

	go containerTaskWorker(probeChan, fsmonChan, dpStatusChan)

	go func() {
		if err := global.RT.MonitorEvent(runtimeEventCallback, false); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Runtime: MonitorEvent Failed")
		}
	}()
}

func stopMonitorLoop() {
	log.Info("")

	// To trigger the select in containerTaskWorker
	if len(ContainerTaskChan) == 0 {
		task := ContainerTask{task: TASK_EXIT}
		ContainerTaskChan <- &task
	}

	global.RT.StopMonitorEvent()
}

func cbGetContainerPid(id string) int {
	// If it is our container, return a non-zero number, so it will not call all the time
	if isAgentContainer(id) {
		return Agent.Pid
	}

	if c, ok := gInfoReadActiveContainer(id); ok {
		return c.pid
	}
	return 0
}

func getContainerService(id string) (string, bool, bool) {
	if id == "" {
		return "nodes", true, false // allowed kill
	}

	if c, ok := gInfoReadActiveContainer(id); ok {
		return c.service, c.capBlock, false
	}

	if c, ok := gInfoReadNeuvectorContainer(id); ok {
		return c.service, c.capBlock, true
	}
	return "", false, false
}

// For debug only - not to expose.
func setContainerInterceptDelay() {
	delay := os.Getenv("CONTAINER_INTERCEPT_DELAY")
	if delay != "" {
		if d, err := strconv.ParseUint(delay, 10, 32); err == nil {
			containerGracePeriod = time.Duration(d) * time.Second
			log.WithFields(log.Fields{"delay": containerGracePeriod}).Info("Set intercept delay")
		} else {
			log.WithFields(log.Fields{"delay": delay}).Error("Fail to parse intercept delay")
		}
	}
}

func cbGetAllContainerList() utils.Set {
	gInfoRLock()
	defer gInfoRUnlock()
	return gInfo.allContainers.Clone()
}

func StartMonitorHostInterface(hid string, pid int, stopCh chan struct{}) {
	log.WithFields(log.Fields{"hostid": hid}).Debug("")
	dbgError := global.SYS.CallNetNamespaceFunc(pid, func(params interface{}) {
		intfHostMonitorLoop(hid, stopCh)
	}, nil)
	if dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func intfHostMonitorLoop(hid string, stopCh chan struct{}) {
	var err error
	chLink := make(chan netlink.LinkUpdate)
	doneLink := make(chan struct{})
	defer close(doneLink)

	if err = netlink.LinkSubscribe(chLink, doneLink); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Link change subscription failed")
	}

	chAddr := make(chan netlink.AddrUpdate)
	doneAddr := make(chan struct{})
	defer close(doneAddr)

	if err = netlink.AddrSubscribe(chAddr, doneAddr); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Address change subscription failed")
	}

	log.Debug("Start monitoring Host Interface changes...")

	// Set up a timer to call taskReexamHostIntf only once after 1 minute
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-stopCh:
			log.WithFields(log.Fields{"hostid": hid}).Debug("Monitor host i/f Stopped")
			return
		case updateLink := <-chLink:
			if updateLink.Link == nil || updateLink.Link.Attrs() == nil {
				continue
			}
			linkName := updateLink.Link.Attrs().Name
			curState := updateLink.Link.Attrs().OperState == netlink.OperUp
			if prevState, exists := gInfo.linkStates[linkName]; exists {
				if prevState == curState {
					continue
				}
			}
			taskReexamHostIntf()
		case updateAddr := <-chAddr:
			// only monitor ipv4 for now
			if utils.IsIPv4(updateAddr.LinkAddress.IP) {
				if updateAddr.NewAddr && gInfo.hostIPs.Contains(updateAddr.LinkAddress.IP.String()) {
					continue
				}
				// for all other conditions(includes address delete) re-exam host interface
				taskReexamHostIntf()
			}
		case <-timer.C:
			taskReexamHostIntf()
			timer.Stop()
		}
	}
}
