package cache

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type workloadDigest struct {
	ipnet   net.IPNet
	wlID    string
	port    uint16
	alive   bool
	managed bool   // IP of workload managed by enforcer
	orched  bool   // IP reported from orchestration, wlID maybe empty
	node    string // node name to decide unmanaged wl
}

type hostDigest struct {
	ipnet   net.IPNet
	hostID  string
	managed bool // IP of workload managed by enforcer
	orched  bool // IP reported from orchestration, wlID maybe empty
}

type hostCache struct {
	host         *share.CLUSHost
	agents       utils.Set
	workloads    utils.Set
	portWLMap    map[string]*workloadDigest
	ipWLMap      map[string]*workloadDigest
	wlSubnets    utils.Set          // host-scope subnet *net.IPNet, such as 172.17.0.0/16
	scanBrief    *api.RESTScanBrief // Stats of filtered entries
	state        string
	timerTask    string
	timerSched   time.Time
	runningPods  utils.Set
	runningCntrs utils.Set
}

type agentCache struct {
	agent        *share.CLUSAgent
	config       *share.CLUSAgentConfig
	joinAt       time.Time
	displayName  string
	selfHostname string
	state        string
	disconnAt    time.Time
	timerTask    string
}

type ctrlCache struct {
	ctrl        *share.CLUSController
	config      *share.CLUSControllerConfig
	joinAt      time.Time
	clusKey     string
	displayName string
	state       string
	disconnAt   time.Time
	timerTask   string
}

type workloadCache struct {
	workload         *share.CLUSWorkload
	config           *share.CLUSWorkloadConfig
	groups           utils.Set
	serviceName      string
	learnedGroupName string
	state            string
	platformRole     string
	displayName      string
	podName          string
	svcChanged       string // old learned group name
	serviceAccount   string
	scanBrief        *api.RESTScanBrief // Stats of filtered entries
	children         utils.Set
}

type workloadNames struct {
	name    string
	domain  string
	image   string
	service string
}

type workloadEphemeral struct {
	stop time.Time
	key  string
	wl   string
	host string
	isip bool
}

type k8sHostCache struct {
	id          string
	k8sNodeName string            // set when k8s node name is customized only(like IBM Cloud)
	labels      map[string]string // k8s node's labels
	annotations map[string]string // k8s node's annotations
}

// Wait 30m, some sessions are not terminated until timeout
const workloadEphemeralPeriod = time.Duration(time.Minute * 2)
const workloadEphemeralLife = time.Duration(time.Minute * 30)

// Within graphMutex, cacheMutex can be used; cacheMutex cannot embed graphMutex
var cacheMutex sync.RWMutex

func cacheMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	cacheMutex.Lock()
}

func cacheMutexUnlock() {
	cacheMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func cacheMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	cacheMutex.RLock()
}

func cacheMutexRUnlock() {
	cacheMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

var hostPlatform string
var hostCacheMap map[string]*hostCache = make(map[string]*hostCache)         // key is host id
var k8sHostInfoMap map[string]*k8sHostCache = make(map[string]*k8sHostCache) // key is the host name seen by enforcer. only used in k8s/oc env
var agentCacheMap map[string]*agentCache = make(map[string]*agentCache)
var ctrlCacheMap map[string]*ctrlCache = make(map[string]*ctrlCache)
var nvwlCacheMap map[string]*workloadCache = make(map[string]*workloadCache)
var wlCacheMap map[string]*workloadCache = make(map[string]*workloadCache)
var ipHostMap map[string]*hostDigest = make(map[string]*hostDigest)
var tunnelHostMap map[string]string = make(map[string]string)
var ipWLMap map[string]*workloadDigest = make(map[string]*workloadDigest)
var ipDevMap map[string]*workloadEphemeral = make(map[string]*workloadEphemeral)
var cachedInternalSubnets map[string]share.CLUSSubnet = make(map[string]share.CLUSSubnet)
var effectiveInternalSubnets map[string]share.CLUSSubnet = make(map[string]share.CLUSSubnet)
var cachedSpecialSubnets map[string]share.CLUSSpecSubnet = make(map[string]share.CLUSSpecSubnet)
var effectiveSpecialSubnets map[string]share.CLUSSpecSubnet = make(map[string]share.CLUSSpecSubnet)
var wlEphemeral []*workloadEphemeral
var nodePodSAMap map[string]map[string]string = make(map[string]map[string]string) // key is node name, value is map[workload id]{service account of the pod}

type Context struct {
	k8sVersion               string
	ocVersion                string
	RancherEP                string // from yaml/helm chart
	RancherSSO               bool   // from yaml/helm chart
	TelemetryFreq            uint   // from yaml
	CheckDefAdminFreq        uint   // from yaml, in minutes
	CspPauseInterval         uint   // from yaml, in minutes
	LocalDev                 *common.LocalDevice
	EvQueue                  cluster.ObjectQueueInterface
	AuditQueue               cluster.ObjectQueueInterface
	Messenger                cluster.MessengerInterface
	OrchChan                 chan *resource.Event
	TimerWheel               *utils.TimerWheel
	DebugCPath               bool
	Debug                    []string
	EnableRmNsGroups         bool
	EnableIcmpPolicy         bool
	ConnLog                  *log.Logger
	MutexLog                 *log.Logger
	ScanLog                  *log.Logger
	K8sResLog                *log.Logger
	CspType                  share.TCspType
	CtrlerVersion            string
	NvSemanticVersion        string
	StartStopFedPingPollFunc func(cmd, interval uint32, param1 interface{}) error
	RestConfigFunc           func(cmd, interval uint32, param1 interface{}, param2 interface{}) error
	CreateQuerySessionFunc   func(qsr *api.QuerySessionRequest) error
	DeleteQuerySessionFunc   func(queryToken string) error
	NotifyCertChange         func(cn string) error
}

type k8sProbeCmd struct {
	app  string
	path string
	cmds []string
}

type k8sPodEvent struct {
	pod      resource.Pod
	group    string        // group name, index
	groupAlt string        // likely group name
	probes   []k8sProbeCmd // k8s probe commands
	cleanAt  int64         // terminated time
}

var cctx *Context
var localDev *common.LocalDevice

var clusHelper kv.ClusterHelper
var cfgHelper kv.ConfigHelper
var dispatchHelper kv.DispatcherHelper
var evhdls eventHandlers
var admCtrlEvQueue cluster.ObjectQueueInterface

type CacheMethod struct {
	leadAddr        string
	isLeader        bool
	isScanner       bool
	leaderElectedAt time.Time
	disablePCAP     bool
	k8sPodEvents    map[string]*k8sPodEvent
	rmNsGrps        bool
}

var cacher CacheMethod

var exitingFlag int32
var policyApplyIngress bool

func shouldExit() bool {
	return (atomic.LoadInt32(&exitingFlag) != 0)
}

func hasLeader() bool {
	return cacher.leadAddr != ""
}

func isLeader() bool {
	return cacher.isLeader
}

func isScanner() bool {
	return cacher.isScanner
}

func ScannerChangeNotify(isScanner bool) {
	log.WithFields(log.Fields{"isScanner": isScanner}).Info()

	if cacher.isScanner != isScanner {
		autoScaleHistory = tAutoScaleHistory{}
	}
	cacher.isScanner = isScanner
	if isScanner {
		scanBecomeScanner()
	}
}

func LeadChangeNotify(isLeader bool, leadAddr string) {
	log.WithFields(log.Fields{"isLeader": isLeader, "leadAddr": leadAddr}).Info()

	cacher.isLeader = isLeader
	cacher.leadAddr = leadAddr

	resource.SetLeader(isLeader)

	if leadAddr != "" {
		cacher.leaderElectedAt = time.Now()
	}

	if !isLeader {
		return
	}

	// NVSHAS-7485: Here we are dealing a case that container's learned group cannot be created in version<=5.1.0
	// In pre-5.0 versions, the enforcer cannot derive some pods' learned group name correctly.
	// Although it is fixed in 5.0, during upgrade, the learned group with the correct name is not created.
	// Even we reboot the enforcer again, the correct learned group still fails to be created.
	// The reason being the controller regards the pod as running during enforcer upgrade, so when it is
	// reported to the controller by the new enforcer, the controller won't create new group. Even we fix
	// this login in the controller, because only the lead create learned group and the lead can be
	// the old controller, the group still cannot be created.
	// ==> Here we give the new controller a chance to refresh pods' learned group membership when it becomes
	// the lead.
	refreshLearnedGroupMembership()

	// When lead change, synchonize states in case operation was missed
	syncLeftNVObjectsToCluster()
	//NVSHAS-5914, During rolling upgrade remove the unmanaged workload
	//drawn on network activity canvas related to host/tunnel ip.
	cleanHostUnmanagedWorkload()

	// When recovering from a lead loss because controllers left ungracefully, the new lead
	// could be a fresh new controller. Should not sync the policy to the cluster.
	// syncLearnedPolicyToClusterWrapper()

	//NVSHAS-5234, for rolling upgrade need to recalculate
	//policy because internal workload id for "nodes" and
	//"fed.nodes" is changed from CLUSWLAddressGroup to
	//CLUSHostAddrGroup
	scheduleIPPolicyCalculation(false)
	scheduleDlpRuleCalculation(false)

	// NVSHAS-1890: when the lead transits during upgrade, we sometime saw dummy entries
	// Let's do a resync of node state on the lead as well (non-lead controller already did it)
	syncMemberStateFromCluster()
	// It's possible that not all hosts are read from the cluster yet. However, as this is to
	// schedule a key deletion, as loong as one controller does it, it will be fine.
	pruneHost()
	SchedulePruneGroups()

	if localDev.Host.Platform == share.PlatformKubernetes {
		cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, resource.NvAdmValidatingName, false)
	}
}

func FillControllerCounter(c *share.CLUSControllerCounter) {
	c.ScanTasks = uint32(scanScher.TaskCount())

	graphMutexRLock()
	c.GraphNodes = uint32(wlGraph.GetNodeCount())
	graphMutexRUnlock()
}

func deriveWorkloadState(cache *workloadCache) string {
	if cache.workload == nil {
		return api.WorkloadStateExit
	}

	wl := cache.workload
	if cache.state == api.StateUnmanaged {
		return api.WorkloadStateUnmanaged
	}
	if !wl.Running {
		return api.WorkloadStateExit
	}

	if cache.workload.Quarantine {
		return api.WorkloadStateQuarantine
	} else if cache.workload.Inline {
		return api.WorkloadStateProtect
	}

	mode, _ := getWorkloadPerGroupPolicyMode(cache)
	switch mode {
	case share.PolicyModeEvaluate:
		return api.WorkloadStateMonitor
	case share.PolicyModeEnforce:
		return api.WorkloadStateProtect
	default:
		return api.WorkloadStateDiscover
	}

	return api.WorkloadStateDiscover
}

func initHostCache(id string) *hostCache {
	return &hostCache{
		host:         &share.CLUSHost{ID: id},
		agents:       utils.NewSet(),
		workloads:    utils.NewSet(),
		wlSubnets:    utils.NewSet(),
		portWLMap:    make(map[string]*workloadDigest), // host port to workload ID and port
		ipWLMap:      make(map[string]*workloadDigest), // ip of host-scope to workload ID
		runningPods:  utils.NewSet(),
		runningCntrs: utils.NewSet(),
		state:        api.StateOnline,
	}
}

func isDummyHostCache(hc *hostCache) bool {
	return hc.host == nil || hc.host.Name == ""
}

func initAgentCache(id string) *agentCache {
	return &agentCache{
		agent:  &share.CLUSAgent{CLUSDevice: share.CLUSDevice{ID: id}},
		config: &share.CLUSAgentConfig{Debug: make([]string, 0)},
		state:  api.StateOnline,
	}
}

func isDummyAgentCache(ac *agentCache) bool {
	return ac.joinAt.IsZero()
}

func initCtrlCache(id string) *ctrlCache {
	return &ctrlCache{
		ctrl:   &share.CLUSController{CLUSDevice: share.CLUSDevice{ID: id}},
		config: &share.CLUSControllerConfig{Debug: make([]string, 0)},
		state:  api.StateOnline,
	}
}

func isDummyCtrlCache(cc *ctrlCache) bool {
	return cc.joinAt.IsZero()
}

func initWorkloadCache() *workloadCache {
	return &workloadCache{
		workload: &share.CLUSWorkload{},
		config:   &share.CLUSWorkloadConfig{Wire: share.WireDefault},
		groups:   utils.NewSet(),
		children: utils.NewSet(),
		state:    api.StateOnline,
	}
}

func isDummyWorkloadCache(wl *workloadCache) bool {
	return wl.workload.CreatedAt.IsZero()
}

func getHostCache(id string) *hostCache {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := hostCacheMap[id]; ok {
		return cache
	}
	return nil
}

func getWorkloadCache(id string) *workloadCache {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		return cache
	}
	return nil
}

func (m CacheMethod) CanAccessHost(id string, acc *access.AccessControl) error {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := hostCacheMap[id]; ok {
		if !acc.Authorize(cache.host, nil) {
			return common.ErrObjectAccessDenied
		}
		return nil
	}
	return common.ErrObjectNotFound
}

func (m CacheMethod) GetHost(id string, acc *access.AccessControl) (*api.RESTHost, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := hostCacheMap[id]; ok {
		if !acc.Authorize(cache.host, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		k8sCache, _ := k8sHostInfoMap[cache.host.Name]
		return host2REST(cache, k8sCache), nil
	}
	return nil, common.ErrObjectNotFound
}

func getHostName(id string) string {
	if id != "" {
		if cache := getHostCache(id); cache != nil {
			return cache.host.Name
		}
	}
	return ""
}

func getHostIDFromHostIP(hostIP net.IP) string {
	cacheMutexLock()
	defer cacheMutexUnlock()

	if hp, ok := ipHostMap[hostIP.String()]; ok {
		return hp.hostID
	}

	return ""
}

func isHostTunnelIP(ip net.IP) bool {
	cacheMutexLock()
	defer cacheMutexUnlock()

	_, ok := tunnelHostMap[ip.String()]
	return ok
}

func (m CacheMethod) GetController(id string, acc *access.AccessControl) *api.RESTController {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := ctrlCacheMap[id]; ok {
		if acc.Authorize(cache.ctrl, nil) {
			return ctrl2REST(cache)
		}
	}
	return nil
}

func getControllerName(id string) string {
	if id != "" {
		if cache := getControllerCache(id); cache != nil {
			return cache.displayName
		}
	}
	return ""
}

func getControllerCache(id string) *ctrlCache {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := ctrlCacheMap[id]; ok {
		return cache
	}
	return nil
}

func (m CacheMethod) GetAgent(id string, acc *access.AccessControl) *api.RESTAgent {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := agentCacheMap[id]; ok {
		if acc.Authorize(cache.agent, nil) {
			return agent2REST(cache)
		}
	}
	return nil
}

func getAgentName(id string) string {
	if id != "" {
		if cache := getAgentCache(id); cache != nil {
			return cache.displayName
		}
	}
	return ""
}

func getAgentNameNoLock(id string) string {
	if id != "" {
		if cache, _ := agentCacheMap[id]; cache != nil {
			return cache.displayName
		}
	}
	return ""
}

func getAgentCache(id string) *agentCache {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := agentCacheMap[id]; ok {
		return cache
	}
	return nil
}

func (m CacheMethod) GetAgentsbyHost(id string, acc *access.AccessControl) ([]string, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := hostCacheMap[id]; ok {
		if !acc.Authorize(cache.host, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return cache.agents.ToStringSlice(), nil
	}
	return nil, common.ErrObjectNotFound
}

func getNvName(id string) *workloadNames {
	// locked at upper calling function
	if cache, ok := agentCacheMap[id]; ok {
		names := &workloadNames{
			name:   cache.agent.Name,
			domain: cache.agent.Domain,
		}
		return names
	}

	if cache, ok := ctrlCacheMap[id]; ok {
		names := &workloadNames{
			name:   cache.ctrl.Name,
			domain: cache.ctrl.Domain,
		}
		return names
	}

	if cache, ok := nvwlCacheMap[id]; ok {
		wl := cache.workload
		names := &workloadNames{
			name:   cache.podName,
			domain: wl.Domain,
			image:  wl.Image,
		}
		return names
	}
	return nil
}

func (m CacheMethod) CanAccessWorkload(id string, acc *access.AccessControl) error {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return common.ErrObjectAccessDenied
		}
		return nil
	}
	return common.ErrObjectNotFound
}

func (m CacheMethod) GetWorkload(id string, view string, acc *access.AccessControl) (*api.RESTWorkload, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		wl := workload2REST(cache)
		switch view {
		case api.QueryValueViewPod:
			for child := range cache.children.Iter() {
				if childCache, ok := wlCacheMap[child.(string)]; ok {
					wl.Children = append(wl.Children, workload2REST(childCache))
				}
			}
			sort.Slice(wl.Children, func(i, j int) bool {
				return wl.Children[i].DisplayName < wl.Children[j].DisplayName
			})
		case api.QueryValueViewPodOnly:
		}

		return wl, nil
	}
	return nil, common.ErrObjectNotFound
}

func fakeWorkloadBrief(id string) *api.RESTWorkloadBrief {
	return &api.RESTWorkloadBrief{
		ID: id, Name: id, DisplayName: id, State: api.StateOnline,
	}
}

func getWorkloadBrief(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadBrief, error) {
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		wl := workload2BriefREST(cache)
		switch view {
		case api.QueryValueViewPod:
			for child := range cache.children.Iter() {
				if childCache, ok := wlCacheMap[child.(string)]; ok {
					wl.Children = append(wl.Children, workload2BriefREST(childCache))
				}
			}
			sort.Slice(wl.Children, func(i, j int) bool {
				return wl.Children[i].DisplayName < wl.Children[j].DisplayName
			})
		case api.QueryValueViewPodOnly:
		}

		return wl, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetWorkloadBrief(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadBrief, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	return getWorkloadBrief(id, view, acc)
}

func (m CacheMethod) GetWorkloadRisk(id string, acc *access.AccessControl) (*common.WorkloadRisk, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		wl := workload2Risk(cache, true)
		for child := range cache.children.Iter() {
			if childCache, ok := wlCacheMap[child.(string)]; ok {
				wl.Children = append(wl.Children, workload2Risk(childCache, true))
			}
		}

		return wl, nil
	}
	return nil, common.ErrObjectNotFound
}

/*
func (m CacheMethod) GetFakeWorkloadBrief(id string) *api.RESTWorkloadBrief {
	return fakeWorkloadBrief(id)
}
*/

func (m CacheMethod) GetWorkloadDetail(id string, view string, acc *access.AccessControl) (*api.RESTWorkloadDetail, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		wl := workload2DetailREST(cache)
		switch view {
		case api.QueryValueViewPod:
			for child := range cache.children.Iter() {
				if childCache, ok := wlCacheMap[child.(string)]; ok {
					wl.Children = append(wl.Children, workload2DetailREST(childCache))
				}
			}
			sort.Slice(wl.Children, func(i, j int) bool {
				return wl.Children[i].DisplayName < wl.Children[j].DisplayName
			})
		case api.QueryValueViewPodOnly:
		}

		return wl, nil
	}
	return nil, common.ErrObjectNotFound
}

func getWorkloadNameForLogging(id string) *workloadNames {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if id != "" {
		if cache, ok := wlCacheMap[id]; ok {
			wl := cache.workload
			names := &workloadNames{
				name:    cache.podName,
				domain:  wl.Domain,
				image:   wl.Image,
				service: cache.serviceName,
			}
			return names
		}
		if grpcache, ok := groupCacheMap[id]; ok {
			names := &workloadNames{
				name:   id,
				domain: grpcache.group.Domain,
			}
			// if id is service ip group name
			if strings.HasPrefix(id, api.LearnedSvcGroupPrefix) {
				names.service = id[len(api.LearnedSvcGroupPrefix):]
			} else {
				// UI relies on this field to show rule review button.
				// Workload group should not come here, so use the id directly.
				names.service = id
			}
			return names
		}
	}

	if nvName := getNvName(id); nvName != nil {
		return nvName
	}
	return &workloadNames{name: id}
}

func getCombinedThreatSeverity(wafseverity, dlpseverity, severity uint8) (string, string) {
	var tseverity uint8
	if wafseverity > dlpseverity {
		tseverity = wafseverity
	} else {
		tseverity = dlpseverity
	}
	if tseverity > severity {
		return common.SeverityString(tseverity)
	} else {
		return common.SeverityString(severity)
	}
}

func getCombinedThreatName(threatid, dlpid, wafid uint32) string {
	var dname, tname, wname string = "", "", ""

	if isDlpThreatID(dlpid) {
		dname, _, _ = getDlpThreatNameSensorGroup(dlpid)
	}
	if isWafThreatID(wafid) {
		wname, _, _ = getWafThreatNameSensorGroup(wafid)
	}
	tname = common.ThreatName(threatid)
	if dname == "" && tname == "" && wname == "" {
		return ""
	} else if dname == "" && tname == "" {
		return wname
	} else if dname == "" && wname == "" {
		return tname
	} else if tname == "" && wname == "" {
		return dname
	} else if dname == "" {
		return tname + "," + wname
	} else if tname == "" {
		return dname + "," + wname
	} else if wname == "" {
		return dname + "," + tname
	} else {
		return dname + "," + tname + "," + wname
	}
}

func isWafThreatID(id uint32) bool {
	if id >= uint32(api.MinWafRuleID) && id < uint32(api.MaxWafRuleID) {
		return true
	}
	return false
}

func isDlpThreatID(id uint32) bool {
	if id >= uint32(api.MinDlpRuleID) && id < uint32(api.MaxDlpPredefinedRuleID) {
		return true
	}
	return false
}

func getDlpThreatNameSensorGroup(id uint32) (string, string, *[]string) { //dlp threat name, sensor name, groups
	if id == 0 {
		return "", "", nil
	}

	rname, sname, grpname := cacher.GetDlpRuleSensorGroupById(id)
	if rname == "" {
		return fmt.Sprintf("%s#%v", common.DlpPrefix, id), sname, grpname
	} else {
		return fmt.Sprintf("%s%s.%s", common.DlpPrefix, sname, common.GetOrigDlpRuleName(rname)), sname, grpname
	}
}

func getWafThreatNameSensorGroup(id uint32) (string, string, *[]string) { //waf threat name, sensor name, groups
	if id == 0 {
		return "", "", nil
	}

	rname, sname, grpname := cacher.GetWafRuleSensorGroupById(id)
	if rname == "" {
		return fmt.Sprintf("%s#%v", common.WafPrefix, id), sname, grpname
	} else {
		return fmt.Sprintf("%s%s.%s", common.WafPrefix, sname, common.GetOrigWafRuleName(rname)), sname, grpname
	}
}

func getWorkloadDlpGrp(id string, grpname *[]string) string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	var gns string = ""
	if id != "" {
		if cache, ok := wlCacheMap[id]; ok {
			if grpname != nil {
				for _, gn := range *grpname {
					if cache.groups.Contains(gn) {
						if gns == "" {
							gns += gn
						} else {
							gns += "," + gn
						}
					}
				}
			}
		}
	}
	return gns
}

func mappedPortKey(ipproto uint8, port uint16) string {
	return fmt.Sprintf("%d/%d", ipproto, port)
}

func getAppFromWorkloadIPPort(id string, ipproto uint8, port uint16) (uint32, uint32) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := wlCacheMap[id]; ok {
		key := utils.GetPortLink(ipproto, port)
		if app, ok := cache.workload.Apps[key]; ok {
			if app.Application > 0 {
				return app.Application, app.Server
			} else {
				return app.Proto, app.Server
			}
		}
	}

	return 0, 0
}

func getWorkloadFromHostIDIPPort(id string, ipproto uint8, hostPort uint16) (string, uint16, bool) {
	// rlock might not be necessary, called by connectUpdate(), no one writes at the same time
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := hostCacheMap[id]; ok {
		key := mappedPortKey(ipproto, hostPort)
		if wlp, ok := cache.portWLMap[key]; ok {
			return wlp.wlID, wlp.port, wlp.alive
		}
	}

	return "", 0, false
}

func isWorkloadOnHost(ip net.IP, cache *hostCache) bool {
	for str := range cache.wlSubnets.Iter() {
		if _, subnet, err := net.ParseCIDR(str.(string)); err == nil {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// Return if IP on host, workload ID and if workload alive
func getWorkloadFromIPOnHost(ip net.IP, hostID string) (bool, string, bool) {
	// rlock might not be necessary, called by connectUpdate(), no one writes at the same time
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	cache, ok := hostCacheMap[hostID]
	if !ok {
		return false, "", false
	}

	if !isWorkloadOnHost(ip, cache) {
		return false, "", false
	}

	var wlp *workloadDigest
	if wlp, ok = cache.ipWLMap[ip.String()]; ok {
		return true, wlp.wlID, wlp.alive
	} else {
		return true, "", false
	}
}

func getWorkloadFromGlobalIP(ip net.IP) (string, bool) {
	// rlock might not be necessary, called by connectUpdate(), no one writes at the same time
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if wlp, ok := ipWLMap[ip.String()]; ok {
		return wlp.wlID, wlp.alive
	}
	return "", false
}

func getMappedPortFromWorkloadIPPort(id string, ipproto uint8, port uint16) uint16 {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := wlCacheMap[id]; ok {
		key := utils.GetPortLink(ipproto, port)
		if mp, ok := cache.workload.Ports[key]; ok {
			if mp.IPProto == ipproto && mp.Port == port {
				return mp.HostPort
			}
		}
	}
	return 0
}

func isDeviceIP(ip net.IP) bool {
	ipStr := ip.String()

	cacheMutexLock()
	defer cacheMutexUnlock()

	if dev, ok := ipDevMap[ipStr]; ok {
		if dev.stop.IsZero() {
			// running
			return true
		}
		if time.Since(dev.stop) < workloadEphemeralLife {
			return true
		} else {
			delete(ipDevMap, ipStr)
			log.WithFields(log.Fields{"ip": ipStr, "id": dev.wl}).Info("remove ip-device map")
			return false
		}
	}

	return false
}

/*
func isWorkloadSwarmService(id string) bool {
	cacheMutexLock()
	defer cacheMutexUnlock()

	if cache, ok := wlCacheMap[id]; ok {
		_, ok := cache.workload.Labels[utils.DockerSwarmServiceKey]
		return ok
	}
	return false
}
*/

func (m CacheMethod) GetWorkloadConfig(id string, acc *access.AccessControl) (*api.RESTWorkloadConfig, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		cfg := &api.RESTWorkloadConfig{
			Wire:       cache.config.Wire,
			Quarantine: cache.config.Quarantine,
			QuarReason: cache.config.QuarReason,
		}
		return cfg, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetControllerConfig(id string, acc *access.AccessControl) (*api.RESTControllerConfig, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := ctrlCacheMap[id]; ok {
		if !acc.Authorize(cache.ctrl, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		return &api.RESTControllerConfig{
			Debug:    &cache.config.Debug,
			LogLevel: &cache.config.LogLevel,
		}, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetControllerRPCEndpoint(id string, acc *access.AccessControl) (*common.RPCEndpoint, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := ctrlCacheMap[id]; ok {
		if !acc.Authorize(cache.ctrl, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		if !isDummyCtrlCache(cache) && cache.state == api.StateOnline {
			return &common.RPCEndpoint{ID: id, ClusterIP: cache.ctrl.ClusterIP, RPCServerPort: cache.ctrl.RPCServerPort}, nil
		}
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetAllControllerRPCEndpoints(acc *access.AccessControl) []*common.RPCEndpoint {
	eps := make([]*common.RPCEndpoint, 0)

	cacheMutexRLock()
	defer cacheMutexRUnlock()
	for id, cache := range ctrlCacheMap {
		if !acc.Authorize(cache.ctrl, nil) {
			continue
		}

		if !isDummyCtrlCache(cache) && cache.state == api.StateOnline {
			eps = append(eps, &common.RPCEndpoint{
				ID: id, Leader: cache.ctrl.Leader,
				ClusterIP: cache.ctrl.ClusterIP, RPCServerPort: cache.ctrl.RPCServerPort,
			})
		}
	}

	return eps
}

func (m CacheMethod) GetPlatform() (string, string, string) {
	// Host in localDev can be set by orch connector, this logic can help us correctly identify platform type
	// in case agent cannot figure it out.
	if localDev.Host.Flavor == share.FlavorOpenShift || localDev.Host.Flavor == share.FlavorRancher {
		return getHostPlatform(share.PlatformKubernetes, localDev.Host.Flavor), cctx.k8sVersion, cctx.ocVersion
	}

	return hostPlatform, cctx.k8sVersion, cctx.ocVersion
}

func (m CacheMethod) GetAgentConfig(id string, acc *access.AccessControl) (*api.RESTAgentConfig, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := agentCacheMap[id]; ok {
		if !acc.Authorize(cache.agent, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		return &api.RESTAgentConfig{
			Debug:    &cache.config.Debug,
			LogLevel: &cache.config.LogLevel,
		}, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetAllHostsRisk(acc *access.AccessControl) []*common.WorkloadRisk {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	hosts := make([]*common.WorkloadRisk, 0, len(hostCacheMap))
	for _, cache := range hostCacheMap {
		if !acc.Authorize(cache.host, nil) || isDummyHostCache(cache) {
			continue
		}

		var baseOS string
		if cache.scanBrief != nil {
			baseOS = cache.scanBrief.BaseOS
		}
		pm, _ := getHostPolicyMode(cache)

		wr := &common.WorkloadRisk{
			ID:         cache.host.ID,
			Name:       cache.host.Name,
			BaseOS:     baseOS,
			PolicyMode: pm,
		}

		bench, err := db.GetBenchData(cache.host.ID)
		if err == nil {
			wr.CustomBenchValue = bench.CustomBenchValue
			wr.DockerBenchValue = bench.DockerBenchValue
			wr.MasterBenchValue = bench.MasterBenchValue
			wr.WorkerBenchValue = bench.WorkerBenchValue
		}
		hosts = append(hosts, wr)
	}
	return hosts
}

func (m CacheMethod) GetAllHosts(acc *access.AccessControl) []*api.RESTHost {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	hosts := make([]*api.RESTHost, 0, len(hostCacheMap))
	for _, cache := range hostCacheMap {
		if !acc.Authorize(cache.host, nil) || isDummyHostCache(cache) {
			continue
		}
		k8sCache, _ := k8sHostInfoMap[cache.host.Name]
		hosts = append(hosts, host2REST(cache, k8sCache))
	}
	return hosts
}

func getAllControllers() []*share.CLUSController {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ctrls := make([]*share.CLUSController, 0, len(ctrlCacheMap))
	for _, cache := range ctrlCacheMap {
		if isDummyCtrlCache(cache) {
			continue
		}

		ctrls = append(ctrls, cache.ctrl)
	}
	return ctrls
}

func (m CacheMethod) GetAllControllers(acc *access.AccessControl) []*api.RESTController {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ctrls := make([]*api.RESTController, 0, len(ctrlCacheMap))
	for _, cache := range ctrlCacheMap {
		if !acc.Authorize(cache.ctrl, nil) || isDummyCtrlCache(cache) {
			continue
		}

		ctrls = append(ctrls, ctrl2REST(cache))
	}
	return ctrls
}

func getAllAgents() []*share.CLUSAgent {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	agents := make([]*share.CLUSAgent, 0, len(agentCacheMap))
	for _, cache := range agentCacheMap {
		if isDummyAgentCache(cache) {
			continue
		}

		agents = append(agents, cache.agent)
	}
	return agents
}

func (m CacheMethod) GetAllAgents(acc *access.AccessControl) []*api.RESTAgent {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	agents := make([]*api.RESTAgent, 0, len(agentCacheMap))
	for _, cache := range agentCacheMap {
		if !acc.Authorize(cache.agent, nil) || isDummyAgentCache(cache) {
			continue
		}

		agents = append(agents, agent2REST(cache))
	}
	return agents
}

func (m CacheMethod) GetAllWorkloads(view string, acc *access.AccessControl, idlist utils.Set) []*api.RESTWorkload {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	wls := make([]*api.RESTWorkload, 0, len(wlCacheMap))

	switch view {
	case api.QueryValueViewPod:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if idlist.Cardinality() > 0 {
				if idlist.Contains(cache.workload.ID) == false {
					continue
				}
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2REST(cache)
				for child := range cache.children.Iter() {
					if childCache, ok := wlCacheMap[child.(string)]; ok {
						wl.Children = append(wl.Children, workload2REST(childCache))
					}
				}
				sort.Slice(wl.Children, func(i, j int) bool {
					return wl.Children[i].DisplayName < wl.Children[j].DisplayName
				})
				wls = append(wls, wl)
			}
		}
	case api.QueryValueViewPodOnly:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2REST(cache)
				wls = append(wls, wl)
			}
		}
	default:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			wls = append(wls, workload2REST(cache))
		}
	}
	return wls
}

func (m CacheMethod) GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	wls := make([]*api.RESTWorkloadBrief, 0, len(wlCacheMap))
	switch view {
	case api.QueryValueViewPod:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2BriefREST(cache)
				for child := range cache.children.Iter() {
					if childCache, ok := wlCacheMap[child.(string)]; ok {
						wl.Children = append(wl.Children, workload2BriefREST(childCache))
					}
				}
				sort.Slice(wl.Children, func(i, j int) bool {
					return wl.Children[i].DisplayName < wl.Children[j].DisplayName
				})
				wls = append(wls, wl)
			}
		}
	case api.QueryValueViewPodOnly:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2BriefREST(cache)
				wls = append(wls, wl)
			}
		}
	default:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			wls = append(wls, workload2BriefREST(cache))
		}
	}
	return wls
}

func (m CacheMethod) GetAllWorkloadsRisk(acc *access.AccessControl) []*common.WorkloadRisk {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	wls := make([]*common.WorkloadRisk, 0, len(wlCacheMap))
	for _, cache := range wlCacheMap {
		if !acc.Authorize(cache.workload, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(cache.workload) {
			continue
		}
		if !cache.workload.Running {
			continue
		}

		if cache.workload.ShareNetNS == "" {
			wl := workload2Risk(cache, true)
			for child := range cache.children.Iter() {
				if childCache, ok := wlCacheMap[child.(string)]; ok {
					wl.Children = append(wl.Children, workload2Risk(childCache, true))
				}
			}
			wls = append(wls, wl)
		}
	}
	return wls
}

func (m CacheMethod) GetAllWorkloadsDetail(view string, acc *access.AccessControl) []*api.RESTWorkloadDetail {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	wls := make([]*api.RESTWorkloadDetail, 0, len(wlCacheMap))
	switch view {
	case api.QueryValueViewPod:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2DetailREST(cache)
				for child := range cache.children.Iter() {
					if childCache, ok := wlCacheMap[child.(string)]; ok {
						wl.Children = append(wl.Children, workload2DetailREST(childCache))
					}
				}
				sort.Slice(wl.Children, func(i, j int) bool {
					return wl.Children[i].DisplayName < wl.Children[j].DisplayName
				})
				wls = append(wls, wl)
			}
		}
	case api.QueryValueViewPodOnly:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			if cache.workload.ShareNetNS == "" {
				wl := workload2DetailREST(cache)
				wls = append(wls, wl)
			}
		}
	default:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}

			wls = append(wls, workload2DetailREST(cache))
		}
	}
	return wls
}

func (m CacheMethod) GetHostCount(acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if acc.HasGlobalPermissions(share.PERM_INFRA_BASIC, 0) {
		return len(hostCacheMap)
	} else {
		var count int
		for _, cache := range hostCacheMap {
			if !acc.Authorize(cache.host, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetAgentCount(acc *access.AccessControl, state string) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if acc.HasGlobalPermissions(share.PERM_NV_RESOURCE, 0) && state == "" {
		return len(agentCacheMap)
	} else {
		var count int
		for _, cache := range agentCacheMap {
			if !acc.Authorize(cache.agent, nil) {
				continue
			}
			if state != "" && state != cache.state {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetControllerCount(acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if acc.HasGlobalPermissions(share.PERM_NV_RESOURCE, 0) {
		return len(ctrlCacheMap)
	} else {
		var count int
		for _, cache := range ctrlCacheMap {
			if !acc.Authorize(cache.ctrl, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetComponentVersions(acc *access.AccessControl) []string {
	vers := make([]string, 0)
	s := utils.NewSet()

	cacheMutexRLock()
	defer cacheMutexRUnlock()
	for _, cache := range ctrlCacheMap {
		if !acc.Authorize(cache.ctrl, nil) {
			continue
		}
		if !s.Contains(cache.ctrl.Ver) {
			vers = append(vers, cache.ctrl.Ver)
			s.Add(cache.ctrl.Ver)
		}
	}
	for _, cache := range agentCacheMap {
		if !acc.Authorize(cache.agent, nil) {
			continue
		}
		if !s.Contains(cache.agent.Ver) {
			vers = append(vers, cache.agent.Ver)
			s.Add(cache.agent.Ver)
		}
	}

	return vers
}

func (m CacheMethod) GetWorkloadCount(acc *access.AccessControl) (int, int, int) {
	var wl, runningWL, runningPod int

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	for _, cache := range wlCacheMap {
		if !acc.Authorize(cache.workload, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(cache.workload) {
			continue
		}

		wl++
		if cache.workload.Running {
			runningWL++
			if cache.workload.ShareNetNS == "" {
				runningPod++
			}
		}
	}

	return wl, runningWL, runningPod
}

func (m CacheMethod) GetWorkloadCountOnHost(hostID string, view string, acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := hostCacheMap[hostID]; ok {
		if !acc.Authorize(cache.host, nil) {
			return 0
		}

		var count int = 0
		for id := range cache.workloads.Iter() {
			if wlCache, ok := wlCacheMap[id.(string)]; ok {
				if !acc.Authorize(wlCache.workload, nil) {
					continue
				}
				if common.OEMIgnoreWorkload(wlCache.workload) {
					continue
				}

				switch view {
				case api.QueryValueViewPod, api.QueryValueViewPodOnly:
					if wlCache.workload.ShareNetNS == "" {
						count++
					}
				default:
					count++
				}
			}
		}
		return count
	}
	return 0
}

func (m CacheMethod) GetAgentbyWorkload(wlID string, acc *access.AccessControl) (string, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[wlID]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return "", common.ErrObjectAccessDenied
		}
		return cache.workload.AgentID, nil
	}
	return "", common.ErrObjectNotFound
}

func (m CacheMethod) GetIP2WorkloadMap(hostID string) []*api.RESTDebugIP2Workload {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if hostID == "" {
		l := make([]*api.RESTDebugIP2Workload, len(ipWLMap))
		i := 0
		for ip, wlp := range ipWLMap {
			if wlCache, ok := wlCacheMap[wlp.wlID]; ok {
				l[i] = &api.RESTDebugIP2Workload{IP: ip, Workload: workload2BriefREST(wlCache)}
			} else {
				l[i] = &api.RESTDebugIP2Workload{IP: ip, Workload: nil}
			}
			i++
		}

		for key, svc := range addr2SvcMap {
			l = append(l, &api.RESTDebugIP2Workload{IP: key, Workload: fakeWorkloadBrief(svc.group.Name)})
		}

		for key, _ := range tunnelHostMap {
			l = append(l, &api.RESTDebugIP2Workload{IP: key, Workload: &api.RESTWorkloadBrief{
				ID: api.EndpointIngress, Name: api.EndpointIngress, DisplayName: api.EndpointIngress,
			}})
		}

		return l
	} else if hostCache, ok := hostCacheMap[hostID]; ok {
		l := make([]*api.RESTDebugIP2Workload, len(hostCache.ipWLMap))
		i := 0
		for ip, wlp := range hostCache.ipWLMap {
			if wlCache, ok := wlCacheMap[wlp.wlID]; ok {
				l[i] = &api.RESTDebugIP2Workload{IP: ip, Workload: workload2BriefREST(wlCache)}
			} else {
				l[i] = &api.RESTDebugIP2Workload{IP: ip, Workload: nil}
			}
			i++
		}
		return l
	} else {
		return nil
	}
}

func (m CacheMethod) GetInternalSubnets() *api.RESTInternalSubnets {
	ret := &api.RESTInternalSubnets{
		ConfiguredInternalSubnets: systemConfigCache.InternalSubnets,
	}

	ret.LearnedInternalSubnets = make([]string, len(cachedInternalSubnets))
	var i int = 0
	for _, snet := range cachedInternalSubnets {
		ret.LearnedInternalSubnets[i] = snet.Subnet.String()
		i++
	}
	ret.EffectiveInternalSubnets = make([]string, len(effectiveInternalSubnets))
	i = 0
	for _, snet := range effectiveInternalSubnets {
		ret.EffectiveInternalSubnets[i] = snet.Subnet.String()
		i++
	}
	return ret
}

// Return "" if subnet is not found
func getIPAddrScope(ip net.IP) string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	// In case pod and host share the same network, subnet based check is not
	// reliable. Check the known endpoints first.
	if _, ok := ipHostMap[ip.String()]; ok {
		return share.CLUSIPAddrScopeNAT
	}
	if _, ok := ipWLMap[ip.String()]; ok {
		return share.CLUSIPAddrScopeGlobal
	}

	for _, subnet := range cachedInternalSubnets {
		if subnet.Subnet.Contains(ip) {
			return subnet.Scope
		}
	}
	for _, subnet := range systemConfigCache.InternalSubnets {
		if _, ipnet, err := net.ParseCIDR(subnet); err == nil {
			if ipnet.Contains(ip) {
				return share.CLUSIPAddrScopeGlobal
			}
		}
	}
	return ""
}

// --
// give enough time for all agent to settle
const unManagedWlProcDelayFast = time.Duration(time.Minute * 2)
const unManagedWlProcDelaySlow = time.Duration(time.Minute * 8)
const pruneKVPeriod = time.Duration(time.Minute * 30)
const pruneGroupPeriod = time.Duration(time.Minute * 1)
const rmEmptyGroupPeriod = time.Duration(time.Minute * 1)
const groupMetricCheckPeriod = time.Duration(time.Minute * 1)

var unManagedWlTimer *time.Timer

func startWorkerThread(ctx *Context) {
	ephemeralTicker := time.NewTicker(workloadEphemeralPeriod)
	emptyGrpTicker := time.NewTicker(rmEmptyGroupPeriod)
	scannerTicker := time.NewTicker(scannerCleanupPeriod)
	usageReportTicker := time.NewTicker(usageReportPeriod)
	unManagedWlTimer = time.NewTimer(unManagedWlProcDelaySlow)
	pruneTicker := time.NewTicker(pruneGroupPeriod)
	if !cacher.rmNsGrps {
		pruneTicker.Stop()
	}
	groupMetricCheckTicker := time.NewTicker(groupMetricCheckPeriod)

	wlSuspected := utils.NewSet() // supicious workload ids
	pruneKvTicker := time.NewTicker(pruneKVPeriod)
	pruneWorkloadKV(wlSuspected) // the first scan

	noTelemetry := false
	telemetryFreq := ctx.TelemetryFreq
	if telemetryFreq == 0 {
		noTelemetry = true
		telemetryFreq = 60
	}
	teleReportTicker := time.NewTicker(time.Duration(telemetryFreq) * time.Minute)

	unManagedWlTimer.Stop()

	if isLeader() {
		SchedulePruneGroups()
	}

	go func() {
		for {
			select {
			case <-usageReportTicker.C:
				if isLeader() {
					writeUsageReport()
				}
			case <-groupMetricCheckTicker.C:
				if isLeader() {
					CheckGroupMetric()
				}
			case <-teleReportTicker.C:
				if isLeader() {
					if !noTelemetry {
						if sendTelemetry, teleData := getTelemetryData(telemetryFreq); sendTelemetry {
							var param interface{} = &teleData
							cctx.StartStopFedPingPollFunc(share.ReportTelemetryData, 0, param)
						}
					}
					if ctx.CheckDefAdminFreq != 0 { // 0 means do not check default admin's password
						checkDefAdminPwd(ctx.CheckDefAdminFreq) // default to log event per-24 hours
					}

					masterCluster := cacher.GetFedMasterCluster(access.NewReaderAccessControl())
					ConfigCspUsages(false, false, cacher.GetFedMembershipRoleNoAuth(), masterCluster.ID)
				}
			case <-pruneTicker.C:
				pruneGroupsByNamespace()
			case <-emptyGrpTicker.C:
				rmEmptyGroupsFromCluster()
			case <-unManagedWlTimer.C:
				cacheMutexRLock()
				refreshInternalIPNet()
				cacheMutexRUnlock()
			case <-ephemeralTicker.C:
				cacheMutexLock()
				refreshuwl := timeoutEphemeralWorkload()
				if refreshuwl {
					refreshInternalIPNet()
				}
				cacheMutexUnlock()
			case <-pruneKvTicker.C:
				pruneWorkloadKV(wlSuspected)
			case <-scannerTicker.C:
				if isScanner() {
					// Remove stalled scanner
					cacheMutexRLock()
					for sid, cache := range scannerCacheMap {
						// For built-in scanner, remove if controller does not exists. (20220621: no build-in scanner any more)
						if cache.scanner.BuiltIn {
							// Sometimes, NVSHAS-4116, controller notifications are received very late, after
							// we already remove the scanners. Here is a work-around to wait at least the self
							// controller is reported
							if _, ok := ctrlCacheMap[localDev.Ctrler.ID]; ok {
								if _, ok = ctrlCacheMap[sid]; !ok {
									cache.errCount++
									if cache.errCount >= scannerClearnupErrorMax {
										log.WithFields(log.Fields{"scanner": sid}).Info("Remove stalled internal scanner")
										clusHelper.DeleteScanner(sid)
									}
								} else {
									cache.errCount = 0
								}
							}
						} else {
							// Ping external scanner, remove if no response after 3 tries.
							if err := rpc.Ping(sid, scannerClearnupTimeout); err != nil {
								log.WithFields(log.Fields{"scanner": sid, "error": err}).Error("Failed to ping scanner")
								cache.errCount++
								if cache.errCount >= scannerClearnupErrorMax {
									log.WithFields(log.Fields{"scanner": sid}).Info("Remove stalled external scanner")
									clusHelper.DeleteScanner(sid)
								}
							} else {
								cache.errCount = 0
							}
						}
					}
					autoscaleCfg := systemConfigCache.ScannerAutoscale
					cacheMutexRUnlock()

					taskCount := scan.RegTaskCount()
					taskCount = taskCount + scanScher.TaskCount()
					replicas := atomic.LoadUint32(&scannerReplicas)
					if (autoscaleCfg.Strategy != api.AutoScaleImmediate && autoscaleCfg.Strategy != api.AutoScaleDelayed) || (replicas == 0) ||
						(replicas <= autoscaleCfg.MinPods && taskCount == 0) || (replicas >= autoscaleCfg.MaxPods && taskCount > 0) {
						// no need to autoscale when:
						// 1. autoscale is not enabled
						// 2. scanner replicas is 0 (either scanner is not deployed or is manually set to 0 replicas)
						// 3. there is no task in the queue & the scanner count is the minimum configured value
						// 4. there is task in the queue & the scanner count is the maximum configured value
					} else {
						rescaleScanner(autoscaleCfg, replicas, taskCount)
					}
				}
			case ev := <-cctx.OrchChan:
				cctx.K8sResLog.WithFields(log.Fields{"event": ev.Event, "type": ev.ResourceType}).Debug("Event received")
				if shouldExit() {
					break
				}
				if ev.ResourceNew == nil && ev.ResourceOld == nil {
					break
				}
				switch ev.ResourceType {
				case resource.RscTypeNode:
					var n, o *resource.Node
					if ev.ResourceNew != nil {
						n = ev.ResourceNew.(*resource.Node)
					}
					if ev.ResourceOld != nil {
						o = ev.ResourceOld.(*resource.Node)
					}
					if n != nil {
						if o == nil {
							addrOrchHostAdd(n.IPNets)
							clusterUsage.nodes += 1
						} else {
							if ((o.IPNets == nil || len(o.IPNets) == 0) &&
								(n.IPNets != nil && len(n.IPNets) > 0)) ||
								(o.IPNets != nil && len(o.IPNets) > 0 &&
									n.IPNets != nil && len(n.IPNets) > 0 &&
									!reflect.DeepEqual(o.IPNets, n.IPNets)) {
								addrOrchHostAdd(n.IPNets)
							}
						}
					} else if o != nil {
						//new is nil and old is not nil
						addrOrchHostDelete(o.IPNets)
						connectOrchHostDelete(o.IPNets)
						if clusterUsage.nodes > 1 {
							clusterUsage.nodes -= 1
						}
					}
					if n != nil {
						cacheMutexLock()
						hostName := n.Name
						if n.IBMCloudWorkerID != "" {
							hostName = n.IBMCloudWorkerID // is like "kube-c40msj4d0tb4oeriggqg-atibmcluste-default-000001f1"
						}
						k8sCache, ok := k8sHostInfoMap[hostName]
						if !ok {
							k8sCache = &k8sHostCache{}
						}
						k8sCache.labels = n.Labels
						k8sCache.annotations = n.Annotations
						if n.IBMCloudWorkerID != "" {
							// special handling for IBM cloud: save the customized k8s node name which is IP (as in 2021/07/29)
							k8sCache.k8sNodeName = n.Name
						}
						k8sHostInfoMap[hostName] = k8sCache
						cacheMutexUnlock()
					} else {
						if o != nil {
							hostName := o.Name
							if o.IBMCloudWorkerID != "" {
								hostName = o.IBMCloudWorkerID
							}
							cacheMutexLock()
							delete(k8sHostInfoMap, hostName)
							cacheMutexUnlock()
						}
					}
				case resource.RscTypeNamespace:
					var n, o *resource.Namespace
					if ev.ResourceNew != nil {
						n = ev.ResourceNew.(*resource.Namespace)
					}
					if ev.ResourceOld != nil {
						o = ev.ResourceOld.(*resource.Namespace)
					}
					if isLeader() {
						if n != nil {
							// ignore neuvector domain
							if n.Name != localDev.Ctrler.Domain {
								domainAdd(n.Name, n.Labels)
							} else {
								// for the upgrade case
								domainDelete(n.Name)
							}
						} else if o != nil {
							domainDelete(o.Name)
						}
					}
					if n != nil {
						if skip := atomic.LoadUint32(&nvDeployDeleted); skip == 0 && isLeader() && admission.IsNsSelectorSupported() {
							admission.VerifyK8sNs(admStateCache.Enable, n.Name, n.Labels)
						}
					}
				case resource.RscTypePod:
					var n, o *resource.Pod
					if ev.ResourceNew != nil {
						n = ev.ResourceNew.(*resource.Pod)
					}
					if ev.ResourceOld != nil {
						o = ev.ResourceOld.(*resource.Pod)
					}

					// Assume IP doesn't change. Ignore host mode containers.
					if (o == nil || o.IPNet.IP == nil) && (n != nil && !n.HostNet && n.IPNet.IP != nil) {
						addrOrchWorkloadAdd(&n.IPNet, n.Node)
					} else if (n == nil || n.IPNet.IP == nil) && (o != nil && !o.HostNet && o.IPNet.IP != nil) {
						addrOrchWorkloadStop(&o.IPNet)
						connectOrchWorkloadDelete(&o.IPNet)
					}
					if n != nil {
						if o == nil { // create
							if !isNeuvectorContainerName(n.Name) {
								var probeCmds [][]string
								var bPrivileged bool
								for _, c := range n.Containers {
									if len(c.LivenessCmds) > 0 {
										probeCmds = append(probeCmds, c.LivenessCmds)
									}
									if len(c.ReadinessCmds) > 0 {
										probeCmds = append(probeCmds, c.ReadinessCmds)
									}
									if c.Privileged {
										bPrivileged = true
									}
								}
								if len(probeCmds) > 0 || bPrivileged {
									addK8sPodEvent(*n, probeCmds)
								}
							}

							queryK8sVer := false
							if localDev.Host.Flavor == share.FlavorOpenShift {
								if n.Domain == "openshift-apiserver" && strings.HasPrefix(n.Name, "apiserver-") {
									queryK8sVer = true
								}
							} else if n.Domain == "kube-system" {
								if strings.HasPrefix(n.Name, "kube-apiserver-") {
									queryK8sVer = true
								} else if strings.Index(cctx.k8sVersion, "-eks-") > 0 && strings.HasPrefix(n.Name, "kube-proxy-") {
									queryK8sVer = true
								} else if strings.Index(cctx.k8sVersion, "-gke.") > 0 && strings.HasPrefix(n.Name, "kube-dns-autoscaler-") {
									queryK8sVer = true
								}
							}
							if queryK8sVer {
								QueryK8sVersion()
							}
						}
						if n.SA != "" && len(n.ContainerIDs) > 0 {
							cacheMutexLock()
							for _, containerID := range n.ContainerIDs {
								if wl, ok := wlCacheMap[containerID]; ok {
									if wl.serviceAccount != n.SA {
										wl.serviceAccount = n.SA
										if wl.workload.ShareNetNS != "" {
											if parent, ok := wlCacheMap[wl.workload.ShareNetNS]; ok {
												parent.serviceAccount = n.SA
											}
										}
									}
								} else {
									var podSAMap map[string]string
									if podSAMap, _ = nodePodSAMap[n.Node]; podSAMap == nil {
										podSAMap = make(map[string]string, 1)
										nodePodSAMap[n.Node] = podSAMap
									}
									podSAMap[containerID] = n.SA
								}
							}
							cacheMutexUnlock()
						}
					} else if o != nil && n == nil { // delete
						cacheMutexLock()
						if podSAMap, ok := nodePodSAMap[o.Node]; podSAMap != nil {
							for _, containerID := range o.ContainerIDs {
								if _, ok = podSAMap[containerID]; ok {
									delete(podSAMap, containerID)
								}
							}
						}
						cacheMutexUnlock()
					}
				case resource.RscTypeService:
					if isLeader() {
						var n, o *resource.Service
						if ev.ResourceNew != nil {
							n = ev.ResourceNew.(*resource.Service)
						}
						if ev.ResourceOld != nil {
							o = ev.ResourceOld.(*resource.Service)
						}
						// IPs list can change. As long as new values are not empty, apply changes to group.
						if n != nil && n.IPs != nil && len(n.IPs) > 0 {
							createServiceIPGroup(n)
						} else if (n == nil || n.IPs == nil || len(n.IPs) == 0) && (o != nil && o.IPs != nil && len(o.IPs) > 0) {
							deleteServiceIPGroup(o.Domain, o.Name, 0) // 0 means we don't know the group's CfgType yet
						} else if (o != nil && (o.ExternalIPs == nil || len(o.ExternalIPs) == 0) &&
							(n != nil && n.ExternalIPs != nil && len(n.ExternalIPs) > 0)) ||
							(o != nil && o.ExternalIPs != nil && len(o.ExternalIPs) > 0 &&
								n != nil && (n.ExternalIPs == nil || len(n.ExternalIPs) == 0)) ||
							(o != nil && o.ExternalIPs != nil && len(o.ExternalIPs) > 0 &&
								n != nil && n.ExternalIPs != nil && len(n.ExternalIPs) > 0 &&
								!reflect.DeepEqual(o.ExternalIPs, n.ExternalIPs)) {
							// externalIP changes
							createServiceIPGroup(n)
						}

						if n == nil && o != nil && o.Name == resource.NvAdmSvcName {
							log.WithFields(log.Fields{"name": o.Name}).Warn("Critical service is deleted")
						}
					} else {
						//for non-lead, svcip->externalIP map also need to be updated
						//especially for rolling upgrade case
						var n *resource.Service
						if ev.ResourceNew != nil {
							n = ev.ResourceNew.(*resource.Service)
						}
						if n != nil && n.IPs != nil {
							createServiceIPGroup(n)
						}
					}
				case resource.RscTypeDeployment:
					var n, o *resource.Deployment
					if ev.ResourceNew != nil {
						n = ev.ResourceNew.(*resource.Deployment)
					} else if ev.ResourceOld != nil {
						o = ev.ResourceOld.(*resource.Deployment)
					}
					if n != nil {
						if n.Domain == resource.NvAdmSvcNamespace && n.Name == "neuvector-scanner-pod" {
							atomic.StoreUint32(&scannerReplicas, uint32(n.Replicas))
						}

						if o == nil && n.Name == "neuvector-csp-pod" {
							log.WithFields(log.Fields{"name": n.Name, "domain": n.Domain}).Info("detected")
						}
					} else if o != nil { // delete
						if o.Domain == resource.NvAdmSvcNamespace && o.Name == "neuvector-scanner-pod" {
							atomic.StoreUint32(&scannerReplicas, 0)
						}

						if o.Name == "neuvector-csp-pod" {
							log.WithFields(log.Fields{"name": o.Name, "domain": o.Domain}).Info("deleted")
						}
					}
				/*
						case resource.RscTypeMutatingWebhookConfiguration:
							var n, o *resource.AdmissionWebhookConfiguration
							if ev.ResourceNew != nil {
								n = ev.ResourceNew.(*resource.AdmissionWebhookConfiguration)
							}
							if ev.ResourceOld != nil {
								o = ev.ResourceOld.(*resource.AdmissionWebhookConfiguration)
							}
							refreshK8sAdminWebhookStateCache(o, n)
					case resource.RscTypeCrdNvGroundFwRule:
						var n, o *resource.NvGroundFwRule
						if ev.ResourceNew != nil {
							n = ev.ResourceNew.(*resource.NvGroundFwRule)
						}
						if ev.ResourceOld != nil {
							o = ev.ResourceOld.(*resource.NvGroundFwRule)
						}
						fmt.Println("old: ", o)
						fmt.Println("new: ", n)

				*/
				case resource.RscTypeValidatingWebhookConfiguration:
					if skip := atomic.LoadUint32(&nvDeployDeleted); skip > 0 {
						log.WithFields(log.Fields{"event": ev.Event, "type": ev.ResourceType}).Info("being deleted")
						return
					}
					var n, o *resource.AdmissionWebhookConfiguration
					if ev.ResourceNew != nil {
						n = ev.ResourceNew.(*resource.AdmissionWebhookConfiguration)
					}
					if ev.ResourceOld != nil {
						o = ev.ResourceOld.(*resource.AdmissionWebhookConfiguration)
					}
					refreshK8sAdminWebhookStateCache(o, n)
				}
			}
		}
	}()
}

// handler of K8s resource watcher calls cbResourceWatcher() which sends to orchObjChan/objChan
// [2021-02-15] CRD-related resource changes do not call this function.
//
//	If they need to in the future, re-work the calling of SyncAdmCtrlStateToK8s()
func refreshK8sAdminWebhookStateCache(oldConfig, newConfig *resource.AdmissionWebhookConfiguration) {
	updateDetected := false
	config := newConfig
	if oldConfig != nil && newConfig == nil {
		config = oldConfig
	}
	if config == nil {
		return
	}
	if oldConfig != nil && newConfig != nil {
		updateDetected = true
	}
	log.WithFields(log.Fields{"name": config.Name, "old": oldConfig, "new": newConfig}).Debug("ValidatingWebhookConfiguration is changed")
	if isLeader() && config.Name == resource.NvPruneValidatingName {
		// for manually fixing orphan crd groups only
		if oldConfig != nil && newConfig == nil {
			pruneOrphanGroups()
		}
	}
	if config.Name != resource.NvAdmValidatingName {
		return
	}

	if isLeader() {
		skip, err := cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, config.Name, updateDetected)
		if skip && err == nil {
			// meaning nv resource in k8s sync with nv's cluster status. do nothing
		} else if !skip {
			alog := share.CLUSEventLog{ReportedAt: time.Now().UTC()}
			if err == nil {
				alog.Event = share.CLUSEvAdmCtrlK8sConfigured
				alog.Msg = fmt.Sprintf("Admission control is re-configured because of mismatched Kubernetes resource configuration found (%s).", config.Name)
			} else {
				alog.Event = share.CLUSEvAdmCtrlK8sConfigFailed
				alog.Msg = fmt.Sprintf("Failed to re-configure admission control after mismatched Kubernetes resource configuration found (%s).", config.Name)
			}
			cctx.EvQueue.Append(&alog)
		}
	}
}

func Init(ctx *Context, leader bool, leadAddr, restoredFedRole string) CacheInterface {
	log.WithFields(log.Fields{"isLeader": leader, "leadAddr": leadAddr}).Info()

	cctx = ctx
	localDev = ctx.LocalDev
	cctx.k8sVersion, cctx.ocVersion = global.ORCH.GetVersion(false, false)
	cacher.isLeader = leader
	cacher.leadAddr = leadAddr
	cacher.k8sPodEvents = make(map[string]*k8sPodEvent)
	cacher.rmNsGrps = ctx.EnableRmNsGroups
	clusHelper = kv.GetClusterHelper()
	cfgHelper = kv.GetConfigHelper()
	dispatchHelper = kv.GetDispatchHelper()

	envParser := utils.NewEnvironParser(os.Environ())
	if _, ok := envParser.Value(share.ENV_DISABLE_PCAP); ok {
		cacher.disablePCAP = true
	}

	registerEventHandlers()

	policyApplyIngress = global.ORCH.ApplyPolicyAtIngress()

	// admissionRuleInit needs to be called before startWorkerThread so that
	// we know whether we need to modify namesapce for admCtrl's namespaceSelector feature before orch watcher starts
	admissionRuleInit()

	startWorkerThread(ctx) // timer and orch channel
	startPolicyThread()

	configIcmpPolicy(ctx)
	configInit()
	scanInit()

	crdInit()
	fedInit(restoredFedRole)
	// Keep license update at last. Data structure preparation should be done before this point,
	// license update will update the limit and could trigger actions
	licenseInit()
	ruleid.SetGetGroupWithoutLockFunc(getGroupWithoutLock)
	clusHelper.SetCtrlState(share.CLUSCtrlNodeAdmissionKey)
	automode_init(ctx)

	db.SetGetCVERecordFunc(GetCVERecord)
	db.SetGetCVEListFunc(ExtractVulAttributes)
	db.SetFillVulPackagesFunc(FillVulPackages)

	go ProcReportBkgSvc()
	go FileReportBkgSvc()
	return &cacher
}

func Close() {
	atomic.StoreInt32(&exitingFlag, 1)
}

func CacheEvent(ev share.TLogEvent, msg string) error {
	if isLeader() {
		log := share.CLUSEventLog{
			Event:          ev,
			ReportedAt:     time.Now().UTC(),
			ControllerID:   localDev.Ctrler.ID,
			ControllerName: localDev.Ctrler.Name,
			Msg:            msg,
		}
		cctx.EvQueue.Append(&log)
		if ev == share.CLUSEvK8sNvRBAC {
			cctx.EvQueue.Flush()
		}
	}

	return nil
}

func QueryK8sVersion() {
	if k8sVer, _ := global.ORCH.GetVersion(true, false); k8sVer != "" && k8sVer != cctx.k8sVersion {
		log.WithFields(log.Fields{"oldVer": cctx.k8sVersion, "newVer": k8sVer}).Info()
		cctx.k8sVersion = k8sVer
		resource.SetK8sVersion(k8sVer)
		scanMapDelete(common.ScanPlatformID)
		scanMapAdd(common.ScanPlatformID, "", nil, share.ScanObjectType_PLATFORM)
	}
}

// //// event handlers for enforcer's kv dispatcher
// node: HostID
func nodeLeaveDispatcher(node string, param interface{}) {
	dispatchHelper.NodeLeave(node, isLeader())
}

// name: group name
func customGroupDelete(name string, param interface{}) {
	if utils.IsCustomProfileGroup(name) {
		dispatchHelper.CustomGroupDelete(name, isLeader())
	}
}

func (m CacheMethod) IsGroupMember(name, id string) bool {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if groupCache, ok := groupCacheMap[name]; ok {
		if wlCache, ok := wlCacheMap[id]; ok {
			return share.IsGroupMember(groupCache.group, wlCache.workload, getDomainData(wlCache.workload.Domain))
		}
	}
	return true // unknown, but play safe here, it eventually flushed by other events
}

func (m CacheMethod) GetConfigKvData(key string) ([]byte, bool) {
	if backupKvStores != nil {
		return backupKvStores.GetBackupKvStore(key)
	}
	return nil, false
}

func lookupPurgeWorkloadEntries(keys []string, nIndex int, curr, suspected, confirm, updated utils.Set) []string {
	var removed []string
	for _, key := range keys {
		id := share.CLUSKeyNthToken(key, nIndex)
		if !strings.Contains(id, ":") { // filter out non-id case, like "nodeID"
			if !updated.Contains(id) { // allow one updated missing per round
				if !curr.Contains(id) {
					if suspected.Contains(id) {
						confirm.Add(id) // confirmed
						removed = append(removed, key)
					} else {
						suspected.Add(id)
						updated.Add(id) // mark this as missed and updated
					}
				}
			}
		}
	}
	return removed
}

func pruneWorkloadKV(suspected utils.Set) {
	ids := utils.NewSet()
	confirmed := utils.NewSet()
	updated := utils.NewSet() // allow one update per round

	cacheMutexRLock()
	for id, _ := range wlCacheMap {
		ids.Add(id)
		suspected.Remove(id) // remove the missing id
	}
	cacheMutexRUnlock()

	// Those keys are written at enforcers so they are not synchronized with the cacher
	// It is a slow process, it need a flag to mark the missing id(s)
	// Implement: continuous 2-strikes out method
	// When it is confirmed by next cycle, it relative keys are deleted

	// (1) bench reports: bench/<id>/report/<BenchType>
	keys, _ := cluster.GetKeys(share.CLUSBenchStore, "/") // middle element
	removed := lookupPurgeWorkloadEntries(keys, 1, ids, suspected, confirmed, updated)
	// log.WithFields(log.Fields{"keys": keys, "suspected": suspected}).Debug("bench reports")

	// (2) bench scan state: scan/state/bench/workload/<id>
	keys, _ = cluster.GetKeys(share.CLUSScanStateKey("bench/workload"), " ") // last element
	removed = append(removed, lookupPurgeWorkloadEntries(keys, 4, ids, suspected, confirmed, updated)...)
	// log.WithFields(log.Fields{"keys": keys, "confirmed": confirmed, "suspected": suspected}).Debug("bench wl state")

	// (3) auto scan reports: scan/data/report/workload/<id>
	keys, _ = cluster.GetKeys(fmt.Sprintf("%sreport/workload", share.CLUSScanDataStore), " ") // last element
	removed = append(removed, lookupPurgeWorkloadEntries(keys, 4, ids, suspected, confirmed, updated)...)
	// log.WithFields(log.Fields{"keys": keys, "confirmed": confirmed, "suspected": suspected}).Debug("auto scan reports")

	// (4) scan state records: scan/state/report/workload/<id>
	keys, _ = cluster.GetKeys(fmt.Sprintf("%sreport/workload", share.CLUSScanStateStore), " ") // last element
	removed = append(removed, lookupPurgeWorkloadEntries(keys, 4, ids, suspected, confirmed, updated)...)

	// remove confirmed ids from the missing ids and pass into the next round
	for id := range suspected.Iter() {
		if !updated.Contains(id) || confirmed.Contains(id) {
			// disappeared or need to be removed
			suspected.Remove(id)
		}
	}

	if isLeader() {
		// log.WithFields(log.Fields{"confirmed": confirmed, "suspected": suspected}).Debug()
		if len(removed) > 0 {
			// delete kv entries: transact is faster
			txn := cluster.Transact()
			for _, key := range removed {
				txn.DeleteTree(key)
			}
			txn.Apply()
			txn.Close()
			log.WithFields(log.Fields{"pruned": len(removed), "removed": removed}).Info()
		}
	}
}

func (m CacheMethod) GetAllWorkloadsID(acc *access.AccessControl) []string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	workloadIDs := make([]string, 0)
	for _, cache := range wlCacheMap {
		if !acc.Authorize(cache.workload, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(cache.workload) {
			continue
		}
		if !cache.workload.Running {
			continue
		}

		if cache.workload.ShareNetNS == "" {
			workloadIDs = append(workloadIDs, cache.workload.ID)
			for child := range cache.children.Iter() {
				if childCache, ok := wlCacheMap[child.(string)]; ok {
					workloadIDs = append(workloadIDs, childCache.workload.ID)
				}
			}
		}
	}
	return workloadIDs
}

func (m CacheMethod) GetAllHostsID(acc *access.AccessControl) []string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	hostIDs := make([]string, 0)
	for _, cache := range hostCacheMap {
		if !acc.Authorize(cache.host, nil) || isDummyHostCache(cache) {
			continue
		}

		hostIDs = append(hostIDs, cache.host.ID)
	}
	return hostIDs
}

func (m CacheMethod) GetPlatformID(acc *access.AccessControl) string {
	scanMutexRLock()
	defer scanMutexRUnlock()

	if acc.Authorize(&share.CLUSHost{}, nil) {
		if _, ok := scanMap[common.ScanPlatformID]; ok {
			return common.ScanPlatformID
		}
	}

	return ""
}

func GetCVERecord(name, dbKey, baseOS string) *db.DbVulAsset {
	cve := scanUtils.GetCVERecord(name, dbKey, baseOS)
	vul := &db.DbVulAsset{
		Severity:    cve.Severity,
		Description: cve.Description,
		Link:        cve.Link,
		Score:       int(cve.Score * 10),
		Vectors:     cve.Vectors,
		ScoreV3:     int(cve.ScoreV3 * 10),
		VectorsV3:   cve.VectorsV3,
		PublishedTS: cve.PublishedTS,
		LastModTS:   cve.LastModTS,
	}
	return vul
}
