package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	nvcrd "github.com/neuvector/neuvector/controller/nvk8sapi/neuvectorcrd"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
}
var Ctrler, parentCtrler share.CLUSController

type ctrlEnvInfo struct {
	startsAt       time.Time
	procDir        string
	cgroupMemory   string
	cgroupCPUAcct  string
	runInContainer bool
	debugCPath     bool
}

var ctrlEnv ctrlEnvInfo
var exitingFlag int32

var evqueue cluster.ObjectQueueInterface
var auditQueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var cacher cache.CacheInterface
var scanner scan.ScanInterface
var orchConnector orchConnInterface
var timerWheel *utils.TimerWheel

const statsInterval uint32 = 5
const controllerStartGapThreshold = time.Duration(time.Minute * 2)
const memoryRecyclePeriod uint32 = 10                     // minutes
const memControllerTopPeak uint64 = 4 * 512 * 1024 * 1024 // 2 GB (inc. allinone case)
const memSafeGap uint64 = 64 * 1024 * 1024                // 64 MB

// Unlike in enforcer, only read host IPs in host mode, so no need to enter host network namespace
func getHostModeHostIPs() {
	ifaces := global.SYS.GetGlobalAddrs(true)

	Ctrler.Ifaces = make(map[string][]share.CLUSIPAddr)
	for name, addrs := range ifaces {
		Ctrler.Ifaces[name] = []share.CLUSIPAddr{}
		for _, addr := range addrs {
			if utils.IsIPv4(addr.IP) {
				Ctrler.Ifaces[name] = append(Ctrler.Ifaces[name], share.CLUSIPAddr{
					IPNet: addr,
					Scope: share.CLUSIPAddrScopeNAT,
				})
			}
		}
	}
}

func getLocalInfo(selfID string, pid2ID map[int]string) error {
	host, err := global.RT.GetHost()
	if err != nil {
		return err
	}
	Host = *host
	Host.CgroupVersion = global.SYS.GetCgroupVersion()
	ctrlEnv.startsAt = time.Now().UTC()
	if ctrlEnv.runInContainer {
		dev, meta, err := global.RT.GetDevice(selfID)
		if err != nil {
			return err
		}
		Ctrler.CLUSDevice = *dev

		_, parent := global.RT.GetParent(meta, pid2ID)
		if parent != "" {
			dev, _, err = global.RT.GetDevice(parent)
			if err != nil {
				return err
			}
			parentCtrler.CLUSDevice = *dev
		}
	} else {
		Ctrler.ID = Host.ID
		Ctrler.Pid = os.Getpid()
		Ctrler.NetworkMode = "host"
		Ctrler.PidMode = "host"
		Ctrler.CreatedAt = time.Now()
		Ctrler.StartedAt = time.Now()
		getHostModeHostIPs()
	}
	Ctrler.HostID = Host.ID
	Ctrler.HostName = Host.Name
	Ctrler.Ver = Version

	ctrlEnv.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(0, "memory")
	ctrlEnv.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(0, "cpuacct")
	return nil
}

// A heuristic way to decide if this is a new cluster installation.
// This is called right after the controller joins the cluster. If this is
// the oldest controller or the oldest controller started not very long before,
// It's likely all controllers starts together and this is a new cluster.
func likelyNewCluster() bool {
	clusHelper := kv.GetClusterHelper()
	all := clusHelper.GetAllControllers()

	if len(all) <= 1 {
		return true
	}

	var oldest *share.CLUSController
	for _, c := range all {
		if oldest == nil || c.StartedAt.Before(oldest.StartedAt) {
			oldest = c
		}
	}

	log.WithFields(log.Fields{"oldest": oldest.ID}).Info()

	if oldest.ID == Ctrler.ID {
		return true
	}

	// If all controllers start within the reasonable duration, consider them
	// to be starting together
	if Ctrler.StartedAt.Sub(oldest.StartedAt) < controllerStartGapThreshold {
		return true
	}

	return false
}

func flushEventQueue() {
	evqueue.Flush()
	auditQueue.Flush()
	cacher.FlushAdmCtrlStats()
}

///
type localSystemInfo struct {
	mutex sync.Mutex
	stats share.ContainerStats
}

var gInfo localSystemInfo

func updateStats() {
	cpuSystem, _ := global.SYS.GetHostCPUUsage()
	mem, _ := global.SYS.GetContainerMemoryUsage(ctrlEnv.cgroupMemory)
	cpu, _ := global.SYS.GetContainerCPUUsage(ctrlEnv.cgroupCPUAcct)

	gInfo.mutex.Lock()
	system.UpdateStats(&gInfo.stats, mem, cpu, cpuSystem)
	gInfo.mutex.Unlock()
}

// utility functions for enforcer dispatcher
func isGroupMember(name, id string) bool {
	return cacher.IsGroupMember(name, id)
}

func getConfigKvData(key string) ([]byte, bool) {
	return cacher.GetConfigKvData(key)
}

// TODO: sidecar implementation might have two app pods
func adjustContainerPod(selfID string, containers []*container.ContainerMeta) string {
	for _, c := range containers {
		if v, ok := c.Labels["io.kubernetes.sandbox.id"]; ok {
			if v == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
				return c.ID
			}
		}
		if c.Sandbox != "" && c.Sandbox == selfID {
			log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
			return c.ID
		}
	}
	return selfID
}

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "CTL"})

	connLog := log.New()
	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	scanLog := log.New()
	scanLog.Out = os.Stdout
	scanLog.Level = log.InfoLevel
	scanLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	mutexLog := log.New()
	mutexLog.Out = os.Stdout
	mutexLog.Level = log.InfoLevel
	mutexLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// bootstrap := flag.Bool("b", false, "Bootstrap cluster")
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	debug := flag.Bool("d", false, "Enable control path debug")
	restPort := flag.Uint("p", api.DefaultControllerRESTAPIPort, "REST API server port")
	fedPort := flag.Uint("fed_port", 11443, "Fed REST API server port")
	rpcPort := flag.Uint("rpc_port", 0, "Cluster server RPC port")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	internalSubnets := flag.String("n", "", "Predefined internal subnets")
	persistConfig := flag.Bool("pc", false, "Persist configurations")
	admctrlPort := flag.Uint("admctrl_port", 20443, "Admission Webhook server port")
	crdvalidatectrlPort := flag.Uint("crdvalidatectrl_port", 30443, "general crd Webhook server port")
	pwdValidUnit := flag.Uint("pwd_valid_unit", 1440, "")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		scanLog.SetLevel(log.DebugLevel)
		ctrlEnv.debugCPath = true
	}
	if *join != "" {
		// Join addresses might not be all ready. Accept whatever input is, resolve them
		// when starting the cluster.
		joinAddr = *join
		log.WithFields(log.Fields{"join": joinAddr}).Info()
	}
	if *adv != "" {
		ips, err := utils.ResolveIP(*adv)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"advertise": *adv}).Error("Invalid adv address. Exit!")
			os.Exit(-2)
		}

		advAddr = ips[0].String()
		log.WithFields(log.Fields{"advertise": advAddr}).Info()
	}
	if *bind != "" {
		bindAddr = *bind
		log.WithFields(log.Fields{"bind": bindAddr}).Info()
	}
	if *restPort > 65535 || *fedPort > 65535 || *rpcPort > 65535 || *lanPort > 65535 {
		log.Error("Invalid port value. Exit!")
		os.Exit(-2)
	}

	// Set global objects at the very first
	platform, flavor, network, containers, err := global.SetGlobalObjects(*rtSock, resource.Register)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		os.Exit(-2)
	}

	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {
		k8sVer, ocVer := global.ORCH.GetVersion()
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer}).Info()
	}

	if _, err = global.ORCH.GetOEMVersion(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unsupported OEM platform. Exit!")
		os.Exit(-2)
	}

	var selfID string

	ctrlEnv.runInContainer = global.SYS.IsRunningInContainer()
	if ctrlEnv.runInContainer {
		selfID, _, err = global.SYS.GetSelfContainerID()
		if selfID == "" {
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes {
		selfID = adjustContainerPod(selfID, containers)
	}

	// Container port can be injected after container is up. Wait for at least one.
	pid2ID := make(map[int]string)
	for _, meta := range containers {
		if meta.Pid != 0 {
			pid2ID[meta.Pid] = meta.ID
		}
	}

	for {
		// Get local host and controller info
		if err = getLocalInfo(selfID, pid2ID); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get local device information")
			os.Exit(-2)
		}

		if len(Ctrler.Ifaces) > 0 {
			break
		}

		log.Info("Wait for local interface ...")
		time.Sleep(time.Second * 4)
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.Network = network
	Host.StorageDriver = global.RT.GetStorageDriver()

	Ctrler.Domain = global.ORCH.GetDomain(Ctrler.Labels)
	parentCtrler.Domain = global.ORCH.GetDomain(parentCtrler.Labels)
	resource.NvAdmSvcNamespace = Ctrler.Domain
	if platform == share.PlatformKubernetes {
		resource.AdjustAdmWebhookName()
	}

	// Assign controller interface/IP scope
	if ctrlEnv.runInContainer {
		networks, err := global.RT.ListNetworks()
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
			os.Exit(-2)
		}

		meta := container.ContainerMeta{
			ID:      Ctrler.ID,
			Name:    Ctrler.Name,
			NetMode: Ctrler.NetworkMode,
			Labels:  Ctrler.Labels,
		}
		global.ORCH.SetIPAddrScope(Ctrler.Ifaces, &meta, networks)
	}

	log.WithFields(log.Fields{"host": Host}).Info("")
	log.WithFields(log.Fields{"ctrler": Ctrler}).Info("")

	// Other objects
	timerWheel = utils.NewTimerWheel()
	timerWheel.Start()

	dev := &common.LocalDevice{
		Host:   &Host,
		Ctrler: &Ctrler,
	}

	eventLogKey := share.CLUSControllerEventLogKey(Host.ID, Ctrler.ID)
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	auditLogKey := share.CLUSAuditLogKey(Host.ID, Ctrler.ID)
	auditQueue = cluster.NewObjectQueue(auditLogKey, 128)
	messenger = cluster.NewMessenger(Host.ID, Ctrler.ID)

	kv.Init(Ctrler.ID, dev.Ctrler.Ver, Host.Platform, Host.Flavor, *persistConfig, isGroupMember, getConfigKvData)
	ruleid.Init()

	// Start cluster
	clusterCfg := &cluster.ClusterConfig{
		ID:            Ctrler.ID,
		Server:        true,
		Debug:         false,
		Ifaces:        Ctrler.Ifaces,
		JoinAddr:      joinAddr,
		AdvertiseAddr: advAddr,
		BindAddr:      bindAddr,
		RPCPort:       *rpcPort,
		LANPort:       *lanPort,
		DataCenter:    cluster.DefaultDataCenter,
		EnableDebug:   *debug,
	}
	self, lead, err := clusterStart(clusterCfg)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to start cluster. Exit!")
		os.Exit(-2)
	}

	Ctrler.Leader = (lead == self)
	Ctrler.ClusterIP = self
	if Ctrler.Leader {
		recordLeadChangeEvent(share.CLUSEvControllerLeadElect, lead, "")
	}

	// get grpc port before put controller info to cluster
	var grpcServer *cluster.GRPCServer
	if *grpcPort == 0 {
		*grpcPort = cluster.DefaultControllerGRPCPort
	}
	Ctrler.RPCServerPort = uint16(*grpcPort)

	ctlrPutLocalInfo()

	// In the normal cases, initial deployment, rolling upgrade, if the controller starts as the leader
	// it means this is the initial deployment case and it is the first controller; however, in the case
	// when 2 of 3 controllers are lost, it's possible one of two new controllers can be elected
	// as the lead.

	// Considerations:
	// - We trust the KV store can resolve the stored KV correctly and consistently;
	// - For the new controller as leader at startup (following logic), it's OK to restore the config
	// even there might be other controllers are much older.
	// - SyncInit() is to sync in-memory data, such as graph. Sync from the oldest controller. The new
	// lead should perform sync as well unless it's a new cluster installation.
	// - Wait until initial sync is done to start calculating policies. Policy calculation is based on
	// in-memory graph.
	// - When a controller becomes leader, it's OK to do a full backup, because backup is to copy data
	// from the KV store to the files.
	// - When a controller becomes leader, it should NOT sync policy from the memory to the KV store,
	// because we are not sure if graph is all synced. It doesn't seem necessary either.
	// - When the cluster leader is re-elected and there was a leader-loss for at least a short period, we
	// call CtrlFailRecovery(). Sync from the lead controller but only if it has run a while, this is
	// important because the new leader maybe just started and does not possess the graph data.

	isNewCluster := likelyNewCluster()

	log.WithFields(log.Fields{"ctrler": Ctrler, "lead": lead, "self": self, "new-cluster": isNewCluster}).Info()

	purgeFedRulesOnJoint := false
	if Ctrler.Leader {
		// See [NVSHAS-5490]:
		// clusterHelper.AcquireLock() may fail with error "failed to create session: Unexpected response code: 500 (Missing node registration)".
		// It indicates that the node is not yet registered in the catalog.
		// It's possibly because controller attempts to create a session immediately after starting Consul but actually Consul is not ready yet.
		// Even it's rare, we might need to allow Consul some time to initialize and sync the node registration to the catalog.
		clusHelper := kv.GetClusterHelper()
		for i := 0; i < 6; i++ {
			lock, err := clusHelper.AcquireLock(share.CLUSLockUpgradeKey, time.Duration(time.Second))
			if err != nil {
				log.WithFields(log.Fields{"i": i, "err": err}).Info("retry for session creation")
				time.Sleep(time.Second)
				continue
			}
			clusHelper.ReleaseLock(lock)
			break
		}

		// Initiate installation ID if the controller is the first, ignore if ID is already set.
		clusHelper.PutInstallationID()

		// Restore persistent config.
		// Calling restore is unnecessary if this is not a new cluster installation, but not a big issue,
		// assuming the PV should have the latest config.
		fedRole, _ := kv.GetConfigHelper().Restore()
		if fedRole == api.FedRoleJoint {
			// fed rules are not restored on joint cluster but there might be fed rules left in kv so
			// 	we need to clean up fed rules & revisions in kv
			// if not using persist storage, the returned fedRole is always empty string
			purgeFedRulesOnJoint = true
		}

		if *internalSubnets != "" {
			subnets := strings.Split(*internalSubnets, ",")
			for _, subnet := range subnets {
				if _, _, err := net.ParseCIDR(subnet); err != nil {
					log.WithFields(log.Fields{"subnet": subnet}).Error("Invalid format!")
					os.Exit(-2)
				}
			}
			cfg := common.DefaultSystemConfig
			cfg.InternalSubnets = subnets

			clusHelper.PutSystemConfigRev(&cfg, 0)
		}
	}

	// All controllers start at same time in a new cluster. Because the lead load the PV,
	// non-lead can get here first and upgrade the KV. The sequence is not correct.
	// So, for the new cluster, we only want the lead to upgrade the KV. In the rolling
	// upgrade case, (not new cluster), the new controller (not a lead) should upgrade
	// the KV so it can behave correctly. The old lead won't be affected, in theory.
	if Ctrler.Leader || !isNewCluster {
		kv.GetClusterHelper().UpgradeClusterKV()
		kv.GetClusterHelper().FixMissingClusterKV()
	}

	if Ctrler.Leader {
		kv.ValidateWebhookCert()
		setConfigLoaded()
	} else {
		// The lead can take some time to restore the PV. Synchronize here so when non-lead
		// read from the KV, such as policy list, it knows the data is complete.
		waitConfigLoaded(isNewCluster)
		kv.ValidateWebhookCert()
	}

	// pre-build compliance map
	scanUtils.GetComplianceMeta()

	// start orchestration connection.
	// orchConnector should be created before LeadChangeCb is registered.
	orchObjChan := make(chan *resource.Event, 32)
	orchScanChan := make(chan *resource.Event, 16)

	// Initialize cache
	// - Start policy learning thread and build learnedPolicyRuleWrapper from KV
	cctx := cache.Context{
		LocalDev:                 dev,
		EvQueue:                  evqueue,
		AuditQueue:               auditQueue,
		Messenger:                messenger,
		OrchChan:                 orchObjChan,
		TimerWheel:               timerWheel,
		DebugCPath:               ctrlEnv.debugCPath,
		ConnLog:                  connLog,
		MutexLog:                 mutexLog,
		ScanLog:                  scanLog,
		StartFedRestServerFunc:   rest.StartFedRestServer,
		StopFedRestServerFunc:    rest.StopFedRestServer,
		StartStopFedPingPollFunc: rest.StartStopFedPingPoll,
	}
	cacher = cache.Init(&cctx, Ctrler.Leader, lead)
	cache.ScannerChangeNotify(Ctrler.Leader)

	sctx := scan.Context{
		AuditQueue: auditQueue,
		ScanChan:   orchScanChan,
		TimerWheel: timerWheel,
		MutexLog:   mutexLog,
		ScanLog:    scanLog,
	}
	scanner = scan.Init(&sctx, Ctrler.Leader)
	scan.ScannerChangeNotify(Ctrler.Leader)

	if platform == share.PlatformKubernetes {
		// k8s rbac watcher won't know anything about non-existing resources
		resource.GetNvServiceAccount(cache.CacheEvent)

		clusterRoleErrors, clusterRoleBindingErrors, roleBindingErrors := resource.VerifyNvK8sRBAC(dev.Host.Flavor, true)
		if len(clusterRoleErrors) > 0 || len(clusterRoleBindingErrors) > 0 || len(roleBindingErrors) > 0 {
			msgs := clusterRoleErrors
			msgs = append(msgs, clusterRoleBindingErrors...)
			msgs = append(msgs, roleBindingErrors...)
			cache.CacheEvent(share.CLUSEvK8sNvRBAC, strings.Join(msgs, "\n"))
		}
	}

	// Orch connector should be started after cacher so the listeners are ready
	orchConnector = newOrchConnector(orchObjChan, orchScanChan, Ctrler.Leader)
	orchConnector.Start()

	// GRPC should be started after cacher as the handler are cache functions
	grpcServer, _ = startGRPCServer(uint16(*grpcPort))

	// init rest server context before listening KV object store, as federation server can be started from there.
	rctx := rest.Context{
		LocalDev:     dev,
		EvQueue:      evqueue,
		AuditQueue:   auditQueue,
		Messenger:    messenger,
		Cacher:       cacher,
		Scanner:      scanner,
		RESTPort:     *restPort,
		FedPort:      *fedPort,
		PwdValidUnit: *pwdValidUnit,
	}
	rest.InitContext(&rctx)

	// Registry cluster event handlers
	cluster.RegisterLeadChangeWatcher(leadChangeHandler, lead)
	cluster.RegisterNodeWatcher(ctlrMemberUpdateHandler)

	// Sync follows the lead so must be after leadChangeHandler registered.
	cache.SyncInit(isNewCluster)

	cluster.RegisterStoreWatcher(share.CLUSObjectStore, cache.ObjectUpdateHandler, false)
	cluster.RegisterStateWatcher(cache.ClusterMemberStateUpdateHandler)
	cluster.RegisterStoreWatcher(share.CLUSScannerStore, cache.ScannerUpdateHandler, false)
	cluster.RegisterStoreWatcher(share.CLUSScanStateStore, cache.ScanUpdateHandler, false)

	if m := kv.GetClusterHelper().GetFedMembership(); m != nil {
		access.UpdateUserRoleForFedRoleChange(m.FedRole)
	}

	// start rest server
	rest.LoadInitCfg(Ctrler.Leader) // Load config from ConfigMap

	nvcrd.Init(Ctrler.Leader)
	// To prevent crd webhookvalidating timeout need queue the crd and process later.
	go rest.CrdQueueProc()
	go rest.StartRESTServer()

	if platform == share.PlatformKubernetes {
		rest.LeadChangeNotify(Ctrler.Leader)
		if Ctrler.Leader {
			cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, resource.NvAdmValidatingName)
		}
		go rest.CleanupSessCfgCache()
		go rest.AdmissionRestServer(*admctrlPort, false, *debug)
		go rest.CrdValidateRestServer(*crdvalidatectrlPort, false, *debug)
	}

	go rest.FedPollingClient(Ctrler.Leader, purgeFedRulesOnJoint)

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	logController(share.CLUSEvControllerStart)
	logController(share.CLUSEvControllerJoin)

	go func() {
		var memStatsControllerResetMark uint64 = memControllerTopPeak - memSafeGap

		ticker := time.Tick(time.Second * time.Duration(5))
		memStatTicker := time.Tick(time.Minute * time.Duration(memoryRecyclePeriod))
		statsTicker := time.Tick(time.Second * time.Duration(statsInterval))

		if limit, err := global.SYS.GetContainerMemoryLimitUsage(ctrlEnv.cgroupMemory); err == nil {
			if limit/2 > memSafeGap {
				memStatsControllerResetMark = limit/2 - memSafeGap
			}
			log.WithFields(log.Fields{"Limit": limit, "Controlled_At": memStatsControllerResetMark}).Info("Memory Resource")
		}

		// for allinone and controller
		go global.SYS.MonitorMemoryPressureEvents(memStatsControllerResetMark, memoryPressureNotification)
		for {
			select {
			case <-ticker:
				// When cluster has no lead, write to the cluster fails silently
				if !clusterFailed {
					flushEventQueue()
				}
			case <-statsTicker:
				updateStats()
			case <-memStatTicker:
				global.SYS.ReCalculateMemoryMetrics(memStatsControllerResetMark)
			case <-c_sig:
				logController(share.CLUSEvControllerStop)
				flushEventQueue()
				done <- true
			}
		}
	}()

	<-done

	log.Info("Exiting ...")
	atomic.StoreInt32(&exitingFlag, 1)

	cache.Close()
	orchConnector.Close()
	ctrlDeleteLocalInfo()
	cluster.LeaveCluster(true)
	grpcServer.Stop()
}
