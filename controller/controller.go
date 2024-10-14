package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/healthz"
	"github.com/neuvector/neuvector/share/migration"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
}

// When accessing global Ctrler, Ctrler.OrchConnStatus and Ctrler.OrchConnLastError will be empty all the time.
// Use GetOrchConnStatus() instead.
var Ctrler, parentCtrler share.CLUSController

type ctrlEnvInfo struct {
	startsAt time.Time
	// procDir           string
	cgroupMemory      string
	cgroupCPUAcct     string
	runInContainer    bool
	debugCPath        bool
	customBenchmark   bool
	autoProfieCapture uint64
	memoryLimit       uint64
	peakMemoryUsage   uint64
	snapshotMemStep   uint64
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
var k8sResLog *log.Logger

const statsInterval uint32 = 5
const controllerStartGapThreshold = time.Duration(time.Minute * 2)
const memoryRecyclePeriod uint32 = 10                      // minutes
const memoryCheckPeriod uint32 = 5                         // minutes
const memControllerTopPeak uint64 = 6 * 1024 * 1024 * 1024 // 6 GB (inc. allinone case)

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
	all, err := clusHelper.GetAllControllers()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
	}

	if len(all) <= 1 {
		return true
	}

	var oldest *share.CLUSController
	ips := utils.NewSet()
	for _, c := range all {
		ips.Add(c.ClusterIP)
		if oldest == nil || c.StartedAt.Before(oldest.StartedAt) {
			oldest = c
		}
	}

	log.WithFields(log.Fields{"oldest": oldest.ID, "all": ips.ToStringSlice()}).Info()

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

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error
	debug := false
	debugLevel := make([]string, 0)

	log.SetOutput(os.Stdout)
	log.SetLevel(share.CLUSGetLogLevel(common.CtrlLogLevel))
	log.SetFormatter(&utils.LogFormatter{Module: "CTL"})

	connLog := log.New()
	connLog.Out = os.Stdout
	connLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
	connLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	scanLog := log.New()
	scanLog.Out = os.Stdout
	scanLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
	scanLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	mutexLog := log.New()
	mutexLog.Out = os.Stdout
	mutexLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
	mutexLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	k8sResLog = log.New()
	k8sResLog.Out = os.Stdout
	k8sResLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
	k8sResLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// bootstrap := flag.Bool("b", false, "Bootstrap cluster")
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	log_level := flag.String("log_level", share.LogLevel_Info, "Controller log level")
	debug_level := flag.String("v", "", "debug level")
	restPort := flag.Uint("p", api.DefaultControllerRESTAPIPort, "REST API server port")
	fedPort := flag.Uint("fed_port", 11443, "Fed REST API server port")
	rpcPort := flag.Uint("rpc_port", 0, "Cluster server RPC port")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	internalSubnets := flag.String("n", "", "Predefined internal subnets")
	persistConfig := flag.Bool("pc", false, "Persist configurations")
	searchRegistries := flag.String("search_registries", "", "Comma separated list of search registries for shortnames")
	admctrlPort := flag.Uint("admctrl_port", 20443, "Admission Webhook server port")
	crdvalidatectrlPort := flag.Uint("crdvalidatectrl_port", 30443, "general crd Webhook server port")
	pwdValidUnit := flag.Uint("pwd_valid_unit", 1440, "")
	rancherEP := flag.String("rancher_ep", "", "Rancher endpoint URL")
	rancherSSO := flag.Bool("rancher_sso", false, "Rancher SSO integration")
	teleNeuvectorEP := flag.String("telemetry_neuvector_ep", "", "")                   // for testing only
	teleCurrentVer := flag.String("telemetry_current_ver", "", "")                     // in the format {major}.{minor}.{patch}[-s{#}], for testing only
	telemetryFreq := flag.Uint("telemetry_freq", 60, "")                               // in minutes, for testing only
	noDefAdmin := flag.Bool("no_def_admin", false, "Do not create default admin user") // for new install only
	cspEnv := flag.String("csp_env", "", "")                                           // "" or "aws"
	cspPauseInterval := flag.Uint("csp_pause_interval", 240, "")                       // in minutes, for testing only
	noRmNsGrps := flag.Bool("no_rm_nsgroups", false, "Not to remove groups when namespace was deleted")
	en_icmp_pol := flag.Bool("en_icmp_policy", false, "Enable icmp policy learning")
	autoProfile := flag.Int("apc", 1, "Enable auto profile collection")
	custom_check_control := flag.String("cbench", share.CustomCheckControl_Disable, "Custom check control")
	flag.Parse()

	// default log_level is LogLevel_Info
	if *log_level != "" && *log_level != common.CtrlLogLevel {
		common.CtrlLogLevel = *log_level
		log.SetLevel(share.CLUSGetLogLevel(common.CtrlLogLevel))
		scanLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
		k8sResLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
		if *log_level == share.LogLevel_Debug {
			debug = true
			ctrlEnv.debugCPath = true
			debugLevel = []string{"cpath"}
		} else {
			connLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
			mutexLog.Level = share.CLUSGetLogLevel(common.CtrlLogLevel)
		}
	}
	if debug && *debug_level != "" {
		var validLevelSet utils.Set = utils.NewSet("conn", "mutex", "scan", "cluster", "k8s_monitor")
		splitLevels := strings.Split(*debug_level, " ")
		var validLevels []string
		for _, level := range splitLevels {
			level = strings.TrimSpace(level)
			if level == "all" {
				validLevels = append(validLevels, validLevelSet.ToStringSlice()...)
				break
			}
			if validLevelSet.Contains(level) {
				validLevels = append(validLevels, level)
			}
		}
		levels := utils.NewSetFromSliceKind(append(debugLevel, validLevels...))
		debugLevel = levels.ToStringSlice()
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
	ctrlEnv.autoProfieCapture = 1 // default
	if *autoProfile != 1 {
		if *autoProfile < 0 {
			ctrlEnv.autoProfieCapture = 0 // no auto profile
			log.WithFields(log.Fields{"auto-profile": *autoProfile}).Error("Invalid value, disable auto-profile")
		} else {
			ctrlEnv.autoProfieCapture = (uint64)(*autoProfile)
		}
		log.WithFields(log.Fields{"auto-profile": ctrlEnv.autoProfieCapture}).Info()
	}
	if *custom_check_control == share.CustomCheckControl_Loose || *custom_check_control == share.CustomCheckControl_Strict {
		ctrlEnv.customBenchmark = true
		log.WithFields(log.Fields{"custom_check_control": *custom_check_control}).Info("Enable custom benchmark")
	} else if *custom_check_control != share.CustomCheckControl_Disable {
		*custom_check_control = share.CustomCheckControl_Disable
	}

	// Set global objects at the very first
	platform, flavor, cloudPlatform, network, containers, err := global.SetGlobalObjects(*rtSock, resource.Register)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		if err == global.ErrEmptyContainerList {
			// Temporary get container list error
			// => exit the process but the container doesn't need to be restarted
			os.Exit(-1)
		}
		os.Exit(-2)
	}

	ocImageRegistered := false
	enableRmNsGrps := true
	log.WithFields(log.Fields{"cgroups": global.SYS.GetCgroupsVersion()}).Info()
	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {
		k8sVer, ocVer := global.ORCH.GetVersion(false, false)
		if flavor == "" && resource.IsRancherFlavor() {
			flavor = share.FlavorRancher
			global.ORCH.SetFlavor(flavor)
		} else if k8sVer != "" && ocVer == "" {
			if err := global.ORCH.RegisterResource(resource.RscTypeImage); err == nil {
				// Use ImageStream as an indication of OpenShift
				flavor = share.FlavorOpenShift
				global.ORCH.SetFlavor(flavor)
				ocImageRegistered = true
			}
		}
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer, "flavor": flavor}).Info()

		if *noRmNsGrps {
			log.Info("Remove groups when namespace was deleted")
			enableRmNsGrps = false
		}
	}

	enableIcmpPolicy := false
	if *en_icmp_pol {
		log.Info("Enable icmp policy learning")
		enableIcmpPolicy = true
	}

	if _, err = global.ORCH.GetOEMVersion(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unsupported OEM platform. Exit!")
		os.Exit(-2)
	}

	var selfID string

	ctrlEnv.runInContainer = global.SYS.IsRunningInContainer()
	if ctrlEnv.runInContainer {
		selfID = global.RT.GetSelfID()
		if selfID == "" {
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes && global.RT.String() != container.StubRtName {
		if selfID, err = global.IdentifyK8sContainerID(selfID); err != nil {
			log.WithFields(log.Fields{"selfID": selfID, "error": err}).Error("lookup")
		}
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

	if platform == share.PlatformKubernetes {
		if global.RT.String() == container.StubRtName {
			if err := amendStubRtInfo(); err != nil {
				log.WithFields(log.Fields{"error": err, "Ctrler": Ctrler}).Error("Failed to get local device information")
			}
		} else if Ctrler.HostName == "" { // non-privileged mode
			if err := amendNotPrivilegedMode(); err != nil {
				log.WithFields(log.Fields{"error": err, "Ctrler": Ctrler}).Error("Failed to get not-privileged information")
			}
		}
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.CloudPlatform = cloudPlatform
	Host.Network = network
	Host.StorageDriver = global.RT.GetStorageDriver()

	Ctrler.Domain = global.ORCH.GetDomain(Ctrler.Labels)
	parentCtrler.Domain = global.ORCH.GetDomain(parentCtrler.Labels)
	resource.NvAdmSvcNamespace = Ctrler.Domain

	cspType, _ := common.GetMappedCspType(cspEnv, nil)
	if cspType != share.CSP_NONE && cspType != share.CSP_EKS && cspType != share.CSP_AKS && cspType != share.CSP_GCP {
		cspType = share.CSP_NONE
	}
	if *cspPauseInterval == 0 {
		*cspPauseInterval = 240
	}

	if platform == share.PlatformKubernetes {
		resource.AdjustAdmWebhookName(cache.QueryK8sVersion, admission.VerifyK8sNs, cspType)
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

	log.WithFields(log.Fields{"host": Host}).Info()
	log.WithFields(log.Fields{"ctrler": Ctrler}).Info()

	// Other objects
	timerWheel = utils.NewTimerWheel()
	timerWheel.Start()

	dev := &common.LocalDevice{
		Host:   &Host,
		Ctrler: &Ctrler,
	}

	var grpcServer *cluster.GRPCServer
	var internalCertControllerCancel context.CancelFunc
	var ctx context.Context

	if os.Getenv("AUTO_INTERNAL_CERT") != "" {

		log.Info("start initializing k8s internal secret controller and wait for internal secret creation if it's not created")

		go func() {
			if err := healthz.StartHealthzServer(); err != nil {
				log.WithError(err).Warn("failed to start healthz server")
			}
		}()

		ctx, internalCertControllerCancel = context.WithCancel(context.Background())
		defer internalCertControllerCancel()
		// Initialize secrets.  Most of services are not running at this moment, so skip their reload functions.
		capable, err := migration.InitializeInternalSecretController(ctx, []func([]byte, []byte, []byte) error{
			// Reload consul
			func(cacert []byte, cert []byte, key []byte) error {
				log.Info("Reloading consul config")
				if err := cluster.Reload(nil); err != nil {
					return fmt.Errorf("failed to reload consul: %w", err)
				}

				return nil
			},
			// Reload grpc servers/clients
			func(cacert []byte, cert []byte, key []byte) error {
				log.Info("Reloading gRPC servers/clients")
				if err := cluster.ReloadInternalCert(); err != nil {
					return fmt.Errorf("failed to reload gRPC's certificate: %w", err)
				}
				return nil
			},
		})
		if err != nil {
			log.WithError(err).Error("failed to initialize internal secret controller")
			os.Exit(-2)
		}
		if capable {
			log.Info("internal certificate is initialized")
		} else {
			if os.Getenv("NO_FALLBACK") == "" {
				log.Warn("required permission is missing...fallback to the built-in certificate if it exists")
			} else {
				log.Error("required permission is missing...ending now")
				os.Exit(-2)
			}
		}
	}

	err = cluster.ReloadInternalCert()
	if err != nil {
		log.WithError(err).Fatal("failed to reload internal certificate")
	}

	eventLogKey := share.CLUSControllerEventLogKey(Host.ID, Ctrler.ID)
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	auditLogKey := share.CLUSAuditLogKey(Host.ID, Ctrler.ID)
	auditQueue = cluster.NewObjectQueue(auditLogKey, 128)
	messenger = cluster.NewMessenger(Host.ID, Ctrler.ID)

	db.CreateVulAssetDb(false)

	kv.Init(Ctrler.ID, dev.Ctrler.Ver, Host.Platform, Host.Flavor, *persistConfig, isGroupMember, getConfigKvData, evqueue)
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
		EnableDebug:   debug,
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
	if *grpcPort == 0 {
		*grpcPort = cluster.DefaultControllerGRPCPort
	}
	Ctrler.RPCServerPort = uint16(*grpcPort)

	// pre-build compliance map
	scanUtils.InitComplianceMeta(Host.Platform, Host.Flavor, Host.CloudPlatform)
	scanUtils.InitImageBenchMeta()
	scanUtils.UpdateComplianceConfigs()
	Ctrler.ReadPrimeConfig = scanUtils.ReadPrimeConfig

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
	if platform == share.PlatformKubernetes {
		resource.GetNvControllerPodsNumber()
	}

	log.WithFields(log.Fields{"ctrler": Ctrler, "lead": lead, "self": self, "new-cluster": isNewCluster,
		"noDefAdmin": *noDefAdmin, "cspEnv": *cspEnv}).Info()

	restoredFedRole := ""
	purgeFedRulesOnJoint := false
	defAdminRestored := false

	// Initialize installation ID.  Ignore if ID is already set.
	clusHelper := kv.GetClusterHelper()
	if _, err := clusHelper.GetInstallationID(); err != nil {
		log.WithError(err).Warn("installation id is not readable. Will retry later.")
	}

	emptyKvFound := false
	ver := kv.GetControlVersion()
	if ver.CtrlVersion == "" && ver.KVVersion == "" {
		emptyKvFound = true
	}
	log.WithFields(log.Fields{"emptyKvFound": emptyKvFound, "ver": ver}).Info()

	if Ctrler.Leader || emptyKvFound {
		// See [NVSHAS-5490]:
		// clusterHelper.AcquireLock() may fail with error "failed to create session: Unexpected response code: 500 (Missing node registration)".
		// It indicates that the node is not yet registered in the catalog.
		// It's possibly because controller attempts to create a session immediately after starting Consul but actually Consul is not ready yet.
		// Even it's rare, we might need to allow Consul some time to initialize and sync the node registration to the catalog.
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

		// Restore persistent config.
		// Calling restore is unnecessary if this is not a new cluster installation, but not a big issue,
		// assuming the PV should have the latest config.
		var restored bool
		var restoredKvVersion string
		var errRestore error
		restoredFedRole, defAdminRestored, restored, restoredKvVersion, errRestore = kv.GetConfigHelper().Restore()
		if restored && errRestore == nil {
			clog := share.CLUSEventLog{
				Event:          share.CLUSEvKvRestored,
				HostID:         Host.ID,
				HostName:       Host.Name,
				ControllerID:   Ctrler.ID,
				ControllerName: Ctrler.Name,
				ReportedAt:     time.Now().UTC(),
				Msg:            fmt.Sprintf("Restored kv version: %s", restoredKvVersion),
			}
			evqueue.Append(&clog)
		}
		if restoredFedRole == api.FedRoleJoint {
			// fed rules are not restored on joint cluster but there might be fed rules left in kv so
			// 	we need to clean up fed rules & revisions in kv
			// if not using persist storage, the returned restoredFedRole is always empty string
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
	crossCheckCRD := false
	if Ctrler.Leader || !isNewCluster || emptyKvFound {
		nvImageVersion := Version
		if strings.HasPrefix(nvImageVersion, "interim/") {
			// it's daily dev build image
			if *teleCurrentVer != "" {
				nvImageVersion = *teleCurrentVer
			}
		}
		verUpdated := clusHelper.UpgradeClusterKV(nvImageVersion)
		if Ctrler.Leader || verUpdated {
			// corss-check existing CRs in k9s in situations:
			// 1. the 1st lead controller in fresh deployment
			// 2. the 1st new-version controller in rolling upgrade
			crossCheckCRD = true
		}
		clusHelper.FixMissingClusterKV()
	}

	if Ctrler.Leader {
		kv.ValidateWebhookCert()
		if isNewCluster && *noDefAdmin {
			clusHelper.DeleteUser(common.DefaultAdminUser)
		}
		setConfigLoaded()
	} else {
		// The lead can take some time to restore the PV. Synchronize here so when non-lead
		// read from the KV, such as policy list, it knows the data is complete.
		waitConfigLoaded(isNewCluster)
		kv.ValidateWebhookCert()
	}

	var nvAppFullVersion string  // in the format  {major}.{minor}.{patch}[-s{#}]
	var nvSemanticVersion string // in the format v{major}.{minor}.{patch}
	{
		if value, _ := cluster.Get(share.CLUSCtrlVerKey); value != nil {
			// ver.CtrlVersion   : in the format v{major}.{minor}.{patch}[-s{#}] or interim/master.xxxx
			// nvAppFullVersion  : in the format  {major}.{minor}.{patch}[-s{#}]
			// nvSemanticVersion : in the format v{major}.{minor}.{patch}
			var ver share.CLUSCtrlVersion
			json.Unmarshal(value, &ver)
			if strings.HasPrefix(ver.CtrlVersion, "interim/") {
				// it's daily dev build image
				if *teleCurrentVer == "" {
					nvAppFullVersion = "5.2.0"
				} else {
					nvAppFullVersion = *teleCurrentVer
				}
			} else {
				// it's official release image
				nvAppFullVersion = ver.CtrlVersion[1:]
			}
			if ss := strings.Split(nvAppFullVersion, "-"); len(ss) >= 1 {
				nvSemanticVersion = "v" + ss[0]
			}
		}
	}

	checkDefAdminFreq := *pwdValidUnit // check default admin's password every 24 hours by default
	if isNewCluster && *noDefAdmin {
		checkDefAdminFreq = 0 // do not check default admin's password if it's disabled
	}

	// start orchestration connection.
	// orchConnector should be created before LeadChangeCb is registered.
	orchObjChan := make(chan *resource.Event, 32)
	orchScanChan := make(chan *resource.Event, 16)

	if strings.HasSuffix(*teleNeuvectorEP, "apikeytest") {
		rest.TESTApikeySpecifiedCretionTime = true
		*teleNeuvectorEP = ""
	}

	if strings.HasSuffix(*teleNeuvectorEP, "dbperftest") {
		rest.TESTDbPerf = true
		*teleNeuvectorEP = ""
	}

	if value, _ := cluster.Get(share.CLUSCtrlVerKey); value != nil {
		var ver share.CLUSCtrlVersion
		json.Unmarshal(value, &ver)
		if !strings.HasPrefix(ver.CtrlVersion, "interim/") {
			// it's official release image
			if *teleNeuvectorEP == "" {
				// use public neuvector-upgrade-responder if testing upgrade-responder url is not specified
				*teleNeuvectorEP = "https://upgrades.neuvector-upgrade-responder.livestock.rancher.io/v1/checkupgrade"
			}
		}
	}
	if *teleNeuvectorEP == "" {
		*telemetryFreq = 0
	}

	// Initialize cache
	// - Start policy learning thread and build learnedPolicyRuleWrapper from KV
	cctx := cache.Context{
		RancherEP:                *rancherEP,
		RancherSSO:               *rancherSSO,
		TelemetryFreq:            *telemetryFreq,
		CheckDefAdminFreq:        checkDefAdminFreq,
		LocalDev:                 dev,
		EvQueue:                  evqueue,
		AuditQueue:               auditQueue,
		Messenger:                messenger,
		OrchChan:                 orchObjChan,
		TimerWheel:               timerWheel,
		DebugCPath:               ctrlEnv.debugCPath,
		Debug:                    debugLevel,
		EnableRmNsGroups:         enableRmNsGrps,
		EnableIcmpPolicy:         enableIcmpPolicy,
		ConnLog:                  connLog,
		MutexLog:                 mutexLog,
		ScanLog:                  scanLog,
		K8sResLog:                k8sResLog,
		CspType:                  cspType,
		CspPauseInterval:         *cspPauseInterval,
		CtrlerVersion:            Version,
		NvSemanticVersion:        nvSemanticVersion,
		StartStopFedPingPollFunc: rest.StartStopFedPingPoll,
		RestConfigFunc:           rest.RestConfig,
		CreateQuerySessionFunc:   rest.CreateQuerySession,
		DeleteQuerySessionFunc:   rest.DeleteQuerySession,
		NotifyCertChange:         nil, // To be filled later
	}
	cacher = cache.Init(&cctx, Ctrler.Leader, lead, restoredFedRole)
	cache.ScannerChangeNotify(Ctrler.Leader)

	var fedRole string
	if m := clusHelper.GetFedMembership(); m != nil {
		fedRole = m.FedRole
	}

	sctx := scan.Context{
		AuditQueue: auditQueue,
		ScanChan:   orchScanChan,
		TimerWheel: timerWheel,
		MutexLog:   mutexLog,
		ScanLog:    scanLog,
		FedRole:    fedRole,
	}
	scanner = scan.Init(&sctx, Ctrler.Leader)
	scan.ScannerChangeNotify(Ctrler.Leader)

	if platform == share.PlatformKubernetes {
		// k8s rbac watcher won't know anything about non-existing resources
		resource.GetNvCtrlerServiceAccount(cache.CacheEvent)
		resource.SetLeader(Ctrler.Leader)

		clusterRoleErrors, clusterRoleBindingErrors, roleErrors, roleBindingErrors := resource.VerifyNvK8sRBAC(dev.Host.Flavor, "", true)
		if len(clusterRoleErrors) > 0 || len(roleErrors) > 0 || len(clusterRoleBindingErrors) > 0 || len(roleBindingErrors) > 0 {
			msgs := clusterRoleErrors
			msgs = append(msgs, clusterRoleBindingErrors...)
			msgs = append(msgs, roleErrors...)
			msgs = append(msgs, roleBindingErrors...)
			cache.CacheEvent(share.CLUSEvK8sNvRBAC, strings.Join(msgs, "\n"))
		}
	}

	// start OPA server, should be started before RegisterStoreWatcher()
	opa.InitOpaServer()

	rctx := rest.Context{
		LocalDev:           dev,
		EvQueue:            evqueue,
		AuditQueue:         auditQueue,
		Messenger:          messenger,
		Cacher:             cacher,
		Scanner:            scanner,
		RESTPort:           *restPort,
		FedPort:            *fedPort,
		PwdValidUnit:       *pwdValidUnit,
		TeleNeuvectorURL:   *teleNeuvectorEP,
		SearchRegistries:   *searchRegistries,
		TeleFreq:           *telemetryFreq,
		NvAppFullVersion:   nvAppFullVersion,
		NvSemanticVersion:  nvSemanticVersion,
		CspType:            cspType,
		CspPauseInterval:   *cspPauseInterval,
		CustomCheckControl: *custom_check_control,
		CheckCrdSchemaFunc: nvcrd.CheckCrdSchema,
	}
	// rest.PreInitContext() must be called before orch connector because existing CRD handling could happen right after orch connecter starts
	rest.PreInitContext(&rctx)

	// Orch connector should be started after cacher so the listeners are ready
	orchConnector = newOrchConnector(orchObjChan, orchScanChan, Ctrler.Leader)
	orchConnector.Start(ocImageRegistered, cspType)

	if platform == share.PlatformKubernetes {
		nvcrd.Init(Ctrler.Leader, crossCheckCRD, cspType)
	}

	// GRPC should be started after cacher as the handler are cache functions
	grpcServer, _ = startGRPCServer(uint16(*grpcPort))

	// init rest server context before listening KV object store, as federation server can be started from there.
	rest.InitContext(&rctx)

	// Assign callback so cert manager can receive cert changes.
	cctx.NotifyCertChange = rest.CertManager.NotifyChanges

	// Registry cluster event handlers
	cluster.RegisterLeadChangeWatcher(leadChangeHandler, lead)
	cluster.RegisterNodeWatcher(ctlrMemberUpdateHandler)

	// Sync follows the lead so must be after leadChangeHandler registered.
	cache.SyncInit(isNewCluster)

	cluster.RegisterStoreWatcher(share.CLUSObjectStore, cache.ObjectUpdateHandler, false)
	cluster.RegisterStateWatcher(cache.ClusterMemberStateUpdateHandler)
	cluster.RegisterStoreWatcher(share.CLUSScannerStore, cache.ScannerUpdateHandler, false)
	cluster.RegisterStoreWatcher(share.CLUSScanStateStore, cache.ScanUpdateHandler, false)

	access.UpdateUserRoleForFedRoleChange(fedRole)

	// Load config from ConfigMap
	defAdminLoaded := rest.LoadInitCfg(Ctrler.Leader, dev.Host.Platform)
	if !defAdminRestored && !defAdminLoaded {
		// if platform == share.PlatformKubernetes && Ctrler.Leader && isNewCluster && !*noDefAdmin {
		if platform == share.PlatformKubernetes && Ctrler.Leader && !*noDefAdmin {
			if bootstrapPwd := resource.RetrieveBootstrapPassword(); bootstrapPwd != "" {
				acc := access.NewFedAdminAccessControl()
				user, rev, err := clusHelper.GetUserRev(common.DefaultAdminUser, acc)
				if user != nil {
					user.PasswordHash = utils.HashPassword(bootstrapPwd)
					user.ResetPwdInNextLogin = true
					user.UseBootstrapPwd = true
					user.PwdResetTime = time.Now().UTC()
					err = clusHelper.PutUserRev(user, rev)
				}
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Error()
				}
			}
		}
	}

	// To prevent crd webhookvalidating timeout need queue the crd and process later.
	rest.CrdValidateReqManager()

	// start rest server
	go rest.StartRESTServer(isNewCluster, Ctrler.Leader)

	// go rest.StartLocalDevHttpServer() // for local dev only

	if platform == share.PlatformKubernetes {
		rest.LeadChangeNotify(Ctrler.Leader)
		if Ctrler.Leader {
			cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, resource.NvAdmValidatingName, false)
		}
		go rest.CleanupSessCfgCache()
		go rest.AdmissionRestServer(*admctrlPort, false, debug)
		go rest.CrdValidateRestServer(*crdvalidatectrlPort, false, debug)
	}

	go rest.FedPollingClient(Ctrler.Leader, purgeFedRulesOnJoint)

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	logController(share.CLUSEvControllerStart)
	logController(share.CLUSEvControllerJoin)

	cache.PopulateRulesToOpa()

	go func() {
		ticker := time.Tick(time.Second * time.Duration(5))
		memStatTicker := time.Tick(time.Minute * time.Duration(memoryRecyclePeriod))
		memCheckTicker := time.NewTicker(time.Minute * time.Duration(memoryCheckPeriod))
		statsTicker := time.Tick(time.Second * time.Duration(statsInterval))

		ctrlEnv.memoryLimit = memControllerTopPeak
		if limit, err := global.SYS.GetContainerMemoryLimitUsage(ctrlEnv.cgroupMemory); err == nil && limit > 0 {
			ctrlEnv.memoryLimit = limit
		}
		ctrlEnv.snapshotMemStep = ctrlEnv.memoryLimit / 10
		memSnapshotMark := ctrlEnv.memoryLimit * 3 / 5             // 60% as starting point
		memStatsControllerResetMark := ctrlEnv.memoryLimit * 3 / 4 // 75% as starting point
		if ctrlEnv.autoProfieCapture > 1 {
			var mark uint64 = (uint64)(ctrlEnv.autoProfieCapture * 1024 * 1024) // into mega bytes
			memSnapshotMark = mark * 3 / 5
			ctrlEnv.snapshotMemStep = mark / 10
		}

		if ctrlEnv.autoProfieCapture > 0 {
			log.WithFields(log.Fields{"Step": ctrlEnv.snapshotMemStep, "Snapshot_At": memSnapshotMark}).Info("Memory Snapshots")
		} else {
			memCheckTicker.Stop()
		}
		log.WithFields(log.Fields{"Controlled_Limit": ctrlEnv.memoryLimit, "Controlled_At": memStatsControllerResetMark}).Info("Memory Resource")

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
				if mStats, err := global.SYS.GetContainerMemoryStats(); err == nil && mStats.WorkingSet > memStatsControllerResetMark {
					global.SYS.ReCalculateMemoryMetrics(memStatsControllerResetMark)
				}
			case <-memCheckTicker.C:
				if mStats, err := global.SYS.GetContainerMemoryStats(); err == nil && mStats.WorkingSet > memSnapshotMark {
					memorySnapshot(mStats.WorkingSet)
				}
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

func amendStubRtInfo() error {
	podname := Ctrler.Name
	objs, err := global.ORCH.ListResource(resource.RscTypeNamespace, "")
	if err == nil {
		for _, obj := range objs {
			if domain := obj.(*resource.Namespace); domain != nil {
				if o, err := global.ORCH.GetResource(resource.RscTypePod, domain.Name, podname); err == nil {
					if pod := o.(*resource.Pod); pod != nil {
						log.WithFields(log.Fields{"pod": pod}).Debug()
						Ctrler.Domain = domain.Name
						Ctrler.Labels = pod.Labels
						if Ctrler.Labels != nil {
							Ctrler.Labels["io.kubernetes.container.name"] = resource.NvDeploymentName
							Ctrler.Labels["io.kubernetes.pod.name"] = podname
							Ctrler.Labels["io.kubernetes.pod.namespace"] = Ctrler.Domain
							Ctrler.Labels["io.kubernetes.pod.uid"] = pod.UID
							Ctrler.Labels["name"] = share.NeuVectorRoleController
							Ctrler.Labels["neuvector.role"] = share.NeuVectorRoleController
							Ctrler.Labels["release"] = ""
							Ctrler.Labels["vendor"] = "NeuVector Inc."
							Ctrler.Labels["version"] = ""
						}
						if pod.HostNet {
							Ctrler.NetworkMode = "host"
						} else {
							Ctrler.NetworkMode = "default"
						}
						Host.Name = pod.Node
						Ctrler.HostName = Host.Name
						if tokens := strings.Split(Ctrler.HostID, ":"); len(tokens) > 0 {
							Host.ID = fmt.Sprintf("%s:%s", Host.Name, tokens[1])
							Ctrler.HostID = Host.ID
						}
						Ctrler.Name = "k8s_" + Ctrler.Labels["io.kubernetes.container.name"] + "_" +
							Ctrler.Labels["io.kubernetes.pod.name"] + "_" +
							Ctrler.Labels["io.kubernetes.pod.namespace"] + "_" +
							Ctrler.Labels["io.kubernetes.pod.uid"] + "_0"
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("can not found: err = %v", err)
}

func amendNotPrivilegedMode() error {
	podname := Ctrler.Labels["io.kubernetes.pod.name"]
	domain := Ctrler.Labels["io.kubernetes.pod.namespace"]
	if o, err := global.ORCH.GetResource(resource.RscTypePod, domain, podname); err != nil {
		return fmt.Errorf("can not found: err = %v, %v, %v", domain, podname, err)
	} else {
		if pod := o.(*resource.Pod); pod != nil {
			log.WithFields(log.Fields{"pod": pod}).Debug()
			Host.Name = pod.Node
			Ctrler.HostName = Host.Name
			if tokens := strings.Split(Ctrler.HostID, ":"); len(tokens) > 0 {
				Host.ID = fmt.Sprintf("%s:%s", Host.Name, tokens[1])
				Ctrler.HostID = Host.ID
			}
		}
	}
	return nil
}
