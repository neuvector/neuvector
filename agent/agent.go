package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/pipe"
	"github.com/neuvector/neuvector/agent/probe"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const goroutineStackSize = 1024 * 1024

var containerTaskExitChan chan interface{} = make(chan interface{}, 1)
var errRestartChan chan interface{} = make(chan interface{}, 1)
var restartChan chan interface{} = make(chan interface{}, 1)
var monitorExitChan chan interface{} = make(chan interface{}, 1)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
	Network:  share.NetworkDefault,
}
var Agent, parentAgent share.CLUSAgent
var agentEnv AgentEnvInfo

var evqueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var agentTimerWheel *utils.TimerWheel
var prober *probe.Probe
var bench *Bench
var grpcServer *cluster.GRPCServer
var scanUtil *scanUtils.ScanUtil
var fileWatcher *fsmon.FileWatch

var connLog *log.Logger = log.New()
var nvSvcPort, nvSvcBrPort string
var driver string
var exitingFlag int32
var exitingTaskFlag int32

var walkerTask *workerlet.Tasker

func shouldExit() bool {
	return (atomic.LoadInt32(&exitingFlag) != 0)
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func isAgentContainer(id string) bool {
	return id == Agent.ID || id == parentAgent.ID
}

func getHostIPs() {
	addrs := getHostAddrs()
	Host.Ifaces, gInfo.hostIPs, gInfo.jumboFrameMTU = parseHostAddrs(addrs, Host.Platform, Host.Network)
	if tun := global.ORCH.GetHostTunnelIP(addrs); tun != nil {
		Host.TunnelIP = tun
	}

	if global.ORCH.ConsiderHostsAsInternal() {
		addHostSubnets(Host.Ifaces, gInfo.localSubnetMap)
	}
	mergeLocalSubnets(gInfo.internalSubnets)
}

func getLocalInfo(selfID string, pid2ID map[int]string) error {
	host, err := global.RT.GetHost()
	if err != nil {
		return err
	}
	Host = *host
	Host.CgroupVersion = global.SYS.GetCgroupVersion()

	getHostIPs()

	if networks, err := global.RT.ListNetworks(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
	} else {
		gInfo.networks = networks
	}

	agentEnv.startsAt = time.Now().UTC()
	if agentEnv.runInContainer {
		dev, meta, err := global.RT.GetDevice(selfID)
		if err != nil {
			return err
		}
		Agent.CLUSDevice = *dev

		_, parent := global.RT.GetParent(meta, pid2ID)
		if parent != "" {
			dev, _, err := global.RT.GetDevice(parent)
			if err != nil {
				return err
			}
			parentAgent.CLUSDevice = *dev
			if parentAgent.PidMode == "host" {
				Agent.PidMode = "host"
			}
		}
	} else {
		Agent.ID = Host.ID
		Agent.Pid = os.Getpid()
		Agent.NetworkMode = "host"
		Agent.PidMode = "host"
		Agent.SelfHostname = Host.Name
		Agent.Ifaces = Host.Ifaces
	}
	Agent.HostName = Host.Name
	Agent.HostID = Host.ID
	Agent.Ver = Version

	agentEnv.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(0, "memory")
	agentEnv.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(0, "cpuacct")
	return nil
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only need to consider containers in the set, not those already exist.
func sortContainerByNetMode(ids utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, ids.Cardinality())
	for id := range ids.Iter() {
		if info, err := global.RT.GetContainer(id.(string)); err == nil {
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only for Container Start from Probe channel
func sortProbeContainerByNetMode(starts utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, starts.Cardinality())
	for start := range starts.Iter() {
		s := start.(*share.ProbeContainerStart)
		if info, err := global.RT.GetContainer(s.Id); err == nil {
			if info.Running && info.Pid == 0 { // cri-o: fault-tolerent for http channel errors
				info.Pid = s.RootPid_alt
				log.WithFields(log.Fields{"id": s.Id, "rootPid": info.Pid}).Debug("PROC: Update")
			}
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Enforcer cannot run together with enforcer.
// With SDN, enforcer can run together with controller; otherwise, port conflict will prevent them from running.
func checkAntiAffinity(containers []*container.ContainerMeta, skips ...string) error {
	skipSet := utils.NewSet()
	for _, skip := range skips {
		skipSet.Add(skip)
	}

	for _, c := range containers {
		if skipSet.Contains(c.ID) {
			continue
		}

		if v, ok := c.Labels[share.NeuVectorLabelRole]; ok {
			if strings.Contains(v, share.NeuVectorRoleEnforcer) {
				return fmt.Errorf("Must not run with another enforcer")
			}
		}
	}
	return nil
}

func cbRerunKube(cmd, cmdRemap string) {
	if Host.CapKubeBench {
		bench.RerunKube(cmd, cmdRemap, false)
	}
}

func waitContainerTaskExit() {
	// Wait for container task gorouting exiting and container ports' are restored.
	// If clean-up doesn't star, it's possible that container task queue get stuck.
	// In that case, call clean-up function directly and move forward. If the clean-up
	// already started, keep waiting.
	for {
		select {
		case <-containerTaskExitChan:
			return
		case <-time.After(time.Second * 4):
			if atomic.LoadInt32(&exitingTaskFlag) == 0 {
				containerTaskExit()
				return
			}
		}
	}
}

func dumpGoroutineStack() {
	log.Info("Enforcer goroutine stack")
	buf := make([]byte, goroutineStackSize)
	bytes := runtime.Stack(buf, true)
	if bytes > 0 {
		log.Printf("%s", buf[:bytes])
	}
}

func lookupK8sContainerID(id, role string, containers []*container.ContainerMeta) (string, error) {
	var podname string

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
				if v, ok := c.Labels[share.NeuVectorLabelRole]; ok {
					if strings.Contains(v, role) {
						// neuvector image role: it might have more than one children
						return c.ID, nil
					}
				}
			}
		}
	}
	return id, fmt.Errorf("failed to find container")
}

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "AGT"})

	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "AGT"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// log_file, log_err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	// if log_err == nil {
	//	  log.SetOutput(log_file)
	//    defer log_file.close()
	// }

	withCtlr := flag.Bool("c", false, "Coexist controller and ranger")
	debug := flag.Bool("d", false, "Enable control path debug")
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	pipeType := flag.String("p", "", "Pipe driver")
	cnet_type := flag.String("n", "", "Container Network type")
	skip_nvProtect := flag.Bool("s", false, "Skip NV Protect")
	show_monitor_trace := flag.Bool("m", false, "Show process/file monitor traces")
	disable_kv_congest_ctl := flag.Bool("no_kvc", false, "disable kv congestion control")
	disable_scan_secrets := flag.Bool("no_scrt", false, "disable secret scans")
	disable_auto_benchmark := flag.Bool("no_auto_benchmark", false, "disable auto benchmark")
	disable_system_protection := flag.Bool("no_sys_protect", false, "disable system protections")
	policy_puller := flag.Int("policy_puller", 0, "set policy pulling period")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
		gInfo.agentConfig.Debug = []string{"ctrl"}
	}

	agentEnv.kvCongestCtrl = true
	if *disable_kv_congest_ctl {
		log.Info("KV congestion control is disabled")
		agentEnv.kvCongestCtrl = false
	}

	agentEnv.scanSecrets = true
	if *disable_scan_secrets {
		log.Info("Scanning secrets on containers is disabled")
		agentEnv.scanSecrets = false
	}

	agentEnv.autoBenchmark = true
	if *disable_auto_benchmark {
		log.Info("Auto benchmark is disabled")
		agentEnv.autoBenchmark = false
	}

	agentEnv.systemProfiles = true
	if *disable_system_protection {
		log.Info("System protection is disabled (process/file profiles)")
		agentEnv.systemProfiles = false
	}

	agentEnv.netPolicyPuller = *policy_puller
	if *policy_puller != 0 {
		log.WithFields(log.Fields{"period": *policy_puller}).Info("policy pull regulator")
	}

	if *join != "" {
		// Join addresses might not be all ready. Accept whatever input is, resolve them
		// when starting the cluster.
		/*
			addrs := utils.ResolveJoinAddr(*join)
			if addrs == "" {
				log.WithFields(log.Fields{"join": *join}).Error("Invalid join address. Exit!")
				os.Exit(-2)
			}
		*/
		joinAddr = *join
	}
	if *adv != "" {
		ips, err := utils.ResolveIP(*adv)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"advertise": *adv}).Error("Invalid join address. Exit!")
			os.Exit(-2)
		}

		advAddr = ips[0].String()
	}
	if *bind != "" {
		bindAddr = *bind
		log.WithFields(log.Fields{"bind": bindAddr}).Info()
	}

	// Set global objects at the very first
	platform, flavor, network, containers, err := global.SetGlobalObjects(*rtSock, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		if err == global.ErrEmptyContainerList {
			// Temporary get container list error
			// => exit the process but the container doesn't need to be restarted
			os.Exit(-1)
		}
		os.Exit(-2)
	}

	walkerTask = workerlet.NewWalkerTask(*show_monitor_trace, global.SYS)

	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {
		k8sVer, ocVer := global.ORCH.GetVersion(false, false)
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer}).Info()
	}

	var selfID string
	agentEnv.runWithController = *withCtlr
	agentEnv.runInContainer = global.SYS.IsRunningInContainer()
	if agentEnv.runInContainer {
		selfID, agentEnv.containerInContainer, err = global.SYS.GetSelfContainerID()
		if selfID == "" { // it is a POD ID in the k8s cgroup v2; otherwise, a real container ID
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
		agentEnv.containerShieldMode = (!*skip_nvProtect)
		log.WithFields(log.Fields{"shield": agentEnv.containerShieldMode}).Info("PROC:")
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes {
		if selfID, err = lookupK8sContainerID(selfID, share.NeuVectorRoleEnforcer, containers); err != nil {
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
		// Get local host and agent info
		if err = getLocalInfo(selfID, pid2ID); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get local device information")
			os.Exit(-2)
		}

		if len(Agent.Ifaces) > 0 {
			break
		}

		log.Info("Wait for local interface ...")
		time.Sleep(time.Second * 4)
	}

	// Check anti-affinity
	var retry int
	retryDuration := time.Duration(time.Second * 2)
	for {
		err = checkAntiAffinity(containers, Agent.ID, parentAgent.ID)
		if err != nil {
			// Anti affinity check failure might be because the old enforcer is not stopped yet.
			// This can happen when user switches from an enforcer to an allinone on the same host.
			// Will wait and retry instead of quit to tolerate the timing issue.
			// Also if this enforcer is inside an allinone, the controller can still work correctly.
			retry++
			if retry == 10 {
				retryDuration = time.Duration(time.Second * 30)
				log.Info("Will retry affinity check every 30 seconds")
			}
			time.Sleep(retryDuration)

			// List only running containers
			containers, err = global.RT.ListContainers(true)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to list containers")
				os.Exit(-2)
			}
		} else {
			break
		}
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.Network = network
	Host.CapDockerBench = (global.RT.String() == container.RuntimeDocker)
	Host.CapKubeBench = global.ORCH.SupportKubeCISBench()

	Agent.Domain = global.ORCH.GetDomain(Agent.Labels)
	parentAgent.Domain = global.ORCH.GetDomain(parentAgent.Labels)

	policyInit()

	// Assign agent interface/IP scope
	if agentEnv.runInContainer {
		meta := container.ContainerMeta{
			ID:      Agent.ID,
			Name:    Agent.Name,
			NetMode: Agent.NetworkMode,
			Labels:  Agent.Labels,
		}
		global.ORCH.SetIPAddrScope(Agent.Ifaces, &meta, gInfo.networks)
	}

	Host.StorageDriver = global.RT.GetStorageDriver()
	log.WithFields(log.Fields{"hostIPs": gInfo.hostIPs}).Info("")
	log.WithFields(log.Fields{"host": Host}).Info("")
	log.WithFields(log.Fields{"agent": Agent}).Info("")

	// Other objects
	eventLogKey := share.CLUSAgentEventLogKey(Host.ID, Agent.ID)
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	messenger = cluster.NewMessenger(Host.ID, Agent.ID)

	//var driver string
	if *pipeType == "ovs" {
		driver = pipe.PIPE_OVS
	} else if *pipeType == "no_tc" {
		driver = pipe.PIPE_NOTC
	} else {
		driver = pipe.PIPE_TC
	}
	log.WithFields(log.Fields{"pipeType": driver, "jumboframe": gInfo.jumboFrameMTU}).Info("")

	if nvSvcPort, nvSvcBrPort, err = pipe.Open(driver, cnet_type, Agent.Pid, gInfo.jumboFrameMTU); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open pipe driver")
		os.Exit(-2)
	}

	// Start cluster
	var clusterCfg cluster.ClusterConfig
	clusterCfg.ID = Agent.ID
	clusterCfg.Server = false
	clusterCfg.Debug = false
	clusterCfg.Ifaces = Agent.Ifaces
	clusterCfg.JoinAddr = joinAddr
	clusterCfg.AdvertiseAddr = advAddr
	clusterCfg.BindAddr = bindAddr
	clusterCfg.LANPort = *lanPort
	clusterCfg.DataCenter = cluster.DefaultDataCenter
	clusterCfg.EnableDebug = *debug

	if err = clusterStart(&clusterCfg); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to start cluster. Exit!")
		if err == errNotAdmitted || err == errCtrlNotReady {
			// This indicates controllers are up but license is not loaded.
			// => exit the process but the container doesn't need to be restarted
			os.Exit(-1)
		} else {
			// Monitor will exit, so the container will be restarted
			os.Exit(-2)
		}
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	agentTimerWheel = utils.NewTimerWheel()
	agentTimerWheel.Start()

	// Read existing containers again, cluster start can take a while.
	existing, _ := global.RT.ListContainerIDs()

	if existing.Cardinality() > containerTaskChanSizeMin {
		ContainerTaskChan = make(chan *ContainerTask, existing.Cardinality())
	} else {
		ContainerTaskChan = make(chan *ContainerTask, containerTaskChanSizeMin)
	}

	rtStorageDriver = Host.StorageDriver
	log.WithFields(log.Fields{"name": rtStorageDriver}).Info("Runtime storage driver")

	// Datapath
	dpStatusChan := make(chan bool, 2)
	dp.Open(dpTaskCallback, dpStatusChan, errRestartChan)

	// Benchmark
	bench = newBench(Host.Platform, Host.Flavor)
	go bench.BenchLoop()

	if Host.CapDockerBench {
		bench.RerunDocker(false)
	} else {
		// If the older version write status into the cluster, clear it.
		bench.ResetDockerStatus()
	}
	if !Host.CapKubeBench {
		// If the older version write status into the cluster, clear it.
		bench.ResetKubeStatus()
	}

	bPassiveContainerDetect := global.RT.String() == container.RuntimeCriO

	// Probe
	probeTaskChan := make(chan *probe.ProbeMessage, 256) // increase to avoid underflow
	fsmonTaskChan := make(chan *fsmon.MonitorMessage, 8)
	faEndChan := make(chan bool, 1)
	fsmonEndChan := make(chan bool, 1)
	probeConfig := probe.ProbeConfig{
		ProfileEnable:        agentEnv.systemProfiles,
		Pid:                  Agent.Pid,
		PidMode:              Agent.PidMode,
		DpTaskCallback:       dpTaskCallback,
		NotifyTaskChan:       probeTaskChan,
		NotifyFsTaskChan:     fsmonTaskChan,
		PolicyLookupFunc:     hostPolicyLookup,
		ProcPolicyLookupFunc: processPolicyLookup,
		IsK8sGroupWithProbe:  pe.IsK8sGroupWithProbe,
		ReportLearnProc:      addLearnedProcess,
		ContainerInContainer: agentEnv.containerInContainer,
		GetContainerPid:      cbGetContainerPid,
		GetAllContainerList:  cbGetAllContainerList,
		RerunKubeBench:       cbRerunKube,
		GetEstimateProcGroup: cbEstimateDeniedProcessdByGroup,
		GetServiceGroupName:  cbGetLearnedGroupName,
		FAEndChan:            faEndChan,
		DeferContStartRpt:    bPassiveContainerDetect,
		EnableTrace:          *show_monitor_trace,
		KubePlatform:         Host.Platform == share.PlatformKubernetes,
		KubeFlavor:           Host.Flavor,
		WalkHelper:           walkerTask,
	}

	if prober, err = probe.New(&probeConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to probe. Exit!")
		os.Exit(-2)
	}

	fmonConfig := fsmon.FileMonitorConfig{
		ProfileEnable:  agentEnv.systemProfiles,
		IsAufs:         global.RT.GetStorageDriver() == "aufs",
		EnableTrace:    *show_monitor_trace,
		EndChan:        fsmonEndChan,
		WalkerTask:     walkerTask,
		PidLookup:      prober.ProcessLookup,
		SendReport:     prober.SendAggregateFsMonReport,
		SendAccessRule: sendLearnedFileAccessRule,
		EstRule:        cbEstimateFileAlertByGroup,
	}

	if fileWatcher, err = fsmon.NewFileWatcher(&fmonConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open file monitor!")
		os.Exit(-2)
	}

	prober.SetFileMonitor(fileWatcher)

	scanUtil = scanUtils.NewScanUtil(global.SYS)

	// grpc need to be put after probe (grpc requests like sessionList, ProbeSummary require probe ready),
	// and it also should be before clusterLoop, sending grpc port in update agent
	global.SYS.CallNetNamespaceFunc(Agent.Pid, func(params interface{}) {
		grpcServer, Agent.RPCServerPort = startGRPCServer(uint16(*grpcPort))
	}, nil)

	// Start container task thread
	// Start monitoring container events
	eventMonitorLoop(probeTaskChan, fsmonTaskChan, dpStatusChan)

	// Update host and device info to cluster
	logAgent(share.CLUSEvAgentStart)
	Agent.JoinedAt = time.Now().UTC()
	putLocalInfo()
	logAgent(share.CLUSEvAgentJoin)

	clusterLoop(existing)
	existing = nil

	go statsLoop(bPassiveContainerDetect)
	go timerLoop()

	if agentEnv.systemProfiles {
		go group_profile_loop()
	}

	// Wait for SIGTREM
	go func() {
		<-c_sig
		done <- true
	}()

	log.Info("Ready ...")

	var rc int
	select {
	case <-done:
		rc = 0
	case <-monitorExitChan:
		rc = -2
	case <-restartChan:
		// Agent is kicked because of license limit.
		// Return -1 so that monitor will restart the agent,
		// and agent will reconnect after license update.
		rc = -1
	case <-errRestartChan:
		// Proactively restart agent to recover from error condition.
		// Return -1 so that monitor will restart the agent.
		rc = -1
		dumpGoroutineStack()
	}

	// Check shouldExit() to see the loops that will exit when the flag is set
	atomic.StoreInt32(&exitingFlag, 1)

	log.Info("Exiting ...")

	if walkerTask != nil {
		walkerTask.Close()
	}

	prober.Close() // both file monitors should be released at first
	fileWatcher.Close()
	bench.Close()

	stopMonitorLoop()
	closeCluster()

	waitContainerTaskExit()

	if driver != pipe.PIPE_NOTC {
		dp.DPCtrlDelSrvcPort(nvSvcPort)
	}

	pipe.Close()

	releaseAllSniffer()

	grpcServer.Stop()

	// Close DP at the last
	dp.Close()

	global.SYS.StopToolProcesses()
	<-faEndChan
	<-fsmonEndChan
	log.Info("Exited")
	os.Exit(rc)
}
