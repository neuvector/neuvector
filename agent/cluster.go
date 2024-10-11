package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

// const LogFile string = "/var/log/ranger/monitor.log"
var ClusterEventChan chan *ClusterEvent = make(chan *ClusterEvent, 256)

var selfAddr string
var leadAddr string
var leadGrpcPort uint16

var errNotAdmitted = fmt.Errorf("Enforcer is not able to join the cluster")
var errCtrlNotReady = fmt.Errorf("Controller is not ready")

type workloadInfo struct {
	wl *share.CLUSWorkload
}

var wlCacheMap map[string]*workloadInfo = make(map[string]*workloadInfo)

func leaveCluster() {
	// Don't try to remove keys. Let controller do that.
	if !agentEnv.runWithController {
		cluster.LeaveCluster(false)
	}
}

func waitForAdmission() error {
	shortWait := time.Second * 2
	longWait := time.Second * 15
	maxRetry := 60
	retry := 0

	print := true
	for {
		if val, err := cluster.Get(share.CLUSCtrlNodeAdmissionKey); err != nil || string(val) != share.CLUSCtrlEnabledValue {
			time.Sleep(shortWait)
			retry++
		} else {
			break
		}
		if print {
			log.Error("Node admission is not enabled yet")
			print = false
		}
		if retry > maxRetry {
			// we can get here if the license is not loaded
			return errCtrlNotReady
		}
	}

	log.Info("Node admission is enabled")

	req := share.CLUSAdmissionRequest{
		ID: Agent.ID, HostID: Host.ID, HostCPUs: Host.CPUs, HostMemory: Host.Memory,
	}

	retry = 0
	for {
		log.Info("Sending join request")
		resp, err := requestAdmission(&req, time.Second*4)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Agent join request failed")
			time.Sleep(shortWait)
		} else if !resp.Allowed {
			// Most likely the connection request is rejected due to license
			log.WithFields(log.Fields{"reason": resp.Reason}).Error("Agent join request rejected")
			time.Sleep(longWait)
		} else {
			break
		}

		retry++
		if retry > maxRetry {
			return errNotAdmitted
		}
	}

	log.Info("Agent join request accepted")

	return nil
}

func clusterStart(clusterCfg *cluster.ClusterConfig) error {
	log.WithFields(log.Fields{"with_ctlr": agentEnv.runWithController}).Debug("")

	var err error
	if !agentEnv.runWithController {
		if err = cluster.FillClusterAddrs(clusterCfg, global.SYS); err != nil {
			return err
		}
		leadAddr, err = cluster.StartCluster(clusterCfg)
		if err != nil {
			return err
		}
	} else {
		leadAddr, err = cluster.StartCluster(nil)
		if err != nil {
			return err
		}
	}

	cluster.RegisterLeadChangeWatcher(leadChangeHandler, leadAddr)
	if err = waitForAdmission(); err != nil {
		return err
	}

	selfAddr = cluster.GetSelfAddress()
	return nil
}

func s2cConfig(subject, id string, data []byte) {
	switch subject {
	case "workload":
		// SET-KEY: .../workload/<workload_id>
		var conf share.CLUSWorkloadConfig
		if dbgError := json.Unmarshal(data, &conf); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		task := ContainerTask{task: TASK_CONFIG_CONTAINER, id: id, macConf: &conf}
		ContainerTaskChan <- &task
	case "agent":
		// SET-KEY: .../agent/<agent_id>
		var conf share.CLUSAgentConfig
		if dbgError := json.Unmarshal(data, &conf); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		task := ContainerTask{task: TASK_CONFIG_AGENT, agentConf: &conf}
		ContainerTaskChan <- &task
	}
}

func uniconfHandler(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{
		"type": cluster.ClusterNotifyName[nType], "key": key,
	}).Debug("")

	// Key removed only means it's recycled. All config and diagnose command should be explicit.
	if nType == cluster.ClusterNotifyDelete {
		return
	}

	subject := share.CLUSUniconfKey2Subject(key)
	id := share.CLUSUniconfKey2ID(key)
	log.WithFields(log.Fields{"subject": subject, "id": id}).Debug("")

	s2cConfig(subject, id, value)
}

func logAgent(ev share.TLogEvent) {
	clog := share.CLUSEventLog{
		Event:     ev,
		HostID:    Host.ID,
		HostName:  Host.Name,
		AgentID:   Agent.ID,
		AgentName: Agent.Name,
	}
	switch ev {
	case share.CLUSEvAgentStart:
		clog.ReportedAt = agentEnv.startsAt
	default:
		clog.ReportedAt = time.Now().UTC()
	}

	if dbgError := evqueue.Append(&clog); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func logWorkload(ev share.TLogEvent, wl *share.CLUSWorkload, msg *string) {
	// ignore NeuVector containers
	if wl.PlatformRole == container.PlatformContainerNeuVector {
		return
	}

	clog := share.CLUSEventLog{
		Event:        ev,
		HostID:       Host.ID,
		HostName:     Host.Name,
		AgentID:      Agent.ID,
		AgentName:    Agent.Name,
		WorkloadID:   wl.ID,
		WorkloadName: wl.Name,
	}
	if msg != nil {
		clog.Msg = *msg
	}
	switch ev {
	case share.CLUSEvWorkloadStart:
		clog.ReportedAt = wl.StartedAt
	case share.CLUSEvWorkloadStop:
		clog.ReportedAt = wl.FinishedAt
	default:
		clog.ReportedAt = time.Now().UTC()
	}

	if dbgError := evqueue.Append(&clog); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

var snapshotIndex int

func memorySnapshot(usage uint64) {
	if agentEnv.autoProfieCapture > 0 {
		log.WithFields(log.Fields{"usage": usage}).Debug()
		if usage > agentEnv.peakMemoryUsage {
			agentEnv.peakMemoryUsage = usage + agentEnv.snapshotMemStep // level up
			label := "p"                                                // peak
			if snapshotIndex < 4 {                                      // keep atmost 4 copies + an extra peak copy
				snapshotIndex++
				label = strconv.Itoa(snapshotIndex)
			}
			log.WithFields(log.Fields{"label": label, "next": agentEnv.peakMemoryUsage}).Debug()
			utils.PerfSnapshot(Agent.Pid, agentEnv.memoryLimit, agentEnv.autoProfieCapture, usage, share.SnaphotFolder, Agent.ID, "enf.", label)
		}
	}
}

var curMemoryPressure uint64

func memoryPressureNotification(rpt *system.MemoryPressureReport) {
	if rpt.Level >= 2 { // cap its maximum
		rpt.Level = 2
		memorySnapshot(rpt.Stats.WorkingSet)
	}

	if rpt.Level == curMemoryPressure {
		return // skip report
	}

	log.WithFields(log.Fields{"rpt": rpt}).Info()
	// launch falling-edge watcher
	if curMemoryPressure == 0 {
		go func() {
			var err error
			var mStats *system.CgroupMemoryStats

			acc := 0
			for acc < 7 {
				time.Sleep(time.Minute * 1)
				if mStats, err = global.SYS.GetContainerMemoryStats(); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("mem stat")
					continue
				}

				limit := mStats.Usage.Limit
				if mStats.Usage.Limit == 0 { // it's hitting node's limit
					limit = uint64(Host.Memory)
				}

				ratio := uint64(rpt.Stats.WorkingSet * 100 / limit)
				// log.WithFields(log.Fields{"ratio": ratio, "acc": acc, "limit": limit}).Debug()
				if ratio <= 50 { // what is the reasonable threshold?
					acc++
				} else {
					acc = 0
				}
			}

			rptt := &system.MemoryPressureReport{
				Level: 0, // assumption
				Stats: *mStats,
			}

			putMemoryPressureEvent(rptt, false)
			curMemoryPressure = 0 // reset
		}()
	}

	curMemoryPressure = rpt.Level

	//
	putMemoryPressureEvent(rpt, true)
}

func putMemoryPressureEvent(rpt *system.MemoryPressureReport, setRisingEdge bool) {
	var description string
	if rpt.Stats.Usage.Limit == 0 {
		// it's hitting node's limit
		ratio := uint64(rpt.Stats.WorkingSet * 100 / uint64(Host.Memory))
		if setRisingEdge {
			description = fmt.Sprintf("Memory usage[%s] is more than %d %% of the node memory[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(Host.Memory)))
		} else {
			description = fmt.Sprintf("Memory usage[%s] is normal, %d %% of the node memory[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(Host.Memory)))
		}
	} else {
		ratio := uint64(rpt.Stats.WorkingSet * 100 / rpt.Stats.Usage.Limit)
		if setRisingEdge {
			description = fmt.Sprintf("Memory usage[%s] is more than %d %% of the container memory limit[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(rpt.Stats.Usage.Limit)))
		} else {
			description = fmt.Sprintf("Memory usage[%s] is normal, %d %% of the container memory limit[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(rpt.Stats.Usage.Limit)))
		}
	}

	report := map[string]interface{}{
		"Description":  description,
		"Level":        rpt.Level,
		"UsageLimit":   rpt.Stats.Usage.Limit,
		"NetUsage":     rpt.Stats.WorkingSet,
		"MaxUsage":     rpt.Stats.Usage.MaxUsage,
		"ActiveAnon":   rpt.Stats.Stats["active_anon"],
		"InactiveAnon": rpt.Stats.Stats["inactive_anon"],
		"Cache":        rpt.Stats.Stats["cache"],
		"PageFaults":   rpt.Stats.Stats["pgfault"],
		"RSS":          rpt.Stats.Stats["rss"],
		"Failcnt":      rpt.Stats.Usage.Failcnt,
	}

	b := new(bytes.Buffer)
	if dbgError := json.NewEncoder(b).Encode(report); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	msg := b.String()

	// log.WithFields(log.Fields{"msg": msg}).Debug()

	clog := share.CLUSEventLog{
		Event:      share.CLUSEvMemoryPressureAgent,
		HostID:     Host.ID,
		HostName:   Host.Name,
		AgentID:    Agent.ID,
		AgentName:  Agent.Name,
		ReportedAt: time.Now().UTC(),
		Msg:        msg,
	}

	if dbgError := evqueue.Append(&clog); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

// PUT-KEY: /object/host/<host_docker_id>
// PUT-KEY: /object/device/<host_docker_id>/<device_uuid>
func putLocalInfo() {
	log.Debug()

	value, _ := json.Marshal(Host)
	key := share.CLUSHostKey(Host.ID, "agent")
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}

	Agent.ClusterIP = selfAddr
	value, _ = json.Marshal(Agent)
	key = share.CLUSAgentKey(Host.ID, Agent.ID)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func putHostIfInfo() {
	log.Debug()

	value, _ := json.Marshal(Host)
	key := share.CLUSHostKey(Host.ID, "agent")
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func deleteAgentInfo() {
	log.Debug()

	key := share.CLUSAgentKey(Host.ID, Agent.ID)
	if err := cluster.Delete(key); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

// PUT-KEY: object/networkep/<host_id>/<id>
func putNetworkEP(nep *share.CLUSNetworkEP) {
	value, _ := json.Marshal(nep)
	key := share.CLUSNetworkEPKey(Host.ID, nep.ID)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func deleteNetworkEP(nepID string) {
	key := share.CLUSNetworkEPKey(Host.ID, nepID)
	if dbgError := cluster.Delete(key); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

// PUT-KEY: object/workload/<host_id>/<id>
func putWorkload(wl *share.CLUSWorkload) {
	value, _ := json.Marshal(wl)
	key := share.CLUSWorkloadKey(Host.ID, wl.ID)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func putContainerForStop(info *container.ContainerMetaExtra, wl *share.CLUSWorkload) {
	if info != nil {
		log.WithFields(log.Fields{"container": info.ID}).Debug("")
		wl.FinishedAt = info.FinishedAt
		wl.Running = info.Running
		wl.ExitCode = info.ExitCode
		wl.Pid = info.Pid
	} else {
		wl.FinishedAt = time.Now().UTC()
		wl.Running = false
	}

	// !!! Keep interface IP so controller could easily use the IP to remove ip-workload map entries
	// !!! when it figured the container is not running
	// wl.Ifaces = make(map[string][]share.CLUSIPAddr)
	// wl.Apps = make(map[string]share.CLUSApp)
	putWorkload(wl)
}

func createWorkload(info *container.ContainerMetaExtra, svc, domain *string) *share.CLUSWorkload {
	wl := share.CLUSWorkload{
		ID:           info.ID,
		Name:         info.Name,
		SelfHostname: info.Hostname,
		AgentID:      Agent.ID,
		HostName:     Host.Name,
		HostID:       Host.ID,
		Image:        info.Image,
		ImageID:      info.ImageID,
		ImgCreateAt:  info.ImgCreateAt,
		Author:       info.Author,
		NetworkMode:  info.NetMode,
		Privileged:   info.Privileged,
		RunAsRoot:    info.RunAsRoot,
		CreatedAt:    info.CreatedAt,
		StartedAt:    info.StartedAt,
		FinishedAt:   info.FinishedAt,
		Running:      info.Running,
		ExitCode:     info.ExitCode,
		Pid:          info.Pid,
		Inline:       false,
		Labels:       info.Labels,
		MemoryLimit:  info.MemoryLimit,
		CPUs:         info.CPUs,
		ProxyMesh:    info.ProxyMesh,
		Sidecar:      info.Sidecar,
		Ifaces:       make(map[string][]share.CLUSIPAddr),
		Ports:        make(map[string]share.CLUSMappedPort),
		Apps:         make(map[string]share.CLUSApp),
	}

	if wl.Running {
		if info.IPAddress != "" {
			wl.Ifaces["eth0"] = []share.CLUSIPAddr{
				{
					IPNet: net.IPNet{
						IP:   net.ParseIP(info.IPAddress),
						Mask: net.CIDRMask(info.IPPrefixLen, 32),
					},
					// Gateway info is not used right now and is not read from
					// pullAllContainerPorts() either
					// Gateway: info.NetworkSettings.Gateway,
					Scope: share.CLUSIPAddrScopeLocalhost,
				},
			}
		}
	}

	if svc != nil && domain != nil {
		// It must be a full service name, like "iperf.demo".
		wl.Service = *svc
		wl.Domain = *domain
	}
	return &wl
}

func translateAppMap(apps map[share.CLUSProtoPort]*share.CLUSApp) map[string]share.CLUSApp {
	newApps := make(map[string]share.CLUSApp, len(apps))
	for p, app := range apps {
		key := utils.GetPortLink(p.IPProto, p.Port)
		newApps[key] = *app
	}
	return newApps
}

func translateMappedPort(ports map[share.CLUSProtoPort]*share.CLUSMappedPort) map[string]share.CLUSMappedPort {
	newPorts := make(map[string]share.CLUSMappedPort, len(ports))
	for p, port := range ports {
		key := utils.GetPortLink(p.IPProto, p.Port)
		newPorts[key] = *port
	}
	return newPorts
}

// Translate open port to host port map, only used for host-mode container
func app2MappedPort(apps map[share.CLUSProtoPort]*share.CLUSApp) map[share.CLUSProtoPort]*share.CLUSMappedPort {
	ports := make(map[share.CLUSProtoPort]*share.CLUSMappedPort, len(apps))
	for p := range apps {
		cp := share.CLUSProtoPort{
			Port:    p.Port,
			IPProto: p.IPProto,
		}
		ports[cp] = &share.CLUSMappedPort{
			CLUSProtoPort: cp,
			HostIP:        net.ParseIP("0.0.0.0"),
			HostPort:      p.Port,
		}
	}
	return ports
}

func updateContainer(ev *ClusterEvent, wl *share.CLUSWorkload) {
	if ev.capIntcp != nil {
		wl.CapIntcp = *ev.capIntcp
	}
	if ev.capSniff != nil {
		wl.CapSniff = *ev.capSniff
	}
	if ev.hasDatapath != nil {
		wl.HasDatapath = *ev.hasDatapath
	}
	if ev.inline != nil {
		wl.Inline = *ev.inline
	}
	if ev.quar != nil {
		quar := wl.Quarantine
		wl.Quarantine = *ev.quar
		if !quar && wl.Quarantine {
			logWorkload(share.CLUSEvWorkloadQuarantined, wl, ev.quarReason)
		} else if quar && !wl.Quarantine {
			logWorkload(share.CLUSEvWorkloadUnquarantined, wl, nil)
		}
	}

	if ev.apps != nil {
		wl.Apps = ev.apps
	}
	if ev.ports != nil {
		wl.Ports = ev.ports
	}
	if ev.ifaces != nil {
		wl.Ifaces = ev.ifaces
	}
	if ev.service != nil {
		wl.Service = *ev.service
	}
	if ev.domain != nil {
		wl.Domain = *ev.domain
	}
	if ev.role != nil {
		wl.PlatformRole = *ev.role
	}
	if ev.shareNetNS != nil {
		wl.ShareNetNS = *ev.shareNetNS
	}
	if ev.info != nil {
		wl.ProxyMesh = ev.info.ProxyMesh
	}
}

func clusterAddContainer(ev *ClusterEvent) {
	log.WithFields(log.Fields{"container": ev.id}).Debug("")

	if cache, ok := wlCacheMap[ev.id]; !ok || cache.wl.Running != ev.info.Running {
		wl := createWorkload(ev.info, ev.service, ev.domain)
		if ev.role != nil {
			wl.PlatformRole = *ev.role
		}
		logWorkload(share.CLUSEvWorkloadStart, wl, nil)

		updateContainer(ev, wl)
		wl.SecuredAt = time.Now().UTC()
		logWorkload(share.CLUSEvWorkloadSecured, wl, nil)

		if !wl.Running && wl.FinishedAt.IsZero() {
			// this short-lived workload was stopped before report adding a workload event
			// fabricate a reference time
			wl.FinishedAt = time.Now().UTC()
		}

		putWorkload(wl)
		wlCacheMap[ev.id] = &workloadInfo{wl: wl}
		if !wl.Running {
			logWorkload(share.CLUSEvWorkloadStop, wl, nil)
		}
	}
}

func clusterStopContainer(ev *ClusterEvent) {
	log.WithFields(log.Fields{"container": ev.id}).Debug("")

	if cache, ok := wlCacheMap[ev.id]; ok {
		if cache.wl.Running {
			putContainerForStop(ev.info, cache.wl)
			logWorkload(share.CLUSEvWorkloadStop, cache.wl, nil)
		}
	} else {
		// This should not happen with the new code change - 03/02/2017
		log.WithFields(log.Fields{"id": ev.id}).Error("Miss add event!")
		if ev.info == nil {
			return
		}

		// Container might not be intercepted and reported yet.
		wl := createWorkload(ev.info, ev.service, ev.domain)
		if _, ok := getNeuVectorRole(ev.info); ok {
			// nuVector pod
			wl.PlatformRole = container.PlatformContainerNeuVector
		}
		putWorkload(wl)
		wlCacheMap[ev.id] = &workloadInfo{wl: wl}

		logWorkload(share.CLUSEvWorkloadStart, wl, nil)
		logWorkload(share.CLUSEvWorkloadStop, wl, nil)
	}
}

func clusterDelContainer(id string) {
	log.WithFields(log.Fields{"container": id}).Debug("")

	if dbgError := cluster.Delete(share.CLUSWorkloadKey(Host.ID, id)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	if dbgError := cluster.DeleteTree(share.CLUSBenchKey(id)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	if dbgError := cluster.Delete(share.CLUSBenchStateWorkloadKey(id)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Scan keys are deleted by the controller
	if cache, ok := wlCacheMap[id]; ok {
		logWorkload(share.CLUSEvWorkloadRemove, cache.wl, nil)
		delete(wlCacheMap, id)
	}
}

func clusterUpdateContainer(ev *ClusterEvent) {
	log.WithFields(log.Fields{"container": ev.id}).Debug("")

	cache, ok := wlCacheMap[ev.id]
	if !ok {
		log.Errorf("Unable to find container in cache.")
		return
	}

	updateContainer(ev, cache.wl)

	putWorkload(cache.wl)
}

func clusterRefreshContainers() {
	log.Debug("")

	// Remove non-existing containers from cluster
	existing := utils.NewSet()
	for id := range wlCacheMap {
		existing.Add(id)
	}

	store := share.CLUSWorkloadHostStore(Host.ID)
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		id := share.CLUSWorkloadKey2ID(key)
		if !existing.Contains(id) {
			if dbgError := cluster.Delete(key); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
	}

	// Report container information
	for _, cache := range wlCacheMap {
		putWorkload(cache.wl)
	}
}

func clusterEventHandler(ev *ClusterEvent) {
	log.WithFields(log.Fields{"event": ClusterEventName[ev.event]}).Debug("start")
	switch ev.event {
	case EV_ADD_CONTAINER:
		clusterAddContainer(ev)
	case EV_STOP_CONTAINER:
		clusterStopContainer(ev)
	case EV_DEL_CONTAINER:
		clusterDelContainer(ev.id)
	case EV_REFRESH_CONTAINERS:
		clusterRefreshContainers()
	case EV_UPDATE_CONTAINER:
		clusterUpdateContainer(ev)
	}
	log.WithFields(log.Fields{"event": ClusterEventName[ev.event]}).Debug("Done")
}

func uploadCurrentInfo() {
	log.Debug("")

	putLocalInfo()

	ev := ClusterEvent{event: EV_REFRESH_CONTAINERS}
	ClusterEventChan <- &ev
}

var clusterFailed bool = false

func leadChangeHandler(newLead, oldLead string) {
	log.WithFields(log.Fields{"newLead": newLead, "oldLead": oldLead}).Info("")
	if shouldExit() {
		return
	}
	if newLead == "" {
		leadAddr = ""
		clusterFailed = true
		cluster.PauseAllWatchers(true)
	} else {
		leadAddr = newLead
		if clusterFailed {
			clusterFailed = false
			uploadCurrentInfo()
			if bench != nil {
				if Host.CapDockerBench {
					bench.RerunDocker(false)
				}
				if Host.CapKubeBench {
					bench.RerunKube("", "", false)
				}
			}
			cluster.ResumeAllWatchers()
		}
	}
}

func getControllerFromCluster(ip string) *share.CLUSController {
	store := share.CLUSControllerStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			var ctrl share.CLUSController
			if dbgError := json.Unmarshal(value, &ctrl); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if ctrl.ClusterIP == ip {
				return &ctrl
			}
		} else {
			log.WithFields(log.Fields{"err": err}).Debug("")
		}
	}
	return nil
}

func getLeadGRPCEndpoint() string {
	// Assume leadGrpcPort is not changed, so we only grab it once
	if leadGrpcPort == 0 {
		if ctrler := getControllerFromCluster(leadAddr); ctrler != nil {
			leadGrpcPort = ctrler.RPCServerPort
		}
	}
	if leadAddr == "" || leadGrpcPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%v", leadAddr, leadGrpcPort)
}

func clusterLoop(existing utils.Set) {
	// Remove non-existing containers from cluster
	keys, _ := cluster.GetStoreKeys(share.CLUSWorkloadHostStore(Host.ID))
	txn := cluster.Transact()
	for _, key := range keys {
		if !existing.Contains(share.CLUSWorkloadKey2ID(key)) {
			txn.Delete(key)
		}
	}

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Remove workloads")
	}
	txn.Close()

	// Start event loop first so existing containers can be posted
	go func() {
		for {
			if shouldExit() {
				log.Info("Exit cluster worker")
				break
			}
			ev := <-ClusterEventChan
			if ev.event != EV_CLUSTER_EXIT {
				clusterEventHandler(ev)
			}
		}

		logAgent(share.CLUSEvAgentStop)
		evqueue.Flush()

		// Delete agent info only, keep the host so when the new agent starts
		// on the same host, network connection info can be retained.
		deleteAgentInfo()
		leaveCluster()
	}()

	sorted := sortContainerByNetMode(existing)

	// Update existing containers to cluster.
	go func() {
		for _, info := range sorted {
			log.WithFields(log.Fields{"id": info.ID, "name": info.Name}).Info()
			task := ContainerTask{task: TASK_ADD_CONTAINER, id: info.ID, info: info}
			ContainerTaskChan <- &task
		}

		// At this time, local container and devices info has been processed, corresponding
		// container tasks have been enqueued. Now, we can start listening config and diagnose
		// command, because they can only applied to known objects.
		cluster.RegisterStoreWatcher(share.CLUSUniconfTargetStore(Host.ID), uniconfHandler, false)
		cluster.RegisterStoreWatcher(share.CLUSNetworkStore, systemUpdateHandler, false)
		cluster.RegisterStoreWatcher(share.CLUSNodeRulesKey(Host.ID), systemUpdateHandler, false)
		cluster.RegisterStoreWatcher(share.CLUSNodeCommonProfileStore, systemUpdateHandler, agentEnv.kvCongestCtrl)
		cluster.RegisterStoreWatcher(share.CLUSNodeProfileStoreKey(Host.ID), systemUpdateHandler, agentEnv.kvCongestCtrl)
		cluster.RegisterStoreWatcher(share.CLUSConfigDomainStore, domainConfigUpdate, false)
	}()
}

func closeCluster() {
	cluster.PauseAllWatchers(true)

	if len(ClusterEventChan) == 0 {
		ev := ClusterEvent{event: EV_CLUSTER_EXIT}
		ClusterEventChan <- &ev
	}
}
