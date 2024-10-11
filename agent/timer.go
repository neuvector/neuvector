package main

// #include "../defs.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

type threatLog struct {
	mac  net.HardwareAddr
	slog *share.CLUSThreatLog
}

var threatLogCache []*threatLog
var incidentLogCache []*share.CLUSIncidentLog
var connectionMap map[string]*dp.Connection = make(map[string]*dp.Connection)
var incidentMutex sync.Mutex
var threatMutex sync.Mutex
var connectionMutex sync.Mutex
var connsCache []*dp.ConnectionData
var connsCacheMutex sync.Mutex
var auditLogCache []*share.CLUSAuditLog
var auditMutex sync.Mutex
var fqdnIpCache []*share.CLUSFqdnIp
var fqdnIpMutex sync.Mutex
var ipFqdnStorageCache map[string]string = make(map[string]string)
var ipFqdnStorageMutex sync.Mutex

const reportInterval uint32 = 5
const statsInterval uint32 = 5
const runStateInterval uint32 = 120
const runFastStateInterval uint32 = 20

var connectReportInterval uint32 = reportInterval
var reportTick uint32 = 0
var nextConnectReportTick uint32 = reportInterval

// /
const memoryRecyclePeriod uint32 = 10                       // minutes
const memoryCheckPeriod uint32 = 5                          // minutes
const memEnforcerMediumPeak uint64 = 3 * 512 * 1024 * 1024  // 1.5 GB
const memEnforcerTopPeak uint64 = 2 * memEnforcerMediumPeak // 3.0 GB
const memSafeGap uint64 = 64 * 1024 * 1024                  // 64 MB
var memStatsEnforcerResetMark uint64 = memEnforcerTopPeak - memSafeGap

func statsLoop(bPassiveContainerDetect bool) {
	statsTicker := time.Tick(time.Second * time.Duration(statsInterval))
	memStatsTicker := time.NewTicker(time.Minute * time.Duration(memoryRecyclePeriod))
	memCheckTicker := time.NewTicker(time.Minute * time.Duration(memoryCheckPeriod))

	agentEnv.memoryLimit = memEnforcerTopPeak
	if limit, err := global.SYS.GetContainerMemoryLimitUsage(agentEnv.cgroupMemory); err == nil && limit > 0 {
		agentEnv.memoryLimit = limit
	}
	agentEnv.snapshotMemStep = agentEnv.memoryLimit / 10
	memSnapshotMark := agentEnv.memoryLimit * 3 / 5          // 60% as starting point
	memStatsEnforcerResetMark = agentEnv.memoryLimit * 3 / 4 // 75% as starting point
	if agentEnv.autoProfieCapture > 1 {
		var mark uint64 = (uint64)(agentEnv.autoProfieCapture * 1024 * 1024) // into mega bytes
		memSnapshotMark = mark * 3 / 5
		agentEnv.snapshotMemStep = mark / 10
	}

	if agentEnv.autoProfieCapture > 0 {
		log.WithFields(log.Fields{"Step": agentEnv.snapshotMemStep, "Snapshot_At": memSnapshotMark}).Info("Memory Snapshots")
	} else {
		memCheckTicker.Stop()
	}
	if agentEnv.runWithController { // effctive by the enforcer alone
		memStatsTicker.Stop()
	} else {
		log.WithFields(log.Fields{"Controlled_Limit": agentEnv.memoryLimit, "Controlled_At": memStatsEnforcerResetMark}).Info("Memory Resource")
		go func() {
			if err := global.SYS.MonitorMemoryPressureEvents(memStatsEnforcerResetMark, memoryPressureNotification); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Runtime: MonitorMemoryPressureEvents Failed")
			}
		}()
	}

	stateTimerInterval := runStateInterval
	if bPassiveContainerDetect {
		stateTimerInterval = runFastStateInterval
	}
	runStateTicker := time.Tick(time.Second * time.Duration(stateTimerInterval))

	for {
		select {
		case <-statsTicker:
			system, _ := global.SYS.GetHostCPUUsage()
			gInfoRLock()
			updateAgentStats(system)
			updateContainerStats(system)
			gInfoRUnlock()
		case <-runStateTicker:
			// Check container periodically in case container removal event is missed.
			existing, stops := global.RT.ListContainerIDs()
			gInfoRLock()
			gone := gInfo.allContainers.Difference(existing)
			creates := existing.Difference(gInfo.allContainers)
			gInfoRUnlock()
			if stops != nil {
				// differentiate from active containers
				for id := range stops.Iter() {
					cid := id.(string)
					if _, ok := gInfoReadActiveContainer(cid); !ok {
						stops.Remove(cid)
					}
				}
			}

			if stops != nil {
				for id := range stops.Iter() {
					log.WithFields(log.Fields{"id": id.(string)}).Debug("Found stop container")
					task := ContainerTask{task: TASK_STOP_CONTAINER, id: id.(string)}
					ContainerTaskChan <- &task
				}
			}
			for id := range gone.Iter() {
				log.WithFields(log.Fields{"id": id.(string)}).Debug("Found non-existent container")
				task := ContainerTask{task: TASK_DEL_CONTAINER, id: id.(string)}
				ContainerTaskChan <- &task
			}
			for id := range creates.Iter() {
				log.WithFields(log.Fields{"id": id.(string)}).Debug("Found new container")
				task := ContainerTask{task: TASK_ADD_CONTAINER, id: id.(string)}
				ContainerTaskChan <- &task
			}
			gone.Clear()
			creates.Clear()
			gone, creates = nil, nil
		case <-memStatsTicker.C:
			if mStats, err := global.SYS.GetContainerMemoryStats(); err == nil && mStats.WorkingSet > memStatsEnforcerResetMark {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				agentMem := m.TotalAlloc
				if mStats.WorkingSet > memEnforcerMediumPeak && ((mStats.WorkingSet - agentMem) > 2*agentMem) { // the gap is greater
					global.SYS.ReCalculateMemoryMetrics(memEnforcerMediumPeak)
				} else {
					global.SYS.ReCalculateMemoryMetrics(memStatsEnforcerResetMark)
				}
			}
		case <-memCheckTicker.C:
			if mStats, err := global.SYS.GetContainerMemoryStats(); err == nil && mStats.WorkingSet > memSnapshotMark {
				memorySnapshot(mStats.WorkingSet)
			}
		}
	}
}

func timerLoop() {
	ticker := time.Tick(time.Second * time.Duration(reportInterval))
	for {
		<-ticker
		go writeCluster()
	}
}

func writeCluster() {
	reportTick += reportInterval

	putThreatLogs()
	putFqdnIps()
	updateConnection()
	putConnections()
	putIncidentLogs()
	putAuditLogs()
	reportLearnedProcess()
	evqueue.Flush()
}

func dpTaskCallback(task *dp.DPTask) {
	switch task.Task {
	case dp.DP_TASK_THREAT_LOG:
		threatMutex.Lock()
		threatLogCache = append(threatLogCache, &threatLog{mac: task.MAC, slog: task.SecLog})
		threatMutex.Unlock()
	case dp.DP_TASK_FQDN_IP:
		fqdnIpMutex.Lock()
		fqdnIpCache = append(fqdnIpCache, task.Fqdns)
		fqdnIpMutex.Unlock()
	case dp.DP_TASK_IP_FQDN_STORAGE_UPDATE:
		ipFqdnStorageMutex.Lock()
		ip := task.FqdnStorageUpdate.IP.String()
		name := task.FqdnStorageUpdate.Name
		ipFqdnStorageCache[ip] = name
		ipFqdnStorageMutex.Unlock()
	case dp.DP_TASK_IP_FQDN_STORAGE_RELEASE:
		ipFqdnStorageMutex.Lock()
		ip := task.FqdnStorageRelease.String()
		delete(ipFqdnStorageCache, ip)
		ipFqdnStorageMutex.Unlock()
	case dp.DP_TASK_CONNECTION:
		connsCacheMutex.Lock()
		connsCache = append(connsCache, task.Connects...)
		connsCacheMutex.Unlock()
	case dp.DP_TASK_HOST_CONNECTION:
		updateHostConnection(task.Connects)
	case dp.DP_TASK_APPLICATION:
		ctask := ContainerTask{task: TASK_APP_UPDATE_FROM_DP, mac: task.MAC, apps: task.Apps}
		select {
		case ContainerTaskChan <- &ctask:
		default:
			log.WithFields(log.Fields{"len": len(ContainerTaskChan)}).Info("Container Task chan full")
		}
	}
}

func updateAgentStats(cpuSystem uint64) {
	var mem, cpu uint64 = 0, 0
	if agentEnv.cgroupMemory != "" {
		mem, _ = global.SYS.GetContainerMemoryUsage(agentEnv.cgroupMemory)
	}
	if agentEnv.cgroupCPUAcct != "" {
		cpu, _ = global.SYS.GetContainerCPUUsage(agentEnv.cgroupCPUAcct)
	}
	system.UpdateStats(&gInfo.agentStats, mem, cpu, cpuSystem)
}

func updateContainerStats(cpuSystem uint64) {
	for _, c := range gInfo.activeContainers {
		var mem, cpu uint64 = 0, 0
		if c.cgroupMemory != "" {
			mem, _ = global.SYS.GetContainerMemoryUsage(c.cgroupMemory)
		}
		if c.cgroupCPUAcct != "" {
			cpu, _ = global.SYS.GetContainerCPUUsage(c.cgroupCPUAcct)
		}
		system.UpdateStats(&c.stats, mem, cpu, cpuSystem)
	}
}

// -- fqdn->ips mapping

func putFqdnIps() {
	fqdnIpMutex.Lock()
	fqdnips := fqdnIpCache
	fqdnIpCache = nil
	fqdnIpMutex.Unlock()

	for _, fqdnip := range fqdnips {
		key := share.CLUSFqdnIpKey(Host.ID, fqdnip.FqdnName)
		value, _ := json.Marshal(fqdnip)
		zb := utils.GzipBytes(value)
		log.WithFields(log.Fields{"key": key, "fqdnip": fqdnip}).Debug("Put fqdn ip")
		if err := cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
		}
	}
}

// -- threats

func putThreatLogs() {
	threatMutex.Lock()
	tmp := threatLogCache
	threatLogCache = nil
	threatMutex.Unlock()

	tlogs := make([]*share.CLUSThreatLog, 0)
	for _, tl := range tmp {
		if c := getContainerByMAC(tl.mac); c != nil {
			tl.slog.HostID = Host.ID
			tl.slog.HostName = Host.Name
			tl.slog.AgentID = Agent.ID
			tl.slog.AgentName = Agent.Name
			tl.slog.WorkloadID = c.id
			tl.slog.WorkloadName = c.name
			if tl.slog.PktIngress {
				tl.slog.LocalPeer = isLocalHostIP(tl.slog.SrcIP)
			} else {
				tl.slog.LocalPeer = isLocalHostIP(tl.slog.DstIP)
			}
			tlogs = append(tlogs, tl.slog)
		}
	}

	if len(tlogs) > 0 {
		key := share.CLUSThreatLogKey(Host.ID, Agent.ID)
		value, _ := json.Marshal(tlogs)
		zb := utils.GzipBytes(value)
		log.WithFields(log.Fields{"key": key}).Debug("Put threat log")
		if err := cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
		}
	}
}

// -- incidents
func putIncidentLogs() {
	incidentMutex.Lock()
	tmp := incidentLogCache
	incidentLogCache = nil
	incidentMutex.Unlock()

	if len(tmp) > 0 {
		key := share.CLUSIncidentLogKey(Host.ID, Agent.ID)
		value, _ := json.Marshal(tmp)
		zb := utils.GzipBytes(value)
		log.WithFields(log.Fields{"key": key, "len": len(tmp)}).Debug("Put incident log")
		if err := cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
		}
	}
}

// -- audit
func putAuditLogs() {
	auditMutex.Lock()
	tmp := auditLogCache
	auditLogCache = nil
	auditMutex.Unlock()

	if len(tmp) > 0 {
		key := share.CLUSAuditLogKey(Host.ID, Agent.ID)
		value, _ := json.Marshal(tmp)
		zb := utils.GzipBytes(value)
		log.WithFields(log.Fields{"key": key, "len": len(tmp)}).Debug("Put audit log")
		if err := cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
		}
	}
}

// -- connections

const connectionMapMax int = 2048 * 16

func keyTCPUDPConnection(conn *dp.Connection) string {
	return fmt.Sprintf("%v-%v-%v-%v-%v-%v-%v",
		conn.ClientIP, conn.ServerIP, conn.ServerPort, conn.IPProto, conn.Ingress, conn.PolicyId, conn.Application)
}

func keyOtherConnection(conn *dp.Connection) string {
	return fmt.Sprintf("%v-%v-%v-%v-%v",
		conn.ClientIP, conn.ServerIP, conn.Ingress, conn.PolicyId, conn.Application)
}

func updateConnection() {
	connsCacheMutex.Lock()
	conns := connsCache
	connsCache = nil
	connsCacheMutex.Unlock()

	for _, data := range conns {
		conn := data.Conn
		//dp will set clientport if the dns session is too large
		if c := getContainerByMAC(data.EPMAC); c != nil {
			conn.AgentID = Agent.ID
			conn.HostID = Host.ID
			if conn.ClientPort != 0 {
				var cport share.CLUSProtoPort
				if conn.Ingress {
					cport = share.CLUSProtoPort{
						Port:    conn.ServerPort,
						IPProto: conn.IPProto,
					}
				} else {
					cport = share.CLUSProtoPort{
						Port:    conn.ClientPort,
						IPProto: conn.IPProto,
					}
				}
				ids := []string{c.id}

				// get the child container too
				gInfoRLock()
				for id, con := range gInfo.activeContainers {
					if _, parent := getSharedContainerWithLock(con.info); parent != nil && parent.id == c.id {
						ids = append(ids, id)
					}
				}
				gInfoRUnlock()

				if found := prober.CheckDNSTunneling(ids, cport, conn.ClientIP,
					conn.ServerIP, conn.ClientPort, conn.ServerPort); found {
					conn.Severity = C.THRT_SEVERITY_CRITICAL
					conn.ThreatID = C.THRT_ID_DNS_TUNNELING
				}
			}
			updateConnectionMap(conn, data.EPMAC, c.id)
		}
	}
}

func updateSidecarConnection(conn *dp.Connection, id string) {
	if c, ok := gInfoReadActiveContainer(id); ok {
		for podID := range c.pods.Iter() {
			if pod, ok := gInfoReadActiveContainer(podID.(string)); ok {
				if pod.info.Sidecar {
					if conn.Ingress {
						conn.ClientWL = podID.(string)
					} else {
						conn.ServerWL = podID.(string)
					}
					for port := range pod.appMap {
						if conn.ServerPort == port.Port && conn.IPProto == port.IPProto {
							conn.ToSidecar = true
						}
					}
					break
				}
			}
		}
	}
}

func realSameConn(entry *dp.Connection, proxyMeshMac bool) bool {
	if !proxyMeshMac {
		if entry.Network != share.NetworkProxyMesh {
			return true
		}
	} else {
		if entry.Network == share.NetworkProxyMesh {
			return true
		}
	}
	return false
}

func updateConnectionMap(conn *dp.Connection, EPMAC net.HardwareAddr, id string) {
	connectionMutex.Lock()
	defer connectionMutex.Unlock()

	var key string
	if conn.IPProto == syscall.IPPROTO_TCP || conn.IPProto == syscall.IPPROTO_UDP {
		key = keyTCPUDPConnection(conn)
	} else {
		key = keyOtherConnection(conn)
	}

	var proxyMeshMac bool = false
	if strings.Contains(EPMAC.String(), container.KubeProxyMeshLoMacPrefix) {
		proxyMeshMac = true
	}

	/*
	 * With service mesh, egress connection on eth0 and lo i/f can collide,
	 * we add additional check to prevent collision from happening.
	 */
	if entry, exist := connectionMap[key]; exist && realSameConn(entry, proxyMeshMac) {
		entry.Bytes += conn.Bytes
		entry.Sessions += conn.Sessions
		entry.Violates += conn.Violates
		if entry.LastSeenAt <= conn.LastSeenAt {
			entry.LastSeenAt = conn.LastSeenAt
			entry.PolicyAction = conn.PolicyAction
			entry.PolicyId = conn.PolicyId
		}
		if entry.Severity < conn.Severity {
			entry.Severity = conn.Severity
			entry.ThreatID = conn.ThreatID
		}

		connLog.WithFields(log.Fields{"connection": entry, "mac": EPMAC.String()}).Debug("")
	} else if len(connectionMap) < connectionMapMax || conn.PolicyAction > C.DP_POLICY_ACTION_CHECK_APP {
		if conn.Ingress {
			conn.ServerWL = id
			conn.Scope, conn.Network = getIPAddrScope(EPMAC, conn.ServerIP)
			conn.LocalPeer = isLocalHostIP(conn.ClientIP)
		} else {
			conn.ClientWL = id
			conn.Scope, conn.Network = getIPAddrScope(EPMAC, conn.ClientIP)
			conn.LocalPeer = isLocalHostIP(conn.ServerIP)
		}
		if proxyMeshMac {
			conn.Network = share.NetworkProxyMesh
			updateSidecarConnection(conn, id)
		}
		connectionMap[key] = conn

		connLog.WithFields(log.Fields{"connection": conn, "mac": EPMAC.String()}).Debug("")
	} else {
		log.WithFields(log.Fields{
			"conn": *conn, "len": len(connectionMap),
		}).Info("Connection map full -- drop")
	}
}

func updateHostConnection(conns []*dp.ConnectionData) {
	if gInfo.disableNetPolicy {
		return
	}
	for _, data := range conns {
		conn := data.Conn

		var id *string
		if conn.Ingress {
			id = &conn.ServerWL
		} else {
			id = &conn.ClientWL
		}

		// To be consistent with non-host-mode platform container, ignore the connection reprot
		c, ok := gInfoReadActiveContainer(*id)
		if !ok {
			continue
		} else if c.parentNS != "" {
			*id = c.parentNS
			if c, ok = gInfoReadActiveContainer(*id); !ok {
				log.WithFields(log.Fields{
					"wlID": *id,
				}).Error("cannot find parent container")
				continue
			}
		}
		if c.pid != 0 && !c.hasDatapath {
			continue
		}

		conn.AgentID = Agent.ID
		conn.HostID = Host.ID
		conn.Scope = share.CLUSIPAddrScopeLocalhost

		var key string
		if conn.IPProto == syscall.IPPROTO_TCP || conn.IPProto == syscall.IPPROTO_UDP {
			key = keyTCPUDPConnection(conn)
		} else {
			key = keyOtherConnection(conn)
		}

		connectionMutex.Lock()
		if entry, ok := connectionMap[key]; ok {
			entry.Bytes += conn.Bytes
			entry.Sessions += conn.Sessions
			entry.Violates += conn.Violates
			if entry.LastSeenAt <= conn.LastSeenAt {
				entry.LastSeenAt = conn.LastSeenAt
				entry.PolicyAction = conn.PolicyAction
				entry.PolicyId = conn.PolicyId
			}

			connLog.WithFields(log.Fields{"connection": conn}).Debug("")
		} else if len(connectionMap) < connectionMapMax {
			connectionMap[key] = conn
			connLog.WithFields(log.Fields{"connection": conn}).Debug("")
		} else {
			connLog.WithFields(log.Fields{
				"conn": conn, "len": len(connectionMap),
			}).Info("Connection map full -- drop")
		}
		connectionMutex.Unlock()
	}
}

// Max number of entries to transmit at one time.
const connectionListMax int = 2048 * 4

func conn2CLUS(c *dp.Connection) *share.CLUSConnection {
	fqdn := ""
	ipFqdnStorageMutex.Lock()
	if c.ExternalPeer && len(ipFqdnStorageCache) > 0 {
		if name, ok := ipFqdnStorageCache[net.IP(c.ServerIP).String()]; ok {
			fqdn = name
		}
	}
	ipFqdnStorageMutex.Unlock()

	return &share.CLUSConnection{
		AgentID:      c.AgentID,
		HostID:       c.HostID,
		ClientWL:     c.ClientWL,
		ServerWL:     c.ServerWL,
		ClientIP:     c.ClientIP,
		ServerIP:     c.ServerIP,
		Scope:        c.Scope,
		Network:      c.Network,
		ClientPort:   uint32(c.ClientPort),
		ServerPort:   uint32(c.ServerPort),
		IPProto:      uint32(c.IPProto),
		Application:  c.Application,
		Bytes:        c.Bytes,
		Sessions:     c.Sessions,
		FirstSeenAt:  c.FirstSeenAt,
		LastSeenAt:   c.LastSeenAt,
		ThreatID:     c.ThreatID,
		Severity:     uint32(c.Severity),
		PolicyAction: uint32(c.PolicyAction),
		Ingress:      c.Ingress,
		ExternalPeer: c.ExternalPeer,
		LocalPeer:    c.LocalPeer,
		PolicyId:     c.PolicyId,
		Violates:     c.Violates,
		LogUID:       uuid.New().String(),
		Xff:          c.Xff,
		SvcExtIP:     c.SvcExtIP,
		ToSidecar:    c.ToSidecar,
		MeshToSvr:    c.MeshToSvr,
		LinkLocal:    c.LinkLocal,
		TmpOpen:      c.TmpOpen,
		UwlIp:        c.UwlIp,
		FQDN:         fqdn,
		EpSessCurIn:  c.EpSessCurIn,
		EpSessIn12:   c.EpSessIn12,
		EpByteIn12:   c.EpByteIn12,
		Nbe:          c.Nbe,
		NbeSns:       c.NbeSns,
	}
}

func putConnections() {
	var list []*dp.Connection
	var keys []string

	if reportTick < nextConnectReportTick {
		return
	}

	connectionMutex.Lock()
	for key, conn := range connectionMap {
		list = append(list, conn)
		keys = append(keys, key)
		delete(connectionMap, key)

		if len(list) == connectionListMax {
			break
		}
	}
	connectionMutex.Unlock()

	if len(list) > 0 {
		conns := make([]*share.CLUSConnection, len(list))
		for i, c := range list {
			conns[i] = conn2CLUS(c)
		}

		resp, err := sendConnections(conns)
		if err != nil {
			connLog.WithFields(log.Fields{"error": err}).Error("Failed to send connections")
		}

		if (resp != nil && resp.Action == share.ReportRespAction_Resend) || err != nil {
			var keep int
			connectionMutex.Lock()
			if len(connectionMap)+len(list) <= connectionMapMax {
				keep = len(list)
			} else {
				keep = connectionMapMax - len(connectionMap)
				log.WithFields(log.Fields{"drops": len(list) - keep}).Info("Connection map full -- drop")
			}
			for i, conn := range list[:keep] {
				connectionMap[keys[i]] = conn
			}
			connectionMutex.Unlock()
		}
		if resp != nil && resp.ReportInterval != 0 && connectReportInterval != resp.ReportInterval {
			connLog.WithFields(log.Fields{"interval": resp.ReportInterval}).Debug("report interval changed")
			connectReportInterval = resp.ReportInterval
		}
	}

	nextConnectReportTick += connectReportInterval
}
