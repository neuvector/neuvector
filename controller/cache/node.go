package cache

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

const updateAgent int = 0x1
const updateCtrl int = 0x2

const disconnectRemovalDelay = time.Duration(time.Second * 180)
const deleteRemovalDelay = time.Duration(time.Second * 1)
const hostRemovalDelay = time.Duration(time.Second * 600)

func ClusterMemberStateUpdateHandler(nType cluster.ClusterNotifyType, member string, agentId string) {
	memberStateUpdateHandler(nType, member, agentId, updateAgent|updateCtrl)
}

func agentStopEventHandler(ev *share.CLUSEventLog) {
	// respond to agent stop event explicitly (instead of waiting for consul
	// detection) so that agent record can be removed quickly. Check the time
	// to avoid responding to past event for multi-controller case
	var notify bool = false
	cacheMutexRLock()
	if cache, ok := agentCacheMap[ev.AgentID]; ok {
		if ev.ReportedAt.After(cache.agent.JoinedAt) {
			notify = true
		}
	}
	cacheMutexRUnlock()

	if notify {
		memberStateUpdateHandler(cluster.ClusterNotifyDelete, "", ev.AgentID, updateAgent)
	}
}

type agentDisconnectEvent struct {
	hostID  string
	agentID string
}

type controllerDisconnectEvent struct {
	hostID    string
	ctrlID    string
	clusterIP string
}

type hostRemovalEvent struct {
	hostID string
}

func (p *agentDisconnectEvent) Expire() {
	log.WithFields(log.Fields{"HostID": p.hostID, "AgentID": p.agentID}).Info()

	cacheMutexLock()
	defer cacheMutexUnlock()
	if ac := agentCacheMap[p.agentID]; ac != nil {
		if ac.state == api.StateOnline {
			log.WithFields(log.Fields{"agentID": p.agentID}).Info("state is online")
			ac.timerTask = ""
			return
		}
		// Mark the state to prevent delete failure due to lead change
		ac.state = api.StateLeft
		deleteAgentFromCluster(p.hostID, p.agentID)
	}
}

func (p *controllerDisconnectEvent) Expire() {
	log.WithFields(log.Fields{"HostID": p.hostID, "ctrlID": p.ctrlID}).Info()
	cacheMutexLock()
	defer cacheMutexUnlock()
	if cc := ctrlCacheMap[p.ctrlID]; cc != nil {
		if cc.state == api.StateOnline {
			log.WithFields(log.Fields{"ctrlID": p.ctrlID}).Info("state is online")
			cc.timerTask = ""
			return
		}
		// Mark the state to prevent delete failure due to lead change
		cc.state = api.StateLeft
		deleteControllerFromCluster(p.hostID, p.ctrlID, p.clusterIP)
	}
}

func (p *hostRemovalEvent) Expire() {
	log.WithFields(log.Fields{"HostID": p.hostID}).Info()
	cacheMutexLock()
	defer cacheMutexUnlock()
	if cache, ok := hostCacheMap[p.hostID]; ok {
		if cache.agents.Cardinality() != 0 {
			log.WithFields(log.Fields{"count": cache.agents.Cardinality}).Info("host has agent")
			cache.timerTask = ""
			cache.state = api.StateOnline
			cache.timerSched = time.Time{}
			return
		}
		// Mark the state to prevent delete failure due to lead change
		cache.state = api.StateLeft
		deleteHostFromCluster(p.hostID)
	}
}

// Protected by cacheMutexLock
func scheduleHostRemoval(cache *hostCache) {
	log.WithFields(log.Fields{
		"host": cache.host.ID, "timer": hostRemovalDelay,
	}).Info("Schedule host removal")

	markWorkloadState(cache.workloads, api.StateUnmanaged)
	cache.state = api.StateUnmanaged
	if cache.timerTask != "" {
		log.WithFields(log.Fields{"host": cache.host.ID, "sched": cache.timerSched}).Info("Already scheduled")
		// TODO: for some reason, host expire doesn't always kick in, so we remove the node forcefully.
		if !cache.timerSched.IsZero() && time.Since(cache.timerSched) > hostRemovalDelay {
			log.WithFields(log.Fields{"host": cache.host.ID}).Info("Force remove the host")
			cache.state = api.StateLeft
			_ = cctx.TimerWheel.RemoveTask(cache.timerTask)
			deleteHostFromCluster(cache.host.ID)
		}
		return
	}

	task := &hostRemovalEvent{
		hostID: cache.host.ID,
	}
	cache.timerTask, _ = cctx.TimerWheel.AddTask(task, hostRemovalDelay)
	if cache.timerTask == "" {
		log.Error("Fail to insert timer")
	} else {
		cache.timerSched = time.Now()
	}
}

// Protected by cacheMutexLock
func cancelHostRemoval(cache *hostCache) {
	markWorkloadState(cache.workloads, api.StateOnline)
	cache.state = api.StateOnline
	if cache.timerTask != "" {
		log.WithFields(log.Fields{
			"host": cache.host.ID,
		}).Info("cancel host removal")
		_ = cctx.TimerWheel.RemoveTask(cache.timerTask)
		cache.timerTask = ""
		cache.timerSched = time.Time{}
	}
}

func memberStateUpdateHandler(nType cluster.ClusterNotifyType, member string, agentId string, flag int) {
	var ac *agentCache
	var cc *ctrlCache

	log.WithFields(log.Fields{
		"member": member, "agentID": agentId, "notify": cluster.ClusterNotifyName[nType], "flag": flag,
	}).Info()

	cacheMutexLock()
	if (flag & updateAgent) > 0 {
		if agentId == "" {
			for _, cache := range agentCacheMap {
				if cache.agent.ClusterIP == member {
					ac = cache
					break
				}
			}
		} else {
			ac = agentCacheMap[agentId]
		}
	}

	if (flag & updateCtrl) > 0 {
		if agentId == "" {
			for _, cache := range ctrlCacheMap {
				if cache.ctrl.ClusterIP == member {
					cc = cache
					break
				}
			}
		} else {
			cc = ctrlCacheMap[agentId]
		}
	}
	cacheMutexUnlock()

	if ac != nil {
		switch nType {
		case cluster.ClusterNotifyStateOnline:
			cacheMutexLock()
			if ac.state == api.StateOnline {
				cacheMutexUnlock()
				break
			}

			if ac.state == api.StateOffline {
				logAgentEvent(share.CLUSEvAgentConnect, ac.agent, "")
			}
			ac.state = api.StateOnline
			ac.joinAt = time.Now().UTC()

			evhdls.Trigger(EV_AGENT_ONLINE, ac.agent.ID, ac)

			if ac.timerTask != "" {
				log.Debug("remove old timer")
				_ = cctx.TimerWheel.RemoveTask(ac.timerTask)
				ac.timerTask = ""
			}

			cacheMutexUnlock()

		case cluster.ClusterNotifyStateOffline:
			cacheMutexLock()
			if ac.state == api.StateOffline || ac.state == api.StateLeft {
				cacheMutexUnlock()
				break
			}
			ac.state = api.StateOffline
			ac.disconnAt = time.Now().UTC()
			logAgentEvent(share.CLUSEvAgentDisconnect, ac.agent, "")

			evhdls.Trigger(EV_AGENT_OFFLINE, ac.agent.ID, ac)

			log.WithFields(log.Fields{
				"agent": ac.agent.ID, "timer": disconnectRemovalDelay,
			}).Info("Schedule agent removal")

			task := &agentDisconnectEvent{
				hostID:  ac.agent.HostID,
				agentID: ac.agent.ID,
			}
			ac.timerTask, _ = cctx.TimerWheel.AddTask(task, disconnectRemovalDelay)
			if ac.timerTask == "" {
				log.Error("Fail to insert timer")
			}

			cacheMutexUnlock()
		case cluster.ClusterNotifyDelete:
			cacheMutexLock()
			if ac.state == api.StateLeft {
				cacheMutexUnlock()
				break
			}
			ac.state = api.StateLeft

			evhdls.Trigger(EV_AGENT_OFFLINE, ac.agent.ID, ac)

			if ac.timerTask != "" {
				log.Debug("remove old timer")
				_ = cctx.TimerWheel.RemoveTask(ac.timerTask)
				ac.timerTask = ""
			}

			log.WithFields(log.Fields{
				"agent": ac.agent.ID, "timer": deleteRemovalDelay,
			}).Info("Schedule agent removal")

			task := &agentDisconnectEvent{
				hostID:  ac.agent.HostID,
				agentID: ac.agent.ID,
			}
			ac.timerTask, _ = cctx.TimerWheel.AddTask(task, deleteRemovalDelay)
			if ac.timerTask == "" {
				log.Error("Fail to insert timer")
			}

			cacheMutexUnlock()
		}
	}

	if cc != nil {
		cacheMutexLock()
		defer cacheMutexUnlock()

		switch nType {
		case cluster.ClusterNotifyStateOnline:
			if cc.state == api.StateOnline {
				break
			}
			cc.state = api.StateOnline
			cc.joinAt = time.Now().UTC()
			logControllerEvent(share.CLUSEvControllerConnect, cc.ctrl, "")

			if cc.timerTask != "" {
				log.Debug("remove old cc timer")
				_ = cctx.TimerWheel.RemoveTask(cc.timerTask)
				cc.timerTask = ""
			}

		case cluster.ClusterNotifyStateOffline:
			if cc.state == api.StateOffline || cc.state == api.StateLeft {
				break
			}
			cc.state = api.StateOffline
			cc.disconnAt = time.Now().UTC()
			logControllerEvent(share.CLUSEvControllerDisconnect, cc.ctrl, "")

			log.WithFields(log.Fields{
				"controller": cc.ctrl.ID, "timer": disconnectRemovalDelay,
			}).Info("Schedule controller removal")

			task := &controllerDisconnectEvent{
				hostID:    cc.ctrl.HostID,
				ctrlID:    cc.ctrl.ID,
				clusterIP: cc.ctrl.ClusterIP,
			}
			cc.timerTask, _ = cctx.TimerWheel.AddTask(task, disconnectRemovalDelay)
			if cc.timerTask == "" {
				log.Error("Fail to insert cc timer")
			}

		case cluster.ClusterNotifyDelete:
			// If controller leaves gracefully, the entry will be deleted
			// by the controller. If not, let it be for now.
			if cc.state == api.StateLeft {
				break
			}
			cc.state = api.StateLeft

			if cc.timerTask != "" {
				log.Debug("remove old cc timer")
				_ = cctx.TimerWheel.RemoveTask(cc.timerTask)
				cc.timerTask = ""
			}

			log.WithFields(log.Fields{
				"controller": cc.ctrl.ID, "timer": deleteRemovalDelay,
			}).Info("Schedule controller removal")

			task := &controllerDisconnectEvent{
				hostID:    cc.ctrl.HostID,
				ctrlID:    cc.ctrl.ID,
				clusterIP: cc.ctrl.ClusterIP,
			}
			cc.timerTask, _ = cctx.TimerWheel.AddTask(task, deleteRemovalDelay)
			if cc.timerTask == "" {
				log.Error("Fail to insert cc timer")
			}
		}
	}
}

func deleteHostFromCluster(hostID string) {
	if !isLeader() {
		return
	}

	log.WithFields(log.Fields{"hostID": hostID}).Info()

	store := share.CLUSWorkloadHostStore(hostID)
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		_ = cluster.Delete(key)
	}

	store = share.CLUSNetworkEPHostStore(hostID)
	keys, _ = cluster.GetStoreKeys(store)
	for _, key := range keys {
		_ = cluster.Delete(key)
	}

	//remove wildcard fqdn->ip mapping saved in kv
	fqdn_store := fmt.Sprintf("%s%s/", share.CLUSFqdnIpStore, hostID)
	fqdnkeys, _ := cluster.GetStoreKeys(fqdn_store)
	for _, fqdnkey := range fqdnkeys {
		_ = cluster.Delete(fqdnkey)
	}

	key := share.CLUSHostKey(hostID, "agent")
	_ = cluster.Delete(key)
}

func deleteAgentFromCluster(hostID string, agentID string) {
	if !isLeader() {
		return
	}

	log.WithFields(log.Fields{"hostID": hostID, "enforcer": agentID}).Info()

	key := share.CLUSAgentKey(hostID, agentID)
	_ = cluster.Delete(key)
}

func deleteControllerFromCluster(hostID string, ctrlID string, clusterIP string) {
	if !isLeader() {
		return
	}

	log.WithFields(log.Fields{"hostID": hostID, "controller": ctrlID}).Info()

	key := share.CLUSControllerKey(hostID, ctrlID)
	if err := cluster.Delete(key); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}

	/* Force leave the node to avoid controller node in fail state */
	cluster.ForceLeave(clusterIP, true)
}

func syncLeftNVObjectsToCluster() {
	// When lead change, agent delete caused by old lead leaving might fail
	// due to lead transition. New lead will try to fix them.
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	for _, cache := range agentCacheMap {
		if cache.state == api.StateLeft {
			deleteAgentFromCluster(cache.agent.HostID, cache.agent.ID)
		}
	}

	for _, cache := range ctrlCacheMap {
		if cache.state == api.StateLeft {
			deleteControllerFromCluster(cache.ctrl.HostID,
				cache.ctrl.ID, cache.ctrl.ClusterIP)
		}
	}

	for _, cache := range hostCacheMap {
		if cache.state == api.StateLeft {
			deleteHostFromCluster(cache.host.ID)
		}
	}
}

func cleanHostUnmanagedWorkload() {
	graphMutexLock()
	defer graphMutexUnlock()
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	for _, cache := range hostCacheMap {
		if cache.state != api.StateLeft {
			_connectHostAdd(cache.host)
		}
	}
}

func pruneHost() {
	cacheMutexLock()
	for _, cache := range hostCacheMap {
		if cache.agents.Cardinality() == 0 {
			scheduleHostRemoval(cache)
		}
	}
	cacheMutexUnlock()
}

func syncMemberStateFromCluster() []*share.CLUSController {
	// This way of figuring out failed members loses the precise disconnect
	// time (up to 10 minutes difference) but it is simple comparing to active sync
	// Using this simple method for now unless we really want to be precise
	// on this matter
	nodes := cluster.GetAllMembers()
	// make sure cluster is still healthy
	if len(nodes) == 0 || cacher.leadAddr == "" {
		return nil
	}

	memberStateMap := make(map[string]cluster.ClusterMemberInfo)
	for _, node := range nodes {
		memberStateMap[node.Name] = node
	}

	cs := make([]*share.CLUSController, 0)
	cids := utils.NewSet()
	controllers, _ := clusHelper.GetAllControllers()
	for _, c := range controllers {
		if n, ok := memberStateMap[c.ClusterIP]; !ok || n.Role != cluster.NodeRoleServer {
			log.WithFields(log.Fields{"node": c.ClusterIP}).Debug("ctrl is missing")
			memberStateUpdateHandler(cluster.ClusterNotifyDelete, c.ClusterIP, c.ID, updateCtrl)
		} else if n.State == cluster.NodeStateLeft || n.State == cluster.NodeStateFail {
			log.WithFields(log.Fields{"node": c.ClusterIP}).Debug("ctrl is offline")
			memberStateUpdateHandler(cluster.ClusterNotifyStateOffline, c.ClusterIP, c.ID, updateCtrl)
		} else {
			cs = append(cs, c)
			cids.Add(c.ID)
		}
	}

	agents := clusHelper.GetAllEnforcers()
	for _, a := range agents {
		// Check if it is the enforcer in allinone
		if cids.Contains(a.ID) {
			continue
		}

		if n, ok := memberStateMap[a.ClusterIP]; !ok || n.Role != cluster.NodeRoleClient {
			log.WithFields(log.Fields{"node": a.ClusterIP}).Debug("agent is missing")
			memberStateUpdateHandler(cluster.ClusterNotifyDelete, a.ClusterIP, a.ID, updateAgent)
		} else if n.State == cluster.NodeStateLeft || n.State == cluster.NodeStateFail {
			log.WithFields(log.Fields{"node": a.ClusterIP}).Debug("agent is offline")
			memberStateUpdateHandler(cluster.ClusterNotifyStateOffline, a.ClusterIP, a.ID, updateAgent)
		}
	}

	return cs
}

func AgentAdmissionRequest(req *share.CLUSAdmissionRequest) *share.CLUSAdmissionResponse {
	log.WithFields(log.Fields{
		"host": req.HostID, "id": req.ID,
	}).Info("Receive connect request")

	var ac *agentCache
	var allowConnect bool = true
	var onlineEnforcers int
	var disallowMsg string
	cacheMutexLock()
	if ac = agentCacheMap[req.ID]; ac == nil {
		if host, ok := hostCacheMap[req.HostID]; ok {
			for m := range host.agents.Iter() {
				if ac = agentCacheMap[m.(string)]; ac != nil {
					break
				}
			}
		}
	}

	if ac != nil {
		if isDummyAgentCache(ac) {
			// It's a dummy entry created by other means, and only exists in cache
			// Allow connect as the deletion will happen immediately
			log.WithFields(log.Fields{
				"host": ac.agent.HostID, "agent": ac.agent.ID, "state": ac.state,
			}).Info("Found a dummy existing agent on host")

			if ac.agent.ID != req.ID {
				deleteAgentFromCache(ac)
			} /*else {
				// Dummy with the same agent id - keep the old place holder in case
				// there is data in it
			} */
		} else {
			log.WithFields(log.Fields{
				"host": req.HostID, "agent": ac.agent.ID, "state": ac.state,
			}).Info("Found existing agent on host")

			// A host can only have one enforcer on it, so delete the old one
			if ac.timerTask != "" {
				log.Debug("remove old timer")
				_ = cctx.TimerWheel.RemoveTask(ac.timerTask)
				ac.timerTask = ""
			}
			if ac.agent.ID != req.ID {
				deleteAgentFromCluster(ac.agent.HostID, ac.agent.ID)
				allowConnect = false
				disallowMsg = "Retry connection to the controller."
			}
		}
	} else {
		onlineEnforcers = countOnlineEnforcers()
		allowConnect = isNewAgentAllowed(onlineEnforcers)
		if !allowConnect {
			disallowMsg = "The max. number of allowed enforcers has reached."
		}
	}
	cacheMutexUnlock()

	log.WithFields(log.Fields{"host": req.HostID, "id": req.ID, "allowed": allowConnect, "online": onlineEnforcers}).Info()

	// agent will retry if no allow msg is sent
	if allowConnect {
		return &share.CLUSAdmissionResponse{Allowed: true}
	} else {
		return &share.CLUSAdmissionResponse{Allowed: false, Reason: disallowMsg}
	}
}

// cacheMutex protected
func countOnlineEnforcers() int {
	var n int
	for _, ac := range agentCacheMap {
		if ac.state == api.StateOnline {
			n++
		}
	}
	return n
}

func isNewAgentAllowed(num int) bool {
	return true
}

func rpcAgentOnline(id string, param interface{}) {
	agent := param.(*agentCache).agent
	// Should be OK even when controller and enforcer are running together.
	rpc.CreateEnforcerServerDest(id, agent.ClusterIP, agent.RPCServerPort)
}

func rpcAgentOffline(id string, param interface{}) {
	rpc.RemoveEnforcerServerDest(id)
}
