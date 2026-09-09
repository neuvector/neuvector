package cache

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"net"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/graph"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type groupPair struct {
	from  string
	to    string
	isApp bool
}

type learnedPolicyRule struct {
	fromHost string
	toHost   string
	objs     utils.Set
}

// As both are learned apps, assume a1 has not duplication and either contains 'any'
func cmpLearnedApps(a1 []uint32, a2 utils.Set) bool {
	if len(a1) != a2.Cardinality() {
		return false
	}

	for _, a := range a1 {
		if !a2.Contains(a) {
			return false
		}
	}

	return true
}

func apps2Slice(appSet utils.Set) []uint32 {
	i := 0
	apps := make([]uint32, appSet.Cardinality())
	for a := range appSet.Iter() {
		if u, ok := a.(uint32); ok {
			apps[i] = u
			i++
		}
	}
	return apps
}

func ports2Slice(portSet utils.Set) []string {
	i := 0
	ports := make([]string, portSet.Cardinality())
	for p := range portSet.Iter() {
		if s, ok := p.(string); ok {
			ports[i] = s
			i++
		}
	}
	return ports
}

func ports2String(portSet utils.Set) string {
	ports := make([]string, 0)
	for p := range portSet.Iter() {
		if s, ok := p.(string); ok {
			ports = append(ports, s)
		}
	}
	sort.Strings(ports)
	return strings.Join(ports, ",")
}

// remove count entries if the total entries exceeds the max allowed
func removeOldEntries(a *graphAttr, max, count int) bool {
	total := len(a.entries)
	if total <= max {
		return false
	}

	if total <= count {
		log.WithFields(log.Fields{
			"total": total, "count": count,
		}).Error("remove count exceeds the total count!")
		return false
	}

	entries := make([]*GraphSyncEntry, len(a.entries))
	var k int
	for key, entry := range a.entries {
		entries[k] = graphEntry2Sync(&key, entry)
		k++
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Last < entries[j].Last })

	// Now entries are sorted by time, oldest first
	var removeCnt int = 0
	for _, e := range entries {
		gkey, _ := graphSync2Entry(e)
		delete(a.entries, *gkey)
		removeCnt++
		if removeCnt == count {
			break
		}
	}
	recalcConversation(a)
	log.WithFields(log.Fields{
		"removeCnt": removeCnt, "left": len(a.entries),
	}).Debug("remove")
	return true
}

// Application must be 0 to call this function. Attr can be nil
func qualifyPortLink(conn *share.CLUSConnection, port string, attr *polAttr) bool {
	if attr != nil && attr.ports.Contains(api.PolicyPortAny) {
		return false
	}

	if attr != nil && attr.ports.Contains(port) {
		return true
	}
	/*
	 * NVSHAS-6687,traffic for previously learned rule with app identified
	 * will cause violation under monitor/protect mode when app is empty in
	 * session, so we still need to learn this port even it is seen before.
	 */
	/*if conn.PolicyAction == C.DP_POLICY_ACTION_LEARN {
		// Do not learn the port rule if app rule on the same port has been learned
		if attr != nil && !attr.ports.Contains(port) && attr.portsSeen.Contains(port) {
			return false
		}
	}*/

	if conn.IPProto == syscall.IPPROTO_UDP {
		// For UDP, the server port might be misidentified. So we will not
		// learn it if the dst is workload but we cannot find its app
		cacheMutexRLock()
		defer cacheMutexRUnlock()
		if cache, ok := wlCacheMap[conn.ServerWL]; ok {
			if _, found := cache.workload.Apps[port]; !found {
				log.WithFields(log.Fields{
					"serverWL": conn.ServerWL, "port": port,
				}).Debug("Not reliable, skip learning")
				return false
			}
		}
	}

	return true
}

func addConnectToGraph(conn *share.CLUSConnection, ca, sa *nodeAttr, stip *serverTip) {
	if conn.ClientWL == "" || conn.ServerWL == "" {
		log.WithFields(log.Fields{
			"conn": conn, "ca": ca, "sa": sa, "stip": stip,
		}).Debug("empty endpoint!")
		return
	}
	//check whether network policy is disabled
	if getDisableNetPolicyStatus() {
		return
	}

	// Node attributes: not to replace the attribute node so the alias can be kept.
	if a := wlGraph.Attr(conn.ClientWL, attrLink, dummyEP); a == nil {
		wlGraph.AddLink(conn.ClientWL, attrLink, dummyEP, ca)
	}
	if a := wlGraph.Attr(conn.ServerWL, attrLink, dummyEP); a == nil {
		wlGraph.AddLink(conn.ServerWL, attrLink, dummyEP, sa)
	}

	// dumpLink(conn.ClientWL, policyLink, conn.ServerWL)

	//no policy match for service mesh with sidecar
	if !strings.Contains(conn.Network, share.NetworkProxyMesh) || conn.Xff || conn.MeshToSvr {
		switch conn.PolicyAction {
		case C.DP_POLICY_ACTION_LEARN:
			// This is used to create policy.
			// addrgrp can be created by user or from service IP group. If it's created by user, the
			// conversation already matches a policy and action won't be 'learn'.
			oldPolicyId := conn.PolicyId

			ipp := utils.GetPortLink(uint8(conn.IPProto), stip.wlPort)
			if a := wlGraph.Attr(conn.ClientWL, policyLink, conn.ServerWL); a != nil {
				attr := a.(*polAttr)

				if conn.Application > 0 {
					if !attr.apps.Contains(conn.Application) {
						// If connection application is not in the policy rules, add the app and check
						// if the entry of the same port exists. If yes, remove it and recalc policy.
						attr.apps.Add(conn.Application)
						attr.portsSeen.Add(ipp)
						conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
						attr.ports.Remove(ipp)
						unlearnAppPort(conn.ClientWL, conn.ServerWL, nil, &ipp)
						attr.lastRecalcAt = time.Now().Unix()

						cctx.ConnLog.WithFields(log.Fields{
							"client": conn.ClientIP, "server": conn.ServerIP, "app": conn.Application, "port": ipp,
						}).Debug("Replace port rule")
					} else if conn.PolicyId == 0 || needPolicyIdRecalc(attr) {
						// This is an ad-hoc way of fixing policy id if the matching policy changed
						// due to the operation above
						conn.PolicyId = getLearnedPolicy(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
					}
				} else {
					if qualifyPortLink(conn, ipp, attr) {
						attr.ports.Add(ipp)
						attr.portsSeen.Add(ipp)
						conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, nil, &ipp)
					} else if conn.PolicyId == 0 {
						conn.PolicyId = getLearnedPolicy(conn.ClientWL, conn.ServerWL, nil, &ipp)
					}
				}
			} else {
				attr := &polAttr{apps: utils.NewSet(), ports: utils.NewSet(), portsSeen: utils.NewSet()}

				if conn.Application > 0 {
					attr.apps.Add(conn.Application)
					attr.portsSeen.Add(ipp)
					conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
					wlGraph.AddLink(conn.ClientWL, policyLink, conn.ServerWL, attr)
				} else {
					if !qualifyPortLink(conn, ipp, attr) {
						cctx.ConnLog.WithFields(log.Fields{
							"client": conn.ClientIP, "server": conn.ServerIP,
						}).Debug("Ignore non-qualified connection")
						return
					} else {
						attr.ports.Add(ipp)
						attr.portsSeen.Add(ipp)
						wlGraph.AddLink(conn.ClientWL, policyLink, conn.ServerWL, attr)
						conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, nil, &ipp)
					}
				}
			}
			if oldPolicyId != conn.PolicyId {
				cctx.ConnLog.WithFields(log.Fields{
					"old": oldPolicyId, "new": conn.PolicyId,
				}).Debug("Modify policy id")
			}
		case C.DP_POLICY_ACTION_ALLOW:
			// If the port rule not the app rule is learned, the connection with the app detected should be
			// ALLOWED. We are to replace the port rule if possible.
			ipp := utils.GetPortLink(uint8(conn.IPProto), stip.wlPort)
			if a := wlGraph.Attr(conn.ClientWL, policyLink, conn.ServerWL); a != nil {
				attr := a.(*polAttr)

				if conn.Application > 0 {
					if !attr.apps.Contains(conn.Application) {
						if attr.ports.Contains(ipp) {
							attr.apps.Add(conn.Application)
							conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
							attr.ports.Remove(ipp)
							unlearnAppPort(conn.ClientWL, conn.ServerWL, nil, &ipp)
							attr.lastRecalcAt = time.Now().Unix()

							cctx.ConnLog.WithFields(log.Fields{
								"client": conn.ClientIP, "server": conn.ServerIP, "app": conn.Application, "port": ipp,
							}).Debug("Replace port rule")
						} else if attr.ports.Contains(api.PolicyPortAny) {
							attr.apps.Add(conn.Application)
							conn.PolicyId = learnAppPort(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
							attr.lastRecalcAt = time.Now().Unix()

							cctx.ConnLog.WithFields(log.Fields{
								"client": conn.ClientIP, "server": conn.ServerIP, "app": conn.Application, "port": ipp,
							}).Debug("Add application rule without replacing port any rule")
						}
					} else if needPolicyIdRecalc(attr) {
						// This is an ad-hoc way of fixing policy id if the matching policy changed
						// due to the operation above
						conn.PolicyId = getLearnedPolicy(conn.ClientWL, conn.ServerWL, &conn.Application, nil)
					}
				}
			}
		case C.DP_POLICY_ACTION_VIOLATE:
			ipp := utils.GetPortLink(uint8(conn.IPProto), stip.wlPort)
			if conn.Violates > 0 && (conn.Application > 0 || qualifyPortLink(conn, ipp, nil)) {
				violationUpdate(conn, stip.appServer)
			}
		case C.DP_POLICY_ACTION_DENY:
			if conn.Violates > 0 {
				violationUpdate(conn, stip.appServer)
			}
		case C.DP_POLICY_ACTION_CHECK_APP:
			// Check app action will be reported only if the session is already closed
			// Treat this as action allow
			conn.PolicyAction = C.DP_POLICY_ACTION_ALLOW
		case C.DP_POLICY_ACTION_CHECK_VH:
			// Treat this as action allow
			conn.PolicyAction = C.DP_POLICY_ACTION_ALLOW
		}
	}

	gkey := graphKey{ipproto: uint8(conn.IPProto), port: stip.wlPort, application: conn.Application,
		cip: utils.IPv42Int(conn.ClientIP), sip: utils.IPv42Int(conn.ServerIP)}

	// This is used to create conversations
	var attr *graphAttr

	if a := wlGraph.Attr(conn.ClientWL, graphLink, conn.ServerWL); a != nil {
		attr = a.(*graphAttr)
		attr.bytes += conn.Bytes
		attr.sessions += conn.Sessions
		if uint8(conn.Severity) > attr.severity {
			attr.severity = uint8(conn.Severity)
		}
	} else {
		attr = &graphAttr{
			bytes:    conn.Bytes,
			sessions: conn.Sessions,
			severity: uint8(conn.Severity),
			entries:  make(map[graphKey]*graphEntry),
		}
	}

	// Save to entries index-ed by graphKey
	var recalcAction bool = false
	if ge, ok := attr.entries[gkey]; ok {
		ge.bytes += conn.Bytes
		ge.sessions += conn.Sessions
		if isDlpThreatID(conn.ThreatID) { //dlp
			if uint8(conn.Severity) >= ge.dlpSeverity {
				ge.dlpID = conn.ThreatID
				ge.dlpSeverity = uint8(conn.Severity)
			}
		} else if isWafThreatID(conn.ThreatID) { //waf
			if uint8(conn.Severity) >= ge.wafSeverity {
				ge.wafID = conn.ThreatID
				ge.wafSeverity = uint8(conn.Severity)
			}
		} else {
			if uint8(conn.Severity) > ge.severity {
				ge.threatID = conn.ThreatID
				ge.severity = uint8(conn.Severity)
			}
		}
		if conn.LastSeenAt >= ge.last {
			if uint8(conn.PolicyAction) >= attr.policyAction {
				attr.policyAction = uint8(conn.PolicyAction)
			} else if uint8(conn.PolicyAction) < ge.policyAction {
				recalcAction = true
			}
			ge.policyAction = uint8(conn.PolicyAction)
			ge.policyID = conn.PolicyId
			ge.last = conn.LastSeenAt
		}
		if conn.Xff {
			ge.xff = 1
		} else {
			ge.xff = 0
		}
		if conn.ToSidecar {
			ge.toSidecar = 1
		} else {
			ge.toSidecar = 0
		}
		// No need to update the FQDN field if (ge.fqdn != "" && conn.FQDN == "") for the
		// same connection. This may be due to the IP-FQDN record has timed out.
		if ge.fqdn == "" || conn.FQDN != "" {
			ge.fqdn = conn.FQDN
		}
		if conn.Nbe {
			ge.nbe = 1
		} else {
			ge.nbe = 0
		}
	} else {
		ge := &graphEntry{
			bytes:    conn.Bytes,
			sessions: conn.Sessions,
			server:   stip.appServer,
			last:     conn.LastSeenAt,
			fqdn:     conn.FQDN,
		}
		if conn.Xff {
			ge.xff = 1
		} else {
			ge.xff = 0
		}
		if conn.ToSidecar {
			ge.toSidecar = 1
		} else {
			ge.toSidecar = 0
		}
		if conn.Nbe {
			ge.nbe = 1
		} else {
			ge.nbe = 0
		}
		if isDlpThreatID(conn.ThreatID) {
			ge.dlpID = conn.ThreatID
			ge.dlpSeverity = uint8(conn.Severity)
		} else if isWafThreatID(conn.ThreatID) {
			ge.wafID = conn.ThreatID
			ge.wafSeverity = uint8(conn.Severity)
		} else {
			ge.threatID = conn.ThreatID
			ge.severity = uint8(conn.Severity)
		}
		if stip.mappedPort > 0 {
			ge.mappedPort = stip.mappedPort
		} else {
			ge.mappedPort = uint16(conn.ServerPort)
		}
		if uint8(conn.PolicyAction) >= attr.policyAction {
			attr.policyAction = uint8(conn.PolicyAction)
		} else {
			recalcAction = true
		}
		ge.policyAction = uint8(conn.PolicyAction)
		ge.policyID = conn.PolicyId
		attr.entries[gkey] = ge
	}

	// When in protect mode, traffic can be dropped with application not checked.
	// If later policy mode changed so that the same traffic is passed now, remove the
	// old blocked conversation
	if uint8(conn.PolicyAction) != C.DP_POLICY_ACTION_DENY &&
		attr.policyAction == C.DP_POLICY_ACTION_DENY {
		gkey2 := gkey
		gkey2.application = C.DPI_APP_NOT_CHECKED
		if _, ok := attr.entries[gkey2]; ok {
			delete(attr.entries, gkey2)
			recalcAction = true
		}
	}

	if removeOldEntries(attr, 1000, 100) {
		// recalc is already done in removeOldEntries()
		recalcAction = false
	}

	// derive policy action from all entries
	if recalcAction {
		attr.policyAction = getAggregatedAction(attr.entries)
	}

	wlGraph.AddLink(conn.ClientWL, graphLink, conn.ServerWL, attr)
}

/*--------------------------------------------------------------*/
/*------- Incremental way of policy learning -------------------*/
type learnedPolicyRuleWrapper struct {
	rule   learnedPolicyRule
	id     uint32
	action int
}

const lprAdd = 0x1
const lprModify = 0x2
const lprDelete = 0x4
const lprRecalc = 0x8

var lprWrapperMap map[groupPair]*learnedPolicyRuleWrapper
var maxLearnRuleID uint32 = api.PolicyLearnedIDBase
var lprActiveRuleIDs utils.Set = utils.NewSet()

const PolicyLearnedIDMax uint32 = api.PolicyFedRuleIDBase

func allocLearnedRuleID() uint32 {
	//ids in cluster is in written by lead ctrl, same connection is
	//processed by lead first and then after some time by non-lead,
	//to prevent same connection being learned with different rule id
	//between ctrls, each ctrl keep track of its own id allocation
	//NVSHAS-5192, each new connection need to learn new policy id,
	//for large deployment, GetAvailablePolicyID spend much time in
	//finding max, so we increase maxLearnRuleID to get new id
	var newid uint32
	if maxLearnRuleID < PolicyLearnedIDMax-1 {
		maxLearnRuleID++
		newid = maxLearnRuleID
	} else {
		//finding an id < api.PolicyFedRuleIDBase that is unused
		newid = common.GetAvailablePolicyID(lprActiveRuleIDs, share.Learned)
	}

	if newid != 0 {
		lprActiveRuleIDs.Add(newid)
	}

	return newid
}

func isHostIP(ip string) bool {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if _, ok := ipHostMap[ip]; ok {
		return true
	}
	return false
}

func isNodeInHostGroup(node string) bool {
	if strings.HasPrefix(node, api.LearnedHostPrefix) {
		name := node[len(api.LearnedHostPrefix):]
		ip := net.ParseIP(name)
		if ip != nil {
			// This is for unamanged host learned from orchestration
			// They don't have host ID, but we still consider them in
			// Host group if they are in ipHostMap
			return isHostIP(name)
		} else {
			return true
		}
	}
	return false
}

func node2Group(node string) (string, bool) {
	if cache := getWorkloadCache(node); cache != nil {
		return cache.learnedGroupName, true
	} else if isNodeInHostGroup(node) {
		return api.AllHostGroup, false
	} else if isNonWorkloadLearnedEndpoint(node) {
		// Any user-created group, including ip-address group, will not be part of the learned policy.
		return node, false
	}
	log.WithFields(log.Fields{"node": node}).Debug("Cannot find group!")
	return "", false
}

func getLearnedPolicyRuleKey(fromNode, toNode string, app *uint32, port *string) *groupPair {
	fromGroup, fromContainer := node2Group(fromNode)
	toGroup, toContainer := node2Group(toNode)
	if fromGroup == "" || toGroup == "" {
		log.WithFields(log.Fields{
			"from": fromNode, "to": toNode,
			"fromGroup": fromGroup, "toGroup": toGroup,
		}).Debug("cannot find group!")
		return nil
	}

	// learned rule must have one side being container
	if !fromContainer && !toContainer {
		log.WithFields(log.Fields{
			"from": fromNode, "to": toNode,
		}).Debug("Invalid from-to pair for policy learning")
		return nil
	}

	var pair groupPair
	if app != nil {
		pair = groupPair{from: fromGroup, to: toGroup, isApp: true}
	} else {
		pair = groupPair{from: fromGroup, to: toGroup, isApp: false}
	}
	return &pair
}

func addSingleLinkPortAny(attr *polAttr, port *string) {
	if attr == nil || port == nil {
		return
	}

	if attr.ports != nil && attr.ports.Contains(*port) {
		attr.ports.Remove(*port)
	}
	if attr.portsSeen != nil && attr.portsSeen.Contains(*port) {
		attr.portsSeen.Remove(*port)
	}
	attr.ports.Add(api.PolicyPortAny)
	attr.portsSeen.Add(api.PolicyPortAny)
	cctx.ConnLog.WithFields(log.Fields{"ports": attr.ports, "portsSeen": attr.portsSeen}).Debug("add portAny")
}

func addLinkPortAny(attr *polAttr, rw *learnedPolicyRuleWrapper) {
	if rw.rule.objs == nil || attr == nil {
		return
	}

	for p := range rw.rule.objs.Iter() {
		pt := p.(string)
		if attr.ports != nil && attr.ports.Contains(pt) {
			attr.ports.Remove(pt)
		}
		if attr.portsSeen != nil && attr.portsSeen.Contains(pt) {
			attr.portsSeen.Remove(pt)
		}
	}

	attr.ports.Add(api.PolicyPortAny)
	attr.portsSeen.Add(api.PolicyPortAny)
	cctx.ConnLog.WithFields(log.Fields{"ports": attr.ports, "portsSeen": attr.portsSeen}).Debug("add portAny")
}

func replaceLearnedRulePortAny(pair *groupPair, rw *learnedPolicyRuleWrapper) {
	fromNodes := getNodesFromGroup(pair.from)
	toNodes := getNodesFromGroup(pair.to)
	//ports are aggregated from all policy link between 2 groups
	for _, from := range fromNodes {
		for _, to := range toNodes {
			if a := wlGraph.Attr(from, policyLink, to); a != nil {
				attr := a.(*polAttr)
				if !pair.isApp {
					//replace ports in policy link to port 'any'
					addLinkPortAny(attr, rw)
				}
			}
		}
	}
	rw.rule.objs.Clear()
	rw.rule.objs.Add(api.PolicyPortAny)
	cctx.ConnLog.WithFields(log.Fields{"pair": *pair, "rule": rw.id, "objs": rw.rule.objs}).Debug("replace ports with portAny")
}

const MaxSvcPortNum int = 20

func learnAppPort(fromNode, toNode string, app *uint32, port *string) uint32 {
	if app == nil && port == nil {
		log.WithFields(log.Fields{
			"from": fromNode, "to": toNode,
		}).Error("Missing param!!")
		return 0
	}

	pair := getLearnedPolicyRuleKey(fromNode, toNode, app, port)
	if pair == nil {
		return 0
	}

	var changed bool = false
	rw, ok := lprWrapperMap[*pair]
	if ok {
		rule := &rw.rule
		if app != nil {
			if !rule.objs.Contains(*app) {
				rule.objs.Add(*app)
				rw.action |= lprModify
				changed = true

				cctx.ConnLog.WithFields(log.Fields{
					"from": fromNode, "to": toNode, "rule": rw.id, "app": *app,
				}).Debug("Add app")
			}
		} else {
			if !rule.objs.Contains(api.PolicyPortAny) && !rule.objs.Contains(*port) {
				rule.objs.Add(*port)
				//when there are more than  MaxSvcPortNum svc ports in a single rule,
				//we change it to 'any' port to avoid translating into huge amounts of
				//ip rules
				if rule.objs.Cardinality() > MaxSvcPortNum {
					replaceLearnedRulePortAny(pair, rw)
				}
				rw.action |= lprModify
				changed = true
				cctx.ConnLog.WithFields(log.Fields{
					"from": fromNode, "to": toNode, "rule": rw.id, "port": *port,
				}).Debug("Add port")
			} else if !rule.objs.Contains(*port) {
				if a := wlGraph.Attr(fromNode, policyLink, toNode); a != nil {
					attr := a.(*polAttr)
					addSingleLinkPortAny(attr, port)
				}
			}
		}
	} else {
		rw = &learnedPolicyRuleWrapper{rule: learnedPolicyRule{objs: utils.NewSet()}}
		rw.id = allocLearnedRuleID()
		if rw.id > 0 {
			if app != nil {
				rw.rule.objs.Add(*app)
			} else {
				rw.rule.objs.Add(*port)
			}
			rw.action |= lprAdd
			lprWrapperMap[*pair] = rw
			changed = true
			cctx.ConnLog.WithFields(log.Fields{
				"from": fromNode, "to": toNode, "rule": rw.id, "objs": rw.rule.objs,
			}).Debug("Add new rule")
		}
	}
	if changed {
		scheduleLearnedPolicyProc()
	}
	return rw.id
}

func getLearnedPolicy(fromNode, toNode string, app *uint32, port *string) uint32 {
	pair := getLearnedPolicyRuleKey(fromNode, toNode, app, port)
	if pair != nil {
		if rw, ok := lprWrapperMap[*pair]; ok {
			return rw.id
		}
	}
	return 0
}

func unlearnAppPort(fromNode, toNode string, app *uint32, port *string) {
	pair := getLearnedPolicyRuleKey(fromNode, toNode, app, port)
	if pair == nil {
		return
	}
	if rw, ok := lprWrapperMap[*pair]; ok {
		rw.action |= lprRecalc
		cctx.ConnLog.WithFields(log.Fields{
			"from": fromNode, "to": toNode, "rule": rw.id,
		}).Debug("Mark recalc")
		scheduleLearnedPolicyProc()
	}
}

func needPolicyIdRecalc(attr *polAttr) bool {
	return (time.Now().Unix() - attr.lastRecalcAt) < 30
}

func unlearnAll(groupName string) {
	var changed bool = false
	for pair, rw := range lprWrapperMap {
		if pair.from == groupName || pair.to == groupName {
			rw.action |= lprDelete
			changed = true
			cctx.ConnLog.WithFields(log.Fields{
				"from": pair.from, "to": pair.to, "rule": rw.id,
			}).Debug("Mark delete")
		}
	}
	if changed {
		scheduleLearnedPolicyProc()
	}
}

// reduce maxLearnRuleID when delete rules
func adjustMaxLearnRuleID(id uint32) {
	lprActiveRuleIDs.Remove(id)
	if id == maxLearnRuleID {
		maxLearnRuleID--
		for {
			if lprActiveRuleIDs.Cardinality() == 0 {
				maxLearnRuleID = api.PolicyLearnedIDBase
				break
			}
			if lprActiveRuleIDs.Contains(maxLearnRuleID) {
				break
			} else {
				maxLearnRuleID--
				//to prevent unexpected infinite loop
				if maxLearnRuleID <= api.PolicyLearnedIDBase {
					maxLearnRuleID = api.PolicyLearnedIDBase
					break
				}
			}
		}
		//log.WithFields(log.Fields{"ruleid": id, "maxLearnRuleID":maxLearnRuleID}).Debug("Adjust maxLearnRuleID")
	}
}

func deleteRuleFromLprWrapperMap(r *share.CLUSPolicyRule) {
	if r.CfgType != share.Learned {
		return
	}

	var pair groupPair
	if len(r.Applications) > 0 {
		pair = groupPair{from: r.From, to: r.To, isApp: true}
	} else {
		pair = groupPair{from: r.From, to: r.To, isApp: false}
	}
	//in normal case r.ID is eqal to rw.id, but in import's
	//case, due to pause of watch, rw.id can be not equal to
	//r.ID, so always delete rw.id
	rw, ok := lprWrapperMap[pair]
	if ok {
		delete(lprWrapperMap, pair)
		//remove id from active rule ids list
		adjustMaxLearnRuleID(rw.id)
	}
}

func getNodesFromGroup(groupName string) []string {
	gr, _ := cacher.GetGroup(groupName, "", false, access.NewReaderAccessControl())
	if gr != nil && len(gr.Members) > 0 {
		nodes := make([]string, len(gr.Members))
		for i, wl := range gr.Members {
			nodes[i] = wl.ID
		}
		return nodes
	} else {
		nodes := []string{groupName}
		return nodes
	}
}

func recalcLearnedRule(pair *groupPair, rw *learnedPolicyRuleWrapper) {
	fromNodes := getNodesFromGroup(pair.from)
	toNodes := getNodesFromGroup(pair.to)
	objs := utils.NewSet()
	for _, from := range fromNodes {
		for _, to := range toNodes {
			if a := wlGraph.Attr(from, policyLink, to); a != nil {
				attr := a.(*polAttr)
				if !pair.isApp {
					if attr.ports.Cardinality() > 0 {
						objs = objs.Union(attr.ports)
					}
				} else {
					if attr.apps.Cardinality() > 0 {
						objs = objs.Union(attr.apps)
					}
				}
			}
		}
	}
	cctx.ConnLog.WithFields(log.Fields{
		"rule": rw.id, "old objs": rw.rule.objs, "objs": objs,
	}).Debug("")

	if !pair.isApp {
		if objs.Cardinality() > 1 && objs.Contains(api.PolicyPortAny) {
			objs.Clear()
			objs.Add(api.PolicyPortAny)
		}

		if rw.rule.objs.Cardinality() > 1 && rw.rule.objs.Contains(api.PolicyPortAny) {
			rw.rule.objs.Clear()
			rw.rule.objs.Add(api.PolicyPortAny)
		}
		cctx.ConnLog.WithFields(log.Fields{
			"rule": rw.id, "old objs": rw.rule.objs, "objs": objs,
		}).Debug("Check PortAny")
	}

	rw.action &^= lprRecalc
	if !rw.rule.objs.Equal(objs) {
		rw.rule.objs = objs
		if objs.Cardinality() == 0 {
			rw.action |= lprDelete
		} else {
			rw.action |= lprModify
		}
	}
	cctx.ConnLog.WithFields(log.Fields{"pair": *pair, "rw": *rw, "rule": rw.rule}).Debug("")
}

func adjustRuleAction(pair *groupPair, rw *learnedPolicyRuleWrapper) {
	if rw.action&lprRecalc > 0 {
		recalcLearnedRule(pair, rw)
	}

	if rw.action&lprDelete > 0 {
		if rw.action&lprAdd > 0 {
			// rule has not been added yet
			fromNodes := getNodesFromGroup(pair.from)
			toNodes := getNodesFromGroup(pair.to)
			for _, from := range fromNodes {
				for _, to := range toNodes {
					deleteConversationByPolicyId(from, to, rw.id)
				}
			}
			delete(lprWrapperMap, *pair)
			rw.action = 0
			//remove id from active rule ids list
			adjustMaxLearnRuleID(rw.id)
		} else {
			// clear all other flags
			rw.action = lprDelete
		}
	} else if rw.action&lprAdd > 0 {
		// clear all other flags
		rw.action = lprAdd
	}
}

func learnedRule2ClusterRule(pair *groupPair, rw *learnedPolicyRuleWrapper) *share.CLUSPolicyRule {
	lpr := &rw.rule
	rule := share.CLUSPolicyRule{
		ID:           rw.id,
		From:         pair.from,
		FromHost:     lpr.fromHost,
		To:           pair.to,
		ToHost:       lpr.toHost,
		Ports:        api.PolicyPortAny,
		Applications: make([]uint32, 0),
		Action:       share.PolicyActionAllow,
		CfgType:      share.Learned,
	}
	if pair.isApp {
		rule.Applications = apps2Slice(lpr.objs)
	} else {
		rule.Ports = ports2String(lpr.objs)
	}
	return &rule
}

func procLearnedPolicy(updateCluster bool) int {
	var modifyList []*share.CLUSPolicyRule
	var addList []*share.CLUSPolicyRule
	var deleteMap map[uint32]bool = make(map[uint32]bool)

	for pair, rw := range lprWrapperMap {
		adjustRuleAction(&pair, rw)
		if rw.action == 0 {
			continue
		}

		lpr := &rw.rule
		switch rw.action {
		case lprAdd:
			if updateCluster {
				rule := learnedRule2ClusterRule(&pair, rw)
				rule.CreatedAt = time.Now().UTC()
				rule.LastModAt = rule.CreatedAt
				addList = append(addList, rule)
			}
		case lprModify:
			if updateCluster {
				rule := share.CLUSPolicyRule{ID: rw.id, Ports: api.PolicyPortAny}
				if pair.isApp {
					rule.Applications = apps2Slice(lpr.objs)
				} else {
					rule.Ports = ports2String(lpr.objs)
				}
				modifyList = append(modifyList, &rule)
			}
		case lprDelete:
			if updateCluster {
				deleteMap[rw.id] = true
				log.WithFields(log.Fields{
					"pair": pair, "rw": rw, "objs": lpr.objs,
				}).Info("rule to be deleted while learning")
			}
			delete(lprWrapperMap, pair)
			//this id can be reused so remove it from
			//active rule ids list
			adjustMaxLearnRuleID(rw.id)
		default:
			log.WithFields(log.Fields{
				"pair": pair, "rw": rw, "objs": lpr.objs,
			}).Error("Unexpected action!")
		}
		rw.action = 0
	}

	if !updateCluster {
		return 0
	}

	lenAdd := len(addList)
	lenDel := len(deleteMap)
	if len(modifyList) > 0 || lenAdd > 0 || lenDel > 0 {
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
			return -1
		}
		defer clusHelper.ReleaseLock(lock)

		txn := cluster.Transact()
		defer txn.Close()

		for _, rule := range modifyList {
			cr, _ := clusHelper.GetPolicyRule(rule.ID)
			if cr != nil {
				cr.Applications = rule.Applications
				cr.Ports = rule.Ports
				cr.LastModAt = time.Now().UTC()
				_ = clusHelper.PutPolicyRuleTxn(txn, cr)
				cctx.ConnLog.WithFields(log.Fields{
					"from": cr.From, "to": cr.To, "id": cr.ID,
				}).Debug("update")
			}
		}

		if lenAdd > 0 || lenDel > 0 {
			crhs := clusHelper.GetPolicyRuleList()
			if (len(crhs) + lenAdd - lenDel) < 0 {
				log.Error("To be deleted rules more than total!")
				return -1
			}
			newList := make([]*share.CLUSRuleHead, 0, len(crhs)+lenAdd-lenDel)
			nids := utils.NewSet()
			for i, r := range crhs {
				if _, ok := deleteMap[r.ID]; !ok {
					newList = append(newList, crhs[i])
					nids.Add(crhs[i].ID)
				}
			}

			if lenDel > 0 {
				for id := range deleteMap {
					_ = clusHelper.DeletePolicyRuleTxn(txn, id)
				}
			}

			if lenAdd > 0 {
				sort.Slice(addList, func(i, j int) bool { return addList[i].ID < addList[j].ID })
				for _, rule := range addList {
					_ = clusHelper.PutPolicyRuleTxn(txn, rule)
					cctx.ConnLog.WithFields(log.Fields{
						"from": rule.From, "to": rule.To, "id": rule.ID,
					}).Debug("add")
					//no duplicate rule id is allowed in rulelist
					//but we override rule in cache with what
					//we just learned to ensure synchronization
					if nids.Contains(rule.ID) {
						continue
					}
					newList = append(newList, &share.CLUSRuleHead{ID: rule.ID, CfgType: share.Learned})
				}
			}

			if err := clusHelper.PutPolicyRuleListTxn(txn, newList); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Put policy rule list")
				return -1
			}
		}

		if ok, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			return -1
		} else if !ok {
			log.Error("Atomic write failed")
			return -1
		}
	}
	return 0
}

var policyProcReturn int = 0

func syncLearnedPolicyToCluster() int {
	log.Debug("")

	procLearnedPolicy(false)

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return -1
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	var lprWrapperMapById map[uint32]bool = make(map[uint32]bool)
	var addList []*share.CLUSPolicyRule

	for pair, rw := range lprWrapperMap {
		lpr := &rw.rule
		lprWrapperMapById[rw.id] = true
		cr, _ := clusHelper.GetPolicyRule(rw.id)
		if cr != nil {
			if len(cr.Applications) > 0 {
				if !cmpLearnedApps(cr.Applications, lpr.objs) {
					cr.Applications = apps2Slice(lpr.objs)
					cr.LastModAt = time.Now().UTC()
					_ = clusHelper.PutPolicyRuleTxn(txn, cr)

					log.WithFields(log.Fields{
						"from": pair.from, "to": pair.to, "apps": lpr.objs,
					}).Debug("update")
				}
			} else {
				newPorts := ports2String(lpr.objs)
				if cr.Ports != newPorts {
					cr.Ports = newPorts
					cr.LastModAt = time.Now().UTC()
					_ = clusHelper.PutPolicyRuleTxn(txn, cr)
				}
			}
		} else {
			rule := learnedRule2ClusterRule(&pair, rw)
			addList = append(addList, rule)
		}
	}

	crhs := clusHelper.GetPolicyRuleList()
	newList := make([]*share.CLUSRuleHead, 0)
	for _, r := range crhs {
		if r.CfgType != share.Learned {
			newList = append(newList, r)
		} else if _, ok := lprWrapperMapById[r.ID]; ok {
			newList = append(newList, r)
		} else {
			_ = clusHelper.DeletePolicyRuleTxn(txn, r.ID)
		}
	}

	if len(addList) > 0 {
		sort.Slice(addList, func(i, j int) bool { return addList[i].ID < addList[j].ID })
		for _, rule := range addList {
			_ = clusHelper.PutPolicyRuleTxn(txn, rule)
			log.WithFields(log.Fields{
				"from": rule.From, "to": rule.To, "id": rule.ID,
			}).Debug("add")
			newList = append(newList, &share.CLUSRuleHead{ID: rule.ID, CfgType: share.Learned})
		}
	}

	if !reflect.DeepEqual(newList, crhs) {
		if err := clusHelper.PutPolicyRuleListTxn(txn, newList); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Put policy rule list")
			return -1
		}
	}

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return -1
	} else if !ok {
		log.Error("Atomic write failed")
		return -1
	}
	return 0
}

func SyncLearnedPolicyFromCluster() {
	graphMutexLock()
	defer graphMutexUnlock()
	lprWrapperMap = make(map[groupPair]*learnedPolicyRuleWrapper)
	maxLearnRuleID = api.PolicyLearnedIDBase

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	crhs := clusHelper.GetPolicyRuleList()
	dels := utils.NewSet()
	lprActiveRuleIDs.Clear()

	for _, r := range crhs {
		if r.CfgType != share.Learned {
			continue
		} else {
			cr, _ := clusHelper.GetPolicyRule(r.ID)
			if cr == nil {
				// The policy may not be found due to reasons such as upgrade,
				dels.Add(r.ID)
				continue
			}
			pair := groupPair{from: cr.From, to: cr.To}
			rw := &learnedPolicyRuleWrapper{
				id: r.ID,
				rule: learnedPolicyRule{
					fromHost: cr.FromHost,
					toHost:   cr.ToHost,
					objs:     utils.NewSet(),
				},
			}

			if len(cr.Applications) > 0 {
				pair.isApp = true
				for _, app := range cr.Applications {
					rw.rule.objs.Add(app)
				}
			} else {
				ports := strings.Split(cr.Ports, ",")
				for _, port := range ports {
					rw.rule.objs.Add(port)
				}
			}
			lprWrapperMap[pair] = rw

			//keep track of id being used
			lprActiveRuleIDs.Add(r.ID)

			if maxLearnRuleID < r.ID {
				maxLearnRuleID = r.ID
			}
			//log.WithFields(log.Fields{"pair": pair, "rw": *rw}).Debug("Recover learned rule")
		}
	}

	if dels.Cardinality() > 0 {
		log.WithFields(log.Fields{"delete": dels}).Info("Delete rules after sync from cluster")
		newList := make([]*share.CLUSRuleHead, 0, len(crhs)-dels.Cardinality())
		for _, r := range crhs {
			if !dels.Contains(r.ID) {
				newList = append(newList, r)
			}
		}
		if err := clusHelper.PutPolicyRuleList(newList); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Put policy rule list")
			return
		}
	}

	log.WithFields(log.Fields{
		"total learned rules": len(lprWrapperMap), "maxLearnRuleID": maxLearnRuleID},
	).Info()
}

func cbDeleteNode(node string) {
	// Only delete learned policies if endpoint is unmanaged, host:x.x.x.x or workload:x.x.x.x,
	// user created rule will not be deleted.
	if (isHostOrUnmanagedWorkload(node) && !strings.Contains(node, api.EndpointIngress)) ||
		strings.HasPrefix(node, api.LearnedSvcGroupPrefix) {
		unlearnAll(node)
	}
}

func startPolicyThread() {
	wlGraph = graph.NewGraph()
	wlGraph.RegisterDelNodeHook(cbDeleteNode)
	// NOTE.1: The following way to detect if a service group has external connections is efficient but logic
	// need to be fine tuned. Links can be created before the workload is discovered (sync from the lead),
	// or deleted after the workload is gone.
	// wlGraph.RegisterNewLinkHook(cbNewLink)
	// wlGraph.RegisterDelLinkHook(cbDeleteLink)

	lprWrapperMap = make(map[groupPair]*learnedPolicyRuleWrapper)
	policyProcTimer = time.NewTimer(policyProcDelayIdle)
	policyProcTimer.Stop()
	policyCalculatingTimer = time.NewTimer(policyCalculatingDelaySlow)
	policyCalculatingTimer.Stop()
	ctrlSyncTimer = time.NewTimer(ctrlSyncDelay)
	ctrlSyncTimer.Stop()
	dlpCalculatingTimer = time.NewTimer(dlpCalculatingDelaySlow)
	dlpCalculatingTimer.Stop()
	vulProfUpdateTimer = time.NewTimer(vulProfUpdateDelayIdle)
	vulProfUpdateTimer.Stop()

	syncCheckTicker := time.Tick(time.Second * time.Duration(120))

	// In case there are already learned rule in cluster, fetch the rules.
	// This can happen when controller restarts
	SyncLearnedPolicyFromCluster()

	go func() {
		// Wait until graph is synced
		for !syncInitDone {
			time.Sleep(time.Second)
		}

		for {
			select {
			case <-policyProcTimer.C:
				graphMutexLock()
				if policyProcReturn == 0 || !isLeader() {
					// if last learning process succeeded or this is not the lead,
					// (non-lead just learn but not write the policy)
					policyProcReturn = procLearnedPolicy(isLeader())
				} else {
					// if last learning process failed, write again.
					policyProcReturn = syncLearnedPolicyToCluster()
				}
				policyUpdated = false
				if policyProcReturn != 0 {
					// proc failed due to cluster issue - schedule resync
					scheduleLearnedPolicyProc()
				}
				graphMutexUnlock()
			case <-ctrlSyncTimer.C:
				putHotSyncRequest()
			case <-dlpCalculatingTimer.C:
				updateDlpRuleNetwork()
			case <-policyCalculatingTimer.C:
				//check whether network policy is disabled
				if getDisableNetPolicyStatus() {
					continue
				}
				if !isLeader() {
					policyCalculated = false
					continue
				}
				cacheMutexRLock()
				newIPRules := calculateIPPolicyFromCache()
				cacheMutexRUnlock()
				policyCalculated = false
				if policyApplyIngress {
					reorgPolicyIPRulesPerNodePAI(newIPRules)
				} else {
					reorgPolicyIPRulesPerNode(newIPRules)
				}
				putPolicyIPRulesToClusterScaleNode(newIPRules)
				resetNodePolicy()
			case <-vulProfUpdateTimer.C:
				scanVulProfUpdate()
			case <-syncCheckTicker:
				syncCheck(isLeader())
			}
		}
	}()
}

/* --------------------------------------------------------------------- */
// Graph Sync Functions
type graphSyncNodeData struct {
	Name     string `json:"name"`
	Alias    string `json:"alias"`
	HostID   string `json:"host_id,omitempty"`
	External bool   `json:"external,omitempty"`
	Workload bool   `json:"workload,omitempty"`
	Host     bool   `json:"host,omitempty"`
	Managed  bool   `json:"managed,omitempty"`
	Addrgrp  bool   `json:"addrgrp,omitempty"`
	IPSvcgrp bool   `json:"svcgrp,omitempty"`
}

const (
	linkPolicy = 0x1
	linkGraph  = 0x2
)

type GraphSyncEntry struct {
	Ipproto      uint8
	Port         uint16
	Application  uint32
	CIP          uint32
	SIP          uint32
	MappedPort   uint16
	ThreatID     uint32
	DlpID        uint32
	WafID        uint32
	Severity     uint8
	DlpSeverity  uint8
	WafSeverity  uint8
	PolicyAction uint8
	PolicyID     uint32
	Bytes        uint64
	Sessions     uint32
	Server       uint32
	Last         uint32
	Xff          uint8
	ToSidecar    uint8
	FQDN         string
	Nbe          uint8
}

func graphEntry2Sync(k *graphKey, e *graphEntry) *GraphSyncEntry {
	return &GraphSyncEntry{Ipproto: k.ipproto,
		Port: k.port, Application: k.application,
		CIP: k.cip, SIP: k.sip,
		MappedPort: e.mappedPort, Bytes: e.bytes,
		Sessions: e.sessions, Server: e.server,
		Severity: e.severity, DlpSeverity: e.dlpSeverity, WafSeverity: e.wafSeverity,
		ThreatID: e.threatID, DlpID: e.dlpID, WafID: e.wafID, PolicyAction: e.policyAction,
		PolicyID: e.policyID, Last: e.last, Xff: e.xff, ToSidecar: e.toSidecar, FQDN: e.fqdn,
		Nbe: e.nbe,
	}
}

func graphSync2Entry(e *GraphSyncEntry) (*graphKey, *graphEntry) {
	gkey := graphKey{ipproto: e.Ipproto, port: e.Port,
		application: e.Application, cip: e.CIP, sip: e.SIP,
	}

	gEntry := graphEntry{mappedPort: e.MappedPort,
		bytes: e.Bytes, sessions: e.Sessions,
		server: e.Server, severity: e.Severity, dlpSeverity: e.DlpSeverity, wafSeverity: e.WafSeverity,
		threatID: e.ThreatID, dlpID: e.DlpID, wafID: e.WafID, policyAction: e.PolicyAction,
		policyID: e.PolicyID, last: e.Last, xff: e.Xff, toSidecar: e.ToSidecar, fqdn: e.FQDN, nbe: e.Nbe,
	}
	return &gkey, &gEntry
}

type graphSyncLinkData struct {
	From         string
	To           string
	Flag         uint8
	Ports        []string
	Apps         []uint32
	Bytes        uint64
	Sessions     uint32
	Severity     uint8
	PolicyAction uint8
	Entries      []*GraphSyncEntry
}

type graphSyncLearnedRule struct {
	From     string
	To       string
	IsApp    bool
	FromHost string
	ToHost   string
	Ports    []string
	Apps     []uint32
	ID       uint32
}

type graphSyncData struct {
	Nodes          []*graphSyncNodeData    `json:"nodes,omitempty"`
	Links          []*graphSyncLinkData    `json:"links,omitempty"`
	Vios           []*api.Violation        `json:"vios,omitempty"`
	LearnedRules   []*graphSyncLearnedRule `json:"learned_rules,omitempty"`
	MaxLearnRuleID uint32                  `json:"max_learn_rule_id"`
}

func getSyncLearnedRule(pair *groupPair, rw *learnedPolicyRuleWrapper) *graphSyncLearnedRule {
	s := graphSyncLearnedRule{
		From:     pair.from,
		To:       pair.to,
		IsApp:    pair.isApp,
		FromHost: rw.rule.fromHost,
		ToHost:   rw.rule.toHost,
		ID:       rw.id,
	}
	if s.IsApp {
		s.Apps = apps2Slice(rw.rule.objs)
	} else {
		s.Ports = ports2Slice(rw.rule.objs)
	}
	return &s
}

func recoverLearnedRule(s *graphSyncLearnedRule) (*groupPair, *learnedPolicyRuleWrapper) {
	pair := groupPair{
		from:  s.From,
		to:    s.To,
		isApp: s.IsApp,
	}

	rw := learnedPolicyRuleWrapper{
		rule: learnedPolicyRule{fromHost: s.FromHost,
			toHost: s.ToHost,
			objs:   utils.NewSet(),
		},
		id: s.ID,
	}
	if s.IsApp {
		for _, app := range s.Apps {
			rw.rule.objs.Add(app)
		}
	} else {
		for _, port := range s.Ports {
			rw.rule.objs.Add(port)
		}
	}
	return &pair, &rw
}

func syncGraphTx() *syncDataMsg {
	var i int = 0

	graphMutexLock()
	defer graphMutexUnlock()

	// proc queued policy operations
	policyProcReturn = procLearnedPolicy(true)
	if policyProcReturn != 0 {
		scheduleLearnedPolicyProc()
		return nil
	}

	all := wlGraph.All()
	nodes := make([]*graphSyncNodeData, all.Cardinality())
	for n := range all.Iter() {
		if n.(string) == dummyEP {
			continue
		}
		node := graphSyncNodeData{Name: n.(string)}
		if a := wlGraph.Attr(node.Name, attrLink, dummyEP); a != nil {
			attr := a.(*nodeAttr)
			node.External = attr.external
			node.Addrgrp = attr.addrgrp
			node.IPSvcgrp = attr.ipsvcgrp
			node.Workload = attr.workload
			node.Host = attr.host
			node.Managed = attr.managed
			node.HostID = attr.hostID
			node.Alias = attr.alias
		}
		nodes[i] = &node
		i++
	}
	nodes = nodes[0:i]

	i = 0
	links := make([]*graphSyncLinkData, 0)
	for i < len(nodes) {
		var j int = 0
		for j < len(nodes) {
			var link graphSyncLinkData
			var flag uint8

			if attr := wlGraph.Attr(nodes[i].Name, policyLink, nodes[j].Name); attr != nil {
				a := attr.(*polAttr)
				if a.ports.Cardinality() > 0 {
					link.Ports = ports2Slice(a.ports)
				}
				if a.apps.Cardinality() > 0 {
					link.Apps = apps2Slice(a.apps)
				}
				flag |= linkPolicy
			}
			if attr := wlGraph.Attr(nodes[i].Name, graphLink, nodes[j].Name); attr != nil {
				a := attr.(*graphAttr)
				link.Bytes = a.bytes
				link.Sessions = a.sessions
				link.Severity = a.severity
				link.PolicyAction = a.policyAction
				flag |= linkGraph
				link.Entries = make([]*GraphSyncEntry, len(a.entries))
				var k int
				for key, entry := range a.entries {
					link.Entries[k] = graphEntry2Sync(&key, entry)
					k++
				}
			}
			if flag > 0 {
				link.From = nodes[i].Name
				link.To = nodes[j].Name
				link.Flag = flag
				links = append(links, &link)
			}
			j++
		}
		i++
	}

	var violations []*api.Violation
	if curVioIndex > 0 {
		violations = vioCache[0:curVioIndex]
	}

	learnedRules := make([]*graphSyncLearnedRule, 0, len(lprWrapperMap))
	for pair, rw := range lprWrapperMap {
		learnedRules = append(learnedRules, getSyncLearnedRule(&pair, rw))
	}

	gd := graphSyncData{
		Nodes:          nodes,
		Links:          links,
		Vios:           violations,
		LearnedRules:   learnedRules,
		MaxLearnRuleID: maxLearnRuleID,
	}
	data, err := json.Marshal(gd)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("marshal error")
		return nil
	} /* else {
		//log.WithFields(log.Fields{"data": string(data)}).Debug("marshal result")
	} */
	msg := syncDataMsg{CatgName: syncCatgGraph, ModifyIdx: getModifyIdx(syncCatgGraphIdx), Data: data}
	log.WithFields(log.Fields{
		"nodes": len(nodes), "links": len(links), "violations": len(violations),
		"rules": len(learnedRules), "maxLearnRuleID": maxLearnRuleID, "data": len(data),
	}).Info()
	return &msg
}

func syncGraphRx(msg *syncDataMsg) int {
	graphMutexLock()

	if !validateModifyIdx(syncCatgGraphIdx, msg.ModifyIdx) {
		graphMutexUnlock()
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	defer graphMutexUnlock()

	if msg.Data != nil {
		var gd graphSyncData
		if err := json.Unmarshal(msg.Data, &gd); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			return syncRxErrorFailed
		} else {
			log.WithFields(log.Fields{
				"nodes": len(gd.Nodes), "links": len(gd.Links), "vios": len(gd.Vios),
				"rules": len(gd.LearnedRules), "maxLearnRuleID": gd.MaxLearnRuleID,
			}).Info()

			wlGraph.Reset()
			renameMap := make(map[string]string)

			for _, node := range gd.Nodes {
				var a nodeAttr
				a.external = node.External
				a.addrgrp = node.Addrgrp
				a.ipsvcgrp = node.IPSvcgrp
				a.workload = node.Workload
				a.host = node.Host
				a.managed = node.Managed
				a.hostID = node.HostID
				a.alias = node.Alias

				// Rename Host:name to Host:ID
				name := node.Name
				if n, ok := renameMap[name]; ok {
					name = n
				} else if node.Host && node.Managed && node.HostID != "" {
					name = specialEPName(api.LearnedHostPrefix, node.HostID)
					renameMap[node.Name] = name
				}

				wlGraph.AddLink(name, attrLink, dummyEP, &a)
			}
			for _, link := range gd.Links {
				if link.Flag&linkPolicy > 0 {
					a := polAttr{apps: utils.NewSet(), ports: utils.NewSet(), portsSeen: utils.NewSet()}
					for _, port := range link.Ports {
						a.ports.Add(port)
					}
					for _, app := range link.Apps {
						a.apps.Add(app)
					}

					// Rename Host:name to Host:ID
					from := link.From
					to := link.To
					if f, ok := renameMap[from]; ok {
						from = f
					}
					if t, ok := renameMap[to]; ok {
						to = t
					}

					wlGraph.AddLink(from, policyLink, to, &a)
				}
				if link.Flag&linkGraph > 0 {
					var a graphAttr
					a.bytes = link.Bytes
					a.sessions = link.Sessions
					a.severity = link.Severity
					a.policyAction = link.PolicyAction
					a.entries = make(map[graphKey]*graphEntry)
					for _, e := range link.Entries {
						gkey, entry := graphSync2Entry(e)
						a.entries[*gkey] = entry
					}

					// Rename Host:name to Host:ID
					from := link.From
					to := link.To
					if f, ok := renameMap[from]; ok {
						from = f
					}
					if t, ok := renameMap[to]; ok {
						to = t
					}

					wlGraph.AddLink(from, graphLink, to, &a)
				}
			}

			curVioIndex = len(gd.Vios)
			for i, vio := range gd.Vios {
				vio.Level = api.UpgradeLogLevel(vio.Level)
				vioCache[i] = vio
			}

			maxLearnRuleID = gd.MaxLearnRuleID
			//after sync clear active rule id list
			lprActiveRuleIDs.Clear()
			lprWrapperMap = make(map[groupPair]*learnedPolicyRuleWrapper)
			for _, s := range gd.LearnedRules {
				pair, rw := recoverLearnedRule(s)
				lprWrapperMap[*pair] = rw
				//keep track of id being synced
				lprActiveRuleIDs.Add(rw.id)
			}
			setModifyIdx(syncCatgGraphIdx, msg.ModifyIdx)
		}
	} else {
		// Empty sync data - this should not happen
		log.WithFields(log.Fields{"msg": msg}).Error("Empty data!")
	}
	return syncRxErrorNone
}

func checkGraphSyncState(ss *share.CLUSPolicySyncStatus, compareRules bool) {
	errorList := make([]*share.CLUSPolicyRuleMismatch, 0)
	syncStatusMap := make(map[uint32]bool) //key is rule id

	graphMutexRLock()
	cacheMutexRLock()
	if compareRules {
		//first loop to decide sync status of rules
		for pair, rw := range lprWrapperMap {
			rule := learnedRule2ClusterRule(&pair, rw)
			// 1. Only compare the rules if it is in the policy cache,
			// because some rules are not written to the cluster yet.
			// We have learned rule modify case, so using ruleContains()
			// instead of exact equal for comparison
			// 2. Learned rules with duplicate rule id may cause infinite
			// sync, we need to consider such case to decide sync status
			if cr, ok := policyCache.ruleMap[rw.id]; ok {
				if !ruleContains(rule, cr) {
					if _, ok1 := syncStatusMap[rw.id]; !ok1 {
						syncStatusMap[rw.id] = false
					}
				} else {
					if st, ok1 := syncStatusMap[rw.id]; ok1 {
						if !st {
							syncStatusMap[rw.id] = true
						}
					} else {
						syncStatusMap[rw.id] = true
					}
				}
			}
		}
		//second loop to fill mismatch content if any
		for pair, rw := range lprWrapperMap {
			if st, ok := syncStatusMap[rw.id]; ok && !st { //not in sync
				rule := learnedRule2ClusterRule(&pair, rw)
				if cr, ok1 := policyCache.ruleMap[rw.id]; ok1 {
					errorList = append(errorList,
						&share.CLUSPolicyRuleMismatch{
							ClusterRule: &share.CLUSPolicyRuleCheck{
								ID: cr.ID, From: cr.From, To: cr.To,
								Ports: cr.Ports, Applications: cr.Applications,
								Disabled:  cr.Disable,
								CreatedTS: cr.CreatedAt.Unix(), LastModTS: cr.LastModAt.Unix(),
							},
							LearnedRule: &share.CLUSPolicyRuleCheck{
								ID: rule.ID, From: rule.From, To: rule.To,
								Ports: rule.Ports, Applications: rule.Applications,
								Disabled:  rule.Disable,
								CreatedTS: rule.CreatedAt.Unix(), LastModTS: rule.LastModAt.Unix(),
							},
						})
				}
			}
		}
	}
	ss.GraphNodeCount = uint32(wlGraph.GetNodeCount())
	ss.LearnedRuleMax = maxLearnRuleID
	cacheMutexRUnlock()
	graphMutexRUnlock()
	ss.Mismatches = errorList
}
