package cache

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/graph"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	dummyEP = "Dummy"
)

const (
	policyLink = "policy"
	graphLink  = "graph"
	attrLink   = "attr"
)

// Workaround test package doesn't support cgo
const (
	DP_POLICY_ACTION_OPEN      = C.DP_POLICY_ACTION_OPEN
	DP_POLICY_ACTION_LEARN     = C.DP_POLICY_ACTION_LEARN
	DP_POLICY_ACTION_ALLOW     = C.DP_POLICY_ACTION_ALLOW
	DP_POLICY_ACTION_CHECK_VH  = C.DP_POLICY_ACTION_CHECK_VH
	DP_POLICY_ACTION_CHECK_APP = C.DP_POLICY_ACTION_CHECK_APP
	DP_POLICY_ACTION_VIOLATE   = C.DP_POLICY_ACTION_VIOLATE
	DP_POLICY_ACTION_DENY      = C.DP_POLICY_ACTION_DENY
)

// When adding fields, don't forget update GraphSyncEntry
type graphEntry struct {
	bytes        uint64
	sessions     uint32
	server       uint32
	threatID     uint32
	dlpID        uint32
	wafID        uint32
	mappedPort   uint16
	severity     uint8
	dlpSeverity  uint8
	wafSeverity  uint8
	policyAction uint8
	policyID     uint32
	last         uint32
	xff          uint8
	toSidecar    uint8
	fqdn         string // server fqdn if it is egress direction. otherwise, the fqdn is empty
	nbe          uint8
}

type graphKey struct {
	port        uint16
	ipproto     uint8
	application uint32
	cip         uint32 // client ip
	sip         uint32 // server ip
}

type graphAttr struct {
	bytes        uint64
	sessions     uint32
	severity     uint8
	policyAction uint8
	entries      map[graphKey]*graphEntry
}

type polAttr struct {
	ports        utils.Set // string
	portsSeen    utils.Set // string, only used to qualify conn, not used to calculate policyy
	apps         utils.Set // uint32
	lastRecalcAt int64
}

type nodeAttr struct {
	external bool
	workload bool
	host     bool
	managed  bool
	addrgrp  bool
	ipsvcgrp bool
	hostID   string
	alias    string
}

type serverTip struct {
	wlPort     uint16
	mappedPort uint16
	appServer  uint32
}

// Within graphMutex, cacheMutex can be used; but not the other way around.
var graphMutex sync.RWMutex
var wlGraph *graph.Graph

func graphMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	graphMutex.Lock()
}

func graphMutexUnlock() {
	graphMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func graphMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	graphMutex.RLock()
}

func graphMutexRUnlock() {
	graphMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

// Not to do grouping too often, Only when no new link is added for 10 seconds;
const policyProcDelayIdle = time.Duration(time.Second * 10)

// but not to slow either, guarantee to do calculation every 3 minutes
const policyProcDelayMax = time.Duration(time.Second * 180)

var firstPolicyUpdateAt time.Time
var policyUpdated bool
var policyProcTimer *time.Timer
var vulProfUpdateTimer *time.Timer

const vulProfUpdateDelayIdle = time.Duration(time.Second * 2)

// policy recalculation
var firstPolicyCalculateAt time.Time
var policyCalculated bool
var policyCalculatingTimer *time.Timer
var ctrlSyncTimer *time.Timer
var dlpCalculatingTimer *time.Timer

const policyCalDelayMax = time.Duration(time.Second * 60)
const policyCalculatingDelayFast = time.Duration(time.Second * 2)
const policyCalculatingDelaySlow = time.Duration(time.Second * 4)

const policyClusterLockWait = time.Duration(time.Second * 12)

func conn2Violation(conn *share.CLUSConnection, server uint32) *api.Violation {
	cwln := getWorkloadNameForLogging(conn.ClientWL)
	swln := getWorkloadNameForLogging(conn.ServerWL)

	c := &api.Violation{
		LogCommon: api.LogCommon{
			ReportedTimeStamp: time.Unix(int64(conn.LastSeenAt), 0).UTC().Unix(),
			ReportedAt:        api.RESTTimeString(time.Unix(int64(conn.LastSeenAt), 0).UTC()),
			ClusterName:       systemConfigCache.ClusterName,
			HostID:            conn.HostID,
			HostName:          getHostName(conn.HostID),
			AgentID:           conn.AgentID,
			AgentName:         getAgentName(conn.AgentID),
		},
		ID:            conn.LogUID,
		ClientWL:      conn.ClientWL,
		ServerWL:      conn.ServerWL,
		ServerPort:    uint16(conn.ServerPort),
		IPProto:       uint8(conn.IPProto),
		PolicyAction:  common.PolicyActionString(uint8(conn.PolicyAction)),
		PolicyID:      conn.PolicyId,
		Sessions:      conn.Sessions,
		ClientIP:      net.IP(conn.ClientIP).String(),
		ServerIP:      net.IP(conn.ServerIP).String(),
		FQDN:          conn.FQDN,
		ClientName:    cwln.name,
		ClientDomain:  cwln.domain,
		ClientImage:   cwln.image,
		ClientService: cwln.service,
		ServerName:    swln.name,
		ServerDomain:  swln.domain,
		ServerImage:   swln.image,
		ServerService: swln.service,
		Xff:           conn.Xff,
		Nbe:           conn.Nbe,
	}
	if conn.PolicyAction == C.DP_POLICY_ACTION_DENY {
		c.Level = api.LogLevelCRIT
	} else {
		c.Level = api.LogLevelWARNING
	}

	appName, _ := common.AppNameMap[conn.Application]
	svrName, _ := common.AppNameMap[server]
	c.Applications = []string{appName}
	c.Servers = []string{svrName}
	return c
}

// Merge workload mapped ports and workload traffic ports. Return RESTIPPort in mapset
/*
func mergeWorkloadPorts(ports []api.RESTWorkloadPorts, links utils.Set) utils.Set {
	portSet := utils.NewSet()

	for _, p := range ports {
		portSet.Add(share.GetPortLink(p.IPProto, p.Port))
	}

	portSet = portSet.Union(links)

	return portSet
}
*/

func isDummyEndpoint(name string) bool {
	return name == dummyEP
}

func isHostOrUnmanagedWorkload(name string) bool {
	return strings.HasPrefix(name, api.LearnedHostPrefix) ||
		strings.HasPrefix(name, api.LearnedWorkloadPrefix)
}

func isFqdnGroup(name string) bool {
	if gfqs, ok := grp2FqdnMap[name]; ok {
		if gfqs != nil && gfqs.Cardinality() > 0 {
			return true
		}
	}
	return false
}

func isNonWorkloadLearnedEndpoint(name string) bool {
	return isHostOrUnmanagedWorkload(name) || isFqdnGroup(name) || name == api.LearnedExternal ||
		strings.HasPrefix(name, api.LearnedGroupPrefix)
}

func isInfraTraffic(ipproto uint8, app uint32) bool {
	if ipproto != syscall.IPPROTO_TCP && ipproto != syscall.IPPROTO_UDP {
		return true
	}
	return app == C.DPI_APP_DNS || app == C.DPI_APP_DHCP || app == C.DPI_APP_NTP ||
		app == C.DPI_APP_ECHO
}

func scheduleLearnedPolicyProc() {
	if !policyUpdated {
		policyUpdated = true
		firstPolicyUpdateAt = time.Now().UTC()
		policyProcTimer.Reset(policyProcDelayIdle)
	} else if time.Since(firstPolicyUpdateAt) > policyProcDelayMax {
		log.Debug("Trigger policy proc")
		policyProcTimer.Reset(0)
	} else {
		policyProcTimer.Reset(policyProcDelayIdle)
	}
}

func isWorkloadNode(node string) bool {
	if a := wlGraph.Attr(node, attrLink, dummyEP); a != nil {
		attr := a.(*nodeAttr)
		return attr.workload && attr.managed
	}

	return false
}

func dumpLink(c, l, s string) {
	cctx.ConnLog.WithFields(log.Fields{"client": c, "server": s, "link": l}).Debug("Add link")
}

// Called with cacheMutex read lock
func isAddressGroup(name string) bool {
	if gc, ok := groupCacheMap[name]; ok {
		if len(gc.group.Criteria) > 0 && gc.group.Criteria[0].Key == share.CriteriaKeyAddress {
			return true
		}
	}
	return false
}

func getFqdnAddrGroupName(fqdn string) string {
	if grps, ok := fqdn2GrpMap[fqdn]; ok {
		return grps.Any().(string)
	}
	//try wildcard
	fn := strings.Split(fqdn, ".")
	fqdnlen := len(fn)
	for i := 0; i < fqdnlen-2; i++ {
		tfqdn := "*"
		for j := i+1; j < fqdnlen; j++ {
			tfqdn = fmt.Sprintf("%s.%s", tfqdn, fn[j])
		}
		if fgrps, ok := fqdn2GrpMap[tfqdn]; ok {
			return fgrps.Any().(string)
		}
	}
	if fqdnlen == 2 {
		tfqdn := fmt.Sprintf("%s.%s", "www", fqdn)
		if fgrps, ok := fqdn2GrpMap[tfqdn]; ok {
			return fgrps.Any().(string)
		}
		tfqdn = fmt.Sprintf("%s.%s", "*", fqdn)
		if fgrps, ok := fqdn2GrpMap[tfqdn]; ok {
			return fgrps.Any().(string)
		}
	}
	return ""
}

func getIpAddrGroupName(ip string) string {
	if grps, ok := ip2GrpMap[ip]; ok {
		return grps.Any().(string)
	}
	return ""
}

func getAddrGroupNameFromPolicy(polid uint32, client bool) string {
	if polid != 0 {
		cacheMutexRLock()
		defer cacheMutexRUnlock()
		if pol, ok := policyCache.ruleMap[polid]; ok {
			var group string
			if client {
				group = pol.From
			} else {
				group = pol.To
			}
			if isAddressGroup(group) {
				return group
			}
		}
	}

	return ""
}

func specialEPName(ep, name string) string {
	return fmt.Sprintf("%s%s", ep, name)
}

type actionEntry struct {
	policyAction uint8
	last         uint32
}

type actionKey struct {
	port        uint16
	ipproto     uint8
	application uint32
}

func getAggregatedAction(entries map[graphKey]*graphEntry) uint8 {
	actionMap := make(map[actionKey]*actionEntry)
	for gkey, ge := range entries {
		k := actionKey{port: gkey.port, ipproto: gkey.ipproto,
			application: gkey.application}
		if exist, ok := actionMap[k]; ok {
			if exist.last < ge.last {
				exist.last = ge.last
				exist.policyAction = ge.policyAction
			}
		} else {
			actionMap[k] = &actionEntry{
				policyAction: ge.policyAction,
				last:         ge.last,
			}
		}
	}
	var act uint8 = 0
	for _, e := range actionMap {
		//log.WithFields(log.Fields{"k": k, "e": e, "act": act}).Debug("########")
		if e.policyAction > act {
			act = e.policyAction
		}
	}
	return act
}

func recalcConversation(attr *graphAttr) {
	attr.bytes = 0
	attr.sessions = 0
	attr.severity = 0
	attr.policyAction = 0
	for _, ge := range attr.entries {
		attr.bytes += ge.bytes
		attr.sessions += ge.sessions
		if ge.severity > attr.severity {
			attr.severity = ge.severity
		}
		if ge.dlpSeverity > attr.severity {
			attr.severity = ge.dlpSeverity
		}
		if ge.wafSeverity > attr.severity {
			attr.severity = ge.wafSeverity
		}
	}
	attr.policyAction = getAggregatedAction(attr.entries)
}

func deleteConversationByNode(node string) {
	outs := wlGraph.OutsByLink(node, graphLink)
	for o := range outs.Iter() {
		wlGraph.DeleteLink(node, graphLink, o.(string))
	}
	ins := wlGraph.InsByLink(node, graphLink)
	for i := range ins.Iter() {
		wlGraph.DeleteLink(i.(string), graphLink, node)
	}
}

func deleteConversationByKeyIfViolation(fromNode, toNode string, key *graphKey) {
	if a := wlGraph.Attr(fromNode, graphLink, toNode); a != nil {
		attr := a.(*graphAttr)
		if e, ok := attr.entries[*key]; ok {
			if e.policyAction > C.DP_POLICY_ACTION_CHECK_APP {
				delete(attr.entries, *key)
				if len(attr.entries) == 0 {
					wlGraph.DeleteLink(fromNode, graphLink, toNode)
				} else {
					recalcConversation(attr)
				}
			}
		}
	}
}

func deleteConversationByKey(fromNode, toNode string, key *graphKey) {
	if a := wlGraph.Attr(fromNode, graphLink, toNode); a != nil {
		attr := a.(*graphAttr)
		if _, ok := attr.entries[*key]; ok {
			delete(attr.entries, *key)
			if len(attr.entries) == 0 {
				wlGraph.DeleteLink(fromNode, graphLink, toNode)
			} else {
				recalcConversation(attr)
			}
		}
	}
}

func deleteConversationByPolicyId(fromNode, toNode string, id uint32) {
	if a := wlGraph.Attr(fromNode, graphLink, toNode); a != nil {
		var found bool
		attr := a.(*graphAttr)
		for gkey, ge := range attr.entries {
			if ge.policyID == id {
				delete(attr.entries, gkey)
				found = true
			}
		}
		if found {
			if len(attr.entries) == 0 {
				wlGraph.DeleteLink(fromNode, graphLink, toNode)
			} else {
				recalcConversation(attr)
			}
		}
	}
}

// obsolete. Use grpc instead
func connectUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	if checkModifyIdx(syncCatgGraphIdx, modifyIdx) == false {
		return
	}

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			cctx.ConnLog.Error("Failed to unzip data")
			return
		}

		var conns []*share.CLUSConnection
		json.Unmarshal(uzb, &conns)

		UpdateConnections(conns)

		setModifyIdx(syncCatgGraphIdx, modifyIdx)
	}
}

const (
	sessCurInViolation uint8 = (1 << iota)
	sessionInViolation
	bandwidInViolation
)
const (
	SESS_CUR_VIOLATION = "IngressActiveSessionViolation"
	SESS_IN_VIOLATION  = "IngressSessionRateViolation"
	BAND_IN_VIOLATION  = "IngressBandwidthViolation"
)

const CalWlMetMax int = 32
const MetSlotInterval uint32 = 5

func groupMetricViolationEvent(ev share.TLogEvent, group string, vio_met uint8,
	grpSessCurIn, grpSessRateInVio, grpBandwidthInVio uint32) {
	clog := share.CLUSEventLog{
		Event:      ev,
		GroupName:  group,
		ReportedAt: time.Now().UTC(),
	}
	vioMetStr := ""
	if (vio_met & sessCurInViolation) > 0  {
		vioMetStr = fmt.Sprintf("%s(%d current active session)", SESS_CUR_VIOLATION, grpSessCurIn)
	}
	if (vio_met & sessionInViolation) > 0 {
		if vioMetStr != "" {
			vioMetStr = fmt.Sprintf("%s, %s(%dcps)", vioMetStr, SESS_IN_VIOLATION, grpSessRateInVio)
		} else {
			vioMetStr = fmt.Sprintf("%s(%dcps)", SESS_IN_VIOLATION, grpSessRateInVio)
		}
	}
	if (vio_met & bandwidInViolation) > 0 {
		if vioMetStr != "" {
			vioMetStr = fmt.Sprintf("%s, %s(%dMbps)", vioMetStr, BAND_IN_VIOLATION, grpBandwidthInVio)
		} else {
			vioMetStr = fmt.Sprintf("%s(%dMbps)", BAND_IN_VIOLATION, grpBandwidthInVio)
		}
	}
	clog.Msg = fmt.Sprintf("Group %s exceed preconfigured metric threshold: %s.\n", group, vioMetStr)
	cctx.EvQueue.Append(&clog)
}

func CheckGroupMetric() {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	//check metric violation
	for lgrpname, grpmet := range groupMetricMap {
		var vioMet uint8 = 0
		if grpcache, ok := groupCacheMap[lgrpname]; ok {
			cctx.ConnLog.WithFields(log.Fields{
				"GroupSessCurIn":    grpmet.GroupSessCurIn,
				"GroupSessIn12":     grpmet.GroupSessIn12,
				"GroupByteIn12":     grpmet.GroupByteIn12,
			}).Debug()
			grpSessCurIn := grpmet.GroupSessCurIn//active session count
			grpSessRateIn12 := uint32(grpmet.GroupSessIn12/(12*MetSlotInterval))//session per second
			grpBandwidthIn12 := uint32(grpmet.GroupByteIn12*8/uint64(12*MetSlotInterval)/1000000)//mbps

			if grpcache.group.GrpSessCur > 0 && grpSessCurIn > grpcache.group.GrpSessCur {
				vioMet |= sessCurInViolation
			}
			//try past 60sec to see whether there is any violation
			if grpcache.group.GrpSessRate > 0 && grpSessRateIn12 > grpcache.group.GrpSessRate {
				vioMet |= sessionInViolation
			}
			if grpcache.group.GrpBandWidth > 0 && grpBandwidthIn12 > grpcache.group.GrpBandWidth {
				vioMet |= bandwidInViolation
			}
			cctx.ConnLog.WithFields(log.Fields{
				"vioMet":           vioMet,
				"grpSessCurIn":     grpSessCurIn,
				"grpSessRateIn12":  grpSessRateIn12,
				"grpBandwidthIn12": grpBandwidthIn12,
			}).Debug()
			if vioMet > 0 {
				groupMetricViolationEvent(share.CLUSEvGroupMetricViolation, lgrpname, vioMet,
					grpSessCurIn, grpSessRateIn12, grpBandwidthIn12)
			}
			grpmet.GroupSessCurIn = 0//reset
			grpmet.GroupSessIn12 = 0
			grpmet.GroupByteIn12 = 0
			for _, cwlmet := range grpmet.WlMetric {
				cwlmet.WlSessCurIn = 0
				cwlmet.WlSessIn12 = 0
				cwlmet.WlByteIn12 = 0
			}
		}
	}
}

func getRealMemCnt(cache *workloadCache, grpcache *groupCache) int {
	memcnt := grpcache.members.Cardinality()
	if memcnt == 1 {
		return memcnt
	}
	isSvcMesh := false
	if cache.workload.ShareNetNS != "" {
		if pa, ok := wlCacheMap[cache.workload.ShareNetNS]; ok {
			isSvcMesh = pa.workload.ProxyMesh
		}
	} else {
		isSvcMesh = cache.workload.ProxyMesh
	}
	if isSvcMesh {
		memcnt = memcnt/3
	} else {
		memcnt = memcnt/2
	}
	return memcnt
}

func calGrpMet(lgrpname, epWL string, cache *workloadCache, grpcache *groupCache, conn *share.CLUSConnection) {
	if lgrpname != "" {
		if groupMetricMap == nil {
			groupMetricMap = make(map[string]*share.CLUSGroupMetric)
		}
		if grpMet, ok := groupMetricMap[lgrpname]; ok {
			memcnt := getRealMemCnt(cache, grpcache)
			exceedMax := false
			if grpMet.WlMetric == nil {
				grpMet.WlMetric = make(map[string]*share.CLUSWlMetric)
			}
			if len(grpMet.WlMetric) == CalWlMetMax && memcnt > CalWlMetMax {
				//only sample CalWlMetMax member of group
				exceedMax = true
			}
			if wlmetric, exst := grpMet.WlMetric[epWL]; exst {
				if conn.EpSessCurIn > wlmetric.WlSessCurIn {
					wlmetric.WlSessCurIn = conn.EpSessCurIn
				}
				if conn.EpSessIn12 > wlmetric.WlSessIn12 {
					wlmetric.WlSessIn12 = conn.EpSessIn12
				}
				if conn.EpByteIn12 > wlmetric.WlByteIn12 {
					wlmetric.WlByteIn12 = conn.EpByteIn12
				}
			} else {
				if !exceedMax {
					wlmet := &share.CLUSWlMetric {
						WlID: epWL,
						WlSessCurIn: conn.EpSessCurIn,
						WlSessIn12:  conn.EpSessIn12,
						WlByteIn12:  conn.EpByteIn12,
					}
					grpMet.WlMetric[epWL] = wlmet
				}
			}
			//reset group metric
			grpMet.GroupSessCurIn = 0
			grpMet.GroupSessIn12 = 0
			grpMet.GroupByteIn12 = 0
			for _, cwlmet := range grpMet.WlMetric {
				grpMet.GroupSessCurIn += cwlmet.WlSessCurIn
				grpMet.GroupSessIn12 += cwlmet.WlSessIn12
				grpMet.GroupByteIn12 += cwlmet.WlByteIn12
			}
			if exceedMax {
				var avGrpSessCurIn float32
				var avGrpSessIn12 float32
				var avGrpByteIn12 float64

				avGrpSessCurIn = float32(grpMet.GroupSessCurIn) / float32(CalWlMetMax)
				avGrpSessIn12 = float32(grpMet.GroupSessIn12) / float32(CalWlMetMax)
				avGrpByteIn12 = float64(grpMet.GroupByteIn12) / float64(CalWlMetMax)

				grpMet.GroupSessCurIn = uint32(avGrpSessCurIn * float32(memcnt))
				grpMet.GroupSessIn12 = uint32(avGrpSessIn12 * float32(memcnt))
				grpMet.GroupByteIn12 = uint64(avGrpByteIn12 * float64(memcnt))
			}
		} else {
			grpMetric := &share.CLUSGroupMetric {
				GroupName: lgrpname,
				GroupSessCurIn: conn.EpSessCurIn,
				GroupSessIn12: conn.EpSessIn12,
				GroupByteIn12: conn.EpByteIn12,
			}
			if grpMetric.WlMetric == nil {
				grpMetric.WlMetric = make(map[string]*share.CLUSWlMetric)
			}
			wlmet := &share.CLUSWlMetric {
				WlID: epWL,
				WlSessCurIn: conn.EpSessCurIn,
				WlSessIn12:  conn.EpSessIn12,
				WlByteIn12:  conn.EpByteIn12,
			}
			grpMetric.WlMetric[epWL] = wlmet
			groupMetricMap[lgrpname] = grpMetric
		}
	}
}

func isCalGrpMet(grpcache *groupCache) bool {
	if  grpcache.group.MonMetric && (grpcache.group.GrpSessCur > 0 || grpcache.group.GrpSessRate > 0 ||
		grpcache.group.GrpBandWidth > 0) && (grpcache.group.CfgType == share.Learned ||
		grpcache.group.CfgType == share.UserCreated || 	grpcache.group.CfgType == share.GroundCfg ||
		grpcache.group.CfgType == share.FederalCfg) &&	grpcache.group.Kind == share.GroupKindContainer &&
		!grpcache.group.Reserved {
		return true
	}
	return false
}

//EP's stats are piggybacked in connection to detect whether
//there are bandwidth/session-rate violation based on pre-configured threshold
func CalculateGroupMetric(conn *share.CLUSConnection) {
	//when metric threshold is not set, do not calculate group metric
	if strings.Contains(conn.Network, share.NetworkProxyMesh)|| conn.Xff || conn.MeshToSvr {
		return
	}
	var epWL string
	if conn.Ingress {
		epWL = conn.ServerWL
	} else {
		epWL = conn.ClientWL
	}
	if cache := getWorkloadCache(epWL); cache != nil {
		cacheMutexLock()
		defer cacheMutexUnlock()
		for name := range cache.groups.Iter() {
			lgrpname := name.(string)
			if grpcache, ok := groupCacheMap[lgrpname]; ok && isCalGrpMet(grpcache) {
				calGrpMet(lgrpname, epWL, cache, grpcache, conn)
			}
		}
	}
}

func UpdateConnections(conns []*share.CLUSConnection) {
	//syncLock(syncCatgGraphIdx)
	// use graph lock instead of sync lock for simplicity
	graphMutexLock()
	defer graphMutexUnlock()

	for i, _ := range conns {
		conn := conns[i]
		if !preQualifyConnect(conn) {
			continue
		}
		if conn.Ingress {
			CalculateGroupMetric(conn)
		}

		var ca, sa *nodeAttr
		var stip *serverTip
		var add bool
		var scwl string

		if strings.Contains(conn.Network, share.NetworkProxyMesh) {
			if conn.Ingress {
				scwl = conn.ClientWL
			} else {
				scwl = conn.ServerWL
			}
		}

		if policyApplyIngress {
			ca, sa, stip, add = preProcessConnectPAI(conn)
		} else {
			ca, sa, stip, add = preProcessConnect(conn)
		}

		if !add {
			continue
		}

		if !postQualifyConnect(conn, ca, sa) {
			continue
		}

		cctx.ConnLog.WithFields(log.Fields{
			"agent":          container.ShortContainerId(conn.AgentID),
			"host":           conn.HostID,
			"client":         container.ShortContainerId(conn.ClientWL),
			"server":         container.ShortContainerId(conn.ServerWL),
			"clientIP":       net.IP(conn.ClientIP),
			"serverIP":       net.IP(conn.ServerIP),
			"clientPort":     conn.ClientPort,
			"serverPort":     conn.ServerPort,
			"ipproto":        conn.IPProto,
			"app":            conn.Application,
			"scope":          conn.Scope,
			"network":        conn.Network,
			"bytes":          conn.Bytes,
			"sessions":       conn.Sessions,
			"first":          conn.FirstSeenAt,
			"last":           conn.LastSeenAt,
			"threatID":       conn.ThreatID,
			"threatSev":      conn.Severity,
			"policyAction":   conn.PolicyAction,
			"policyID":       conn.PolicyId,
			"policyViolates": conn.Violates,
			"ingress":        conn.Ingress,
			"external":       conn.ExternalPeer,
			"local":          conn.LocalPeer,
			"xff":            conn.Xff,
			"extIP":          conn.SvcExtIP,
			"toSidecar":      conn.ToSidecar,
			"meshToSvr":      conn.MeshToSvr,
			"linkLocal":      conn.LinkLocal,
			"fqdn":           conn.FQDN,
			"nbe":            conn.Nbe,
			"nbesns":         conn.NbeSns,
			"EpSessCurIn":    conn.EpSessCurIn,
			"EpSessIn12":     conn.EpSessIn12,
			"EpByteIn12":     conn.EpByteIn12,
		}).Debug()

		addConnectToGraph(conn, ca, sa, stip)

		//add additional conversation link between sidecar and app
		if strings.Contains(conn.Network, share.NetworkProxyMesh) && !conn.Xff && !conn.MeshToSvr {
			if conn.Ingress {
				conn.ClientWL = scwl
			} else {
				conn.ServerWL = scwl
			}
			addConnectToGraph(conn, ca, sa, stip)
		}
	}
}

func preQualifyConnect(conn *share.CLUSConnection) bool {
	/*
		if conn.IPProto != syscall.IPPROTO_TCP && conn.IPProto != syscall.IPPROTO_UDP && conn.Severity == 0 {
			cctx.ConnLog.WithFields(log.Fields{"protocol": conn.IPProto}).Debug("Ignore non-TCP/UDP conntection")
			return false
		}
	*/

	var localWL string
	if conn.Ingress {
		localWL = conn.ServerWL
	} else {
		localWL = conn.ClientWL
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	// Ignore the connection if the rule has been removed. This is somewhat heuristic.
	// For example, the rule is removed and then new rule with the same ID is created,
	// it won't be detected and there will be a mismatch.
	if conn.PolicyId != 0 {
		if _, ok := policyCache.ruleMap[conn.PolicyId]; !ok {
			cctx.ConnLog.WithFields(log.Fields{"id": conn.PolicyId}).Debug("Ignore connection with obsolete policy id")
			return false
		}
	}

	if _, ok := wlCacheMap[localWL]; !ok {
		cctx.ConnLog.WithFields(log.Fields{"id": localWL}).Debug("Ignore connection reported from a left container")
		return false
	}

	return true
}

// With cacheMutex hold
func isWorkloadQuarantine(id string) bool {
	if cache, ok := wlCacheMap[id]; ok {
		return cache.workload.Quarantine
	}
	return false
}

func postQualifyConnect(conn *share.CLUSConnection, ca, sa *nodeAttr) bool {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if ca.workload && ca.managed && isWorkloadQuarantine(conn.ClientWL) {
		return false
	}

	if sa.workload && sa.managed && isWorkloadQuarantine(conn.ServerWL) {
		return false
	}

	return true
}

func wouldGenerateUnmanagedEndpoint(conn *share.CLUSConnection, ingress bool) bool {
	// Disable this check to avoid missing conversations
	// For example, the policy can be from workload to unmanaged
	// workload/host. If the rule is preloaded, then it is possible that the
	// endpoint is not in graph yet.

	/*
		// When in protect mode, a violation can have 0 session count
		if conn.Sessions == 0 && conn.Violates == 0 && conn.Severity == 0 {
			return false
		}

		if (conn.PolicyAction != C.DP_POLICY_ACTION_OPEN) && conn.PolicyId != 0 {
			return false
		}
	*/
	return true
}

const resyncRequestReasonEphemeral = 1

func scheduleControllerResync(reason int) {
	if isLeader() == false {
		return
	}

	var syncFilter []ctrlResyncFilter = make([]ctrlResyncFilter, 0)
	cacheMutexRLock()
	switch reason {
	case resyncRequestReasonEphemeral:
		if len(wlEphemeral) > 0 {
			for _, cache := range ctrlCacheMap {
				if cache.state == api.StateOnline &&
					cache.joinAt.After(wlEphemeral[0].stop) {
					syncFilter = append(syncFilter, ctrlResyncFilter{ctrlID: cache.ctrl.ID})
				}
			}
		}
	}
	cacheMutexRUnlock()
	if len(syncFilter) > 0 {
		queueHotSyncRequest(syncFilter)
	}
}

// Check from global IP. We already know the IP is of Global scope.
// Return if connection should be added.
func connectFromGlobal(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip) bool {
	if wl, alive := getWorkloadFromGlobalIP(conn.ClientIP); wl != "" {
		if alive == false && wouldGenerateUnmanagedEndpoint(conn, true) {
			scheduleControllerResync(resyncRequestReasonEphemeral)
		}
		if conn.UwlIp {
			// Unmanaged workload
			if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
				conn.ClientWL = ep
				ca.addrgrp = true
			} else {
				ipStr := net.IP(conn.ClientIP).String()
				ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
				conn.ClientWL = ep
			}
			stip.wlPort = uint16(conn.ServerPort)
			ca.workload = true
			return true
		} else if conn.Nbe || conn.NbeSns{
			if alive {
				conn.ClientWL = wl
				stip.wlPort = uint16(conn.ServerPort)
				ca.workload = true
				ca.managed = true
				return true
			}
		}
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection from global IP space")
		return false
	} else {
		// From unmanaged workload
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
			conn.ClientWL = ep
			ca.addrgrp = true
		} else {
			ipStr := net.IP(conn.ClientIP).String()
			ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, true) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection with old session from unknown global IP")
				return false
			}
			conn.ClientWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		ca.workload = true
	}

	return true
}

// Check from local container. Return if client is local, if connection should be added.
func connectFromLocal(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip) (bool, bool) {
	// This function also checks if container is on the host's local subnets (172.x.x.x).
	if local, _, _ := getWorkloadFromIPOnHost(net.IP(conn.ClientIP), conn.HostID); !local {
		return false, false
	} else {
		// In local subnet
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection from local container")
		return true, false
	}
}

func connectFromManagedHost(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip, hostID string) bool {
	if global.ORCH.IgnoreConnectFromManagedHost() {
		// If we cannot tell if an ingress connection is from a host process, or from a
		// local container, source IP in both case are docker0's IP
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection from managed host")
		return false
	}

	/* to be tested
	if conn.ClientWL != "" {
		// This is only possible if this is host-mode container to host-mode container on the same host
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection to known workload")
		return false
	}
	*/

	remoteCache := getHostCache(hostID)
	if remoteCache == nil || remoteCache.host == nil || remoteCache.host.Name == "" {
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection from unknown host")
		return false
	}

	conn.ClientWL = specialEPName(api.LearnedHostPrefix, remoteCache.host.ID)
	if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
		conn.ClientWL = ep
		ca.addrgrp = true
	}

	ca.host = true
	ca.managed = true
	ca.hostID = remoteCache.host.ID

	return true
}

// Handle from host IP connection. We know the IP is on the host subnet (NAT scope).
// Return if connection should be added.
func connectFromHost(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip) bool {
	if remote := getHostIDFromHostIP(conn.ClientIP); remote != "" {
		return connectFromManagedHost(conn, ca, stip, remote)
	} else {
		// From unmanaged host
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
			conn.ClientWL = ep
			ca.addrgrp = true
		} else {
			ep = specialEPName(api.LearnedHostPrefix, net.IP(conn.ClientIP).String())
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, true) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection with old session from unmanaged host")
				return false
			}
			conn.ClientWL = ep
		}

		stip.wlPort = uint16(conn.ServerPort)
		stip.mappedPort = getMappedPortFromWorkloadIPPort(
			conn.ServerWL, uint8(conn.IPProto), uint16(conn.ServerPort))
		ca.host = true
	}

	return true
}

// Check to global IP. We already know the IP is of Global scope.
// Return if connection should be added.
func connectToGlobal(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip) bool {
	if wl, alive := getWorkloadFromGlobalIP(conn.ServerIP); wl != "" {
		conn.ServerWL = wl
		if alive {
			stip.wlPort = uint16(conn.ServerPort)

			sa.workload = true
			sa.managed = true
		} else {
			if wouldGenerateUnmanagedEndpoint(conn, false) {
				scheduleControllerResync(resyncRequestReasonEphemeral)
			}
			cctx.ConnLog.WithFields(log.Fields{
				"server": conn.ServerWL,
			}).Debug("Ignore egress connection to left endpoint")
			return false
		}
	} else {
		// Unknown workload
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		} else {
			ipStr := net.IP(conn.ServerIP).String()
			ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, false) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore egress connection with old session to unknown global IP")
				return false
			}
			conn.ServerWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		sa.workload = true
	}

	return true
}

// Check to local container. Return if server is local, if connection should be added.
func connectToLocal(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip) (bool, bool) {
	// This function also checks if container is on the host's local subnets (172.x.x.x).
	if local, wl, alive := getWorkloadFromIPOnHost(net.IP(conn.ServerIP), conn.HostID); !local {
		return false, false
	} else {
		// In local subnet
		conn.ServerWL = wl
		if conn.ServerWL == "" {
			// Cannot find local container on the same host by IP. Ignore and wait.
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress connection to unknown container on local host")
			return true, false
		} else if alive {
			stip.wlPort = uint16(conn.ServerPort)

			sa.workload = true
			sa.managed = true
		} else {
			cctx.ConnLog.WithFields(log.Fields{
				"server": conn.ServerWL,
			}).Debug("Ignore egress connection to left endpoint on local host")
			return true, false
		}
	}

	return true, true
}

// Handle to host IP connection. We know the IP is on the host subnet (NAT scope).
// Return if connection should be added.
func connectToHost(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip) bool {
	if remote := getHostIDFromHostIP(conn.ServerIP); remote != "" {
		return connectToManagedHost(conn, sa, stip, remote)
	} else {
		// Unmanaged host
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		} else if ep = getIpAddrGroupName(net.IP(conn.ServerIP).String()); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
			tep := specialEPName(api.LearnedHostPrefix, net.IP(conn.ServerIP).String())
			if wlGraph.DeleteNode(tep) != "" {
				log.WithFields(log.Fields{"endpoint": tep}).Debug("Delete unknown host ip endpoint")
			}
		} else {
			ep = specialEPName(api.LearnedHostPrefix, net.IP(conn.ServerIP).String())
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, false) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore egress connection with old session to unknown host")
				return false
			}
			conn.ServerWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		sa.host = true
		return true
	}
}

// Given hostID and mapped port on the host, locate the container on the host. If not found, add an
// endpoint of Host:hostname. Return if connection should be added.
func connectToManagedHost(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip, hostID string) bool {
	/* to be tested
	if conn.ServerWL != "" {
		// This is only possible if this is host-mode container to host-mode container on the same host
		sa.workload = true
		sa.managed = true
		return true
	}
	*/

	var alive bool
	conn.ServerWL, stip.wlPort, alive =
		getWorkloadFromHostIDIPPort(hostID, uint8(conn.IPProto), uint16(conn.ServerPort))
	if conn.ServerWL == "" {
		remoteCache := getHostCache(hostID)
		if remoteCache == nil || remoteCache.host == nil || remoteCache.host.Name == "" {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress connection to unknown host")
			return false
		}

		// If workload cannot be found by server port map, it could be
		// a host process or host-mode container, but could also be
		// a workload unreported yet (TODO)
		conn.ServerWL = specialEPName(api.LearnedHostPrefix, remoteCache.host.ID)
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		}
		stip.wlPort = uint16(conn.ServerPort)

		sa.host = true
		sa.managed = true
		sa.hostID = remoteCache.host.ID
	} else if alive {
		sa.workload = true
		sa.managed = true
	} else {
		cctx.ConnLog.WithFields(log.Fields{
			"server": conn.ServerWL,
		}).Debug("Ignore egress connection to left endpoint")
		return false
	}

	return true
}

func preProcessConnect(conn *share.CLUSConnection) (*nodeAttr, *nodeAttr, *serverTip, bool) {
	var ca, sa nodeAttr // Client and Server node attributes
	stip := serverTip{wlPort: uint16(conn.ServerPort)}

	// cctx.ConnLog.WithFields(log.Fields{"conversation": conn}).Debug("")

	switch conn.PolicyAction {
	case C.DP_POLICY_ACTION_VIOLATE, C.DP_POLICY_ACTION_DENY:
		cctx.ConnLog.WithFields(log.Fields{
			"ipproto": conn.IPProto, "client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			"port":      conn.ServerPort,
			"action":    common.PolicyActionString(uint8(conn.PolicyAction)),
			"policy_id": conn.PolicyId,
		}).Debug("Detected policy violation")
	}

	// UnknownPeer: IP is not on host or container subnet
	// LocalPeer: IP is a host local IP
	if conn.Ingress {
		sa.workload = true
		sa.managed = true

		if strings.Contains(conn.Network, share.NetworkProxyMesh) && !conn.Xff {
			conn.ClientWL = conn.ServerWL
			ca.external = false
			ca.workload = true
			ca.managed = true
			return &ca, &sa, &stip, true
		} else if conn.TmpOpen {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore ingress temporary open connection")
			return &ca, &sa, &stip, false
		} else if isDeviceIP(conn.ClientIP) {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore ingress connection from nv device")
			return &ca, &sa, &stip, false
		} else if conn.LocalPeer {
			if !connectFromManagedHost(conn, &ca, &stip, conn.HostID) {
				return &ca, &sa, &stip, false
			}
		} else if isHostTunnelIP(conn.ClientIP) {
			conn.ClientWL = specialEPName(api.LearnedWorkloadPrefix, api.EndpointIngress)
			if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
				conn.ClientWL = ep
				ca.addrgrp = true
			}
			stip.wlPort = uint16(conn.ServerPort)
			ca.workload = true
		} else if local, _ := connectFromLocal(conn, &ca, &stip); local {
			return &ca, &sa, &stip, false
		} else if isHostIP(net.IP(conn.ClientIP).String()) {
			if !connectFromHost(conn, &ca, &stip) {
				return &ca, &sa, &stip, false
			}
		} else if ipsvcgrp := getSvcAddrGroupName(net.IP(conn.ClientIP), 0); ipsvcgrp != "" {
			conn.ClientWL = ipsvcgrp
			ca.ipsvcgrp = true
			stip.wlPort = uint16(conn.ServerPort)
		} else {
			switch getIPAddrScope(conn.ClientIP) {
			case "":
				// If the enforcer say it's not from external, respect that.
				if !conn.ExternalPeer {
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
					}).Debug("Ignore ingress connection from unknown subnet")
					return &ca, &sa, &stip, false
				} else {
					// Not on internal subnets - external
					conn.ClientWL = api.LearnedExternal
					if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
						conn.ClientWL = ep
						ca.addrgrp = true
					}
					stip.wlPort = uint16(conn.ServerPort)
					stip.mappedPort = getMappedPortFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), uint16(conn.ServerPort))
					ca.external = true
				}
			case share.CLUSIPAddrScopeNAT:
				if !connectFromHost(conn, &ca, &stip) {
					return &ca, &sa, &stip, false
				}
			case share.CLUSIPAddrScopeGlobal:
				if !connectFromGlobal(conn, &ca, &stip) {
					return &ca, &sa, &stip, false
				}
			default:
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection from unknown scope")
				return &ca, &sa, &stip, false
			}
		}
	} else {
		// egress
		ca.workload = true
		ca.managed = true

		if strings.Contains(conn.Network, share.NetworkProxyMesh) {
			conn.ServerWL = conn.ClientWL
			sa.external = false
			sa.workload = true
			sa.managed = true
			return &ca, &sa, &stip, true
		} else if conn.TmpOpen {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress temporary open connection")
			return &ca, &sa, &stip, false
		} else if isDeviceIP(conn.ServerIP) {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress connection to nv device")
			return &ca, &sa, &stip, false
		} else if conn.LocalPeer {
			if !connectToManagedHost(conn, &sa, &stip, conn.HostID) {
				return &ca, &sa, &stip, false
			}
		} else {
			if ipsvcgrp := getSvcAddrGroupName(net.IP(conn.ServerIP), uint16(conn.ServerPort)); ipsvcgrp != "" {
				conn.ServerWL = ipsvcgrp
				sa.ipsvcgrp = true
			} else if conn.SvcExtIP {
				if ipsvcgrp := getSvcAddrGroupNameByExtIP(net.IP(conn.ServerIP), uint16(conn.ServerPort)); ipsvcgrp != "" {
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
						"svcipgroup": ipsvcgrp,
					}).Debug("extIP connection")
					conn.ServerWL = ipsvcgrp
					sa.ipsvcgrp = true
				}
			} else if local, add := connectToLocal(conn, &sa, &stip); local {
				if !add {
					return &ca, &sa, &stip, false
				}
			} else if isHostTunnelIP(conn.ServerIP) {
				// We should not see egress traffic to tunnel IP, except
				// that for some udp pkt, we might identify the direction
				// incorrectly. Ignore these traffic.
				cctx.ConnLog.WithFields(log.Fields{
					"conn": conn,
				}).Debug("Ignore egress connection to ingress endpoint")
				return &ca, &sa, &stip, false
			} else if isHostIP(net.IP(conn.ServerIP).String()) {
				if !connectToHost(conn, &sa, &stip) {
					return &ca, &sa, &stip, false
				}
			} else {
				switch getIPAddrScope(conn.ServerIP) {
				case "":
					// If the enforcer say it's not to external, respect that.
					if !conn.ExternalPeer {
						// Consider it as unknown global workload
						if !connectToGlobal(conn, &sa, &stip) {
							return &ca, &sa, &stip, false
						}
					} else {
						// Not on internal subnets - external
						conn.ServerWL = api.LearnedExternal
						sa.external = true
						if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
							conn.ServerWL = ep
							sa.addrgrp = true
						} else if conn.FQDN != "" && conn.PolicyId == 0 {
							//learn to predefined address group
							if fqdngrp := getFqdnAddrGroupName(conn.FQDN); fqdngrp != "" {
								conn.ServerWL = fqdngrp
								sa.addrgrp = true
								cctx.ConnLog.WithFields(log.Fields{
									"ServerWL": conn.ServerWL, "policyaction":conn.PolicyAction,
								}).Debug("To FQDN address group")
							}
						}
						stip.wlPort = uint16(conn.ServerPort)
					}
				case share.CLUSIPAddrScopeNAT:
					if !connectToHost(conn, &sa, &stip) {
						return &ca, &sa, &stip, false
					}
				case share.CLUSIPAddrScopeGlobal:
					if !connectToGlobal(conn, &sa, &stip) {
						return &ca, &sa, &stip, false
					}
				default:
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
					}).Debug("Ignore egress connection to unknown scope")
					return &ca, &sa, &stip, false
				}
			}
		}
	}

	// Try to look up application by server port
	if sa.workload && sa.managed {
		if conn.Application == 0 {
			// For protocol application, if they are not identified, we are sure the traffic
			// doesn't match the protocol pattern, so don't assign app by server port.
			app, svr := getAppFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), stip.wlPort)
			if app >= C.DPI_APP_PROTO_MARK {
				conn.Application = app
				stip.appServer = svr
			}
		} else {
			_, stip.appServer = getAppFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), stip.wlPort)
		}
	}

	return &ca, &sa, &stip, true
}

// ---------------------------------

func connectGroupAdd(name string, param interface{}) {
	cache := param.(*groupCache)

	graphMutexLock()
	defer graphMutexUnlock()

	for ip := range cache.svcAddrs.Iter() {
		node := specialEPName(api.LearnedWorkloadPrefix, ip.(string))
		if wlGraph.DeleteNode(node) != "" {
			log.WithFields(log.Fields{"node": node}).Debug("Delete node")
		}
	}
}

func connectGroupDelete(name string, param interface{}) {
	graphMutexLock()
	defer graphMutexUnlock()

	if a := wlGraph.Attr(name, attrLink, dummyEP); a != nil {
		attr := a.(*nodeAttr)
		if attr.addrgrp || attr.ipsvcgrp {
			if wlGraph.DeleteNode(name) != "" {
				log.WithFields(log.Fields{"node": name}).Debug("Delete node")
			}
		}
	}
}

func connectHostAdd(id string, param interface{}) {
	host := param.(*hostCache).host

	graphMutexLock()
	defer graphMutexUnlock()

	_connectHostAdd(host)
}

func _connectHostAdd(host *share.CLUSHost) {
	for _, addrs := range host.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeNAT:
				ep := specialEPName(api.LearnedHostPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(ep) != "" {
					log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete host ip endpoint")
				}
				// In case the IP was identified as workload or identical to a workload
				ep = specialEPName(api.LearnedWorkloadPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(ep) != "" {
					log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete host ip endpoint as workload")
				}
			}
		}
	}
	for _, ipnet := range host.TunnelIP {
		ep := specialEPName(api.LearnedWorkloadPrefix, ipnet.IP.String())
		if wlGraph.DeleteNode(ep) != "" {
			log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete tunnel ip endpoint")
		}
		ep = specialEPName(api.LearnedHostPrefix, ipnet.IP.String())
		if wlGraph.DeleteNode(ep) != "" {
			log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete tunnel ip endpoint")
		}
	}
}

func connectHostDelete(id string, param interface{}) {
	host := param.(*hostCache).host

	graphMutexLock()
	defer graphMutexUnlock()
	for _, addrs := range host.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeNAT:
				ep := specialEPName(api.LearnedHostPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(ep) != "" {
					log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete host ip endpoint")
				}
				// In case the IP was identified as workload or identical to a workload
				ep = specialEPName(api.LearnedWorkloadPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(ep) != "" {
					log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete host ip endpoint as workload")
				}
			}
		}
	}
	for _, ipnet := range host.TunnelIP {
		ep := specialEPName(api.LearnedHostPrefix, ipnet.IP.String())
		if wlGraph.DeleteNode(ep) != "" {
			log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete tunnel ip endpoint as host")
		}
		ep = specialEPName(api.LearnedWorkloadPrefix, ipnet.IP.String())
		if wlGraph.DeleteNode(ep) != "" {
			log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete tunnel ip endpoint as workload")
		}
	}
	ep := specialEPName(api.LearnedHostPrefix, host.ID)
	if wlGraph.DeleteNode(ep) != "" {
		log.WithFields(log.Fields{"endpoint": ep}).Debug("Delete host endpoint")
	}
}

func connectDeviceAdd(dev *share.CLUSDevice) {
	graphMutexLock()
	defer graphMutexUnlock()
	for _, addrs := range dev.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				node := specialEPName(api.LearnedWorkloadPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(node) != "" {
					log.WithFields(log.Fields{"node": node}).Debug("Delete node")
				}
				// In the case that device and host share the same network, an originally
				// unmanaged device could be identified as host, so try to delete it here.
				node = specialEPName(api.LearnedHostPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(node) != "" {
					log.WithFields(log.Fields{"node": node}).Debug("Delete device as host node")
				}
			}
		}
	}
}

func connectControllerAdd(id string, param interface{}) {
	ctrl := param.(*ctrlCache).ctrl

	log.WithFields(log.Fields{"id": id, "name": ctrl.Name}).Info()

	connectDeviceAdd(&ctrl.CLUSDevice)
}

func connectAgentAdd(id string, param interface{}) {
	agent := param.(*agentCache).agent

	log.WithFields(log.Fields{"id": id, "name": agent.Name}).Info()

	connectDeviceAdd(&agent.CLUSDevice)
}

func _connectWorkloadAdd(wl *share.CLUSWorkload) {
	for _, addrs := range wl.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				node := specialEPName(api.LearnedWorkloadPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(node) != "" {
					log.WithFields(log.Fields{"node": node}).Debug("Delete workload node")
				}
				// In the case that pod and host share the same network, an originally
				// unmanaged pod could be identified as host, a workload can take a removed
				// host's IP, so try to delete it here.
				node = specialEPName(api.LearnedHostPrefix, addr.IPNet.IP.String())
				if wlGraph.DeleteNode(node) != "" {
					log.WithFields(log.Fields{"node": node}).Debug("Delete host node")
				}
			}
		}
	}
}

func connectWorkloadAdd(id string, param interface{}) {
	wl := param.(*workloadCache).workload

	log.WithFields(log.Fields{"id": id, "name": wl.Name}).Debug()

	graphMutexLock()
	defer graphMutexUnlock()
	_connectWorkloadAdd(wl)
}

func connectWorkloadDelete(id string, param interface{}) {
	wl := param.(*workloadCache).workload
	graphMutexLock()
	defer graphMutexUnlock()
	//delete Workload:IP/Host:IP node from graph if it is there.
	_connectWorkloadAdd(wl)
	if wlGraph.DeleteNode(id) != "" {
		log.WithFields(log.Fields{"node": id}).Debug("Delete node")
	}
}

// Delete corresponding unmanaged endpoint if exists
func connectOrchWorkloadDelete(ipnet *net.IPNet) {
	ep := specialEPName(api.LearnedWorkloadPrefix, ipnet.IP.String())

	graphMutexLock()
	defer graphMutexUnlock()
	if wlGraph.DeleteNode(ep) != "" {
		log.WithFields(log.Fields{"node": ep}).Debug("Delete node")
	}
}

// Delete corresponding unmanaged host if exists
func connectOrchHostDelete(ipnets []net.IPNet) {
	graphMutexLock()
	defer graphMutexUnlock()
	for _, ipnet := range ipnets {
		ep := specialEPName(api.LearnedHostPrefix, ipnet.IP.String())
		if wlGraph.DeleteNode(ep) != "" {
			log.WithFields(log.Fields{"node": ep}).Debug("Delete node")
		}
	}
}

// Only delete graph link, keep the policy link
func connectWorkloadDeleteLink(id string, param interface{}) {
	log.WithFields(log.Fields{"node": id}).Debug("Delete node linke")

	graphMutexLock()
	defer graphMutexUnlock()
	deleteConversationByNode(id)
}

// ---------------------------------

func conver2REST(from, to *api.RESTConversationEndpoint, attr *graphAttr) *api.RESTConversation {
	cr := graphAttr2REST(attr)
	if from.ServiceMeshSidecar || to.ServiceMeshSidecar {
		cr.SidecarProxy = true
	}

	return &api.RESTConversation{
		From: from, To: to, RESTConversationReport: cr,
	}
}

func graphAttr2REST(attr *graphAttr) *api.RESTConversationReport {
	conver := &api.RESTConversationReport{
		Bytes: attr.bytes, Sessions: attr.sessions,
	}
	conver.PolicyAction = common.PolicyActionRESTString(attr.policyAction)
	conver.Severity, _ = common.SeverityString(attr.severity)

	protos := utils.NewSet()
	apps := utils.NewSet()
	ports := utils.NewSet()

	var eventype map[string]string = make(map[string]string)
	var entries []*api.RESTConversationReportEntry

	for key, ge := range attr.entries {
		entry := &api.RESTConversationReportEntry{
			Bytes:        ge.bytes,
			Sessions:     ge.sessions,
			PolicyAction: common.PolicyActionRESTString(ge.policyAction),
			CIP:          utils.Int2IPv4( key.cip).String(),
			SIP:          utils.Int2IPv4(key.sip).String(),
			FQDN:         ge.fqdn,
		}
		protos.Add(key.ipproto)
		if key.application == 0 || key.application == C.DPI_APP_NOT_CHECKED {
			ports.Add(utils.GetPortLink(key.ipproto, key.port))
			entry.Port = utils.GetPortLink(key.ipproto, key.port)
		} else {
			apps.Add(key.application)
			entry.Application = common.AppNameMap[key.application]
		}
		if _, ok := common.LogThreatMap[ge.threatID]; ok {
			eventype[share.EventThreat] = share.EventThreat
		}
		if isDlpThreatID(ge.dlpID) {
			eventype[share.EventDlp] = share.EventDlp
		}
		if isWafThreatID(ge.wafID) {
			eventype[share.EventWaf] = share.EventWaf
		}
		if ge.xff > 0 {
			conver.XffEntry = true
		}
		if ge.nbe > 0 {
			conver.Nbe = true
		}
		entries = append(entries, entry)
	}
	conver.EventType = make([]string, 0)
	for _, et := range eventype {
		conver.EventType = append(conver.EventType, et)
	}

	conver.Protos = make([]string, 0)
	for proto := range protos.Iter() {
		str := utils.Proto2Name(proto.(uint8))
		conver.Protos = append(conver.Protos, str)
	}
	conver.Apps = make([]string, 0)
	for app := range apps.Iter() {
		str, _ := common.AppNameMap[app.(uint32)]
		conver.Apps = append(conver.Apps, str)
	}
	for port := range ports.Iter() {
		str := port.(string)
		conver.Ports = append(conver.Ports, str)
	}
	conver.Entries = entries

	return conver
}

// Calling with both graph and cache read-lock held
func getNonWorkloadEndpoint(node string) *api.RESTConversationEndpoint {
	if a := wlGraph.Attr(node, attrLink, dummyEP); a != nil {
		var kind string
		brief := api.RESTWorkloadBrief{ID: node}
		attr := a.(*nodeAttr)
		// Keep addrgrp at the top!
		if attr.addrgrp {
			kind = api.EndpointKindAddrGroup
			brief.Name = node
			brief.ServiceGroup = node
			if cache, ok := groupCacheMap[node]; ok {
				brief.Domain = cache.group.Domain
				brief.PolicyMode = cache.group.PolicyMode
			}
		} else if attr.ipsvcgrp {
			kind = api.EndpointKindIPSvcGroup
			brief.Name = node
			brief.ServiceGroup = node
			if cache, ok := groupCacheMap[node]; ok {
				brief.Domain = cache.group.Domain
				brief.PolicyMode = cache.group.PolicyMode
				brief.CapChgMode = cache.capChgMode
			}
		} else if attr.external {
			kind = api.EndpointKindExternal
			brief.Name = "External Network"
			brief.ServiceGroup = api.LearnedExternal
		} else if attr.host {
			kind = api.EndpointKindHostIP
			brief.Name = node[len(api.LearnedHostPrefix):]
			if attr.managed {
				brief.ServiceGroup = api.AllHostGroup
				if cache, ok := groupCacheMap[api.AllHostGroup]; ok {
					brief.PolicyMode = cache.group.PolicyMode
					brief.ProfileMode = cache.group.ProfileMode
					brief.CapChgMode = cache.capChgMode
				}
				if hostCache, ok := hostCacheMap[attr.hostID]; ok {
					brief.Name = hostCache.host.Name
					brief.ScanSummary = hostCache.scanBrief
					brief.State = hostCache.state
				}
			} else if hd, ok := ipHostMap[brief.Name]; ok {
				brief.ServiceGroup = api.AllHostGroup
				if hd != nil && !hd.managed {
					brief.State = api.StateUnmanaged
				}
			}
		} else if attr.workload && !attr.managed {
			kind = api.EndpointKindWorkloadIP
			brief.Name = node[len(api.LearnedWorkloadPrefix):]
			if strings.Contains(brief.Name, api.EndpointIngress) {
				brief.ServiceGroup = node
			}
		} else {
			// It gets here only if endpoint is workload and managed, however container
			// cannot be found by ID
			kind = api.EndpointKindContainer
			brief.Name = node
		}

		if attr.alias == "" {
			brief.DisplayName = brief.Name
			brief.PodName = brief.Name
		} else {
			brief.DisplayName = attr.alias
			brief.PodName = attr.alias
		}
		if brief.State == "" {
			brief.State = api.StateOnline
		}

		return &api.RESTConversationEndpoint{Kind: kind, RESTWorkloadBrief: brief}
	}

	return nil
}

type conversationEntrySorter []*api.RESTConversationEntry

func (s conversationEntrySorter) Len() int {
	return len(s)
}

func (s conversationEntrySorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s conversationEntrySorter) Less(i, j int) bool {
	if t1, err1 := time.Parse(api.RESTTimeFomat, s[i].LastSeenAt); err1 == nil {
		if t2, err2 := time.Parse(api.RESTTimeFomat, s[j].LastSeenAt); err2 == nil {
			return t1.After(t2)
		}
	}
	return false
}

func isNodeConnected(node string, wls utils.Set) bool {
	outs := wlGraph.OutsByLink(node, graphLink)
	if outs != nil && outs.Intersect(wls).Cardinality() > 0 {
		return true
	}

	ins := wlGraph.InsByLink(node, graphLink)
	if ins != nil && ins.Intersect(wls).Cardinality() > 0 {
		return true
	}
	return false
}

func (m CacheMethod) GetAllConverEndpoints(view string, acc *access.AccessControl) []*api.RESTConversationEndpoint {
	eps := make([]*api.RESTConversationEndpoint, 0)

	graphMutexRLock()
	defer graphMutexRUnlock()

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	switch view {
	case "":
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}
			if cache.workload.ShareNetNS == "" {
				eps = append(eps, workload2EndpointREST(cache, false))
			}
		}
	case api.QueryValueViewPod, api.QueryValueViewPodOnly:
		for _, cache := range wlCacheMap {
			if !acc.Authorize(cache.workload, nil) {
				continue
			}
			if common.OEMIgnoreWorkload(cache.workload) {
				continue
			}
			if cache.workload.ShareNetNS == "" {
				ep := workload2EndpointREST(cache, true)
				eps = append(eps, ep)
			}
		}
	}

	all := wlGraph.All()

	for n := range all.Iter() {
		if _, ok := wlCacheMap[n.(string)]; !ok {
			if ep := getNonWorkloadEndpoint(n.(string)); ep != nil {
				if !acc.Authorize(ep, nil) {
					continue
				}
				eps = append(eps, ep)
			}
		}
	}

	return eps
}

func (m CacheMethod) GetConverEndpoint(name string, acc *access.AccessControl) (*api.RESTConversationEndpoint, error) {
	graphMutexRLock()
	defer graphMutexRUnlock()
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := wlCacheMap[name]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return workload2EndpointREST(cache, false), nil
	} else if cache, ok := groupCacheMap[name]; ok {
		if !acc.Authorize(cache.group, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return group2EndpointREST(cache), nil
	} else {
		ep := getNonWorkloadEndpoint(name)
		if ep == nil {
			return nil, common.ErrObjectNotFound
		}
		if !acc.Authorize(ep, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return ep, nil
	}
}

func (m CacheMethod) getApplicationConver(src, dst string, acc *access.AccessControl) (*api.RESTConversationDetail, error) {
	accReadAll := access.NewReaderAccessControl()
	from, _ := m.GetConverEndpoint(src, accReadAll)
	to, _ := m.GetConverEndpoint(dst, accReadAll)

	if from == nil || to == nil {
		return nil, common.ErrObjectNotFound
	}

	graphMutexRLock()
	defer graphMutexRUnlock()
	if a := wlGraph.Attr(src, graphLink, dst); a != nil {
		attr := a.(*graphAttr)
		conver := api.RESTConversationDetail{
			RESTConversation: conver2REST(from, to, attr),
			Entries:          make([]*api.RESTConversationEntry, len(attr.entries)),
		}

		if !acc.Authorize(conver.RESTConversation, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		i := 0
		for key, entry := range attr.entries {
			c := &api.RESTConversationEntry{
				Bytes:        entry.bytes,
				Sessions:     entry.sessions,
				Port:         utils.GetPortLink(key.ipproto, key.port),
				MappedPort:   utils.GetPortLink(key.ipproto, entry.mappedPort),
				ThreatName:   getCombinedThreatName(entry.threatID, entry.dlpID, entry.wafID),
				PolicyAction: common.PolicyActionRESTString(entry.policyAction),
				PolicyID:     entry.policyID,
				LastSeenAt:   api.RESTTimeString(time.Unix(int64(entry.last), 0).UTC()),
				CIP:          utils.Int2IPv4(key.cip).String(),
				SIP:          utils.Int2IPv4(key.sip).String(),
				FQDN:         entry.fqdn,
			}
			c.Application, _ = common.AppNameMap[key.application]
			c.Server, _ = common.AppNameMap[entry.server]
			c.Severity, _ = getCombinedThreatSeverity(entry.wafSeverity, entry.dlpSeverity, entry.severity)
			if entry.xff > 0 {
				c.Xff = true
			}
			if entry.toSidecar > 0 {
				c.ToSidecar = true
			}
			if entry.nbe > 0 {
				c.Nbe = true
			}
			conver.Entries[i] = c
			i++
		}
		sort.Sort(conversationEntrySorter(conver.Entries))
		return &conver, nil
	}

	conver := api.RESTConversationDetail{
		RESTConversation: &api.RESTConversation{From: from, To: to},
		Entries:          make([]*api.RESTConversationEntry, 0),
	}

	if !acc.Authorize(conver.RESTConversation, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	return &conver, nil
}

func (m CacheMethod) GetApplicationConver(src, dst string, srcList, dstList []string, acc *access.AccessControl) (*api.RESTConversationDetail, error) {
	if srcList != nil && dstList != nil {
		var report api.RESTConversationReport
		protos := utils.NewSet()
		apps := utils.NewSet()
		ports := utils.NewSet()
		entries := make([]*api.RESTConversationEntry, 0)
		reportEntries := make([]*api.RESTConversationReportEntry, 0)

		for _, s := range srcList {
			for _, d := range dstList {
				if c, err := m.getApplicationConver(s, d, acc); err == nil {
					entries = append(entries, c.Entries...)
					if c.RESTConversationReport != nil {
						r := c.RESTConversationReport
						report.Bytes += r.Bytes
						report.Sessions += r.Sessions
						if r.Severity > report.Severity {
							report.Severity = r.Severity
						}
						for _, a := range r.Protos {
							protos.Add(a)
						}
						for _, a := range r.Ports {
							ports.Add(a)
						}
						for _, a := range r.Apps {
							apps.Add(a)
						}
						reportEntries = append(reportEntries, r.Entries...)
					}
				}
			}
		}

		report.Protos = protos.ToStringSlice()
		report.Ports = ports.ToStringSlice()
		report.Apps = apps.ToStringSlice()
		report.Entries = reportEntries

		accReadAll := access.NewReaderAccessControl()
		from, _ := m.GetConverEndpoint(src, accReadAll)
		to, _ := m.GetConverEndpoint(dst, accReadAll)

		conver := api.RESTConversationDetail{
			RESTConversation: &api.RESTConversation{From: from, To: to, RESTConversationReport: &report},
			Entries:          entries,
		}
		return &conver, nil
	} else {
		return m.getApplicationConver(src, dst, acc)
	}
}

func filterConvers(
	gc *groupCache, domainFilter string, from, to *api.RESTConversationEndpoint, acc *access.AccessControl,
) *api.RESTConversation {
	// Filter group
	if gc != nil {
		if gc.members.Cardinality() > 0 {
			if !gc.members.Contains(from.ID) && !gc.members.Contains(to.ID) {
				return nil
			}
		} else {
			if from.ID != gc.group.Name && to.ID != gc.group.Name {
				return nil
			}
		}
	}
	// Filter domain
	if domainFilter != "" {
		if from.Domain != domainFilter && to.Domain != domainFilter {
			return nil
		}
	}

	a := wlGraph.Attr(from.ID, graphLink, to.ID)
	if a == nil {
		return nil
	}

	attr := a.(*graphAttr)
	conver := conver2REST(from, to, attr)
	if !acc.Authorize(conver, nil) {
		return nil
	}
	return conver
}

// If domainFileter is "", return endpoints of all domains - there is no 'global domain'.
func (m CacheMethod) GetAllApplicationConvers(
	groupFilter, domainFilter string, acc *access.AccessControl,
) ([]*api.RESTConversationCompact, []*api.RESTConversationEndpoint) {
	convers := make([]*api.RESTConversationCompact, 0)
	endpoints := make([]*api.RESTConversationEndpoint, 0)

	// eps contains all workloads plus endpoints in the graph that the login user can see
	eps := m.GetAllConverEndpoints(api.QueryValueViewPod, acc)
	if len(eps) == 0 {
		return convers, endpoints
	}
	epsMap := make(map[string]*api.RESTConversationEndpoint)
	for _, ep := range eps {
		epsMap[ep.ID] = ep
	}

	graphMutexRLock()
	defer graphMutexRUnlock()

	var gc *groupCache

	// It's OK to lock cacheMutex inside graphMutex
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if groupFilter != "" {
		gc, _ = groupCacheMap[groupFilter]
		if gc != nil && !acc.Authorize(gc.group, nil) {
			return convers, endpoints
		}
	}

	wlSet := utils.NewSet()
	all := wlGraph.All()
	for n := range all.Iter() {
		var ep *api.RESTConversationEndpoint
		var ok bool
		if ep, ok = epsMap[n.(string)]; !ok {
			continue
		}

		outs := wlGraph.OutsByLink(ep.ID, graphLink)
		for o := range outs.Iter() {
			to, ok := epsMap[o.(string)]
			if !ok {
				// The 'to' end is not visible to the login user, still include the conversation.
				// Cannot add the endpoint to epsMap, which will have better performace if the endpoint is gonna used
				// many times, because we use epsMap to check conversation duplication, see 'in-link' logic.
				if cache, ok := wlCacheMap[o.(string)]; ok {
					to = workload2EndpointREST(cache, true)
				} else {
					to = getNonWorkloadEndpoint(o.(string))
				}
			}

			if c := filterConvers(gc, domainFilter, ep, to, acc); c != nil {
				convers = append(convers, &api.RESTConversationCompact{
					From: c.From.ID, To: c.To.ID, RESTConversationReport: c.RESTConversationReport,
				})
				if !wlSet.Contains(ep.ID) {
					endpoints = append(endpoints, ep)
					wlSet.Add(ep.ID)
				}
				if !wlSet.Contains(to.ID) && !to.ServiceMeshSidecar {
					endpoints = append(endpoints, to)
					wlSet.Add(to.ID)
				}
			}
		}

		ins := wlGraph.InsByLink(ep.ID, graphLink)
		for o := range ins.Iter() {
			// if the other end is already in the epsMap, the link is included by the about 'out-link' logic.
			from, ok := epsMap[o.(string)]
			if ok {
				continue
			}

			// the 'from' end is not visible to the login user, still include the conversation.
			if cache, ok := wlCacheMap[o.(string)]; ok {
				from = workload2EndpointREST(cache, true)
			} else {
				from = getNonWorkloadEndpoint(o.(string))
			}

			if c := filterConvers(gc, domainFilter, from, ep, acc); c != nil {
				convers = append(convers, &api.RESTConversationCompact{
					From: c.From.ID, To: c.To.ID, RESTConversationReport: c.RESTConversationReport,
				})
				if !wlSet.Contains(from.ID) && !from.ServiceMeshSidecar {
					endpoints = append(endpoints, from)
					wlSet.Add(from.ID)
				}
				if !wlSet.Contains(ep.ID) {
					endpoints = append(endpoints, ep)
					wlSet.Add(ep.ID)
				}
			}
		}
	}

	// Merge endpoints with workload list, which may have workloads not in the graph (no traffic).
	for _, ep := range eps {
		if wlSet.Contains(ep.ID) {
			continue
		}

		// Filter group
		if gc != nil {
			if gc.members.Cardinality() > 0 {
				if !gc.members.Contains(ep.ID) {
					continue
				}
			} else {
				if ep.ID != groupFilter {
					continue
				}
			}
		}
		// Filter domain
		if domainFilter != "" {
			if ep.Domain != domainFilter {
				continue
			}
		}

		// eps list has been authorized with children included

		endpoints = append(endpoints, ep)
	}

	return convers, endpoints
}

// -------------------------------------------------

func DeleteConver(src, dst string) {
	graphMutexLock()
	defer graphMutexUnlock()

	links := wlGraph.BetweenDirLinks(src, dst)
	for l, _ := range links {
		wlGraph.DeleteLink(src, l, dst)
	}
}

func DeleteAllConvers() {
	graphMutexLock()
	defer graphMutexUnlock()

	nodes := wlGraph.All()
	for n := range nodes.Iter() {
		wlGraph.DeleteNode(n.(string))
	}
}

func DeleteEndpoint(name string) {
	log.WithFields(log.Fields{"name": name}).Debug("")
	graphMutexLock()
	defer graphMutexUnlock()

	wlGraph.DeleteNode(name)
}

func ConfigEndpoint(name string, alias string) {
	log.WithFields(log.Fields{"name": name, "alias": alias}).Debug("")
	graphMutexLock()
	defer graphMutexUnlock()

	if a := wlGraph.Attr(name, attrLink, dummyEP); a != nil {
		attr := a.(*nodeAttr)
		attr.alias = alias
	}
}

func getEndpointsForGroup(name string) utils.Set {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if name == api.AllHostGroup {
		s := utils.NewSet()
		for ip, digest := range ipHostMap {
			if cache, ok := hostCacheMap[digest.hostID]; ok {
				s.Add(specialEPName(api.LearnedHostPrefix, cache.host.ID))
			} else {
				s.Add(specialEPName(api.LearnedHostPrefix, ip))
			}
		}
		return s
	} else if gc, ok := groupCacheMap[name]; ok &&
		(gc.group.Kind == share.GroupKindContainer || gc.group.CfgType == share.FederalCfg) {
		return gc.members
	} else {
		return utils.NewSet(name)
	}
}

func deletePolicyLinkByRule(from, to string, cr *share.CLUSPolicyRule) {
	if a := wlGraph.Attr(from, policyLink, to); a != nil {
		attr := a.(*polAttr)
		if len(cr.Applications) > 0 {
			if attr.apps.Cardinality() > 0 {
				log.WithFields(log.Fields{"src": from, "dst": to}).Debug("remove app")
				attr.apps = utils.NewSet()
			}
		} else {
			if attr.ports.Cardinality() > 0 {
				log.WithFields(log.Fields{"src": from, "dst": to}).Debug("remove port")
				attr.ports = utils.NewSet()
			}
		}
		if attr.apps.Cardinality() == 0 && attr.ports.Cardinality() == 0 {
			log.WithFields(log.Fields{"src": from, "dst": to}).Debug("remove policy link")
			wlGraph.DeleteLink(from, policyLink, to)
		}
	}
}

func deleteConversByPolicyRule(cr *share.CLUSPolicyRule, deleteRule bool) {
	log.WithFields(log.Fields{"rule": cr}).Debug()

	fromSet := getEndpointsForGroup(cr.From)
	toSet := getEndpointsForGroup(cr.To)
	graphMutexLock()
	defer graphMutexUnlock()
	for from := range fromSet.Iter() {
		for to := range toSet.Iter() {
			log.WithFields(log.Fields{"src": from, "dst": to}).Debug("remove conv")
			deleteConversationByPolicyId(from.(string), to.(string), cr.ID)
			if cr.CfgType == share.Learned || cr.CfgType == share.FederalCfg {
				deletePolicyLinkByRule(from.(string), to.(string), cr)
			}
		}
	}

	if cr.CfgType == share.Learned && deleteRule {
		deleteRuleFromLprWrapperMap(cr)
	}
}
