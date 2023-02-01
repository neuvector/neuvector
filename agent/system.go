package main

// #include "../defs.h"
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/policy"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/neuvector/share/container"
)

var policyApplyDir int
var pe policy.Engine
var learnedProcess []*share.CLUSProcProfileReq
var learnedProcessMtx sync.Mutex

const maxLearnedProcess int = 2000

type domainCache struct {
	domain *share.CLUSDomain
}

var domainCacheMap map[string]*domainCache = make(map[string]*domainCache)
var domainMutex sync.RWMutex

func initDomain(name string, nsLabels map[string]string) *share.CLUSDomain {
	return &share.CLUSDomain{Name: name, Labels: nsLabels}
}

func policyInit() {
	if global.ORCH.ApplyPolicyAtIngress() {
		policyApplyDir = C.DP_POLICY_APPLY_INGRESS
	} else {
		policyApplyDir = C.DP_POLICY_APPLY_EGRESS
	}
	pe.Init(Host.ID, gInfo.hostIPs, Host.TunnelIP, ObtainGroupProcessPolicy)
}

func updateContainerPolicyMode(id, policyMode string) {
	cid := ""
	if c, ok := gInfo.activeContainers[id]; ok {
		//NVSHAS-6719,sometimes the real traffic is pass even the action is block in oc 4.9+
		//when parent's pid==0, we need to execute func with child first to make sure datapath
		//is setup correctly
		if c.pid == 0 {
			for podID := range c.pods.Iter() {
				if pod, ok := gInfo.activeContainers[podID.(string)]; ok {
					if pod.pid != 0 && pod.hasDatapath {
						cid = podID.(string)
						break
					}
				}
			}
			//log.WithFields(log.Fields{"cid": cid}).Debug("")
			if cid != "" {
				if pc, exist := gInfo.activeContainers[cid]; exist {
					if pc.policyMode != policyMode {
						pc.policyMode = policyMode
						inline := isContainerInline(pc)
						if inline != pc.inline {
							changeContainerWire(pc, inline, pc.quar, nil)
						}
					}
				}
			}
		}
		if c.policyMode != policyMode {
			c.policyMode = policyMode
			inline := isContainerInline(c)
			if inline != c.inline {
				changeContainerWire(c, inline, c.quar, nil)
			}
		}
	}
}

func systemConfigPolicyMode(mode string) {
	// Disable global policy config as policy mode is per
	// container and is carried in policy now
	/*
	   if mode == "" {
	       mode = defaultPolicyMode
	   }

	   gInfo.policyMode = mode
	*/
}

func systemConfigTapProxymesh(tapProxymesh bool) {
	//proxy mesh status is changed
	gInfo.tapProxymesh = tapProxymesh
	for _, c := range gInfo.activeContainers {
		if tapProxymesh == true {
			//enable proxy mesh
			enableTapProxymesh(c)
		} else {
			//disable proxy mesh
			disableTapProxymesh(c)
		}
	}
}

func systemConfigXff(xffenabled bool) {
	if gInfo.xffEnabled == xffenabled {
		return
	}
	gInfo.xffEnabled = xffenabled
	//set xff to dp
	xff := gInfo.xffEnabled
	dp.DPCtrlSetSysConf(&xff)
}

func systemConfigProc(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		log.WithFields(log.Fields{"value": string(value)}).Debug("")

		var conf share.CLUSSystemConfig
		json.Unmarshal(value, &conf)
		systemConfigPolicyMode(conf.NewServicePolicyMode)
		systemConfigTapProxymesh(conf.TapProxymesh)
		systemConfigXff(conf.XffEnabled)
	case cluster.ClusterNotifyDelete:
		systemConfigPolicyMode(defaultPolicyMode)
		systemConfigTapProxymesh(defaultTapProxymesh)
		systemConfigXff(defaultXffEnabled)
	}
}

func initWorkloadPolicyMap() map[string]*policy.WorkloadIPPolicyInfo {
	workloadPolicyMap := make(map[string]*policy.WorkloadIPPolicyInfo)
	for wlID, c := range gInfo.activeContainers {
		pInfo := policy.WorkloadIPPolicyInfo{
			RuleMap: make(map[string]*dp.DPPolicyIPRule),
			Policy: dp.DPWorkloadIPPolicy{
				WlID:        wlID,
				WorkloadMac: nil,
				IPRules:     nil,
				ApplyDir:    policyApplyDir,
			},
			SkipPush:   !c.hasDatapath,
			HostMode:   c.hostMode,
			CapIntcp:   c.capIntcp,
			Configured: false,
		}

		for _, pair := range c.intcpPairs {
			pInfo.Policy.WorkloadMac = append(pInfo.Policy.WorkloadMac, pair.MAC.String())
		}
		workloadPolicyMap[wlID] = &pInfo
	}
	return workloadPolicyMap
}

func getPolicyConfig(newRuleKey string, slots, ruleslen int) []share.CLUSGroupIPPolicy {
	pols := make([]share.CLUSGroupIPPolicy, ruleslen)
	log.WithFields(log.Fields{"newRuleKey": newRuleKey, "slots": slots, "ruleslen": ruleslen}).Debug("")
	for i := 0; i < slots; i++ {
		key := fmt.Sprintf("%s%v", newRuleKey, i)
		//log.WithFields(log.Fields{"key": key,}).Debug("rule key")
		if value, _ := cluster.Get(key); value != nil {
			pol := make([]share.CLUSGroupIPPolicy, 0)
			uzb := utils.GunzipBytes(value)
			if uzb == nil {
				log.Error("Failed to unzip data")
				continue
			}
			err := json.Unmarshal(uzb, &pol)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Cannot decode policy")
				continue
			}
			//log.WithFields(log.Fields{"value": string(uzb), "policy_len":len(pol),}).Debug("policy per rule key")

			//to keep the original rules order
			for idx, plc := range pol {
				tidx := slots*idx + i
				pols[tidx] = plc
			}
		}
	}
	return pols
}

func mergeWlPolicyConfig(rules []share.CLUSGroupIPPolicy, ruleslen, wlslots, wlens int) []share.CLUSGroupIPPolicy {
	newGroupIPPolicy := make([]share.CLUSGroupIPPolicy, 0)
	pol := share.CLUSGroupIPPolicy{
		ID: share.DefaultGroupRuleID,
	}
	pol.From = make([]*share.CLUSWorkloadAddr, 0)
	log.WithFields(log.Fields{"ruleslen": ruleslen, "wlslots": wlslots, "wlens": wlens}).Debug("")
	//assemble address map
	for i := 0; i < wlslots; i++ {
		for _, addr := range rules[i].From {
			//no need to keep original order
			if addr != nil {
				pol.From = append(pol.From, addr)
			}
		}
	}
	newGroupIPPolicy = append(newGroupIPPolicy, pol)
	newGroupIPPolicy = append(newGroupIPPolicy, rules[wlslots:]...)
	return newGroupIPPolicy
}

func systemConfigPolicyVersion(s share.CLUSGroupIPPolicyVer) []share.CLUSGroupIPPolicy {
	groupIPPolicy := make([]share.CLUSGroupIPPolicy, 0)

	//check whether key "recalculate/groupIPRules" exist, if not
	//use old key "network/groupIPRules" for rolling upgrade case
	var rule_key, newRuleKey string
	rule_key = fmt.Sprintf("%s/", share.CLUSRecalPolicyIPRulesKey(share.PolicyIPRulesDefaultName))
	if cluster.Exist(rule_key) {
		// indicate network policy version change.
		newRuleKey = fmt.Sprintf("%s%s/", rule_key, s.PolicyIPRulesVersion)
	} else {
		rule_key = fmt.Sprintf("%s/", share.CLUSPolicyIPRulesKey(share.PolicyIPRulesDefaultName))
		if !cluster.Exist(rule_key) {
			return groupIPPolicy
		}
		// indicate network policy version change.
		newRuleKey = fmt.Sprintf("%s%s/", rule_key, s.PolicyIPRulesVersion)
	}

	//combine group ip rules from separate slots
	groupIPPolicy = getPolicyConfig(newRuleKey, s.SlotNo, s.RulesLen)

	if groupIPPolicy != nil && len(groupIPPolicy) > 0 && s.WorkloadSlot > 0 && s.WorkloadLen > 0 {
		groupIPPolicy = mergeWlPolicyConfig(groupIPPolicy, s.RulesLen, s.WorkloadSlot, s.WorkloadLen)
	}
	//log.WithFields(log.Fields{"mergelen":len(groupIPPolicy)}).Debug("after merge")
	return groupIPPolicy
}

// parent goroutine: containerTaskWorker()
func systemConfigPolicy(nType cluster.ClusterNotifyType, key string, value []byte) {
	if nType == cluster.ClusterNotifyDelete {
		// This should not happen
		log.Error("Policy key delete not supported!")
		return
	}

	//get group ip rules from cluster
	var s share.CLUSGroupIPPolicyVer
	if err := json.Unmarshal(value, &s); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return
	}

	if agentEnv.netPolicyPuller == 0 {
		systemUpdatePolicy(s) // inline
	} else {
		nextNetworkPolicyVer = &s // regulator
	}
}

func systemUpdatePolicy(s share.CLUSGroupIPPolicyVer) bool {
	// log.WithFields(log.Fields{"ver": s.PolicyIPRulesVersion}).Debug()
	groupIPPolicy := systemConfigPolicyVersion(s)
	if len(groupIPPolicy) == 0 {
		if pe.NetworkPolicy == nil {
			log.Error("Empty policy")
		}
		return false
	}

	wm := initWorkloadPolicyMap()
	hostPolicyChangeSet := pe.UpdateNetworkPolicy(groupIPPolicy, wm)

	for id, pInfo := range pe.GetNetworkPolicy() {
		if pInfo.Configured == false {
			continue
		}
		/*
		 * NVSHAS-3883: Pod in protect mode failed to start with tight liveness check setting
		 * When a POD starts, its mac/addr maynot be immediately available/pulled which
		 * is monitored by "intfMonitorLoop", however this POD is considered active at
		 * agent and pushed to cluster, ctrler is updated/cached and performs policy
		 * recalculation, policy is then pushed to agent/dp with no rules(no addr for POD),
		 * as a side action container mode is updated here which go through programUpdatePairs,
		 * At the mean time "intfMonitorLoop" also pick up mac/address change event and try to
		 * perfrom programUpdatePairs and may think there is no intf/addr change, and no update
		 * is pushed to ctrler about intf/addr change, so this POD can never get up because no
		 * policy/rule is made ready for it and default action is deny.
		 * solution: for non-hostmode container perform container mode change only when mac/addr is pulled
		 */
		if !pInfo.HostMode && (pInfo.Policy.WorkloadMac == nil || len(pInfo.Policy.WorkloadMac) == 0) {
			continue
		}
		updateContainerPolicyMode(id, pInfo.Policy.Mode)
	}

	if hostPolicyChangeSet.Cardinality() > 0 && prober != nil {
		// The hostPolicyChangeSet only contains parent pod, add the childen
		// container id here as well as the prober works on individual container
		for _, c := range gInfo.activeContainers {
			if c.parentNS != "" && hostPolicyChangeSet.Contains(c.parentNS) {
				hostPolicyChangeSet.Add(c.id)
			}
		}

		log.WithFields(log.Fields{
			"containers": hostPolicyChangeSet,
		}).Debug("notify host mode container policy change")

		prober.NotifyPolicyChange(hostPolicyChangeSet)
		if prober.IsConnectionMonitored() == false {
			prober.StartMonitorConnection()
		}
	}
	return true
}

func hostPolicyLookup(conn *dp.Connection) (uint32, uint8, bool) {
	gInfoRLock()

	// Use parent's policy if the connection is reported on child
	var wlID *string
	if conn.Ingress {
		wlID = &conn.ServerWL
		conn.LocalPeer = conn.ClientIP.IsLoopback()
		conn.ExternalPeer = !isIPInternal(conn.ClientIP)
	} else {
		wlID = &conn.ClientWL
		conn.LocalPeer = conn.ServerIP.IsLoopback()
		conn.ExternalPeer = !isIPInternal(conn.ServerIP)
	}

	c, ok := gInfo.activeContainers[*wlID]
	if !ok {
		gInfoRUnlock()
		return 0, C.DP_POLICY_ACTION_OPEN, false
	} else if c.parentNS != "" {
		pc ,exist := gInfo.activeContainers[c.parentNS]
		if exist {
			if pc.pid != 0 {
				wlID = &c.parentNS
				c, _ = gInfo.activeContainers[*wlID]
			}
		} else {
			if !c.hasDatapath {
				gInfoRUnlock()
				log.WithFields(log.Fields{
					"wlID": *wlID,
				}).Error("cannot find parent container")
				return 0, C.DP_POLICY_ACTION_OPEN, false
			}
		}
	}

	gInfoRUnlock()

	if !c.hasDatapath {
		return 0, C.DP_POLICY_ACTION_OPEN, false
	}
	return pe.HostNetworkPolicyLookup(*wlID, conn)
}

// with gInfoLock held
func mergeLocalSubnets(subnetMap map[string]share.CLUSSubnet) bool {
	var changed bool
	for _, subnet := range gInfo.localSubnetMap {
		if utils.MergeSubnet(subnetMap, subnet) {
			changed = true
		}
	}
	return changed
}

func systemConfigInternalSubnet(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	uzb := utils.GunzipBytes(value)
	if uzb == nil {
		log.Error("Failed to unzip data")
		return
	}

	var subnets []share.CLUSSubnet
	json.Unmarshal(uzb, &subnets)

	newInternalSubnets := make(map[string]share.CLUSSubnet)
	for _, subnet := range subnets {
		newInternalSubnets[subnet.Subnet.String()] = subnet
	}
	mergeLocalSubnets(newInternalSubnets)

	if reflect.DeepEqual(gInfo.internalSubnets, newInternalSubnets) == false {
		gInfo.internalSubnets = newInternalSubnets
		dp.DPCtrlConfigInternalSubnet(newInternalSubnets)
	}
}

func systemConfigSpecialSubnet(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	uzb := utils.GunzipBytes(value)
	if uzb == nil {
		log.Error("Failed to unzip data")
		return
	}

	var subnets []share.CLUSSpecSubnet
	json.Unmarshal(uzb, &subnets)

	newSpecialSubnets := make(map[string]share.CLUSSpecSubnet)
	for _, subnet := range subnets {
		newSpecialSubnets[subnet.Subnet.String()] = subnet
	}

	if reflect.DeepEqual(specialSubnets, newSpecialSubnets) == false {
		specialSubnets = newSpecialSubnets
		dp.DPCtrlConfigSpecialIPSubnet(newSpecialSubnets)
	}
}

func networkDerivedProc(nType cluster.ClusterNotifyType, key string, value []byte) {
	which := share.CLUSNetworkKey2Subject(key)

	switch which {
	case share.PolicyIPRulesVersionID:
		systemConfigPolicy(nType, key, value)
	case share.InternalIPNetDefaultName:
		systemConfigInternalSubnet(nType, key, value)
	case share.SpecialIPNetDefaultName:
		systemConfigSpecialSubnet(nType, key, value)
	case share.DlpRulesDefaultName:
		dlpConfigRule(nType, key, value)
	case share.CFGEndpointSystem:
		systemConfigProc(nType, key, value)
	default:
		log.WithFields(log.Fields{"derived": which}).Debug("Miss handler")
	}
}

func profileDerivedProc(nType cluster.ClusterNotifyType, key string, value []byte) {
	which := share.CLUSNetworkKey2Subject(key)
	value, _ = utils.UnzipDataIfValid(value)
	// log.WithFields(log.Fields{"key": key}).Debug("GRP:")
	switch which {
	case share.ProfileGroup:
		systemConfigGroup(nType, key, value)
	case share.ProfileProcess:
		profileConfigGroup(nType, key, value)
	case share.ProfileFileMonitor:
		systemConfigFileMonitor(nType, key, value)
	case share.ProfileFileAccess:
		systemConfigFileAccessRule(nType, key, value)
	case share.ProfileScript:
		systemConfigScript(nType, key, value)
	default:
		log.WithFields(log.Fields{"derived": which}).Debug("Miss handler")
	}
}

func profileConfigGroup(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSProfileKey2Name(key)
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key, "name": name}).Debug("GRP:")

	if nType == cluster.ClusterNotifyDelete {
		pe.DeleteProcessPolicy(name)
		return
	}

	var pg share.CLUSProcessProfile
	json.Unmarshal(value, &pg)
	if utils.DoesGroupHavePolicyMode(name) {
		if updated, last := pe.UpdateProcessPolicy(name, &pg); updated {
			if pg.Baseline == share.ProfileZeroDrift {
				if last == nil || last.Baseline != pg.Baseline {
					// rebuild family trees for all match containers
					updateContainerFamilyTrees(name)
				}
			}
		}
	}
	updateGroupProfileCache(nType, name, pg)
}

const learnedGroupPrefix string = "nv."

func makeLearnedGroupName(svc string) string {
	return fmt.Sprintf("%s%s", learnedGroupPrefix, svc)
}

func cbGetLearnedGroupName(id string) (string, bool, bool) {
	svc, _, bNeuvector := getContainerService(id)
	if svc == "" {
		log.WithFields(log.Fields{"id": id}).Debug("svc not found")
		return "", false, false
	} else if svc == "nodes" {
		return svc, false, false
	}

	return makeLearnedGroupName(utils.NormalizeForURL(svc)), true, bNeuvector
}

func processPolicyLookup(id, riskType, pname, ppath string, pid, pgid, shellCmd int, proc *share.CLUSProcessProfileEntry) (string, string, string, string, bool, error) {
	var svcGroup string
	var bAllowSuspicious bool
	svc, capBlock, bNeuvector := getContainerService(id)
	if svc == "" {
		return "", "", "", "", bAllowSuspicious, errors.New("Service not found")
	} else if svc == "nodes" {
		svcGroup = svc
	} else {
		svcGroup = makeLearnedGroupName(utils.NormalizeForURL(svc))
	}

	mode, setting, group, err := pe.ProcessPolicyLookup(svcGroup, id, proc, pid)
	if err == nil {
		// log.WithFields(log.Fields{"mode": mode, "group": group, "proc": proc, "pid": pid, "shellCmd": shellCmd}).Debug("PROC: ")
		bNotInWhitelist := (proc.Uuid == share.CLUSReservedUuidNotAlllowed)
		// not in the whitelist, not a risk app, and shell script name
		if bNotInWhitelist && riskType == "" && shellCmd == 1 {
			proc.Action = share.PolicyActionAllow // not recording
		}

		switch proc.Action {
		case share.PolicyActionLearn:
			if riskType != "" && !pe.IsAllowedSuspiciousApp(svcGroup, id, riskType) { // risky processs
				// override the action to checkApp
				proc.Action = share.PolicyActionCheckApp
			}
		case share.PolicyActionViolate: // policy mode decision
			if !bNeuvector && pe.IsAllowedByParentApp(svcGroup, id, proc.Name, pname, ppath, pgid) {
				proc.Action = share.PolicyActionAllow
				bAllowSuspicious = true
				log.WithFields(log.Fields{"group": svcGroup, "pname": pname, "name": proc.Name}).Debug("PROC: allowed by parent")
			}
		case share.PolicyActionCheckApp, share.PolicyActionAllow: // a real policy
			if riskType != "" {
				bAllowSuspicious = pe.IsAllowedSuspiciousApp(svcGroup, id, riskType)
				if !bAllowSuspicious {
					// override the action to checkApp
					proc.Action = share.PolicyActionCheckApp
				}
			}
		case share.PolicyActionDeny: // a real policy
			///// a signature for upper layers to recognize the incidents
			if bNeuvector {
				group = share.GroupNVProtect // updated
				svcGroup = group
				log.WithFields(log.Fields{"id": id, "name": proc.Name, "path": proc.Path}).Info("GRP: NV Protect")
			} else if pe.IsAllowedByParentApp(svcGroup, id, proc.Name, pname, ppath, pgid) {
				proc.Action = share.PolicyActionAllow
				bAllowSuspicious = true
				log.WithFields(log.Fields{"group": svcGroup, "pname": pname, "name": proc.Name}).Debug("PROC: allowed by parent")
			}
		}

		if mode == share.PolicyModeEnforce && proc.Action != share.PolicyActionAllow && !capBlock {
			// override the action for system containers to generate alert only
			proc.Action = share.PolicyActionViolate
		}
	}
	return mode, setting, group, svcGroup, bAllowSuspicious, err
}

var lastReportTime time.Time
var reportSkipCnt int

func accumulateReport() bool {
	if time.Since(lastReportTime) > time.Second*time.Duration(2) {
		return false
	} else {
		if reportSkipCnt > 0 {
			reportSkipCnt = 0
			return false
		} else {
			reportSkipCnt++
			return true
		}
	}
}

func reportLearnedProcess() {
	learnedProcessMtx.Lock()
	if len(learnedProcess) == 0 || accumulateReport() {
		learnedProcessMtx.Unlock()
		return
	}
	tmp := learnedProcess
	learnedProcess = nil
	learnedProcessMtx.Unlock()

	cnt := len(tmp)
	if cnt > 0 {
		if err := sendLearnedProcess(tmp); err == nil {
			log.WithFields(log.Fields{"cnt": cnt}).Debug("Report succeeded")
		} else {
			log.WithFields(log.Fields{"cnt": cnt, "err": err}).Debug("Report failed")
			learnedProcessMtx.Lock()
			learnedProcess = append(tmp, learnedProcess...)
			if len(learnedProcess) > maxLearnedProcess {
				log.WithFields(log.Fields{"cnt": len(learnedProcess)}).Debug("Too many - truncate")
				learnedProcess = learnedProcess[:maxLearnedProcess]
			}
			learnedProcessMtx.Unlock()
		}
	}
}

//dlp
func dlpModeToDefaultAction(mode string, capIntcp bool) uint8 {
	switch mode {
	case share.PolicyModeLearn:
		return C.DPI_ACTION_ALLOW
	case share.PolicyModeEvaluate:
		return C.DPI_ACTION_ALLOW
	case share.PolicyModeEnforce:
		if capIntcp {
			return C.DPI_ACTION_DROP
		} else {
			return C.DPI_ACTION_ALLOW
		}
	}
	return C.DPI_ACTION_ALLOW
}

func adjustDlpAction(action uint8, mode string) uint8 {
	var adjustedDlpAction uint8 = action

	switch mode {
	case share.PolicyModeLearn:
		if action == C.DPI_ACTION_DROP {
			adjustedDlpAction = C.DPI_ACTION_ALLOW
		}
	case share.PolicyModeEvaluate:
		if action == C.DPI_ACTION_DROP {
			adjustedDlpAction = C.DPI_ACTION_ALLOW
		}
	case share.PolicyModeEnforce:
		adjustedDlpAction = action
	case "":
		adjustedDlpAction = action
	default:
		log.WithFields(log.Fields{"mode": mode, "action": action}).Error("Invalid mode!")
	}
	log.WithFields(log.Fields{"action": action, "mode": mode, "adjustedDlpAction": adjustedDlpAction}).Debug("")
	return adjustedDlpAction
}

func dlpConvertToDpAction(act string) uint8 {
	switch act {
	case share.DlpRuleActionAllow:
		return C.DPI_ACTION_ALLOW
	case share.DlpRuleActionDrop:
		return C.DPI_ACTION_DROP
	default:
		return C.DPI_ACTION_ALLOW
	}
}

func dlpConvertToDpSeverity(svrty string) uint8 {
	switch svrty {
	case share.DlpRuleSeverityInfo:
		return C.THRT_SEVERITY_INFO
	case share.DlpRuleSeverityLow:
		return C.THRT_SEVERITY_LOW
	case share.DlpRuleSeverityMed:
		return C.THRT_SEVERITY_MEDIUM
	case share.DlpRuleSeverityHigh:
		return C.THRT_SEVERITY_HIGH
	case share.DlpRuleSeverityCrit:
		return C.THRT_SEVERITY_CRITICAL
	default:
		return C.THRT_SEVERITY_MEDIUM
	}
}

func printWorkloadDlpRuleConfig(drm map[string]*dp.DPWorkloadDlpRule) {
	for wlid, dr := range drm {
		log.WithFields(log.Fields{"wlid": wlid, "dlpruleinfo": *dr}).Debug("wl ruleinfo")
		for _, rnact := range dr.DlpRuleNames {
			log.WithFields(log.Fields{"dlprulename": rnact.Name, "dlpruleaction": rnact.Action}).Debug("dlp wl ruleinfo rule name and action")
		}
		log.WithFields(log.Fields{"policyids": dr.PolicyRuleIds}).Debug("dlp wl ruleinfo policyids")
		for _, rnact := range dr.WafRuleNames {
			log.WithFields(log.Fields{"wafrulename": rnact.Name, "wafruleaction": rnact.Action}).Debug("waf wl ruleinfo rule name and action")
		}
		log.WithFields(log.Fields{"wafpolicyids": dr.PolWafRuleIds}).Debug("waf wl ruleinfo policyids")
	}
}

func updateWorkloadDlpRuleConfig(DlpWlRules []*share.CLUSDlpWorkloadRule, dlprulenames map[string]string, wlmacs utils.Set, dlprnid map[string]uint32) bool {
	var updated bool = false
	workloadDlpRulesMap := make(map[string]*dp.DPWorkloadDlpRule)

	for _, dre := range DlpWlRules {
		if c, ok := gInfo.activeContainers[dre.WorkloadId]; ok {
			if c.hasDatapath {
				dlpWlRule := dp.DPWorkloadDlpRule{
					WlID:          dre.WorkloadId,
					Mode:          dre.PolicyMode,
					DefAction:     dlpModeToDefaultAction(dre.PolicyMode, c.capIntcp),
					WorkloadMac:   nil,
					DlpRuleNames:  nil,
					WafRuleNames:  nil,
					PolicyRuleIds: nil,
					PolWafRuleIds: nil,
					ApplyDir:      policyApplyDir,
				}
				if dre.RuleType == share.WafWlRuleIn || dre.RuleType == share.WafWlRuleOut {
					dlpWlRule.WafRuleType = dre.RuleType
				} else {
					dlpWlRule.RuleType = dre.RuleType
				}
				for _, pair := range c.intcpPairs {
					dlpWlRule.WorkloadMac = append(dlpWlRule.WorkloadMac, pair.MAC.String())
					wlmacs.Add(pair.MAC.String())
				}
				//we need to detect traffic between sidecar and service container
				if gInfo.tapProxymesh && c.info.ProxyMesh {
					lomac_str := fmt.Sprintf(container.KubeProxyMeshLoMacStr, (c.pid>>8)&0xff, c.pid&0xff)
					dlpWlRule.WorkloadMac = append(dlpWlRule.WorkloadMac, lomac_str)
					wlmacs.Add(lomac_str)
				}
				if dlpWlRule.WorkloadMac == nil || len(dlpWlRule.WorkloadMac) == 0 {
					continue
				}
				sort.Slice(dlpWlRule.WorkloadMac, func(i, j int) bool {
					return strings.Compare(dlpWlRule.WorkloadMac[i], dlpWlRule.WorkloadMac[j]) < 0
				})

				for _, rn := range dre.RuleListNames {
					rnact := dp.DPDlpSetting{
						Name:   rn.Name,
						ID:     dlprnid[rn.Name],
						Action: adjustDlpAction(dlpConvertToDpAction(rn.Action), dlpWlRule.Mode),
					}
					if dre.RuleType == share.WafWlRuleIn || dre.RuleType == share.WafWlRuleOut {
						dlpWlRule.WafRuleNames = append(dlpWlRule.WafRuleNames, &rnact)
						sort.Slice(dlpWlRule.WafRuleNames, func(i, j int) bool {
							return strings.Compare(dlpWlRule.WafRuleNames[i].Name, dlpWlRule.WafRuleNames[j].Name) < 0
						})
					} else {
						dlpWlRule.DlpRuleNames = append(dlpWlRule.DlpRuleNames, &rnact)
						sort.Slice(dlpWlRule.DlpRuleNames, func(i, j int) bool {
							return strings.Compare(dlpWlRule.DlpRuleNames[i].Name, dlpWlRule.DlpRuleNames[j].Name) < 0
						})
					}
					dlprulenames[rn.Name] = rn.Name
				}

				for _, rid := range dre.RuleIds {
					if dre.RuleType == share.WafWlRuleIn  || dre.RuleType == share.WafWlRuleOut {
						dlpWlRule.PolWafRuleIds = append(dlpWlRule.PolWafRuleIds, rid)
						sort.Slice(dlpWlRule.PolWafRuleIds, func(i, j int) bool {
							return (dlpWlRule.PolWafRuleIds[i] < dlpWlRule.PolWafRuleIds[j])
						})
					} else {
						dlpWlRule.PolicyRuleIds = append(dlpWlRule.PolicyRuleIds, rid)
						sort.Slice(dlpWlRule.PolicyRuleIds, func(i, j int) bool {
							return (dlpWlRule.PolicyRuleIds[i] < dlpWlRule.PolicyRuleIds[j])
						})
					}
				}

				//wl can have both dlp and waf, we need to do a merge here
				if edlpWlRule, rexist := workloadDlpRulesMap[dre.WorkloadId]; !rexist {
					workloadDlpRulesMap[dre.WorkloadId] = &dlpWlRule
				} else {
					//dlp rule in array is always before waf rule
					edlpWlRule.WafRuleNames = append(edlpWlRule.WafRuleNames, dlpWlRule.WafRuleNames...)
					edlpWlRule.PolWafRuleIds = append(edlpWlRule.PolWafRuleIds, dlpWlRule.PolWafRuleIds...)
					edlpWlRule.WafRuleType = dlpWlRule.WafRuleType
				}
			}
		}
	}
	pe.Mutex.Lock()
	wlDlpInfo := pe.DlpWlRulesInfo          //old
	pe.DlpWlRulesInfo = workloadDlpRulesMap //new
	pe.Mutex.Unlock()

	dpConnected := dp.Connected()

	for wlid, wldre := range workloadDlpRulesMap {
		if exist_wldre, ok := wlDlpInfo[wlid]; !ok { //add
			updated = true
			if dpConnected {
				dp.DPCtrlConfigDlp(wldre)
			}
		} else { //modify
			if reflect.DeepEqual(wldre, exist_wldre) != true {
				updated = true
				if dpConnected {
					dp.DPCtrlConfigDlp(wldre)
				}
			}
		}
	}
	//printWorkloadDlpRuleConfig(workloadDlpRulesMap)

	delmacs := utils.NewSet()
	for wl_id, wl_dre := range wlDlpInfo {
		if _, ok := workloadDlpRulesMap[wl_id]; !ok { //del
			for _, del_mac := range wl_dre.WorkloadMac {
				delmacs.Add(del_mac)
			}
		}
	}

	if delmacs.Cardinality() > 0 {
		updated = true
		if dpConnected {
			dp.DPCtrlDlpCfgChgMac(delmacs)
		}
	}

	return updated
}

func printDlpDetectionRules(drl []*dp.DPDlpRuleEntry) {
	for _, dr := range drl {
		log.WithFields(log.Fields{"dlpruleentry": *dr}).Debug("dp rule entry")
	}
}

func updateDlpDetectionRules(drlist []*share.CLUSDlpRule,
	dlprulenames map[string]string, wlmacs utils.Set) (bool, bool) {
	var updated bool = false
	var macUpdated bool = false
	var delmacs utils.Set = utils.NewSet()
	var addmacs utils.Set = utils.NewSet()
	var oldmacs utils.Set = utils.NewSet()

	dlpbldinfo := policy.DlpBuildInfo{
		DlpRulesInfo: make([]*dp.DPDlpRuleEntry, 0),
		DlpDpMacs:    utils.NewSet(),
		ApplyDir:     policyApplyDir,
	}

	//update rules
	for _, cdre := range drlist {
		if _, ok := dlprulenames[cdre.Name]; ok {
			dpdlpre := dp.DPDlpRuleEntry{
				Name: cdre.Name,
				ID:   cdre.ID,
			}
			for _, pc := range cdre.Patterns {
				pat := ""
				if pc.Op == share.CriteriaOpNotRegex {
					pat = fmt.Sprintf("!")
				}
				pat = fmt.Sprintf("%s/%s/is", pat, pc.Value)
				if pc.Context == "" {
					pat = fmt.Sprintf("%s; context %s", pat, share.DlpPatternContextDefault)
				} else {
					pat = fmt.Sprintf("%s; context %s", pat, pc.Context)
				}
				dpdlpre.Patterns = append(dpdlpre.Patterns, pat)
			}
			sort.Slice(dpdlpre.Patterns, func(i, j int) bool {
				return strings.Compare(dpdlpre.Patterns[i], dpdlpre.Patterns[j]) < 0
			})
			dlpbldinfo.DlpRulesInfo = append(dlpbldinfo.DlpRulesInfo, &dpdlpre)
		}
	}
	sort.Slice(dlpbldinfo.DlpRulesInfo, func(i, j int) bool {
		return strings.Compare(dlpbldinfo.DlpRulesInfo[i].Name, dlpbldinfo.DlpRulesInfo[j].Name) < 0
	})
	//printDlpDetectionRules(dlpbldinfo.DlpRulesInfo)

	//update macs
	dlpbldinfo.DlpDpMacs = wlmacs

	pe.Mutex.Lock()
	if !reflect.DeepEqual(pe.DlpBldInfo.DlpRulesInfo, dlpbldinfo.DlpRulesInfo) {
		updated = true
	}

	if !pe.DlpBldInfo.DlpDpMacs.Equal(dlpbldinfo.DlpDpMacs) {
		macUpdated = true
		oldmacs = pe.DlpBldInfo.DlpDpMacs
		delmacs = pe.DlpBldInfo.DlpDpMacs.Difference(dlpbldinfo.DlpDpMacs)
		addmacs = dlpbldinfo.DlpDpMacs.Difference(pe.DlpBldInfo.DlpDpMacs)
	}
	pe.DlpBldInfo = &dlpbldinfo
	dlp_bld_info := pe.DlpBldInfo
	pe.Mutex.Unlock()

	dpConnected := dp.Connected()

	if updated || macUpdated { //rules/endpoint have changed, thus rebuild
		//rule update may not be as frequent as macUpdated
		//we separate these 2 cases so to reduce times to
		// to rebuild detection tree
		if updated || (delmacs.Cardinality() > 0 && oldmacs.Equal(delmacs)) {
			if dpConnected && dlp_bld_info != nil {
				dp.DPCtrlBldDlp(dlp_bld_info.DlpRulesInfo, dlp_bld_info.DlpDpMacs, delmacs, dlp_bld_info.ApplyDir)
			}
		} else {
			if dpConnected && dlp_bld_info != nil {
				dp.DPCtrlBldDlpChgMac(oldmacs, addmacs, delmacs)
			}
		}
	}
	return updated, macUpdated
}

func dlpConfigRule(nType cluster.ClusterNotifyType, key string, value []byte) {
	var dlprules share.CLUSWorkloadDlpRules
	var dlprulenames map[string]string = make(map[string]string)
	var wlmacs utils.Set = utils.NewSet()
	var dlprnid map[string]uint32 = make(map[string]uint32)

	uzb := utils.GunzipBytes(value)
	if uzb == nil {
		log.Error("Failed to unzip data")
		return
	}
	json.Unmarshal(uzb, &dlprules)

	//log.WithFields(log.Fields{"value": string(uzb)}).Debug("")

	//no dlp rules to build detection tree
	if len(dlprules.DlpRuleList) == 0 &&
		(pe.DlpBldInfo == nil ||
			pe.DlpBldInfo.DlpRulesInfo == nil ||
			len(pe.DlpBldInfo.DlpRulesInfo) == 0) {
		log.Debug("Empty dlp rules entry info")
		return
	}
	//endpoint does not associate with any dlp rules which means we
	//do not need to push any info to DP
	if len(dlprules.DlpWlRules) == 0 &&
		(pe.DlpWlRulesInfo == nil ||
			len(pe.DlpWlRulesInfo) == 0) {
		log.Debug("Empty dlp workload rules info")
		return
	}

	if nType == cluster.ClusterNotifyDelete {
		// This should not happen
		log.Error("Dlp rule/sensor delete not supported!")
		return
	}

	for _, cdr := range dlprules.DlpRuleList {
		dlprnid[cdr.Name] = cdr.ID
	}

	configUpdated := updateWorkloadDlpRuleConfig(dlprules.DlpWlRules, dlprulenames, wlmacs, dlprnid)
	if configUpdated {
		log.WithFields(log.Fields{"configUpdated": configUpdated}).Debug("detect tree reconfigured")
	}

	detectUpdated, macUpdated := updateDlpDetectionRules(dlprules.DlpRuleList, dlprulenames, wlmacs)

	if detectUpdated || macUpdated {
		log.WithFields(log.Fields{"detectUpdated": detectUpdated, "macUpdated": macUpdated}).Debug("rebuild detect tree")
	}
}

func systemUpdateProc(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("GRP: ")
	store := share.CLUSKey2Target(key) + "/"
	switch store {
	case share.CLUSNetworkStore:
		networkDerivedProc(nType, key, value)
	case share.CLUSNodeStore:
		profileDerivedProc(nType, share.CLUSNodeProfileSubkey(key), value)
	}
}

type systemConfigTask struct {
	nType cluster.ClusterNotifyType
	key   string
	value []byte
}

// This is run in task thread context
func (p *systemConfigTask) handler() {
	systemUpdateProc(p.nType, p.key, p.value)
}

func systemUpdateHandler(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	// log.WithFields(log.Fields{"nType": nType, "key": key}).Debug()
	configTask := &systemConfigTask{
		nType: nType,
		key:   key,
		value: value,
	}
	task := ContainerTask{task: TASK_CONFIG_SYSTEM, taskData: configTask}
	ContainerTaskChan <- &task
}

func systemConfigFileMonitor(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		// log.WithFields(log.Fields{"value": string(value), "key": key}).Debug("GRP:")
		var profile share.CLUSFileMonitorProfile
		json.Unmarshal(value, &profile)
		name := share.CLUSProfileKey2Name(key)

		if name == "nodes" { // reserved group: make it a trigger to file monitor on lost host
			fileWatcher.ContainerCleanup(1)
			config := &fsmon.FsmonConfig{} // TODO:
			config.Profile = &profile
			if len(profile.Filters) > 0 {
				config.Profile.Mode = share.PolicyModeEvaluate // always monitor mode
				go fileWatcher.StartWatch("", 1, config, false, false)
			}
		}
		updateGroupProfileCache(nType, name, profile)
	case cluster.ClusterNotifyDelete: // required no group member that means no belonged containers, either
	}
}

func systemConfigFileAccessRule(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		//	log.WithFields(log.Fields{"value": string(value), "key": key}).Debug("")
		var rule share.CLUSFileAccessRule
		json.Unmarshal(value, &rule)
		name := share.CLUSProfileKey2Name(key)
		updateGroupProfileCache(nType, name, rule)
	}
}

//////
type groupProfile struct {
	group  *share.CLUSGroup
	script *share.CLUSCustomCheckGroup
}

var groupMux sync.RWMutex
var groups map[string]*groupProfile = make(map[string]*groupProfile)

func systemConfigGroup(nType cluster.ClusterNotifyType, key string, value []byte) {
	//	log.WithFields(log.Fields{"value": string(value), "key": key}).Debug("GRP:")
	name := share.CLUSProfileKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var grp share.CLUSGroup
		json.Unmarshal(value, &grp)
		updateGroupProfileCache(nType, name, grp)

		// scripts
		groupMux.Lock()
		defer groupMux.Unlock()
		gp, ok := groups[name]
		if !ok {
			gp = &groupProfile{}
			groups[name] = gp
		}
		gp.group = &grp
		if gp.script != nil {
			bench.triggerContainerCustomCheck()
		}

	case cluster.ClusterNotifyDelete:
		deleteGroupProfileCache(name)

		// scripts
		groupMux.Lock()
		delete(groups, name)
		groupMux.Unlock()
	}
}

func getGroup(name string) (*share.CLUSGroup, error) {
	key := share.CLUSGroupKey(name)
	value, err := cluster.Get(key)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return nil, err
	}
	var grp share.CLUSGroup
	json.Unmarshal(value, &grp)
	return &grp, nil
}

func systemConfigScript(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSProfileKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		log.WithFields(log.Fields{"value": string(value), "key": key}).Debug("")

		groupMux.Lock()
		defer groupMux.Unlock()

		gp, ok := groups[name]
		if !ok {
			grp, err := getGroup(name)
			if err != nil {
				log.WithFields(log.Fields{"name": name}).Error("group not found")
				return
			}
			gp = &groupProfile{group: grp}
			groups[name] = gp
		}

		var script share.CLUSCustomCheckGroup
		json.Unmarshal(value, &script)
		gp.script = &script

		if gp.group.Kind == share.GroupKindNode {
			bench.triggerHostCustomCheck(&script)
		} else if gp.group.Kind == share.GroupKindContainer {
			bench.triggerContainerCustomCheck()
		}
	case cluster.ClusterNotifyDelete:
		groupMux.Lock()
		delete(groups, name)
		groupMux.Unlock()
	}
}

func addLearnedProcess(svcGroup string, proc *share.CLUSProcessProfileEntry) {
	// use the executable as the learned name
	if proc.Name == "" {
		index := strings.LastIndexByte(proc.Path, '/')
		proc.Name = proc.Path[index+1:]
		//	log.WithFields(log.Fields{"name": proc.Name, "path": proc.Path}).Debug("PROC:")
	}

	report := &share.CLUSProcProfileReq{
		GroupName: svcGroup,
		Name:      proc.Name,
		Path:      proc.Path,
		User:      proc.User,
		Uid:       proc.Uid,
		Hash:      proc.Hash,
		Action:    proc.Action,
	}
	learnedProcessMtx.Lock()
	lastReportTime = time.Now()
	if len(learnedProcess) < maxLearnedProcess {
		learnedProcess = append(learnedProcess, report)
	} else {
		// Should not happen, just in case
		log.WithFields(log.Fields{"report": *report}).Debug("Too many - drop")
	}
	learnedProcessMtx.Unlock()
}

func getDomainData(name string) *share.CLUSDomain {
	domainMutex.RLock()
	defer domainMutex.RUnlock()
	if domainCache, ok := domainCacheMap[name]; ok {
		return domainCache.domain
	}
	return nil
}

func domainConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	name := share.CLUSDomainKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var domain share.CLUSDomain
		json.Unmarshal(value, &domain)

		domainMutex.Lock()
		oDomain, _ := domainCacheMap[name]
		domainCacheMap[name] = &domainCache{domain: &domain}
		domainMutex.Unlock()

		if oDomain == nil || !reflect.DeepEqual(oDomain.domain.Labels, domain.Labels){
			domainChange(domain)
		}
		log.WithFields(log.Fields{"domain": domain, "name": name}).Debug()

	case cluster.ClusterNotifyDelete:
		domainMutex.Lock()
		defer domainMutex.Unlock()

		if _, ok := domainCacheMap[name]; !ok {
			log.WithFields(log.Fields{"domain": name}).Error("Unknown domain")
			return
		}

		// Shouldn't happen, but have the logic anyway. Not delete kv, only initial the cache
		domainCacheMap[name] = &domainCache{domain: initDomain(name, nil)}
	}
}
