package cache

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var cfgTypeMapping = map[share.TCfgType]string{
	share.Learned:       api.CfgTypeLearned,
	share.UserCreated:   api.CfgTypeUserCreated,
	share.GroundCfg:     api.CfgTypeGround,
	share.FederalCfg:    api.CfgTypeFederal,
	share.SystemDefined: api.CfgSystemDefined,
}

type policyCacheType struct {
	ruleMap      map[uint32]*share.CLUSPolicyRule
	ruleHeads    []*share.CLUSRuleHead
	ruleOrderMap map[uint32]int
}

var policyCache policyCacheType = policyCacheType{
	ruleMap:      make(map[uint32]*share.CLUSPolicyRule),
	ruleHeads:    make([]*share.CLUSRuleHead, 0),
	ruleOrderMap: make(map[uint32]int, 0),
}

func ruleHeads2OrderMap(heads []*share.CLUSRuleHead) map[uint32]int {
	m := make(map[uint32]int, 0)
	for i, h := range heads {
		m[h.ID] = i
	}
	return m
}

func appIDs2Names(ids []uint32) []string {
	if ids == nil {
		return []string{api.PolicyAppAny}
	}

	var names []string = make([]string, 0)
	for _, id := range ids {
		if name, ok := common.AppNameMap[id]; ok {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return []string{api.PolicyAppAny}
	}

	sort.Strings(names)
	return names
}

func policyRule2REST(rule *share.CLUSPolicyRule) *api.RESTPolicyRule {
	r := api.RESTPolicyRule{
		ID:           rule.ID,
		Comment:      rule.Comment,
		From:         rule.From,
		To:           rule.To,
		Ports:        rule.Ports,
		Applications: appIDs2Names(rule.Applications),
		Action:       rule.Action,
		Learned:      rule.CfgType == share.Learned,
		Disable:      rule.Disable,
		CreatedTS:    rule.CreatedAt.Unix(),
		LastModTS:    rule.LastModAt.Unix(),
		Priority:     rule.Priority,
	}
	r.CfgType, _ = cfgTypeMapping[rule.CfgType]

	return &r
}

func stringArrayContains(a1, a2 []string) bool {
	set1 := utils.NewSet()
	set2 := utils.NewSet()
	for _, a := range a1 {
		set1.Add(a)
	}
	for _, a := range a2 {
		set2.Add(a)
	}
	return set2.IsSubset(set1)
}

func uintArrayContains(a1, a2 []uint32) bool {
	set1 := utils.NewSet()
	set2 := utils.NewSet()
	for _, a := range a1 {
		set1.Add(a)
	}
	for _, a := range a2 {
		set2.Add(a)
	}
	return set2.IsSubset(set1)
}

// return true if rule r1 contains rule r2
func ruleContains(r1, r2 *share.CLUSPolicyRule) bool {
	if r1.ID != r2.ID || r1.From != r2.From || r1.To != r2.To ||
		r1.Action != r2.Action || r1.Disable != r2.Disable {
		return false
	}

	if r1.Ports != "any" && r1.Ports != r2.Ports {
		pl1 := strings.Split(r1.Ports, ",")
		pl2 := strings.Split(r2.Ports, ",")
		if stringArrayContains(pl1, pl2) == false {
			return false
		}
	}

	// take care application any case
	if len(r1.Applications) == 0 {
		return true
	} else if len(r2.Applications) == 0 {
		return false
	}

	if uintArrayContains(r1.Applications, r2.Applications) == false {
		return false
	}
	return true
}

func policyConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	var del *share.CLUSPolicyRule

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		if share.CLUSIsPolicyRuleKey(key) {
			var rule share.CLUSPolicyRule
			json.Unmarshal(value, &rule)

			// post-3.2.2 enforcer report nv containers to controller, if the controller happens to be pre-3.2.2,
			// for example, in upgrade case, the group will be created.
			// Ignore policies of these groups. The group will be deleted in group update.
			if isNeuvectorContainerGroup(rule.From) || isNeuvectorContainerGroup(rule.To) {
				log.WithFields(log.Fields{"rule": rule}).Info("Ignore neuvector policy")
				return
			}

			cacheMutexLock()
			if exist, ok := policyCache.ruleMap[rule.ID]; ok {
				if rule.CfgType == share.UserCreated && !ruleContains(&rule, exist) {
					del = exist
				}

				if gc, ok := groupCacheMap[exist.From]; ok {
					gc.usedByPolicy.Remove(exist.ID)
				}
				if gc, ok := groupCacheMap[exist.To]; ok {
					gc.usedByPolicy.Remove(exist.ID)
				}
			}
			policyCache.ruleMap[rule.ID] = &rule
			// Policy From and To is either a group (including external) or an unmanaged workload or host
			if !rule.Disable {
				if !isHostOrUnmanagedWorkload(rule.From) {
					if gc, ok := groupCacheMap[rule.From]; ok {
						gc.usedByPolicy.Add(rule.ID)
					} else {
						// Could happend at startup or joining the cluster, watch could return
						// policy update before group
						gc = initGroupCache(rule.CfgType, rule.From)
						gc.usedByPolicy.Add(rule.ID)
						groupCacheMap[rule.From] = gc
					}
				}
				if !isHostOrUnmanagedWorkload(rule.To) {
					if gc, ok := groupCacheMap[rule.To]; ok {
						gc.usedByPolicy.Add(rule.ID)
					} else {
						// Could happend at startup or joining the cluster, watch could return
						// policy update before group
						gc = initGroupCache(rule.CfgType, rule.To)
						gc.usedByPolicy.Add(rule.ID)
						groupCacheMap[rule.To] = gc
					}
				}
			}
			cacheMutexUnlock()

			if del != nil {
				deleteConversByPolicyRule(del, false)
			}
		} else if share.CLUSIsPolicyZipRuleListKey(key) {
			var heads []*share.CLUSRuleHead
			json.Unmarshal(value, &heads)

			cacheMutexLock()
			policyCache.ruleHeads = nil
			policyCache.ruleHeads = heads
			policyCache.ruleOrderMap = ruleHeads2OrderMap(heads)
			cacheMutexUnlock()
		}
	case cluster.ClusterNotifyDelete:
		if share.CLUSIsPolicyRuleKey(key) {
			id := share.CLUSPolicyRuleKey2ID(key)
			cacheMutexLock()
			if exist, ok := policyCache.ruleMap[id]; ok {
				if g, ok := groupCacheMap[exist.From]; ok {
					g.usedByPolicy.Remove(exist.ID)
				}
				if g, ok := groupCacheMap[exist.To]; ok {
					g.usedByPolicy.Remove(exist.ID)
				}
				delete(policyCache.ruleMap, id)
				del = exist
			}
			cacheMutexUnlock()
			if del != nil {
				deleteConversByPolicyRule(del, true)
			}
		} else if share.CLUSIsPolicyZipRuleListKey(key) {
			cacheMutexLock()
			policyCache.ruleHeads = nil
			policyCache.ruleHeads = make([]*share.CLUSRuleHead, 0)
			policyCache.ruleOrderMap = ruleHeads2OrderMap(policyCache.ruleHeads)
			cacheMutexUnlock()
		}
	}

	scheduleIPPolicyCalculation(false)
	scheduleDlpRuleCalculation(false)
}

func (m CacheMethod) GetPolicyRuleCount(acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, 0) {
		return len(policyCache.ruleHeads)
	} else {
		var count int = 0
		for _, rh := range policyCache.ruleHeads {
			if rule, ok := policyCache.ruleMap[rh.ID]; ok {
				if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
					continue
				}
				count++
			}
		}
		return count
	}
}

func (m CacheMethod) GetPolicyRule(id uint32, acc *access.AccessControl) (*api.RESTPolicyRule, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if rule, ok := policyCache.ruleMap[id]; ok {
		if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
			return nil, common.ErrObjectAccessDenied
		}
		return policyRule2REST(rule), nil
	}

	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetPolicyRuleCache(id uint32, acc *access.AccessControl) (*share.CLUSPolicyRule, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if rule, ok := policyCache.ruleMap[id]; ok {
		// NOTE: We call "Authorize" instead of "Authorize" here, because most likely this is
		//       to "get for config/delete"
		if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
			return nil, common.ErrObjectAccessDenied
		}
		return rule, nil
	}

	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) PolicyRule2REST(rule *share.CLUSPolicyRule) *api.RESTPolicyRule {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	return policyRule2REST(rule)
}

func (m CacheMethod) GetAllPolicyRules(scope string, acc *access.AccessControl) []*api.RESTPolicyRule {
	var getLocal, getFed bool
	switch scope {
	case share.ScopeLocal:
		getLocal = true
	case share.ScopeFed:
		getFed = true
	case share.ScopeAll:
		getFed = true
		getLocal = true
	default:
		return nil
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rules := make([]*api.RESTPolicyRule, 0, len(policyCache.ruleHeads))
	for _, head := range policyCache.ruleHeads {
		if rule, ok := policyCache.ruleMap[head.ID]; ok {
			if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
				continue
			}
			if (getFed && rule.CfgType == share.FederalCfg) || (getLocal && rule.CfgType != share.FederalCfg) {
				rules = append(rules, policyRule2REST(rule))
			}
		}
	}

	return rules
}

// For replacePolicyRule(), return (rule found in cache, rule is readable, rule is writable)
func (m CacheMethod) CheckPolicyRuleAccess(id uint32, accRead *access.AccessControl, accWrite *access.AccessControl) (bool, bool, bool) {
	var found bool
	var readable, writable bool

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if rule, ok := policyCache.ruleMap[id]; ok {
		found = true
		if accRead.Authorize(rule, getAccessObjectFuncNoLock) {
			readable = true
		}
		if accWrite.Authorize(rule, getAccessObjectFuncNoLock) {
			writable = true
		}
	}

	return found, readable, writable
}

func (m CacheMethod) GetAllPolicyRulesCache(acc *access.AccessControl) []*share.CLUSPolicyRule {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rules := make([]*share.CLUSPolicyRule, 0, len(policyCache.ruleHeads))
	for _, head := range policyCache.ruleHeads {
		if rule, ok := policyCache.ruleMap[head.ID]; ok {
			// NOTE: We call "Authorize" instead of "Authorize" here, because most likely this is
			//       to "get for config/delete"
			if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
				continue
			}
			rules = append(rules, rule)
		}
	}

	return rules
}

// caller owns cacheMutexRLock & has allRead right
func (m CacheMethod) GetFedNetworkRulesCache() ([]*share.CLUSPolicyRule, []*share.CLUSRuleHead) {
	count := 0
	for _, head := range policyCache.ruleHeads {
		if head.CfgType == share.FederalCfg {
			count++
		}
	}
	heads := make([]*share.CLUSRuleHead, 0, count)
	rules := make([]*share.CLUSPolicyRule, 0, count)
	for _, head := range policyCache.ruleHeads {
		if head.CfgType == share.FederalCfg {
			heads = append(heads, head)
			if rule, ok := policyCache.ruleMap[head.ID]; ok {
				if rule.CfgType == share.FederalCfg {
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules, heads
}

func getHostPolicyMode(cache *hostCache) (string, string) {
	if cache, ok := groupCacheMap[api.AllHostGroup]; ok {
		return cache.group.PolicyMode, cache.group.ProfileMode
	} else {
		return share.PolicyModeLearn, share.PolicyModeLearn
	}
}

func getWorkloadPerGroupPolicyMode(wlCache *workloadCache) (string, string) {
	if cache, ok := groupCacheMap[wlCache.learnedGroupName]; ok {
		return cache.group.PolicyMode, cache.group.ProfileMode
	} else {
		return share.PolicyModeLearn, share.PolicyModeLearn
	}
}

// If global net service status is enabled, use global net service
// policy mode, profile still use per group mode
func getWorkloadEffectivePolicyMode(wlCache *workloadCache) (string, string) {
	if getNetServiceStatus() {
		if cache, ok := groupCacheMap[wlCache.learnedGroupName]; ok {
			return getNetServicePolicyMode(), cache.group.ProfileMode
		} else {
			return getNetServicePolicyMode(), share.PolicyModeLearn
		}
	} else {
		if cache, ok := groupCacheMap[wlCache.learnedGroupName]; ok {
			return cache.group.PolicyMode, cache.group.ProfileMode
		} else {
			return share.PolicyModeLearn, share.PolicyModeLearn
		}
	}
}

func getWorkloadBaselineProfile(wlCache *workloadCache) string {
	if cache, ok := groupCacheMap[wlCache.learnedGroupName]; ok {
		return cache.group.BaselineProfile
	}
	return ""
}

func getWorkloadAddress(wlCache *workloadCache) share.CLUSWorkloadAddr {
	wlAddr := share.CLUSWorkloadAddr{
		WlID: wlCache.workload.ID,
	}
	wlAddr.PolicyMode, _ = getWorkloadEffectivePolicyMode(wlCache)
	for _, addrs := range wlCache.workload.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeLocalhost:
				wlAddr.LocalIP = append(wlAddr.LocalIP, addr.IPNet.IP)
			case share.CLUSIPAddrScopeGlobal:
				wlAddr.GlobalIP = append(wlAddr.GlobalIP, addr.IPNet.IP)
			}
		}
	}

	hostID := wlCache.workload.HostID
	if hostCache, ok := hostCacheMap[hostID]; ok {
		for _, addrs := range hostCache.host.Ifaces {
			for _, addr := range addrs {
				wlAddr.NatIP = append(wlAddr.NatIP, addr.IPNet.IP)
			}
		}
	}

	if !policyApplyIngress {
		//For mixed group policy on openshift platform etc.,
		//prepare NatPortApp for CLUSWLModeGroup type policy.
		pp := getMappedPort(wlCache.workload, "any")
		if pp != "" {
			wlAddr.NatPortApp = []share.CLUSPortApp{
				share.CLUSPortApp{
					Ports:       pp,
					Application: C.DP_POLICY_APP_ANY,
				},
			}
		}
	}
	return wlAddr
}

// Accept IP range list separated by comma
func getIPList(ipList string) []net.IP {
	var ret []net.IP
	ipRanges := strings.Split(ipList, ",")
	for _, ipRange := range ipRanges {
		ip, ipr := utils.ParseIPRange(ipRange)
		if ip == nil || ipr == nil {
			return nil
		}
		ret = append(ret, ip)
		if ipr.Equal(ip) {
			// use nil to indicate single IP so that agent can use it directly
			ret = append(ret, nil)
		} else {
			ret = append(ret, ipr)
		}
	}
	return ret
}

func getCommonPorts(ports1 string, ports2 string) string {
	var p, pp string = "", ""
	var low, high uint16
	var proto uint8

	p1 := strings.Split(ports1, ",")
	p2 := strings.Split(ports2, ",")
	for _, pp1 := range p1 {
		proto1, low1, high1, err := utils.ParsePortRangeLink(pp1)
		if err != nil {
			// log.WithFields(log.Fields{"port": ports1}).Error("Fail to parse")
			continue
		}
		for _, pp2 := range p2 {
			proto2, low2, high2, err := utils.ParsePortRangeLink(pp2)
			if err != nil {
				// log.WithFields(log.Fields{"port": ports2}).Error("Fail to parse")
				continue
			}

			if proto1 == 0 {
				proto = proto2
			} else if proto2 == 0 {
				proto = proto1
			} else if proto1 == proto2 {
				proto = proto1
			} else {
				continue
			}
			if high1 < low2 || high2 < low1 {
				continue
			}
			if low1 > low2 {
				low = low1
			} else {
				low = low2
			}
			if high1 > high2 {
				high = high2
			} else {
				high = high1
			}
			pp = utils.GetPortRangeLink(proto, low, high)
			if p == "" {
				p = pp
			} else {
				p = fmt.Sprintf("%s,%s", p, pp)
			}
		}
	}
	//log.WithFields(log.Fields{"ports1": ports1, "ports2": ports2, "common": p}).Debug()
	return p
}

func getMappedPort(wl *share.CLUSWorkload, ports string) string {
	var pp string = ""
	portList := strings.Split(ports, ",")
	for _, ap := range portList {
		proto, pl, ph, err := utils.ParsePortRangeLink(ap)
		if err != nil {
			// log.WithFields(log.Fields{"port": ap}).Error("Fail to parse")
			continue
		}
		for _, mp := range wl.Ports {
			// seems the mapping is not ip specific, so ip is ignored in mapping search
			if (mp.IPProto == proto || proto == 0) && (mp.Port >= pl && mp.Port <= ph) {
				if pp == "" {
					pp = utils.GetPortLink(mp.IPProto, mp.HostPort)
				} else {
					pp = fmt.Sprintf("%s,%s", pp, utils.GetPortLink(mp.IPProto, mp.HostPort))
				}
			}
		}
	}
	return pp
}

func fillPortsForWorkloadAddress(wlAddr *share.CLUSWorkloadAddr, ports string, apps []uint32) {
	var wlCache *workloadCache
	var ok bool
	var pp string

	if wlCache, ok = wlCacheMap[wlAddr.WlID]; !ok {
		log.WithFields(log.Fields{"workload": wlAddr.WlID}).Error("Cannot find workload")
		return
	}

	//log.WithFields(log.Fields{"port": ports, "apps": apps}).Debug("")
	if apps != nil && len(apps) != 0 {
		wlAddr.LocalPortApp = make([]share.CLUSPortApp, 0)
		wlAddr.NatPortApp = make([]share.CLUSPortApp, 0)
		for _, app := range apps {
			if ports == "" {
				pp = "any"
			} else {
				pp = ports
			}
			// Allow rule for the given app and port (if not given use port any
			// as the reported ports for the app may not be accurate
			wlAddr.LocalPortApp = append(wlAddr.LocalPortApp,
				share.CLUSPortApp{
					Ports:       pp,
					Application: app,
					CheckApp:    true,
				})
			mapp := getMappedPort(wlCache.workload, pp)
			if mapp != "" {
				wlAddr.NatPortApp = append(wlAddr.NatPortApp,
					share.CLUSPortApp{
						Ports:       mapp,
						Application: app,
						CheckApp:    true,
					})
			}

			// For some app, we may not always reliablely identify them.
			// So we utilize the recognized ports. If the app
			// is not identified on these ports, we handle them the same as
			// the specified app
			if app >= C.DPI_APP_PROTO_MARK {
				appPorts := getPortsForApplication(wlCache.workload, app)
				if ports == "" {
					pp = appPorts
				} else {
					pp = getCommonPorts(appPorts, ports)
				}
				if pp != "" {
					wlAddr.LocalPortApp = append(wlAddr.LocalPortApp,
						share.CLUSPortApp{
							Ports:       pp,
							Application: C.DP_POLICY_APP_UNKNOWN,
							CheckApp:    true,
						})

					mapp := getMappedPort(wlCache.workload, pp)
					if mapp != "" {
						wlAddr.NatPortApp = append(wlAddr.NatPortApp,
							share.CLUSPortApp{
								Ports:       mapp,
								Application: C.DP_POLICY_APP_UNKNOWN,
								CheckApp:    true,
							})
					}
				}
			}
		}
	} else if ports != "" {
		wlAddr.LocalPortApp = []share.CLUSPortApp{
			share.CLUSPortApp{
				Ports:       ports,
				Application: C.DP_POLICY_APP_ANY,
			},
		}
		pp := getMappedPort(wlCache.workload, ports)

		if pp != "" {
			wlAddr.NatPortApp = []share.CLUSPortApp{
				share.CLUSPortApp{
					Ports:       pp,
					Application: C.DP_POLICY_APP_ANY,
				},
			}
		}
	}
}

func getPortApp(ports string, apps []uint32) []share.CLUSPortApp {
	if apps != nil && len(apps) != 0 {
		num := len(apps)
		portApp := make([]share.CLUSPortApp, num)
		for i := 0; i < num; i++ {
			portApp[i] = share.CLUSPortApp{
				Ports:       ports,
				Application: apps[i],
				CheckApp:    true,
			}
		}
		return portApp
	} else if ports != "" {
		portApp := []share.CLUSPortApp{
			share.CLUSPortApp{
				Ports:       ports,
				Application: C.DP_POLICY_APP_ANY,
			},
		}
		return portApp
	}
	return nil
}

func fillAddrForGroup(name string, ports string, hostID string, apps []uint32, isDst bool) []*share.CLUSWorkloadAddr {
	if name == api.LearnedExternal {
		groupAddrs := []*share.CLUSWorkloadAddr{
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLExternal,
				NatIP:      []net.IP{share.CLUSIPExternal},
				NatPortApp: getPortApp(ports, apps),
			},
		}
		return groupAddrs
	} else if utils.IsGroupNodes(name) {
		groupAddrs := []*share.CLUSWorkloadAddr{
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSHostAddrGroup,
				NatIP:      make([]net.IP, 0),
				NatPortApp: getPortApp(ports, apps),
			},
		}
		for _, host := range ipHostMap {
			groupAddrs[0].NatIP = append(groupAddrs[0].NatIP, []net.IP{host.ipnet.IP, nil}...)
		}
		if !isDst {
			// If from address is AllHostGroup, always append the loopback IP to allow connections
			// from host loopback IP to the host-mode containers.
			// No effect for non-host-mode container.
			groupAddrs[0].NatIP = append(groupAddrs[0].NatIP, []net.IP{utils.IPv4Loopback, nil}...)
		}
		return groupAddrs
	} else if cache, ok := groupCacheMap[name]; ok {
		groupAddrs := make([]*share.CLUSWorkloadAddr, 0, cache.members.Cardinality())
		for _, m := range cache.members.ToSlice() {
			wlAddr := share.CLUSWorkloadAddr{
				WlID: m.(string),
			}
			//set PolicyMode here to avoid 'Missing policy mode'
			//errror at the adjustAction().
			if wlCache1, ok1 := wlCacheMap[m.(string)]; ok1 {
				if wlCache1.workload.HasDatapath == false {
					continue
				}
				wlAddr.PolicyMode, _ = getWorkloadEffectivePolicyMode(wlCache1)
			}
			if isDst {
				fillPortsForWorkloadAddress(&wlAddr, ports, apps)
			}
			groupAddrs = append(groupAddrs, &wlAddr)
		}

		var ipList []net.IP
		for _, cri := range cache.group.Criteria {
			if cri.Key == share.CriteriaKeyAddress {
				if a := getIPList(cri.Value); a != nil {
					ipList = append(ipList, a...)
				} else {
					// domain name
					wlAddr := share.CLUSWorkloadAddr{
						WlID:       share.CLUSWLFqdnPrefix + cri.Value,
						NatPortApp: getPortApp(ports, apps),
					}
					groupAddrs = append(groupAddrs, &wlAddr)
				}
			}
		}

		if !policyApplyIngress && isDst { //openshift
			svcips := make([]net.IP, 0)
			if svcipset, ok1 := grpSvcIpByDomainMap[cache.group.Name]; ok1 {
				for sipgrp := range svcipset.Iter() {
					if sigc, ok2 := groupCacheMap[sipgrp.(string)]; ok2 {
						for a := range sigc.svcAddrs.Iter() {
							svcips = append(svcips, []net.IP{net.ParseIP(a.(string)), nil}...)
						}
					}
				}
			}
			//include nv.ip.xxx in openshift
			if svcips != nil && len(svcips) > 0 {
				ipList = append(ipList, svcips...)
			}
		}

		if len(ipList) > 0 {
			ipAddr := share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLAddressGroup,
				NatIP:      ipList,
				NatPortApp: getPortApp(ports, apps),
			}
			groupAddrs = append(groupAddrs, &ipAddr)
		}
		/*
			// no need to pass service address for source group right now
			if cache.svcAddr != nil && isDst {
				svcPort := utils.GetPortLink(0, cache.svcAddr.Port)
				if ports != "" {
					svcPort = getCommonPorts(svcPort, ports)
				}
				if svcPort != "" {
					svcAddr := share.CLUSWorkloadAddr{
						WlID:         share.CLUSWLService,
						PolicyMode:   getGroupPolicyMode(cache),
						GlobalIP:     []net.IP{cache.svcAddr.IPNet.IP},
						LocalPortApp: getPortApp(svcPort, apps),
					}
					groupAddrs = append(groupAddrs, &svcAddr)
				}
			}
		*/
		return groupAddrs
	} else if strings.HasPrefix(name, api.LearnedHostPrefix) {
		if names := strings.Split(name, api.LearnedHostPrefix); len(names) == 2 {
			ip := net.ParseIP(names[1])
			if ip != nil {
				groupAddrs := []*share.CLUSWorkloadAddr{
					&share.CLUSWorkloadAddr{
						WlID:       name,
						NatIP:      []net.IP{ip},
						NatPortApp: getPortApp(ports, apps),
					},
				}
				return groupAddrs
			} else if hostCache, ok := hostCacheMap[hostID]; ok {
				groupAddrs := []*share.CLUSWorkloadAddr{
					&share.CLUSWorkloadAddr{
						WlID:       specialEPName(api.LearnedHostPrefix, hostID),
						NatIP:      make([]net.IP, 0),
						NatPortApp: getPortApp(ports, apps),
					},
				}
				for _, addrs := range hostCache.host.Ifaces {
					for _, addr := range addrs {
						groupAddrs[0].NatIP = append(groupAddrs[0].NatIP, addr.IPNet.IP)
					}

				}
				return groupAddrs
			}
		}
	} else if strings.HasPrefix(name, api.LearnedWorkloadPrefix) {
		if names := strings.Split(name, api.LearnedWorkloadPrefix); len(names) == 2 {
			addr := share.CLUSWorkloadAddr{
				WlID:         name,
				GlobalIP:     make([]net.IP, 0),
				LocalPortApp: getPortApp(ports, apps),
			}
			if names[1] == api.EndpointIngress {
				for _, c := range hostCacheMap {
					for _, ipnet := range c.host.TunnelIP {
						addr.GlobalIP = append(addr.GlobalIP, ipnet.IP)
					}
				}
			} else {
				addr.GlobalIP = append(addr.GlobalIP, net.ParseIP(names[1]))
			}
			groupAddrs := []*share.CLUSWorkloadAddr{&addr}
			return groupAddrs
		}
	}

	log.WithFields(log.Fields{"group": name, "host": hostID}).Error("Failed!")
	return nil
}

func printOneGroupIPPolicy(p *share.CLUSGroupIPPolicy) {
	/*
		value, _ := json.Marshal(p)
		log.WithFields(log.Fields{"value": string(value)}).Debug("")
	*/
}

var wlLearnList []*share.CLUSWorkloadAddr
var wlEvalList []*share.CLUSWorkloadAddr
var wlEnforceList []*share.CLUSWorkloadAddr

func getDefaultGroupPolicy() share.CLUSGroupIPPolicy {
	policy := share.CLUSGroupIPPolicy{
		ID: share.DefaultGroupRuleID,
	}

	policy.From = make([]*share.CLUSWorkloadAddr, 0, len(wlCacheMap))
	wlLearnList = make([]*share.CLUSWorkloadAddr, 0)
	wlEvalList = make([]*share.CLUSWorkloadAddr, 0)
	wlEnforceList = make([]*share.CLUSWorkloadAddr, 0)
	for _, cache := range wlCacheMap {
		if cache.groups.Cardinality() == 0 {
			/* workload not assigned group yet - skip */
			continue
		}
		if !cache.workload.Running {
			continue
		}
		/*
		 * In a new deployment, a new workload info is sent by enforcer to cluster
		 * and controller will process workloadUpdate and create new learned group.
		 * this workload/container is added as a member of 'containers' group, this
		 * will trigger a policy recalculation, but at this time groupcache W.R.T.
		 * newly created group may not be stored in groupcacheMap yet depending on
		 * when groupConfigUpdate is triggered.
		 * So we do not calculate policy for this workload until the learned group
		 * is in groupcache so that we can get correct mode information
		 */
		if _, ok := groupCacheMap[cache.learnedGroupName]; !ok {
			continue
		}
		//we only push container that has datapath, normally it is parent, but since oc4.9+
		//parent pid could be 0, so it is also possible this is child
		//we only want to carry one member of POD family to reduce policy recalculate size
		//this can save cpu, memory and internal network bandwidth
		if cache.workload.HasDatapath == false {
			continue
		}
		addr := getWorkloadAddress(cache)
		policy.From = append(policy.From, &addr)
		if addr.PolicyMode == share.PolicyModeLearn {
			wlLearnList = append(wlLearnList, &addr)
		} else if addr.PolicyMode == share.PolicyModeEvaluate {
			wlEvalList = append(wlEvalList, &addr)
		} else if addr.PolicyMode == share.PolicyModeEnforce {
			wlEnforceList = append(wlEnforceList, &addr)
		}
	}

	printOneGroupIPPolicy(&policy)
	return policy
}

func getServiceAddrForMode(mode string) []*share.CLUSWorkloadAddr {
	dstList := make([]*share.CLUSWorkloadAddr, 0)
	for _, cache := range groupCacheMap {
		for a := range cache.svcAddrs.Iter() {
			if cache.group.PolicyMode == mode {
				svcAddr := share.CLUSWorkloadAddr{
					WlID:       share.CLUSWLAddressGroup,
					PolicyMode: mode,
					NatIP:      []net.IP{net.ParseIP(a.(string)), nil},
					NatPortApp: getPortApp("any", nil),
				}
				dstList = append(dstList, &svcAddr)
			}
		}
	}
	return dstList
}

func getMixedGroupPolicyForIngress() []share.CLUSGroupIPPolicy {
	policyList := make([]share.CLUSGroupIPPolicy, 0)
	if len(wlLearnList) > 0 && (len(wlEvalList) > 0 || len(wlEnforceList) > 0) {
		policy := share.CLUSGroupIPPolicy{
			ID:     share.DefaultGroupRuleID,
			Action: C.DP_POLICY_ACTION_LEARN,
		}
		policy.From = append(policy.From,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeLearn,
			})

		policy.To = append(policy.To,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeEvaluate + "," + share.PolicyModeEnforce,
				LocalPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
			})
		printOneGroupIPPolicy(&policy)
		policyList = append(policyList, policy)
	}

	if len(wlEvalList) > 0 && len(wlEnforceList) > 0 {
		policy := share.CLUSGroupIPPolicy{
			ID:     share.DefaultGroupRuleID,
			Action: C.DP_POLICY_ACTION_VIOLATE,
		}
		policy.From = append(policy.From,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeEvaluate,
			})
		policy.To = append(policy.To,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeEnforce,
				LocalPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
			})
		printOneGroupIPPolicy(&policy)
		policyList = append(policyList, policy)
	}
	return policyList
}

func getMixedGroupPolicy() []share.CLUSGroupIPPolicy {
	policyList := make([]share.CLUSGroupIPPolicy, 0)
	if len(wlLearnList) > 0 && (len(wlEvalList) > 0 || len(wlEnforceList) > 0) {
		policy := share.CLUSGroupIPPolicy{
			ID:     share.DefaultGroupRuleID,
			Action: C.DP_POLICY_ACTION_LEARN,
		}

		if len(wlEvalList) > 0 {
			policy.From = append(policy.From,
				&share.CLUSWorkloadAddr{
					WlID:       share.CLUSWLModeGroup,
					PolicyMode: share.PolicyModeEvaluate,
				})
		}
		if len(wlEnforceList) > 0 {
			policy.From = append(policy.From,
				&share.CLUSWorkloadAddr{
					WlID:       share.CLUSWLModeGroup,
					PolicyMode: share.PolicyModeEnforce,
				})
		}

		/*for _, wl := range wlLearnList {
			wlAddr := share.CLUSWorkloadAddr{
				WlID: wl.WlID,
			}
			fillPortsForWorkloadAddress(&wlAddr, "any", nil)
			policy.To = append(policy.To, &wlAddr)
		}*/
		//the whole calculateIPPolicyFromCache function
		//is locked by cacheMutexRLock/cacheMutexRUnlock
		//it is better use CLUSWLModeGroup here and expand
		//it later in agent's parseGroupIPPolicy function
		//to reduce locking time

		policy.To = append(policy.To,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeLearn,
				LocalPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
				NatPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
			})

		srv := getServiceAddrForMode(share.PolicyModeLearn)
		policy.To = append(policy.To, srv...)
		if len(policy.To) != 0 {
			policyList = append(policyList, policy)
		}
		printOneGroupIPPolicy(&policy)
	}

	if len(wlEvalList) > 0 && len(wlEnforceList) > 0 {
		policy := share.CLUSGroupIPPolicy{
			ID:     share.DefaultGroupRuleID,
			Action: C.DP_POLICY_ACTION_VIOLATE,
		}

		policy.From = append(policy.From,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeEnforce,
			})
		/*for _, wl := range wlEvalList {
			wlAddr := share.CLUSWorkloadAddr{
				WlID: wl.WlID,
			}
			fillPortsForWorkloadAddress(&wlAddr, "any", nil)
			policy.To = append(policy.To, &wlAddr)
		}*/
		policy.To = append(policy.To,
			&share.CLUSWorkloadAddr{
				WlID:       share.CLUSWLModeGroup,
				PolicyMode: share.PolicyModeEvaluate,
				LocalPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
				NatPortApp: []share.CLUSPortApp{
					share.CLUSPortApp{
						Ports:       "any",
						Application: C.DP_POLICY_APP_ANY,
					},
				},
			})
		srv := getServiceAddrForMode(share.PolicyModeEvaluate)
		policy.To = append(policy.To, srv...)
		if len(policy.To) != 0 {
			policyList = append(policyList, policy)
		}
		printOneGroupIPPolicy(&policy)
	}
	return policyList
}

/*func printRuleHeads(rhs []*share.CLUSRuleHead, debugMsg string) {
	for _, head := range rhs {
		log.WithFields(log.Fields{"rulehead": *head}).Debug(debugMsg)
	}
}*/

func ruleAdjustOrder(rule *share.CLUSPolicyRule) bool {
	//user created rule with deny action  from/to 'nodes' or 'Host:xxxxxx'
	if rule.CfgType != share.Learned &&
		rule.Action == share.PolicyActionDeny &&
		(utils.IsGroupNodes(rule.From) ||
			utils.IsGroupNodes(rule.To) ||
			strings.HasPrefix(rule.From, api.LearnedHostPrefix) ||
			strings.HasPrefix(rule.To, api.LearnedHostPrefix)) {
		return true
	}
	return false
}

func adjustPolicyRuleHeads() []*share.CLUSRuleHead {
	adjRuleHeads := make([]*share.CLUSRuleHead, 0)
	hostRuleHeads := make([]*share.CLUSRuleHead, 0)
	for _, head := range policyCache.ruleHeads {
		if rule, ok := policyCache.ruleMap[head.ID]; ok && !rule.Disable {
			if ruleAdjustOrder(rule) {
				hostRuleHeads = append(hostRuleHeads, head)
			} else {
				adjRuleHeads = append(adjRuleHeads, head)
			}
		} else { //keep the original rule list
			adjRuleHeads = append(adjRuleHeads, head)
		}
	}
	//user created host related deny rules are put to the end of list
	adjRuleHeads = append(adjRuleHeads, hostRuleHeads...)

	return adjRuleHeads
}

func calculateIPPolicyFromCache() []share.CLUSGroupIPPolicy {
	log.Debug("")

	//simulator func to test policy capacity
	//return kv.CalculateIPPolicyFromCacheFake()

	groupIPPolicies := make([]share.CLUSGroupIPPolicy, 0, len(policyCache.ruleHeads)+1)
	groupIPPolicies = append(groupIPPolicies, getDefaultGroupPolicy())
	/*
	 * host mode system container use same ip as host itself
	 * user created host related rule has higher priority than
	 * learned rule, to prevent already established connection
	 * to/from host mode system container being denied we put
	 * user created host related deny rules to the end
	 */
	adjustRuleHeads := adjustPolicyRuleHeads()

	for _, head := range adjustRuleHeads {
		if rule, ok := policyCache.ruleMap[head.ID]; !ok {
			log.WithFields(log.Fields{"ID": head.ID}).Debug()
		} else if !rule.Disable {
			policy := share.CLUSGroupIPPolicy{
				ID:     head.ID,
				Action: C.DP_POLICY_ACTION_ALLOW,
			}
			if rule.Action == share.PolicyActionDeny {
				policy.Action = C.DP_POLICY_ACTION_DENY
			}

			// assume the from/to contains only one group
			/*
				log.WithFields(log.Fields{
					"from": rule.From, "to": rule.To, "ports": rule.Ports, "app": rule.Applications,
				}).Debug("Calculate rule")
			*/

			policy.From = fillAddrForGroup(rule.From, "", rule.FromHost, nil, false)
			if policy.From == nil || len(policy.From) == 0 {
				continue
			}
			policy.To = fillAddrForGroup(rule.To, rule.Ports, rule.ToHost, rule.Applications, true)
			if policy.To == nil || len(policy.To) == 0 {
				continue
			}
			groupIPPolicies = append(groupIPPolicies, policy)
			printOneGroupIPPolicy(&policy)
		}
	}
	if policyApplyIngress {
		policy := getMixedGroupPolicyForIngress()
		groupIPPolicies = append(groupIPPolicies, policy...)
	} else {
		policy := getMixedGroupPolicy()
		groupIPPolicies = append(groupIPPolicies, policy...)
	}
	//release memory
	wlLearnList = nil
	wlEvalList = nil
	wlEnforceList = nil

	return groupIPPolicies
}

func getPolicyIPRulesFromCluster() []share.CLUSGroupIPPolicy {
	rules := make([]share.CLUSGroupIPPolicy, 0)
	key := share.CLUSPolicyIPRulesKey(share.PolicyIPRulesDefaultName)
	if value, _ := cluster.Get(key); value != nil {
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip data")
		} else {
			json.Unmarshal(uzb, &rules)
		}
		return rules
	}

	return nil
}

//each slot's max size after zip is 500k
const maxPolicySlots = 512
//based on cluster size start from different base
const beginSlotSmall = 16
const beginSlotMedium = 32
const beginSlotLarge = 64
const beginSlotSuper = 128
const clusterSmall = 3000
const clusterMedium = 6000
const clusterLarge = 9000

func preparePolicySlots(rules []share.CLUSGroupIPPolicy) ([][]byte, int, int, error) {
	//total number of workloads
	wlen := len(rules[0].From)
	//start from different base to save cpu
	beginSlot := 0
	if wlen < clusterSmall {
		beginSlot = beginSlotSmall
	} else if wlen < clusterMedium {
		beginSlot = beginSlotMedium
	} else if wlen < clusterLarge {
		beginSlot = clusterLarge
	} else {
		beginSlot = beginSlotSuper
	}
	log.WithFields(log.Fields{
			"wlen":           wlen,
			"beginSlot":      beginSlot,
			"maxPolicySlots": maxPolicySlots,
	}).Debug("begin slots")
	// deal with case that compressed rule size is > max kv value size (512K)
	for slots := beginSlot; slots <= maxPolicySlots; slots *= 2 {
		//first rule has address info for all workloads in cluster
		//the size can be very big so we need to split this rule into
		//small rules
		wl_lens := len(rules[0].From)
		wl_slots := slots
		if wl_lens < slots {
			wl_slots = wl_lens
		}
		rules_wl := make([]share.CLUSGroupIPPolicy, wl_slots)
		for i := 0; i < wl_lens; i++ {
			if i < wl_slots {
				rules_wl[i].ID = share.DefaultGroupRuleID
				rules_wl[i].From = make([]*share.CLUSWorkloadAddr, 0)
				rules_wl[i].From = append(rules_wl[i].From, rules[0].From[i])
			} else {
				rules_wl[i%wl_slots].From = append(rules_wl[i%wl_slots].From, rules[0].From[i])
			}
		}
		new_rules := make([]share.CLUSGroupIPPolicy, 0)
		new_rules = append(new_rules, rules_wl...)
		new_rules = append(new_rules, rules[1:]...)

		enlarge := false
		final_slots := slots
		rule_lens := len(new_rules)
		if rule_lens < slots {
			final_slots = rule_lens
		}
		log.WithFields(log.Fields{
			"wl_lens":        wl_lens,
			"wl_slots":       wl_slots,
			"slots":          slots,
			"orig_rule_lens": len(rules),
			"rule_lens":      rule_lens,
			"final_slots":    final_slots,
			"maxPolicySlots": maxPolicySlots,
		}).Debug("segregate rules to slots")

		//put rules to slots evenly
		plcs := make([][]share.CLUSGroupIPPolicy, final_slots)
		for idx, rl := range new_rules {
			//log.WithFields(log.Fields{"slot_idx": idx%final_slots, "rule_idx": idx, }).Debug("assign rules to slots")
			plcs[idx%final_slots] = append(plcs[idx%final_slots], rl)
		}

		//zip each slots
		zbs := make([][]byte, final_slots)
		for i, plc := range plcs {
			value, _ := json.Marshal(plc)
			zb := utils.GzipBytes(value)
			//log.WithFields(log.Fields{"slot_idx": i, "size": len(zb)}).Debug("gzip policy ip rules")
			if len(zb) >= cluster.KVValueSizeMax {
				log.WithFields(log.Fields{"slot_idx": i, "size": len(zb)}).Debug("gzip policy ip rules too large")
				enlarge = true
				break
			}
			zbs[i] = zb
		}

		//log.WithFields(log.Fields{"enlarge": enlarge}).Debug("")
		if !enlarge {
			return zbs, wl_slots, wl_lens, nil
		}
	}

	return nil, 0, 0, errors.New("Policy rules are too large")
}

func policyIPRulesCleanup(ruleKeys []string) {
	txn := cluster.Transact()
	defer txn.Close()

	// Remove keys that have been written
	for _, key := range ruleKeys {
		txn.Delete(key)
	}
	//Ignore failure, missed keys will be removed the next update.
	txn.Apply()
}

func putPolicyIPRulesToClusterScale(rules []share.CLUSGroupIPPolicy) {
	//
	//GroupIPRules is not directly watched by consul, to improve performance
	//change key from "network/GroupIPRules/" to "recalculate/policy/GroupIPRules/"
	//rule_key := fmt.Sprintf("%s/", share.CLUSPolicyIPRulesKey(share.PolicyIPRulesDefaultName))
	rule_key := fmt.Sprintf("%s/", share.CLUSRecalPolicyIPRulesKey(share.PolicyIPRulesDefaultName))
	oldKeys, _ := cluster.GetStoreKeys(rule_key)

	verstr := fmt.Sprintf("ver.%d.%d", time.Now().UTC().UnixNano(), time.Now().UTC().UnixNano())
	newRuleKey := fmt.Sprintf("%s%s/", rule_key, verstr)

	// separate all rules into slots
	zbs, wlslots, wlens, err := preparePolicySlots(rules)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return
	}

	//put rules to cluster in separate slot
	for i, zb := range zbs {
		key := fmt.Sprintf("%s%d", newRuleKey, i)
		if err = cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err, "slot": i, "size": len(zb)}).Error()
			newKeys, _ := cluster.GetStoreKeys(newRuleKey)
			policyIPRulesCleanup(newKeys)
			return
		}
	}

	//new kv to indicate rule change
	polVer := share.CLUSGroupIPPolicyVer{
		Key:                  share.PolicyIPRulesVersionID,
		PolicyIPRulesVersion: verstr,
		SlotNo:               len(zbs),
		RulesLen:             len(rules) + wlslots - 1,
		WorkloadSlot:         wlslots,
		WorkloadLen:          wlens,
	}
	log.WithFields(log.Fields{"PolicyIPRules": newRuleKey, "policyVer": polVer}).Debug("New policy rules written")

	clusHelper := kv.GetClusterHelper()
	if err = clusHelper.PutPolicyVer(&polVer); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write network policy to the cluster")
		newKeys, _ := cluster.GetStoreKeys(newRuleKey)
		policyIPRulesCleanup(newKeys)
		return
	}
	policyIPRulesCleanup(oldKeys)
}

func putPolicyIPRulesToCluster(rules []share.CLUSGroupIPPolicy) {
	key := share.CLUSPolicyIPRulesKey(share.PolicyIPRulesDefaultName)
	value, _ := json.Marshal(rules)
	zb := utils.GzipBytes(value)
	if err := cluster.PutBinary(key, zb); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
	}
	//log.WithFields(log.Fields{"value": string(value), "len": len(value), "zb": len(zb)}).Debug("")
}

func scheduleIPPolicyCalculation(fast bool) {
	log.WithFields(log.Fields{"fast": fast, "policyCalculated": policyCalculated}).Debug("")

	if !policyCalculated {
		policyCalculated = true
		firstPolicyCalculateAt = time.Now().UTC()
		if fast {
			policyCalculatingTimer.Reset(policyCalculatingDelayFast)
		} else {
			policyCalculatingTimer.Reset(policyCalculatingDelaySlow)
		}
	} else if time.Since(firstPolicyCalculateAt) > policyCalDelayMax {
		log.Debug("Trigger policy recalculation")
		policyCalculatingTimer.Reset(0)
	} else {
		if fast {
			policyCalculatingTimer.Reset(policyCalculatingDelayFast)
		} else {
			policyCalculatingTimer.Reset(policyCalculatingDelaySlow)
		}
	}
}
