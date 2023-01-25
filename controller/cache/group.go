package cache

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type groupCache struct {
	group               *share.CLUSGroup
	members             utils.Set
	svcAddrs            utils.Set // net.IP.String()
	usedByPolicy        utils.Set
	usedByResponseRules utils.Set
	ipsvcInternal       bool
	capChgMode          bool
	capScorable         bool
	oemHide             bool
	ingressDMZ          int
	egressDMZ           int
	timerTask           string
	atmo_d2m            int64
	atmo_m2p            int64
}

func isIPSvcGrpInternal(group *share.CLUSGroup) bool {
	// Only consider the svc address as internal if the service group has selector for workload
	// Otherwise, the svc can be a redirect to outside ip

	// 2018/10/9: only kubernetes-like platform create ip service group. Always use having selector
	// or not to check if ip is internal
	// 2018/10/11: internal flag is only used to refresh internal IP
	for _, c := range group.Criteria {
		if c.Key == share.CriteriaKeyLabel {
			return true
		}
	}

	// 2021/5: the name "isIPSvcGrpInternal" does not always mean what it is. In swarm case, we create
	// service IP group without selectors, but they are internal groups. As of now, this flag is only
	// used to check if a group should be hidden when policy is applied at ingress, while swarm applies
	// policy at egress, so we are OK.
	return false
}

func isIPSvcGrpHidden(cache *groupCache) bool {
	// 2018/10/11: this only affect group and if group appears in the graph
	if policyApplyIngress {
		return cache.ipsvcInternal
	} else {
		return false
	}
}

func authorizeGroup(cache *groupCache, acc *access.AccessControl) error {
	if cache.group.CfgType != share.FederalCfg && isIPServiceGroup(cache.group) && isIPSvcGrpHidden(cache) {
		return common.ErrObjectNotFound
	}
	if !acc.Authorize(cache.group, nil) {
		return common.ErrObjectAccessDenied
	}
	return nil
}

func authorizeService(cache *groupCache, acc *access.AccessControl) error {
	if cache.group.CfgType != share.Learned || cache.group.Kind != share.GroupKindContainer {
		if cache.group.CfgType == share.GroundCfg && strings.HasPrefix(cache.group.Name, api.LearnedGroupPrefix) {
			log.WithFields(log.Fields{"GrandServie ": cache.group.Name}).Debug("Find service")
		} else {
			return common.ErrObjectNotFound
		}
	}
	if !acc.Authorize(cache.group, nil) {
		return common.ErrObjectAccessDenied
	}
	return nil
}

var groupCacheMap map[string]*groupCache = make(map[string]*groupCache)
var addr2SvcMap map[string]*groupCache = make(map[string]*groupCache)
var nepMap map[string]*share.CLUSNetworkEP = make(map[string]*share.CLUSNetworkEP)
var grpSvcIpByDomainMap map[string]utils.Set = make(map[string]utils.Set) //key is group name, value is nv.ip.xxx group names
var addr2ExtIpMap map[string][]net.IP = make(map[string][]net.IP)         //key svc cluster ip, value is externalIPs
var extIp2addrMap map[string]net.IP = make(map[string]net.IP)             //key externalIP, value is svc cluster ip
var addr2ExtIpRefreshMap map[string]bool = make(map[string]bool)          //key svc cluster ip

func getSvcAddrGroupNameByExtIP(ip net.IP, port uint16) string {
	if addrip, ok := extIp2addrMap[ip.String()]; ok {
		return getSvcAddrGroupName(addrip, port)
	}
	return ""
}

func getSvcAddrGroupName(ip net.IP, port uint16) string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if svc, ok := addr2SvcMap[ip.String()]; ok {
		return svc.group.Name
	}

	return ""
}

func getSvcAddrGroup(ip net.IP, port uint16) *groupCache {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if svc, ok := addr2SvcMap[ip.String()]; ok {
		return svc
	}
	return nil
}

func updateAddr2SvcMap(svcgrp *groupCache, ip string) {
	log.WithFields(log.Fields{
		"svc": svcgrp.group.Name, "internal": svcgrp.ipsvcInternal, "addr": ip,
	}).Debug("")
	addr2SvcMap[ip] = svcgrp
}

func deleteAddr2SvcMap(ip string) {
	delete(addr2SvcMap, ip)
	for _, extip := range addr2ExtIpMap[ip] {
		delete(extIp2addrMap, extip.String())
	}
	delete(addr2ExtIpMap, ip)
	delete(addr2ExtIpRefreshMap, ip)
}

// Calling with both graph and cache read-lock held
func group2EndpointREST(cache *groupCache) *api.RESTConversationEndpoint {
	return &api.RESTConversationEndpoint{
		Kind: api.EndpointKindService,
		RESTWorkloadBrief: api.RESTWorkloadBrief{
			ID:           cache.group.Name,
			Name:         cache.group.Name,
			DisplayName:  cache.group.Name,
			ServiceGroup: cache.group.Name,
			Domain:       cache.group.Domain,
			PolicyMode:   cache.group.PolicyMode,
			CapChgMode:   cache.capChgMode,
			State:        api.StateOnline,
		},
	}
}

func group2BriefREST(cache *groupCache, withCap bool) *api.RESTGroupBrief {
	g := &api.RESTGroupBrief{
		Name:            cache.group.Name,
		Comment:         cache.group.Comment,
		Learned:         cache.group.CfgType == share.Learned,
		Reserved:        cache.group.Reserved,
		PolicyMode:      cache.group.PolicyMode,
		ProfileMode:     cache.group.ProfileMode,
		NotScored:       cache.group.NotScored,
		Domain:          cache.group.Domain,
		CreaterDomains:  cache.group.CreaterDomains,
		Kind:            cache.group.Kind,
		PlatformRole:    cache.group.PlatformRole,
		BaselineProfile: cache.group.BaselineProfile,
	}
	if withCap {
		g.CapChgMode = &cache.capChgMode
		g.CapScorable = &cache.capScorable
	}
	g.CfgType, _ = cfgTypeMapping[cache.group.CfgType]
	return g
}

// cacheMutex locked
func group2REST(cache *groupCache, view string, withCap bool) *api.RESTGroup {
	group := cache.group

	r := api.RESTGroup{
		RESTGroupBrief: *group2BriefREST(cache, withCap),
		Criteria:       make([]api.RESTCriteriaEntry, len(group.Criteria)),
		Members:        make([]*api.RESTWorkloadBrief, 0),
		PolicyRules:    make([]uint32, cache.usedByPolicy.Cardinality()),
		ResponseRules:  make([]uint32, cache.usedByResponseRules.Cardinality()),
	}
	for i, crt := range group.Criteria {
		r.Criteria[i] = api.RESTCriteriaEntry{
			Key: crt.Key, Value: crt.Value, Op: crt.Op,
		}
	}

	for m := range cache.members.Iter() {
		if wl, _ := getWorkloadBrief(m.(string), view, access.NewReaderAccessControl()); wl != nil {
			if (view == api.QueryValueViewPod || view == api.QueryValueViewPodOnly) && wl.ShareNSWith != "" {
				continue
			}

			r.Members = append(r.Members, wl)
		}
	}
	if utils.IsGroupNodes(cache.group.Name) && len(r.Members) == 0 {
		for _, hostCache := range hostCacheMap {
			brief := &api.RESTWorkloadBrief{
				ID:           hostCache.host.ID,
				Name:         hostCache.host.Name,
				Service:      api.AllHostGroup,
				ServiceGroup: api.AllHostGroup,
				ScanSummary:  hostCache.scanBrief,
				State:        hostCache.state,
				CapChgMode:   true,
			}
			r.Members = append(r.Members, brief)
		}
	}
	sort.Slice(r.Members, func(i, j int) bool { return r.Members[i].DisplayName < r.Members[j].DisplayName })

	i := 0
	for pol := range cache.usedByPolicy.Iter() {
		r.PolicyRules[i] = pol.(uint32)
		i++
	}

	//keep network rule in priority order for easy analyzing support log
	sort.Slice(r.PolicyRules, func(i, j int) bool {
		if o1, ok1 := policyCache.ruleOrderMap[r.PolicyRules[i]]; ok1 {
			if o2, ok2 := policyCache.ruleOrderMap[r.PolicyRules[j]]; ok2 {
				return o1 < o2
			} else {
				return true
			}
		} else {
			return false
		}
	})
	i = 0
	for pol := range cache.usedByResponseRules.Iter() {
		r.ResponseRules[i] = pol.(uint32)
		i++
	}
	sort.Slice(r.ResponseRules, func(i, j int) bool { return r.ResponseRules[i] < r.ResponseRules[j] })

	return &r
}

func groupDetail2REST(cache *groupCache, view string, withCap bool) *api.RESTGroupDetail {
	group := cache.group

	g := api.RESTGroupDetail{
		RESTGroupBrief: *group2BriefREST(cache, withCap),
		Criteria:       make([]api.RESTCriteriaEntry, len(group.Criteria)),
		Members:        make([]*api.RESTWorkloadBrief, 0),
		PolicyRules:    make([]*api.RESTPolicyRule, 0, cache.usedByPolicy.Cardinality()),
		ResponseRules:  make([]*api.RESTResponseRule, 0, cache.usedByResponseRules.Cardinality()),
	}
	for i, crt := range group.Criteria {
		g.Criteria[i] = api.RESTCriteriaEntry{
			Key: crt.Key, Value: crt.Value, Op: crt.Op,
		}
	}

	for m := range cache.members.Iter() {
		if wl, _ := getWorkloadBrief(m.(string), view, access.NewReaderAccessControl()); wl != nil {
			if (view == api.QueryValueViewPod || view == api.QueryValueViewPodOnly) && wl.ShareNSWith != "" {
				continue
			}

			g.Members = append(g.Members, wl)
		}
	}
	sort.Slice(g.Members, func(i, j int) bool { return g.Members[i].DisplayName < g.Members[j].DisplayName })

	for p := range cache.usedByPolicy.Iter() {
		if r := policyCache.ruleMap[p.(uint32)]; r != nil {
			rule := policyRule2REST(r)
			g.PolicyRules = append(g.PolicyRules, rule)
		}
	}
	sort.Sort(ByRuleOrder(g.PolicyRules))

	for p := range cache.usedByResponseRules.Iter() {
		var resPolicyCache *resPolicyCacheType
		if group.CfgType == share.FederalCfg {
			resPolicyCache = &fedResPolicyCache
		} else {
			resPolicyCache = &localResPolicyCache
		}
		if r := resPolicyCache.ruleMap[p.(uint32)]; r != nil {
			var cacher CacheMethod
			rule := cacher.ResponseRule2REST(r)
			g.ResponseRules = append(g.ResponseRules, rule)
		}
	}
	sort.Sort(ByResponseRuleOrder(g.ResponseRules))

	return &g
}

func initGroupCache(cfgType share.TCfgType, name string) *groupCache {
	return &groupCache{
		group:               &share.CLUSGroup{Name: name, CfgType: cfgType},
		members:             utils.NewSet(),
		svcAddrs:            utils.NewSet(),
		usedByPolicy:        utils.NewSet(),
		usedByResponseRules: utils.NewSet(),
	}
}

func isDummyGroupCache(gc *groupCache) bool {
	return len(gc.group.Criteria) == 0
}

func isGroupProfileExist(name, policyMode string) (bool, string) {
	mode := policyMode
	if _, ok := profileGroups[name]; !ok {
		if strings.HasPrefix(name, api.LearnedGroupPrefix) && // exclude "nodes"
			!strings.HasPrefix(name, api.LearnedSvcGroupPrefix) {
			switch mode {
			case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
			default:
				// invalid mode, use the default mode
				mode = getNewServicePolicyMode()
			}
		}
		return false, mode
	}
	return true, mode
}

func isNeuvectorContainerGroup(group string) bool {
	if dot := strings.LastIndex(group, "."); dot != -1 {
		if group[dot+1:] == localDev.Ctrler.Domain {
			name := group[:dot]
			if name == "nv.neuvector-manager-pod" ||
				name == "nv.neuvector-scanner-pod" ||
				name == "nv.neuvector-controller-pod" ||
				name == "nv.neuvector-enforcer-pod" ||
				name == "nv.neuvector-updater-pod" {
				return true
			}
		}
	}
	return false
}

func groupConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSGroupKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var group share.CLUSGroup
		json.Unmarshal(value, &group)

		// post-3.2.2 enforcer report nv containers to controller, if the controller happens to be pre-3.2.2,
		// for example, in upgrade case, the group will be created. This is to remove the group as we see it.
		if isNeuvectorContainerGroup(group.Name) {
			kv.DeletePolicyByGroup(group.Name)
			kv.DeleteResponseRuleByGroup(group.Name)
			clusHelper.DeleteGroup(group.Name)
			log.WithFields(log.Fields{"group": group.Name}).Info("Delete neuvector group")
			return
		}

		// CRD group cannot change mode but it is scorable
		capChgMode := utils.DoesGroupHavePolicyMode(group.Name) && (group.CfgType == share.Learned || group.Name == api.AllHostGroup)
		capScorable := utils.DoesGroupHavePolicyMode(group.Name)

		cache := initGroupCache(group.CfgType, group.Name)
		cache.group = &group
		cache.capChgMode = capChgMode
		cache.capScorable = capScorable

		cacheMutexLock()
		exist, ok := groupCacheMap[group.Name]
		if ok {
			cache.usedByPolicy = exist.usedByPolicy
			cache.usedByResponseRules = exist.usedByResponseRules
			cache.ingressDMZ = exist.ingressDMZ
			cache.egressDMZ = exist.egressDMZ
		}

		// profile initialization (secondary allocation)
		if ok, mode := isGroupProfileExist(group.Name, group.ProfileMode); !ok {
			// both profiles are bundled together, another option:  group.Learned
			cache.group.ProfileMode = mode
			fedRole := fedMembershipCache.FedRole
			if (group.CfgType != share.FederalCfg || fedRole == api.FedRoleMaster) && group.CfgType != share.GroundCfg {
				// CRD has its own pre-assigned rules
				// For joint clusters, create fed process/file profiles in replaceFedGroups() instead of here
				if isLeader() {
					revs := make([]string, 0, 3)
					preExist := false
					if clusHelper.GetProcessProfile(group.Name) != nil {
						preExist = true // will increase fed rule provision only when the process profile doesn't exist yet
					}
					if cacher.CreateProcessProfile(group.Name, mode, "", group.CfgType) {
						if !preExist && group.CfgType == share.FederalCfg && fedRole == api.FedRoleMaster {
							revs = append(revs, share.FedProcessProfilesType)
						}
					}
					preExist = false
					if p, _ := clusHelper.GetFileMonitorProfile(group.Name); p != nil {
						preExist = true // will increase fed rule provision only when the process profile doesn't exist yet
					}
					if cacher.CreateGroupFileMonitor(group.Name, mode, group.CfgType) {
						if !preExist && group.CfgType == share.FederalCfg && fedRole == api.FedRoleMaster {
							revs = append(revs, share.FedFileMonitorProfilesType)
						}
					}
					if len(revs) > 0 {
						revs = append(revs, share.FedGroupType)
						clusHelper.UpdateFedRulesRevision(revs)
					}
				}
			}
		}

		if isIPServiceGroup(&group) {
			cache.ipsvcInternal = isIPSvcGrpInternal(&group)
			for _, e := range group.Criteria {
				if e.Key == share.CriteriaKeyAddress {
					if e.Value != "<nil>" {
						cache.svcAddrs.Add(e.Value)
					}
				}
			}
			groupCacheMap[group.Name] = cache

			// In case of group config change, remove old stuff
			var adds, dels utils.Set
			if exist != nil {
				adds = cache.svcAddrs.Difference(exist.svcAddrs)
				dels = exist.svcAddrs.Difference(cache.svcAddrs)
			} else {
				adds = cache.svcAddrs
				dels = utils.NewSet()
			}

			for a := range adds.Iter() {
				updateAddr2SvcMap(cache, a.(string))
			}
			for a := range dels.Iter() {
				deleteAddr2SvcMap(a.(string))
			}

			var extipChanged bool
			for a := range cache.svcAddrs.Iter() {
				if addr2ExtIpRefreshMap[a.(string)] {
					extipChanged = true
					break
				}
			}
			//only refresh entire internal subnet when
			//there is address change
			if dels.Cardinality() > 0 || extipChanged {
				refreshInternalIPNet()
			} else if adds.Cardinality() > 0 {
				for a := range adds.Iter() {
					ipnet := &net.IPNet{IP: net.ParseIP(a.(string)), Mask: net.CIDRMask(32, 32)}
					updateInternalIPNet(ipnet, share.CLUSIPAddrScopeGlobal, true)
				}
			}

			//nv.ip.xxx group to join user
			//created group if domain matches
			svcipGroupJoin(cache)
		} else {
			refreshGroupMember(cache)
			groupCacheMap[group.Name] = cache
		}
		if ok := isCreateDlpGroup(&group); ok {
			createDlpGroup(group.Name, group.CfgType)
		}
		if ok := isCreateWafGroup(&group); ok {
			createWafGroup(group.Name, group.CfgType)
		}

		cacheMutexUnlock()

		// If we see a traffic destinated to service IP before service group is created,
		// a workload endpoint with service IP is used. We need to replace it when the group
		// is created.
		// Must do this outside of cacheMutex as it acquires graphMutex
		evhdls.Trigger(EV_GROUP_ADD, name, cache)

		log.WithFields(log.Fields{"group": cache.group}).Debug("Update group cache")

		if cache.usedByPolicy.Cardinality() > 0 {
			scheduleIPPolicyCalculation(false)
		} else if cache.members.Cardinality() > 0 {
			// When a new workload joins and creates new group,
			// need to triger policy recal fast so that the policy
			// for the new workload can be quickly configured

			//nodes has a member whose id is empty string
			if !utils.IsGroupNodes(group.Name) {
				scheduleIPPolicyCalculation(true)
			}
		}

		scheduleDlpRuleCalculation(true)

	case cluster.ClusterNotifyDelete:
		var cache *groupCache
		var ok bool

		cacheMutexLock()
		if cache, ok = groupCacheMap[name]; ok {
			if isIPServiceGroup(cache.group) {
				for ip := range cache.svcAddrs.Iter() {
					deleteAddr2SvcMap(ip.(string))
				}
				if cache.ipsvcInternal {
					refreshInternalIPNet()
				}
			}

			//if cache.group.Learned && cache.members.Cardinality() > 0 {
			if cache.group.CfgType == share.Learned && cache.members.Cardinality() > 0 {
				// This should not happen. If we see this error, needs a way to remedy
				log.WithFields(log.Fields{"group": name}).Error("learned group is not empty")
			}

			delete(groupCacheMap, name)
		}
		cacheMutexUnlock()

		if cache != nil && !isIPSvcGrpHidden(cache) {
			evhdls.Trigger(EV_GROUP_DELETE, name, cache)
		}

		err1 := clusHelper.DeleteProcessProfile(name)
		err2 := clusHelper.DeleteFileMonitor(name)
		if cache != nil && cache.group != nil {
			if isLeader() && cache.group.CfgType == share.FederalCfg && (err1 == nil || err2 == nil) {
				fedRole := fedMembershipCache.FedRole
				if fedRole != api.FedRoleNone {
					// it's not demote/leave/kicked from fed
					clusHelper.UpdateFedRulesRevision([]string{share.FedProcessProfilesType, share.FedFileMonitorProfilesType})
				}
			}
			if cache.group.Kind == share.GroupKindContainer {
				clusHelper.DeleteDlpGroup(name)
				clusHelper.DeleteWafGroup(name)
			}
		}
		clusHelper.DeleteCustomCheckConfig(name)
	}
}

func makeLearnedGroupName(name string) string {
	return fmt.Sprintf("%s%s", api.LearnedGroupPrefix, name)
}

func makeServiceIPGroupName(svc string) string {
	return makeLearnedGroupName(fmt.Sprintf("ip.%s", utils.NormalizeForURL(svc)))
}

func isIPServiceGroup(group *share.CLUSGroup) bool {
	return group.Kind == share.GroupKindIPService
}

func deleteServiceIPGroup(domain, name string, gCfgType share.TCfgType) {
	svc := utils.MakeServiceName(domain, name)
	gname := makeServiceIPGroupName(svc)
	if gCfgType == 0 {
		if cg, _, _ := clusHelper.GetGroup(gname, access.NewAdminAccessControl()); cg != nil {
			gCfgType = cg.CfgType
		}
	}

	// Remove all rules that use the group
	dels := utils.NewSet()
	keeps := make([]*share.CLUSRuleHead, 0)

	crhs := clusHelper.GetPolicyRuleList()
	for _, crh := range crhs {
		if cr, _ := clusHelper.GetPolicyRule(crh.ID); cr != nil {
			//if cr.From == gname || cr.To == gname {
			if (cr.CfgType != share.GroundCfg) && (gname == cr.From || gname == cr.To) {
				// To be deleted if it's not crd policies. crd policies can only be deleted thru k8s
				dels.Add(crh.ID)
			} else {
				keeps = append(keeps, crh)
			}
		}
	}

	// Write updated rules to the cluster
	if dels.Cardinality() > 0 {
		txn := cluster.Transact()
		defer txn.Close()

		clusHelper.PutPolicyRuleListTxn(txn, keeps)
		for id := range dels.Iter() {
			clusHelper.DeletePolicyRuleTxn(txn, id.(uint32))
		}
		if ok, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			return
		} else if !ok {
			log.Error("Atomic write failed")
			return
		}
	}
	//leave delete group related rule outside of lock
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	if gCfgType != share.GroundCfg {
		// crd nv.ip.xxx group can only be deleted thru k8s
		clusHelper.DeleteGroup(gname)
	}
}

func updateAddr2ExtIpMap(addrIP net.IP, extIPs []net.IP) {
	//extlIPs delete and modify, special subnet need refresh
	oextips := addr2ExtIpMap[addrIP.String()]
	if len(extIPs) != len(oextips) || (len(extIPs) != 0 && !reflect.DeepEqual(oextips, extIPs)) {
		addr2ExtIpRefreshMap[addrIP.String()] = true
	} else {
		addr2ExtIpRefreshMap[addrIP.String()] = false
	}
	//delete existing svcip/extip mapping
	for _, extip := range addr2ExtIpMap[addrIP.String()] {
		delete(extIp2addrMap, extip.String())
	}
	delete(addr2ExtIpMap, addrIP.String())

	//install new svcip/extip mapping
	addr2ExtIpMap[addrIP.String()] = make([]net.IP, 0, len(extIPs))
	for _, extip := range extIPs {
		addr2ExtIpMap[addrIP.String()] = append(addr2ExtIpMap[addrIP.String()], extip)
		extIp2addrMap[extip.String()] = addrIP
	}
}

// Create or update the service IP group, combine the IP from the same network
func addToNetworkEPGroup(nep *share.CLUSNetworkEP) *share.CLUSGroup {
	cacheMutexLock()
	nepMap[nep.ID] = nep
	cacheMutexUnlock()

	if !isLeader() {
		return nil
	}

	log.WithFields(log.Fields{"name": nep.Name, "ip": nep.IP, "id": nep.ID}).Debug()

	svc := utils.MakeServiceName("", nep.Name)
	gname := makeServiceIPGroupName(svc)

	// only the lead modify the group synchronously
	accAll := access.NewAdminAccessControl()
	cg, _, _ := clusHelper.GetGroup(gname, accAll)
	if cg == nil {
		cg = &share.CLUSGroup{
			Name:     gname,
			CfgType:  share.Learned,
			Criteria: make([]share.CLUSCriteriaEntry, 0),
			Kind:     share.GroupKindIPService,
			CapIntcp: false,
		}
	}

	// Add to Criteria, remove duplication
	existing := utils.NewSet()
	for _, e := range cg.Criteria {
		if e.Key == share.CriteriaKeyAddress {
			existing.Add(e.Value)
		}
	}

	for _, ip := range nep.IP {
		if !existing.Contains(ip.String()) {
			cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
				Key:   share.CriteriaKeyAddress,
				Value: ip.String(),
				Op:    share.CriteriaOpEqual,
			})
		}
	}

	if err := clusHelper.PutGroup(cg, false); err != nil {
		log.WithFields(log.Fields{"error": err, "group": cg.Name}).Error("")
		return nil
	} else {
		log.WithFields(log.Fields{"group": cg.Name}).Debug("Create/update group")
		return cg
	}
}

func removeFromNetworkEPGroup(nepID string) {
	cacheMutexLock()
	nep, ok := nepMap[nepID]
	delete(nepMap, nepID)
	cacheMutexUnlock()
	if !ok {
		return
	}

	if !isLeader() {
		return
	}

	log.WithFields(log.Fields{"name": nep.Name, "ip": nep.IP, "id": nep.ID}).Debug()

	svc := utils.MakeServiceName("", nep.Name)
	gname := makeServiceIPGroupName(svc)

	// only the lead modify the group synchronously
	accAll := access.NewAdminAccessControl()
	cg, _, _ := clusHelper.GetGroup(gname, accAll)
	if cg == nil {
		return
	}

	// Remove the criteria with matched IP
	var cur int
	for i, e := range cg.Criteria {
		var found bool
		for _, ip := range nep.IP {
			if e.Key == share.CriteriaKeyAddress && e.Value == ip.String() {
				found = true
				break
			}
		}

		if !found {
			cg.Criteria[cur] = cg.Criteria[i]
			cur++
		}
	}

	if cur < len(cg.Criteria) {
		cg.Criteria = cg.Criteria[:cur]
	} else {
		log.WithFields(log.Fields{"group": cg.Name}).Debug("No change group")
		return
	}

	if len(cg.Criteria) == 0 {
		deleteServiceIPGroup("", nep.Name, cg.CfgType)
		log.WithFields(log.Fields{"group": cg.Name}).Debug("Delete group")
	} else {
		if err := clusHelper.PutGroup(cg, false); err != nil {
			log.WithFields(log.Fields{"error": err, "group": cg.Name}).Error("Failed to update group")
		} else {
			log.WithFields(log.Fields{"group": cg.Name}).Debug("Update group")
		}
	}
}

func createServiceIPGroup(r *resource.Service) *share.CLUSGroup {
	// Ignore the service in the same domain/namespace of the controller. If other container services
	// are deployed in the same domain/namespace, we won't be able to see it.
	if localDev.Ctrler.Domain != "" && localDev.Ctrler.Domain == r.Domain {
		log.WithFields(log.Fields{"domain": r.Domain}).Debug("Ignore service in self's domain")
		return nil
	}
	// Ignore the service with label key contains 'neuvector'. This is probably from docker swarm
	for k, v := range r.Labels {
		if strings.Contains(strings.ToLower(k), "neuvector") {
			log.WithFields(log.Fields{"key": k, "value": v}).Debug("Ignore service with neuvector label")
			return nil
		}
	}

	// update svcip/extip mapping for both lead and non-lead,
	// only lead controller continue to create svcip group
	cacheMutexLock()
	for _, ip := range r.IPs {
		updateAddr2ExtIpMap(ip, r.ExternalIPs)
	}
	cacheMutexUnlock()

	if !isLeader() {
		return nil
	}

	log.WithFields(log.Fields{"domain": r.Domain, "name": r.Name, "ip": r.IPs, "selector": r.Selector}).Debug()

	svc := utils.MakeServiceName(r.Domain, r.Name)

	// !!! Update isIPServiceGroup() if criteria changes.
	var criteria []share.CLUSCriteriaEntry
	for _, ip := range r.IPs {
		if ip == nil {
			continue
		}
		criteria = append(criteria, share.CLUSCriteriaEntry{
			Key:   share.CriteriaKeyAddress,
			Value: ip.String(),
			Op:    share.CriteriaOpEqual,
		})
	}
	if r.Domain != "" {
		criteria = append(criteria, share.CLUSCriteriaEntry{
			Key:   share.CriteriaKeyDomain,
			Value: r.Domain,
			Op:    share.CriteriaOpEqual,
		})
	}
	if r.Selector != nil && len(r.Selector) > 0 {
		for k, v := range r.Selector {
			// This criteria is just for information/flag purpose right now
			// Cannot match to find the correponding workloads yet
			criteria = append(criteria, share.CLUSCriteriaEntry{
				Key:   share.CriteriaKeyLabel,
				Value: k + "=" + v,
				Op:    share.CriteriaOpEqual,
			})
		}
	}

	cg := &share.CLUSGroup{
		Name:     makeServiceIPGroupName(svc),
		CfgType:  share.Learned,
		Criteria: criteria,
		Domain:   r.Domain,
		Kind:     share.GroupKindIPService,
		CapIntcp: false,
	}
	if g, _, _ := clusHelper.GetGroup(cg.Name, access.NewAdminAccessControl()); g != nil {
		// if there is an existing nv.ip.xxx group, do not change its CfgType
		cg.CfgType = g.CfgType
	}

	// Not to grab lock. In a busy system this can timeout. It's unlikely to run into race condition.
	/*
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
			return nil
		}
		defer clusHelper.ReleaseLock(lock)
	*/

	// Update the group no matter it exists or not
	if err := clusHelper.PutGroup(cg, false); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return nil
	}

	log.WithFields(log.Fields{"group": cg.Name}).Debug("Create group")

	return cg
}

func createLearnedGroup(wlc *workloadCache, policyMode, baseline string, notScored bool, comment string, acc *access.AccessControl) error {
	var criteria []share.CLUSCriteriaEntry

	criteria = append(criteria, share.CLUSCriteriaEntry{
		Key:   share.CriteriaKeyService,
		Value: wlc.workload.Service,
		Op:    share.CriteriaOpEqual,
	})
	if wlc.workload.Domain != "" {
		criteria = append(criteria, share.CLUSCriteriaEntry{
			Key:   share.CriteriaKeyDomain,
			Value: wlc.workload.Domain,
			Op:    share.CriteriaOpEqual,
		})
	}

	cg := &share.CLUSGroup{
		Name:            wlc.learnedGroupName,
		Comment:         comment,
		CfgType:         share.Learned,
		Criteria:        criteria,
		PolicyMode:      policyMode,
		ProfileMode:     policyMode,
		NotScored:       notScored,
		Domain:          wlc.workload.Domain,
		Kind:            share.GroupKindContainer,
		PlatformRole:    wlc.workload.PlatformRole,
		CapIntcp:        wlc.workload.CapIntcp,
		BaselineProfile: baseline,
	}

	if !acc.Authorize(cg, nil) {
		return common.ErrObjectAccessDenied
	}

	// Write group definition into key-value store. Although we checked the cache,
	// to avoid lock, we still need make sure group doesn't exist.
	if err := clusHelper.PutGroup(cg, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}

	//	cacher.CreateProcessProfile(cg.Name, cg.PolicyMode, cg.CfgType)
	//	cacher.CreateGroupFileMonitor(cg.Name, cg.PolicyMode, cg.CfgType)

	log.WithFields(log.Fields{"group": cg.Name}).Debug("Create group")
	return nil
}

// This is the path to allow user to create a service and its process/file/network profile before
// starting the containers in protect mode.
func (m CacheMethod) CreateService(svc *api.RESTServiceConfig, acc *access.AccessControl) error {
	svcName := utils.MakeServiceName(svc.Domain, svc.Name)

	var comment string
	if svc.Comment != nil {
		comment = *svc.Comment
	}

	var policyMode string
	if svc.PolicyMode == nil || *svc.PolicyMode == "" {
		policyMode = getNewServicePolicyMode()
	} else {
		policyMode = *svc.PolicyMode
	}

	var baseline string
	if svc.BaselineProfile == nil || *svc.BaselineProfile == "" {
		baseline = getNewServiceProfileBaseline() // default
	} else {
		baseline = *svc.BaselineProfile
	}

	var notScored bool
	if svc.NotScored != nil {
		notScored = *svc.NotScored
	}

	wlc := &workloadCache{
		learnedGroupName: makeLearnedGroupName(utils.NormalizeForURL(svcName)),
		workload: &share.CLUSWorkload{
			Domain:   svc.Domain,
			Service:  svcName,
			CapIntcp: true,
		},
	}

	cacheMutexLock()
	defer cacheMutexUnlock()

	if _, ok := groupCacheMap[wlc.learnedGroupName]; ok {
		return common.ErrObjectExists
	}

	return createLearnedGroup(wlc, policyMode, baseline, notScored, comment, acc)
}

func groupRemoveEvent(ev share.TLogEvent, group string) {
	clog := share.CLUSEventLog{
		Event:      ev,
		GroupName:  group,
		ReportedAt: time.Now().UTC(),
	}
	clog.Msg = fmt.Sprintf("Auto remove unused group: %s and related network/response rules.\n", group)
	cctx.EvQueue.Append(&clog)
}

const groupsPruneDelay = time.Duration(time.Minute * 10)

type groupRemovalEvent struct {
	groupname string
}

func (p *groupRemovalEvent) Expire() {
	cacheMutexLock()
	if cache, ok := groupCacheMap[p.groupname]; ok {
		if cache.members.Cardinality() != 0 {
			//we need to set timerTask to empty string
			//so that in future this group can be scheduled
			//for auto-removal when condition allows
			cache.timerTask = ""
			cacheMutexUnlock()
			return
		}
		//to deal with leadership change
		//always reset task whether group
		//is really deleted or not
		cache.timerTask = ""
		deleted := deleteGroupFromCluster(p.groupname)
		cacheMutexUnlock()

		//leave delete policy by group outside any lock
		//so that not to hold lock too long
		if deleted {
			kv.DeletePolicyByGroup(p.groupname)
			kv.DeleteResponseRuleByGroup(p.groupname)
			groupRemoveEvent(share.CLUSEvGroupAutoRemove, p.groupname)
		}
	} else {
		cacheMutexUnlock()
	}
}

func deleteGroupFromCluster(groupname string) bool {
	if isLeader() == false {
		return false
	}
	log.WithFields(log.Fields{"group": groupname}).Info("")

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	accAll := access.NewAdminAccessControl()
	cg, _, _ := clusHelper.GetGroup(groupname, accAll)
	if cg == nil {
		log.WithFields(log.Fields{"group": groupname}).Error("Group doesn't exist in kv")
		if _, ok := groupCacheMap[groupname]; ok {
			delete(groupCacheMap, groupname)
		}
	} else {
		if err := clusHelper.DeleteGroup(groupname); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			return false
		}
	}
	return true
}

// Protected by cacheMutexLock
func scheduleGroupRemoval(cache *groupCache) {
	//Reserved group and CRD group cannot be deleted
	if cache.group.Reserved {
		//log.WithFields(log.Fields{"group": cache.group.Name}).Info("Reserved group cannot be removed")
		return
	}
	//Service IP group cannot be deleted
	if cache.group.Kind == share.GroupKindIPService || cache.group.Kind == share.GroupKindAddress {
		//log.WithFields(log.Fields{"group": cache.group.Name}).Info("Service IP or Address group cannot be auto deleted")
		return
	}
	//Only learned group can be auto deleted
	if cache.group.CfgType != share.Learned {
		//log.WithFields(log.Fields{"group": cache.group.Name}).Info("Only learned group can be auto removed")
		return
	}
	//If a group is referred by a CRD rule, it cannot be deleted
	for pol := range cache.usedByPolicy.Iter() {
		idx := pol.(uint32)
		if idx >= share.PolicyGroundRuleIDBase {
			//log.WithFields(log.Fields{"name": cache.group.Name, "crdruleid": idx}).Info("Group referenced by SecurityRule cannot be deleted")
			return
		}
	}

	if cache.timerTask != "" {
		//log.WithFields(log.Fields{"group": cache.group.Name}).Info("Group removal already scheduled")
		return
	}

	unusedGrpAge := time.Duration(cacher.GetUnusedGroupAging())
	groupRemovalDelay := time.Duration(time.Hour * unusedGrpAge)

	task := &groupRemovalEvent{
		groupname: cache.group.Name,
	}
	cache.timerTask, _ = cctx.TimerWheel.AddTask(task, groupRemovalDelay)
	if cache.timerTask == "" {
		log.Error("Fail to insert timer")
	}
	log.WithFields(
		log.Fields{
			"group":             cache.group.Name,
			"groupRemovalDelay": groupRemovalDelay,
			"timertask":         cache.timerTask,
		}).Info("Timertask scheduled")
}

type groupPruneEvent struct{}

func (p *groupPruneEvent) Expire() {
	//by this time auto removal configuration
	//could be changed
	if cacher.GetUnusedGroupAging() == 0 {
		return
	}
	cacheMutexLock()
	for _, cache := range groupCacheMap {
		if cache.members.Cardinality() == 0 {
			scheduleGroupRemoval(cache)
		}
	}
	cacheMutexUnlock()
}

func SchedulePruneGroups() {
	if cacher.GetUnusedGroupAging() == 0 {
		return
	}
	task := &groupPruneEvent{}
	timertask, _ := cctx.TimerWheel.AddTask(task, groupsPruneDelay)
	log.WithFields(log.Fields{"timertask": timertask}).Info("group prune timertask scheduled")
	if timertask == "" {
		log.Error("Fail to insert timer")
	}
}

func groupWorkloadLeave(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	var memberLeave bool
	bHasGroupProfile := utils.HasGroupProfiles(wlc.learnedGroupName)
	dptCustomGrps := utils.NewSet()

	cacheMutexLock()
	for _, cache := range groupCacheMap {
		if cache.members.Contains(wl.ID) {
			wlc.groups.Remove(cache.group.Name)
			cache.members.Remove(wl.ID)
			if bHasGroupProfile && utils.IsCustomProfileGroup(cache.group.Name) {
				dptCustomGrps.Add(cache.group.Name)
			}
			memberLeave = true
			log.WithFields(log.Fields{"group": cache.group.Name}).Debug("Leave group")
			if cache.members.Cardinality() == 0 && cacher.GetUnusedGroupAging() != 0 {
				scheduleGroupRemoval(cache)
			}
		}
	}

	if memberLeave {
		scheduleDlpRuleCalculation(true)
		//container used fqdn related policy
		//it needs to inform dp that a fqdn
		//is no longer needed
		scheduleIPPolicyCalculation(false)
	}
	cacheMutexUnlock()

	// warning: avoid cacheMutexLock() before calling below function
	if memberLeave && bHasGroupProfile {
		dispatchHelper.WorkloadLeave(wlc.workload.HostID, wlc.learnedGroupName, id, dptCustomGrps, isLeader())
	}
}

func hostWorkloadStart(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	cacheMutexLock()
	defer cacheMutexUnlock()

	if host, ok := hostCacheMap[wl.HostID]; ok {
		if localDev.Host.Platform == share.PlatformKubernetes {
			if wlc.workload.ShareNetNS == "" {
				host.runningPods.Add(wl.ID)
			}
		} else {
			host.runningPods.Add(wl.ID)
		}
		host.runningCntrs.Add(wl.ID)
		host.workloads.Add(wl.ID)
	}
}

func hostWorkloadStop(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	cacheMutexLock()
	defer cacheMutexUnlock()

	if host, ok := hostCacheMap[wl.HostID]; ok {
		host.runningPods.Remove(wl.ID)
		host.runningCntrs.Remove(wl.ID)
	}
}

func hostWorkloadDelete(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	cacheMutexLock()
	defer cacheMutexUnlock()

	if host, ok := hostCacheMap[wl.HostID]; ok {
		host.runningPods.Remove(wl.ID)
		host.runningCntrs.Remove(wl.ID)
		host.workloads.Remove(wl.ID)
	}
}

func groupWorkloadJoin(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	var memberUpdated bool
	bHasGroupProfile := utils.HasGroupProfiles(wlc.learnedGroupName)
	dptCustomGrpAdds := utils.NewSet()

	cacheMutexLock()

	// TODO: multi-controller
	// Normally, we are first notified with the new workload, create group then handle group
	// creation; in multi-controller case, when the new controller joins the cluster, the
	// order of cluster watch update for workload and group is not guaranteed.
	// Would it cause issue?
	// Join and create learned group.
	if cache, ok := groupCacheMap[wlc.learnedGroupName]; !ok || isDummyGroupCache(cache) {
		if isLeader() {
			if bHasGroupProfile {
				createLearnedGroup(wlc, getNewServicePolicyMode(), getNewServiceProfileBaseline(), false, "", access.NewAdminAccessControl())
				if localDev.Host.Platform == share.PlatformKubernetes {
					updateK8sPodEvent(wlc.learnedGroupName, wlc.podName, wlc.workload.Domain)
				}
			}
			// Members is calculated when group change is handled
			// Service address is updated when group change is handled. It cannot be written
			// into the cluster as service IP cannot be ported to other systems.
		}
	} else {
		if !cache.members.Contains(wl.ID) {
			wlc.groups.Add(wlc.learnedGroupName)
			cache.members.Add(wl.ID)
			memberUpdated = true
			log.WithFields(log.Fields{"group": wlc.learnedGroupName}).Debug("Join group")
		}
	}

	// Join user defined group
	for _, cache := range groupCacheMap {
		if cache.group.CfgType == share.Learned {
			continue
		}

		if share.IsGroupMember(cache.group, wlc.workload, getDomainData(wlc.workload.Domain)) {
			if !cache.members.Contains(wl.ID) {
				wlc.groups.Add(cache.group.Name)
				cache.members.Add(wl.ID)
				memberUpdated = true
				log.WithFields(log.Fields{"group": cache.group.Name}).Debug("Join group")
			}

			if bHasGroupProfile {
				dptCustomGrpAdds.Add(cache.group.Name)
			}
		}
	}

	if memberUpdated {
		scheduleIPPolicyCalculation(true)
		scheduleDlpRuleCalculation(true)
	}

	cacheMutexUnlock()

	// warning: avoid cacheMutexLock() before calling below function
	if bHasGroupProfile {
		if localDev.Host.Platform == share.PlatformKubernetes {
			if !strings.HasPrefix(wlc.workload.Name, "k8s_POD") { // ignore POD
				cacheMutexLock()
				updateK8sPodEvent(wlc.learnedGroupName, wlc.podName, wlc.workload.Domain)
				cacheMutexUnlock()
			}
		}
		dispatchHelper.WorkloadJoin(wlc.workload.HostID, wlc.learnedGroupName, id, dptCustomGrpAdds, isLeader())
	}
}

func svcipGroupJoin(svcipcache *groupCache) {
	//for openshift platform and learned nv.ip.xxx
	if policyApplyIngress || svcipcache.group.CfgType != share.Learned {
		return
	}
	// Join user defined group
	for _, cache := range groupCacheMap {
		if cache.group.CfgType == share.Learned {
			continue
		}

		if share.IsSvcIpGroupMember(cache.group, svcipcache.group) {
			if _, ok := grpSvcIpByDomainMap[cache.group.Name]; !ok {
				grpSvcIpByDomainMap[cache.group.Name] = utils.NewSet()
			}
			grpSvcIpByDomainMap[cache.group.Name].Add(svcipcache.group.Name)
			svcipcache.usedByPolicy = svcipcache.usedByPolicy.Union(cache.usedByPolicy)
			log.WithFields(
				log.Fields{"svcipgroup": svcipcache.group.Name,
					"usergroup": cache.group.Name,
				}).Debug("Svc ip group join group")
		}
	}
}

func refreshGroupMember(cache *groupCache) {
	// Remove group from it's members' group list
	for m := range cache.members.Iter() {
		if wlc, ok := wlCacheMap[m.(string)]; ok {
			wlc.groups.Remove(cache.group.Name)
		}
	}

	cache.members.Clear()

	// special and only member for nodes
	if cache.group.Kind == share.GroupKindNode {
		cache.members.Add("") // for all nodes
		return
	}

	if cache.group.Kind != share.GroupKindContainer {
		return
	}

	// for openshift platform, add nv.ip.xxx to group if domain matches
	if !policyApplyIngress && cache.group.CfgType != share.Learned {
		//remove existing grp->nv.ip.xxx mapping
		if _, ok := grpSvcIpByDomainMap[cache.group.Name]; ok {
			delete(grpSvcIpByDomainMap, cache.group.Name)
		}
		// check all nv.ip.xxx svc group
		for _, svcipcache := range groupCacheMap {
			if svcipcache.group.Kind != share.GroupKindIPService ||
				svcipcache.group.CfgType != share.Learned {
				continue
			}
			if share.IsSvcIpGroupMember(cache.group, svcipcache.group) {
				if _, ok := grpSvcIpByDomainMap[cache.group.Name]; !ok {
					grpSvcIpByDomainMap[cache.group.Name] = utils.NewSet()
				}
				grpSvcIpByDomainMap[cache.group.Name].Add(svcipcache.group.Name)
				svcipcache.usedByPolicy = svcipcache.usedByPolicy.Union(cache.usedByPolicy)
				log.WithFields(
					log.Fields{"svcipgroup": svcipcache.group.Name,
						"usergroup": cache.group.Name,
					}).Debug("Group add svc ip group member")
			}
		}
	}

	bHasCustomGroupProfile := utils.IsCustomProfileGroup(cache.group.Name)
	dptLearnedGrpAdds := utils.NewSet()
	// For every workload, re-calculate its membership
	for _, wlc := range wlCacheMap {
		if !wlc.workload.Running {
			continue
		}

		if share.IsGroupMember(cache.group, wlc.workload, getDomainData(wlc.workload.Domain)) {
			cache.members.Add(wlc.workload.ID)
			wlc.groups.Add(cache.group.Name)

			if cache.group.CfgType == share.Learned && common.OEMIgnoreWorkload(wlc.workload) {
				cache.oemHide = true
			}

			// handle workloads which have the profiles
			if bHasCustomGroupProfile && utils.HasGroupProfiles(wlc.learnedGroupName) {
				dptLearnedGrpAdds.Add(wlc.learnedGroupName)
			}
		}
	}

	if bHasCustomGroupProfile {
		dispatchHelper.CustomGroupUpdate(cache.group.Name, dptLearnedGrpAdds, isLeader())
	}
}

// This function is used to mitigate the case when old enforcer cannot derive the correct pod service group,
// and the old controller cannot create the correct group when the new enforcer joins.
// See the caller for more info.
func refreshLearnedGroupMembership() {
	var notGroupedPods []*workloadCache

	cacheMutexRLock()
	for _, wlc := range wlCacheMap {
		if wlc.learnedGroupName == "" {
			continue
		}

		if _, ok := groupCacheMap[wlc.learnedGroupName]; !ok {
			notGroupedPods = append(notGroupedPods, wlc)
		}
	}
	cacheMutexRUnlock()

	for _, wlc := range notGroupedPods {
		groupWorkloadJoin(wlc.workload.ID, wlc)
	}
}

func getGroupWithoutLock(name string) *share.CLUSGroup {
	if cache, ok := groupCacheMap[name]; ok {
		return cache.group
	}
	return nil
}

func (m CacheMethod) DoesGroupExist(name string, acc *access.AccessControl) (bool, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			return false, err
		}
		if cache.oemHide {
			return false, common.ErrObjectNotFound
		}
		return true, nil
	}
	return false, common.ErrObjectNotFound
}

func (m CacheMethod) GetGroupCount(scope string, acc *access.AccessControl) int {
	var countLocal, countFed bool
	if scope == share.ScopeLocal {
		countLocal = true
	} else if scope == share.ScopeFed {
		countFed = true
	} else if scope == share.ScopeAll {
		countFed = true
		countLocal = true
	} else {
		return 0
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	var count int
	for _, cache := range groupCacheMap {
		if err := authorizeGroup(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		if (cache.group.CfgType == share.FederalCfg && countFed) || cache.group.Name == api.LearnedExternal ||
			(cache.group.CfgType != share.FederalCfg && countLocal) {
			count++
		}
	}
	return count
}

func getGroupCache(name string) *groupCache {
	if cache, ok := groupCacheMap[name]; ok {
		return cache
	}

	return nil
}

func (m CacheMethod) GetGroupBrief(name string, withCap bool, acc *access.AccessControl) (*api.RESTGroupBrief, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			return nil, err
		}
		return group2BriefREST(cache, withCap), nil
	}

	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetGroup(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroup, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			return nil, err
		}
		return group2REST(cache, view, withCap), nil
	}

	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetGroupDetail(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTGroupDetail, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			return nil, err
		}
		return groupDetail2REST(cache, view, withCap), nil
	}

	return nil, common.ErrObjectNotFound
}

// notice: external, nodes are also included in return when scope=fed
func (m CacheMethod) GetAllGroups(scope, view string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroup {
	var getLocal, getFed bool
	var localGrpsCount, fedGrpsCount int
	if scope == share.ScopeLocal {
		getLocal = true
	} else if scope == share.ScopeFed {
		getFed = true
		fedGrpsCount += 2
	} else if scope == share.ScopeAll {
		getLocal = true
		getFed = true
	} else {
		return nil
	}

	cacheMutexRLock()
	for _, cache := range groupCacheMap {
		if getLocal && cache.group.CfgType != share.FederalCfg {
			if !cache.oemHide {
				localGrpsCount++
			}
		}
		if getFed && (cache.group.CfgType == share.FederalCfg || cache.group.Name == api.LearnedExternal) {
			if !cache.oemHide {
				fedGrpsCount++
			}
		}
	}
	localGroups := make([]*api.RESTGroup, 0, localGrpsCount)
	fedGroups := make([]*api.RESTGroup, 0, fedGrpsCount)

	for _, cache := range groupCacheMap {
		if err := authorizeGroup(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		if getLocal && cache.group.CfgType != share.FederalCfg {
			localGroups = append(localGroups, group2REST(cache, view, withCap))
		}
		if getFed && (cache.group.CfgType == share.FederalCfg || cache.group.Name == api.LearnedExternal) {
			if cache.group.CfgType == share.FederalCfg {
				fedGroups = append(fedGroups, group2REST(cache, view, withCap))
			} else {
				if scope == share.ScopeFed {
					fedGroups = append(fedGroups, group2REST(cache, view, withCap))
				}
			}
		}
	}
	cacheMutexRUnlock()

	groups := make([][]*api.RESTGroup, 0, 2)
	if len(fedGroups) > 0 {
		groups = append(groups, fedGroups)
	}
	if len(localGroups) > 0 {
		groups = append(groups, localGroups)
	}

	return groups
}

// notice: external, nodes are also included in return when scope=fed
func (m CacheMethod) GetAllGroupsBrief(scope string, withCap bool, acc *access.AccessControl) [][]*api.RESTGroupBrief {
	var getLocal, getFed bool
	var localGrpsCount, fedGrpsCount int
	if scope == share.ScopeLocal {
		getLocal = true
	} else if scope == share.ScopeFed {
		getFed = true
		fedGrpsCount += 2
	} else if scope == share.ScopeAll {
		getLocal = true
		getFed = true
	} else {
		return nil
	}

	cacheMutexRLock()
	for _, cache := range groupCacheMap {
		if getLocal && cache.group.CfgType != share.FederalCfg {
			if !cache.oemHide {
				localGrpsCount++
			}
		}
		if getFed && (cache.group.CfgType == share.FederalCfg || cache.group.Name == api.LearnedExternal) {
			if !cache.oemHide {
				fedGrpsCount++
			}
		}
	}
	localGroups := make([]*api.RESTGroupBrief, 0, localGrpsCount)
	fedGroups := make([]*api.RESTGroupBrief, 0, fedGrpsCount)

	for _, cache := range groupCacheMap {
		if err := authorizeGroup(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		if getLocal && cache.group.CfgType != share.FederalCfg {
			localGroups = append(localGroups, group2BriefREST(cache, withCap))
		}
		if getFed && (cache.group.CfgType == share.FederalCfg || cache.group.Name == api.LearnedExternal) {
			if cache.group.CfgType == share.FederalCfg {
				fedGroups = append(fedGroups, group2BriefREST(cache, withCap))
			} else {
				if scope == share.ScopeFed {
					fedGroups = append(fedGroups, group2BriefREST(cache, withCap))
				}
			}
		}
	}
	cacheMutexRUnlock()

	groups := make([][]*api.RESTGroupBrief, 0, 2)
	if len(fedGroups) > 0 {
		groups = append(groups, fedGroups)
	}
	if len(localGroups) > 0 {
		groups = append(groups, localGroups)
	}

	return groups
}

// caller owns cacheMutexRLock & has readAll right
func (m CacheMethod) GetFedGroupsCache() []*share.CLUSGroup {
	var count int
	for _, cache := range groupCacheMap {
		if cache.group.CfgType == share.FederalCfg {
			count++
		}
	}
	groups := make([]*share.CLUSGroup, 0, count)
	for _, cache := range groupCacheMap {
		if cache.group.CfgType == share.FederalCfg && strings.HasPrefix(cache.group.Name, api.FederalGroupPrefix) {
			groups = append(groups, cache.group)
		}
	}

	return groups
}

func (m CacheMethod) GetGroupCache(name string, acc *access.AccessControl) (*share.CLUSGroup, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cache, ok := groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			return nil, err
		}
		return cache.group, nil
	}

	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) DeleteGroupCache(name string, acc *access.AccessControl) error {
	var cache *groupCache
	var ok bool

	cacheMutexLock()
	if cache, ok = groupCacheMap[name]; ok {
		if err := authorizeGroup(cache, acc); err != nil {
			cacheMutexUnlock()
			return err
		}
		delete(groupCacheMap, name)
	}
	cacheMutexUnlock()
	//delete group related policy
	clusHelper.DeleteProcessProfile(name)
	clusHelper.DeleteFileMonitor(name)
	if cache != nil && cache.group != nil {
		if cache.group.Kind == share.GroupKindContainer {
			clusHelper.DeleteDlpGroup(name)
			clusHelper.DeleteWafGroup(name)
		}
	}
	clusHelper.DeleteCustomCheckConfig(name)
	return nil
}

func (m CacheMethod) GetFedGroupNames(acc *access.AccessControl) utils.Set {
	groups := utils.NewSet()

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	for _, cache := range groupCacheMap {
		if cache.group.CfgType == share.FederalCfg && strings.HasPrefix(cache.group.Name, api.FederalGroupPrefix) {
			groups.Add(cache.group.Name)
		}
	}

	return groups
}

func (m CacheMethod) GetServiceCount(acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	var count int
	for _, cache := range groupCacheMap {
		if err := authorizeService(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		count++
	}
	return count
}

func (m CacheMethod) GetAllServiceCount(acc *access.AccessControl) int {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	var count int
	for _, cache := range groupCacheMap {
		if err := authorizeService(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		count++
	}
	return count
}

type ByRuleOrder []*api.RESTPolicyRule

func (p ByRuleOrder) Len() int {
	return len(p)
}

func (p ByRuleOrder) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p ByRuleOrder) Less(i, j int) bool {
	if o1, ok1 := policyCache.ruleOrderMap[p[i].ID]; ok1 {
		if o2, ok2 := policyCache.ruleOrderMap[p[j].ID]; ok2 {
			return o1 < o2
		} else {
			return true
		}
	} else {
		return false
	}
}

type ByResponseRuleOrder []*api.RESTResponseRule

func (p ByResponseRuleOrder) Len() int {
	return len(p)
}

func (p ByResponseRuleOrder) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p ByResponseRuleOrder) Less(i, j int) bool {
	if o1, ok1 := localResPolicyCache.ruleOrderMap[p[i].ID]; ok1 {
		if o2, ok2 := localResPolicyCache.ruleOrderMap[p[j].ID]; ok2 {
			return o1 < o2
		} else {
			return true
		}
	} else {
		return false
	}
}

func group2Service(gc *groupCache, view string, withCap bool) *api.RESTService {
	idx := len(api.LearnedGroupPrefix)
	sv := api.RESTService{
		Name:            gc.group.Name[idx:],
		PolicyMode:      gc.group.PolicyMode,
		ProfileMode:     gc.group.ProfileMode,
		NotScored:       gc.group.NotScored,
		Domain:          gc.group.Domain,
		PlatformRole:    gc.group.PlatformRole,
		BaselineProfile: gc.group.BaselineProfile,
	}
	if withCap {
		sv.CapChgMode = &gc.capChgMode
		sv.CapScorable = &gc.capScorable
	}

	for m := range gc.members.Iter() {
		n := m.(string)
		if wlGraph.Attr(n, graphLink, api.LearnedExternal) != nil || wlGraph.Attr(n, graphLink, api.EndpointIngress) != nil {
			sv.EgressExposure = true
			break
		}
	}
	for m := range gc.members.Iter() {
		n := m.(string)
		if wlGraph.Attr(api.LearnedExternal, graphLink, n) != nil || wlGraph.Attr(api.EndpointIngress, graphLink, n) != nil {
			sv.IngressExposure = true
			break
		}
	}

	sv.Members = make([]*api.RESTWorkloadBrief, 0, gc.members.Cardinality())
	for m := range gc.members.Iter() {
		if wl, _ := getWorkloadBrief(m.(string), view, access.NewReaderAccessControl()); wl != nil {
			if (view == api.QueryValueViewPod || view == api.QueryValueViewPodOnly) && wl.ShareNSWith != "" {
				continue
			}

			sv.Members = append(sv.Members, wl)
		}
	}
	sort.Slice(sv.Members, func(i, j int) bool { return sv.Members[i].DisplayName < sv.Members[j].DisplayName })

	sv.PolicyRules = make([]*api.RESTPolicyRule, 0, gc.usedByPolicy.Cardinality())
	for p := range gc.usedByPolicy.Iter() {
		if r := policyCache.ruleMap[p.(uint32)]; r != nil {
			rule := policyRule2REST(r)
			sv.PolicyRules = append(sv.PolicyRules, rule)
		}
	}
	sort.Sort(ByRuleOrder(sv.PolicyRules))

	sv.ResponseRules = make([]*api.RESTResponseRule, 0, gc.usedByResponseRules.Cardinality())
	for p := range gc.usedByResponseRules.Iter() {
		var resPolicyCache *resPolicyCacheType
		if gc.group.CfgType == share.FederalCfg {
			resPolicyCache = &fedResPolicyCache
		} else {
			resPolicyCache = &localResPolicyCache
		}
		if r := resPolicyCache.ruleMap[p.(uint32)]; r != nil {
			var cacher CacheMethod
			rule := cacher.ResponseRule2REST(r)
			sv.ResponseRules = append(sv.ResponseRules, rule)
		}
	}
	sort.Sort(ByResponseRuleOrder(sv.ResponseRules))
	return &sv
}

func (m CacheMethod) IsGroupPolicyModeChangeable(name string) bool {
	if cache, ok := groupCacheMap[name]; ok {
		return cache.capChgMode
	}
	return false
}

func (m CacheMethod) GetAllServices(view string, withCap bool, acc *access.AccessControl) []*api.RESTService {
	// NOTE: group2Service() access graph to calculate external exposure
	graphMutexLock()
	defer graphMutexUnlock()
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	services := make([]*api.RESTService, 0)
	for _, cache := range groupCacheMap {
		if err := authorizeService(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}
		services = append(services, group2Service(cache, view, withCap))
	}

	return services
}

func (m CacheMethod) GetService(name string, view string, withCap bool, acc *access.AccessControl) (*api.RESTService, error) {
	// NOTE: group2Service() access graph to calculate external exposure
	graphMutexLock()
	defer graphMutexUnlock()
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	gname := api.LearnedGroupPrefix + name
	if cache, ok := groupCacheMap[gname]; ok {
		if err := authorizeService(cache, acc); err != nil {
			return nil, err
		}
		return group2Service(cache, view, withCap), nil
	}
	return nil, common.ErrObjectNotFound
}

func isNeuvectorContainerName(name string) bool {
	if matched, err := regexp.MatchString(`^neuvector-(controller|enforcer|manager|allinone|updater|scanner)-pod`, name); err == nil {
		return matched
	}
	return false
}

func domainChange(domain share.CLUSDomain) {
	log.WithFields(log.Fields{"domain": domain}).Debug()

	var groups []*groupCache

	cacheMutexLock()
	defer cacheMutexUnlock()

	for _, cache := range groupCacheMap {
		if utils.IsCustomProfileGroup(cache.group.Name) {
			for _, crt := range cache.group.Criteria {
				if strings.HasPrefix(crt.Key, "ns:") {
					groups = append(groups, cache)
					break
				}
			}
		}
	}

	// For every workload, re-calculate its membership
	dptLearnedGrpAdds := utils.NewSet()
	for _, cache := range groups {
		cache.members.Clear() // reset
		for _, wlc := range wlCacheMap {
			if !wlc.workload.Running {
				continue
			}

			if share.IsGroupMember(cache.group, wlc.workload, getDomainData(wlc.workload.Domain)) {
				cache.members.Add(wlc.workload.ID)
				wlc.groups.Add(cache.group.Name)
				dptLearnedGrpAdds.Add(wlc.learnedGroupName)
			} else {
				wlc.groups.Remove(cache.group.Name)
			}
		}
		dispatchHelper.CustomGroupUpdate(cache.group.Name, dptLearnedGrpAdds, isLeader())
	}
}
