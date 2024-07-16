package cache

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type eventDesc struct {
	id                      string
	event                   string
	name                    string
	groupName               string
	level                   string
	proc                    string
	cve_critical            int
	cve_high                int
	cve_med                 int
	cve_critical_fixed_info []scanUtils.FixedVulInfo
	cve_high_fixed_info     []scanUtils.FixedVulInfo
	items                   []string
	vuls                    utils.Set
	arg                     interface{}
	noQuar                  bool
}

type actionDesc struct {
	id       uint32
	comment  string
	actions  []string
	webhooks []string
}

type responseActionFunc struct {
	logFunc     func(arg interface{})
	webhookFunc func(act *actionDesc, arg interface{})
}

var responseFuncs map[string]responseActionFunc = map[string]responseActionFunc{
	share.EventActivity:   responseActionFunc{logActivity, webhookActivity},
	share.EventEvent:      responseActionFunc{logEvent, webhookEvent},
	share.EventCVEReport:  responseActionFunc{logAudit, webhookAudit},
	share.EventThreat:     responseActionFunc{logThreat, webhookThreat},
	share.EventIncident:   responseActionFunc{logIncident, webhookIncident},
	share.EventViolation:  responseActionFunc{logViolation, webhookViolation},
	share.EventCompliance: responseActionFunc{logAudit, webhookAudit},
	share.EventAdmCtrl:    responseActionFunc{logAudit, webhookAudit},
	share.EventServerless: responseActionFunc{logAudit, webhookAudit},
}

type resPolicyCacheType struct {
	ruleMap      map[uint32]*share.CLUSResponseRule
	ruleHeads    []*share.CLUSRuleHead
	ruleOrderMap map[uint32]int
}

var localResPolicyCache resPolicyCacheType = resPolicyCacheType{
	ruleMap:      make(map[uint32]*share.CLUSResponseRule),
	ruleHeads:    make([]*share.CLUSRuleHead, 0),
	ruleOrderMap: make(map[uint32]int, 0),
}

var fedResPolicyCache resPolicyCacheType = resPolicyCacheType{
	ruleMap:      make(map[uint32]*share.CLUSResponseRule),
	ruleHeads:    make([]*share.CLUSRuleHead, 0),
	ruleOrderMap: make(map[uint32]int, 0),
}

var logLevelMap map[string]int = map[string]int{
	api.LogLevelDEBUG:   1,
	api.LogLevelINFO:    2,
	api.LogLevelNOTICE:  3,
	api.LogLevelWARNING: 4,
	api.LogLevelERR:     5,
	api.LogLevelCRIT:    6,
	api.LogLevelALERT:   7,
	api.LogLevelEMERG:   8,
}

func logLevelComp(level1, level2 string) (int, error) {
	n1, ok := logLevelMap[level1]
	if !ok {
		return 0, fmt.Errorf("unsupported level %s", level1)
	}
	n2, ok := logLevelMap[level2]
	if !ok {
		return 0, fmt.Errorf("unsupported level %s", level2)
	}
	return n1 - n2, nil
}

func selectResPolicyCache(policyName string) *resPolicyCacheType {
	if policyName == share.DefaultPolicyName {
		return &localResPolicyCache
	} else if policyName == share.FedPolicyName {
		return &fedResPolicyCache
	}
	log.WithFields(log.Fields{"policyName": policyName}).Error("Response policy cache not found")
	return nil
}

func (m CacheMethod) ResponseRule2REST(rule *share.CLUSResponseRule) *api.RESTResponseRule {
	restRule := &api.RESTResponseRule{
		ID:      rule.ID,
		Event:   rule.Event,
		Comment: rule.Comment,
		Group:   rule.Group,
		Disable: rule.Disable,
	}
	restRule.CfgType, _ = cfgTypeMapping[rule.CfgType]
	conditions := make([]share.CLUSEventCondition, len(rule.Conditions))
	for i := 0; i < len(rule.Conditions); i++ {
		conditions[i] = rule.Conditions[i]
	}
	restRule.Conditions = conditions

	if len(rule.Actions) == 0 {
		restRule.Actions = make([]string, 0)
	} else {
		restRule.Actions = rule.Actions
	}
	if len(rule.Webhooks) == 0 {
		restRule.Webhooks = make([]string, 0)
	} else {
		restRule.Webhooks = rule.Webhooks
	}
	return restRule
}

func responseRuleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	policyName, cfgType := share.CLUSPolicyKey2ResPolicySubkey(key)
	resPolicyCache := selectResPolicyCache(policyName)
	if resPolicyCache == nil {
		return
	}

	cacheMutexLock()
	defer cacheMutexUnlock()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		if cfgType == share.CLUSResCfgRule {
			var rule share.CLUSResponseRule
			json.Unmarshal(value, &rule)
			if exist, ok := resPolicyCache.ruleMap[rule.ID]; ok {
				if gc, ok := groupCacheMap[exist.Group]; ok {
					gc.usedByResponseRules.Remove(exist.ID)
				}
			}
			resPolicyCache.ruleMap[rule.ID] = &rule
			if rule.Group != "" && !rule.Disable {
				if gc, ok := groupCacheMap[rule.Group]; ok {
					gc.usedByResponseRules.Add(rule.ID)
				} else {
					// Could happend at startup or joining the cluster, watch could return
					// policy update before group
					gc = initGroupCache(rule.CfgType, rule.Group)
					gc.usedByResponseRules.Add(rule.ID)
					groupCacheMap[rule.Group] = gc
				}
			}
		} else if cfgType == share.CLUSResCfgRuleList {
			var heads []*share.CLUSRuleHead
			json.Unmarshal(value, &heads)
			resPolicyCache.ruleHeads = heads
			resPolicyCache.ruleOrderMap = ruleHeads2OrderMap(heads)
		}
	case cluster.ClusterNotifyDelete:
		if cfgType == share.CLUSResCfgRule {
			id := share.CLUSPolicyRuleKey2ID(key)
			if exist, ok := resPolicyCache.ruleMap[id]; ok {
				if gc, ok := groupCacheMap[exist.Group]; ok {
					gc.usedByResponseRules.Remove(exist.ID)
				}
				delete(resPolicyCache.ruleMap, id)
			}
		} else if cfgType == share.CLUSResCfgRuleList {
			resPolicyCache.ruleHeads = make([]*share.CLUSRuleHead, 0)
			resPolicyCache.ruleOrderMap = ruleHeads2OrderMap(resPolicyCache.ruleHeads)
		}
	}
}

func matchConditions(desc *eventDesc, conds []share.CLUSEventCondition) bool {
	// AND op within a rule. Return false if one criterion doesn't match
	var match bool = true
	for _, d := range conds {
		switch d.CondType {
		case share.EventCondTypeName:
			var itemMatch bool
			// The serverless borrow item to filling in scan result for both permission/cve
			// so need skip from the Name match
			if len(desc.items) > 0 && desc.event != share.EventServerless {
				for _, item := range desc.items {
					if i := strings.Index(item, " "); i > 0 {
						if d.CondValue == item[:i] {
							itemMatch = true
							break
						}
					}
				}
			}
			if !itemMatch && !strings.EqualFold(desc.name, d.CondValue) {
				return false
			}
		case share.EventCondTypeCVEName:
			if desc.vuls == nil || !desc.vuls.Contains(d.CondValue) {
				return false
			}
		case share.EventCondTypeCVEHigh:
			count, err := strconv.Atoi(d.CondValue)
			if err != nil || desc.cve_high < count {
				return false
			}
		case share.EventCondTypeCVEHighWithFix:
			ss := strings.Split(d.CondValue, "/")
			cveCountInRule, err := strconv.Atoi(ss[0]) // high vul with fix count configured in response rule
			// get settings from response rule
			if err != nil {
				return false
			}
			if len(ss) >= 1 && len(desc.cve_high_fixed_info) < cveCountInRule {
				// it's configured like: ( high_vul_with_fix:X ) meaning "# of high vul(with fix) >= X"
				return false
			}
			if len(ss) == 2 {
				// it's configured like: ( high_vul_with_fix:X/Y ) meaning "# of (high vul that are reported Y days ago AND have fix) >= X"
				daysReported, err := strconv.Atoi(ss[1])
				if err != nil {
					return false
				}
				hoursReported := float64(24 * daysReported) // "reported before N hours" that is configured in response rule
				reportedBeforeNDays := 0
				// calculate how many high cve(with fix) that are reported before <daysReported> days
				for _, info := range desc.cve_high_fixed_info {
					dur := time.Since(time.Unix(info.PubTS, 0))
					if dur.Hours() >= hoursReported { // found high cve that is reported before <daysReported> days ago
						reportedBeforeNDays += 1
					}
				}
				if reportedBeforeNDays == 0 {
					return false
				}
			}
		case share.EventCondTypeCVEMedium:
			count, err := strconv.Atoi(d.CondValue)
			if err != nil || desc.cve_med < count {
				return false
			}
		case share.EventCondTypeLevel:
			cmp, err := logLevelComp(desc.level, d.CondValue)
			if err != nil || cmp != 0 {
				return false
			}
		case share.EventCondTypeProc:
			if desc.proc != d.CondValue {
				return false
			}
		}
	}
	return match
}

func checkGrpThreatDlpGrp(grp string, arg interface{}) bool {
	rlog := arg.(*api.Threat)

	dlpgrps := strings.Split(rlog.Group, ",")

	for _, dgrp := range dlpgrps {
		if strings.Compare(grp, dgrp) == 0 {
			return true
		}
	}
	return false
}

// cacheMutex is owned by caller
func lookup(desc *eventDesc) []actionDesc {
	var resPolicyCaches []*resPolicyCacheType
	if fedRole := fedMembershipCache.FedRole; fedRole == api.FedRoleMaster || fedRole == api.FedRoleJoint {
		resPolicyCaches = []*resPolicyCacheType{&fedResPolicyCache, &localResPolicyCache}
	} else {
		resPolicyCaches = []*resPolicyCacheType{&localResPolicyCache}
	}
	ret := make([]actionDesc, 0)
	for _, resPolicyCache := range resPolicyCaches {
		for _, head := range resPolicyCache.ruleHeads {
			rule, ok := resPolicyCache.ruleMap[head.ID]
			if !ok {
				log.WithFields(log.Fields{"id": head.ID}).Error("cannot find rule")
				continue
			}

			if rule.Disable {
				continue
			}

			if rule.Event == share.EventRuntime {
				if desc.event != share.EventIncident && desc.event != share.EventThreat && desc.event != share.EventViolation {
					continue
				}
			} else if rule.Event != desc.event {
				continue
			}

			// If no group config, it means applying to all
			if rule.Group != "" {
				group, ok := groupCacheMap[rule.Group] //-> TO CHECK ?
				if !ok {
					log.WithFields(log.Fields{"id": head.ID, "group": rule.Group}).Error("cannot find group")
					continue
				}
				if desc.name == api.EventNameGroupAutoRemove || desc.name == api.EventNameGroupAutoPromote { // they for groups, not for workloads
					if desc.groupName != rule.Group {
						continue
					}
				} else {
					if !group.members.Contains(desc.id) { //-> TO CHECK ?
						continue
					}
				}
				//DLP threat, rule.Group belong to dlp group that triggers DLP threat?
				if strings.HasPrefix(desc.name, common.DlpPrefix) && !checkGrpThreatDlpGrp(rule.Group, desc.arg) {
					continue
				}
			}
			if len(rule.Conditions) == 0 || matchConditions(desc, rule.Conditions) {
				ret = append(ret, actionDesc{id: rule.ID, comment: rule.Comment, actions: rule.Actions, webhooks: rule.Webhooks})
			}
		}
	}
	return ret
}

func responseRuleLookup(desc *eventDesc) {

	react, ok := responseFuncs[desc.event]
	if !ok {
		log.WithFields(log.Fields{"event": desc.event}).Error("Not supported")
		return
	}

	cacheMutexRLock()
	matched := lookup(desc)
	cacheMutexRUnlock()

	if len(matched) > 0 {
		log.WithFields(log.Fields{
			"workload": desc.id, "event": desc.event, "matched": matched,
		}).Debug("")
	} else {
		log.WithFields(log.Fields{
			"workload": desc.id, "event": desc.event,
		}).Debug("No response rule match")
	}

	suppressLog := false
	acts := utils.NewSet()
	for _, actDesc := range matched {
		id := actDesc.id
		for _, action := range actDesc.actions {
			if acts.Contains(action) {
				continue
			} else {
				acts.Add(action)
			}

			if action == share.EventActionSuppressLog {
				suppressLog = true
			}

			if action == share.EventActionWebhook && react.webhookFunc != nil {
				// leader check is inside the webhook function
				react.webhookFunc(&actDesc, desc.arg)
			}

			if !desc.noQuar && action == share.EventActionQuarantine && isLeader() && strings.Index(desc.name, "AdmCtrl.") != 0 {
				cacheMutexRLock()
				wlc, ok := wlCacheMap[desc.id]
				if !ok {
					log.WithFields(log.Fields{
						"workload": desc.id, "event": desc.event, "rule": id,
					}).Debug("Cannot find workload to quarantine")
				} else if wlc.workload.ShareNetNS != "" {
					if parent, ok := wlCacheMap[wlc.workload.ShareNetNS]; ok {
						wlc = parent
					} else {
						log.WithFields(log.Fields{
							"container": desc.id, "parent": wlc.workload.ShareNetNS,
						}).Error("cannot find parent")
						wlc = nil
					}
				}
				cacheMutexRUnlock()

				if wlc != nil {
					if !wlc.workload.CapIntcp {
						log.WithFields(log.Fields{
							"workload": wlc.workload.ID, "event": desc.event, "rule": id,
						}).Debug("workload cannot be quarantined")
					} else if wlc.workload.Quarantine {
						log.WithFields(log.Fields{
							"workload": wlc.workload.ID, "event": desc.event, "rule": id,
						}).Error("workload is already quarantined")
					} else {
						log.WithFields(log.Fields{
							"wrokload": wlc.workload.ID, "event": desc.event, "rule": id,
						}).Debug("Need quarantine")

						var cconf share.CLUSWorkloadConfig
						key := share.CLUSUniconfWorkloadKey(wlc.workload.HostID, wlc.workload.ID)
						value, rev, _ := cluster.GetRev(key)
						if value != nil {
							json.Unmarshal(value, &cconf)
						} else {
							cconf.Wire = share.WireDefault
						}
						if !cconf.Quarantine {
							cconf.Quarantine = true
							cconf.QuarReason = share.QuarantineReasonEvent(desc.event, id)
							value, _ = json.Marshal(&cconf)
							if err := cluster.PutRev(key, value, rev); err != nil {
								log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
							}
						}
					}
				}
			}
		}
	}

	// suppress incident logs implicitly
	if desc.name == api.EventNameHostPackageUpdated {
		suppressLog = true
	}
	// By default, log the event
	if !suppressLog && react.logFunc != nil {
		react.logFunc(desc.arg)
	}
	return
}

func (m CacheMethod) GetResponseRuleCount(scope string, acc *access.AccessControl) int {
	var names []string
	switch scope {
	case share.ScopeLocal:
		names = []string{share.DefaultPolicyName}
	case share.ScopeFed:
		names = []string{share.FedPolicyName}
	case share.ScopeAll:
		names = []string{share.FedPolicyName, share.DefaultPolicyName}
	default:
		return 0
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	var count int
	for _, name := range names {
		resPolicyCache := selectResPolicyCache(name)
		if resPolicyCache != nil {
			for _, r := range resPolicyCache.ruleMap {
				if !acc.Authorize(r, getAccessObjectFuncNoLock) {
					continue
				}
				count++
			}
		}
	}
	return count
}

func (m CacheMethod) GetResponseRule(policyName string, id uint32, acc *access.AccessControl) (*api.RESTResponseRule, error) {
	resPolicyCache := selectResPolicyCache(policyName)
	if resPolicyCache == nil {
		return nil, common.ErrObjectNotFound
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if r, ok := resPolicyCache.ruleMap[id]; ok {
		if !acc.Authorize(r, getAccessObjectFuncNoLock) {
			return nil, common.ErrObjectAccessDenied
		}
		return m.ResponseRule2REST(r), nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetAllResponseRules(scope string, acc *access.AccessControl) []*api.RESTResponseRule {
	size := 0
	caches := make([]*resPolicyCacheType, 0, 2)
	var names []string
	switch scope {
	case share.ScopeLocal:
		names = []string{share.DefaultPolicyName}
	case share.ScopeFed:
		names = []string{share.FedPolicyName}
	case share.ScopeAll:
		names = []string{share.FedPolicyName, share.DefaultPolicyName}
	default:
		return nil
	}
	for _, name := range names {
		resPolicyCache := selectResPolicyCache(name)
		if resPolicyCache != nil {
			caches = append(caches, resPolicyCache)
			size += len(resPolicyCache.ruleHeads)
		}
	}
	if len(caches) == 0 {
		return nil
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rules := make([]*api.RESTResponseRule, 0, size)
	for _, resPolicyCache := range caches {
		for _, head := range resPolicyCache.ruleHeads {
			if rule, ok := resPolicyCache.ruleMap[head.ID]; ok {
				if !acc.Authorize(rule, getAccessObjectFuncNoLock) {
					continue
				}
				rules = append(rules, m.ResponseRule2REST(rule))
			}
		}
	}

	return rules
}

func (m CacheMethod) GetWorkloadResponseRules(policyName, id string, acc *access.AccessControl) ([]*api.RESTResponseRule, error) {
	resPolicyCache := selectResPolicyCache(policyName)
	if resPolicyCache == nil {
		return nil, common.ErrObjectNotFound
	}

	ret := make([]*api.RESTResponseRule, 0)
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := wlCacheMap[id]; ok {
		if !acc.Authorize(cache.workload, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		for _, head := range resPolicyCache.ruleHeads {
			rule, ok := resPolicyCache.ruleMap[head.ID]
			if !ok {
				continue
			}
			if !acc.Authorize(rule, nil) {
				continue
			}
			if rule.Group != "" {
				group, ok := groupCacheMap[rule.Group]
				if !ok || !group.members.Contains(id) {
					continue
				}
			}
			ret = append(ret, m.ResponseRule2REST(rule))
		}
	}
	return ret, nil
}

// caller owns cacheMutexRLock & has readAll right
func (m CacheMethod) GetFedResponseRulesCache() (map[uint32]*share.CLUSResponseRule, []*share.CLUSRuleHead) {
	resPolicyCache := selectResPolicyCache(share.FedPolicyName)
	if resPolicyCache == nil {
		return make(map[uint32]*share.CLUSResponseRule), make([]*share.CLUSRuleHead, 0)
	}

	return resPolicyCache.ruleMap, resPolicyCache.ruleHeads
}
