package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

const dlpCalculatingDelayFast = time.Duration(time.Second * 2)
const dlpCalculatingDelaySlow = time.Duration(time.Second * 4)

var dlpSensors map[string]*share.CLUSDlpSensor = make(map[string]*share.CLUSDlpSensor) //sensor name to sensor map
var dlpRuleSensors map[string]utils.Set = make(map[string]utils.Set)                   //key is rule entry name, value is sensor name
var dlpGroupSensors map[string]utils.Set = make(map[string]utils.Set)                  //key is group name, value is sensor name
var dlpGroups map[string]*share.CLUSDlpGroup = make(map[string]*share.CLUSDlpGroup)
var dlpIdRule map[uint32]string = make(map[uint32]string) //key is rule id, value is rule name

// update dlp rule from config
func dlpRuleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	sensor := share.CLUSDlpRuleKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var dlpsensor share.CLUSDlpSensor
		if err := json.Unmarshal(value, &dlpsensor); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Fail to decode")
			return
		}

		cacheMutexLock()
		dlpSensors[sensor] = &dlpsensor
		if sensor != share.CLUSDlpDefaultSensor {
			//rule entry always belong to default sensor, no need to
			//be in this map, this map check whether this rule entry
			//belong to other sensor(s) or not
			for _, cds := range dlpRuleSensors {
				if cds != nil {
					if cds.Contains(sensor) {
						cds.Remove(sensor)
					}
				}
			}
			for _, cdrename := range dlpsensor.RuleListNames {
				if dlpRuleSensors[cdrename] == nil {
					dlpRuleSensors[cdrename] = utils.NewSet()
				}
				dlpRuleSensors[cdrename].Add(sensor)
			}
		} else {
			for id := range dlpIdRule {
				delete(dlpIdRule, id)
			}
			if dlpIdRule == nil {
				dlpIdRule = make(map[uint32]string)
			}
			for _, cdr := range dlpsensor.RuleList {
				if cdr != nil {
					dlpIdRule[cdr.ID] = cdr.Name
				}
			}
			for _, cdrl := range dlpsensor.PreRuleList {
				if len(cdrl) > 0 {
					dlpIdRule[cdrl[0].ID] = cdrl[0].Name
				}
			}
		}

		//sync with CLUSGroup
		syncDlpClusGroup(sensor)

		for cg := range dlpsensor.Groups {
			//group to sensors map
			if dlpGroupSensors[cg] == nil {
				dlpGroupSensors[cg] = utils.NewSet()
			}
			dlpGroupSensors[cg].Add(sensor)
		}

		cacheMutexUnlock()
		scheduleDlpRuleCalculation(true)
		log.WithFields(log.Fields{"sensor": sensor}).Debug("Update")

	case cluster.ClusterNotifyDelete:
		updategrp := false
		cacheMutexLock()
		if dlpsensor, ok := dlpSensors[sensor]; ok {
			for cg := range dlpsensor.Groups {
				if dlpGroupSensors[cg] != nil && dlpGroupSensors[cg].Contains(sensor) {
					updategrp = true
				}
			}
			for _, cdrename := range dlpsensor.RuleListNames {
				if dlpRuleSensors[cdrename] != nil {
					dlpRuleSensors[cdrename].Remove(sensor)
				}
			}
			delete(dlpSensors, sensor)
		}
		cacheMutexUnlock()
		if updategrp {
			scheduleDlpRuleCalculation(true)
		}
		deleteDlpRuleNetwork(sensor)
	}
}

func isCreateDlpGroup(group *share.CLUSGroup) bool {
	if group == nil || group.Kind != share.GroupKindContainer ||
		strings.HasPrefix(group.Name, api.FederalGroupPrefix) {
		return false
	}
	if _, ok := dlpGroups[group.Name]; !ok {
		return true
	}

	return false
}

func createDlpGroup(group string, cfgType share.TCfgType) {
	dlpgroup := &share.CLUSDlpGroup{
		Name:    group,
		Status:  true,
		Sensors: make([]*share.CLUSDlpSetting, 0),
		CfgType: cfgType,
	}
	if err := clusHelper.PutDlpGroup(dlpgroup, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Put dlp group fail")
	}
}

func dlpGroupConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	group := share.CLUSDlpGroupKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var dlpgroup share.CLUSDlpGroup
		if err := json.Unmarshal(value, &dlpgroup); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Fail to decode")
			return
		}

		cacheMutexLock()
		dlpGroups[group] = &dlpgroup
		dlpProcessGroup(&dlpgroup)
		cacheMutexUnlock()

		scheduleDlpRuleCalculation(true)
		log.WithFields(log.Fields{"dlpgroup": group}).Debug("Update")

	case cluster.ClusterNotifyDelete:
		cacheMutexLock()
		if dlpgroup, ok := dlpGroups[group]; ok {
			dlpProcessGroupDel(dlpgroup)
			delete(dlpGroups, group)
		}
		cacheMutexUnlock()
		log.WithFields(log.Fields{"dlpgroup": group}).Debug("Delete")
		//on cli group can be deleted even with non-zero members
		//on GUI group cannot be deleted with non-zero members
		//for cli's case, schedule recalculation
		scheduleDlpRuleCalculation(true)
	}
}

func syncDlpClusGroup(sname string) {
	for grp, cgs := range dlpGroupSensors { //loop through group->sensors mapping
		if cgs != nil && cgs.Contains(sname) {
			if dr, ok := dlpSensors[sname]; ok {
				if _, ok1 := dr.Groups[grp]; !ok1 { //sensor is not used by group, not in sync
					if dlpgrp, ok2 := dlpGroups[grp]; ok2 { //need to sync with CLUSDlpGroup
						if dlpgrp != nil {
							log.WithFields(log.Fields{"dlpgroup": dlpgrp}).Debug("sync dlp group")
							dlpFillSensorGroup(dlpgrp, sname)
						}
					}
				}
			}
			cgs.Remove(sname)
		}
	}
}

func dlpFillSensorGroup(group *share.CLUSDlpGroup, sensor string) {
	cs := &share.CLUSDlpSetting{Name: sensor, Action: share.DlpRuleActionDrop}
	if idx, ok := common.FindSensorInDlpGroup(group.Sensors, cs); ok {
		if dr, ok1 := dlpSensors[sensor]; ok1 {
			if dr.Groups == nil {
				dr.Groups = make(map[string]string)
			}
			dr.Groups[group.Name] = group.Sensors[idx].Action
		}
	}
}
func dlpProcessGroupDel(group *share.CLUSDlpGroup) {
	if cgs, ok := dlpGroupSensors[group.Name]; ok {
		for sen := range cgs.Iter() {
			sname := sen.(string)
			if dr, ok1 := dlpSensors[sname]; ok1 {
				delete(dr.Groups, group.Name)
			}
		}
		dlpGroupSensors[group.Name].Clear()
	}
	for _, sen := range group.Sensors {
		if dr, ok := dlpSensors[sen.Name]; ok {
			delete(dr.Groups, group.Name)
		}
	}
}
func dlpProcessGroup(group *share.CLUSDlpGroup) {
	if cgs, ok := dlpGroupSensors[group.Name]; ok {
		for sen := range cgs.Iter() {
			sname := sen.(string)
			if dr, ok1 := dlpSensors[sname]; ok1 {
				delete(dr.Groups, group.Name)
			}
		}
		dlpGroupSensors[group.Name].Clear()
	}
	if group.Status { //add/modify dlp sensors for group
		for _, sen := range group.Sensors {
			if dr, ok := dlpSensors[sen.Name]; ok {
				if dr.Groups == nil {
					dr.Groups = make(map[string]string)
				}
				dr.Groups[group.Name] = sen.Action
			}
			if dlpGroupSensors[group.Name] == nil {
				dlpGroupSensors[group.Name] = utils.NewSet()
			}
			dlpGroupSensors[group.Name].Add(sen.Name)
		}
	} else { //delete dlp sensors for group
		for _, sen := range group.Sensors {
			if dr, ok := dlpSensors[sen.Name]; ok {
				delete(dr.Groups, group.Name)
			}
		}
	}
}

func assocWl2PolicyIds(grp string, senset utils.Set, outside_wl2sensor map[string]map[string]string,
	wl2policies, outside_wl2policies map[string]utils.Set) {
	var inside_grps utils.Set = utils.NewSet()
	var outside_grps utils.Set = utils.NewSet()
	var inside_ruleids utils.Set = utils.NewSet()
	var outside_ruleids utils.Set = utils.NewSet()
	var out2ingrp map[string]map[string]string = make(map[string]map[string]string)
	if grpcache, ok := groupCacheMap[grp]; ok {
		for _, m := range grpcache.members.ToSlice() {
			wlid := m.(string)
			if wlcache, ok := wlCacheMap[wlid]; ok && wlcache.workload.HasDatapath {
				inside_grps = inside_grps.Union(wlcache.groups)
			}
		}
	}
	for _, head := range policyCache.ruleHeads {
		if rule, ok := policyCache.ruleMap[head.ID]; !ok {
			log.WithFields(log.Fields{"ID": head.ID}).Debug("rule does not exist")
		} else if !rule.Disable {
			if inside_grps.Contains(rule.From) && inside_grps.Contains(rule.To) {
				inside_ruleids.Add(rule.ID)
			} else {
				if policyApplyIngress {
					if inside_grps.Contains(rule.From) {
						outside_ruleids.Add(rule.ID)
						outside_grps.Add(rule.To)
						if out2ingrp[rule.To] == nil {
							out2ingrp[rule.To] = make(map[string]string)
						}
						out2ingrp[rule.To][rule.From] = rule.From
					}
				} else {
					if inside_grps.Contains(rule.To) {
						outside_ruleids.Add(rule.ID)
						outside_grps.Add(rule.From)
						if out2ingrp[rule.From] == nil {
							out2ingrp[rule.From] = make(map[string]string)
						}
						out2ingrp[rule.From][rule.To] = rule.To
					}
				}
			}
		}
	}

	if grpcache, ok := groupCacheMap[grp]; ok {
		for _, m := range grpcache.members.ToSlice() {
			wlid := m.(string)
			//only include wl that has datapath to save memory and cpu
			if wlcache, exist := wlCacheMap[wlid]; exist && !wlcache.workload.HasDatapath {
				continue
			}
			if rids, ok := wl2policies[wlid]; !ok {
				wl2policies[wlid] = inside_ruleids
			} else {
				wl2policies[wlid] = rids.Union(inside_ruleids)
			}
		}
	}

	for og := range outside_grps.Iter() {
		ogrp := og.(string)
		if ogrpcache, ok := groupCacheMap[ogrp]; ok {
			for _, om := range ogrpcache.members.ToSlice() {
				owlid := om.(string)
				//only include wl that has datapath to save memory and cpu
				if wlcache, exist := wlCacheMap[owlid]; exist && !wlcache.workload.HasDatapath {
					continue
				}
				if orids, ok := outside_wl2policies[owlid]; !ok {
					outside_wl2policies[owlid] = outside_ruleids
				} else {
					outside_wl2policies[owlid] = orids.Union(outside_ruleids)
				}
				if osam, ok := outside_wl2sensor[owlid]; !ok {
					if outside_wl2sensor[owlid] == nil {
						outside_wl2sensor[owlid] = make(map[string]string)
					}
					for osen := range senset.Iter() {
						osname := osen.(string)
						outside_wl2sensor[owlid][osname] = GetDlpOutsideGrpSensorAction(ogrp, osname, out2ingrp)
					}
				} else {
					for osen := range senset.Iter() {
						osname := osen.(string)
						if _, ok := osam[osname]; !ok {
							osam[osname] = GetDlpOutsideGrpSensorAction(ogrp, osname, out2ingrp)
						} else {
							otact := GetDlpOutsideGrpSensorAction(ogrp, osname, out2ingrp)
							if otact == share.DlpRuleActionDrop {
								osam[osname] = otact
							}
						}
					}
				}
			}
		}
	}
}

func assocWl2Sensors(grp string, senset utils.Set, wl2sensors map[string]map[string]string, dsensors *utils.Set) {
	if grpcache, ok := groupCacheMap[grp]; ok {
		if grpcache.members.Cardinality() > 0 {
			//get all the sensors with no duplication
			//only when there is member in group
			(*dsensors) = (*dsensors).Union(senset)
		}
		for _, m := range grpcache.members.ToSlice() {
			wlid := m.(string)
			//only include wl that has datapath to save memory and cpu
			if wlcache, exist := wlCacheMap[wlid]; exist && !wlcache.workload.HasDatapath {
				continue
			}
			if sam, ok := wl2sensors[wlid]; !ok {
				if wl2sensors[wlid] == nil {
					wl2sensors[wlid] = make(map[string]string)
				}
				for sen := range senset.Iter() {
					sname := sen.(string)
					wl2sensors[wlid][sname] = GetDlpGrpSensorAction(grp, sname)
				}
			} else {
				for sen := range senset.Iter() {
					sname := sen.(string)
					if _, ok := sam[sname]; !ok {
						sam[sname] = GetDlpGrpSensorAction(grp, sname)
					} else {
						tact := GetDlpGrpSensorAction(grp, sname)
						if tact == share.DlpRuleActionDrop {
							sam[sname] = tact
						}
					}
				}
			}
		}
	}
}

func processDlpGroupPolicy(wl2sensors, outside_wl2sensor map[string]map[string]string,
	wl2policies, outside_wl2policies map[string]utils.Set, dsensors *utils.Set) {
	log.Debug("")
	for grp, senset := range dlpGroupSensors {
		if senset.Cardinality() == 0 {
			continue
		}
		//configured group itself
		assocWl2Sensors(grp, senset, wl2sensors, dsensors)
		assocWl2PolicyIds(grp, senset, outside_wl2sensor, wl2policies, outside_wl2policies)
	}
}

func IsAllPatternEmpty(dre *share.CLUSDlpRule) bool {
	if dre != nil {
		for _, cpt := range dre.Patterns {
			if cpt.Value != "" {
				return false
			}
		}
	}

	return true
}

func assocWl2RuleNames(wl2sensors, wl2rules map[string]map[string]string) {
	log.Debug("")
	for wlid, sens := range wl2sensors {
		for sname, act := range sens {
			if cdr, ok := dlpSensors[sname]; ok {
				if cdr.Name == share.CLUSDlpDefaultSensor {
					//user created rule
					for _, cdre := range cdr.RuleList {
						//ignore all pattern empty rule
						if IsAllPatternEmpty(cdre) {
							continue
						}

						if ram, ok := wl2rules[wlid]; !ok {
							if wl2rules[wlid] == nil {
								wl2rules[wlid] = make(map[string]string)
							}
							wl2rules[wlid][cdre.Name] = act
						} else {
							if _, ok := ram[cdre.Name]; !ok {
								ram[cdre.Name] = act
							} else {
								if act == share.DlpRuleActionDrop {
									ram[cdre.Name] = act
								}
							}
						}
					}
					//predefined rule
					for _, cdrelist := range cdr.PreRuleList {
						if ram, ok := wl2rules[wlid]; !ok {
							if wl2rules[wlid] == nil {
								wl2rules[wlid] = make(map[string]string)
							}
							wl2rules[wlid][cdrelist[0].Name] = act
						} else {
							if _, ok := ram[cdrelist[0].Name]; !ok {
								ram[cdrelist[0].Name] = act
							} else {
								if act == share.DlpRuleActionDrop {
									ram[cdrelist[0].Name] = act
								}
							}
						}
					}
				} else {
					for _, cdrename := range cdr.RuleListNames {
						cdrelist := getPreDlpRuleFromDefaultSensor(cdrename)
						//only non-predefined rule check for empty pattern
						if cdrelist == nil {
							//ignore all pattern empty rule
							cdre := getDlpRuleFromDefaultSensor(cdrename)
							if IsAllPatternEmpty(cdre) {
								continue
							}
						}
						if ram, ok := wl2rules[wlid]; !ok {
							if wl2rules[wlid] == nil {
								wl2rules[wlid] = make(map[string]string)
							}
							wl2rules[wlid][cdrename] = act
						} else {
							if _, ok := ram[cdrename]; !ok {
								ram[cdrename] = act
							} else {
								if act == share.DlpRuleActionDrop {
									ram[cdrename] = act
								}
							}
						}
					}
				}
			}
		}
	}
}

func listRuleEntriesForSens(dlprulemap map[string][]*share.CLUSDlpRule, dsensors utils.Set) {
	if dsensors.Contains(share.CLUSDlpDefaultSensor) {
		//default sensor contains all rule entries
		if cdr, ok := dlpSensors[share.CLUSDlpDefaultSensor]; ok {
			//user defined rule
			for _, cdre := range cdr.RuleList {
				if dlprulemap[cdre.Name] == nil {
					dlprulemap[cdre.Name] = make([]*share.CLUSDlpRule, 0)
				}
				dlprulemap[cdre.Name] = append(dlprulemap[cdre.Name], cdre)
			}
			//predefined rule
			for _, cdrelist := range cdr.PreRuleList {
				for _, cdre := range cdrelist {
					if dlprulemap[cdre.Name] == nil {
						dlprulemap[cdre.Name] = make([]*share.CLUSDlpRule, 0)
					}
					dlprulemap[cdre.Name] = append(dlprulemap[cdre.Name], cdre)
				}
			}
		}
	} else {
		for dsen := range dsensors.Iter() {
			ds := dsen.(string)
			if cdr, ok := dlpSensors[ds]; ok {
				for _, cdrename := range cdr.RuleListNames {
					//different sensor may use same rule
					if _, ok := dlprulemap[cdrename]; ok {
						continue
					}
					cdre := getDlpRuleFromDefaultSensor(cdrename)
					if cdre != nil {
						if dlprulemap[cdre.Name] == nil {
							dlprulemap[cdre.Name] = make([]*share.CLUSDlpRule, 0)
						}
						dlprulemap[cdre.Name] = append(dlprulemap[cdre.Name], cdre)
					} else { //predefined rule
						cdrelist := getPreDlpRuleFromDefaultSensor(cdrename)
						for _, cdre := range cdrelist {
							if dlprulemap[cdre.Name] == nil {
								dlprulemap[cdre.Name] = make([]*share.CLUSDlpRule, 0)
							}
							dlprulemap[cdre.Name] = append(dlprulemap[cdre.Name], cdre)
						}
					}
				}
			}
		}
	}
}

func reOrgWlRules(wl2rules, outside_wl2rules map[string]map[string]string, outside_wl2policies map[string]utils.Set) {
	/*
	 * if wl belongs to both inside and outside ruletype,
	 * inside takes higher priority, but wl->rule/action map
	 * needs to be updated
	 */
	for wlid, inram := range wl2rules {
		if outram, ok := outside_wl2rules[wlid]; ok {
			for orn, ora := range outram {
				if _, ok1 := inram[orn]; ok1 {
					if ora == share.DlpRuleActionDrop {
						inram[orn] = ora
					}
				} else {
					inram[orn] = ora
				}
			}
			delete(outside_wl2rules, wlid)
			delete(outside_wl2policies, wlid)
		}
	}
}

func getWlRules(cgdrs *share.CLUSWorkloadDlpRules, wl2rules map[string]map[string]string, wl2policies map[string]utils.Set, ruletype string) {
	for wlid, rns := range wl2rules {
		wlrule := &share.CLUSDlpWorkloadRule{
			WorkloadId:    wlid,
			RuleListNames: make([]*share.CLUSDlpSetting, 0),
			RuleIds:       make([]uint32, 0),
			RuleType:      ruletype,
		}
		if wlcache, ok := wlCacheMap[wlid]; ok {
			wlrule.PolicyMode, _ = getWorkloadEffectivePolicyMode(wlcache)
		} else {
			wlrule.PolicyMode = ""
		}
		for rn, ract := range rns {
			rnact := &share.CLUSDlpSetting{
				Name:   rn,
				Action: ract,
			}
			wlrule.RuleListNames = append(wlrule.RuleListNames, rnact)
		}
		if wlrids, ok := wl2policies[wlid]; ok {
			for rid := range wlrids.Iter() {
				wlrule.RuleIds = append(wlrule.RuleIds, rid.(uint32))
			}
		}
		cgdrs.DlpWlRules = append(cgdrs.DlpWlRules, wlrule)
	}
}

/*
func printDlpRuleMap(dlprulemap map[string][]*share.CLUSDlpRule) {
	for _, drelist := range dlprulemap {
		for _, dre := range drelist {
			log.WithFields(log.Fields{"dre": *dre}).Debug("print dlprulemap")
		}
	}
}
func printDefaultDlpRules(cgdrs *share.CLUSWorkloadDlpRules) {
	for _, rl := range cgdrs.DlpRuleList {
		log.WithFields(log.Fields{"rl": *rl}).Debug("DlpRuleList")
	}
	for _, dl := range cgdrs.DlpWlRules {
		log.WithFields(log.Fields{"dl": *dl}).Debug("DlpWlRules")
		for _, lrn := range dl.RuleListNames {
			log.WithFields(log.Fields{"listrulename": *lrn}).Debug("DlpWlRules")
		}
	}
}
*/

func calculateGroupDlpRulesFromCache() share.CLUSWorkloadDlpRules {
	log.Debug("")

	var wl2sensors map[string]map[string]string = make(map[string]map[string]string)
	var outside_wl2sensors map[string]map[string]string = make(map[string]map[string]string)
	var wl2policies map[string]utils.Set = make(map[string]utils.Set)
	var outside_wl2policies map[string]utils.Set = make(map[string]utils.Set)
	var dsensors utils.Set = utils.NewSet()
	var wl2rules map[string]map[string]string = make(map[string]map[string]string)
	var outside_wl2rules map[string]map[string]string = make(map[string]map[string]string)
	var dlprulemap map[string][]*share.CLUSDlpRule = make(map[string][]*share.CLUSDlpRule)

	//associate workload to sensors and get union of all sensors
	processDlpGroupPolicy(wl2sensors, outside_wl2sensors, wl2policies, outside_wl2policies, &dsensors)

	//associate workload to rule names mapping
	assocWl2RuleNames(wl2sensors, wl2rules)
	assocWl2RuleNames(outside_wl2sensors, outside_wl2rules)

	//get all rule entries in all sensors
	if len(wl2sensors) > 0 {
		listRuleEntriesForSens(dlprulemap, dsensors)
		//printDlpRuleMap(dlprulemap)
	}

	cgdrs := share.CLUSWorkloadDlpRules{
		DlpRuleList: make([]*share.CLUSDlpRule, 0),
		DlpWlRules:  make([]*share.CLUSDlpWorkloadRule, 0),
	}

	for _, drelist := range dlprulemap {
		for _, dre := range drelist {
			//ignore empty pattern rule to be calculated for DlpRuleList
			if IsAllPatternEmpty(dre) {
				continue
			}

			cgdrs.DlpRuleList = append(cgdrs.DlpRuleList, dre)
		}
	}

	//reorg inside and outside wlrules
	reOrgWlRules(wl2rules, outside_wl2rules, outside_wl2policies)
	getWlRules(&cgdrs, wl2rules, wl2policies, share.DlpWlRuleIn)
	getWlRules(&cgdrs, outside_wl2rules, outside_wl2policies, share.DlpWlRuleOut)

	//printDefaultDlpRules(&cgdrs)
	return cgdrs
}

// each slot's max size after zip is 500k
const maxDlpSlots = 512

func prepareDlpSlots(rules share.CLUSWorkloadDlpRules) ([][]byte, int, int, error) {
	// deal with case that compressed rule size is > max kv value size (512K)
	for slots := 16; slots <= maxDlpSlots; slots *= 2 {
		r_lens := len(rules.DlpRuleList)
		wl_lens := len(rules.DlpWlRules)
		rwl_len := wl_lens
		if r_lens > wl_lens {
			rwl_len = r_lens
		}
		enlarge := false
		final_slots := slots
		if rwl_len < slots {
			final_slots = rwl_len
		}
		log.WithFields(log.Fields{
			"r_lens":      r_lens,
			"wl_lens":     wl_lens,
			"slots":       slots,
			"final_slots": final_slots,
			"maxDlpSlots": maxDlpSlots,
		}).Debug("segregate dlpwlrules to slots")

		//put dlpwlrules to slots evenly
		plcs := make([]share.CLUSWorkloadDlpRules, final_slots)
		for idx, rlt := range rules.DlpRuleList {
			if plcs[idx%final_slots].DlpRuleList == nil {
				plcs[idx%final_slots].DlpRuleList = make([]*share.CLUSDlpRule, 0)
			}
			plcs[idx%final_slots].DlpRuleList = append(plcs[idx%final_slots].DlpRuleList, rlt)
			//log.WithFields(log.Fields{"slot_idx": idx%final_slots, "rulelist_idx": idx, }).Debug("assign dlprulelist to slots")
		}
		for idx, rl := range rules.DlpWlRules {
			if plcs[idx%final_slots].DlpWlRules == nil {
				plcs[idx%final_slots].DlpWlRules = make([]*share.CLUSDlpWorkloadRule, 0)
			}
			plcs[idx%final_slots].DlpWlRules = append(plcs[idx%final_slots].DlpWlRules, rl)
			//log.WithFields(log.Fields{"slot_idx": idx%final_slots, "rule_idx": idx, }).Debug("assign dlpwlrules to slots")
		}

		//zip each slots
		zbs := make([][]byte, final_slots)
		for i, plc := range plcs {
			//printDefaultDlpRules(&plc)
			value, _ := json.Marshal(plc)
			zb := utils.GzipBytes(value)
			//log.WithFields(log.Fields{"slot_idx": i, "size": len(zb)}).Debug("gzip dlpwlrules")
			if len(zb) >= cluster.KVValueSizeMax {
				log.WithFields(log.Fields{"slot_idx": i, "size": len(zb)}).Debug("gzip dlpwlrules too large")
				enlarge = true
				break
			}
			zbs[i] = zb
		}

		//log.WithFields(log.Fields{"enlarge": enlarge}).Debug("")
		if !enlarge {
			return zbs, r_lens, wl_lens, nil
		}
	}

	return nil, 0, 0, errors.New("Dlpwlrules are too large")
}

func dlpRulesCleanup(ruleKeys []string) {
	txn := cluster.Transact()
	defer txn.Close()

	// Remove keys that have been written
	for _, key := range ruleKeys {
		txn.Delete(key)
	}
	//Ignore failure, missed keys will be removed the next update.
	_, _ = txn.Apply()
}

func putDlpWorkloadRulesToClusterScale(rules share.CLUSWorkloadDlpRules) {
	//DlpWorkloadRules is not directly watched by consul, to improve performance
	//change key from "network/DlpWorkloadRules/" to "recalculate/dlp/DlpWorkloadRules/"
	rule_key := fmt.Sprintf("%s/", share.CLUSRecalDlpWlRulesKey(share.DlpRulesDefaultName))
	oldKeys, _ := cluster.GetStoreKeys(rule_key)

	verstr := fmt.Sprintf("ver.%d.%d", time.Now().UTC().UnixNano(), time.Now().UTC().UnixNano())
	newRuleKey := fmt.Sprintf("%s%s/", rule_key, verstr)

	// separate all rules into slots
	zbs, rlen, wlens, err := prepareDlpSlots(rules)
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
			dlpRulesCleanup(newKeys)
			return
		}
	}
	//new kv to indicate rule change
	dlpVer := share.CLUSDlpRuleVer{
		Key:             share.DlpRulesVersionID,
		DlpRulesVersion: verstr,
		SlotNo:          len(zbs),
		RulesLen:        rlen,
		WorkloadLen:     wlens,
	}
	log.WithFields(log.Fields{"DlpRules": newRuleKey, "dlpVer": dlpVer}).Debug("New dlp rules written")

	clusHelper := kv.GetClusterHelper()
	if err = clusHelper.PutDlpVer(&dlpVer); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write dlp rules to the cluster")
		newKeys, _ := cluster.GetStoreKeys(newRuleKey)
		dlpRulesCleanup(newKeys)
		return
	}
	dlpRulesCleanup(oldKeys)
}

/*
// network/DlpWorkloadRules is listened by enforcers

	func putDlpWorkloadRulesToCluster(rules share.CLUSWorkloadDlpRules) {
		key := share.CLUSDlpWorkloadRulesKey(share.DlpRulesDefaultName)
		value, _ := json.Marshal(rules)
		zb := utils.GzipBytes(value)
		if err := cluster.PutBinary(key, zb); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
		}
		log.WithFields(log.Fields{"value": string(value), "len": len(value), "zb": len(zb)}).Debug("")
	}
*/

func updateDlpRuleNetwork() {
	if !isLeader() {
		return
	}
	cacheMutexRLock()
	newWlDlpRules := calculateGroupDlpRulesFromCache()
	newWlWafRules := calculateGroupWafRulesFromCache()
	newWlDlpRules.DlpRuleList = append(newWlDlpRules.DlpRuleList, newWlWafRules.DlpRuleList...)
	newWlDlpRules.DlpWlRules = append(newWlDlpRules.DlpWlRules, newWlWafRules.DlpWlRules...)
	cacheMutexRUnlock()
	putDlpWorkloadRulesToClusterScale(newWlDlpRules)
}

func scheduleDlpRuleCalculation(fast bool) {
	if fast {
		dlpCalculatingTimer.Reset(dlpCalculatingDelayFast)
	} else {
		dlpCalculatingTimer.Reset(dlpCalculatingDelaySlow)
	}
}

// if sensor is used by group, it cannot be deleted
// so delete a sensor no need to propagate to enforcer
func deleteDlpRuleNetwork(sensor string) {
	if !isLeader() {
		return
	}
	log.WithFields(log.Fields{"sensor": sensor}).Debug("")
	key := share.CLUSDlpRuleKey(sensor)
	_ = cluster.Delete(key)
}

func getDlpRuleFromDefaultSensor(entry string) *share.CLUSDlpRule {
	if cdr, ok := dlpSensors[share.CLUSDlpDefaultSensor]; ok {
		if cdre, ok1 := cdr.RuleList[entry]; ok1 {
			return cdre
		}
		return nil
	}
	return nil
}

func getPreDlpRuleFromDefaultSensor(entry string) []*share.CLUSDlpRule {
	if cdr, ok := dlpSensors[share.CLUSDlpDefaultSensor]; ok {
		if cdrelist, ok1 := cdr.PreRuleList[entry]; ok1 {
			return cdrelist
		}
		return nil
	}
	return nil
}

func getCombinedDlpSensorRuleName(rname string) string {
	var sname string = ""
	if sens, ok := dlpRuleSensors[rname]; ok {
		if sens.Cardinality() > 0 { //sensor and rule are one <=> one mapping
			sname = sens.ToStringSlice()[0]
		}
	}
	if sname == "" {
		return common.GetOrigDlpRuleName(rname)
	} else {
		return fmt.Sprintf("%s.%s", sname, common.GetOrigDlpRuleName(rname))
	}
}

func (m *CacheMethod) GetDlpRule(rulename string, acc *access.AccessControl) (*api.RESTDlpRuleDetail, error) {
	log.WithFields(log.Fields{"rule_entry": rulename}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	//rule entry + sensor(s) that used rule
	resp := api.RESTDlpRuleDetail{
		Sensors: make([]string, 0),
		Rules:   make([]*api.RESTDlpRule, 0),
	}
	cdre := getDlpRuleFromDefaultSensor(rulename)
	if cdre != nil { //user created rule
		if !acc.Authorize(cdre, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		rdre := &api.RESTDlpRule{
			Name:    cdre.Name,
			ID:      cdre.ID,
			CfgType: cfgTypeMapping[cdre.CfgType],
		}
		for _, cpt := range cdre.Patterns {
			if cpt.Context == "" {
				cpt.Context = share.DlpPatternContextDefault
			}
			rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
				Key:     cpt.Key,
				Value:   cpt.Value,
				Op:      cpt.Op,
				Context: cpt.Context,
			})
		}
		resp.Rules = append(resp.Rules, rdre)
	} else { //try predefined rule
		cdrelist := getPreDlpRuleFromDefaultSensor(rulename)
		if cdrelist == nil {
			return nil, common.ErrObjectAccessDenied
		}
		for idx, cdre := range cdrelist {
			if idx == 0 && !acc.Authorize(cdre, nil) {
				return nil, common.ErrObjectAccessDenied
			}
			rdre := &api.RESTDlpRule{
				Name:    cdre.Name,
				ID:      cdre.ID,
				CfgType: cfgTypeMapping[cdre.CfgType],
			}
			for _, cpt := range cdre.Patterns {
				if cpt.Context == "" {
					cpt.Context = share.DlpPatternContextDefault
				}
				rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
					Key:     cpt.Key,
					Value:   cpt.Value,
					Op:      cpt.Op,
					Context: cpt.Context,
				})
			}
			resp.Rules = append(resp.Rules, rdre)
		}
	}
	if st, ok := dlpRuleSensors[rulename]; ok {
		for ss := range st.Iter() {
			resp.Sensors = append(resp.Sensors, ss.(string))
		}
	}
	return &resp, nil
}

func (m *CacheMethod) GetDlpSensor(sensor string, acc *access.AccessControl) (*api.RESTDlpSensor, error) {
	log.WithFields(log.Fields{"sensor": sensor}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cdr, ok := dlpSensors[sensor]; ok {
		if !acc.Authorize(cdr, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		resp := api.RESTDlpSensor{
			Name:      cdr.Name,
			GroupList: make([]string, 0),
			RuleList:  make([]*api.RESTDlpRule, 0),
			Comment:   cdr.Comment,
			Predefine: cdr.Predefine,
		}
		resp.CfgType = cfgTypeMapping[cdr.CfgType]

		for name := range cdr.Groups {
			resp.GroupList = append(resp.GroupList, name)
		}

		if cdr.Name == share.CLUSDlpDefaultSensor {
			//user created rule
			for _, cdre := range cdr.RuleList {
				rdre := &api.RESTDlpRule{
					Name:    cdre.Name,
					ID:      cdre.ID,
					CfgType: cfgTypeMapping[cdre.CfgType],
				}
				for _, cpt := range cdre.Patterns {
					if cpt.Context == "" {
						cpt.Context = share.DlpPatternContextDefault
					}
					rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
						Key:     cpt.Key,
						Value:   cpt.Value,
						Op:      cpt.Op,
						Context: cpt.Context,
					})
				}
				resp.RuleList = append(resp.RuleList, rdre)
			}
			//predefined rule
			for _, cdrelist := range cdr.PreRuleList {
				for _, cdre := range cdrelist {
					rdre := &api.RESTDlpRule{
						Name:    cdre.Name,
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				}
			}
		} else {
			for _, cdrename := range cdr.RuleListNames {
				cdre := getDlpRuleFromDefaultSensor(cdrename)
				if cdre != nil {
					rdre := &api.RESTDlpRule{
						Name:    common.GetOrigDlpRuleName(cdrename),
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				} else { //try predefined rule
					cdrelist := getPreDlpRuleFromDefaultSensor(cdrename)
					for _, cdre := range cdrelist {
						rdre := &api.RESTDlpRule{
							Name:    common.GetOrigDlpRuleName(cdre.Name),
							ID:      cdre.ID,
							CfgType: cfgTypeMapping[cdre.CfgType],
						}
						for _, cpt := range cdre.Patterns {
							if cpt.Context == "" {
								cpt.Context = share.DlpPatternContextDefault
							}
							rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
								Key:     cpt.Key,
								Value:   cpt.Value,
								Op:      cpt.Op,
								Context: cpt.Context,
							})
						}
						resp.RuleList = append(resp.RuleList, rdre)
					}
				}
			}
		}
		sort.Slice(resp.RuleList, func(i, j int) bool {
			return resp.RuleList[i].Name < resp.RuleList[j].Name
		})
		return &resp, nil
	}
	return nil, common.ErrObjectNotFound
}

// default sensor contains all dlpruleentries, REST API for GUI
func (m *CacheMethod) GetDlpRules(acc *access.AccessControl) ([]*api.RESTDlpRule, error) {
	if sensor, err := m.GetDlpSensor(share.CLUSDlpDefaultSensor, acc); err != nil {
		return nil, err
	} else {
		return sensor.RuleList, nil
	}
}

func (m *CacheMethod) GetAllDlpSensors(acc *access.AccessControl) []*api.RESTDlpSensor {
	log.Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ret := make([]*api.RESTDlpSensor, 0)
	for _, cdr := range dlpSensors {
		if !acc.Authorize(cdr, nil) {
			continue
		}
		if cdr.Name == share.CLUSDlpDefaultSensor {
			continue
		}
		resp := api.RESTDlpSensor{
			Name:      cdr.Name,
			GroupList: make([]string, 0),
			RuleList:  make([]*api.RESTDlpRule, 0),
			Comment:   cdr.Comment,
			Predefine: cdr.Predefine,
		}
		resp.CfgType = cfgTypeMapping[cdr.CfgType]
		for name := range cdr.Groups {
			resp.GroupList = append(resp.GroupList, name)
		}
		if cdr.Name == share.CLUSDlpDefaultSensor {
			//user created rule
			for _, cdre := range cdr.RuleList {
				rdre := &api.RESTDlpRule{
					Name:    cdre.Name,
					ID:      cdre.ID,
					CfgType: cfgTypeMapping[cdre.CfgType],
				}
				for _, cpt := range cdre.Patterns {
					if cpt.Context == "" {
						cpt.Context = share.DlpPatternContextDefault
					}
					rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
						Key:     cpt.Key,
						Value:   cpt.Value,
						Op:      cpt.Op,
						Context: cpt.Context,
					})
				}
				resp.RuleList = append(resp.RuleList, rdre)
			}
			//predefined rule
			for _, cdrelist := range cdr.PreRuleList {
				for _, cdre := range cdrelist {
					rdre := &api.RESTDlpRule{
						Name:    cdre.Name,
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				}
			}
		} else {
			for _, cdrename := range cdr.RuleListNames {
				cdre := getDlpRuleFromDefaultSensor(cdrename)
				if cdre != nil {
					rdre := &api.RESTDlpRule{
						Name:    common.GetOrigDlpRuleName(cdre.Name),
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				} else { //try predefined rule
					cdrelist := getPreDlpRuleFromDefaultSensor(cdrename)
					for _, cdre := range cdrelist {
						rdre := &api.RESTDlpRule{
							Name:    common.GetOrigDlpRuleName(cdre.Name),
							ID:      cdre.ID,
							CfgType: cfgTypeMapping[cdre.CfgType],
						}
						for _, cpt := range cdre.Patterns {
							if cpt.Context == "" {
								cpt.Context = share.DlpPatternContextDefault
							}
							rdre.Patterns = append(rdre.Patterns, api.RESTDlpCriteriaEntry{
								Key:     cpt.Key,
								Value:   cpt.Value,
								Op:      cpt.Op,
								Context: cpt.Context,
							})
						}
						resp.RuleList = append(resp.RuleList, rdre)
					}
				}
			}
		}
		sort.Slice(resp.RuleList, func(i, j int) bool {
			return resp.RuleList[i].Name < resp.RuleList[j].Name
		})
		ret = append(ret, &resp)
	}
	return ret
}

func (m *CacheMethod) IsDlpRuleUsedBySensor(rule string, acc *access.AccessControl) bool {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if st, ok := dlpRuleSensors[rule]; ok {
		return st.Cardinality() != 0
	}
	return false
}

func GetDlpGrpSensorAction(cg, sn string) string {
	if tsen, ok := dlpSensors[sn]; ok {
		if tact, ok1 := tsen.Groups[cg]; ok1 {
			return tact
		}
	}
	return share.DlpRuleActionAllow
}

func GetDlpOutsideGrpSensorAction(cg, sn string, out2ingrp map[string]map[string]string) string {
	if tgrps, ok := out2ingrp[cg]; ok {
		for tg := range tgrps {
			otact := GetDlpGrpSensorAction(tg, sn)
			if otact == share.DlpRuleActionDrop {
				return share.DlpRuleActionDrop
			}
		}
	}
	return share.DlpRuleActionAllow
}

func (m *CacheMethod) GetDlpGroup(group string, acc *access.AccessControl) (*api.RESTDlpGroup, error) {
	log.WithFields(log.Fields{"group": group}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cg, ok := dlpGroups[group]; ok {
		if acc.Authorize(cg, getAccessObjectFuncNoLock) {
			resp := api.RESTDlpGroup{
				Name:    cg.Name,
				Status:  cg.Status,
				Sensors: make([]*api.RESTDlpSetting, 0),
			}
			resp.CfgType = cfgTypeMapping[cg.CfgType]

			for _, cs := range cg.Sensors {
				rdsa := &api.RESTDlpSetting{
					Name:   cs.Name,
					Action: cs.Action,
				}
				if dlpsensor, ok1 := dlpSensors[cs.Name]; ok1 {
					rdsa.Comment = dlpsensor.Comment
					rdsa.CfgType = cfgTypeMapping[dlpsensor.CfgType]
					rdsa.Exist = true
					if dlpsensor.CfgType == share.SystemDefined {
						rdsa.Predefine = true
					}
				} else {
					rdsa.Exist = false
				}
				resp.Sensors = append(resp.Sensors, rdsa)
			}
			return &resp, nil
		} else {
			return nil, common.ErrObjectAccessDenied
		}
	}
	return nil, common.ErrObjectNotFound
}

func (m *CacheMethod) GetAllDlpGroup(acc *access.AccessControl) []*api.RESTDlpGroup {
	log.Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ret := make([]*api.RESTDlpGroup, 0)
	for _, cg := range dlpGroups {
		if !acc.Authorize(cg, getAccessObjectFuncNoLock) {
			continue
		}
		resp := api.RESTDlpGroup{
			Name:    cg.Name,
			Status:  cg.Status,
			Sensors: make([]*api.RESTDlpSetting, 0),
		}
		resp.CfgType = cfgTypeMapping[cg.CfgType]

		for _, cs := range cg.Sensors {
			rdsa := &api.RESTDlpSetting{
				Name:   cs.Name,
				Action: cs.Action,
			}
			if dlpsensor, ok1 := dlpSensors[cs.Name]; ok1 {
				rdsa.Comment = dlpsensor.Comment
				rdsa.CfgType = cfgTypeMapping[dlpsensor.CfgType]
				rdsa.Exist = true
				if dlpsensor.CfgType == share.SystemDefined {
					rdsa.Predefine = true
				}
			} else {
				rdsa.Exist = false
			}
			resp.Sensors = append(resp.Sensors, rdsa)
		}
		ret = append(ret, &resp)
	}
	return ret
}

func (m CacheMethod) DoesDlpSensorExist(name string, acc *access.AccessControl) (bool, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cdr, ok := dlpSensors[name]; ok {
		if !acc.Authorize(cdr, nil) {
			return false, common.ErrObjectAccessDenied
		}
		return true, nil
	}
	return false, common.ErrObjectNotFound
}

func (m CacheMethod) DlpSensorInGroups(sensor string) bool {
	cacheMutexLock()
	defer cacheMutexUnlock()

	cs := &share.CLUSDlpSetting{Name: sensor, Action: share.DlpRuleActionDrop}
	for _, cache := range dlpGroups {
		if cache == nil || cache.Sensors == nil {
			continue
		}
		if _, ok := common.FindSensorInDlpGroup(cache.Sensors, cs); ok {
			return true
		}
	}
	return false
}

func (m CacheMethod) GetDlpRuleSensorGroupById(id uint32) (string, string, *[]string) {
	cacheMutexLock()
	defer cacheMutexUnlock()
	var rname, sname string = "", ""
	var grpname []string = make([]string, 0)
	if rn, ok := dlpIdRule[id]; ok {
		rname = rn
		if sens, ok1 := dlpRuleSensors[rname]; ok1 {
			if sens.Cardinality() > 0 { //sensor and rule are one <=> one mapping
				sname = sens.ToStringSlice()[0]
				if cds, ok2 := dlpSensors[sname]; ok2 {
					if cds != nil {
						for grp := range cds.Groups {
							grpname = append(grpname, grp)
						}
					}
				}
			}
		}
	}
	return rname, sname, &grpname
}

func (m CacheMethod) GetDlpRuleNames() *[]string {
	cacheMutexLock()
	defer cacheMutexUnlock()
	var dlprulenames []string = make([]string, 0)

	if cdr, ok := dlpSensors[share.CLUSDlpDefaultSensor]; ok {
		//user created rule
		for rn := range cdr.RuleList {
			dlprulenames = append(dlprulenames, getCombinedDlpSensorRuleName(rn))
		}
		//predefined rule
		for prn := range cdr.PreRuleList {
			dlprulenames = append(dlprulenames, getCombinedDlpSensorRuleName(prn))
		}
		sort.Slice(dlprulenames, func(i, j int) bool {
			return dlprulenames[i] < dlprulenames[j]
		})
		return &dlprulenames
	}
	return nil
}
