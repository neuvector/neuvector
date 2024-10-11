package cache

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

var wafSensors map[string]*share.CLUSWafSensor = make(map[string]*share.CLUSWafSensor) //sensor name to sensor map
var wafRuleSensors map[string]utils.Set = make(map[string]utils.Set)                   //key is rule entry name, value is sensor name(currently one rule can be in one sensor only)
var wafGroupSensors map[string]utils.Set = make(map[string]utils.Set)                  //key is group name, value is sensors' name, active or not
var wafGroups map[string]*share.CLUSWafGroup = make(map[string]*share.CLUSWafGroup)    //key is group name, value is group's waf setting that contain sensors' name/action
var wafIdRule map[uint32]string = make(map[uint32]string)                              //key is rule id, value is rule name

// update waf rule from config
func wafRuleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	sensor := share.CLUSWafRuleKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var wafsensor share.CLUSWafSensor
		if err := json.Unmarshal(value, &wafsensor); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Fail to decode")
			return
		}

		cacheMutexLock()
		wafSensors[sensor] = &wafsensor
		if sensor != share.CLUSWafDefaultSensor {
			//rule entry always belong to default sensor, no need to
			//be in this map, this map check whether this rule entry
			//belong to other sensor(s) or not
			for _, cds := range wafRuleSensors {
				if cds != nil {
					if cds.Contains(sensor) {
						cds.Remove(sensor)
					}
				}
			}
			for _, cdrename := range wafsensor.RuleListNames {
				if wafRuleSensors[cdrename] == nil {
					wafRuleSensors[cdrename] = utils.NewSet()
				}
				wafRuleSensors[cdrename].Add(sensor)
			}
		} else {
			for id := range wafIdRule {
				delete(wafIdRule, id)
			}
			if wafIdRule == nil {
				wafIdRule = make(map[uint32]string)
			}
			for _, cdr := range wafsensor.RuleList {
				if cdr != nil {
					wafIdRule[cdr.ID] = cdr.Name
				}
			}
			for _, cdrl := range wafsensor.PreRuleList {
				if len(cdrl) > 0 {
					wafIdRule[cdrl[0].ID] = cdrl[0].Name
				}
			}
		}

		//sync with CLUSGroup
		syncWafClusGroup(sensor)

		for cg := range wafsensor.Groups {
			//group to sensors map
			if wafGroupSensors[cg] == nil {
				wafGroupSensors[cg] = utils.NewSet()
			}
			wafGroupSensors[cg].Add(sensor)
		}

		cacheMutexUnlock()
		scheduleDlpRuleCalculation(true)
		log.WithFields(log.Fields{"sensor": sensor}).Debug("Update")

	case cluster.ClusterNotifyDelete:
		updategrp := false
		cacheMutexLock()
		if wafsensor, ok := wafSensors[sensor]; ok {
			for cg := range wafsensor.Groups {
				if wafGroupSensors[cg] != nil && wafGroupSensors[cg].Contains(sensor) {
					updategrp = true
				}
			}
			for _, cdrename := range wafsensor.RuleListNames {
				if wafRuleSensors[cdrename] != nil {
					wafRuleSensors[cdrename].Remove(sensor)
				}
			}
			delete(wafSensors, sensor)
		}
		cacheMutexUnlock()
		if updategrp {
			scheduleDlpRuleCalculation(true)
		}
		deleteWafRuleNetwork(sensor)
	}
}

func isCreateWafGroup(group *share.CLUSGroup) bool {
	if group == nil || group.Kind != share.GroupKindContainer ||
		strings.HasPrefix(group.Name, api.FederalGroupPrefix) {
		return false
	}
	if _, ok := wafGroups[group.Name]; !ok {
		return true
	}

	return false
}

func createWafGroup(group string, cfgType share.TCfgType) {
	wafgroup := &share.CLUSWafGroup{
		Name:    group,
		Status:  true,
		Sensors: make([]*share.CLUSWafSetting, 0),
		CfgType: cfgType,
	}
	if err := clusHelper.PutWafGroup(wafgroup, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Put waf group fail")
	}
}

func wafGroupConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	group := share.CLUSWafGroupKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var wafgroup share.CLUSWafGroup
		if err := json.Unmarshal(value, &wafgroup); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Fail to decode")
			return
		}

		cacheMutexLock()
		wafGroups[group] = &wafgroup
		wafProcessGroup(&wafgroup)
		cacheMutexUnlock()

		scheduleDlpRuleCalculation(true)
		log.WithFields(log.Fields{"wafgroup": group}).Debug("Update")

	case cluster.ClusterNotifyDelete:
		cacheMutexLock()
		if wafgroup, ok := wafGroups[group]; ok {
			wafProcessGroupDel(wafgroup)
			delete(wafGroups, group)
		}
		cacheMutexUnlock()
		log.WithFields(log.Fields{"wafgroup": group}).Debug("Delete")
		//on cli group can be deleted even with non-zero members
		//on GUI group cannot be deleted with non-zero members
		//for cli's case, schedule recalculation
		scheduleDlpRuleCalculation(true)
	}
}

func syncWafClusGroup(sname string) {
	for grp, cgs := range wafGroupSensors { //loop through group->sensors mapping
		if cgs != nil && cgs.Contains(sname) {
			if dr, ok := wafSensors[sname]; ok {
				if _, ok1 := dr.Groups[grp]; !ok1 { //sensor is not used by group, not in sync
					if wafgrp, ok2 := wafGroups[grp]; ok2 { //need to sync with CLUSWafGroup
						if wafgrp != nil {
							log.WithFields(log.Fields{"wafgroup": wafgrp}).Debug("sync waf group")
							wafFillSensorGroup(wafgrp, sname)
						}
					}
				}
			}
			cgs.Remove(sname)
		}
	}
}

func wafFillSensorGroup(group *share.CLUSWafGroup, sensor string) {
	cs := &share.CLUSWafSetting{Name: sensor, Action: share.DlpRuleActionDrop}
	if idx, ok := common.FindSensorInWafGroup(group.Sensors, cs); ok {
		if dr, ok1 := wafSensors[sensor]; ok1 {
			if dr.Groups == nil {
				dr.Groups = make(map[string]string)
			}
			dr.Groups[group.Name] = group.Sensors[idx].Action
		}
	}
}
func wafProcessGroupDel(group *share.CLUSWafGroup) {
	if cgs, ok := wafGroupSensors[group.Name]; ok {
		for sen := range cgs.Iter() {
			sname := sen.(string)
			if dr, ok1 := wafSensors[sname]; ok1 {
				delete(dr.Groups, group.Name)
			}
		}
		wafGroupSensors[group.Name].Clear()
	}
	for _, sen := range group.Sensors {
		if dr, ok := wafSensors[sen.Name]; ok {
			delete(dr.Groups, group.Name)
		}
	}
}
func wafProcessGroup(group *share.CLUSWafGroup) {
	if cgs, ok := wafGroupSensors[group.Name]; ok {
		for sen := range cgs.Iter() {
			sname := sen.(string)
			if dr, ok1 := wafSensors[sname]; ok1 {
				delete(dr.Groups, group.Name)
			}
		}
		wafGroupSensors[group.Name].Clear()
	}
	if group.Status { //add/modify waf sensors for group
		for _, sen := range group.Sensors {
			if dr, ok := wafSensors[sen.Name]; ok {
				if dr.Groups == nil {
					dr.Groups = make(map[string]string)
				}
				dr.Groups[group.Name] = sen.Action
			} else {
				if dr := clusHelper.GetWafSensor(sen.Name); dr != nil {
					if dr.Groups == nil {
						dr.Groups = make(map[string]string)
					}
					dr.Groups[group.Name] = sen.Action
					wafSensors[sen.Name] = dr
					for _, cdrename := range dr.RuleListNames {
						if wafRuleSensors[cdrename] == nil {
							wafRuleSensors[cdrename] = utils.NewSet()
						}
						wafRuleSensors[cdrename].Add(sen.Name)
					}
				}
			}
			if wafGroupSensors[group.Name] == nil {
				wafGroupSensors[group.Name] = utils.NewSet()
			}
			wafGroupSensors[group.Name].Add(sen.Name)
		}
	} else { //delete waf sensors for group
		for _, sen := range group.Sensors {
			if dr, ok := wafSensors[sen.Name]; ok {
				delete(dr.Groups, group.Name)
			}
		}
		if sensors, ok := wafGroupSensors[group.Name]; ok && sensors != nil {
			sensors.Clear()
		}
	}
}

func assocWafWl2PolicyIds(grp string, senset utils.Set, outside_wl2sensor map[string]map[string]string,
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
						outside_wl2sensor[owlid][osname] = GetWafOutsideGrpSensorAction(ogrp, osname, out2ingrp)
					}
				} else {
					for osen := range senset.Iter() {
						osname := osen.(string)
						if _, ok := osam[osname]; !ok {
							osam[osname] = GetWafOutsideGrpSensorAction(ogrp, osname, out2ingrp)
						} else {
							otact := GetWafOutsideGrpSensorAction(ogrp, osname, out2ingrp)
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

func assocWafWl2Sensors(grp string, senset utils.Set, wl2sensors map[string]map[string]string, dsensors *utils.Set) {
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
					wl2sensors[wlid][sname] = GetWafGrpSensorAction(grp, sname)
				}
			} else {
				for sen := range senset.Iter() {
					sname := sen.(string)
					if _, ok := sam[sname]; !ok {
						sam[sname] = GetWafGrpSensorAction(grp, sname)
					} else {
						tact := GetWafGrpSensorAction(grp, sname)
						if tact == share.DlpRuleActionDrop {
							sam[sname] = tact
						}
					}
				}
			}
		}
	}
}

func processWafGroupPolicy(wl2sensors, outside_wl2sensor map[string]map[string]string,
	wl2policies, outside_wl2policies map[string]utils.Set, dsensors *utils.Set) {
	log.Debug("")
	for grp, senset := range wafGroupSensors {
		if senset.Cardinality() == 0 {
			continue
		}
		//configured group itself
		assocWafWl2Sensors(grp, senset, wl2sensors, dsensors)
		assocWafWl2PolicyIds(grp, senset, outside_wl2sensor, wl2policies, outside_wl2policies)
	}
}

func assocWafWl2RuleNames(wl2sensors, wl2rules map[string]map[string]string) {
	log.Debug("")
	for wlid, sens := range wl2sensors {
		for sname, act := range sens {
			if cdr, ok := wafSensors[sname]; ok {
				if cdr.Name == share.CLUSWafDefaultSensor {
					//user created rule
					for _, cdre := range cdr.RuleList {
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

func listWafRuleEntriesForSens(wafrulemap map[string][]*share.CLUSWafRule, dsensors utils.Set) {
	if dsensors.Contains(share.CLUSWafDefaultSensor) {
		//default sensor contains all rule entries
		if cdr, ok := wafSensors[share.CLUSWafDefaultSensor]; ok {
			//user defined rule
			for _, cdre := range cdr.RuleList {
				if wafrulemap[cdre.Name] == nil {
					wafrulemap[cdre.Name] = make([]*share.CLUSWafRule, 0)
				}
				wafrulemap[cdre.Name] = append(wafrulemap[cdre.Name], cdre)
			}
			//predefined rule
			for _, cdrelist := range cdr.PreRuleList {
				for _, cdre := range cdrelist {
					if wafrulemap[cdre.Name] == nil {
						wafrulemap[cdre.Name] = make([]*share.CLUSWafRule, 0)
					}
					wafrulemap[cdre.Name] = append(wafrulemap[cdre.Name], cdre)
				}
			}
		}
	} else {
		for dsen := range dsensors.Iter() {
			ds := dsen.(string)
			if cdr, ok := wafSensors[ds]; ok {
				for _, cdrename := range cdr.RuleListNames {
					//different sensor may use same rule
					if _, ok := wafrulemap[cdrename]; ok {
						continue
					}
					cdre := getWafRuleFromDefaultSensor(cdrename)
					if cdre != nil {
						if wafrulemap[cdre.Name] == nil {
							wafrulemap[cdre.Name] = make([]*share.CLUSWafRule, 0)
						}
						wafrulemap[cdre.Name] = append(wafrulemap[cdre.Name], cdre)
					} else { //predefined rule
						cdrelist := getPreWafRuleFromDefaultSensor(cdrename)
						for _, cdre := range cdrelist {
							if wafrulemap[cdre.Name] == nil {
								wafrulemap[cdre.Name] = make([]*share.CLUSWafRule, 0)
							}
							wafrulemap[cdre.Name] = append(wafrulemap[cdre.Name], cdre)
						}
					}
				}
			}
		}
	}
}

func reOrgWafWlRules(wl2rules, outside_wl2rules map[string]map[string]string, outside_wl2policies map[string]utils.Set) {
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

func getWafWlRules(cgdrs *share.CLUSWorkloadDlpRules, wl2rules map[string]map[string]string, wl2policies map[string]utils.Set, ruletype string) {
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
func printWafRuleMap(wafrulemap map[string][]*share.CLUSWafRule) {
	for _, drelist := range wafrulemap {
		for _, dre := range drelist {
			log.WithFields(log.Fields{"dre": *dre}).Debug("print wafrulemap")
		}
	}
}

func printDefaultWafRules(cgdrs *share.CLUSWorkloadDlpRules) {
	for _, rl := range cgdrs.DlpRuleList {
		log.WithFields(log.Fields{"rl": *rl}).Debug("WafRuleList")
	}
	for _, dl := range cgdrs.DlpWlRules {
		log.WithFields(log.Fields{"dl": *dl}).Debug("WafWlRules")
		for _, lrn := range dl.RuleListNames {
			log.WithFields(log.Fields{"listrulename": *lrn}).Debug("WafWlRules")
		}
	}
}
*/

func calculateGroupWafRulesFromCache() share.CLUSWorkloadDlpRules {
	log.Debug("")

	var wl2sensors map[string]map[string]string = make(map[string]map[string]string)
	var outside_wl2sensors map[string]map[string]string = make(map[string]map[string]string)
	var wl2policies map[string]utils.Set = make(map[string]utils.Set)
	var outside_wl2policies map[string]utils.Set = make(map[string]utils.Set)
	var dsensors utils.Set = utils.NewSet()
	var wl2rules map[string]map[string]string = make(map[string]map[string]string)
	var outside_wl2rules map[string]map[string]string = make(map[string]map[string]string)
	var wafrulemap map[string][]*share.CLUSWafRule = make(map[string][]*share.CLUSWafRule)

	//associate workload to sensors and get union of all sensors
	processWafGroupPolicy(wl2sensors, outside_wl2sensors, wl2policies, outside_wl2policies, &dsensors)

	//associate workload to rule names mapping
	assocWafWl2RuleNames(wl2sensors, wl2rules)
	assocWafWl2RuleNames(outside_wl2sensors, outside_wl2rules)

	//get all rule entries in all sensors
	if len(wl2sensors) > 0 {
		listWafRuleEntriesForSens(wafrulemap, dsensors)
		//printWafRuleMap(wafrulemap)
	}

	cgdrs := share.CLUSWorkloadDlpRules{
		DlpRuleList: make([]*share.CLUSDlpRule, 0),
		DlpWlRules:  make([]*share.CLUSDlpWorkloadRule, 0),
	}

	for _, drelist := range wafrulemap {
		for _, dre := range drelist {
			tdre := &share.CLUSDlpRule{
				Name:     dre.Name,
				ID:       dre.ID,
				Patterns: make([]share.CLUSDlpCriteriaEntry, 0),
			}
			for _, cpt := range dre.Patterns {
				tdre.Patterns = append(tdre.Patterns, share.CLUSDlpCriteriaEntry(cpt))
			}
			cgdrs.DlpRuleList = append(cgdrs.DlpRuleList, tdre)
		}
	}

	reOrgWafWlRules(wl2rules, outside_wl2rules, outside_wl2policies)
	getWafWlRules(&cgdrs, wl2rules, wl2policies, share.WafWlRuleIn)
	getWafWlRules(&cgdrs, outside_wl2rules, outside_wl2policies, share.WafWlRuleOut)

	//printDefaultWafRules(&cgdrs)
	return cgdrs
}

// if sensor is used by group, it cannot be deleted
// so delete a sensor no need to propagate to enforcer
func deleteWafRuleNetwork(sensor string) {
	if !isLeader() {
		return
	}
	log.WithFields(log.Fields{"sensor": sensor}).Debug("")
	key := share.CLUSWafRuleKey(sensor)
	_ = cluster.Delete(key)
}

func getWafRuleFromDefaultSensor(entry string) *share.CLUSWafRule {
	if cdr, ok := wafSensors[share.CLUSWafDefaultSensor]; ok {
		if cdre, ok1 := cdr.RuleList[entry]; ok1 {
			return cdre
		}
		return nil
	}
	return nil
}

func getPreWafRuleFromDefaultSensor(entry string) []*share.CLUSWafRule {
	if cdr, ok := wafSensors[share.CLUSWafDefaultSensor]; ok {
		if cdrelist, ok1 := cdr.PreRuleList[entry]; ok1 {
			return cdrelist
		}
		return nil
	}
	return nil
}

func getCombinedWafSensorRuleName(rname string) string {
	var sname string = ""
	if sens, ok := wafRuleSensors[rname]; ok {
		if sens.Cardinality() > 0 { //sensor and rule are one <=> one mapping
			sname = sens.ToStringSlice()[0]
		}
	}
	if sname == "" {
		return common.GetOrigWafRuleName(rname)
	} else {
		return fmt.Sprintf("%s.%s", sname, common.GetOrigWafRuleName(rname))
	}
}

func (m *CacheMethod) GetWafRule(rulename string, acc *access.AccessControl) (*api.RESTWafRuleDetail, error) {
	log.WithFields(log.Fields{"rule_entry": rulename}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	//rule entry + sensor(s) that used rule
	resp := api.RESTWafRuleDetail{
		Sensors: make([]string, 0),
		Rules:   make([]*api.RESTWafRule, 0),
	}
	cdre := getWafRuleFromDefaultSensor(rulename)
	if cdre != nil { //user created rule
		if !acc.Authorize(cdre, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		rdre := &api.RESTWafRule{
			Name:    cdre.Name,
			ID:      cdre.ID,
			CfgType: cfgTypeMapping[cdre.CfgType],
		}
		for _, cpt := range cdre.Patterns {
			if cpt.Context == "" {
				cpt.Context = share.DlpPatternContextDefault
			}
			rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
				Key:     cpt.Key,
				Value:   cpt.Value,
				Op:      cpt.Op,
				Context: cpt.Context,
			})
		}
		resp.Rules = append(resp.Rules, rdre)
	} else { //try predefined rule
		cdrelist := getPreWafRuleFromDefaultSensor(rulename)
		if cdrelist == nil {
			return nil, common.ErrObjectAccessDenied
		}
		for idx, cdre := range cdrelist {
			if idx == 0 && !acc.Authorize(cdre, nil) {
				return nil, common.ErrObjectAccessDenied
			}
			rdre := &api.RESTWafRule{
				Name:    cdre.Name,
				ID:      cdre.ID,
				CfgType: cfgTypeMapping[cdre.CfgType],
			}
			for _, cpt := range cdre.Patterns {
				if cpt.Context == "" {
					cpt.Context = share.DlpPatternContextDefault
				}
				rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
					Key:     cpt.Key,
					Value:   cpt.Value,
					Op:      cpt.Op,
					Context: cpt.Context,
				})
			}
			resp.Rules = append(resp.Rules, rdre)
		}
	}
	if st, ok := wafRuleSensors[rulename]; ok {
		for ss := range st.Iter() {
			resp.Sensors = append(resp.Sensors, ss.(string))
		}
	}
	return &resp, nil
}

func (m *CacheMethod) GetWafSensor(sensor string, acc *access.AccessControl) (*api.RESTWafSensor, error) {
	log.WithFields(log.Fields{"sensor": sensor}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cdr, ok := wafSensors[sensor]; ok {
		if !acc.Authorize(cdr, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		resp := api.RESTWafSensor{
			Name:      cdr.Name,
			GroupList: make([]string, 0),
			RuleList:  make([]*api.RESTWafRule, 0),
			Comment:   cdr.Comment,
			Predefine: cdr.Predefine,
			CfgType:   cfgTypeMapping[cdr.CfgType],
		}

		for name := range cdr.Groups {
			resp.GroupList = append(resp.GroupList, name)
		}

		if cdr.Name == share.CLUSWafDefaultSensor {
			//user created rule
			for _, cdre := range cdr.RuleList {
				rdre := &api.RESTWafRule{
					Name:    cdre.Name,
					ID:      cdre.ID,
					CfgType: cfgTypeMapping[cdre.CfgType],
				}
				for _, cpt := range cdre.Patterns {
					if cpt.Context == "" {
						cpt.Context = share.DlpPatternContextDefault
					}
					rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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
					rdre := &api.RESTWafRule{
						Name:    cdre.Name,
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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
				cdre := getWafRuleFromDefaultSensor(cdrename)
				if cdre != nil {
					rdre := &api.RESTWafRule{
						Name:    common.GetOrigWafRuleName(cdrename),
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				} else { //try predefined rule
					cdrelist := getPreWafRuleFromDefaultSensor(cdrename)
					for _, cdre := range cdrelist {
						rdre := &api.RESTWafRule{
							Name:    common.GetOrigWafRuleName(cdre.Name),
							ID:      cdre.ID,
							CfgType: cfgTypeMapping[cdre.CfgType],
						}
						for _, cpt := range cdre.Patterns {
							if cpt.Context == "" {
								cpt.Context = share.DlpPatternContextDefault
							}
							rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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

// default sensor contains all waf rule entries, REST API for GUI
func (m *CacheMethod) GetWafRules(acc *access.AccessControl) ([]*api.RESTWafRule, error) {
	if sensor, err := m.GetWafSensor(share.CLUSWafDefaultSensor, acc); err != nil {
		return nil, err
	} else {
		return sensor.RuleList, nil
	}
}

func (m *CacheMethod) GetAllWafSensors(acc *access.AccessControl) []*api.RESTWafSensor {
	log.Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ret := make([]*api.RESTWafSensor, 0)
	for _, cdr := range wafSensors {
		if !acc.Authorize(cdr, nil) {
			continue
		}
		if cdr.Name == share.CLUSWafDefaultSensor {
			continue
		}
		resp := api.RESTWafSensor{
			Name:      cdr.Name,
			GroupList: make([]string, 0),
			RuleList:  make([]*api.RESTWafRule, 0),
			Comment:   cdr.Comment,
			Predefine: cdr.Predefine,
			CfgType:   cfgTypeMapping[cdr.CfgType],
		}
		for name := range cdr.Groups {
			resp.GroupList = append(resp.GroupList, name)
		}
		if cdr.Name == share.CLUSWafDefaultSensor {
			//user created rule
			for _, cdre := range cdr.RuleList {
				rdre := &api.RESTWafRule{
					Name:    cdre.Name,
					ID:      cdre.ID,
					CfgType: cfgTypeMapping[cdre.CfgType],
				}
				for _, cpt := range cdre.Patterns {
					if cpt.Context == "" {
						cpt.Context = share.DlpPatternContextDefault
					}
					rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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
					rdre := &api.RESTWafRule{
						Name:    cdre.Name,
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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
				cdre := getWafRuleFromDefaultSensor(cdrename)
				if cdre != nil {
					rdre := &api.RESTWafRule{
						Name:    common.GetOrigWafRuleName(cdre.Name),
						ID:      cdre.ID,
						CfgType: cfgTypeMapping[cdre.CfgType],
					}
					for _, cpt := range cdre.Patterns {
						if cpt.Context == "" {
							cpt.Context = share.DlpPatternContextDefault
						}
						rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
							Key:     cpt.Key,
							Value:   cpt.Value,
							Op:      cpt.Op,
							Context: cpt.Context,
						})
					}
					resp.RuleList = append(resp.RuleList, rdre)
				} else { //try predefined rule
					cdrelist := getPreWafRuleFromDefaultSensor(cdrename)
					for _, cdre := range cdrelist {
						rdre := &api.RESTWafRule{
							Name:    common.GetOrigWafRuleName(cdre.Name),
							ID:      cdre.ID,
							CfgType: cfgTypeMapping[cdre.CfgType],
						}
						for _, cpt := range cdre.Patterns {
							if cpt.Context == "" {
								cpt.Context = share.DlpPatternContextDefault
							}
							rdre.Patterns = append(rdre.Patterns, api.RESTWafCriteriaEntry{
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

func (m *CacheMethod) IsWafRuleUsedBySensor(rule string, acc *access.AccessControl) (bool, share.TCfgType) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	var cfgType share.TCfgType
	if st, ok := wafRuleSensors[rule]; ok {
		if st.Cardinality() == 0 {
			return false, 0
		}
		for sName := range st.Iter() {
			if wafsensor, ok := wafSensors[sName.(string)]; ok {
				cfgType = wafsensor.CfgType
				break
			}
		}
		return true, cfgType
	}
	return false, 0
}

func GetWafGrpSensorAction(cg, sn string) string {
	if tsen, ok := wafSensors[sn]; ok {
		if tact, ok1 := tsen.Groups[cg]; ok1 {
			return tact
		}
	}
	return share.DlpRuleActionAllow
}

func GetWafOutsideGrpSensorAction(cg, sn string, out2ingrp map[string]map[string]string) string {
	if tgrps, ok := out2ingrp[cg]; ok {
		for tg := range tgrps {
			otact := GetWafGrpSensorAction(tg, sn)
			if otact == share.DlpRuleActionDrop {
				return share.DlpRuleActionDrop
			}
		}
	}
	return share.DlpRuleActionAllow
}

func (m *CacheMethod) GetWafGroup(group string, acc *access.AccessControl) (*api.RESTWafGroup, error) {
	log.WithFields(log.Fields{"group": group}).Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if cg, ok := wafGroups[group]; ok {
		if acc.Authorize(cg, getAccessObjectFuncNoLock) {
			resp := api.RESTWafGroup{
				Name:    cg.Name,
				Status:  cg.Status,
				Sensors: make([]*api.RESTWafSetting, 0),
			}
			resp.CfgType = cfgTypeMapping[cg.CfgType]

			for _, cs := range cg.Sensors {
				rdsa := &api.RESTWafSetting{
					Name:   cs.Name,
					Action: cs.Action,
				}
				if wafsensor, ok1 := wafSensors[cs.Name]; ok1 {
					rdsa.Comment = wafsensor.Comment
					rdsa.CfgType = cfgTypeMapping[wafsensor.CfgType]
					rdsa.Exist = true
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

func (m *CacheMethod) GetAllWafGroup(acc *access.AccessControl) []*api.RESTWafGroup {
	log.Debug("")
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	ret := make([]*api.RESTWafGroup, 0)
	for _, cg := range wafGroups {
		if !acc.Authorize(cg, getAccessObjectFuncNoLock) {
			continue
		}
		resp := api.RESTWafGroup{
			Name:    cg.Name,
			Status:  cg.Status,
			Sensors: make([]*api.RESTWafSetting, 0),
		}
		resp.CfgType = cfgTypeMapping[cg.CfgType]

		for _, cs := range cg.Sensors {
			rdsa := &api.RESTWafSetting{
				Name:   cs.Name,
				Action: cs.Action,
			}
			if wafsensor, ok1 := wafSensors[cs.Name]; ok1 {
				rdsa.Comment = wafsensor.Comment
				rdsa.CfgType = cfgTypeMapping[wafsensor.CfgType]
				rdsa.Exist = true
			} else {
				rdsa.Exist = false
			}
			resp.Sensors = append(resp.Sensors, rdsa)
		}
		ret = append(ret, &resp)
	}
	return ret
}

func (m CacheMethod) DoesWafSensorExist(name string, acc *access.AccessControl) (bool, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cdr, ok := wafSensors[name]; ok {
		if !acc.Authorize(cdr, nil) {
			return false, common.ErrObjectAccessDenied
		}
		return true, nil
	}
	return false, common.ErrObjectNotFound
}

func (m CacheMethod) WafSensorInGroups(sensor string) bool {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	cs := &share.CLUSWafSetting{Name: sensor, Action: share.DlpRuleActionDrop}
	for _, cache := range wafGroups {
		if cache == nil || cache.Sensors == nil {
			continue
		}
		if _, ok := common.FindSensorInWafGroup(cache.Sensors, cs); ok {
			return true
		}
	}
	return false
}

func (m CacheMethod) GetWafRuleSensorGroupById(id uint32) (string, string, *[]string) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	var rname, sname string = "", ""
	var grpname []string = make([]string, 0)
	if rn, ok := wafIdRule[id]; ok {
		rname = rn
		if sens, ok1 := wafRuleSensors[rname]; ok1 {
			if sens.Cardinality() > 0 { //sensor and rule are one <=> one mapping
				sname = sens.ToStringSlice()[0]
				if cds, ok2 := wafSensors[sname]; ok2 {
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

func (m CacheMethod) GetWafRuleNames() *[]string {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	var wafrulenames []string = make([]string, 0)

	if cdr, ok := wafSensors[share.CLUSWafDefaultSensor]; ok {
		//user created rule
		for rn := range cdr.RuleList {
			wafrulenames = append(wafrulenames, getCombinedWafSensorRuleName(rn))
		}
		//predefined rule
		for prn := range cdr.PreRuleList {
			wafrulenames = append(wafrulenames, getCombinedWafSensorRuleName(prn))
		}
		sort.Slice(wafrulenames, func(i, j int) bool {
			return wafrulenames[i] < wafrulenames[j]
		})
		return &wafrulenames
	}
	return nil
}
