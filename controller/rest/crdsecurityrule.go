package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	cmetav1 "github.com/neuvector/k8s/apis/meta/v1"

	//	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spaolacci/murmur3"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
)

type nvCrdHandler struct {
	kvLocked bool
	lockKey  string
	lock     cluster.LockInterface
	acc      *access.AccessControl
}

type nvCrdParser struct {
}

func (h *nvCrdHandler) Init(lockKey string) {
	h.lockKey = lockKey
	h.acc = access.NewReaderAccessControl()
}

func (h *nvCrdHandler) AcquireLock(wait time.Duration) bool {
	if h.kvLocked {
		return true
	}

	if h.lockKey != "" {
		var err error
		h.lock, err = clusHelper.AcquireLock(h.lockKey, wait)
		if err != nil {
			e := "Failed to acquire cluster lock"
			log.WithFields(log.Fields{"error": err}).Error(e)
			return false
		}
		h.kvLocked = true
	}

	return true
}

func (h *nvCrdHandler) ReleaseLock() {
	if !h.kvLocked {
		return
	}

	if h.lock != nil {
		clusHelper.ReleaseLock(h.lock)
	}
	h.kvLocked = false
}

func group2RESTConfig(group *api.RESTGroup) *api.RESTCrdGroupConfig {

	criteria := make([]api.RESTCriteriaEntry, len(group.Criteria))
	for i, crt := range group.Criteria {
		criteria[i] = api.RESTCriteriaEntry{
			Key: crt.Key, Value: crt.Value, Op: crt.Op,
		}
	}

	r := api.RESTCrdGroupConfig{
		Name:     group.Name,
		Comment:  group.Comment,
		Criteria: &criteria,
	}
	return &r
}

func crdConfig2groupConfig(group *api.RESTCrdGroupConfig) *api.RESTGroupConfig {
	r := api.RESTGroupConfig{
		Name:     group.Name,
		Criteria: group.Criteria,
		CfgType:  api.CfgTypeGround,
		Comment:  &group.Comment,
	}
	if r.Criteria != nil {
		entries := *r.Criteria
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Key != entries[j].Key {
				return entries[i].Key < entries[j].Key
			} else {
				return entries[i].Value < entries[j].Value
			}
		})
		r.Criteria = &entries
	}
	return &r
}

func CrdDelAll(k8sKind, kvCrdKind, lockKey string, recordList map[string]*share.CLUSCrdSecurityRule) []string {
	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}

	var crdHandler nvCrdHandler
	crdHandler.Init(lockKey)
	if !crdHandler.AcquireLock(clusterLockWait) {
		return nil
	}
	defer crdHandler.ReleaseLock()

	return crdHandler.crdDelAll(k8sKind, kvCrdKind, recordList)
}

func (h *nvCrdHandler) crdDelAll(k8sKind, kvCrdKind string, recordList map[string]*share.CLUSCrdSecurityRule) []string {
	var removed []string
	if recordList == nil {
		recordList = clusHelper.GetCrdSecurityRuleRecordList(kvCrdKind)
	}
	for recordName, gw := range recordList {
		tokens := strings.Split(recordName, "-")
		if tokens[0] != k8sKind {
			continue
		}
		e := fmt.Sprintf("    %s %s related config removed by cross check due to this crd removed from Kubernate\n", k8sKind, tokens[2])
		removed = append(removed, e)
		switch k8sKind {
		case resource.NvAdmCtrlSecurityRuleKind:
			h.crdDeleteAdmCtrlRules()
			setAdmCtrlStateInCluster(nil, nil, nil, nil, nil, share.UserCreated)
			h.crdDeleteRecord(k8sKind, recordName)
		case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
			h.crdDeleteRules(gw.Rules)
			h.crdHandleGroupRecordDel(gw, gw.Groups, false)
			h.crdDeleteRecordEx(resource.NvSecurityRuleKind, recordName, gw.ProfileName)
		case resource.NvDlpSecurityRuleKind:
			deleteDlpSensor(nil, gw.DlpSensor, share.ReviewTypeCRD, true, h.acc, nil)
			h.crdDeleteRecord(k8sKind, recordName)
		case resource.NvWafSecurityRuleKind:
			deleteWafSensor(nil, gw.WafSensor, share.ReviewTypeCRD, true, h.acc, nil)
			h.crdDeleteRecord(k8sKind, recordName)
		}
	}

	return removed
}

// Create all the group and return group added
func (h *nvCrdHandler) crdHandleGroupsAdd(groups []api.RESTCrdGroupConfig, targetGroup string) ([]string, bool) {
	// record the groups in a new record, then later compare with cached record to add/del
	var groupAdded []string
	var targetGroupDlpWAF bool
	for _, group := range groups {
		if group.Name == api.LearnedExternal || group.Name == api.AllHostGroup {
			updateKV := false
			cg, _, err := clusHelper.GetGroup(group.Name, h.acc)
			if cg == nil {
				log.WithFields(log.Fields{"error": err}).Error()
				cg = &share.CLUSGroup{
					Name:     group.Name,
					CfgType:  share.GroundCfg,
					Comment:  group.Comment,
					Reserved: true,
					Criteria: []share.CLUSCriteriaEntry{},
				}
				if group.Name == api.AllHostGroup {
					cg.Kind = share.GroupKindNode
					cg.PolicyMode = share.PolicyModeLearn   // default
					cg.ProfileMode = share.PolicyModeLearn  // default
					cg.BaselineProfile = share.ProfileBasic // group "nodes" is always at "basic" baseline profile(not configurable by design)
				} else {
					cg.Kind = share.GroupKindExternal
				}
				updateKV = true
			} else if cg.CfgType != share.GroundCfg {
				cg.CfgType = share.GroundCfg // update its type
				updateKV = true
			}
			if updateKV {
				clusHelper.PutGroup(cg, false)
			}
			groupAdded = append(groupAdded, group.Name)
			continue
		}

		isNvIpGroup := strings.HasPrefix(group.Name, api.LearnedSvcGroupPrefix)
		cg, _, _ := clusHelper.GetGroup(group.Name, h.acc)
		if cg != nil {
			// group update case
			updateKV := false
			if isNvIpGroup {
				// existing nv.ip.xxx group(learned or crd) found. promote it to crd if necessary
				if cg.CfgType != share.GroundCfg {
					if cg.CfgType == share.FederalCfg {
						log.WithFields(log.Fields{"group": group.Name, "cfgType": cg.CfgType}).Error()
					} else {
						cg.CfgType = share.GroundCfg
						updateKV = true
					}
				}
				if cg.Comment != group.Comment {
					cg.Comment = group.Comment
					updateKV = true
				}
			} else {
				updateKV = true
				cg.Criteria = nil
				cg.Kind = share.GroupKindContainer
				cg.CfgType = share.GroundCfg
				cg.Comment = group.Comment
				cg.Criteria = make([]share.CLUSCriteriaEntry, 0, len(*group.Criteria))
				for _, ct := range *group.Criteria {
					cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
						Key:   ct.Key,
						Value: ct.Value,
						Op:    ct.Op,
					})
					if ct.Key == share.CriteriaKeyAddress {
						cg.Kind = share.GroupKindAddress
					}
				}
			}
			if updateKV {
				if err := clusHelper.PutGroup(cg, false); err != nil {
					log.WithFields(log.Fields{"error": err}).Error()
					// cache.AuthLog(cache.LOGEV_GROUP_CREATE_FAILED)
					//return errors.New("Put groupd error")
					continue
				}
			}
			groupAdded = append(groupAdded, group.Name)
		} else {
			// new group add
			cg = &share.CLUSGroup{
				Name:           group.Name,
				CfgType:        share.GroundCfg,
				CreaterDomains: h.acc.GetAdminDomains(share.PERMS_RUNTIME_POLICIES),
				Kind:           share.GroupKindContainer,
				Comment:        group.Comment,
			}
			if isNvIpGroup {
				cg.Kind = share.GroupKindIPService
			}

			if utils.DoesGroupHavePolicyMode(group.Name) {
				cg.PolicyMode = cacher.GetNewServicePolicyMode()
				cg.BaselineProfile = cacher.GetNewServiceProfileBaseline()
				fmt.Printf("New learned svc  %s set service as %s, %s\n", group.Name, cg.PolicyMode, cg.BaselineProfile)
			}

			cg.Criteria = make([]share.CLUSCriteriaEntry, 0, len(*group.Criteria))
			for _, ct := range *group.Criteria {
				if isNvIpGroup && ct.Key != share.CriteriaKeyDomain {
					// when creating a new crd nv.ip.xxx group, only keep "domain" key in its criteria
					continue
				}
				cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
					Key:   ct.Key,
					Value: ct.Value,
					Op:    ct.Op,
				})
				if ct.Key == share.CriteriaKeyAddress {
					cg.Kind = share.GroupKindAddress
				}

				if ct.Key == share.CriteriaKeyDomain && strings.HasPrefix(group.Name, api.LearnedGroupPrefix) {
					cg.Domain = ct.Value
				}
			}
			if err := clusHelper.PutGroup(cg, true); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				//return errors.New("Put groupd error")
				continue
			}
			groupAdded = append(groupAdded, group.Name)
		}
		if cg.Name == targetGroup && cg.Kind == share.GroupKindContainer {
			targetGroupDlpWAF = true
		}
	}

	return groupAdded, targetGroupDlpWAF
}

func (h *nvCrdHandler) crdDeleteRules(delRules map[string]uint32) {
	if len(delRules) == 0 {
		return
	}

	txn := cluster.Transact()
	defer txn.Close()

	delRuleIDs := utils.NewSet()
	crhs := clusHelper.GetPolicyRuleList()
	crhsNew := make([]*share.CLUSRuleHead, 0, len(crhs))
	for _, id := range delRules {
		delRuleIDs.Add(id)
		clusHelper.DeletePolicyRuleTxn(txn, id)
	}
	for _, crh := range crhs {
		if crh.CfgType != share.GroundCfg || !delRuleIDs.Contains(crh.ID) {
			crhsNew = append(crhsNew, crh)
		}
	}
	clusHelper.PutPolicyRuleListTxn(txn, crhs)
	txn.Apply()
}

func (h *nvCrdHandler) crdDeleteAdmCtrlRules() {
	txn := cluster.Transact()
	defer txn.Close()

	for _, ruleType := range []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType} {
		arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType)
		ruleHead := make([]*share.CLUSRuleHead, 0, len(arhs))
		for _, arh := range arhs {
			if arh.CfgType == share.GroundCfg {
				if arh.ID < api.StartingLocalAdmCtrlRuleID {
					// default rules cannot be deleted
					if r := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, arh.ID); r != nil {
						if r.CfgType != share.UserCreated {
							r.CfgType = share.UserCreated
							clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, r)
						}
					}
					ruleHead = append(ruleHead, arh)
				} else {
					clusHelper.DeleteAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, arh.ID)
				}
			} else {
				ruleHead = append(ruleHead, arh)
			}
		}
		clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleType, ruleHead)
	}
	txn.Apply()
}

// Compare the added group with the group in the record, find the group removed from crd to delete
func findAbsentGroups(cacheRecord *share.CLUSCrdSecurityRule, groupNew []string) []string {
	var groupToDel []string

	for _, cur := range cacheRecord.Groups {
		found := false
		for _, newMember := range groupNew {
			if cur == newMember {
				found = true
				break
			}
		}
		if !found {
			groupToDel = append(groupToDel, cur)
		}
	}
	return groupToDel
}

func (h *nvCrdHandler) crdDeleteGroup(delGroup []string) {
	for _, name := range delGroup {
		cg, _, _ := clusHelper.GetGroup(name, h.acc)
		if cg == nil {
			log.WithFields(log.Fields{"name": name}).Error("Group doesn't exist")
			continue
		}
		kv.DeletePolicyByGroup(name)
		kv.DeleteResponseRuleByGroup(name)
		clusHelper.DeleteDlpGroup(name)
		clusHelper.DeleteWafGroup(name)
		if err := clusHelper.DeleteGroup(name); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			continue
		}
	}
}

func (h *nvCrdHandler) crdUpdateGroup(updateGroup []string) {
	txn := cluster.Transact()
	defer txn.Close()

	for _, name := range updateGroup {
		cg, _, _ := clusHelper.GetGroup(name, h.acc)
		if cg == nil {
			log.WithFields(log.Fields{"name": name}).Error("Group doesn't exist")
			continue
		}
		if utils.IsGroupLearned(name) || name == api.LearnedExternal {
			cg.CfgType = share.Learned
		} else {
			cg.CfgType = share.UserCreated
		}
		clusHelper.PutGroupTxn(txn, cg)

		dlpGroup := clusHelper.GetDlpGroup(name)
		if dlpGroup == nil {
			log.WithFields(log.Fields{"name": name}).Error("DLP group doesn't exist")
			continue
		}
		dlpGroup.CfgType = share.UserCreated
		clusHelper.PutDlpGroupTxn(txn, dlpGroup)

		wafGroup := clusHelper.GetWafGroup(name)
		if wafGroup == nil {
			log.WithFields(log.Fields{"name": name}).Error("WAF group doesn't exist")
			continue
		}
		wafGroup.CfgType = share.UserCreated
		clusHelper.PutWafGroupTxn(txn, wafGroup)
	}

	txn.Apply()
}

func (h *nvCrdHandler) crdUpdateDlpSensors() {
	txn := cluster.Transact()
	defer txn.Close()

	for _, sensor := range clusHelper.GetAllDlpSensors() {
		var modified bool
		if sensor.CfgType == share.GroundCfg {
			sensor.CfgType = share.UserCreated
			modified = true
		}
		if sensor.Name == share.CLUSDlpDefaultSensor {
			for _, rule := range sensor.RuleList {
				if rule.CfgType == share.GroundCfg {
					rule.CfgType = share.UserCreated
					modified = true
				}
			}
		}
		if modified {
			clusHelper.PutDlpSensorTxn(txn, sensor)
		}
	}

	txn.Apply()
}

func (h *nvCrdHandler) crdUpdateWafSensors() {
	txn := cluster.Transact()
	defer txn.Close()

	for _, sensor := range clusHelper.GetAllWafSensors() {
		var modified bool
		if sensor.CfgType == share.GroundCfg {
			sensor.CfgType = share.UserCreated
			modified = true
		}
		if sensor.Name == share.CLUSWafDefaultSensor {
			for _, rule := range sensor.RuleList {
				if rule.CfgType == share.GroundCfg {
					rule.CfgType = share.UserCreated
					modified = true
				}
			}
		}
		if modified {
			clusHelper.PutWafSensorTxn(txn, sensor)
		}
	}

	txn.Apply()
}

// Group removed from the CRD, try delete from system.
// 1. If group not created by crd then ignore process
// 2. If Group have memeber+LearnedName, then don't remove but rather change cfgtype(add to update)
// 3. If Group also exist on  other crd, then ignore process
// 4. If Group have autolearned or user created policy, then change cfgtype(add to update)

func (h *nvCrdHandler) crdHandleGroupRecordDel(cacheRecord *share.CLUSCrdSecurityRule, groupsDel []string, kvOnly bool) {
	if len(groupsDel) == 0 {
		return
	}

	var groupToUpdate []string
	var groupToDel []string

	gwrecordlist := clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
LOOPALLDEL:
	for _, cur := range groupsDel {
		for recordName, gw := range gwrecordlist {
			if recordName == cacheRecord.Name {
				continue
			}
			// if the group find on another CRD, then do nothing
			for _, gwgroup := range gw.Groups {
				if cur == gwgroup {
					continue LOOPALLDEL
				}
			}
		}
		// at this point no crd using the group
		// In cfg import case can't relay on cacher as at this point, can't be sure cacher is written
		// in regular case check if group was used by user created policy.
		// however, in restart case, this function could be called before any group/policy kv callback is called.
		// in this case the group & all policies related to it will be deleted.
		if kvOnly {
			groupToUpdate = append(groupToUpdate, cur)
		} else {
			group, _ := cacher.GetGroup(cur, "", false, h.acc)
			if group != nil {
				// if group exist before crd apply when delete we should not touch it
				if group.CfgType != api.CfgTypeGround {
					continue LOOPALLDEL
				}

				if strings.HasPrefix(group.Name, api.LearnedSvcGroupPrefix) {
					// nv.ip crd groups are created without address criterion. address criterion is learned later.
					// we delete nv.ip crd group only when its address is not learned yet
					for _, ct := range group.Criteria {
						if ct.Key == share.CriteriaKeyAddress {
							groupToUpdate = append(groupToUpdate, cur)
							continue LOOPALLDEL
						}
					}
				}

				// check other process and file proiles
				if !h.crdReadyToDeleteProfiles(cacheRecord.Name, group) {
					groupToUpdate = append(groupToUpdate, cur)
					continue LOOPALLDEL
				}

				// crd created as learned group, now it has member in it. we should convert.
				if strings.HasPrefix(group.Name, api.LearnedGroupPrefix) && len(group.Members) > 0 {
					groupToUpdate = append(groupToUpdate, cur)
					continue LOOPALLDEL
				}

				// crd created group but have user defined policy on it, we should convert
				for _, idx := range group.PolicyRules {
					if !isSecurityPolicyID(idx) {
						// keep the group but change to different CFGTYPE
						groupToUpdate = append(groupToUpdate, cur)
						continue LOOPALLDEL
					}
				}
			}
			groupToDel = append(groupToDel, cur)
		}
	}
	h.crdDeleteGroup(groupToDel)
	h.crdUpdateGroup(groupToUpdate)

}

func (h *nvCrdHandler) crdHandleProcessProfile(group, mode string, profile *api.RESTProcessProfile, reviewType share.TReviewType) error {
	var cfgType share.TCfgType = share.GroundCfg
	if reviewType == share.ReviewTypeImportGroup {
		cfgType = share.UserCreated
		txn := cluster.Transact()
		// force overwrite process profile kv key
		cacher.CreateProcessProfileTxn(txn, group, mode, profile.Baseline, cfgType)
		txn.Apply()
		txn.Close()
	}
	pp := clusHelper.GetProcessProfile(group)
	if pp == nil {
		cacher.CreateProcessProfile(group, mode, profile.Baseline, cfgType)
		pp = clusHelper.GetProcessProfile(group)
		if pp == nil {
			log.Error("failed to obtain profile") // failure at CreateProcessProfile()
			return fmt.Errorf("failed to obtain profile")
		}
	}

	if profile != nil {
		// update mode
		pp.Mode = mode
		pp.Baseline = profile.Baseline

		list := make([]*share.CLUSProcessProfileEntry, 0)
		if reviewType == share.ReviewTypeCRD {
			// remove all crd entries
			for i, proc := range pp.Process {
				if proc.CfgType != share.GroundCfg {
					list = append(list, pp.Process[i])
				}
			}
		}
		pp.Process = list

		// fill in the merge crd items
		for _, proc := range profile.ProcessList {
			p := &share.CLUSProcessProfileEntry{
				Name:            proc.Name,
				Path:            proc.Path,
				Action:          proc.Action,
				CfgType:         cfgType,
				Uuid:            ruleid.NewUuid(),
				AllowFileUpdate: proc.AllowFileUpdate,
			}
			if ret, ok := common.MergeProcess(pp.Process, p, true); ok {
				pp.Process = ret
			}
		}

		if err := clusHelper.PutProcessProfile(group, pp); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return err
		}
	}
	return nil
}

func (h *nvCrdHandler) crdHandleFileProfile(group, mode string, profile *api.RESTFileMonitorProfile, reviewType share.TReviewType) error {
	var cfgType share.TCfgType = share.GroundCfg
	bLearnedGrp := strings.HasPrefix(group, api.LearnedGroupPrefix) // exclude "nodes"
	if reviewType == share.ReviewTypeImportGroup {
		if bLearnedGrp {
			cfgType = share.Learned
		} else {
			cfgType = share.UserCreated
		}
		txn := cluster.Transact()
		// force overwrite file monitor/rule kv keys with default file rules
		cacher.CreateGroupFileMonitorTxn(txn, group, mode, cfgType)
		txn.Apply()
		txn.Close()
	}
	mon, rev_m := clusHelper.GetFileMonitorProfile(group)
	far, rev_a := clusHelper.GetFileAccessRule(group) // associated with "mon"
	if mon == nil || far == nil {
		cacher.CreateGroupFileMonitor(group, mode, cfgType)
		mon, rev_m = clusHelper.GetFileMonitorProfile(group)
		far, rev_a = clusHelper.GetFileAccessRule(group)
	}

	if far.Filters == nil {
		far.Filters = make(map[string]*share.CLUSFileAccessFilterRule)
	}

	if far.FiltersCRD == nil {
		far.FiltersCRD = make(map[string]*share.CLUSFileAccessFilterRule)
	}

	if profile != nil {
		pmap := make(map[string]*api.RESTFileMonitorFilter, len(profile.Filters))
		for _, ffp := range profile.Filters {
			// local reference
			pmap[ffp.Filter] = ffp
		}

		// deleting non-exist and updating CRD entry from the profile
		for i, ffm := range mon.FiltersCRD {
			ffp, ok := pmap[ffm.Filter] // same filter (primary key)
			if ok {
				mon.FiltersCRD[i].CustomerAdd = true
				mon.FiltersCRD[i].Behavior = ffp.Behavior
				mon.FiltersCRD[i].Recursive = ffp.Recursive
			} else {
				mon.FiltersCRD[i].Behavior = "delete" // invalid type
			}
		}

		// rebuild current file profile
		target := make([]share.CLUSFileMonitorFilter, 0)
		for _, ffm := range mon.FiltersCRD {
			if ffm.Behavior == "delete" {
				key := utils.FilterIndexKey(ffm.Path, ffm.Regex)
				delete(far.FiltersCRD, key)
				// Service group: do not remove predefined filter but turn it back
				predef, ok := cacher.IsPrdefineFileGroup(ffm.Filter, ffm.Recursive)
				if bLearnedGrp && ok {
					_, exist := far.Filters[key]
					if !exist {
						// log.WithFields(log.Fields{"Filter": ffm.Filter}).Debug("CRD: restore predefined")
						a := &share.CLUSFileAccessFilterRule{ // restore
							Apps:        make([]string, 0), // empty
							Behavior:    share.FileAccessBehaviorMonitor,
							CustomerAdd: false,
							CreatedAt:   time.Now().UTC(),
							UpdatedAt:   time.Now().UTC(),
						}
						far.Filters[key] = a
						mon.Filters = append(mon.Filters, *predef) // restore
					}
				}
				continue
			}
			target = append(target, ffm)
		}
		mon.FiltersCRD = target

		var monFilters []share.CLUSFileMonitorFilter
		var farFilters map[string]*share.CLUSFileAccessFilterRule
		if reviewType == share.ReviewTypeCRD {
			farFilters = far.FiltersCRD
		} else if reviewType == share.ReviewTypeImportGroup {
			monFilters = mon.Filters
			farFilters = far.Filters
		}

		// adding new CRD entries
		for _, ffp := range profile.Filters {
			// access filter
			base, regex, _ := parseFileFilter(ffp.Filter) // should be validated before
			key := utils.FilterIndexKey(base, regex)
			if a, exist := farFilters[key]; exist {
				a.Behavior = ffp.Behavior
				a.Apps = append([]string(nil), ffp.Apps...)
				a.UpdatedAt = time.Now().UTC()
				farFilters[key] = a
			} else {
				log.WithFields(log.Fields{"key": key, "behavior": ffp.Behavior}).Debug("CRD: new entry")
				if reviewType == share.ReviewTypeCRD {
					log.WithFields(log.Fields{"key": key, "behavior": ffp.Behavior}).Debug("CRD: new entry")
					if _, exist := far.Filters[key]; exist {
						if _, ok := cacher.IsPrdefineFileGroup(ffp.Filter, ffp.Recursive); ok {
							for i, _ := range mon.Filters {
								if mon.Filters[i].Filter == ffp.Filter && mon.Filters[i].CustomerAdd == false {
									// remove the predefined from the main filters
									delete(far.Filters, key)
									mon.Filters = append(mon.Filters[:i], mon.Filters[i+1:]...)
									break
								}
							}
						}
					}
				}

				a := &share.CLUSFileAccessFilterRule{
					CustomerAdd: true,
					Behavior:    ffp.Behavior,
					Apps:        append([]string(nil), ffp.Apps...),
					CreatedAt:   time.Now().UTC(),
					UpdatedAt:   time.Now().UTC(),
				}
				farFilters[key] = a

				f := &share.CLUSFileMonitorFilter{
					Filter:      ffp.Filter,
					Path:        base,
					Regex:       regex,
					Recursive:   ffp.Recursive,
					Behavior:    ffp.Behavior,
					CustomerAdd: true,
				}
				monFilters = append(monFilters, *f)
			}
		}

		if reviewType == share.ReviewTypeCRD {
			mon.FiltersCRD = monFilters
			far.FiltersCRD = farFilters
		} else if reviewType == share.ReviewTypeImportGroup {
			mon.Filters = monFilters
			far.Filters = farFilters
		}
	}

	if err := clusHelper.PutFileMonitorProfile(group, mon, rev_m); err != nil {
		log.WithFields(log.Fields{"error": err, "group": group}).Error("CRD: monitor file")
		return err
	}
	if err := clusHelper.PutFileAccessRule(group, far, rev_a); err != nil {
		log.WithFields(log.Fields{"error": err, "group": group}).Error("CRD: access file")
		return err
	}
	return nil
}

func (h *nvCrdHandler) crdHandlePolicyMode(policyModeCfg *api.RESTServiceConfig, profile_mode, baseline string) {
	if policyModeCfg != nil {
		grp, _, _ := clusHelper.GetGroup(policyModeCfg.Name, h.acc)
		if grp == nil {
			log.WithFields(log.Fields{"name": policyModeCfg.Name}).Error("Service doesn't exist or access denied")
			return
		}

		var changed bool = false
		if profile_mode != "" {
			if grp.ProfileMode != profile_mode {
				grp.ProfileMode = profile_mode
				changed = true
			}
		}

		if policyModeCfg.PolicyMode != nil {
			if grp.PolicyMode != *policyModeCfg.PolicyMode {
				grp.PolicyMode = *policyModeCfg.PolicyMode
				changed = true
			}
		}

		if baseline != "" {
			if grp.BaselineProfile != baseline {
				grp.BaselineProfile = baseline
				changed = true
			}
		}

		if changed {
			log.WithFields(log.Fields{"group": grp}).Debug("CRD:")
			err := configPolicyMode(grp)
			if err != nil {
				return
			}
			if err = clusHelper.PutGroup(grp, false); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				return
			}

		}
	}
}

func (h *nvCrdHandler) crdHandleRules(rules []api.RESTPolicyRuleConfig, cacheRecord *share.CLUSCrdSecurityRule) *map[string]uint32 {
	if len(rules) == 0 && len(cacheRecord.Rules) == 0 {
		// when there is no network rule in this crd record & we don't remember any network rule for this crd record as well,
		// return empty map which means this crd rule doesn't create any crd network policy
		ret := make(map[string]uint32)
		return &ret
	}
	var cr *share.CLUSPolicyRule
	crhs := clusHelper.GetPolicyRuleList()
	ids := utils.NewSet()
	ruleHead := make(map[uint32]*share.CLUSRuleHead)
	startIdx := 0 // the idx of first non-fed rule in crhs
	startFind := false
	endIdx := 0 // the idx of first non-fed/non-crd in crhs
	endFind := false
	for i, crh := range crhs {
		if crh.CfgType == share.GroundCfg {
			ids.Add(crh.ID)
			ruleHead[crh.ID] = crh
		}
		if crh.CfgType != share.FederalCfg {
			if !startFind {
				startIdx = i
				startFind = true
			}
			if crh.CfgType != share.GroundCfg && !endFind {
				endIdx = i
				endFind = true
			}
		}
	}

	news := make([]*share.CLUSRuleHead, 0)
	newRules := make(map[string]uint32, 0)

	txn := cluster.Transact()
	defer txn.Close()

	for _, ruleConf := range rules {
		if val, ok := cacheRecord.Rules[*ruleConf.Comment]; ok {
			ruleConf.ID = val
		} else {
			ruleConf.ID = common.GetAvailablePolicyID(ids, share.GroundCfg)
			cacheRecord.Rules[*ruleConf.Comment] = ruleConf.ID
			ids.Add(ruleConf.ID)
		}

		if cr, _ = clusHelper.GetPolicyRule(ruleConf.ID); cr == nil {
			cr = &share.CLUSPolicyRule{
				ID:        ruleConf.ID,
				CreatedAt: time.Now().UTC(),
				Disable:   false,
				CfgType:   share.GroundCfg,
			}
			news = append(news, &share.CLUSRuleHead{
				ID:       ruleConf.ID,
				CfgType:  share.GroundCfg,
				Priority: ruleConf.Priority,
			})
		} else {
			if _, ok := ruleHead[ruleConf.ID]; ok {
				ruleHead[ruleConf.ID].Priority = ruleConf.Priority
			} else {
				// We have issue with config lose, policy and rulehead may out of sync
				news = append(news, &share.CLUSRuleHead{
					ID:       ruleConf.ID,
					CfgType:  share.GroundCfg,
					Priority: ruleConf.Priority,
				})
			}
		}

		if ruleConf.From != nil {
			cr.From = *ruleConf.From
		}
		if ruleConf.To != nil {
			cr.To = *ruleConf.To
		}
		if ruleConf.Ports != nil {
			cr.Ports = *ruleConf.Ports
		}
		if ruleConf.Applications != nil {
			cr.Applications = appNames2IDs(*ruleConf.Applications)
		}
		if ruleConf.Action != nil {
			cr.Action = *ruleConf.Action
		}
		if ruleConf.Comment != nil {
			cr.Comment = *ruleConf.Comment
		}
		cr.LastModAt = time.Now().UTC()
		cr.Priority = ruleConf.Priority

		if err := clusHelper.PutPolicyRuleTxn(txn, cr); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			continue
		}
		newRules[*ruleConf.Comment] = ruleConf.ID
	}

	// Check if the rules in the cacheRecord not in the newRules added, if so delete it.
	for cacheName, cacheId := range cacheRecord.Rules {
		if newId, ok := newRules[cacheName]; ok && newId == cacheId {
			continue
		}
		clusHelper.DeletePolicyRuleTxn(txn, cacheId)
		delete(ruleHead, cacheId)
	}

	// Newly added crd rules merge with existing rule by priority order
	for _, v := range ruleHead {
		news = append(news, v)
	}

	sort.Slice(news[:], func(i, j int) bool {
		return news[i].Priority > news[j].Priority
	})

	var newPlus []*share.CLUSRuleHead // for: new CRD network rules + learned/user-created network rules
	if endFind {
		// there is non-fed/non-crd network rule so endIdx really means the idx of first non-fed/non-crd in crhs
		newPlus = append(news, crhs[endIdx:]...)
	} else {
		// there is no non-fed/non-crd network rule
		newPlus = news
	}
	crhs = append(crhs[:startIdx], newPlus...)
	clusHelper.PutPolicyRuleListTxn(txn, crhs)
	txn.Apply()
	return &newRules
}

func (h *nvCrdHandler) crdHandleAdmCtrlRules(scope string, allAdmCtrlRules map[string][]*resource.NvCrdAdmCtrlRule, cacheRecord *share.CLUSCrdSecurityRule,
	reviewType share.TReviewType) map[string]uint32 {

	var rulesCount int
	for _, rules := range allAdmCtrlRules {
		rulesCount += len(rules)
	}
	if rulesCount == 0 && len(cacheRecord.AdmCtrlRules) == 0 {
		// when there is no admission control rule in this crd record,
		// return empty map which means this crd rule doesn't create any crd admission control rule
		return make(map[string]uint32)
	} else if cacheRecord.AdmCtrlRules == nil {
		cacheRecord.AdmCtrlRules = make(map[string]uint32)
	}

	newRules := make(map[string]uint32, rulesCount)
	delRules := utils.NewSet()
	var cfgType share.TCfgType = share.GroundCfg
	if reviewType == share.ReviewTypeImportAdmCtrl {
		cfgType = share.UserCreated
	}

	txn := cluster.Transact()
	defer txn.Close()

	ids := utils.NewSet()
	crdIDs := utils.NewSet()
	clusArhsNew := make(map[string][]*share.CLUSRuleHead, 2)
	for _, ruleType := range []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType} {
		arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType)
		clusArhsNew[ruleType] = arhs
		for _, arh := range arhs {
			ids.Add(arh.ID)
		}
	}

	// iterate thru rules in CRD request. cacheRecord.AdmCtrlRules has the prior imported crd rules info(rule name -> rule id)
	for ruleType, rules := range allAdmCtrlRules {
		for _, ruleConf := range rules {
			var ruleID uint32
			var cr *share.CLUSAdmissionRule

			ruleName := fmt.Sprintf("%s-%d", ruleType, admCtrlRuleHashFromCriteria(ruleConf.Criteria))
			if ruleConf.ID > 0 && ruleConf.ID < api.StartingLocalAdmCtrlRuleID {
				// yaml says it's for default rule
				if cr = clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, ruleConf.ID); cr != nil {
					ruleID = ruleConf.ID // use existing default rule id
				}
			}
			if ruleID == 0 {
				if id, ok := cacheRecord.AdmCtrlRules[ruleName]; ok {
					// found a same-name rule(same ruleType & criteria hash is the same) in cached record
					if cr = clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, id); cr != nil {
						ruleID = id // use existing non-default rule id
					}
				}
			}
			if ruleID == 0 { // will create a new rule for it
				ruleID = getAvailableRuleID(ruleTypeAdmCtrl, ids, cfgType)
			}

			if cr == nil && ruleID >= api.StartingLocalAdmCtrlRuleID {
				cr = &share.CLUSAdmissionRule{
					ID:       ruleID,
					Category: admission.AdmRuleCatK8s,
					RuleType: ruleType,
				}
			}
			if cr != nil {
				if reviewType == share.ReviewTypeCRD {
					crdIDs.Add(ruleID)
				}
				if !ids.Contains(ruleID) {
					arhs, _ := clusArhsNew[ruleType]
					arh := &share.CLUSRuleHead{
						ID:      ruleID,
						CfgType: cfgType,
					}
					clusArhsNew[ruleType] = append(arhs, arh)
					ids.Add(ruleID)
				}

				if ruleID < api.StartingLocalAdmCtrlRuleID {
					// it's default rule
					if reviewType == share.ReviewTypeCRD || cr.CfgType == share.UserCreated {
						// default rules can be enabled/disabled when (1) thru crd or (2) they are not crd-type thru rest api import
						cr.Disable = ruleConf.Disabled
					}
				} else {
					// it's non-default rule
					cr.Criteria, _ = cache.AdmCriteria2CLUS(ruleConf.Criteria)
					cr.Comment = ruleConf.Comment
				}
				cr.CfgType = cfgType
				clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, cr)
				newRules[ruleName] = ruleID
			}
		}
	}

	if reviewType == share.ReviewTypeCRD {
		// delete those rules in the cacheRecord that are not in the newRules. they will be removed from header list later.
		for cacheName, cacheId := range cacheRecord.AdmCtrlRules {
			if newId, ok := newRules[cacheName]; !ok || newId != cacheId {
				// a crd rule is in old yaml file but not in new yaml file
				ss := strings.Split(cacheName, "-") // cacheName is in the format "{ruleType}-{hash}"
				if len(ss) != 2 {
					log.WithFields(log.Fields{"cacheName": cacheName, "cacheId": cacheId}).Error()
				} else {
					ruleType := ss[0] // ss[0] is ruleType
					if cacheId >= api.AdmCtrlCrdRuleIDBase && cacheId < api.AdmCtrlCrdRuleIDMax {
						clusHelper.DeleteAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, cacheId)
						delRules.Add(cacheId)
					} else {
						// default rule cannot be deleted
						if cr := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, cacheId); cr != nil {
							if cr.CfgType != share.UserCreated {
								cr.CfgType = share.UserCreated
								clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, cr)
							}
						}
					}
				}
			}
		}
	}

	for ruleType, arhsNew := range clusArhsNew {
		if reviewType == share.ReviewTypeCRD {
			// remove those crd rules from rule header list that was created by old yaml but not exist in new yaml
			ruleHead := make([]*share.CLUSRuleHead, 0, len(arhsNew))
			for _, arh := range arhsNew {
				if !delRules.Contains(arh.ID) {
					if reviewType == share.ReviewTypeCRD && crdIDs.Contains(arh.ID) {
						arh.CfgType = cfgType
					}
					ruleHead = append(ruleHead, arh)
				}
			}
			clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleType, ruleHead)
		} else {
			clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleType, arhsNew)
		}
	}
	txn.Apply()

	return newRules
}

func (h *nvCrdHandler) crdHandleAdmCtrlConfig(scope string, crdConfig *resource.NvCrdAdmCtrlConfig, cacheRecord *share.CLUSCrdSecurityRule, reviewType share.TReviewType) error {
	if crdConfig == nil {
		if reviewType == share.ReviewTypeCRD { // meaning do not control admission control config thru crd anymore
			setAdmCtrlStateInCluster(nil, nil, nil, nil, nil, share.UserCreated)
		}
		return nil
	}

	defaultAction := share.AdmCtrlActionAllow
	var cfgType share.TCfgType = share.GroundCfg
	if reviewType == share.ReviewTypeImportAdmCtrl {
		cfgType = share.UserCreated
	}
	failurePolicy := resource.IgnoreLower
	status, code, origConf, cconf := setAdmCtrlStateInCluster(&crdConfig.Enable, &crdConfig.Mode, &defaultAction, &crdConfig.AdmClientMode, &failurePolicy, cfgType)
	if status != http.StatusOK {
		return fmt.Errorf(restErrMessage[code])
	}
	time.Sleep(time.Second)

	if ctrlState, exist := cconf.CtrlStates[admission.NvAdmValidateType]; exist {
		// we should be notified by k8s watcher later
		failurePolicy := resource.Ignore
		k8sResInfo := admission.ValidatingWebhookConfigInfo{
			Name: resource.NvAdmValidatingName,
			WebhooksInfo: []*admission.WebhookInfo{
				&admission.WebhookInfo{
					Name: resource.NvAdmValidatingWebhookName,
					ClientConfig: admission.ClientConfig{
						ClientMode:  crdConfig.AdmClientMode,
						ServiceName: resource.NvAdmSvcName,
						Path:        ctrlState.Uri,
					},
					FailurePolicy:  failurePolicy,
					TimeoutSeconds: resource.DefTimeoutSeconds,
				},
				&admission.WebhookInfo{
					Name: resource.NvStatusValidatingWebhookName,
					ClientConfig: admission.ClientConfig{
						ClientMode:  crdConfig.AdmClientMode,
						ServiceName: resource.NvAdmSvcName,
						Path:        ctrlState.NvStatusUri,
					},
					FailurePolicy:  resource.Ignore,
					TimeoutSeconds: resource.DefTimeoutSeconds,
				},
			},
		}
		skip, err := admission.ConfigK8sAdmissionControl(k8sResInfo, ctrlState)
		if !skip {
			alog := share.CLUSEventLog{ReportedAt: time.Now().UTC()}
			if err == nil {
				var msgState string
				if cconf.Enable {
					msgState = "enabled"
				} else {
					msgState = "disabled"
				}
				alog.Event = share.CLUSEvAdmCtrlK8sConfigured
				alog.Msg = fmt.Sprintf("Admission control is %s.", msgState)
			} else {
				alog.Event = share.CLUSEvAdmCtrlK8sConfigFailed
				alog.Msg = "Failed to configure admission control state."
			}
			evqueue.Append(&alog)
		}
		if err != nil {
			status, code, _, _ := setAdmCtrlStateInCluster(&origConf.Enable, &origConf.Mode, &origConf.DefaultAction, &origConf.AdmClientMode, &origConf.FailurePolicy, origConf.CfgType)
			if status != http.StatusOK {
				log.WithFields(log.Fields{"status": status, "code": code}).Info("Failed to revert admission control state in cluster")
			}
			return err
		}
	}
	return nil
}

func (h *nvCrdHandler) crdHandleDlpGroup(name string, dlpGroupCfg *api.RESTCrdDlpGroupConfig, cfgType share.TCfgType) []string {
	if dlpGroupCfg != nil {
		sensors := make([]string, len(dlpGroupCfg.RepSensors))
		settings := make([]*share.CLUSDlpSetting, len(dlpGroupCfg.RepSensors))
		for idx, setting := range dlpGroupCfg.RepSensors {
			sensors[idx] = setting.Name
			settings[idx] = &share.CLUSDlpSetting{
				Name:   setting.Name,
				Action: setting.Action,
			}
		}
		dlpGroup := &share.CLUSDlpGroup{
			Name:    name,
			Sensors: settings,
			CfgType: cfgType,
		}
		dlpGroup.Status = dlpGroupCfg.Status
		clusHelper.PutDlpGroup(dlpGroup, false)
		return sensors
	}
	return nil
}

// caller must own CLUSLockPolicyKey lock
func (h *nvCrdHandler) crdHandleDlpSensor(scope string, dlpSensorConf *api.RESTDlpSensorConfig,
	cacheRecord *share.CLUSCrdSecurityRule, reviewType share.TReviewType) error {

	var err error
	var comment string
	var ruleList []api.RESTDlpRule
	var cfgType share.TCfgType = share.GroundCfg

	if reviewType == share.ReviewTypeImportDLP {
		cfgType = share.UserCreated
	}
	if dlpSensorConf.Comment != nil {
		comment = *dlpSensorConf.Comment
	}

	conf := &api.RESTDlpSensorConfig{
		Name:    dlpSensorConf.Name,
		Rules:   &ruleList,
		Comment: &comment,
	}

	if dlpSensorConf.Rules == nil || len(*dlpSensorConf.Rules) == 0 {
		ruleList = make([]api.RESTDlpRule, 0)
	} else {
		ruleList = make([]api.RESTDlpRule, len(*dlpSensorConf.Rules))
		for idx, ruleConf := range *dlpSensorConf.Rules {
			ruleList[idx] = api.RESTDlpRule{
				Name:     ruleConf.Name,
				Patterns: ruleConf.Patterns,
				CfgType:  cfgTypeMap2Api[cfgType],
			}
		}
	}
	conf.Rules = &ruleList
	sensor := clusHelper.GetDlpSensor(dlpSensorConf.Name)
	if sensor == nil {
		err = createDlpSensor(nil, conf, cfgType)
	} else {
		err = updateDlpSensor(nil, conf, reviewType, sensor)
	}

	return err
}

func (h *nvCrdHandler) crdHandleWafGroup(name string, wafGroupCfg *api.RESTCrdWafGroupConfig, cfgType share.TCfgType) []string {
	if wafGroupCfg != nil {
		sensors := make([]string, len(wafGroupCfg.RepSensors))
		settings := make([]*share.CLUSWafSetting, len(wafGroupCfg.RepSensors))
		for idx, setting := range wafGroupCfg.RepSensors {
			sensors[idx] = setting.Name
			settings[idx] = &share.CLUSWafSetting{
				Name:   setting.Name,
				Action: setting.Action,
			}
		}
		wafGroup := &share.CLUSWafGroup{
			Name:    name,
			Sensors: settings,
			CfgType: cfgType,
		}
		wafGroup.Status = wafGroupCfg.Status
		clusHelper.PutWafGroup(wafGroup, false)
		return sensors
	}
	return nil
}

// caller must own CLUSLockPolicyKey lock
func (h *nvCrdHandler) crdHandleWafSensor(scope string, wafSensorConf *api.RESTWafSensorConfig,
	cacheRecord *share.CLUSCrdSecurityRule, reviewType share.TReviewType) error {

	var err error
	var comment string
	var ruleList []api.RESTWafRule
	var cfgType share.TCfgType = share.GroundCfg

	if reviewType == share.ReviewTypeImportWAF {
		cfgType = share.UserCreated
	}
	if wafSensorConf.Comment != nil {
		comment = *wafSensorConf.Comment
	}

	conf := &api.RESTWafSensorConfig{
		Name:    wafSensorConf.Name,
		Rules:   &ruleList,
		Comment: &comment,
	}

	if wafSensorConf.Rules == nil || len(*wafSensorConf.Rules) == 0 {
		ruleList = make([]api.RESTWafRule, 0)
	} else {
		ruleList = make([]api.RESTWafRule, len(*wafSensorConf.Rules))
		for idx, ruleConf := range *wafSensorConf.Rules {
			ruleList[idx] = api.RESTWafRule{
				Name:     ruleConf.Name,
				Patterns: ruleConf.Patterns,
				CfgType:  cfgTypeMap2Api[cfgType],
			}
		}
	}
	conf.Rules = &ruleList
	sensor := clusHelper.GetWafSensor(wafSensorConf.Name)
	if sensor == nil {
		err = createWafSensor(nil, conf, cfgType)
	} else {
		err = updateWafSensor(nil, conf, reviewType, sensor)
	}

	return err
}

func compareCLUSCriteria(src, dst []api.RESTCriteriaEntry, selfComp bool) bool {
	var dupFind bool
	if len(src) != len(dst) {
		return false
	}
OUTER:
	for _, srcC := range src {
		dupFind = false
		for i, dstC := range dst {
			if reflect.DeepEqual(srcC, dstC) {
				if !selfComp {
					dst = append(dst[:i], dst[i+1:]...)
					continue OUTER
				} else {
					if dupFind {
						return false
					} else {
						dupFind = true
					}
				}
			}
		}
		if !selfComp {
			return false
		}
	}
	return true
}

func groupNameHashFromCriteria(gCriteria []api.RESTCriteriaEntry, reviewType share.TReviewType) uint32 {
	var name string
	sort.Slice(gCriteria[:], func(i, j int) bool {
		if gCriteria[i].Key != gCriteria[j].Key {
			return gCriteria[i].Key < gCriteria[j].Key
		} else {
			return gCriteria[i].Value < gCriteria[j].Value
		}
	})

	for _, criteria := range gCriteria {
		if reviewType == share.ReviewTypeCRD {
			name += fmt.Sprintf("%s%s%s", criteria.Key, criteria.Value, criteria.Op)
		} else {
			name += fmt.Sprintf("%s%s%s%d", criteria.Key, criteria.Value, criteria.Op, reviewType)
		}
	}
	hasher := murmur3.New32()
	hasher.Write([]byte(name))
	return hasher.Sum32()
}

/*
   rules:
   . ignore Fed/external/node
   . pass basic format validate
   . same group in crd/importGroup appear multiple times need have same criteria/policyMode
   . for crd, if group already exists:
          for learned group can't modify criteria/policyMode
          for regular group generate group with new name based on  modified criteria
   . for importGroup:
          if a crd group already exists, return error
		  if a learned/regualr group already exists, replace it
*/

func (h *nvCrdHandler) parseCrdGroup(crdgroupCfg *api.RESTCrdGroupConfig, curGroups *[]api.RESTCrdGroupConfig, recordName string,
	crdCfgRet *resource.NvSecurityParse, reviewType share.TReviewType, reviewTypeDisplay, owner string) (string, int) {

	var err int
	var retMsg string
	groupCfg := crdConfig2groupConfig(crdgroupCfg)
	isLearnedGroupName := strings.HasPrefix(groupCfg.Name, api.LearnedGroupPrefix)
	if reviewType == share.ReviewTypeImportGroup {
		if isLearnedGroupName {
			groupCfg.CfgType = api.CfgTypeLearned
		} else {
			groupCfg.CfgType = api.CfgTypeUserCreated
		}
	}
	crdgroupCfg.OriginalName = crdgroupCfg.Name
	groupStr := fmt.Sprintf("%s(under %s section)", groupCfg.Name, owner)
	if strings.HasPrefix(groupCfg.Name, api.FederalGroupPrefix) {
		retMsg = fmt.Sprintf("%s Rule format error:   Cannot use reserved name %s", reviewTypeDisplay, groupStr)
		return retMsg, api.RESTErrInvalidName
	} else if isLearnedGroupName {
		err, msg := validateLearnGroupConfig(groupCfg)
		if err > 0 {
			retMsg = fmt.Sprintf("%s Rule format error:   Group %s validate error. Details: %s", reviewTypeDisplay, groupStr, msg)
			return retMsg, err
		}
	} else if strings.HasPrefix(groupCfg.Name, api.LearnedWorkloadPrefix) &&
		groupCfg.Name[len(api.LearnedWorkloadPrefix):] == api.EndpointIngress {
		// Learned already processed, now skip Workload:ingress
		return "", 0
	} else if groupCfg.Name == api.AllHostGroup || groupCfg.Name == api.LearnedExternal { // reserved group
		if groupCfg.Criteria == nil || len(*groupCfg.Criteria) == 0 {
			// correct criteria
			*curGroups = append(*curGroups, *crdgroupCfg)
			return "", 0
		}
		retMsg = fmt.Sprintf("%s Rule format error:   Group %s validate error", reviewTypeDisplay, groupStr)
		return retMsg, api.RESTErrInvalidName
	} else if groupCfg.Name == api.AllContainerGroup { // reserved group
		if len(*groupCfg.Criteria) == 1 &&
			(*groupCfg.Criteria)[0].Key == "container" &&
			(*groupCfg.Criteria)[0].Op == "=" &&
			(*groupCfg.Criteria)[0].Value == "*" {
			// correct criteria
			*curGroups = append(*curGroups, *crdgroupCfg)
			return "", 0
		}
		retMsg = fmt.Sprintf("%s Rule format error:   Group %s validate error", reviewTypeDisplay, groupStr)
		return retMsg, api.RESTErrInvalidName
	} else {
		err, msg := validateGroupConfig(groupCfg, true)
		if err > 0 {
			retMsg = fmt.Sprintf("%s Rule format error:   Group %s validate error. Details: %s", reviewTypeDisplay, groupStr, msg)
			return retMsg, err
		}
		if groupCfg.Criteria == nil || len(*groupCfg.Criteria) == 0 {
			retMsg = fmt.Sprintf("%s Rule format error:   Group %s must have criteria", reviewTypeDisplay, groupStr)
			return retMsg, api.RESTErrInvalidRequest
		} else {
			if err, msg, hasAddrCT := validateGroupConfigCriteria(groupCfg, access.NewAdminAccessControl()); err > 0 {
				retMsg = fmt.Sprintf("%s Rule format error:   Group %s criteria validate error. Details: %s", reviewTypeDisplay, groupStr, msg)
				return retMsg, err
			} else if hasAddrCT && crdCfgRet != nil && (crdCfgRet.DlpGroupCfg != nil || crdCfgRet.WafGroupCfg != nil) {
				retMsg = fmt.Sprintf("%s Rule format error:   Group %s with address criterion cannot have DLP/WAF policy", reviewTypeDisplay, groupStr)
				return retMsg, api.RESTErrInvalidRequest
			}
		}
		// make sure Criteria didn't duplicate
		dst := append([]api.RESTCriteriaEntry(nil), *groupCfg.Criteria...)
		if !compareCLUSCriteria(*groupCfg.Criteria, dst, true) {
			retMsg = fmt.Sprintf("%s Rule format error:   Group %s has duplicate/conflict criteria", reviewTypeDisplay, groupStr)
			log.WithFields(log.Fields{"name": groupCfg.Name}).Error(retMsg)
			err = api.RESTErrDuplicateName
			return retMsg, err
		}
	}
	// If non-nv.ip.xxx group already added in this crd and have different criteria, reject.
	// For nv.ip.xxx group, we don't compare its criteria because it may be from existing learned nv.ip.xxx group
	isNvIpGroup := strings.HasPrefix(groupCfg.Name, api.LearnedSvcGroupPrefix)
	for _, g := range *curGroups {
		if !isNvIpGroup && (g.OriginalName == groupCfg.Name) {
			e := "Group already added"
			log.WithFields(log.Fields{"name": groupCfg.Name}).Info(e)
			dst := append([]api.RESTCriteriaEntry(nil), *groupCfg.Criteria...)
			if !compareCLUSCriteria(*g.Criteria, dst, false) {
				retMsg = fmt.Sprintf("%s Rule format error:   Group %s added with different criteria", reviewTypeDisplay, groupStr)
				log.WithFields(log.Fields{"name": groupCfg.Name}).Error(retMsg)
				err = api.RESTErrInvalidRequest
				return retMsg, err
			}
			crdgroupCfg.Name = g.Name
			return "", 0
		}
	}

	acc := access.NewReaderAccessControl()
	// for non-nv.ip.xxx groups:
	// 1. If group already exist and have different criteria, use hashed name to create new one if avialable otherwise faile.
	// 2. if group already exist and have same criteria, keep the original name.
	// 3. If group didn't exist yet and by hash name group exist, use hashed name to continue.
	// 4. If group didn't exist yet and by hash name group also not exist, use original name to create group.
	// for nv.ip.xxx groups, because we only import 'domain' key in its criteria, theoretically there is no need to create nv.ip.xxx-<hash> group:
	// 1. If the learned group already exists, promote it to crd later.
	// 2. If the crd group already exists, keep the existing crd group unchanged.
	// 3. If group doesn't exist yet, create a crd nv.ip.xxx group that has "domain" key(if applicable) in criteria (i.e. drop "address" & other criteria).
	if g, _, _ := clusHelper.GetGroup(groupCfg.Name, acc); g != nil {
		if g.Kind != share.GroupKindContainer && (crdCfgRet != nil && (crdCfgRet.DlpGroupCfg != nil || crdCfgRet.WafGroupCfg != nil)) {
			retMsg = fmt.Sprintf("%s Rule format error:   Group %s cannot have DLP/WAF policy", reviewTypeDisplay, groupStr)
			return retMsg, api.RESTErrInvalidRequest
		}
		rg_criteria := criteria2REST(g.Criteria)
		if isNvIpGroup {
			// found existing nv.ip.xxx group(learned or crd). use its criteria as this group's criteria.
			crdgroupCfg.Criteria = &rg_criteria
		} else {
			if !compareCLUSCriteria(*groupCfg.Criteria, rg_criteria, false) {
				hashval := groupNameHashFromCriteria(*groupCfg.Criteria, reviewType)
				var newName string
				if reviewType == share.ReviewTypeCRD {
					newName = fmt.Sprintf("%s-%s", groupCfg.Name, fmt.Sprint(hashval))
				} else {
					newName = fmt.Sprintf("%s-%s-%d", groupCfg.Name, fmt.Sprint(hashval), reviewType)
				}
				// Make sure alternative group name is avialiable for non-nv.ip.xxx group
				if variation_g, _, _ := clusHelper.GetGroup(newName, acc); variation_g != nil {
					vrg_criteria := criteria2REST(variation_g.Criteria)
					if !compareCLUSCriteria(*groupCfg.Criteria, vrg_criteria, false) {
						retMsg = fmt.Sprintf("%s Rule format error:   Group %s and alternative name %s both taken", reviewTypeDisplay, groupStr, newName)
						return retMsg, api.RESTErrInvalidName
					}
				}

				if reviewType == share.ReviewTypeCRD {
					if g.CfgType != share.GroundCfg {
						// conflict with user created group, use hash name create new one if available
						crdgroupCfg.Name = newName
					} else {
						gwrecordlist := clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
					LOOPALL:
						for _, gw := range gwrecordlist {
							if recordName == gw.Name {
								// if only conflict with own crd, then it is update. keep the name
								continue LOOPALL
							}
							// conflict with group in other crd, use hash name to create new one
							// or if the hash name already using, then keep use it.
							for _, gwgroup := range gw.Groups {
								if gwgroup == groupCfg.Name || gwgroup == newName {
									crdgroupCfg.Name = newName
									break LOOPALL
								}
							}
						}
					}
				} else if reviewType == share.ReviewTypeImportGroup {
					// imported group cannot override CRD group
					if g.CfgType == share.GroundCfg {
						crdgroupCfg.Name = newName
					}
				}
			} else if reviewType == share.ReviewTypeImportGroup {
				// if there is a CRD group with the same name, create a new group because we may need to update process profile/file monitor later
				if g.CfgType == share.GroundCfg {
					hashval := groupNameHashFromCriteria(*groupCfg.Criteria, reviewType)
					crdgroupCfg.Name = fmt.Sprintf("%s-%s-%d", groupCfg.Name, fmt.Sprint(hashval), reviewType)
				}
			}
		}
	} else {
		// new group add
		if isNvIpGroup {
			// when creating a new nv.ip.xxx group, only keep "domain" key in its criteria. hopefully it should be learned later
			crdGroupCriteria := crdgroupCfg.Criteria
			criteria := make([]api.RESTCriteriaEntry, 0, 1)
			if crdGroupCriteria != nil {
				for _, ct := range *crdGroupCriteria {
					if ct.Key == share.CriteriaKeyDomain {
						criteria = append(criteria, ct)
						break
					}
				}
			}
			crdgroupCfg.Criteria = &criteria
		} else {
			if reviewType == share.ReviewTypeCRD {
				hashval := groupNameHashFromCriteria(*groupCfg.Criteria, reviewType)
				newName := fmt.Sprintf("%s-%s", groupCfg.Name, fmt.Sprint(hashval))
				// the group based on variation
				// 1. if already created then it is duplicated create, so keep the variation
				// 2. if not exist, then use the original name to create the group
				if variation_g, _, _ := clusHelper.GetGroup(newName, acc); variation_g != nil {
					crdgroupCfg.Name = newName
				}
			}
		}
	}
	crdgroupCfg.Comment = crdgroupCfg.Comment
	*curGroups = append(*curGroups, *crdgroupCfg)
	return "", err
}

func (h *nvCrdHandler) parseCrdFwRule(from, to, recordName string, ruleDetail resource.NvSecurityRuleDetail, ruleSet utils.Set,
	reviewType share.TReviewType, owner string) (api.RESTPolicyRuleConfig, string, int) {

	var buffer bytes.Buffer

	ruleCfg := api.RESTPolicyRuleConfig{
		Ports:        &ruleDetail.Ports,
		Applications: &ruleDetail.Applications,
		Action:       &ruleDetail.Action,
		Comment:      &ruleDetail.Name,
	}
	ruleCfg.From = &from
	ruleCfg.To = &to

	ownerStr := fmt.Sprintf("(under %s section)", owner)
	if reviewType == share.ReviewTypeCRD {
		if ruleCfg.Comment == nil || *ruleCfg.Comment == "" {
			err := fmt.Sprintf("Rule needs name%s", ownerStr)
			buffer.WriteString(err)
			return ruleCfg, buffer.String(), 1
		}
		if ruleSet.Contains(*ruleCfg.Comment) {
			buffer.WriteString(fmt.Sprintf("Duplicated rule name: %s%s", *ruleCfg.Comment, ownerStr))
			return ruleCfg, buffer.String(), 1

		}
		ruleCfg.Priority = ruleDetail.Priority
	}

	if err := validateRestPolicyRuleConfig(&ruleCfg); err != nil {
		errEx := fmt.Sprintf("%s for rule %s%s", err.Error(), *ruleCfg.Comment, ownerStr)
		log.WithFields(log.Fields{"error": errEx}).Error()
		buffer.WriteString(errEx)
		return ruleCfg, buffer.String(), 1
	}

	return ruleCfg, "", 0
}

func (h *nvCrdHandler) validateCrdProcessRules(baseline string, rules []*api.RESTProcessProfileEntry) (string, int) {

	var buffer bytes.Buffer
	ruleSet := utils.NewSet()
	errCnt := 0
	for i, r := range rules {
		r.Name = strings.TrimSpace(r.Name)
		r.Path = strings.TrimSpace(r.Path)
		r.Action = strings.TrimSpace(r.Action)

		msg := fmt.Sprintf("Name:%v, Path:%v, Action:%v", r.Name, r.Path, r.Action)
		if r.Path == "*" || r.Path == "" {
			// possibly wildcard
		} else if strings.HasSuffix(r.Path, "/") || !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "<>") || strings.Count(r.Path, "*") > 1 {
			buffer.WriteString(fmt.Sprintf(" validate error: process[%s], invalid path format: %s \n", r.Name, r.Path))
			errCnt++
		}

		if r.Path != "" {
			path := r.Path
			r.Path = filepath.Clean(r.Path)
			if r.Path == "." || r.Path == "/" {
				buffer.WriteString(fmt.Sprintf(" validate error: process[%s], unknown path format: %s[%s] \n", r.Name, path, r.Path))
				errCnt++
			}
		}

		if r.Name == "" {
			if r.Path == "*" || r.Path == "" || r.Path == "." || r.Path == "/" {
				buffer.WriteString(fmt.Sprintf(" validate error: process needs a name: Name: %s \n", msg))
				errCnt++
			} else {
				index := strings.LastIndexByte(r.Path, '/')
				r.Name = r.Path[index+1:]
				//	log.WithFields(log.Fields{"name": r.Name, "path": r.Path}).Debug("CRD: patch Name")
			}
		}

		if r.Name == "*" && r.Path == "" {
			buffer.WriteString(fmt.Sprintf(" validate error: process needs a non-empty path: Name: %s \n", msg))
			errCnt++
		}

		key := fmt.Sprintf("%s:%s:%s", r.Name, r.Path, r.Action)
		if ruleSet.Contains(key) {
			buffer.WriteString(fmt.Sprintf(" Duplicated process rule entry: : %s \n", msg))
			errCnt++
		} else {
			ruleSet.Add(key)
		}

		// avoid deny all entry
		if r.Name == "*" && (r.Path == "*" || r.Path == "/*") && r.Action == share.PolicyActionDeny {
			buffer.WriteString(fmt.Sprintf(" invalid process entry: deny all: %s \n", msg))
			errCnt++
		}

		// update final values
		rules[i].Name = r.Name
		rules[i].Path = r.Path
		rules[i].Action = r.Action
	}
	return buffer.String(), errCnt

}

func (h *nvCrdHandler) validateCrdFileRules(rules []*api.RESTFileMonitorFilter) (string, int) {

	var buffer bytes.Buffer
	ruleSet := utils.NewSet()
	errCnt := 0
	for i, r := range rules {
		flt := r.Filter
		r.Filter = strings.TrimSpace(r.Filter)
		r.Behavior = strings.TrimSpace(r.Behavior)
		r.Filter = filepath.Clean(r.Filter)
		if r.Filter == "." || r.Filter == "/" {
			buffer.WriteString(fmt.Sprintf(" validate error: filter: %s[%s] \n", flt, r.Filter))
			errCnt++
		} else {
			_, _, ok := parseFileFilter(r.Filter)
			if !ok {
				buffer.WriteString(fmt.Sprintf(" validate error: unsupported filter: %s[%s] \n", flt, r.Filter))
				errCnt++
			}
		}

		apps := make([]string, 0, len(r.Apps))
		for _, app := range r.Apps {
			apps = append(apps, strings.TrimSpace(app))
		}

		key := fmt.Sprintf("%s:%s:%v", r.Filter, r.Behavior, r.Recursive)
		if ruleSet.Contains(key) {
			buffer.WriteString(fmt.Sprintf(" Duplicated file rule entry: : %s \n", key))
			errCnt++
		} else {
			ruleSet.Add(key)
		}

		// update final values
		rules[i].Filter = r.Filter
		rules[i].Behavior = r.Behavior
		rules[i].Apps = apps
	}
	return buffer.String(), errCnt

}

func (h *nvCrdHandler) validateCrdDlpWafGroup(spec *resource.NvSecurityRuleSpec) (string, int) {
	var errCnt int
	var buffer bytes.Buffer

	if spec.DlpGroup != nil {
		for _, s := range spec.DlpGroup.Settings {
			if s.Name == share.CLUSDlpDefaultSensor {
				buffer.WriteString(fmt.Sprintf(" validate error: cannot use reserved sensor name%s \n", s.Name))
				errCnt++
			}
			if s.Action != share.PolicyActionAllow && s.Action != share.PolicyActionDeny {
				buffer.WriteString(fmt.Sprintf(" validate error: action %s \n", s.Action))
				errCnt++
			}
		}
	}

	if spec.WafGroup != nil {
		for _, s := range spec.WafGroup.Settings {
			if s.Name == share.CLUSWafDefaultSensor {
				buffer.WriteString(fmt.Sprintf(" validate error: cannot use reserved sensor name%s \n", s.Name))
				errCnt++
			}
			if s.Action != share.PolicyActionAllow && s.Action != share.PolicyActionDeny {
				buffer.WriteString(fmt.Sprintf(" validate error: action %s \n", s.Action))
				errCnt++
			}
		}
	}

	return buffer.String(), errCnt
}

// for CRD & group import
func (h *nvCrdHandler) parseCurCrdContent(gfwrule *resource.NvSecurityRule, reviewType share.TReviewType,
	reviewTypeDisplay string) (*resource.NvSecurityParse, int, string, string) {

	var buffer bytes.Buffer
	var errNo int
	var errMsg, ruleNs string
	var crdCfgRet resource.NvSecurityParse
	//	var GroupCfgs []api.RESTCrdGroupConfig
	//	var RuleCfgs []api.RESTPolicyRuleConfig
	var ruleCfg api.RESTPolicyRuleConfig
	var recordName string

	ruleSet := utils.NewSet()
	//	var groupName string
	errCount := 0

	if gfwrule == nil || gfwrule.Metadata == nil || gfwrule.Metadata.Name == nil {
		errMsg := fmt.Sprintf("%s file format error:  validation error", reviewTypeDisplay)
		return nil, 1, errMsg, ""
	}
	if reviewType == share.ReviewTypeCRD {
		if *gfwrule.Kind == resource.NvClusterSecurityRuleKind {
			ruleNs = "default"
		} else {
			ruleNs = *gfwrule.Metadata.Namespace
		}
		recordName = fmt.Sprintf("%s-%s-%s", *gfwrule.Kind, ruleNs, *gfwrule.Metadata.Name)
	} else {
		ruleNs = *gfwrule.Metadata.Namespace
		recordName = gfwrule.Spec.Target.Selector.Name
	}

	// 1. Get the DLP/WAF group settings
	errMsg, errNo = h.validateCrdDlpWafGroup(&gfwrule.Spec)
	if errNo > 0 {
		buffer.WriteString(errMsg)
		errCount += errNo
	} else {
		if gfwrule.Spec.DlpGroup != nil {
			crdCfgRet.DlpGroupCfg = &api.RESTCrdDlpGroupConfig{
				Status:     gfwrule.Spec.DlpGroup.Status,
				RepSensors: gfwrule.Spec.DlpGroup.Settings,
			}
		}
		if gfwrule.Spec.WafGroup != nil {
			crdCfgRet.WafGroupCfg = &api.RESTCrdWafGroupConfig{
				Status:     gfwrule.Spec.WafGroup.Status,
				RepSensors: gfwrule.Spec.WafGroup.Settings,
			}
		}
	}

	// 2. Get the target group and do validation. crdCfgRet.GroupCfgs collects all the mentioned groups in this security rule.
	errMsg, errNo = h.parseCrdGroup(&gfwrule.Spec.Target.Selector, &crdCfgRet.GroupCfgs, recordName, &crdCfgRet, reviewType, reviewTypeDisplay, "target")
	if errNo > 0 {
		errCount++
		return nil, errCount, errMsg, recordName
	}

	//    if the rule was for certain namespace, then the target must belong to same namespace.
	//    neuvector namespace was used for general in/export
	if *gfwrule.Kind == resource.NvSecurityRuleKind {
		for _, ct := range *gfwrule.Spec.Target.Selector.Criteria {
			if ct.Key == share.CriteriaKeyDomain {
				if ct.Op == share.CriteriaOpEqual && ct.Value == ruleNs {
					goto targetpass
				}
			}
		}
		errMsg = fmt.Sprintf("%s Rule format error:   SecurityRule in nameSpace %s need target group %s belong to it",
			reviewTypeDisplay, ruleNs, gfwrule.Spec.Target.Selector.Name)
		errCount++
		return nil, errCount, errMsg, recordName
	}
targetpass:
	crdCfgRet.TargetName = gfwrule.Spec.Target.Selector.Name
	policyModeCfg := gfwrule.Spec.Target.PolicyMode
	if utils.DoesGroupHavePolicyMode(gfwrule.Spec.Target.Selector.Name) {
		if policyModeCfg != nil {
			if *policyModeCfg != share.PolicyModeLearn &&
				*policyModeCfg != share.PolicyModeEvaluate &&
				*policyModeCfg != share.PolicyModeEnforce {
				errMsg = fmt.Sprintf("%s Rule format error:   Target group %s invalide policy mode %s",
					reviewTypeDisplay, gfwrule.Spec.Target.Selector.Name, *policyModeCfg)
				errCount++
				return nil, errCount, errMsg, recordName

			} else {
				pmode := api.RESTServiceConfig{
					Name:       gfwrule.Spec.Target.Selector.Name,
					PolicyMode: policyModeCfg,
				}
				crdCfgRet.PolicyModeCfg = &pmode
			}
		} else {
			//tmp := share.PolicyModeLearn

			tmp := cacher.GetNewServicePolicyMode()
			pmode := api.RESTServiceConfig{
				Name:       gfwrule.Spec.Target.Selector.Name,
				PolicyMode: &tmp,
			}
			crdCfgRet.PolicyModeCfg = &pmode
		}
	} else {
		if policyModeCfg != nil && (*policyModeCfg != "" && *policyModeCfg != share.PolicyModeUnavailable) {
			errMsg = fmt.Sprintf("%s Rule format error:   Target group %s does not support policy mode",
				reviewTypeDisplay, gfwrule.Spec.Target.Selector.Name)
			errCount++
			return nil, errCount, errMsg, recordName
		}
	}
	//Pare target group done.

	// 3. Get the ingress policy and From Group, the target group will be used as To Group
	for _, ruleDetail := range gfwrule.Spec.IngressRule {
		errMsg, errNo = h.parseCrdGroup(&ruleDetail.Selector, &crdCfgRet.GroupCfgs, recordName, nil, reviewType, reviewTypeDisplay, "ingress")
		if errNo > 0 {
			errCount++
			return nil, errCount, errMsg, recordName
		}

		ruleCfg, errMsg, errNo = h.parseCrdFwRule(ruleDetail.Selector.Name, gfwrule.Spec.Target.Selector.Name,
			recordName, ruleDetail, ruleSet, reviewType, "ingress")
		if errNo > 0 {
			buffer.WriteString(errMsg)
			errCount++
			continue
		}
		if reviewType == share.ReviewTypeCRD {
			ruleSet.Add(*ruleCfg.Comment)
		}
		crdCfgRet.RuleCfgs = append(crdCfgRet.RuleCfgs, ruleCfg)
	}

	// 4. Get the egress policy and To Group, the target group will be used as From Group
	for _, ruleDetail := range gfwrule.Spec.EgressRule {
		errMsg, errNo = h.parseCrdGroup(&ruleDetail.Selector, &crdCfgRet.GroupCfgs, recordName, nil, reviewType, reviewTypeDisplay, "egress")
		if errNo > 0 {
			errCount++
			return nil, errCount, errMsg, recordName
		}

		ruleCfg, errMsg, errNo = h.parseCrdFwRule(gfwrule.Spec.Target.Selector.Name, ruleDetail.Selector.Name,
			recordName, ruleDetail, ruleSet, reviewType, "egress")
		if errNo > 0 {
			buffer.WriteString(errMsg)
			errCount++
			continue
		}
		if reviewType == share.ReviewTypeCRD {
			ruleSet.Add(*ruleCfg.Comment)
		}
		crdCfgRet.RuleCfgs = append(crdCfgRet.RuleCfgs, ruleCfg)
	}

	// 5. Get process and file profiles
	if gfwrule.Spec.Target.Selector.Name != "" && utils.HasGroupProfiles(gfwrule.Spec.Target.Selector.Name) {
		// Process profile
		mode := "" // user-created group
		if gfwrule.Spec.Target.PolicyMode != nil {
			mode = *gfwrule.Spec.Target.PolicyMode
		}
		baseline := ""
		if utils.DoesGroupHavePolicyMode(gfwrule.Spec.Target.Selector.Name) {
			baseline = share.ProfileZeroDrift
			if gfwrule.Spec.ProcessProfile != nil && gfwrule.Spec.ProcessProfile.Baseline != nil {
				blValue := *gfwrule.Spec.ProcessProfile.Baseline
				if blValue == share.ProfileBasic {
					baseline = share.ProfileBasic
				} else if (blValue != share.ProfileDefault_UNUSED && blValue != share.ProfileShield_UNUSED && blValue != share.ProfileZeroDrift) ||
					(blValue != share.ProfileBasic && utils.IsGroupNodes(gfwrule.Spec.Target.Selector.Name)) {
					errMsg = fmt.Sprintf("%s Rule format error:   invalid baseline %s for group %s", reviewTypeDisplay, blValue, gfwrule.Spec.Target.Selector.Name)
					buffer.WriteString(errMsg)
					errCount++
				}
			}
		}
		pprofile := api.RESTProcessProfile{
			Group:       gfwrule.Spec.Target.Selector.Name,
			Baseline:    baseline,
			Mode:        mode,
			ProcessList: make([]*api.RESTProcessProfileEntry, 0, len(gfwrule.Spec.ProcessRule)),
		}

		for _, pp := range gfwrule.Spec.ProcessRule {
			p := &api.RESTProcessProfileEntry{
				Name:            pp.Name,
				Path:            pp.Path,
				Action:          pp.Action,
				AllowFileUpdate: pp.AllowFileUpdate,
			}
			pprofile.ProcessList = append(pprofile.ProcessList, p)
		}

		// the contents will be justified
		errMsg, errNo = h.validateCrdProcessRules(pprofile.Baseline, pprofile.ProcessList)
		if errNo > 0 {
			buffer.WriteString(errMsg)
			errCount += errNo
		}
		crdCfgRet.ProcessProfileCfg = &pprofile

		// File profile
		fprofile := api.RESTFileMonitorProfile{
			Group:   gfwrule.Spec.Target.Selector.Name,
			Filters: make([]*api.RESTFileMonitorFilter, 0, len(gfwrule.Spec.FileRule)),
		}

		if gfwrule.Spec.Target.Selector.Name == api.AllHostGroup {
			if len(gfwrule.Spec.FileRule) > 0 {
				errMsg = fmt.Sprintf("  %s Rule file format error:  profile is not supported for \"nodes\"", reviewTypeDisplay)
				buffer.WriteString(errMsg)
				errCount++
			}
		} else {
			for _, ff := range gfwrule.Spec.FileRule {
				f := &api.RESTFileMonitorFilter{
					Filter:    ff.Filter,
					Recursive: ff.Recursive,
					Behavior:  ff.Behavior,
					Apps:      ff.App,
				}
				fprofile.Filters = append(fprofile.Filters, f)
			}

			// the contents will be justified
			errMsg, errNo = h.validateCrdFileRules(fprofile.Filters)
			if errNo > 0 {
				buffer.WriteString(errMsg)
				errCount += errNo
			}
		}
		crdCfgRet.FileProfileCfg = &fprofile
	}

	return &crdCfgRet, errCount, buffer.String(), recordName
}

func admCtrlRuleHashFromCriteria(rCriteria []*api.RESTAdmRuleCriterion) uint32 {
	if len(rCriteria) == 0 {
		return 0
	}

	var name string
	for _, criteria := range rCriteria {
		if len(criteria.SubCriteria) > 1 {
			sort.Slice(criteria.SubCriteria[:], func(i, j int) bool {
				if criteria.SubCriteria[i].Name != criteria.SubCriteria[j].Name {
					return criteria.SubCriteria[i].Name < criteria.SubCriteria[j].Name
				} else if criteria.SubCriteria[i].Op != criteria.SubCriteria[j].Op {
					return criteria.SubCriteria[i].Op < criteria.SubCriteria[j].Op
				} else {
					return criteria.SubCriteria[i].Value < criteria.SubCriteria[j].Value
				}
			})
		}
	}
	sort.Slice(rCriteria[:], func(i, j int) bool {
		if rCriteria[i].Name != rCriteria[j].Name {
			return rCriteria[i].Name < rCriteria[j].Name
		} else if rCriteria[i].Op != rCriteria[j].Op {
			return rCriteria[i].Op < rCriteria[j].Op
		} else if rCriteria[i].Value != rCriteria[j].Value {
			return rCriteria[i].Value < rCriteria[j].Value
		} else {
			if len(rCriteria[i].SubCriteria) != len(rCriteria[j].SubCriteria) {
				return len(rCriteria[i].SubCriteria) < len(rCriteria[j].SubCriteria)
			} else {
				for idx, subCrit1 := range rCriteria[i].SubCriteria {
					subCrit2 := rCriteria[j].SubCriteria[idx]
					if subCrit1.Name != subCrit2.Name {
						return subCrit1.Name < subCrit2.Name
					} else if subCrit1.Op != subCrit2.Op {
						return subCrit1.Op < subCrit2.Op
					} else {
						return subCrit1.Value < subCrit2.Value
					}
				}
			}
		}
		return false
	})

	for _, criteria := range rCriteria {
		name += fmt.Sprintf("%s%s%s", criteria.Name, criteria.Value, criteria.Op)
		if len(criteria.SubCriteria) > 0 {
			name += fmt.Sprintf("-%d", admCtrlRuleHashFromCriteria(criteria.SubCriteria))
		}
	}
	hasher := murmur3.New32()
	hasher.Write([]byte(name))
	return hasher.Sum32()
}

// for CRD admission control import
func (h *nvCrdHandler) parseCurCrdAdmCtrlContent(admCtrlSecRule *resource.NvAdmCtrlSecurityRule, reviewType share.TReviewType,
	reviewTypeDisplay string) (*resource.NvSecurityParse, int, string, string) {

	if admCtrlSecRule == nil || admCtrlSecRule.Metadata == nil || admCtrlSecRule.Metadata.Name == nil {
		errMsg := fmt.Sprintf("%s file format error:  validation error", reviewTypeDisplay)
		return nil, 1, errMsg, ""
	}
	name := *admCtrlSecRule.Metadata.Name
	if reviewType == share.ReviewTypeCRD {
		if name != share.ScopeLocal { // for crd, metadata name must be "local". if it's not, ignore it
			return nil, 0, "", ""
		}
	}

	if reviewType == share.ReviewTypeImportAdmCtrl {
		if name != share.ScopeLocal {
			errMsg := fmt.Sprintf("%s file format error: invalid metadata name \"%s\"", reviewTypeDisplay, name)
			return nil, 1, errMsg, ""
		}
	}

	var buffer bytes.Buffer

	errCount := 0
	crdCfgRet := &resource.NvSecurityParse{}
	recordName := fmt.Sprintf("%s-default-%s", *admCtrlSecRule.Kind, name)
	if admCtrlSecRule.Spec.Config != nil {
		// Get the admission control config
		cfg := admCtrlSecRule.Spec.Config
		if cfg.Enable == nil || cfg.Mode == nil || cfg.AdmClientMode == nil ||
			(*cfg.Mode != share.AdmCtrlModeMonitor && *cfg.Mode != share.AdmCtrlModeProtect) ||
			(*cfg.AdmClientMode != share.AdmClientModeSvc && *cfg.AdmClientMode != share.AdmClientModeUrl) {
			errMsg := fmt.Sprintf("%s file format error:  validation error in %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		crdCfgRet.AdmCtrlCfg = &resource.NvCrdAdmCtrlConfig{
			Enable:        *cfg.Enable,
			Mode:          *cfg.Mode,
			AdmClientMode: *cfg.AdmClientMode,
		}
	}
	if len(admCtrlSecRule.Spec.Rules) > 0 {
		crdRuleIDs := utils.NewSet()
		crdCfgRet.AdmCtrlRulesCfg = make(map[string][]*resource.NvCrdAdmCtrlRule)
		admRuleTypes := []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType}
		admRuleOptions := make(map[string]*api.RESTAdmCatOptions, len(admRuleTypes))
		admRulesCfg := make(map[string][]*resource.NvCrdAdmCtrlRule, len(admRuleTypes))
		for _, ruleType := range admRuleTypes {
			admRuleOptions[ruleType] = nvsysadmission.GetAdmRuleTypeOptions(ruleType)
			admRulesCfg[ruleType] = make([]*resource.NvCrdAdmCtrlRule, 0, len(admCtrlSecRule.Spec.Rules))
		}

		// Get the admission control rules
		acc := access.NewAdminAccessControl()
		for idx, crdRule := range admCtrlSecRule.Spec.Rules {
			var errMsg string
			if (crdRule.Action == nil || (*crdRule.Action != api.ValidatingAllowRuleType && *crdRule.Action != api.ValidatingDenyRuleType)) ||
				len(crdRule.Criteria) == 0 {
				errMsg := fmt.Sprintf("%s file format error:  validation error in %s", reviewTypeDisplay, name)
				return nil, 1, errMsg, recordName
			}
			crdRuleType := *crdRule.Action
			if crdRuleType == api.ValidatingAllowRuleType {
				crdRuleType = api.ValidatingExceptRuleType
			}
			var err error
			var criteria []*share.CLUSAdmRuleCriterion
			if criteria, err = cache.AdmCriteria2CLUS(crdRule.Criteria); err == nil {
				options, _ := admRuleOptions[crdRuleType]
				err = validateAdmCtrlCriteria(criteria, options.K8sOptions.RuleOptions, crdRuleType)
			}
			if err != nil {
				errMsg = fmt.Sprintf("%s Rule format error:   Rule #%d in %s validatation error %s", reviewTypeDisplay, idx, name, err.Error())
			} else {
				if crdRule.ID != nil && *crdRule.ID > 0 && *crdRule.ID < api.StartingLocalAdmCtrlRuleID {
					// if it's for default rule, default rule can only be enabled/disabled
					if rule, err := cacher.GetAdmissionRule(admission.NvAdmValidateType, crdRuleType, *crdRule.ID, acc); err == nil {
						if !reflect.DeepEqual(rule.Criteria, crdRule.Criteria) ||
							(reviewType == share.ReviewTypeImportAdmCtrl && rule.CfgType == api.CfgTypeGround) {
							errMsg = fmt.Sprintf("%s Rule error:   Default rule(id=%d) cannot be modified", reviewTypeDisplay, *crdRule.ID)
						}
					} else {
						errMsg = fmt.Sprintf("%s Rule error:   Default rule(id=%d) not found", reviewTypeDisplay, *crdRule.ID)
					}
				}
				if errMsg == "" {
					ruleCfg := &resource.NvCrdAdmCtrlRule{
						RuleType: crdRuleType,
						Criteria: crdRule.Criteria,
					}
					if crdRule.ID != nil && *crdRule.ID < api.StartingLocalAdmCtrlRuleID {
						ruleCfg.ID = *crdRule.ID
					}
					if crdRule.Comment != nil {
						ruleCfg.Comment = *crdRule.Comment
					}
					if crdRule.Disabled != nil {
						ruleCfg.Disabled = *crdRule.Disabled
					}
					rulesCfg, _ := admRulesCfg[crdRuleType]
					admRulesCfg[crdRuleType] = append(rulesCfg, ruleCfg)
					crdRuleIDs.Add(crdRule.ID)
				}
			}
			if errMsg != "" {
				buffer.WriteString(errMsg)
				errCount++
				continue
			}
		}
		for ruleType, rulesCfg := range admRulesCfg {
			if len(rulesCfg) > 0 {
				crdCfgRet.AdmCtrlRulesCfg[ruleType] = rulesCfg
			}
		}
	}

	return crdCfgRet, errCount, buffer.String(), recordName
}

// for CRD DLP sensor import
func (h *nvCrdHandler) parseCurCrdDlpContent(dlpSecRule *resource.NvDlpSecurityRule, reviewType share.TReviewType,
	reviewTypeDisplay string) (*resource.NvSecurityParse, int, string, string) {

	if dlpSecRule == nil || dlpSecRule.Metadata == nil || dlpSecRule.Metadata.Name == nil {
		errMsg := fmt.Sprintf("%s file format error:  validation error", reviewTypeDisplay)
		return nil, 1, errMsg, ""
	}

	var cfgType string = api.CfgTypeUserCreated
	if reviewType == share.ReviewTypeCRD {
		cfgType = api.CfgTypeGround
	}

	var buffer bytes.Buffer
	errCount := 0
	crdCfgRet := &resource.NvSecurityParse{}
	name := *dlpSecRule.Metadata.Name
	recordName := fmt.Sprintf("%s-default-%s", *dlpSecRule.Kind, name)
	if dlpSecRule.Spec.Sensor != nil {
		sensor := dlpSecRule.Spec.Sensor
		if sensor.Name != name {
			errMsg := fmt.Sprintf("%s file format error:  mismatched name in sensor and metadata %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if !isObjectNameValid(sensor.Name) {
			errMsg := fmt.Sprintf("%s file format error:  invalid characters in name %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if sensor.Name == share.CLUSDlpDefaultSensor || strings.HasPrefix(sensor.Name, api.FederalGroupPrefix) {
			errMsg := fmt.Sprintf("%s file format error:   cannot create sensor with reserved name %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if cs, _ := cacher.GetDlpSensor(sensor.Name, access.NewReaderAccessControl()); cs != nil && cs.Predefine {
			errMsg := fmt.Sprintf("%s file format error:   cannot modify predefined sensor %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if sensor.Comment != nil && len(*sensor.Comment) > api.DlpRuleCommentMaxLen {
			errMsg := fmt.Sprintf("%s file format error:   comment exceed max %d characters!", reviewTypeDisplay, api.DlpRuleCommentMaxLen)
			return nil, 1, errMsg, recordName
		}

		ruleList := make([]api.RESTDlpRule, len(sensor.RuleList))
		for idx, rule := range sensor.RuleList {
			ruleList[idx] = api.RESTDlpRule{
				Name:     *rule.Name,
				Patterns: rule.Patterns,
				CfgType:  cfgType,
			}
		}
		if err := validateDlpRuleConfig(ruleList); err != nil {
			errMsg := fmt.Sprintf("%s file format error:  %s", reviewTypeDisplay, err.Error())
			return nil, 1, errMsg, recordName
		}
		crdCfgRet.DlpSensorCfg = &api.RESTDlpSensorConfig{
			Name:    sensor.Name,
			Comment: sensor.Comment,
			Rules:   &ruleList,
		}
	} else {
		crdCfgRet.DlpSensorCfg = &api.RESTDlpSensorConfig{
			Name: *dlpSecRule.Metadata.Name,
		}
	}

	return crdCfgRet, errCount, buffer.String(), recordName
}

// for CRD WAF sensor import
func (h *nvCrdHandler) parseCurCrdWafContent(wafSecRule *resource.NvWafSecurityRule, reviewType share.TReviewType,
	reviewTypeDisplay string) (*resource.NvSecurityParse, int, string, string) {

	if wafSecRule == nil || wafSecRule.Metadata == nil || wafSecRule.Metadata.Name == nil {
		errMsg := fmt.Sprintf("%s file format error:  validation error", reviewTypeDisplay)
		return nil, 1, errMsg, ""
	}

	var cfgType string = api.CfgTypeUserCreated
	if reviewType == share.ReviewTypeCRD {
		cfgType = api.CfgTypeGround
	}

	var buffer bytes.Buffer
	errCount := 0
	crdCfgRet := &resource.NvSecurityParse{}
	name := *wafSecRule.Metadata.Name
	recordName := fmt.Sprintf("%s-default-%s", *wafSecRule.Kind, name)
	if wafSecRule.Spec.Sensor != nil {
		sensor := wafSecRule.Spec.Sensor
		if sensor.Name != name {
			errMsg := fmt.Sprintf("%s file format error:  mismatched name in sensor and metadata %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if !isObjectNameValid(sensor.Name) {
			errMsg := fmt.Sprintf("%s file format error:  invalid characters in name %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if sensor.Name == share.CLUSWafDefaultSensor || strings.HasPrefix(sensor.Name, api.FederalGroupPrefix) {
			errMsg := fmt.Sprintf("%s file format error:   cannot create sensor with reserved name %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if cs, _ := cacher.GetWafSensor(sensor.Name, access.NewReaderAccessControl()); cs != nil && cs.Predefine {
			errMsg := fmt.Sprintf("%s file format error:   cannot modify predefined sensor %s", reviewTypeDisplay, name)
			return nil, 1, errMsg, recordName
		}
		if sensor.Comment != nil && len(*sensor.Comment) > api.DlpRuleCommentMaxLen {
			errMsg := fmt.Sprintf("%s file format error:   comment exceed max %d characters!", reviewTypeDisplay, api.DlpRuleCommentMaxLen)
			return nil, 1, errMsg, recordName
		}

		ruleList := make([]api.RESTWafRule, len(sensor.RuleList))
		for idx, rule := range sensor.RuleList {
			ruleList[idx] = api.RESTWafRule{
				Name:     *rule.Name,
				Patterns: rule.Patterns,
				CfgType:  cfgType,
			}
		}
		if err := validateWafRuleConfig(ruleList); err != nil {
			errMsg := fmt.Sprintf("%s file format error:  %s", reviewTypeDisplay, err.Error())
			return nil, 1, errMsg, recordName
		}
		crdCfgRet.WafSensorCfg = &api.RESTWafSensorConfig{
			Name:    sensor.Name,
			Comment: sensor.Comment,
			Rules:   &ruleList,
		}
	} else {
		crdCfgRet.WafSensorCfg = &api.RESTWafSensorConfig{
			Name: *wafSecRule.Metadata.Name,
		}
	}

	return crdCfgRet, errCount, buffer.String(), recordName
}

// Process the group and network rule list get from the crd. caller must own CLUSLockPolicyKey lock
func (h *nvCrdHandler) crdGFwRuleProcessRecord(crdCfgRet *resource.NvSecurityParse, kind, recordName string) {
	crdRecord := clusHelper.GetCrdSecurityRuleRecord(kind, recordName)
	if crdRecord == nil {
		crdRecord = &share.CLUSCrdSecurityRule{
			Name:   recordName,
			Groups: make([]string, 0),
			Rules:  make(map[string]uint32),
		}
	}

	groupNew, targetGroupDlpWAF := h.crdHandleGroupsAdd(crdCfgRet.GroupCfgs, crdCfgRet.TargetName)
	absentGroup := findAbsentGroups(crdRecord, groupNew)

	h.crdHandleGroupRecordDel(crdRecord, absentGroup, false)

	log.WithFields(log.Fields{"name": recordName, "target": crdCfgRet.TargetName, "targetDlpWAF": targetGroupDlpWAF}).Debug()
	var profile_mode string
	var baseline string
	if crdCfgRet.ProcessProfileCfg != nil {
		// nodes, containers, service or user-defined groups
		profile_mode = crdCfgRet.ProcessProfileCfg.Mode
		crdRecord.ProfileName = crdCfgRet.TargetName
		crdRecord.ProfileMode = profile_mode
		crdRecord.ProcessProfile = share.CLUSCrdProcessProfile{Baseline: crdCfgRet.ProcessProfileCfg.Baseline}
		crdRecord.ProcessRules = h.crdGetProcessRules(crdCfgRet.ProcessProfileCfg)
		crdRecord.FileRules = h.crdGetFileRules(crdCfgRet.FileProfileCfg)
	}

	// handle rule part of crd
	ruleNew := h.crdHandleRules(crdCfgRet.RuleCfgs, crdRecord)
	crdRecord.Groups = groupNew
	crdRecord.Rules = *ruleNew
	if targetGroupDlpWAF {
		if crdCfgRet.DlpGroupCfg == nil {
			crdCfgRet.DlpGroupCfg = &api.RESTCrdDlpGroupConfig{RepSensors: make([]api.RESTCrdDlpGroupSetting, 0)}
		}
		if crdCfgRet.WafGroupCfg == nil {
			crdCfgRet.WafGroupCfg = &api.RESTCrdWafGroupConfig{RepSensors: make([]api.RESTCrdWafGroupSetting, 0)}
		}
		crdRecord.DlpGroupSensors = h.crdHandleDlpGroup(crdCfgRet.TargetName, crdCfgRet.DlpGroupCfg, share.GroundCfg)
		crdRecord.WafGroupSensors = h.crdHandleWafGroup(crdCfgRet.TargetName, crdCfgRet.WafGroupCfg, share.GroundCfg)
	}
	clusHelper.PutCrdSecurityRuleRecord(kind, recordName, crdRecord)
	if crdRecord.ProfileName != "" {
		profile_mode, baseline = h.crdRebuildGroupProfiles(crdRecord.ProfileName, nil, share.ReviewTypeCRD)
	}
	h.crdHandlePolicyMode(crdCfgRet.PolicyModeCfg, profile_mode, baseline)
}

// Process the admission control rule list get from the crd. caller must own CLUSLockAdmCtrlKey lock
func (h *nvCrdHandler) crdAdmCtrlRuleRecord(crdCfgRet *resource.NvSecurityParse, kind, recordName string) {
	crdRecord := clusHelper.GetCrdSecurityRuleRecord(kind, recordName)
	if crdRecord == nil {
		crdRecord = &share.CLUSCrdSecurityRule{
			Name:         recordName,
			AdmCtrlRules: make(map[string]uint32),
		}
	}

	log.WithFields(log.Fields{"name": recordName}).Debug()
	// handle admission control rule part of crd
	ruleNew := h.crdHandleAdmCtrlRules(share.ScopeLocal, crdCfgRet.AdmCtrlRulesCfg, crdRecord, share.ReviewTypeCRD)
	crdRecord.AdmCtrlRules = ruleNew
	h.crdHandleAdmCtrlConfig(share.ScopeLocal, crdCfgRet.AdmCtrlCfg, crdRecord, share.ReviewTypeCRD)
	clusHelper.PutCrdSecurityRuleRecord(kind, recordName, crdRecord)
}

// Process DLP sensor get from the crd. caller must own CLUSLockPolicyKey lock
func (h *nvCrdHandler) crdDlpSensorRecord(crdCfgRet *resource.NvSecurityParse, kind, recordName string) {
	crdRecord := clusHelper.GetCrdSecurityRuleRecord(kind, recordName)
	if crdRecord == nil {
		crdRecord = &share.CLUSCrdSecurityRule{
			Name:      recordName,
			DlpSensor: crdCfgRet.DlpSensorCfg.Name,
		}
	}

	log.WithFields(log.Fields{"name": recordName}).Debug()
	// handle dlp part of crd (dlp sensor definition, not per-group's sensors association)
	h.crdHandleDlpSensor(share.ScopeLocal, crdCfgRet.DlpSensorCfg, crdRecord, share.ReviewTypeCRD)
	clusHelper.PutCrdSecurityRuleRecord(kind, recordName, crdRecord)
}

// Process WAF sensor get from the crd. caller must own CLUSLockPolicyKey lock
func (h *nvCrdHandler) crdWafSensorRecord(crdCfgRet *resource.NvSecurityParse, kind, recordName string) {
	crdRecord := clusHelper.GetCrdSecurityRuleRecord(kind, recordName)
	if crdRecord == nil {
		crdRecord = &share.CLUSCrdSecurityRule{
			Name:      recordName,
			WafSensor: crdCfgRet.WafSensorCfg.Name,
		}
	}

	log.WithFields(log.Fields{"name": recordName}).Debug()
	// handle waf part of crd (waf sensor definition, not per-group's sensors association)
	h.crdHandleWafSensor(share.ScopeLocal, crdCfgRet.WafSensorCfg, crdRecord, share.ReviewTypeCRD)
	clusHelper.PutCrdSecurityRuleRecord(kind, recordName, crdRecord)
}

// for CRD only
func (h *nvCrdHandler) parseCrdContent(raw []byte) (*resource.NvSecurityParse, int, string, string, string) {
	var crdCfgRet *resource.NvSecurityParse
	var secRulePartial resource.NvSecurityRulePartial
	var gfwrule resource.NvSecurityRule
	var admCtrlSecRule resource.NvAdmCtrlSecurityRule
	var dlpSecRule resource.NvDlpSecurityRule
	var wafSecRule resource.NvWafSecurityRule
	var buffer bytes.Buffer
	var errMsg, recordName string
	var kind string
	var err error

	if err = json.Unmarshal(raw, &secRulePartial); err == nil {
		if secRulePartial.Metadata == nil || secRulePartial.Metadata.Name == nil {
			err = fmt.Errorf("no metadata name")
		} else {
			kind = *secRulePartial.Kind
			switch kind {
			case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
				err = json.Unmarshal(raw, &gfwrule)
			case resource.NvAdmCtrlSecurityRuleKind:
				err = json.Unmarshal(raw, &admCtrlSecRule)
			case resource.NvDlpSecurityRuleKind:
				err = json.Unmarshal(raw, &dlpSecRule)
			case resource.NvWafSecurityRuleKind:
				err = json.Unmarshal(raw, &wafSecRule)
			default:
				err = errors.New("unsupported Kubernetese resource kind")
			}
		}
	}
	//	var groupName string
	errCount := 0
	if err != nil {
		buffer.WriteString("  CRD Rule format error:  ")
		buffer.WriteString(err.Error())
		errMsg = buffer.String()
		errCount++
	} else {
		switch kind {
		case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
			crdCfgRet, errCount, errMsg, recordName = h.parseCurCrdContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
		case resource.NvAdmCtrlSecurityRuleKind:
			crdCfgRet, errCount, errMsg, recordName = h.parseCurCrdAdmCtrlContent(&admCtrlSecRule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
		case resource.NvDlpSecurityRuleKind:
			crdCfgRet, errCount, errMsg, recordName = h.parseCurCrdDlpContent(&dlpSecRule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
		case resource.NvWafSecurityRuleKind:
			crdCfgRet, errCount, errMsg, recordName = h.parseCurCrdWafContent(&wafSecRule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
		}
	}

	if errCount > 0 {
		var err1 error
		log.Printf("CRD validate fail : %s\n", errMsg)
		switch kind {
		case resource.NvSecurityRuleKind:
			err1 = global.ORCH.DeleteResource(resource.RscTypeCrdSecurityRule, &gfwrule)
		case resource.NvClusterSecurityRuleKind:
			r := resource.NvClusterSecurityRule(gfwrule)
			err1 = global.ORCH.DeleteResource(resource.RscTypeCrdClusterSecurityRule, &r)
		case resource.NvAdmCtrlSecurityRuleKind:
			err1 = global.ORCH.DeleteResource(resource.RscTypeCrdAdmCtrlSecurityRule, &admCtrlSecRule)
		case resource.NvDlpSecurityRuleKind:
			err1 = global.ORCH.DeleteResource(resource.RscTypeCrdDlpSecurityRule, &dlpSecRule)
		case resource.NvWafSecurityRuleKind:
			err1 = global.ORCH.DeleteResource(resource.RscTypeCrdWafSecurityRule, &wafSecRule)
		}
		if err1 != nil {
			log.WithFields(log.Fields{"error": err1}).Error(recordName)
		}
	}
	return crdCfgRet, errCount, errMsg, recordName, kind
}

func (h *nvCrdHandler) crdGFwRuleHandler(req *admissionv1beta1.AdmissionRequest) {
	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}
	var detail []string
	switch req.Operation {
	case "DELETE":
		var recordName string
		var ruleNs string = "default"
		var kind string = req.Kind.Kind
		if req.Kind.Kind == resource.NvSecurityRuleKind || req.Kind.Kind == resource.NvClusterSecurityRuleKind {
			kind = resource.NvSecurityRuleKind
			if req.Kind.Kind == resource.NvSecurityRuleKind {
				ruleNs = req.Namespace
			}
		}
		if req.Name == "" {
			var secRulePartial resource.NvSecurityRulePartial
			if err := json.Unmarshal(req.OldObject.Raw, &secRulePartial); err == nil && secRulePartial.Metadata != nil {
				req.Name = secRulePartial.Metadata.GetName()
			}
		}
		recordName = fmt.Sprintf("%s-%s-%s", req.Kind.Kind, ruleNs, req.Name)
		crdRecord := clusHelper.GetCrdSecurityRuleRecord(kind, recordName)
		if crdRecord != nil {
			log.WithFields(log.Fields{"name": req.Name, "kind": req.Kind.Kind, "ns": req.Namespace}).Info("deleting CRD ...")
			switch req.Kind.Kind {
			case resource.NvAdmCtrlSecurityRuleKind:
				h.crdDeleteAdmCtrlRules()
				setAdmCtrlStateInCluster(nil, nil, nil, nil, nil, share.UserCreated)
				h.crdDeleteRecord(req.Kind.Kind, recordName)
			case resource.NvDlpSecurityRuleKind:
				deleteDlpSensor(nil, crdRecord.DlpSensor, share.ReviewTypeCRD, true, h.acc, nil)
				h.crdDeleteRecord(req.Kind.Kind, recordName)
			case resource.NvWafSecurityRuleKind:
				deleteWafSensor(nil, crdRecord.WafSensor, share.ReviewTypeCRD, true, h.acc, nil)
				h.crdDeleteRecord(req.Kind.Kind, recordName)
			case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
				h.crdDeleteRules(crdRecord.Rules)
				h.crdHandleGroupRecordDel(crdRecord, crdRecord.Groups, false)
				h.crdDeleteRecordEx(resource.NvSecurityRuleKind, recordName, crdRecord.ProfileName)
			}
			e := fmt.Sprintf("CustomResourceDefinition %s", req.Kind.Kind)
			msg := fmt.Sprintf("%s deleted.", recordName)
			detail = append(detail, msg)
			k8sResourceLog(share.CLUSEvCrdRemoved, e, detail)
			log.WithFields(log.Fields{"crdName": recordName}).Info("CRD deleted")
		}
	case "CREATE", "UPDATE":
		var kind string
		var errCount int
		var err, recordName string
		var crdCfgRet *resource.NvSecurityParse

		log.WithFields(log.Fields{"name": req.Name, "kind": req.Kind.Kind, "ns": req.Namespace}).Info("processing CRD ...")
		// First parse the crd content, validate for error and generate final list if no error
		crdCfgRet, errCount, err, recordName, kind = h.parseCrdContent(req.Object.Raw)
		if errCount == 0 {
			// process the parse result.
			switch kind {
			case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
				h.crdGFwRuleProcessRecord(crdCfgRet, resource.NvSecurityRuleKind, recordName)
			case resource.NvAdmCtrlSecurityRuleKind:
				if crdCfgRet != nil { // for NvAdmissionControlSecurityRule resource objects with metadata name other than "local", ignore them
					h.crdAdmCtrlRuleRecord(crdCfgRet, kind, recordName)
				}
			case resource.NvDlpSecurityRuleKind:
				h.crdDlpSensorRecord(crdCfgRet, kind, recordName)
			case resource.NvWafSecurityRuleKind:
				h.crdWafSensorRecord(crdCfgRet, kind, recordName)
			default:
				errCount = 1
				err = "unsupported Kubernetese resource kind"
			}
		}
		if errCount > 0 {
			e := fmt.Sprintf("CRD %s Removed", recordName)
			detail = append(detail, err)
			k8sResourceLog(share.CLUSEvCrdErrDetected, e, detail)
			log.WithFields(log.Fields{"crdName": recordName}).Error("Failed to add CRD")
		} else {
			e := fmt.Sprintf("CRD %s Processed", recordName)
			detail = append(detail, recordName)
			k8sResourceLog(share.CLUSEvCrdImported, e, detail)
			log.WithFields(log.Fields{"crdName": recordName}).Info("CRD processed")
		}

	}
	return
}

func isExportSkipGroupName(name string, acc *access.AccessControl) (bool, *api.RESTGroup) {
	// allow group with prefix "nv.ip."
	if strings.HasPrefix(name, api.LearnedHostPrefix) {
		return true, nil
	} else if strings.HasPrefix(name, api.LearnedWorkloadPrefix) {
		if name[len(api.LearnedWorkloadPrefix):] != api.EndpointIngress {
			return true, nil
		}
		return false, nil
	} else {
		group, _ := cacher.GetGroup(name, "", false, acc)
		if group == nil || group.CfgType == api.CfgTypeFederal {
			return true, nil
		}
		return false, group
	}
}

func exportAttachRule(rule *api.RESTPolicyRule, useFrom bool, acc *access.AccessControl, cnt int) *resource.NvSecurityRuleDetail {

	var detail resource.NvSecurityRuleDetail
	var group *api.RESTGroup
	var skip bool
	detail.Applications = rule.Applications
	detail.Ports = rule.Ports
	detail.Action = rule.Action
	detail.Priority = rule.Priority

	if useFrom {
		if skip, group = isExportSkipGroupName(rule.From, acc); skip {
			e := "Skip special group export"
			log.WithFields(log.Fields{"name": rule.From}).Error(e)
			return nil
		}
		detail.Name = fmt.Sprintf("%s-ingress-%d", rule.To, cnt)
		detail.Selector.Name = rule.From
	} else {
		if skip, group = isExportSkipGroupName(rule.To, acc); skip {
			e := "Skip special group export"
			log.WithFields(log.Fields{"name": rule.To}).Error(e)
			return nil
		}

		detail.Name = fmt.Sprintf("%s-egress-%d", rule.To, cnt)
		detail.Selector.Name = rule.To
	}

	if group != nil {
		detail.Selector.Criteria = &group.Criteria
	}

	return &detail
}

func handlerGroupCfgExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()
	var data []byte
	var inCount, eCount int
	var group *api.RESTGroup
	var skip bool

	policy_ids := utils.NewSet()
	acc, _ := getAccessControl(w, r, access.AccessOPRead) // handlerGroupCfgExport() is used for both GET/POST so we force the op to be AccessOPRead for access control
	if acc == nil {
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	var rconf api.RESTGroupExport

	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	apiVersion := resource.NvSecurityRuleVersion
	filename := "cfgExport.yaml"
	resp := resource.NvSecurityRuleList{
		Kind:       &resource.NvListKind,
		ApiVersion: &apiVersion,
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		return
	}
	defer clusHelper.ReleaseLock(lock)
	for _, gname := range rconf.Groups {

		if skip, group = isExportSkipGroupName(gname, acc); skip {
			e := "Skip special group export"
			log.WithFields(log.Fields{"name": gname}).Error(e)
			continue
		}

		if group == nil || group.CfgType == api.CfgTypeFederal {
			continue
		}

		tgroup := group2RESTConfig(group)
		kindName := utils.Dns1123NameChg(gname)
		targetNs := ""
		targetKind := resource.NvClusterSecurityRuleKind
		apiversion := fmt.Sprintf("%s/%s", common.OEMClusterSecurityRuleGroup, resource.NvClusterSecurityRuleVersion)
		for _, ct := range group.Criteria {
			if ct.Key == share.CriteriaKeyDomain {
				targetNs = ct.Value
				targetKind = resource.NvSecurityRuleKind
				apiversion = fmt.Sprintf("%s/%s", common.OEMSecurityRuleGroup, resource.NvSecurityRuleVersion)

			}
		}

		resptmp := resource.NvSecurityRule{
			//Kind: &resource.NvSecurityRuleKind,
			Kind: &targetKind,
			Metadata: &cmetav1.ObjectMeta{
				Name:      &kindName,
				Namespace: &targetNs,
			},
			ApiVersion: &apiversion,
			Spec: resource.NvSecurityRuleSpec{
				Target: resource.NvSecurityTarget{
					Selector: *tgroup,
				},
				IngressRule: make([]resource.NvSecurityRuleDetail, 0),
				EgressRule:  make([]resource.NvSecurityRuleDetail, 0),
				ProcessRule: make([]resource.NvSecurityProcessRule, 0),
				FileRule:    make([]resource.NvSecurityFileRule, 0),
			},
		}
		// If Learned group add the policy mode in crd
		if utils.DoesGroupHavePolicyMode(gname) {
			if rconf.PolicyMode != "" {
				resptmp.Spec.Target.PolicyMode = &rconf.PolicyMode
			} else {
				resptmp.Spec.Target.PolicyMode = &group.PolicyMode
			}
		} else {
			resptmp.Spec.Target.PolicyMode = func() *string { b := share.PolicyModeUnavailable; return &b }()
		}

		// export process and file profiles
		exportProcessRule(gname, &(resptmp.Spec), acc)
		if gname != api.AllHostGroup { // TODO: skip file for now
			exportFileRule(gname, &(resptmp.Spec), acc)
		}

		// export group's dlp/waf data
		if group.Kind == share.GroupKindContainer {
			exportDlpWafGroup(gname, &resptmp, acc)
		}

		for _, idx := range group.PolicyRules {
			if policy_ids.Contains(idx) {
				continue
			}
			policy_ids.Add(idx)
			rule, _ := cacher.GetPolicyRule(idx, acc)
			if rule != nil {
				if rule.To == gname {
					detail := exportAttachRule(rule, true, acc, inCount)
					if detail != nil {
						resptmp.Spec.IngressRule = append(resptmp.Spec.IngressRule, *detail)
						inCount = inCount + 1
					}
				} else {
					detail := exportAttachRule(rule, false, acc, eCount)
					if detail != nil {
						resptmp.Spec.EgressRule = append(resptmp.Spec.EgressRule, *detail)
						eCount = eCount + 1
					}
				}
			}
		}

		resp.Items = append(resp.Items, &resptmp)
	}
	// for all the group in the From/To , if learned group we also need export it's policymode
	// We don't know the default policy mode in other system so in current system just export

	// tell the browser the returned content should be downloaded
	w.Header().Set("Content-Disposition", "Attachment; filename="+filename)
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)
	json_data, _ := json.MarshalIndent(resp, "", "  ")
	data, _ = yaml.JSONToYAML(json_data)
	data = utils.GzipBytes(data)
	w.Write(data)
}

func (h *nvCrdHandler) crdDeleteRecord(kind, recordName string) {
	if recordName != "" {
		clusHelper.DeleteCrdSecurityRuleRecord(kind, recordName)
	}
}

func (h *nvCrdHandler) crdDeleteRecordEx(kind, recordName, profileName string) {
	h.crdDeleteRecord(kind, recordName)
	if profileName == "" {
		return
	}
	mode, baseline := h.crdRebuildGroupProfiles(profileName, nil, share.ReviewTypeCRD)
	if utils.DoesGroupHavePolicyMode(profileName) && mode != "" {
		policy_mode := &api.RESTServiceConfig{Name: profileName, PolicyMode: &mode}
		h.crdHandlePolicyMode(policy_mode, mode, baseline)
	}
}

//// utility functions for process and file profiles
func (h *nvCrdHandler) crdGetProcessRules(profile *api.RESTProcessProfile) []share.CLUSCrdProcessRule {
	rules := make([]share.CLUSCrdProcessRule, 0)
	for _, proc := range profile.ProcessList {
		r := &share.CLUSCrdProcessRule{
			Name:            proc.Name,
			Path:            proc.Path,
			Action:          proc.Action,
			AllowFileUpdate: proc.AllowFileUpdate,
		}
		rules = append(rules, *r)
	}
	return rules
}

func (h *nvCrdHandler) crdGetFileRules(profile *api.RESTFileMonitorProfile) []share.CLUSCrdFileRule {
	rules := make([]share.CLUSCrdFileRule, 0)
	for _, ffp := range profile.Filters {
		fr := &share.CLUSCrdFileRule{
			Filter:    ffp.Filter,
			Recursive: ffp.Recursive,
			Behavior:  ffp.Behavior,
			App:       ffp.Apps,
		}
		rules = append(rules, *fr)
	}
	return rules
}

func exportProcessRule(group string, secRule *resource.NvSecurityRuleSpec, acc *access.AccessControl) bool {
	log.WithFields(log.Fields{"name": group}).Debug()
	if profile, err := cacher.GetProcessProfile(group, acc); err == nil {
		if utils.DoesGroupHavePolicyMode(group) {
			baseline := share.ProfileZeroDrift
			if profile.Baseline == share.ProfileBasic {
				baseline = share.ProfileBasic
			}
			secRule.ProcessProfile = &resource.NvSecurityProcessProfile{Baseline: &baseline}
			secRule.ProcessProfile.Baseline = &baseline
		}
		dupChecker := utils.NewSet()
		for _, gproc := range profile.ProcessList {
			key := fmt.Sprintf("%s::%s::%s", gproc.Name, gproc.Path, gproc.Action)
			if !dupChecker.Contains(key) {
				dupChecker.Add(key)
				//
				r := &resource.NvSecurityProcessRule{
					Name:            gproc.Name,
					Path:            gproc.Path,
					Action:          gproc.Action,
					AllowFileUpdate: gproc.AllowFileUpdate,
				}
				secRule.ProcessRule = append(secRule.ProcessRule, *r)
			}
		}
		return true
	}

	log.WithFields(log.Fields{"name": group}).Debug("failed")
	return false
}

func exportFileRule(group string, rules *resource.NvSecurityRuleSpec, acc *access.AccessControl) bool {
	log.WithFields(log.Fields{"name": group}).Debug()
	// not include predefined list
	if profile, err := cacher.GetFileMonitorProfile(group, acc, false); err == nil {
		dupChecker := utils.NewSet()
		for _, ff := range profile.Filters {
			key := fmt.Sprintf("%s::%v::%s", ff.Filter, ff.Recursive, ff.Behavior)
			if !dupChecker.Contains(key) {
				dupChecker.Add(key)
				//
				r := &resource.NvSecurityFileRule{
					Filter:    ff.Filter,
					Recursive: ff.Recursive,
					Behavior:  ff.Behavior,
					App:       ff.Apps,
				}
				rules.FileRule = append(rules.FileRule, *r)
			}
		}
		return true
	} else {
		log.WithFields(log.Fields{"name": group, "err": err}).Error()
	}

	return false
}

func exportDlpWafGroup(group string, secRule *resource.NvSecurityRule, acc *access.AccessControl) {
	log.WithFields(log.Fields{"name": group}).Debug()
	if dlpGroup, err := cacher.GetDlpGroup(group, acc); err == nil {
		settings := make([]api.RESTCrdDlpGroupSetting, len(dlpGroup.Sensors))
		for idx, s := range dlpGroup.Sensors {
			settings[idx] = api.RESTCrdDlpGroupSetting{
				Name:   s.Name,
				Action: s.Action,
			}
		}
		secRule.Spec.DlpGroup = &resource.NvSecurityDlpGroup{
			Status:   dlpGroup.Status,
			Settings: settings,
		}
	} else {
		log.WithFields(log.Fields{"name": group, "err": err}).Error("dlp")
	}

	if wafGroup, err := cacher.GetWafGroup(group, acc); err == nil {
		settings := make([]api.RESTCrdWafGroupSetting, len(wafGroup.Sensors))
		for idx, s := range wafGroup.Sensors {
			settings[idx] = api.RESTCrdWafGroupSetting{
				Name:   s.Name,
				Action: s.Action,
			}
		}
		secRule.Spec.WafGroup = &resource.NvSecurityWafGroup{
			Status:   wafGroup.Status,
			Settings: settings,
		}
	} else {
		log.WithFields(log.Fields{"name": group, "err": err}).Error("waf")
	}
}

func (h *nvCrdHandler) crdReadyToDeleteProfiles(targetCrdName string, group *api.RESTGroup) bool {
	crdName := targetCrdName
	profileName := group.Name

	// log.WithFields(log.Fields{"crdName": crdName, "profileName": profileName}).Debug("CRD:")

	// valid profile name?
	if profileName == "" {
		// log.WithFields(log.Fields{"crdName": crdName}).Debug("CRD: no profile")
		return true
	}

	// can not removed default group: "nodes" and "containers"
	if profileName == api.AllHostGroup || profileName == api.AllContainerGroup || profileName == api.LearnedExternal {
		return false
	}

	// any local process rules?
	if pp := clusHelper.GetProcessProfile(profileName); pp != nil {
		for _, proc := range pp.Process {
			if proc.CfgType != share.GroundCfg {
				log.WithFields(log.Fields{"crdName": crdName, "name": profileName, "proc": proc}).Debug("CRD: local")
				return false
			}
		}
	}

	// any local file rules?
	if mon, _ := clusHelper.GetFileMonitorProfile(profileName); mon != nil {
		for _, flt := range mon.Filters { // non-CRD
			if f, ok := cacher.IsPrdefineFileGroup(flt.Filter, flt.Recursive); ok {
				if f.CustomerAdd {
					log.WithFields(log.Fields{"crdName": crdName, "name": profileName, "flt": f}).Debug("CRD: local")
					return false
				}
			}
		}
	}

	// other CRD rules, which matched the profile
	records := clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
	for _, record := range records {
		if (record.Name == crdName) || (record.ProfileName != profileName) {
			continue
		}
		if len(record.ProcessRules) > 0 {
			log.WithFields(log.Fields{"crdName": crdName, "name": profileName, "prule_cnt": len(record.ProcessRules)}).Debug("CRD: other")
			return false
		}
		if len(record.FileRules) > 0 {
			log.WithFields(log.Fields{"crdName": crdName, "name": profileName, "frule_cnt": len(record.FileRules)}).Debug("CRD: other")
			return false
		}
	}
	return true
}

// Get highest CRD security level in related crd records
func (h *nvCrdHandler) crdGetProfileSecurityLevel(profileName string, records map[string]*share.CLUSCrdSecurityRule) string {

	mode := ""
	if utils.DoesGroupHavePolicyMode(profileName) {
		for _, record := range records {
			if record.ProfileName != profileName {
				continue
			}

			switch record.ProfileMode {
			case share.PolicyModeEnforce:
				log.WithFields(log.Fields{"name": record.Name}).Debug("CRD: decision")
				mode = record.ProfileMode
			case share.PolicyModeEvaluate:
				log.WithFields(log.Fields{"name": record.Name}).Debug("CRD: decision ...")
				mode = record.ProfileMode
			case share.PolicyModeLearn:
				if mode == "" {
					mode = record.ProfileMode
				}
			}

			// highest level
			if mode == share.PolicyModeEnforce {
				break
			}
		}

		// no more related crd record, restore as system default
		if mode == "" {
			mode = cacher.GetNewServicePolicyMode()
		}
	}
	return mode
}

// rebuild group process and file profiles from CRD records
func (h *nvCrdHandler) crdRebuildGroupProfiles(groupName string, records map[string]*share.CLUSCrdSecurityRule, reviewType share.TReviewType) (string, string) {
	if grp, _, err := clusHelper.GetGroup(groupName, h.acc); grp == nil || err != nil {
		log.WithFields(log.Fields{"groupName": groupName}).Debug("not existed")
		return "", ""
	}

	if records == nil {
		records = clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
	}

	baseline := share.ProfileZeroDrift
	mode := h.crdGetProfileSecurityLevel(groupName, records)
	procs := make(map[string]*share.CLUSCrdProcessRule, 0)
	files := make(map[string]*share.CLUSCrdFileRule, 0)
	for _, record := range records {
		if record.ProfileName != groupName {
			continue
		}

		if record.ProcessProfile.Baseline == share.ProfileBasic {
			baseline = share.ProfileBasic
		}
		// collecting process rules
		for i, pr := range record.ProcessRules {
			key := fmt.Sprintf("%s::%s::%s", pr.Name, pr.Path, pr.Action)
			procs[key] = &(record.ProcessRules[i])
		}

		// collecting file rules
		for i, fr := range record.FileRules {
			key := fmt.Sprintf("%s::%v::%s", fr.Filter, fr.Recursive, fr.Behavior)
			if ffr, ok := files[key]; ok {
				apps := utils.NewSet()
				for _, app := range ffr.App { // from map
					apps.Add(app)
				}

				for _, app := range fr.App { // from new crd
					apps.Add(app)
				}
				ffr.App = apps.ToStringSlice()
			} else { // new entry
				files[key] = &(record.FileRules[i])
			}
		}
	}

	////
	pprofile := &api.RESTProcessProfile{
		Group:       groupName,
		Baseline:    baseline,
		Mode:        mode,
		ProcessList: make([]*api.RESTProcessProfileEntry, 0),
	}

	/// from map to slices
	for _, pp := range procs {
		ppa := &api.RESTProcessProfileEntry{
			Name:            pp.Name,
			Path:            pp.Path,
			Action:          pp.Action,
			AllowFileUpdate: pp.AllowFileUpdate,
		}
		pprofile.ProcessList = append(pprofile.ProcessList, ppa)
	}

	////
	fprofile := &api.RESTFileMonitorProfile{
		Group:   groupName,
		Filters: make([]*api.RESTFileMonitorFilter, 0),
	}

	/// from map to slices
	for _, ff := range files {
		ffa := &api.RESTFileMonitorFilter{
			Filter:    ff.Filter,
			Recursive: ff.Recursive,
			Behavior:  ff.Behavior,
			Apps:      ff.App,
		}
		fprofile.Filters = append(fprofile.Filters, ffa)
	}

	// update process rules
	h.crdHandleProcessProfile(groupName, mode, pprofile, reviewType)

	// update file rules
	h.crdHandleFileProfile(groupName, mode, fprofile, reviewType)
	return mode, baseline
}

// kvOnly: true means the checking is triggered by kv change(ex: import). false means the check is triggered by k8s(ex: startup)
func CrossCheckCrd(kind, rscType, kvCrdKind, lockKey string, kvOnly bool) error {
	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}

	var err error
	var objs []interface{}
	var imported, deleted []string

	gwrecordlist := clusHelper.GetCrdSecurityRuleRecordList(kvCrdKind)
	objs, err = global.ORCH.ListResource(rscType)
	if err != nil {
		log.WithFields(log.Fields{"rscType": rscType, "err": err}).Error()
		return err
	}

	var crdHandler nvCrdHandler
	crdHandler.Init(lockKey)
	if !crdHandler.AcquireLock(clusterLockWait) {
		return nil
	}

	acc := access.NewAdminAccessControl()
	switch kind {
	case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
		if len(gwrecordlist) == 0 && kvOnly {
			// crd records in policy cofiguration export may be missing(4.2.2-) or different from what are configured in k8s.
			// So we first revert crd groups & remove crd policies in kv and then parse the crd rules in k8s(based on objs) again
			// In this way we are sure the final crd groups/policies are exactly what's configured in k8s
			delRules := make(map[string]uint32, 4)
			// for crd network policy
			for _, crh := range clusHelper.GetPolicyRuleList() {
				if isSecurityPolicyID(crh.ID) {
					delRules[fmt.Sprintf("%d", crh.ID)] = crh.ID
				}
			}
			crdHandler.crdDeleteRules(delRules)
			// for crd groups
			groupToUpdate := make([]string, 0, 4)
			for _, cg := range clusHelper.GetAllGroups(share.ScopeLocal, acc) {
				if cg.CfgType == share.GroundCfg {
					groupToUpdate = append(groupToUpdate, cg.Name)
				}
			}
			crdHandler.crdUpdateGroup(groupToUpdate)
			for _, gName := range groupToUpdate {
				crdHandler.crdDeleteRecordEx(kvCrdKind, "", gName)
			}
		}
	case resource.NvAdmCtrlSecurityRuleKind:
		// crd records in admission control rules export may be different from what are configured in k8s.
		// So we first remove crd admission control rules in kv and then parse the crd rules in k8s(based on objs) again
		// In this way we are sure the final crd admission control rules are exactly what's configured in k8s
		crdHandler.crdDeleteAdmCtrlRules()
		setAdmCtrlStateInCluster(nil, nil, nil, nil, nil, share.UserCreated)
	case resource.NvDlpSecurityRuleKind:
		crdHandler.crdUpdateDlpSensors()
	case resource.NvWafSecurityRuleKind:
		crdHandler.crdUpdateWafSensors()
	}
	crdHandler.ReleaseLock()

	for _, obj := range objs {
		var crdCfgRet *resource.NvSecurityParse
		var err, recordname string
		var errCount int

		if !crdHandler.AcquireLock(clusterLockWait) {
			continue
		}

		if kind == resource.NvSecurityRuleKind {
			r := obj.(*resource.NvSecurityRule)
			crdCfgRet, errCount, err, recordname = crdHandler.parseCurCrdContent(r, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
			if errCount > 0 {
				log.WithFields(log.Fields{"error": err}).Error()
				e := fmt.Sprintf("    %s in namespace %s deleted due to error:   %s \n", *r.Metadata.Name,
					*r.Metadata.Namespace, err)
				deleted = append(deleted, e)
				global.ORCH.DeleteResource(resource.RscTypeCrdSecurityRule, r)
			} else {
				e := fmt.Sprintf("    %s in namespace %s detected and imported\n ", *r.Metadata.Name, *r.Metadata.Namespace)
				imported = append(imported, e)
				delete(gwrecordlist, recordname)
				crdHandler.crdGFwRuleProcessRecord(crdCfgRet, resource.NvSecurityRuleKind, recordname)
			}
		} else {
			var metadataName string
			switch kind {
			case resource.NvClusterSecurityRuleKind:
				r1 := obj.(*resource.NvClusterSecurityRule)
				metadataName = *r1.Metadata.Name
				r := resource.NvSecurityRule(*r1)
				crdCfgRet, errCount, err, recordname = crdHandler.parseCurCrdContent(&r, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
			case resource.NvAdmCtrlSecurityRuleKind:
				r := obj.(*resource.NvAdmCtrlSecurityRule)
				metadataName = *r.Metadata.Name
				crdCfgRet, errCount, err, recordname = crdHandler.parseCurCrdAdmCtrlContent(r, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
			case resource.NvDlpSecurityRuleKind:
				r := obj.(*resource.NvDlpSecurityRule)
				metadataName = *r.Metadata.Name
				crdCfgRet, errCount, err, recordname = crdHandler.parseCurCrdDlpContent(r, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
			case resource.NvWafSecurityRuleKind:
				r := obj.(*resource.NvWafSecurityRule)
				metadataName = *r.Metadata.Name
				crdCfgRet, errCount, err, recordname = crdHandler.parseCurCrdWafContent(r, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
			}
			if errCount > 0 {
				if kind == resource.NvSecurityRuleKind || kind == resource.NvClusterSecurityRuleKind || metadataName == "" {
					// for admission control crd resource, if metaname is empty, delete the crd resource
					log.WithFields(log.Fields{"error": err, "name": metadataName}).Error()
					e := fmt.Sprintf("    %s  deleted due to error:   %s \n", metadataName, err)
					deleted = append(deleted, e)
					global.ORCH.DeleteResource(rscType, obj)
				}
			} else {
				switch kind {
				case resource.NvClusterSecurityRuleKind:
					crdHandler.crdGFwRuleProcessRecord(crdCfgRet, resource.NvSecurityRuleKind, recordname)
				case resource.NvAdmCtrlSecurityRuleKind:
					if crdCfgRet != nil { // for NvAdmissionControlSecurityRule resource objects with metadata name other than "local", ignore them
						crdHandler.crdAdmCtrlRuleRecord(crdCfgRet, kind, recordname)
					}
				case resource.NvDlpSecurityRuleKind:
					crdHandler.crdDlpSensorRecord(crdCfgRet, kind, recordname)
				case resource.NvWafSecurityRuleKind:
					crdHandler.crdWafSensorRecord(crdCfgRet, kind, recordname)
				}
				e := fmt.Sprintf("    %s detected and imported ", metadataName)
				imported = append(imported, e)
				delete(gwrecordlist, recordname)
			}
		}
		crdHandler.ReleaseLock()
		time.Sleep(1 * time.Second)
	}

	if len(imported) > 0 {
		e := fmt.Sprintf("CustomResourceDefinition %s detected and imported", kind)
		k8sResourceLog(share.CLUSEvCrdImported, e, imported)
	}

	if len(deleted) > 0 {
		e := fmt.Sprintf("CustomResourceDefinition %s detected Error and deleted", kind)
		k8sResourceLog(share.CLUSEvCrdErrDetected, e, deleted)
	}

	if len(gwrecordlist) > 0 {
		if crdHandler.AcquireLock(clusterLockWait) {
			removed := crdHandler.crdDelAll(kind, kvCrdKind, gwrecordlist)
			crdHandler.ReleaseLock()
			if len(removed) > 0 {
				e := fmt.Sprintf("CustomResourceDefinition %s cross check", kind)
				k8sResourceLog(share.CLUSEvCrdRemoved, e, removed)
			}
		}
	}

	return nil
}
