package cache

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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

const clusterLockWait = time.Duration(time.Second * 10)

type monitorFilter struct {
	// criteria
	CfgType   share.TCfgType
	filter    string
	path      string
	regex     string
	recursive bool

	// rule
	behavior    string
	customerAdd bool
	apps        utils.Set

	// timestamps
	createdAt time.Time
	updatedAt time.Time
}

type monitorProfile struct {
	filters map[string]*monitorFilter // key is "{flt.Path}/{flt.Regex}:{Cfg_Type}"
}

var fsmonProfileGroups map[string]*monitorProfile = make(map[string]*monitorProfile) // key is group name

func fsmonGetCacheKey(idx string, cfgType share.TCfgType) string {
	return fmt.Sprintf("%s:%d", idx, cfgType) // default:
}

// update profile from config
func fsmonProfileConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSFileMonitorKey2Group(key)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		// log.WithFields(log.Fields{"value": string(value), "key": key}).Debug("")
		var conf share.CLUSFileMonitorProfile
		if err := json.Unmarshal(value, &conf); err != nil {
			log.WithFields(log.Fields{"err": err}).Debug("Fail to decode")
			return
		}

		// create new filters for the profile, also load the rule from the old one
		newMp := &monitorProfile{filters: make(map[string]*monitorFilter)}
		cacheMutexLock()
		mp, ok := fsmonProfileGroups[name]
		if !ok {
			mp = newMp
		}

		for _, flt := range conf.Filters {
			idx := utils.FilterIndexKey(flt.Path, flt.Regex)
			key := fsmonGetCacheKey(idx, 0) // default: filter.CfgType
			// key is in the format {flt.Path}/{flt.Regex}:{cfgType}
			mf, ok := mp.filters[key]
			if !ok {
				mf = &monitorFilter{
					apps: utils.NewSet(),
				}
			}

			if conf.CfgType == share.GroundCfg {
				// added after CRD, correct it by its group name
				mf.CfgType = utils.EvaluateGroupType(name)
			} else {
				mf.CfgType = conf.CfgType
			}

			if mf.CfgType == share.Learned { // not for file rules
				mf.CfgType = share.UserCreated
			}

			mf.filter = flt.Filter
			mf.path = flt.Path
			mf.regex = flt.Regex
			mf.recursive = flt.Recursive
			mf.behavior = flt.Behavior
			mf.customerAdd = flt.CustomerAdd
			newMp.filters[key] = mf
		}

		for _, flt := range conf.FiltersCRD {
			idx := utils.FilterIndexKey(flt.Path, flt.Regex)
			key := fsmonGetCacheKey(idx, share.GroundCfg)
			mf, ok := mp.filters[key]
			if !ok {
				mf = &monitorFilter{
					apps: utils.NewSet(),
				}
			}
			mf.CfgType = share.GroundCfg
			mf.filter = flt.Filter
			mf.path = flt.Path
			mf.regex = flt.Regex
			mf.recursive = flt.Recursive
			mf.behavior = flt.Behavior
			mf.customerAdd = flt.CustomerAdd
			newMp.filters[key] = mf
		}

		fsmonProfileGroups[name] = newMp
		cacheMutexUnlock()
	case cluster.ClusterNotifyDelete:
		cacheMutexLock()
		delete(fsmonProfileGroups, name)
		cacheMutexUnlock()
		_ = clusHelper.DeleteFileAccessRule(name)
		log.WithFields(log.Fields{"name": name}).Debug("Delete")
	}
}

// update profile from config
func fileAccessRuleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSFileMonitorKey2Group(key)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var rule share.CLUSFileAccessRule
		if err := json.Unmarshal(value, &rule); err != nil {
			log.WithFields(log.Fields{"value": string(value[:]), "error": err}).Debug("Fail to decode")
			return
		}

		log.WithFields(log.Fields{"key": key, "filters": len(rule.Filters), "crds": len(rule.FiltersCRD)}).Debug("Update")

		cacheMutexLock()
		mp, ok := fsmonProfileGroups[name]
		if !ok {
			mp = &monitorProfile{filters: make(map[string]*monitorFilter)}
			fsmonProfileGroups[name] = mp
		}
		for idx, filter := range rule.Filters {
			// idx is in the format {flt.Path}/{flt.Regex}
			key := fsmonGetCacheKey(idx, 0) // default : no "filter.CfgType"
			mf, ok := mp.filters[key]
			if !ok {
				mf = &monitorFilter{} // new entry
			}
			mf.behavior = filter.Behavior
			mf.customerAdd = filter.CustomerAdd
			mf.apps = utils.NewSet()
			for _, app := range filter.Apps {
				mf.apps.Add(app)
			}
			mf.createdAt = filter.CreatedAt
			mf.updatedAt = filter.UpdatedAt
			mp.filters[key] = mf
		}

		for idx, filter := range rule.FiltersCRD {
			key := fsmonGetCacheKey(idx, share.GroundCfg)
			mf, ok := mp.filters[key]
			if !ok {
				mf = &monitorFilter{}
			}
			mf.behavior = filter.Behavior
			mf.customerAdd = filter.CustomerAdd
			mf.apps = utils.NewSet()
			for _, app := range filter.Apps {
				mf.apps.Add(app)
			}
			mf.createdAt = filter.CreatedAt
			mf.updatedAt = filter.UpdatedAt
			mp.filters[key] = mf
		}
		cacheMutexUnlock()
	case cluster.ClusterNotifyDelete:
		// do nothing, the fsmonProfileConfigUpdate will delete the group in map
		log.WithFields(log.Fields{"name": name}).Debug("Delete")
	}
}

func (m CacheMethod) GetAllFileMonitorProfile(scope string, acc *access.AccessControl, predefined bool) []*api.RESTFileMonitorProfile {
	var getLocal, getFed bool
	var localGrpsCount, fedGrpsCount int
	if scope == share.ScopeLocal {
		getLocal = true
	} else if scope == share.ScopeFed {
		getFed = true
	} else if scope == share.ScopeAll {
		getFed = true
		getLocal = true
	} else {
		return nil
	}

	cacheMutexRLock()
	for _, cache := range groupCacheMap {
		if getLocal && cache.group.CfgType != share.FederalCfg {
			localGrpsCount++
		}
		if getFed && cache.group.CfgType == share.FederalCfg {
			fedGrpsCount++
		}
	}
	localProfiles := make([]*api.RESTFileMonitorProfile, 0, localGrpsCount)
	fedProfiles := make([]*api.RESTFileMonitorProfile, 0, fedGrpsCount)

	var g *share.CLUSGroup
	fp := share.CLUSFileMonitorProfile{}
	for groupName, mp := range fsmonProfileGroups {
		if g = getGroupWithoutLock(groupName); g == nil {
			continue
		}
		fp.Group = groupName
		fp.CfgType = g.CfgType
		if !acc.Authorize(&fp, getAccessObjectFuncNoLock) {
			continue
		}

		if (getFed && g.CfgType == share.FederalCfg) || (getLocal && g.CfgType != share.FederalCfg) {
			filters := make([]*api.RESTFileMonitorFilter, 0)
			for _, filter := range mp.filters {
				if filter.customerAdd == predefined {
					continue
				}

				mf := &api.RESTFileMonitorFilter{
					Filter:           filter.filter,
					Recursive:        filter.recursive,
					Behavior:         filter.behavior,
					CreatedTimeStamp: filter.createdAt.Unix(),
					UpdatedTimeStamp: filter.updatedAt.Unix(),
				}

				mf.CfgType = cfgTypeMapping[filter.CfgType]
				if filter.customerAdd {
					mf.Apps = filter.apps.ToStringSlice()
				}
				filters = append(filters, mf)
			}

			p := &api.RESTFileMonitorProfile{Group: groupName, Filters: filters}
			if getLocal && g.CfgType != share.FederalCfg {
				localProfiles = append(localProfiles, p)
			}
			if getFed && g.CfgType == share.FederalCfg {
				fedProfiles = append(fedProfiles, p)
			}
		}
	}
	cacheMutexRUnlock()

	profiles := make([]*api.RESTFileMonitorProfile, 0, len(fedProfiles)+len(localProfiles))
	profiles = append(profiles, fedProfiles...)
	profiles = append(profiles, localProfiles...)

	return profiles
}

func (m CacheMethod) GetFileMonitorProfile(name string, acc *access.AccessControl, predefined bool) (*api.RESTFileMonitorProfile, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	g := getGroupWithoutLock(name)
	if g == nil {
		return nil, common.ErrObjectNotFound
	}

	mp := &share.CLUSFileMonitorProfile{Group: name, CfgType: g.CfgType}
	if !acc.Authorize(mp, getAccessObjectFuncNoLock) {
		return nil, common.ErrObjectAccessDenied
	}

	p, ok := fsmonProfileGroups[name]
	if !ok {
		return nil, common.ErrObjectNotFound
	}
	filters := make([]*api.RESTFileMonitorFilter, 0)
	for _, filter := range p.filters {
		if filter.customerAdd == predefined {
			continue
		}

		mf := &api.RESTFileMonitorFilter{
			Filter:           filter.filter,
			Recursive:        filter.recursive,
			Behavior:         filter.behavior,
			CreatedTimeStamp: filter.createdAt.Unix(),
			UpdatedTimeStamp: filter.updatedAt.Unix(),
		}

		mf.CfgType = cfgTypeMapping[filter.CfgType]
		if filter.customerAdd {
			mf.Apps = filter.apps.ToStringSlice()
		}
		filters = append(filters, mf)
	}

	profile := &api.RESTFileMonitorProfile{Group: name, Filters: filters}
	return profile, nil
}

// caller owns cacheMutexRLock & has readAll right, no CRD section
func (m CacheMethod) GetFedFileMonitorProfileCache() ([]*share.CLUSFileMonitorProfile, []*share.CLUSFileAccessRule) {
	count := 0
	for groupName := range fsmonProfileGroups {
		if strings.HasPrefix(groupName, api.FederalGroupPrefix) {
			count++
		}
	}

	var g *share.CLUSGroup
	profiles := make([]*share.CLUSFileMonitorProfile, 0, count)
	accessRules := make([]*share.CLUSFileAccessRule, 0, count)
	for groupName, mp := range fsmonProfileGroups {
		if !strings.HasPrefix(groupName, api.FederalGroupPrefix) {
			continue
		}
		g = getGroupWithoutLock(groupName)
		if g == nil {
			continue
		}

		fmfs := make([]share.CLUSFileMonitorFilter, len(mp.filters))
		fafrs := make(map[string]*share.CLUSFileAccessFilterRule, len(mp.filters))
		i := 0
		for key, filter := range mp.filters {
			// key is in the format {flt.Path}/{flt.Regex}:{cfgType}
			if idxCfgType := strings.LastIndex(key, ":"); idxCfgType > 0 {
				// idx is in the format {flt.Path}/{flt.Regex}
				idx := key[:idxCfgType]
				fmfs[i] = share.CLUSFileMonitorFilter{
					Filter:      filter.filter,
					Path:        filter.path,
					Regex:       filter.regex,
					Recursive:   filter.recursive,
					CustomerAdd: filter.customerAdd,
					Behavior:    filter.behavior,
				}

				fafrs[idx] = &share.CLUSFileAccessFilterRule{
					Apps:        filter.apps.ToStringSlice(),
					Behavior:    filter.behavior,
					CustomerAdd: filter.customerAdd,
					CreatedAt:   filter.createdAt,
					UpdatedAt:   filter.updatedAt,
				}
				i++
			}
		}
		if i < len(fmfs) {
			fmfs = fmfs[:i]
		}
		p := &share.CLUSFileMonitorProfile{
			Group:   groupName,
			Mode:    g.ProfileMode,
			Filters: fmfs,
			CfgType: g.CfgType,
		}
		r := &share.CLUSFileAccessRule{
			Group:   groupName,
			Filters: fafrs,
		}
		profiles = append(profiles, p)
		accessRules = append(accessRules, r)
	}
	return profiles, accessRules
}

func (m CacheMethod) IsPrdefineFileGroup(filter string, recursive bool) (*share.CLUSFileMonitorFilter, bool) {
	fmp := common.DefaultFileMonitorConfig
	for _, flt := range fmp.Filters {
		if flt.Filter == filter && flt.Recursive == recursive {
			return &flt, true
		}
	}
	return nil, false
}

func createGroupFileMonitor(txn *cluster.ClusterTransact, name, mode string, cfgType share.TCfgType) bool {
	var fmp share.CLUSFileMonitorProfile

	rconf := &share.CLUSFileAccessRule{
		Filters:    make(map[string]*share.CLUSFileAccessFilterRule),
		FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule),
	}

	if name == api.LearnedExternal {
		return false
	} else {
		if cfgType == share.Learned || (cfgType == share.GroundCfg && strings.HasPrefix(name, api.LearnedGroupPrefix)) { // support CRD type
			fmp = common.DefaultFileMonitorConfig
		}
	}
	fmp.Group = name
	fmp.Mode = mode
	fmp.CfgType = cfgType
	tm := time.Now().UTC()
	for i, flt := range fmp.Filters {
		idx := utils.FilterIndexKey(flt.Path, flt.Regex)
		frule := &share.CLUSFileAccessFilterRule{
			Apps:        make([]string, 0),
			CreatedAt:   tm,
			UpdatedAt:   tm,
			Behavior:    share.FileAccessBehaviorMonitor,
			CustomerAdd: false,
		}
		rconf.Filters[idx] = frule
		fmp.Filters[i].Filter = common.FsmonFilterToRest(flt.Path, flt.Regex)
	}

	if txn == nil {
		var err1, err2 error
		if err1 = clusHelper.PutFileMonitorProfileIfNotExist(name, &fmp); err1 != nil {
			log.WithFields(log.Fields{"error": err1, "group": name}).Error("put file monitor profile fail")
		}
		if err2 = clusHelper.PutFileAccessRuleIfNotExist(name, rconf); err2 != nil {
			log.WithFields(log.Fields{"error": err2, "group": name}).Error("put file access rule fail")
		}
		if err1 == nil || err2 == nil {
			return true
		}
		return false
	} else {
		_ = clusHelper.PutFileMonitorProfileTxn(txn, name, &fmp)
		_ = clusHelper.PutFileAccessRuleTxn(txn, name, rconf)
		return true
	}
}

func (m CacheMethod) CreateGroupFileMonitor(name, mode string, cfgType share.TCfgType) bool {
	return createGroupFileMonitor(nil, name, mode, cfgType)
}

func (m CacheMethod) CreateGroupFileMonitorTxn(txn *cluster.ClusterTransact, name, mode string, cfgType share.TCfgType) bool {
	return createGroupFileMonitor(txn, name, mode, cfgType)
	// txn.Apply() is called in caller
}

// Only for service learned group but we need to clone CRD apps later
func updateFileMonitorProfile(rules []*share.CLUSFileAccessRuleReq) {
	// log.WithFields(log.Fields{"rules": rules}).Debug("FMON:")
	if !isLeader() {
		return
	}
	confs := make(map[string]*monitorProfile)
	cacheMutexLock()
	for _, rule := range rules {
		// the group and filter must exist
		// log.WithFields(log.Fields{"rule": rule}).Debug("FMON:")
		if pf, ok := fsmonProfileGroups[rule.GroupName]; ok {
			key := fsmonGetCacheKey(rule.Filter, 0)
			if filter, ok := pf.filters[key]; ok {
				if !filter.customerAdd { // only for custom-added entries
					continue
				}

				if !filter.apps.Contains(rule.Path) {
					log.WithFields(log.Fields{"group": rule.GroupName,
						"filter": rule.Filter, "path": rule.Path}).Debug("FMON: add file rule")
					filter.apps.Add(rule.Path)

					// create a new profile, add only new filters, new rule
					conf, ok := confs[rule.GroupName]
					if !ok {
						conf = &monitorProfile{filters: make(map[string]*monitorFilter)}
						confs[rule.GroupName] = conf
					}
					nflt, ok := conf.filters[rule.Filter]
					if !ok {
						nflt = &monitorFilter{
							path:  filter.path,
							regex: filter.regex,
							apps:  utils.NewSet(),
						}
						conf.filters[rule.Filter] = nflt
					}
					nflt.apps.Add(rule.Path)
				}
			}
		}
	}
	cacheMutexUnlock()

	for grp, conf := range confs {
		updateFileAccessRule(grp, conf)
	}
}

func updateFileAccessRule(group string, conf *monitorProfile) {
	update := false
	grule, rev := clusHelper.GetFileAccessRule(group)
	if grule == nil || grule.Filters == nil {
		update = true
		grule = &share.CLUSFileAccessRule{
			Filters:    make(map[string]*share.CLUSFileAccessFilterRule),
			FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule),
		}
	}
	for idx, filter := range conf.filters {
		rule, ok := grule.Filters[idx]
		if !ok {
			log.WithFields(log.Fields{"idx": idx}).Error("filter not found")
			continue
		}

		for itr := range filter.apps.Iter() {
			// only append the new added processes
			app := itr.(string)
			found := false
			for _, a := range rule.Apps {
				if a == app {
					found = true // no change
					break
				}
			}

			if found {
				continue
			}

			rule.Apps = append(rule.Apps, app)
			update = true
			log.WithFields(log.Fields{"group": group, "filter": idx, "app": app}).Debug("append rule")
		}
		grule.Filters[idx] = rule
	}

	if update {
		if err := clusHelper.PutFileAccessRule(group, grule, rev); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Write cluster fail")
		}
	}
}

// a dedicated service for reporting system with serialized in the occuring sequence
var fileRuleEntries []*share.CLUSFileAccessRuleReq = make([]*share.CLUSFileAccessRuleReq, 0)
var fileRuleEntryMux sync.Mutex

func FileReportBkgSvc() {
	for {
		fileRuleEntryMux.Lock()
		length := len(fileRuleEntries)
		fileRuleEntryMux.Unlock()

		if length > 0 {
			if kv.IsImporting() {
				fileRuleEntryMux.Lock()
				fileRuleEntries = make([]*share.CLUSFileAccessRuleReq, 0) // reset
				fileRuleEntryMux.Unlock()
			} else {
				if lock, _ := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait); lock != nil {
					var rules []*share.CLUSFileAccessRuleReq
					index := length
					if index > 32 { // 32 entries
						index = 32
					}

					fileRuleEntryMux.Lock()
					rules, fileRuleEntries = fileRuleEntries[:index], fileRuleEntries[index:]
					fileRuleEntryMux.Unlock()

					updateFileMonitorProfile(rules)
					clusHelper.ReleaseLock(lock)
				}
			}
		} else {
			time.Sleep(time.Millisecond * 100) // yield
		}
	}
}

func AddFileRuleReport(rules []*share.CLUSFileAccessRuleReq) bool {
	fileRuleEntryMux.Lock()
	fileRuleEntries = append(fileRuleEntries, rules...)
	fileRuleEntryMux.Unlock()
	return true
}
