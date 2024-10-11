package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neuvector/neuvector/agent/policy"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

// //  group profile
type groupProfileData struct {
	group   *share.CLUSGroup
	members utils.Set
	proc    *share.CLUSProcessProfile
	file    *share.CLUSFileMonitorProfile
	access  *share.CLUSFileAccessRule
}

var grpCacheLock sync.Mutex
var grpProfileCacheMap map[string]*groupProfileData = make(map[string]*groupProfileData)
var grpNotifyProc utils.Set = utils.NewSet()
var grpNotifyFile utils.Set = utils.NewSet()

// ///
type fileMatchRule struct {
	cfgtype  int
	group    string
	behavior string
	regex    *regexp.Regexp
}

// // workload profile map for policy lookups
type workloadProfile struct {
	groups         utils.Set
	proc           *share.CLUSProcessProfile
	file           *share.CLUSFileMonitorProfile
	access         *share.CLUSFileAccessRule
	matchRules     []*fileMatchRule // local usage: match path to (estimated) group
	procCalculated bool
	fileCalculated bool
}

var wlCacheLock sync.Mutex
var wlProfileMap map[string]*workloadProfile = make(map[string]*workloadProfile)

const federalGrpPrefix string = "fed."

/* removed by golint
// ///// DEBUG functions /////////////
func outputGroupInfo(grpCache *groupProfileData) {
	log.WithFields(log.Fields{"group": grpCache.group.Name, "member_count": grpCache.members.Cardinality()}).Debug("GRP:")
	for cid := range grpCache.members.Iter() {
		log.WithFields(log.Fields{"id": cid.(string)}).Debug("GRP: members")
	}

	log.WithFields(log.Fields{"Proc": grpCache.proc}).Debug("GRP:")
	log.WithFields(log.Fields{"File": grpCache.file}).Debug("GRP:")
	log.WithFields(log.Fields{"Access": grpCache.access}).Debug("GRP:")
}
*/

// ///
func loadGroupProfile(name string, profile interface{}) bool {
	var ptype string
	//log.WithFields(log.Fields{"name": name, "type": fmt.Sprintf("%T", profile)}).Debug()
	host := Host.ID
	if utils.IsGroupNodes(name) {
		host = share.ProfileCommonGroup
	}
	switch profile.(type) {
	case *share.CLUSGroup:
		if value, err := cluster.Get(share.CLUSNodeProfileGroupKey(host, share.ProfileGroup, name)); err == nil {
			value, _ = utils.UnzipDataIfValid(value)
			if dbgError := json.Unmarshal(value, profile); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return true
		}
		ptype = "group"
	case *share.CLUSProcessProfile:
		if value, err := cluster.Get(share.CLUSNodeProfileGroupKey(host, share.ProfileProcess, name)); err == nil {
			value, _ = utils.UnzipDataIfValid(value)
			if dbgError := json.Unmarshal(value, profile); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return true
		}
		ptype = "process"
	case *share.CLUSFileMonitorProfile:
		if value, err := cluster.Get(share.CLUSNodeProfileGroupKey(host, share.ProfileFileMonitor, name)); err == nil {
			value, _ = utils.UnzipDataIfValid(value)
			if dbgError := json.Unmarshal(value, profile); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return true
		}
		ptype = "file"
	case *share.CLUSFileAccessRule:
		if value, err := cluster.Get(share.CLUSNodeProfileGroupKey(host, share.ProfileFileAccess, name)); err == nil {
			value, _ = utils.UnzipDataIfValid(value)
			if dbgError := json.Unmarshal(value, profile); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return true
		}
		ptype = "access"
	default:
		ptype = fmt.Sprintf("%T", profile)
	}
	log.WithFields(log.Fields{"group": name, "type": ptype}).Debug("GRP: invalid profile")
	return false
}

func getProcessProfile(name string) (bool, *share.CLUSProcessProfile) {
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		if grpCache.proc.Group == "" {
			if !loadGroupProfile(name, grpCache.proc) {
				return false, nil
			}
		}
		return true, grpCache.proc
	}
	return false, nil
}

func getFileMonitorProfile(name string) (bool, *share.CLUSFileMonitorProfile) {
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		if grpCache.file.Group == "" {
			if !loadGroupProfile(name, grpCache.file) {
				return false, nil
			}
		}
		return true, grpCache.file
	}
	return false, nil
}

func getFileAccessProfile(name string) (bool, *share.CLUSFileAccessRule) {
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		if grpCache.access.Group == "" {
			if !loadGroupProfile(name, grpCache.access) {
				return false, nil
			}
		}
		return true, grpCache.access
	}
	return false, nil
}

// /// patch for random sequences of group creation( one-time)
func fillGroupProfiles(name string) bool {
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		loadGroupProfile(name, grpCache.proc)
		for _, pp := range grpCache.proc.Process {
			pp.DerivedGroup = name // late filled-up to save kv storages
		}

		loadGroupProfile(name, grpCache.file)
		for i := range grpCache.file.Filters {
			grpCache.file.Filters[i].DerivedGroup = name // late filled-up to save kv storages
		}
		loadGroupProfile(name, grpCache.access)
		grpCache.access.Group = name
		refreshGroupMembers(grpCache)
		// outputGroupInfo(grpCache)
		grpNotifyProc = grpNotifyProc.Union(grpCache.members)
		grpNotifyFile = grpNotifyFile.Union(grpCache.members)
		return true
	}
	return false
}

// /////
func addGroupCache(name string, grp share.CLUSGroup) bool {
	if !utils.HasGroupProfiles(name) {
		// ignore network services and nodes config type
		return false
	}

	// log.WithFields(log.Fields{"group": name}).Debug("GRP:")
	grpCache := &groupProfileData{
		group:   &grp,
		members: utils.NewSet(),
		proc:    &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)},
		file:    &share.CLUSFileMonitorProfile{Filters: make([]share.CLUSFileMonitorFilter, 0), FiltersCRD: make([]share.CLUSFileMonitorFilter, 0)},
		access:  &share.CLUSFileAccessRule{Filters: make(map[string]*share.CLUSFileAccessFilterRule), FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule)},
	}

	// protected by its calling function
	grpProfileCacheMap[name] = grpCache

	// best efforts to patch for random sequences of group creation
	go func() {
		time.Sleep(time.Second * 1)
		fillGroupProfiles(name)
	}()
	return true
}

// /////
func updateGroupProfileCache(nType cluster.ClusterNotifyType, name string, obj interface{}) bool {
	if !agentEnv.systemProfiles {
		return false
	}

	log.WithFields(log.Fields{"group": name}).Debug("GRP:")
	procUpdated := false
	fileUpdated := false
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	grpCache, ok := grpProfileCacheMap[name]
	if !ok {
		switch o := obj.(type) {
		case share.CLUSGroup:
			group := o
			return addGroupCache(name, group)
		}

		// the group data is not established yet
		// patch random event sequence later
		log.WithFields(log.Fields{"group": name, "obj": obj}).Debug("GRP: not exist yet")
		return utils.HasGroupProfiles(name)
	}

	// log.WithFields(log.Fields{"group": name, "obj": obj}).Debug("GRP:")
	targets := utils.NewSet()
	switch o := obj.(type) {
	case share.CLUSGroup:
		group := o
		if !reflect.DeepEqual(group, grpCache.group) {
			grpCache.group = &group
			old_members := grpCache.members.Clone()
			refreshGroupMembers(grpCache)
			targets = old_members.SymmetricDifference(grpCache.members)
			// log.WithFields(log.Fields{"old": old_members, "new": grpCache.members, "targets": targets}).Debug("GRP:")
			if targets.Cardinality() > 0 {
				procUpdated = true
				fileUpdated = true
			}
			old_members.Clear()
			old_members = nil
		}
	case share.CLUSProcessProfile:
		proc := o
		if proc.Mode != grpCache.proc.Mode || len(grpCache.proc.Process) == 0 || !reflect.DeepEqual(proc.Process, grpCache.proc.Process) {
			for _, pp := range proc.Process {
				pp.DerivedGroup = name // late filled-up to save kv storages
			}
			grpCache.proc = &proc
			targets = grpCache.members.Clone()
			if targets.Cardinality() > 0 {
				procUpdated = true
			}
		}
	case share.CLUSFileMonitorProfile:
		file := o
		if file.Mode != grpCache.file.Mode || len(grpCache.file.Filters) == 0 || !reflect.DeepEqual(file.Filters, grpCache.file.Filters) {
			for i := range file.Filters {
				file.Filters[i].DerivedGroup = name // late filled-up to save kv storages
			}
			grpCache.file = &file
			targets = grpCache.members.Clone()
			if targets.Cardinality() > 0 {
				fileUpdated = true
			}
		}
	case share.CLUSFileAccessRule:
		access := o
		if len(grpCache.access.Filters) == 0 || !reflect.DeepEqual(access.Filters, grpCache.access.Filters) {
			grpCache.access = &access
			targets = grpCache.members.Clone()
			if targets.Cardinality() > 0 {
				fileUpdated = true
			}
		}
	default:
		log.WithFields(log.Fields{"group": name, "type": obj}).Debug("GRP: unknown type")
		return false
	}

	if procUpdated {
		grpNotifyProc = grpNotifyProc.Union(targets)
	}

	if fileUpdated {
		grpNotifyFile = grpNotifyFile.Union(targets)
	}

	targets.Clear()
	targets = nil
	return true
}

// /////
func deleteGroupProfileCache(name string) bool {
	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		log.WithFields(log.Fields{"group": name}).Debug("GRP: ")
		grpNotifyFile = grpNotifyFile.Union(grpCache.members)
		grpNotifyProc = grpNotifyProc.Union(grpCache.members)
		grpCache.members.Clear()
		delete(grpProfileCacheMap, name)
		return true
	}

	log.WithFields(log.Fields{"group": name}).Debug("GRP: not found")
	return false
}

// ////////////////////////////////////////////////////
// /////// Group-based selection functions ////////////
// ////////////////////////////////////////////////////
func isContainerSelected(c, pod *containerData, group *share.CLUSGroup) bool {
	// TODO: remove "CriteriaKeyAddress" from entry ??
	wl := createWorkload(c.info, &c.service, &c.domain)
	if pod != nil && pod.info != nil { // include its POD's labels
		label := make(map[string]string) // make an extended label map
		for n, v := range c.info.Labels {
			label[n] = v
		}
		for n, v := range pod.info.Labels {
			label[n] = v
		}
		wl.Labels = label
	}
	return share.IsGroupMember(group, wl, getDomainData(wl.Domain))
}

// /////
func refreshGroupMembers(grpCache *groupProfileData) {
	grpCache.members.Clear()
	if utils.IsGroupNodes(grpCache.group.Name) {
		grpCache.members.Add("") // only member : host
		return
	}

	var pod *containerData

	gInfoRLock()
	for _, c := range gInfo.activeContainers {
		if c.parentNS != "" {
			if parent, ok := gInfo.activeContainers[c.parentNS]; ok {
				pod = parent
			}
		}
		if isContainerSelected(c, pod, grpCache.group) {
			grpCache.members.Add(c.id)

			// pod-level inclusion
			if pod, ok := gInfo.activeContainers[c.parentNS]; ok {
				grpCache.members = grpCache.members.Union(pod.pods)
				grpCache.members.Add(c.parentNS)
			}
		}
	}
	gInfoRUnlock()
}

// /////////////////////////////////////////////////////
// ///////////// Profile calculations //////////////////
// Group Profile has higher priority
// /////////////////////////////////////////////////////
// ///// Scheduler: trigger calculation(s) per containers for a certain of time
func group_profile_loop() {
	calculationTicker := time.Tick(time.Second * 5)
	for {
		<-calculationTicker
		grpCacheLock.Lock()
		targets_proc := grpNotifyProc.Clone()
		targets_file := grpNotifyFile.Clone()
		grpNotifyProc.Clear()
		grpNotifyFile.Clear()
		grpCacheLock.Unlock()

		///
		if targets_proc.Cardinality() > 0 {
			go procMemberChanges(targets_proc)
		}

		///
		if targets_file.Cardinality() > 0 {
			go fileMemberChanges(targets_file)
		}
	}
}

// ///// calcualting the runtime profiles
func procMemberChanges(members utils.Set) {
	log.WithFields(log.Fields{"count": members.Cardinality()}).Debug("GRP:")
	for cid := range members.Iter() {
		id := cid.(string)
		if id == "" {
			applyHostProcGroupProfile("nodes") // system reserved entry
			continue
		}

		if c, ok := gInfoReadActiveContainer(id); ok {
			go applyProcGroupProfile(c)
		} else {
			log.WithFields(log.Fields{"id": id}).Debug("GRP: left")
		}
	}
	members.Clear()
}

func fileMemberChanges(members utils.Set) {
	log.WithFields(log.Fields{"count": members.Cardinality()}).Debug("GRP:")
	for cid := range members.Iter() {
		id := cid.(string)
		if id == "" {
			//	log.Debug("GRP: not support nodes")
			continue
		}

		if c, ok := gInfoReadActiveContainer(id); ok {
			applyFileGroupProfile(c)
		} else {
			log.WithFields(log.Fields{"id": id}).Debug("GRP: left")
		}
	}
	members.Clear()
}

// ////
func mapProcToSortedSlices(m map[string]*share.CLUSProcessProfileEntry) []*share.CLUSProcessProfileEntry {
	list := make([]*share.CLUSProcessProfileEntry, 0, len(m)) // single allocation
	for _, item := range m {                                  // map enumeration
		list = append(list, item)
	}

	if len(list) > 0 {
		// sort them by Name, then Path
		sort.Slice(list, func(i, j int) bool {
			if list[i].Name == list[j].Name {
				return list[i].Path < list[j].Path
			}
			return list[i].Name < list[j].Name
		})
	}
	return list
}

// Process Rules (priorities) :
// (0) *,*  == apply all (only for allow)
// (1) deny: specific name and path
// (2) deny: recursive path (directories)
// (3) deny: wildcard name (whole container)
// (4) allow: specific name and path
// (5) allow: recursive path
// (6) allow: wildcard name
func mergeProcessProfiles(cur []*share.CLUSProcessProfileEntry) []*share.CLUSProcessProfileEntry {
	m := make([]map[string]*share.CLUSProcessProfileEntry, 7)
	for i := 0; i < 7; i++ {
		m[i] = make(map[string]*share.CLUSProcessProfileEntry)
	}

	for _, entry := range cur {
		key := fmt.Sprintf("%s:%s", entry.Name, entry.Path)
		if entry.Action == share.PolicyActionDeny {
			if entry.Name == "*" && entry.Path == "*" {
				// (0) deny all : this invalid entry is blocked at REST api level
			} else if entry.Name == "*" {
				// (3) deny and wildcard at name
				m[3][key] = entry
			} else if strings.HasSuffix(entry.Path, "/*") {
				// (2) deny and wildcard at path
				m[2][key] = entry
			} else {
				// (1) deny and specific
				m[1][key] = entry
			}
		} else {
			if entry.Name == "*" && entry.Path == "*" {
				// (0) allow all : override all cases
				m[0][key] = entry
			} else if entry.Name == "*" {
				// (6) allow and wildcard at name
				m[6][key] = entry
			} else if strings.HasSuffix(entry.Path, "/*") {
				// (5)  allow and wildcard at path
				m[5][key] = entry
			} else {
				// (4) allow and specific
				m[4][key] = entry
			}
		}
	}

	var list []*share.CLUSProcessProfileEntry
	for _, mm := range m { // slice enumeration
		list = append(list, mapProcToSortedSlices(mm)...)
	}
	return list
}

// FileMonitor Rules (SLICE: priorities) :
// (1) share.FileAccessBehaviorBlock > share.FileAccessBehaviorMonitor
// (2) recursive > non-recursive
// (3) customer-added > default-setting
func mergeFileMonitorProfile(filters []share.CLUSFileMonitorFilter) []share.CLUSFileMonitorFilter {
	m := make(map[string]share.CLUSFileMonitorFilter)
	for _, ff := range filters { // slice enumeration
		key := GetPathRegexString(ff.Path, ff.Regex, ff.Recursive)
		if v, ok := m[key]; ok {
			if v.Behavior == share.FileAccessBehaviorBlock {
				ff.Behavior = share.FileAccessBehaviorBlock // higher priority
				if v.DerivedGroup != "" {
					ff.DerivedGroup = v.DerivedGroup // keep the first group name
				}
			}

			if v.Recursive {
				ff.Recursive = true // higher priority
			}

			if v.CustomerAdd {
				ff.CustomerAdd = true // higher priority
			}
		}
		m[key] = ff
	}

	var list []share.CLUSFileMonitorFilter = make([]share.CLUSFileMonitorFilter, 0, len(m)) // single allocation
	for _, item := range m {                                                                // map enumeration
		list = append(list, item)
	}

	if len(list) > 0 {
		// sort them by Name, then Path
		sort.Slice(list, func(i, j int) bool {
			if list[i].Filter == list[j].Filter {
				return list[i].Path < list[j].Path
			}
			return list[i].Filter < list[j].Filter
		})
	}
	return list
}

// / remove duplicates: O(N), sorting: O(NlogN)
func mergeStringSlices(bSort bool, s1, s2 []string) []string {
	slices := append(s1, s2...)

	m := make(map[string]bool)
	for _, key := range slices { // slice enumeration
		m[key] = true
	}

	var list []string = make([]string, 0, len(m)) // single allocation
	for v := range m {                            // map enumeration                                                              // map enumeration
		list = append(list, v)
	}

	if bSort && len(list) > 0 {
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	}
	return list
}

// FileAccessMonitor Rules (MAP priorities) :
// (1) share.FileAccessBehaviorBlock > share.FileAccessBehaviorMonitor
func mergeFileAccessProfile(cur, add *share.CLUSFileAccessRule) {
	for name, profile := range add.Filters { // map enumeration
		if ffp, ok := cur.Filters[name]; ok {
			ffp.CustomerAdd = true
			ffp.Apps = mergeStringSlices(true, ffp.Apps, profile.Apps) // optional: false
			if profile.Behavior == share.FileAccessBehaviorBlock {
				ffp.Behavior = share.FileAccessBehaviorBlock // higher priority
			}
		} else {
			cur.Filters[name] = profile // new entry
		}
	}

	for name, profile := range add.FiltersCRD { // map enumeration
		if ffp, ok := cur.FiltersCRD[name]; ok {
			ffp.CustomerAdd = true
			ffp.Apps = mergeStringSlices(true, ffp.Apps, profile.Apps) // optional: false
			if profile.Behavior == share.FileAccessBehaviorBlock {
				ffp.Behavior = share.FileAccessBehaviorBlock // higher priority
			}
		} else {
			cur.FiltersCRD[name] = profile // new entry
		}
	}
}

// //
func calculateProcGroupProfile(id, svc string) (*share.CLUSProcessProfile, bool) {
	log.WithFields(log.Fields{"id": id, "svc": svc}).Debug("GRP: ")

	/// merge group profiles
	fedproc := &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)}
	crdproc := &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)}
	proc := &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)}
	grpCacheLock.Lock()
	for grpName, grpCache := range grpProfileCacheMap {
		if grpCache.members.Contains(id) {
			if strings.HasPrefix(grpName, federalGrpPrefix) {
				fedproc.Process = append(fedproc.Process, grpCache.proc.Process...)
			} else {
				for _, p := range grpCache.proc.Process { // separate CRD and other types
					if p.CfgType == share.GroundCfg {
						crdproc.Process = append(crdproc.Process, p)
					} else {
						proc.Process = append(proc.Process, p)
					}
				}
			}
		}
	}
	grpCacheLock.Unlock()

	// load workload profile
	ok, svc_proc := getProcessProfile(svc)
	if !ok {
		log.WithFields(log.Fields{"id": id, "svc": svc}).Debug("GRP: no profile")
		return nil, false
	}

	for _, p := range svc_proc.Process { // separate CRD and other types
		if p.CfgType == share.GroundCfg {
			crdproc.Process = append(crdproc.Process, p)
		} else {
			proc.Process = append(proc.Process, p)
		}
	}

	// remove the duplicate entries and prioritize the sequences
	pp := &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)}
	if len(fedproc.Process) > 0 {
		// keep federal rules at the top
		fedproc.Process = mergeProcessProfiles(fedproc.Process)
		pp.Process = append(pp.Process, fedproc.Process...)
	}

	if len(crdproc.Process) > 0 {
		// keep crd rules at the secondary
		crdproc.Process = mergeProcessProfiles(crdproc.Process)
		pp.Process = append(pp.Process, crdproc.Process...)
	}

	if len(proc.Process) > 0 {
		// merge service rules
		proc.Process = mergeProcessProfiles(proc.Process)
		pp.Process = append(pp.Process, proc.Process...)
	}

	proc.Group = svc_proc.Group
	proc.Mode = svc_proc.Mode
	proc.AlertDisable = svc_proc.AlertDisable
	proc.HashEnable = svc_proc.HashEnable
	proc.Process = pp.Process

	if id != "" { // container only
		for _, p := range proc.Process { // separate CRD and other types
			// log.WithFields(log.Fields{"proc": p, "Svc": svc}).Debug("GRP:")
			if p.Action == share.PolicyActionAllow {
				prober.UpdateFromAllowRule(id, p.Path)
			}
		}
	}
	return proc, true
}

// //
func calculateFileGroupProfile(id, svc string) (*share.CLUSFileMonitorProfile, *share.CLUSFileAccessRule, bool) {
	log.WithFields(log.Fields{"id": id, "svc": svc}).Debug("GRP: ")

	file := &share.CLUSFileMonitorProfile{
		Filters:    make([]share.CLUSFileMonitorFilter, 0),
		FiltersCRD: make([]share.CLUSFileMonitorFilter, 0),
	}

	access := &share.CLUSFileAccessRule{
		Filters:    make(map[string]*share.CLUSFileAccessFilterRule),
		FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule),
	} // from (map).Filter

	grpCacheLock.Lock()
	for _, grpCache := range grpProfileCacheMap {
		if grpCache.members.Contains(id) {
			file.Filters = append(file.Filters, grpCache.file.Filters...)
			file.FiltersCRD = append(file.FiltersCRD, grpCache.file.FiltersCRD...)
			mergeFileAccessProfile(access, grpCache.access)
		}
	}
	grpCacheLock.Unlock()

	// log.WithFields(log.Fields{"filter": file.Filters}).Debug("GRP:")
	ok, svc_file := getFileMonitorProfile(svc)
	if !ok {
		log.WithFields(log.Fields{"id": id, "svc": svc}).Debug("GRP: no file profile")
		return nil, nil, false
	}

	// basic information
	file.Group = svc_file.Group
	file.Mode = svc_file.Mode

	// merge regular files
	file.Filters = append(file.Filters, svc_file.Filters...)
	file.Filters = mergeFileMonitorProfile(file.Filters)

	// merge CRD files
	file.FiltersCRD = append(file.FiltersCRD, svc_file.FiltersCRD...)
	file.FiltersCRD = mergeFileMonitorProfile(file.FiltersCRD)

	// access profile
	ok, svc_access := getFileAccessProfile(svc)
	if !ok {
		log.WithFields(log.Fields{"id": id, "svc": svc}).Debug("GRP: no access profile")
		return file, nil, true
	}
	//log.WithFields(log.Fields{"svc": svc_access}).Debug("GRP:")
	//for name, profile := range svc_access.Filters { // map enumeration
	//	log.WithFields(log.Fields{"name": name, "profile": profile}).Debug("GRP:")
	//}
	mergeFileAccessProfile(access, svc_access)
	return file, access, true
}

// /////
func GetPathRegexString(path, regex string, bRecursive bool) string {
	regex_str := path
	if bRecursive {
		regex_str = fmt.Sprintf("%s/%s", regex_str, regex)
	}
	return fmt.Sprintf("^%s$", regex_str)
}

// ////
func BuildFileMatchRules(filters []share.CLUSFileMonitorFilter, cfgtype int) []*fileMatchRule {
	rules := make([]*fileMatchRule, 0, len(filters)) // single allocation
	for _, ff := range filters {
		regex, _ := regexp.Compile(GetPathRegexString(ff.Path, ff.Regex, ff.Recursive))
		// log.WithFields(log.Fields{"regex": regex, "ff": ff}).Debug("GRP: ")
		rr := &fileMatchRule{
			group:    ff.DerivedGroup,
			cfgtype:  cfgtype,
			behavior: ff.Behavior,
			regex:    regex,
		}
		rules = append(rules, rr)
	}
	return rules
}

// //
func applyHostProcGroupProfile(svc string) bool {
	if proc, ok := calculateProcGroupProfile("", svc); ok {
		wlCacheLock.Lock()
		wl, ok := wlProfileMap[""]
		if !ok {
			wlProfileMap[""] = &workloadProfile{
				groups: utils.NewSet(),
				proc:   &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)},
				file:   &share.CLUSFileMonitorProfile{Filters: make([]share.CLUSFileMonitorFilter, 0)},
				access: &share.CLUSFileAccessRule{Filters: make(map[string]*share.CLUSFileAccessFilterRule)},
			}
			wl = wlProfileMap[""]
		}
		wl.proc = proc
		wl.procCalculated = true

		wlCacheLock.Unlock()

		// put a minimum data set
		c := &containerData{
			id:           "",
			name:         "host",
			pid:          1,
			capBlock:     false, // no process blocking control but kill processes
			pushPHistory: true,  // no history
		}

		// log.WithFields(log.Fields{"SVC": svc, "mode": proc.Mode}).Debug("GRP:")
		applyProcessProfilePolicy(c, svc) // mode is passed later for process monitor reasons
		return true
	}
	return false
}

// //
func applyProcGroupProfile(c *containerData) bool {
	svc := makeLearnedGroupName(utils.NormalizeForURL(c.service))
	if proc, ok := calculateProcGroupProfile(c.id, svc); ok {
		wlCacheLock.Lock()
		if wl, ok := wlProfileMap[c.id]; ok {
			wl.proc = proc
			wl.procCalculated = true
		}
		wlCacheLock.Unlock()
		applyProcessProfilePolicy(c, svc) // mode is passed later for process monitor reasons
		return true
	}
	return false
}

// //
func applyFileGroupProfile(c *containerData) bool {
	svc := makeLearnedGroupName(utils.NormalizeForURL(c.service))
	if file, access, ok := calculateFileGroupProfile(c.id, svc); ok {
		matchRules := make([]*fileMatchRule, 0)
		if len(file.FiltersCRD) > 0 { // higher report priority
			matchRules = append(matchRules, BuildFileMatchRules(file.FiltersCRD, int(share.GroundCfg))...)
		}

		if len(file.Filters) > 0 {
			matchRules = append(matchRules, BuildFileMatchRules(file.Filters, 0)...) // default: undefined
		}

		wlCacheLock.Lock()
		if wl, ok := wlProfileMap[c.id]; ok {
			wl.file = file
			wl.access = access
			wl.matchRules = matchRules
			wl.fileCalculated = true
		}
		wlCacheLock.Unlock()

		//////
		config := &fsmon.FsmonConfig{
			Profile: file,
			Rule:    access,
		}

		//
		fileWatcher.ContainerCleanup(c.pid, false)
		if len(file.Filters) > 0 && c.pid != 0 {
			fileWatcher.StartWatch(c.id, c.pid, config, c.capBlock, false)
		}
		return true
	}
	return false
}

/* removed by golint
func uppdateFileGroupAccess(c *containerData) bool {
	svc := makeLearnedGroupName(utils.NormalizeForURL(c.service))
	if _, access, ok := calculateFileGroupProfile(c.id, svc); ok && (access != nil) {
		log.WithFields(log.Fields{"ID": c.id, "svc": svc}).Debug("GRP:")
		wlCacheLock.Lock()
		if wl, ok := wlProfileMap[c.id]; ok {
			wl.access = access
		}
		wlCacheLock.Unlock()

		//
		fileWatcher.UpdateAccessRules(svc, c.pid, access)
		return true
	}
	return false
}
*/

// ///// "host" is not an actual workload, will NOT enter this function
func workloadJoinGroup(c, parent *containerData) {
	if !agentEnv.systemProfiles {
		return
	}

	log.WithFields(log.Fields{"id": c.id}).Debug("GRP: ")

	wlCacheLock.Lock()
	if _, ok := wlProfileMap[c.id]; !ok {
		wlProfileMap[c.id] = &workloadProfile{
			groups: utils.NewSet(),
			proc:   &share.CLUSProcessProfile{Process: make([]*share.CLUSProcessProfileEntry, 0)},
			file:   &share.CLUSFileMonitorProfile{Filters: make([]share.CLUSFileMonitorFilter, 0)},
			access: &share.CLUSFileAccessRule{Filters: make(map[string]*share.CLUSFileAccessFilterRule)},
		}
	}
	groups := wlProfileMap[c.id].groups
	wlCacheLock.Unlock()

	grpCacheLock.Lock()
	defer grpCacheLock.Unlock()
	for name, grpCache := range grpProfileCacheMap {
		if utils.IsGroupNodes(name) {
			continue
		}

		if isContainerSelected(c, parent, grpCache.group) {
			grpCache.members.Add(c.id)
			groups.Add(name) // reference

			// pod-level inclusion
			if parent != nil {
				grpCache.members = grpCache.members.Union(parent.pods)
				grpCache.members.Add(c.parentNS)
				grpNotifyProc = grpNotifyProc.Union(parent.pods)
				grpNotifyFile = grpNotifyFile.Union(parent.pods)
			}
		}
	}

	//
	grpNotifyProc.Add(c.id)
	grpNotifyFile.Add(c.id)
}

// /////
func workloadLeaveGroup(c *containerData) {
	if !agentEnv.systemProfiles {
		return
	}

	// log.WithFields(log.Fields{"cid": id}).Debug("GRP: ")
	// remove monitors
	prober.RemoveProcessControl(c.id)
	fileWatcher.ContainerCleanup(c.pid, true)

	grpCacheLock.Lock()
	for name, grpCache := range grpProfileCacheMap {
		if utils.IsGroupNodes(name) {
			continue
		}
		if grpCache.members.Contains(c.id) {
			log.WithFields(log.Fields{"group": name, "id": c.id}).Debug("GRP: ")
			grpCache.members.Remove(c.id)
		}
	}
	grpNotifyProc.Remove(c.id)
	grpNotifyFile.Remove(c.id)
	grpCacheLock.Unlock()

	wlCacheLock.Lock()
	if wl, ok := wlProfileMap[c.id]; ok {
		wl.groups.Clear() // clean up
		wl.proc = nil
		wl.file = nil
		wl.access = nil
		delete(wlProfileMap, c.id)
	}
	wlCacheLock.Unlock()
}

// /////// Use GRPC to return actual policy to CTL
func ObtainGroupProcessPolicy(id string) (*share.CLUSProcessProfile, bool) {
	if id == "nodes" { // from controller, workload id from runtime can not be like "nodes"
		id = ""
	}

	if _, ok := isNeuvectorContainerById(id); ok { // NeuVector: no group process profile
		return nil, true
	}

	wlCacheLock.Lock()
	defer wlCacheLock.Unlock()
	if wl, ok := wlProfileMap[id]; ok {
		if wl.proc != nil { // required
			return wl.proc, wl.procCalculated
		}
	}
	// log.WithFields(log.Fields{"id": id}).Debug("GRP: not ready")
	return nil, false
}

// /////// Use GRPC to return actual policy to CTL
func ObtainGroupFilePolicies(id string) (*share.CLUSFileMonitorProfile, *share.CLUSFileAccessRule, bool) {
	if id == "nodes" { // TODO: from controller, workload id from runtime can not be like "nodes"
		id = ""
	}

	wlCacheLock.Lock()
	defer wlCacheLock.Unlock()
	if wl, ok := wlProfileMap[id]; ok {
		if wl.file != nil { // required
			return wl.file, wl.access, wl.fileCalculated
		}
	}
	return nil, nil, false
}

// ///////////////////////////////////////////////////////////////////////////////
// It is very difficult to obtain the exact rule which applied on the incident
// since the lower (fanotify) layer has been optimized to reduce system resources.
// Also, it is costly by data memory to label all rules at the lower layer.
// Thus, better to use the emulatation of input vectors to find the rules
// ///////////////////////////////////////////////////////////////////////////////
// //// Estimate the rule from group name or service
func cbEstimateDeniedProcessdByGroup(id, name, path string) (string, string) {
	svcGroup, ok, _ := cbGetLearnedGroupName(id)
	if !ok {
		log.WithFields(log.Fields{"id": id}).Error("GRP: no svc")
		return "", share.CLUSReservedUuidNotAlllowed // TODO: if possible
	}

	if profile, ok := ObtainGroupProcessPolicy(id); ok && profile != nil {
		ppe := &share.CLUSProcessProfileEntry{
			Name: name,
			Path: path,
		}

		// match denied policy
		for _, pp := range profile.Process {
			if policy.MatchProfileProcess(pp, ppe) && pp.Action == share.PolicyActionDeny {
				if pp.DerivedGroup == "" {
					break // matched service group
				}
				return pp.DerivedGroup, pp.Uuid // user-defined group
			}
		}

		// by default, it from service (include beyond its white list)
		return svcGroup, share.CLUSReservedUuidNotAlllowed
	}

	if _, ok := isNeuvectorContainerById(id); ok { // NeuVector
		log.WithFields(log.Fields{"id": id, "name": name, "path": path}).Info("GRP: NV Protect")
		return share.GroupNVProtect, share.CLUSReservedUuidNotAlllowed
	}

	log.WithFields(log.Fields{"id": id}).Error("GRP: no profile")
	return "", share.CLUSReservedUuidNotAlllowed
}

// /// Estimate the rule from group name or service
func cbEstimateFileAlertByGroup(id, path string, bBlocked bool) string {
	var rules []*fileMatchRule
	//	log.WithFields(log.Fields{"path": path, "bBlock": bBlocked}).Debug("GRP: matched")
	if id == "" {
		return "nodes"
	}

	svcGroup, ok, _ := cbGetLearnedGroupName(id)
	if !ok {
		log.WithFields(log.Fields{"id": id}).Error("GRP: no svc")
		return ""
	}

	wlCacheLock.Lock()
	if wl, ok := wlProfileMap[id]; ok {
		rules = wl.matchRules
	}
	wlCacheLock.Unlock()

	if rules != nil {
		dgroup := ""
		for _, r := range rules {
			// log.WithFields(log.Fields{"regex": r.regex, "group": r.group, "path": path}).Debug("GRP: ")
			if r.regex != nil {
				if matched := r.regex.MatchString(path); matched {
					if bBlocked && r.behavior == share.FileAccessBehaviorBlock {
						log.WithFields(log.Fields{"group": r.group}).Debug("GRP: matched")
						if r.group == "" {
							return svcGroup
						}
						return r.group
					}

					if dgroup == "" {
						// temporary, keep the first entry until it find the FileAccessBehaviorBlock
						// log.WithFields(log.Fields{"group": group}).Debug("GRP: matched")
						if r.group == "" {
							dgroup = svcGroup
						} else {
							dgroup = r.group
						}
					}
				}
			}
		}
		return dgroup
	}

	if _, ok := isNeuvectorContainerById(id); ok { // NeuVector
		log.WithFields(log.Fields{"id": id, "path": path, "bBlocked": bBlocked}).Info("GRP: NV Protect")
		return share.GroupNVProtect
	}

	log.WithFields(log.Fields{"id": id}).Error("GRP: no profile")
	return ""
}

func updateContainerFamilyTrees(name string) {
	if name == "nodes" {
		return
	}

	var cids []string

	grpCacheLock.Lock()
	if grpCache, ok := grpProfileCacheMap[name]; ok {
		cids = grpCache.members.ToStringSlice()
	}
	grpCacheLock.Unlock()

	for _, cid := range cids {
		bPrivileged := false
		if c, ok := gInfoReadActiveContainer(cid); ok {
			if c.info != nil {
				bPrivileged = c.info.Privileged
			}
			prober.BuildProcessFamilyGroups(c.id, c.pid, false, bPrivileged, c.healthCheck)
		}
	}
}

func domainChange(domain share.CLUSDomain) {
	if !agentEnv.systemProfiles {
		return
	}

	log.WithFields(log.Fields{"domain": domain}).Debug()

	var groups []*groupProfileData
	targets := utils.NewSet()

	// rebuild custom group's members
	grpCacheLock.Lock()
	for _, cache := range grpProfileCacheMap {
		if utils.IsCustomProfileGroup(cache.group.Name) {
			for _, crt := range cache.group.Criteria {
				if strings.HasPrefix(crt.Key, "ns:") {
					groups = append(groups, cache)
					break
				}
			}
		}
	}
	grpCacheLock.Unlock()

	var pod *containerData

	gInfoRLock()
	for _, c := range gInfo.activeContainers {
		targets.Add(c.id) // include all containers
	}

	for _, cache := range groups {
		cache.members.Clear() // reset
		for _, c := range gInfo.activeContainers {
			if c.parentNS != "" {
				if parent, ok := gInfo.activeContainers[c.parentNS]; ok {
					pod = parent
				}
			}
			if isContainerSelected(c, pod, cache.group) {
				cache.members.Add(c.id)
			}
		}
	}
	gInfoRUnlock()

	grpCacheLock.Lock()
	grpNotifyProc = grpNotifyProc.Union(targets)
	grpNotifyFile = grpNotifyFile.Union(targets)
	grpCacheLock.Unlock()
}
