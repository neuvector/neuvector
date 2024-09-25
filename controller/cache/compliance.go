package cache

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type cpCache struct {
	profile *share.CLUSComplianceProfile
	filter  map[string][]string // item => tags
}

var cpCacheMap map[string]*cpCache = make(map[string]*cpCache)
var cpMutex sync.RWMutex

func filterComplianceLog(audit *api.Audit) *api.Audit {
	cpMutex.RLock()
	cache, ok := cpCacheMap[share.DefaultComplianceProfileName]
	cpMutex.RUnlock()
	if !ok {
		// Disable excessive logging
		// log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
		return audit
	}

	var domain string
	switch audit.Name {
	case api.EventNameComplianceContainerBenchViolation, api.EventNameComplianceContainerFileBenchViolation:
		wlc := getWorkloadCache(audit.WorkloadID)
		if wlc == nil || wlc.workload == nil {
			return audit
		}

		// check disable system flag
		if cache.profile.DisableSystem && wlc.platformRole == api.PlatformContainerCore {
			return nil
		}

		// Get workload namespace
		domain = audit.WorkloadDomain
		if domain == "" {
			domain = api.DomainContainers
		}
	case api.EventNameComplianceImageBenchViolation:
		domain = api.DomainImages
	case api.EventNameComplianceHostBenchViolation:
		domain = api.DomainNodes
	}

	// Is the namespace tagged
	tags, _ := cacher.GetDomainEffectiveTags(domain, access.NewReaderAccessControl())
	if len(tags) > 0 {
		// namespace tagged
		domainTags := utils.NewSetFromSliceKind(tags)

		list := make([]string, 0, len(audit.Items))
		for _, item := range audit.Items {
			if tokens := strings.Split(item, " "); len(tokens) > 0 {
				if itemTags, ok := cache.filter[tokens[0]]; !ok {
					list = append(list, item)
				} else {
					// if the item and the domain has common tags, add the item
					for _, t := range itemTags {
						if domainTags.Contains(t) {
							list = append(list, item)
						}
					}
				}
			}
		}

		if len(list) == 0 {
			return nil
		}

		audit.Items = list
	}

	return audit
}

func buildComplianceFilter(ccp *share.CLUSComplianceProfile) map[string][]string {
	filter := make(map[string][]string)

	// First create user override entries
	for _, e := range ccp.Entries {
		filter[e.TestNum] = e.Tags
	}

	// Add checks that are not in the override list
	_, metaMap := scanUtils.GetComplianceMeta(scanUtils.V1)

	for _, m := range metaMap {
		if _, ok := filter[m.TestNum]; !ok {
			var complianceTags []string
			for _, compliance := range m.Tags {
				complianceTags = append(complianceTags, compliance)
			}
			filter[m.TestNum] = complianceTags
		}
	}

	return filter
}

func complianceProfile2REST(ccp *share.CLUSComplianceProfile) *api.RESTComplianceProfile {
	rcp := api.RESTComplianceProfile{
		Name:          ccp.Name,
		DisableSystem: ccp.DisableSystem,
		Entries:       make([]api.RESTComplianceProfileEntry, len(ccp.Entries)),
		CfgType:       cfgTypeMapping[ccp.CfgType],
	}

	i := 0
	for _, ce := range ccp.Entries {
		rcp.Entries[i] = api.RESTComplianceProfileEntry{
			TestNum: ce.TestNum,
			Tags:    ce.Tags,
		}
		i++
	}
	sort.Slice(rcp.Entries, func(i, j int) bool { return rcp.Entries[i].TestNum < rcp.Entries[j].TestNum })

	return &rcp
}

func complianceConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	if share.CLUSComplianceKey2Type(key) != "profile" {
		return
	}

	name := share.CLUSComplianceProfileKey2Name(key)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var ccp share.CLUSComplianceProfile
		if err := json.Unmarshal(value, &ccp); err != nil {
			log.WithFields(log.Fields{"err": err}).Debug("Fail to decode")
			return
		}

		cache := &cpCache{
			profile: &ccp,
			filter:  buildComplianceFilter(&ccp),
		}

		cpMutex.Lock()
		defer cpMutex.Unlock()
		cpCacheMap[name] = cache
	case cluster.ClusterNotifyDelete:
		cpMutex.Lock()
		defer cpMutex.Unlock()
		delete(cpCacheMap, name)
	}
}

func (m CacheMethod) GetComplianceProfile(name string, acc *access.AccessControl) (*api.RESTComplianceProfile, map[string][]string, error) {
	cpMutex.RLock()
	defer cpMutex.RUnlock()
	if cache, ok := cpCacheMap[name]; ok {
		if !acc.Authorize(cache.profile, nil) {
			return nil, nil, common.ErrObjectAccessDenied
		}
		return complianceProfile2REST(cache.profile), cache.filter, nil
	}
	return nil, nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetAllComplianceProfiles(acc *access.AccessControl) []*api.RESTComplianceProfile {
	list := make([]*api.RESTComplianceProfile, 0)

	cpMutex.RLock()
	defer cpMutex.RUnlock()
	for _, cache := range cpCacheMap {
		if !acc.Authorize(cache.profile, nil) {
			continue
		}
		list = append(list, complianceProfile2REST(cache.profile))
	}
	return list
}

// Risk score

type wlMini struct {
	mode string
}

type podVuls struct {
	CriticalVuls int
	HighVuls int
	MedVuls int
}

func (m CacheMethod) GetRiskScoreMetrics(acc, accCaller *access.AccessControl) *api.RESTInternalSystemData {
	var s api.RESTRiskScoreMetrics

	s.Platform, s.K8sVersion, s.OCVersion = m.GetPlatform()
	s.NewServiceMode, s.NewProfileMode = getNewServicePolicyMode()

	// Check if count system container/group
	var disableSystem bool
	cpMutex.RLock()
	cp, ok := cpCacheMap[share.DefaultComplianceProfileName]
	cpMutex.RUnlock()
	if ok && cp.profile.DisableSystem {
		disableSystem = true
	}

	cacheMutexRLock()

	// existing group mode to score
	for _, cache := range groupCacheMap {
		g := cache.group
		if err := authorizeService(cache, acc); err != nil {
			continue
		}
		if (g.PlatformRole != "" && disableSystem) || g.NotScored {
			// skip system containers
			continue
		}
		switch g.PolicyMode {
		case share.PolicyModeLearn:
			s.Groups.DiscoverGroups++
			if g.BaselineProfile == share.ProfileZeroDrift {
				s.Groups.DiscoverGroupsZD++
			}
		case share.PolicyModeEvaluate:
			s.Groups.MonitorGroups++
			if g.BaselineProfile == share.ProfileZeroDrift {
				s.Groups.MonitorGroupsZD++
			}
		case share.PolicyModeEnforce:
			s.Groups.ProtectGroups++
			if g.BaselineProfile == share.ProfileZeroDrift {
				s.Groups.ProtectGroupsZD++
			}
		}
		switch g.ProfileMode {
		case share.PolicyModeLearn:
			s.Groups.ProfileDiscoverGroups++
		case share.PolicyModeEvaluate:
			s.Groups.ProfileMonitorGroups++
		case share.PolicyModeEnforce:
			s.Groups.ProfileProtectGroups++
		}
		s.Groups.Groups++
	}

	// Calculate pod vulnerabilities
	podVulsMap := make(map[string]podVuls) // podName => podVuls
	for _, cache := range wlCacheMap {
		wl := cache.workload
		if !acc.Authorize(wl, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(wl) {
			continue
		}
		if cache.platformRole != "" && disableSystem {
			// skip system containers
			continue
		}
		if !wl.Running || cache.scanBrief == nil {
			continue
		}

		// Calculate sum of vulnerabilities for containers in each pod
		// Do not re-sum existing pod vulnerabilities
		if wl.ShareNetNS != "" {
			pv, ok := podVulsMap[cache.podName]
			if !ok {
				pv = podVuls{}
			}
			pv.CriticalVuls += cache.scanBrief.CriticalVuls
			pv.HighVuls += cache.scanBrief.HighVuls
			pv.MedVuls += cache.scanBrief.MedVuls
			podVulsMap[cache.podName] = pv
		}
	}

	// get all running pod
	epMap := make(map[string]*wlMini) // id ==> plicy mode
	for _, cache := range wlCacheMap {
		wl := cache.workload
		if !acc.Authorize(wl, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(wl) {
			continue
		}
		if cache.platformRole != "" && disableSystem {
			// skip system containers
			continue
		}
		if !wl.Running {
			continue
		}

		var mode string
		if gc, ok := groupCacheMap[cache.learnedGroupName]; ok {
			if gc.group.NotScored {
				continue
			}

			mode = gc.group.PolicyMode
		}

		// Assign containers' sum of vulnerabilities to pod cache
		if wl.ShareNetNS == "" {
			epMap[cache.workload.ID] = &wlMini{mode: mode}
			if podVuls, ok := podVulsMap[cache.podName]; ok {
				if cache.scanBrief == nil {
					cache.scanBrief = &api.RESTScanBrief{}
				}
				cache.scanBrief.CriticalVuls = podVuls.CriticalVuls
				cache.scanBrief.HighVuls = podVuls.HighVuls
				cache.scanBrief.MedVuls = podVuls.MedVuls
			}
		} else {
			// Only counts app containers, not pod
			if wl.Privileged {
				s.WLs.PrivilegedWLs++
			}
			if wl.RunAsRoot {
				s.WLs.RootWLs++
			}

			// workload cve
			if cache.scanBrief != nil {
				cve := cache.scanBrief.CVECount()
				switch mode {
				case share.PolicyModeLearn:
					s.CVEs.DiscoverCVEs += cve
				case share.PolicyModeEvaluate:
					s.CVEs.MonitorCVEs += cve
				case share.PolicyModeEnforce:
					s.CVEs.ProtectCVEs += cve
				}
			}
		}
	}

	// host cve
	var scoreHost bool
	if gc, ok := groupCacheMap[api.AllHostGroup]; !ok || !gc.group.NotScored {
		scoreHost = true
	}
	for _, cache := range hostCacheMap {
		if !acc.Authorize(cache.host, nil) {
			continue
		}
		if cache.scanBrief != nil && scoreHost {
			s.CVEs.HostCVEs += cache.scanBrief.CVECount()
		}
		s.Hosts++
	}

	// count admission control rule to score
	s.DenyAdmCtrlRules = len(admValidateDenyCache.RuleHeads)

	cacheMutexRUnlock()

	scanMutexRLock()
	if acc.Authorize(&share.CLUSHost{}, nil) {
		if info, ok := scanMap[common.ScanPlatformID]; ok && info.brief != nil {
			s.CVEs.PlatformCVEs = info.brief.CVECount()
		}
	}
	scanMutexRUnlock()

	ingress := make(map[string]*api.RESTConversationReport)
	egress := make(map[string]*api.RESTConversationReport)

	s.WLs.RunningPods = len(epMap)

	// count external exposure to score
	graphMutexRLock()
	for id, wl := range epMap {
		var external, violate, threat bool

		if outs := wlGraph.OutsByLink(id, graphLink); outs != nil {
			for o := range outs.Iter() {
				if o.(string) == api.LearnedExternal {
					external = true
					if a := wlGraph.Attr(id, graphLink, api.LearnedExternal); a != nil {
						attr := a.(*graphAttr)

						cr := graphAttr2REST(attr)
						egress[id] = cr

						if cr.PolicyAction == share.PolicyActionViolate || cr.PolicyAction == share.PolicyActionDeny {
							violate = true
						}
						if cr.Severity != "" {
							threat = true
						}
					}
				}
			}
		}
		if ins := wlGraph.InsByLink(id, graphLink); ins != nil {
			for o := range ins.Iter() {
				if o.(string) == api.LearnedExternal {
					external = true
					if a := wlGraph.Attr(api.LearnedExternal, graphLink, id); a != nil {
						attr := a.(*graphAttr)

						cr := graphAttr2REST(attr)
						ingress[id] = cr

						if cr.PolicyAction == share.PolicyActionViolate || cr.PolicyAction == share.PolicyActionDeny {
							violate = true
						}
						if cr.Severity != "" {
							threat = true
						}
					}
				}
			}
		}

		if external {
			switch wl.mode {
			case share.PolicyModeLearn:
				s.WLs.DiscoverExtEPs++
			case share.PolicyModeEvaluate:
				s.WLs.MonitorExtEPs++
			case share.PolicyModeEnforce:
				s.WLs.ProtectExtEPs++
			}
			if violate {
				s.WLs.VioExtEPs++
			}
			if threat {
				s.WLs.ThrtExtEPs++
			}
		}
	}

	graphMutexRUnlock()

	ins := make([]*api.RESTExposedEndpoint, 0, len(ingress))
	outs := make([]*api.RESTExposedEndpoint, 0, len(egress))

	cacheMutexRLock()
	for id, cr := range ingress {
		if cache, ok := wlCacheMap[id]; ok {
			wl := cache.workload
			if !accCaller.Authorize(wl, nil) {
				continue
			}
			r := &api.RESTExposedEndpoint{
				ID:             wl.ID,
				Name:           wl.Name,
				DisplayName:    cache.displayName,
				PodName:        cache.podName,
				Service:        cache.serviceName,
				PolicyAction:   cr.PolicyAction,
				ThreatSeverity: cr.Severity,
				Protos:         cr.Protos,
				Apps:           cr.Apps,
				Ports:          cr.Ports,
				Entries:        cr.Entries,
			}
			r.PolicyMode, _ = getWorkloadPerGroupPolicyMode(cache)
			if cache.scanBrief != nil {
				r.CriticalVuls = cache.scanBrief.CriticalVuls
				r.HighVuls = cache.scanBrief.HighVuls
				r.MedVuls = cache.scanBrief.MedVuls
			}
			ins = append(ins, r)
		}
	}
	for id, cr := range egress {
		if cache, ok := wlCacheMap[id]; ok {
			wl := cache.workload
			if !accCaller.Authorize(wl, nil) {
				continue
			}
			r := &api.RESTExposedEndpoint{
				ID:             wl.ID,
				Name:           wl.Name,
				DisplayName:    cache.displayName,
				PodName:        cache.podName,
				Service:        cache.serviceName,
				PolicyAction:   cr.PolicyAction,
				ThreatSeverity: cr.Severity,
				Protos:         cr.Protos,
				Apps:           cr.Apps,
				Ports:          cr.Ports,
				Entries:        cr.Entries,
			}
			r.PolicyMode, _ = getWorkloadPerGroupPolicyMode(cache)
			if cache.scanBrief != nil {
				r.CriticalVuls = cache.scanBrief.CriticalVuls
				r.HighVuls = cache.scanBrief.HighVuls
				r.MedVuls = cache.scanBrief.MedVuls
			}
			outs = append(outs, r)
		}
	}
	cacheMutexRUnlock()

	return &api.RESTInternalSystemData{Metrics: &s, Ingress: ins, Egress: outs}
}

// ---

func benchHostDelete(id string, param interface{}) {
	cluster.DeleteTree(share.CLUSBenchKey(id))
	cluster.Delete(share.CLUSBenchStateHostKey(id))
}

func benchAgentOnline(id string, param interface{}) {
	// Read bench checks into cache in case its notification came earlier
	agent := param.(*agentCache).agent
	benchStateHandler(cluster.ClusterNotifyAdd, share.CLUSBenchStateHostKey(agent.HostID), nil)
}

func readBenchFromCluster(id string, bench share.BenchType) []byte {
	key := share.CLUSBenchReportKey(id, bench)
	if value, err := cluster.Get(key); err != nil || len(value) == 0 {
		// not all bench type exist, for example custom check, so use INFO level debug
		// log.WithFields(log.Fields{"error": err, "key": key}).Info("Benchmark report not found")
		return nil
	} else {
		return value
	}
}

// value could be nil if it's coming from host/workload object notification
func benchStateHandler(nType cluster.ClusterNotifyType, key string, value []byte) {
	cctx.ScanLog.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug()

	if nType == cluster.ClusterNotifyDelete {
		db.DeleteBenchByID(share.CLUSBenchStateKey2ID(key))
		return
	}

	id := share.CLUSBenchStateKey2ID(key)
	if share.CLUSBenchStateKey2Type(key) == "host" {
		if c := getHostCache(id); c != nil {
			benchData := &db.DbBench{
				Type:    "host",
				AssetID: id,
			}
			if v := readBenchFromCluster(id, share.BenchCustomHost); v != nil {
				benchData.CustomBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchDockerHost); v != nil {
				benchData.DockerBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchKubeMaster); v != nil {
				benchData.MasterBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchKubeWorker); v != nil {
				benchData.WorkerBenchValue = v
			}

			err := db.PopulateBenchData(benchData)
			if err != nil {
				log.WithFields(log.Fields{"err": err, "id": id}).Error("save bench data failed")
			}
		}
	} else {
		if c := getWorkloadCache(id); c != nil {
			benchData := &db.DbBench{
				Type:    "workload",
				AssetID: id,
			}

			if v := readBenchFromCluster(id, share.BenchCustomContainer); v != nil {
				benchData.CustomBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchContainer); v != nil {
				benchData.DockerBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchContainerSecret); v != nil {
				benchData.SecretBenchValue = v
			}
			if v := readBenchFromCluster(id, share.BenchContainerSetID); v != nil {
				benchData.SetidBenchValue = v
			}

			err := db.PopulateBenchData(benchData)
			if err != nil {
				log.WithFields(log.Fields{"err": err, "id": id}).Error("save bench data failed")
			}
		}
	}
}
