package cache

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type domainCache struct {
	domain *share.CLUSDomain
}

var domainCacheMap map[string]*domainCache = make(map[string]*domainCache)
var domainMutex sync.RWMutex
var domainRemoveMap map[string]time.Time = make(map[string]time.Time)
var domainNBEMap map[string]bool = make(map[string]bool)

var _pruningOrphanGroups uint32

func initDomain(name string, nsLabels map[string]string) *share.CLUSDomain {
	return &share.CLUSDomain{Name: name, Labels: nsLabels}
}

// This is from the k8s namespace resource watcher.
// It should not have our predefined domain, like "_images", "_containers" or "_nodes"
func domainAdd(name string, labels map[string]string) {
	log.WithFields(log.Fields{"domain": name}).Debug()
	accReadAll := access.NewReaderAccessControl()
	retry := 0
	for retry < retryClusterMax {
		var prev *uint64
		cd, rev, _ := clusHelper.GetDomain(name, accReadAll)
		if cd == nil {
			cd = initDomain(name, labels)
		} else {
			prev = &rev
		}
		cd.Labels = labels
		if err := clusHelper.PutDomain(cd, prev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}
}

func domainDelete(name string) {
	log.WithFields(log.Fields{"domain": name}).Debug()
	if err := clusHelper.DeleteDomain(name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

func getDomainData(name string) *share.CLUSDomain {
	domainMutex.RLock()
	defer domainMutex.RUnlock()
	if domainCache, ok := domainCacheMap[name]; ok {
		return domainCache.domain
	}
	return nil
}

func domainNBEChange(domain share.CLUSDomain) {
	log.WithFields(log.Fields{"domain": domain}).Debug("")
	oldnbe := false
	newnbe := false
	if onbe, ok := domainNBEMap[domain.Name]; ok {
		oldnbe = onbe
	}

	if v, ok := domain.Labels[share.NsBoundaryKey]; ok {
		if strings.ToLower(v) == share.NsBoundaryValEnable {
			domainNBEMap[domain.Name] = true
			newnbe = true
		} else {
			domainNBEMap[domain.Name] = false
			newnbe = false
		}
	} else {
		domainNBEMap[domain.Name] = false
		newnbe = false
	}
	if newnbe != oldnbe {
		scheduleIPPolicyCalculation(false)
	}
}

func domainConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSDomainKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var domain share.CLUSDomain
		json.Unmarshal(value, &domain)

		domainMutex.Lock()
		oDomain, _ := domainCacheMap[name]
		domainCacheMap[name] = &domainCache{domain: &domain}
		if cacher.rmNsGrps {
			if _, ok := domainRemoveMap[name]; ok {
				log.WithFields(log.Fields{"domain": name}).Debug()
				delete(domainRemoveMap, name)
			}
		}
		domainMutex.Unlock()

		if oDomain == nil || !reflect.DeepEqual(oDomain.domain.Labels, domain.Labels) {
			domainChange(domain)
			//ns-boundary enforcement
			domainNBEChange(domain)
		}
		log.WithFields(log.Fields{"domain": domain, "name": name}).Debug()

	case cluster.ClusterNotifyDelete:
		domainMutex.Lock()
		defer domainMutex.Unlock()

		if _, ok := domainCacheMap[name]; !ok {
			log.WithFields(log.Fields{"domain": name}).Error("Unknown domain")
			return
		}

		// Put pruned namespaces
		if cacher.rmNsGrps {
			if _, ok := domainRemoveMap[name]; !ok {
				log.WithFields(log.Fields{"domain": name}).Debug()
				domainRemoveMap[name] = time.Now()
			}
		}
		if dc, ok := domainCacheMap[name]; ok {
			if !dc.domain.Dummy {
				delete(domainCacheMap, name)
			}
		}
	}
}

func (m CacheMethod) GetDomainEffectiveTags(name string, acc *access.AccessControl) ([]string, error) {
	domainMutex.RLock()
	defer domainMutex.RUnlock()

	if cache, ok := domainCacheMap[name]; ok {
		if !acc.Authorize(cache.domain, nil) {
			return nil, common.ErrObjectAccessDenied
		}

		// Querying images, nodes and containers, return the tags directly
		if cache.domain.Dummy {
			return cache.domain.Tags, nil
		}

		// If _containers entry disabled, means per-domain-tag is on
		if cc, ok := domainCacheMap[api.DomainContainers]; ok {
			if cc.domain.Disable {
				return cache.domain.Tags, nil
			} else {
				return cc.domain.Tags, nil
			}
		} else {
			return cache.domain.Tags, nil
		}
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetDomainCount(acc *access.AccessControl) int {
	domainMutex.RLock()
	defer domainMutex.RUnlock()

	if acc.HasGlobalPermissions(share.PERM_INFRA_BASIC, 0) {
		return len(domainCacheMap) - 3
	} else {
		var count int
		for _, cache := range domainCacheMap {
			if cache.domain.Dummy {
				continue
			}
			if !acc.Authorize(cache.domain, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetAllDomains(acc *access.AccessControl) ([]*api.RESTDomain, bool) {
	var tagPerDomain bool

	domainMutex.RLock()

	dmap := make(map[string]*api.RESTDomain, 0)
	for name, cache := range domainCacheMap {
		if name == api.DomainContainers && cache.domain.Disable {
			tagPerDomain = true
		}
		if !acc.Authorize(cache.domain, nil) {
			continue
		}
		newnbe := false
		if onbe, ok := domainNBEMap[name]; ok {
			newnbe = onbe
		}
		dmap[name] = &api.RESTDomain{Name: name, Tags: cache.domain.Tags, Labels: cache.domain.Labels, Nbe: newnbe}
	}

	domainMutex.RUnlock()

	cacheMutexRLock()

	for _, cache := range wlCacheMap {
		if !acc.Authorize(cache.workload, nil) {
			continue
		}
		if common.OEMIgnoreWorkload(cache.workload) {
			continue
		}

		domain := cache.workload.Domain
		if domain == "" {
			domain = api.DomainContainers
		}

		if d, ok := dmap[domain]; ok {
			d.Workloads++
			if cache.workload.Running {
				d.RunningWorkloads++
				if cache.workload.ShareNetNS == "" {
					d.RunningPods++
				}
			}
		}
	}
	for _, cache := range groupCacheMap {
		if err := authorizeService(cache, acc); err != nil {
			continue
		}
		if cache.oemHide {
			continue
		}

		domain := cache.group.Domain
		if domain == "" {
			domain = api.DomainContainers
		}

		if d, ok := dmap[domain]; ok {
			d.Services++
		}
	}

	cacheMutexRUnlock()

	domains := make([]*api.RESTDomain, len(dmap))
	i := 0
	for _, d := range dmap {
		domains[i] = d
		i++
	}
	return domains, tagPerDomain
}

const pruneGroupDelay time.Duration = time.Minute * time.Duration(1)

func pruneGroupsByNamespace() {
	domains := utils.NewSet()
	now := time.Now()

	domainMutex.Lock()
	for name, t := range domainRemoveMap {
		if now.Sub(t) >= pruneGroupDelay {
			domains.Add(name)
		}
	}
	domainMutex.Unlock()

	if domains.Cardinality() == 0 {
		return
	}

	// only leader has the action items.
	if isLeader() {
		var groups []string
		log.WithFields(log.Fields{"domains": domains}).Debug()

		cacheMutexRLock()
		for name, groupCache := range groupCacheMap {
			if domains.Contains(groupCache.group.Domain) {
				groups = append(groups, name)
			}
		}
		cacheMutexRUnlock()

		if len(groups) > 0 {
			lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
				return
			}

			log.WithFields(log.Fields{"groups": groups}).Debug()
			kv.DeletePolicyByGroups(groups)
			kv.DeleteResponseRuleByGroups(groups)

			txn := cluster.Transact()
			for _, name := range groups {
				clusHelper.DeleteGroupTxn(txn, name)
			}
			if ok, err1 := txn.Apply(); err1 != nil || !ok {
				log.WithFields(log.Fields{"ok": ok, "error": err1}).Error("Atomic write to the cluster failed")
			}
			txn.Close()
			clusHelper.ReleaseLock(lock)
		}
	}

	// remove the domain entries here, in case that it failed to acquire the policy lock
	domainMutex.Lock()
	for itr := range domains.Iter() {
		delete(domainRemoveMap, itr.(string))
	}
	domainMutex.Unlock()
}

func pruneOrphanGroups() {
	// called on demand for k8s only
	if localDev.Host.Platform != share.PlatformKubernetes {
		return
	}

	doPrune := atomic.CompareAndSwapUint32(&_pruningOrphanGroups, 0, 1)
	if doPrune {
		defer atomic.StoreUint32(&_pruningOrphanGroups, 0)

		log.Info()
		domains := utils.NewSet()
		cacheMutexRLock()
		for _, groupCache := range groupCacheMap {
			g := groupCache.group
			if g.CfgType == share.GroundCfg && !domains.Contains(g.Domain) && g.Domain != "" && !g.Reserved {
				domains.Add(g.Domain)
			}
		}
		cacheMutexRUnlock()
		// now domains contains those k8s namespaces for all groups in nv

		if objs, err := global.ORCH.ListResource(resource.RscTypeNamespace, ""); len(objs) > 0 {
			k8sNSs := utils.NewSet()
			for _, obj := range objs {
				if nsObj := obj.(*resource.Namespace); nsObj != nil {
					k8sNSs.Add(nsObj.Name)
				}
			}
			// now k8sNSs contains all k8s namespaces
			for domain := range domains.Iter() {
				name := domain.(string)
				if k8sNSs.Contains(name) {
					// this domain/namespace still exists in k8s
					domains.Remove(name)
				}
			}
		} else {
			log.WithFields(log.Fields{"err": err}).Error()
			return
		}
		// now domains contains those non-existing k8s namespaces

		domainMutex.Lock()
		for domain := range domains.Iter() {
			name := domain.(string)
			if _, ok := domainRemoveMap[name]; ok {
				// this non-existing domain will be handled by pruneGroupsByNamespace()
				domains.Remove(name)
			}
		}
		domainMutex.Unlock()
		// now domains contains those non-existing k8s namespaces but some groups for them still exist in nv

		var groups []string
		if domains.Cardinality() > 0 {
			log.WithFields(log.Fields{"domains": domains}).Info()
			cacheMutexRLock()
			for name, groupCache := range groupCacheMap {
				if domains.Contains(groupCache.group.Domain) {
					groups = append(groups, name)
				}
			}
			cacheMutexRUnlock()
		}
		// now groups are those orphan groups (whose k8s namespace doesn't exist anymore)

		if len(groups) > 0 {
			lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
				return
			}

			log.WithFields(log.Fields{"groups": groups}).Debug()
			kv.DeletePolicyByGroups(groups)
			kv.DeleteResponseRuleByGroups(groups)

			txn := cluster.Transact()
			for _, name := range groups {
				clusHelper.DeleteGroupTxn(txn, name)
			}
			if ok, err1 := txn.Apply(); err1 != nil || !ok {
				log.WithFields(log.Fields{"ok": ok, "error": err1}).Error("Atomic write to the cluster failed")
			}
			txn.Close()
			clusHelper.ReleaseLock(lock)
		}
	}
}
