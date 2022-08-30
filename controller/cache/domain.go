package cache

import (
	"encoding/json"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

type domainCache struct {
	domain *share.CLUSDomain
}

var domainCacheMap map[string]*domainCache = make(map[string]*domainCache)
var domainMutex sync.RWMutex

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
		cd, rev, _ := clusHelper.GetDomain(name, accReadAll)
		if cd == nil {
			cd = initDomain(name, labels)
		}
		cd.Labels = labels
		if err := clusHelper.PutDomain(cd, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
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

func domainConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	name := share.CLUSDomainKey2Name(key)
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var domain share.CLUSDomain
		json.Unmarshal(value, &domain)

		domainMutex.Lock()
		defer domainMutex.Unlock()

		domainCacheMap[name] = &domainCache{domain: &domain}
		log.WithFields(log.Fields{"domain": domain, "name": name}).Debug()

	case cluster.ClusterNotifyDelete:
		domainMutex.Lock()
		defer domainMutex.Unlock()

		if _, ok := domainCacheMap[name]; !ok {
			log.WithFields(log.Fields{"domain": name}).Error("Unknown domain")
			return
		}

		// Shouldn't happen, but have the logic anyway. Not delete kv, only initial the cache
		domainCacheMap[name] = &domainCache{domain: initDomain(name, nil)}
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
		dmap[name] = &api.RESTDomain{Name: name, Tags: cache.domain.Tags}
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
