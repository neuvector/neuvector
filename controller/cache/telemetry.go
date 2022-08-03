package cache

import (
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
)

const (
	const_no_proxy = iota
	const_https_proxy
	const_http_proxy
)

func getTelemetryData() (bool, common.TelemetryData) {
	var teleData common.TelemetryData

	cacheMutexRLock()
	if systemConfigCache.NoTelemetryReport {
		cacheMutexRUnlock()
		return false, teleData
	}
	if systemConfigCache.RegistryHttpsProxy.Enable {
		teleData.UseProxy = const_https_proxy
	}

	teleData.Hosts = len(hostCacheMap)
	teleData.Groups = len(groupCacheMap)
	teleData.PolicyRules = len(policyCache.ruleHeads)
	if admStateCache.Enable {
		teleData.AdmCtrlEnabled = true
	}

	cacheMutexRUnlock()

	fedCacheMutexRLock()
	if fedMembershipCache.FedRole != api.FedRoleNone {
		teleData.InFederate = true
	}
	if fedMembershipCache.FedRole == api.FedRoleMaster {
		teleData.PrimaryCluster = true
		teleData.Clusters = len(fedJoinedClustersCache) + 1
	}
	fedCacheMutexRUnlock()

	return true, teleData
}
