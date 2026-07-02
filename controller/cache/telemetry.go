package cache

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

const (
	const_no_proxy = iota
	const_https_proxy
	const_http_proxy
)

func getTelemetryData(telemetryFreq uint) (bool, common.TelemetryData) {
	var teleData common.TelemetryData

	cacheMutexRLock()
	if systemConfigCache.NoTelemetryReport {
		cacheMutexRUnlock()
		return false, teleData
	}

	var lastUploadTime time.Time
	value, err := cluster.Get(share.CLUSTelemetryStore + "controller")
	if err != nil {
		log.WithError(err).Warn("failed to get telemetry data from cluster")
	}
	if value != nil {
		var nvUpgradeInfo share.CLUSCheckUpgradeInfo
		if err := json.Unmarshal(value, &nvUpgradeInfo); err != nil {
			log.WithError(err).Warn("failed to unmarshal upgrade info")
		}
		lastUploadTime = nvUpgradeInfo.LastUploadTime
	}
	var past = time.Minute * time.Duration(telemetryFreq)
	if time.Since(lastUploadTime) < past {
		cacheMutexRUnlock()
		return false, teleData
	}

	if systemConfigCache.RegistryHttpsProxy.Enable {
		teleData.UseProxy = const_https_proxy
	}
	teleData.Hosts = len(hostCacheMap)
	teleData.Groups = len(groupCacheMap)
	teleData.PolicyRules = len(policyCache.ruleHeads)
	cacheMutexRUnlock()

	var fedRole string
	fedCacheMutexRLock()
	fedRole = fedMembershipCache.FedRole
	fedCacheMutexRUnlock()
	// PrimaryCluster/WorkerClusters fields are only sent by master cluster when a cluster is in federate
	switch fedRole {
	case api.FedRoleNone:
		teleData.Clusters = 1
	case api.FedRoleMaster:
		teleData.Clusters = len(fedJoinedClustersCache) + 1
		teleData.PrimaryCluster = 1
	}

	return true, teleData
}
