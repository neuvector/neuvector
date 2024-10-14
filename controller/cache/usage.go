package cache

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const usageReportPeriod = time.Duration(time.Hour * 12)
const usageReportRetryWait = time.Minute
const usageReportHistory = 180

func signUsageReport(r *share.CLUSSystemUsageReport) string {
	token := make([]byte, 4)
	_, _ = rand.Read(token)
	s := fmt.Sprintf("%d%s", r.ReportedAt.Unix(), base64.StdEncoding.EncodeToString(token))
	return utils.EncryptPassword(s)
}

func writeUsageReport() error {
	r := getUsageReport()
	r.Signature = signUsageReport(r)
	value, _ := json.Marshal(*r)
	key := share.CLUSCtrlUsageReportKey(r.ReportedAt.Unix())

	var err error
	for i := 0; i < 3; i++ {
		if err = cluster.Put(key, value); err != nil {
			time.Sleep(usageReportRetryWait)
		} else {
			break
		}
	}

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write usage report")
		return err
	}

	// clean up
	keys, _ := cluster.GetStoreKeys(share.CLUSCtrlUsageReportStore)
	if len(keys) > usageReportHistory {
		all := make([]int64, 0, len(keys))
		for _, key := range keys {
			ts := share.CLUSCtrlUsageReportKey2TS(key)
			if ts > 0 {
				all = append(all, ts)
			}
		}

		// timestamp big to small (new to old)
		sort.Slice(all, func(i, j int) bool { return all[i] > all[j] })

		for i := usageReportHistory; i < len(all); i++ {
			key := share.CLUSCtrlUsageReportKey(all[i])
			_ = cluster.Delete(key)
		}
	}

	return nil
}

func getUsageReport() *share.CLUSSystemUsageReport {
	var r share.CLUSSystemUsageReport

	r.ReportedAt = time.Now().UTC()
	r.Platform = getHostPlatform(localDev.Host.Platform, localDev.Host.Flavor)
	r.CVEDBVersion = scanUtils.GetScannerDB().CVEDBVersion
	r.Registries = scan.GetRegistryCount()

	cacheMutexRLock()
	r.Hosts = len(hostCacheMap)
	r.Controllers = len(ctrlCacheMap)
	r.Agents = len(agentCacheMap)
	r.Scanners = len(scannerCacheMap)
	r.Groups = len(groupCacheMap)
	r.PolicyRules = len(policyCache.ruleHeads)
	r.AdmCtrlRules = len(admValidateExceptCache.RuleHeads) + len(admValidateDenyCache.RuleHeads)
	r.RespRules = len(localResPolicyCache.ruleMap)

	for _, cache := range hostCacheMap {
		r.CPUCores += int(cache.host.CPUs)
	}
	for _, cache := range wlCacheMap {
		if cache.workload.Running && cache.workload.ShareNetNS == "" {
			r.RunningPods++
		}
	}
	for _, cache := range groupCacheMap {
		if cache.group.PolicyMode == share.PolicyModeEvaluate {
			r.MonitorGroups++
		} else if cache.group.PolicyMode == share.PolicyModeEnforce {
			r.ProtectGroups++
		}
	}
	for _, h := range policyCache.ruleHeads {
		if h.CfgType == share.GroundCfg {
			r.CRDRules++
		}
	}
	cacheMutexRUnlock()

	domainMutex.RLock()
	r.Domains = len(domainCacheMap) - 3
	domainMutex.RUnlock()

	fedCacheMutexRLock()
	r.Clusters = len(fedJoinedClustersCache)
	fedCacheMutexRUnlock()

	store := share.CLUSConfigCloudStore
	keys, _ := cluster.GetStoreKeys(store)
	r.SLessProjs = len(keys)

	r.InstallationID, _ = clusHelper.GetInstallationID()

	return &r
}
