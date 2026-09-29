package cache

import (
	"sort"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
)

func (m CacheMethod) SendExposureReport(acc, accCaller *access.AccessControl, domain string) {
	data := m.GetRiskScoreMetrics(acc, accCaller)
	if data == nil {
		return
	}

	report := buildExposureReport(data.Ingress, data.Egress, domain)
	if len(report.Entries) == 0 {
		return
	}
	sendSyslog(report, api.LogLevelINFO, api.CategoryAudit, api.ExposureReportHeader)
}

// buildExposureReport flattens ingress then egress into one report.
// domain keeps only workloads whose namespace equals domain when domain is non-empty.
// Endpoint order matches the manager export: service name, then pod name.
func buildExposureReport(ingress, egress []*api.RESTExposedEndpoint, domain string) *api.RESTExposureReportLog {
	cacheMutexRLock()
	cluster := systemConfigCache.ClusterName
	var domains map[string]string
	if domain != "" {
		domains = make(map[string]string, len(wlCacheMap))
		for id, c := range wlCacheMap {
			if c.workload != nil {
				domains[id] = c.workload.Domain
			}
		}
	}
	cacheMutexRUnlock()
	reported := time.Now().UTC()

	entries := make([]*api.RESTExposureLogEntry, 0)
	appendDirection := func(list []*api.RESTExposedEndpoint, direction string) {
		sorted := append([]*api.RESTExposedEndpoint(nil), list...)
		sort.SliceStable(sorted, func(i, j int) bool {
			left, right := sorted[i], sorted[j]
			if left == nil || right == nil {
				return left != nil
			}
			return left.Service+left.PodName < right.Service+right.PodName
		})
		for _, ep := range sorted {
			if ep == nil {
				continue
			}
			if domain != "" && domains[ep.ID] != domain {
				continue
			}
			for _, entry := range ep.Entries {
				if entry == nil {
					continue
				}
				ip := entry.SIP
				if direction == "ingress" {
					ip = entry.CIP
				}
				entries = append(entries, &api.RESTExposureLogEntry{
					Direction:    direction,
					Service:      ep.Service,
					Pod:          ep.DisplayName,
					Critical:     ep.CriticalVuls,
					High:         ep.HighVuls,
					Medium:       ep.MedVuls,
					PolicyMode:   ep.PolicyMode,
					ExternalIP:   ip,
					ExternalHost: entry.FQDN,
					Port:         entry.Port,
					Bytes:        entry.Bytes,
					Application:  entry.Application,
					Sessions:     entry.Sessions,
					Action:       entry.PolicyAction,
					SessionTime:  api.RESTTimeString(time.Unix(entry.LastSeenAt, 0).UTC()),
				})
			}
		}
	}
	appendDirection(ingress, "ingress")
	appendDirection(egress, "egress")

	return &api.RESTExposureReportLog{
		Name:              api.EventNameExposureReport,
		Level:             api.LogLevelINFO,
		ReportedTimeStamp: reported.Unix(),
		ReportedAt:        api.RESTTimeString(reported),
		ClusterName:       cluster,
		Entries:           entries,
	}
}
