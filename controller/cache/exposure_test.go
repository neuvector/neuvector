package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

func TestBuildExposureReport(t *testing.T) {
	preTest()
	defer postTest()

	seen := time.Date(2026, 9, 28, 17, 30, 0, 0, time.UTC).Unix()

	ingress := []*api.RESTExposedEndpoint{
		{
			ID:           "wl-b",
			Service:      "b-svc",
			DisplayName:  "pod-b",
			PodName:      "pod-b",
			CriticalVuls: 1,
			HighVuls:     2,
			MedVuls:      3,
			PolicyMode:   "Discover",
			Entries: []*api.RESTConversationReportEntry{
				{
					Bytes: 10, Sessions: 2, Port: "tcp/80", Application: "HTTP",
					PolicyAction: "violate", CIP: "1.1.1.1", SIP: "10.0.0.1",
					FQDN: "in.example", LastSeenAt: seen,
				},
				nil,
			},
		},
		{
			ID:          "wl-a",
			Service:     "a-svc",
			DisplayName: "pod-a",
			PodName:     "pod-a",
			PolicyMode:  "Protect",
			Entries: []*api.RESTConversationReportEntry{
				{
					Bytes: 20, Sessions: 1, Port: "tcp/443",
					PolicyAction: "allow", CIP: "2.2.2.2", SIP: "10.0.0.2",
					LastSeenAt: seen,
				},
			},
		},
	}
	egress := []*api.RESTExposedEndpoint{
		{
			ID:          "wl-a",
			Service:     "a-svc",
			DisplayName: "pod-a",
			PodName:     "pod-a",
			PolicyMode:  "Protect",
			Entries: []*api.RESTConversationReportEntry{
				{
					Bytes: 30, Sessions: 4, Port: "udp/53", Application: "DNS",
					PolicyAction: "open", CIP: "10.0.0.2", SIP: "8.8.8.8",
					FQDN: "dns.example", LastSeenAt: seen,
				},
			},
		},
		{
			ID: "wl-empty", Service: "empty", DisplayName: "pod-empty", PodName: "pod-empty",
		},
	}

	cacheMutexLock()
	prevCluster := systemConfigCache.ClusterName
	systemConfigCache.ClusterName = "cluster-1"
	wlCacheMap["wl-a"] = &workloadCache{workload: &share.CLUSWorkload{ID: "wl-a", Domain: "ns-a"}}
	wlCacheMap["wl-b"] = &workloadCache{workload: &share.CLUSWorkload{ID: "wl-b", Domain: "ns-b"}}
	cacheMutexUnlock()
	t.Cleanup(func() {
		cacheMutexLock()
		systemConfigCache.ClusterName = prevCluster
		delete(wlCacheMap, "wl-a")
		delete(wlCacheMap, "wl-b")
		cacheMutexUnlock()
	})

	before := time.Now().UTC().Unix()
	report := buildExposureReport(ingress, egress, "")
	after := time.Now().UTC().Unix()
	require.NotNil(t, report)
	require.Len(t, report.Entries, 3)

	assert.Equal(t, api.EventNameExposureReport, report.Name)
	assert.Equal(t, api.LogLevelINFO, report.Level)
	assert.Equal(t, "cluster-1", report.ClusterName)
	assert.GreaterOrEqual(t, report.ReportedTimeStamp, before)
	assert.LessOrEqual(t, report.ReportedTimeStamp, after)

	assert.Equal(t, "ingress", report.Entries[0].Direction)
	assert.Equal(t, "a-svc", report.Entries[0].Service)
	assert.Equal(t, "pod-a", report.Entries[0].Pod)
	assert.Equal(t, "2.2.2.2", report.Entries[0].ExternalIP)
	assert.Equal(t, "allow", report.Entries[0].Action)
	assert.Equal(t, time.Unix(seen, 0).UTC().Format(time.RFC3339), report.Entries[0].SessionTime)

	assert.Equal(t, "ingress", report.Entries[1].Direction)
	assert.Equal(t, "b-svc", report.Entries[1].Service)
	assert.Equal(t, "1.1.1.1", report.Entries[1].ExternalIP)
	assert.Equal(t, "in.example", report.Entries[1].ExternalHost)
	assert.Equal(t, 1, report.Entries[1].Critical)
	assert.Equal(t, 2, report.Entries[1].High)
	assert.Equal(t, 3, report.Entries[1].Medium)

	assert.Equal(t, "egress", report.Entries[2].Direction)
	assert.Equal(t, "8.8.8.8", report.Entries[2].ExternalIP)
	assert.Equal(t, "dns.example", report.Entries[2].ExternalHost)
	assert.Equal(t, "DNS", report.Entries[2].Application)
	assert.Equal(t, uint64(30), report.Entries[2].Bytes)
	assert.Equal(t, uint32(4), report.Entries[2].Sessions)

	filtered := buildExposureReport(ingress, egress, "ns-a")
	require.Len(t, filtered.Entries, 2)
	assert.Equal(t, "ingress", filtered.Entries[0].Direction)
	assert.Equal(t, "a-svc", filtered.Entries[0].Service)
	assert.Equal(t, "egress", filtered.Entries[1].Direction)
	assert.Equal(t, "a-svc", filtered.Entries[1].Service)
}
