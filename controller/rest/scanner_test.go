package rest

import (
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/stretchr/testify/assert"
)

// ScannerMockCache is a mock implementation of the cache for testing
type ScannerMockCache struct {
	MockCache
	workloads       map[string]*api.RESTWorkload
	vulnerabilities map[string][]*api.RESTVulnerability
}

// Ensure MockCache implements CacheInterface at compile time
var _ cache.CacheInterface = (*ScannerMockCache)(nil)

// NewScannerMockCache creates a new mock cache instance
func NewScannerMockCache() *ScannerMockCache {
	return &ScannerMockCache{
		workloads:       make(map[string]*api.RESTWorkload),
		vulnerabilities: make(map[string][]*api.RESTVulnerability),
	}
}

// GetVulnerabilityReport returns a mock vulnerability report for testing
func (m *ScannerMockCache) GetVulnerabilityReport(id string, showTag string) ([]*api.RESTVulnerability, []*api.RESTScanModule, error) {
	vulns, exists := m.vulnerabilities[id]
	if exists {
		return vulns, []*api.RESTScanModule{}, nil
	}

	return []*api.RESTVulnerability{}, []*api.RESTScanModule{}, nil
}

// GetAllWorkloads returns all workloads from the mock cache
func (m *ScannerMockCache) GetAllWorkloads(view string, acc *access.AccessControl, idlist utils.Set) []*api.RESTWorkload {
	result := make([]*api.RESTWorkload, 0, len(m.workloads))
	for _, workload := range m.workloads {
		result = append(result, workload)
	}
	return result
}

// AddWorkload adds a workload to the mock cache
func (m *ScannerMockCache) AddWorkload(id string, workload *api.RESTWorkload) {
	m.workloads[id] = workload
}

// AddVulnerability adds a vulnerability to the mock cache for a specific workload
func (m *ScannerMockCache) AddVulnerability(id string, vuln *api.RESTVulnerability) {
	if m.vulnerabilities[id] == nil {
		m.vulnerabilities[id] = make([]*api.RESTVulnerability, 0)
	}
	m.vulnerabilities[id] = append(m.vulnerabilities[id], vuln)
}

func setupWorkloads(mockCache *ScannerMockCache) {
	mockCache.AddWorkload("wl1", &api.RESTWorkload{
		RESTWorkloadBrief: api.RESTWorkloadBrief{
			ID:       "wl1",
			Name:     "workload1",
			Domain:   "default",
			HostName: "host1",
		},
	})
	mockCache.AddWorkload("wl2", &api.RESTWorkload{
		RESTWorkloadBrief: api.RESTWorkloadBrief{
			ID:       "wl2",
			Name:     "workload2",
			Domain:   "default",
			HostName: "host1",
		},
	})
	mockCache.AddWorkload("wl3", &api.RESTWorkload{
		RESTWorkloadBrief: api.RESTWorkloadBrief{
			ID:       "wl3",
			Name:     "workload3",
			Domain:   "default",
			HostName: "host1",
		},
	})
	mockCache.AddVulnerability("wl1", &api.RESTVulnerability{
		Name:     "vulnerability11",
		Severity: "critical",
	})
	mockCache.AddVulnerability("wl1", &api.RESTVulnerability{
		Name:     "vulnerability12",
		Severity: "critical",
	})
	mockCache.AddVulnerability("wl1", &api.RESTVulnerability{
		Name:     "vulnerability1",
		Severity: "high",
	})
	mockCache.AddVulnerability("wl1", &api.RESTVulnerability{
		Name:     "vulnerability2",
		Severity: "high",
	})
	mockCache.AddVulnerability("wl1", &api.RESTVulnerability{
		Name:     "vulnerability3",
		Severity: "high",
	})
	mockCache.AddVulnerability("wl2", &api.RESTVulnerability{
		Name:     "vulnerability1",
		Severity: "high",
	})
	mockCache.AddVulnerability("wl2", &api.RESTVulnerability{
		Name:     "vulnerability3",
		Severity: "high",
	})
}

// TestHandlerWorkloadsScanReportInternal verifies the handlerWorkloadsScanReportInternal function
func TestHandlerWorkloadsScanReportInternal(t *testing.T) {
	preTest()

	// Create mock cache
	mockCache := NewScannerMockCache()

	// Create access control
	acc := &access.AccessControl{}

	tests := []struct {
		name           string
		setupWorkloads func()
		query          *api.RESTAssetsScanReportQuery
		expectedLen    int
		expectedError  bool
		validate       func(*testing.T, api.RESTAssetScanReportData)
	}{
		{
			name: "empty workloads",
			setupWorkloads: func() {
				// No workloads added
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "single workload with vulnerabilities",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
			},
			expectedLen:   0, // No vulnerabilities in mock
			expectedError: false,
		},
		{
			name: "with domain filter",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "prod",
						HostName: "host1",
					},
				})
				mockCache.AddWorkload("wl2", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl2",
						Name:     "workload2",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				Filters: []api.RESTAssetsScanReportFilter{
					{
						Name:  "domain",
						Op:    api.OPeq,
						Value: []string{"prod"},
					},
				},
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "with hostname filter",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
				mockCache.AddWorkload("wl2", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl2",
						Name:     "workload2",
						Domain:   "default",
						HostName: "host2",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				Filters: []api.RESTAssetsScanReportFilter{
					{
						Name:  "host_name",
						Op:    api.OPeq,
						Value: []string{"host1"},
					},
				},
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "with cursor pagination",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
				mockCache.AddWorkload("wl2", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl2",
						Name:     "workload2",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				Cursor: api.RESTScanReportCursor{
					Domain:   "default",
					HostName: "host1",
					Name:     "workload1",
				},
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "show accepted vulnerabilities",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				ShowAccepted:  true,
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "default max values",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				// MaxCveRecords and MaxAssets are 0, should use defaults
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "with view pod parameter",
			setupWorkloads: func() {
				mockCache.AddWorkload("wl1", &api.RESTWorkload{
					RESTWorkloadBrief: api.RESTWorkloadBrief{
						ID:       "wl1",
						Name:     "workload1",
						Domain:   "default",
						HostName: "host1",
					},
				})
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				ViewPod:       stringPtr(api.QueryValueViewPod),
			},
			expectedLen:   0,
			expectedError: false,
		},
		{
			name: "with LastStopAtAsset and LastStopAtCVE",
			setupWorkloads: func() {
				setupWorkloads(mockCache)
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				ViewPod:       stringPtr(api.QueryValueViewPod),
				Cursor: api.RESTScanReportCursor{
					Domain:   "default",
					HostName: "host1",
					Name:     "workload1",
					CVEName:  "vulnerability2",
				},
			},
			expectedLen:   3,
			expectedError: false,
		},
		{
			name: "with empty LastStopAtAsset and LastStopAtCVE",
			setupWorkloads: func() {
				setupWorkloads(mockCache)
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 100,
				ViewPod:       stringPtr(api.QueryValueViewPod),
				Cursor:        api.RESTScanReportCursor{},
			},
			expectedLen:   7,
			expectedError: false,
		},
		{
			name: "with low MaxCveRecords and MaxAssets",
			setupWorkloads: func() {
				setupWorkloads(mockCache)
			},
			query: &api.RESTAssetsScanReportQuery{
				MaxCveRecords: 1,
				ViewPod:       stringPtr(api.QueryValueViewPod),
				Cursor:        api.RESTScanReportCursor{},
			},
			expectedLen:   1,
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mock cache
			mockCache = NewScannerMockCache()
			tc.setupWorkloads()

			result, err := handlerAssetsScanReportInternal(mockCache, tc.query, func() []api.AssetScanReportInterface {
				workloads := mockCache.GetAllWorkloads("", acc, utils.NewSet())
				ret := make([]api.AssetScanReportInterface, len(workloads))
				for i, wl := range workloads {
					ret[i] = wl
				}
				return ret
			})

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result.ScanData)
				assert.Equal(t, tc.expectedLen, len(result.ScanData))

				if tc.validate != nil {
					tc.validate(t, result)
				}
			}
		})
	}
}

func TestFilterAndSortCVE(t *testing.T) {
	tests := []struct {
		name          string
		filter        *api.RESTVulScoreFilter
		vuls          []*api.RESTVulnerability
		expectedLen   int
		expectedOrder []string
		shouldError   bool
	}{
		{
			name:   "nil filter with vulnerabilities",
			filter: nil,
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", Score: 7.5, ScoreV3: 8.1},
				{Name: "CVE-2021-002", Score: 5.0, ScoreV3: 6.2},
			},
			expectedLen:   2,
			expectedOrder: []string{"CVE-2021-001", "CVE-2021-002"},
			shouldError:   false,
		},
		{
			name:        "empty vulnerabilities list",
			filter:      nil,
			vuls:        []*api.RESTVulnerability{},
			expectedLen: 0,
			shouldError: false,
		},
		{
			name:   "filter with version v2 - within range",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v2", ScoreBottom: 5.0, ScoreTop: 8.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", Score: 7.5},
				{Name: "CVE-2021-002", Score: 5.5},
				{Name: "CVE-2021-003", Score: 9.0},
			},
			expectedLen:   2,
			expectedOrder: []string{"CVE-2021-001", "CVE-2021-002"},
			shouldError:   false,
		},
		{
			name:   "filter with version v3 - within range",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v3", ScoreBottom: 6.0, ScoreTop: 9.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", ScoreV3: 8.1},
				{Name: "CVE-2021-002", ScoreV3: 5.5},
				{Name: "CVE-2021-003", ScoreV3: 7.2},
			},
			expectedLen:   2,
			expectedOrder: []string{"CVE-2021-001", "CVE-2021-003"},
			shouldError:   false,
		},
		{
			name:   "filter excludes all vulnerabilities",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v2", ScoreBottom: 9.0, ScoreTop: 10.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", Score: 7.5},
				{Name: "CVE-2021-002", Score: 5.0},
			},
			expectedLen: 0,
			shouldError: false,
		},
		{
			name:   "filter boundary values",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v2", ScoreBottom: 5.0, ScoreTop: 5.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", Score: 5.0},
				{Name: "CVE-2021-002", Score: 5.5},
			},
			expectedLen:   1,
			expectedOrder: []string{"CVE-2021-001"},
			shouldError:   false,
		},
		{
			name:   "vulnerabilities sorted by name",
			filter: nil,
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-003"},
				{Name: "CVE-2021-001"},
				{Name: "CVE-2021-002"},
			},
			expectedLen:   3,
			expectedOrder: []string{"CVE-2021-001", "CVE-2021-002", "CVE-2021-003"},
			shouldError:   false,
		},
		{
			name:   "single vulnerability with filter",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v2", ScoreBottom: 5.0, ScoreTop: 8.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", Score: 6.5},
			},
			expectedLen:   1,
			expectedOrder: []string{"CVE-2021-001"},
			shouldError:   false,
		},
		{
			name:   "filter v3 with zero scores",
			filter: &api.RESTVulScoreFilter{ScoreVersion: "v3", ScoreBottom: 0.0, ScoreTop: 10.0},
			vuls: []*api.RESTVulnerability{
				{Name: "CVE-2021-001", ScoreV3: 0.0},
				{Name: "CVE-2021-002", ScoreV3: 5.0},
			},
			expectedLen:   2,
			expectedOrder: []string{"CVE-2021-001", "CVE-2021-002"},
			shouldError:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := filterAndSortCVE(tc.filter, tc.vuls)

			if tc.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedLen, len(result), "expected %d vulnerabilities, got %d", tc.expectedLen, len(result))

				if len(tc.expectedOrder) > 0 {
					for i, expectedName := range tc.expectedOrder {
						assert.Equal(t, expectedName, result[i].Name, "expected vulnerability at index %d to be %s, got %s", i, expectedName, result[i].Name)
					}
				}
			}
		})
	}
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}
