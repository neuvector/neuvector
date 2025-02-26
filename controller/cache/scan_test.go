package cache

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

// fix all of the test caases
func TestCompareScanConfig(t *testing.T) {
	enable := true
	disable := false
	testCases := []struct {
		name          string
		currentCfg    *share.CLUSScanConfig
		updateCfg     *share.CLUSScanConfig
		shouldEnable  bool
		shouldDisable bool
	}{
		{
			name: "update from fresh install",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			updateCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			shouldEnable:  true,
			shouldDisable: false,
		},
		{
			name: "update from enabled",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			shouldEnable:  false,
			shouldDisable: true,
		},
		{
			name: "disable idempotent test",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			updateCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable idempotent test",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable workload idempotent test",
			currentCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable host idempotent test",
			currentCfg: &share.CLUSScanConfig{
				EnableAutoScanHost: &enable,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanHost: &enable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "disable workload idempotent test",
			currentCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &disable,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &disable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "disable host idempotent test",
			currentCfg: &share.CLUSScanConfig{
				EnableAutoScanHost: &disable,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanHost: &disable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable workload and disable host",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
				EnableAutoScanHost:     &disable,
			},
			shouldEnable:  true,
			shouldDisable: false,
		},
		{
			name: "enable first, enable workload and disable host",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
				EnableAutoScanHost:     &disable,
			},
			shouldEnable:  false,
			shouldDisable: true,
		},
		{
			name: "enable first, disable workload and enable host",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &disable,
				EnableAutoScanHost:     &enable,
			},
			shouldEnable:  false,
			shouldDisable: true,
		},
		{
			name: "enable first, enable workload and enable host",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
				EnableAutoScanHost:     &enable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable first, enable workload",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
		{
			name: "enable first, disable workload",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: true,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &disable,
			},
			shouldEnable:  false,
			shouldDisable: true,
		},
		{
			name: "disable first, enable workload",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &enable,
			},
			shouldEnable:  true,
			shouldDisable: false,
		},
		{
			name: "disable first, disable workload",
			currentCfg: &share.CLUSScanConfig{
				AutoScan: false,
			},
			updateCfg: &share.CLUSScanConfig{
				EnableAutoScanWorkload: &disable,
			},
			shouldEnable:  false,
			shouldDisable: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldEnable, shouldDisable := CompareScanConfig(tc.currentCfg, tc.updateCfg)
			fmt.Printf("test case: %s, shouldEnable: %v, shouldDisable: %v\n", tc.name, shouldEnable, shouldDisable)
			assert.Equal(t, tc.shouldEnable, shouldEnable)
			assert.Equal(t, tc.shouldDisable, shouldDisable)
		})
	}
}
