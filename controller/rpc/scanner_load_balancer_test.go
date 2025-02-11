package rpc

import (
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

func TestNewScannerLoadBalancer(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	assert.NotNil(t, mgr)
	assert.Equal(t, 0, mgr.heap.Len())
	assert.Equal(t, 0, len(mgr.activeScanners))
}

func TestRegisterScanner(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	mgr.RegisterScanner(scanner, 2)

	assert.Equal(t, 1, mgr.heap.Len())
	assert.Equal(t, 1, len(mgr.activeScanners))
	assert.Equal(t, 2, mgr.activeScanners["scanner1"].availableScanCredits)
}

func TestUnregisterScanner(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	mgr.RegisterScanner(scanner, 2)
	scannerEntry, err := mgr.UnregisterScanner(scanner.ID)

	assert.Nil(t, err)
	assert.Equal(t, 0, mgr.heap.Len())
	assert.Equal(t, 0, len(mgr.activeScanners))
	assert.Equal(t, scanner, scannerEntry.scanner)

	// Try removing again (should fail)
	scannerEntry, err = mgr.UnregisterScanner(scanner.ID)
	assert.Nil(t, scannerEntry)
	assert.NotNil(t, err)
}

func TestLoadBalancerReleaseScanCredit(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	mgr.RegisterScanner(scanner, 2)
	err := mgr.ReleaseScanCredit(scanner.ID)
	assert.Nil(t, err)

	assert.Equal(t, 3, mgr.activeScanners["scanner1"].availableScanCredits)
}

func TestLoadBalancerAcquireScanCredit(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	mgr.RegisterScanner(scanner, 2)
	err := mgr.AcquireScanCredit(scanner.ID)
	assert.Nil(t, err)

	assert.Equal(t, 1, mgr.activeScanners["scanner1"].availableScanCredits)

	// Try decreasing below zero (should fail)
	err = mgr.AcquireScanCredit(scanner.ID)
	assert.Nil(t, err)

	err = mgr.AcquireScanCredit(scanner.ID) // Now at -1
	assert.NotNil(t, err)

	// Try decreasing again (when no scanner)
	err = mgr.AcquireScanCredit("scanner2")
	assert.NotNil(t, err)

	// Try decreasing again (when no scanner)
	mgr.RegisterScanner(scanner, 2)
	scannerEntry, err := mgr.UnregisterScanner(scanner.ID)
	assert.Nil(t, err)
	assert.NotNil(t, scannerEntry)

	err = mgr.AcquireScanCredit(scanner.ID)
	assert.NotNil(t, err)
}

func TestPickLeastLoadedScanner(t *testing.T) {
	mgr := NewScannerLoadBalancer()
	scanner1 := &share.CLUSScanner{ID: "scanner1"}
	scanner2 := &share.CLUSScanner{ID: "scanner2"}
	scanner3 := &share.CLUSScanner{ID: "scanner3"}

	mgr.RegisterScanner(scanner1, 2)
	mgr.RegisterScanner(scanner2, 2) // Scanner2 should be picked first
	mgr.RegisterScanner(scanner3, 1)

	expectedOrder := []struct {
		expectedID          string
		expectedCreditAfter int
	}{
		{"scanner2", 1}, // scanner2 is picked → credits: (scanner1: 2, scanner2: 1, scanner3: 1)
		{"scanner1", 1}, // scanner1 is picked → credits: (scanner1: 1, scanner2: 1, scanner3: 1)
		{"scanner3", 0}, // scanner3 is picked → credits: (scanner1: 1, scanner2: 1, scanner3: 0) *REMOVED*
		{"scanner2", 0}, // scanner2 is picked → credits: (scanner1: 1, scanner2: 0, scanner3: 0) *REMOVED*
		{"scanner1", 0}, // scanner1 is picked → credits: (scanner1: 0, scanner2: 0, scanner3: 0) *REMOVED*
	}

	for _, step := range expectedOrder {
		pickedScanner, err := mgr.PickLeastLoadedScanner()
		assert.Nil(t, err)
		assert.Equal(t, step.expectedID, pickedScanner.ID)
		assert.Equal(t, step.expectedCreditAfter, mgr.activeScanners[step.expectedID].availableScanCredits)
	}
}
