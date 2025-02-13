package scannerlb

import (
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

func TestNewScannerLoadBalancer(t *testing.T) {
	lb := NewScannerLoadBalancer()
	assert.NotNil(t, lb)
	assert.Equal(t, 0, lb.Heap.Len())
	assert.Equal(t, 0, len(lb.ActiveScanners))
}

func TestRegisterScanner(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)

	assert.Equal(t, 1, lb.Heap.Len())
	assert.Equal(t, 1, len(lb.ActiveScanners))
	assert.Equal(t, 2, lb.ActiveScanners["scanner1"].AvailableScanCredits)
}

func TestUnregisterScanner(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)
	scannerEntry, err := lb.UnregisterScanner(scanner.ID)

	assert.Nil(t, err)
	assert.Equal(t, 0, lb.Heap.Len())
	assert.Equal(t, 0, len(lb.ActiveScanners))
	assert.Equal(t, scanner, scannerEntry.Scanner)

	// Try removing again (should fail)
	scannerEntry, err = lb.UnregisterScanner(scanner.ID)
	assert.Nil(t, scannerEntry)
	assert.NotNil(t, err)
}

func TestLoadBalancerReleaseScanCredit(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)
	err := lb.ReleaseScanCredit(scanner.ID)
	assert.Nil(t, err)

	assert.Equal(t, 3, lb.ActiveScanners["scanner1"].AvailableScanCredits)
}

func TestLoadBalancerAcquireScanCredit(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)
	err := lb.acquireScanCredit(scanner.ID)
	assert.Nil(t, err)

	assert.Equal(t, 1, lb.ActiveScanners["scanner1"].AvailableScanCredits)

	// Try decreasing below zero (should fail)
	err = lb.acquireScanCredit(scanner.ID)
	assert.Nil(t, err)

	err = lb.acquireScanCredit(scanner.ID) // Now at -1
	assert.NotNil(t, err)

	// Try decreasing again (when no scanner)
	err = lb.acquireScanCredit("scanner2")
	assert.NotNil(t, err)

	// Try decreasing again (when no scanner)
	lb.RegisterScanner(scanner, 2)
	scannerEntry, err := lb.UnregisterScanner(scanner.ID)
	assert.Nil(t, err)
	assert.NotNil(t, scannerEntry)

	err = lb.acquireScanCredit(scanner.ID)
	assert.NotNil(t, err)
}

func TestPickLeastLoadedScanner(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner1 := &share.CLUSScanner{ID: "scanner1"}
	scanner2 := &share.CLUSScanner{ID: "scanner2"}
	scanner3 := &share.CLUSScanner{ID: "scanner3"}

	lb.RegisterScanner(scanner1, 2)
	lb.RegisterScanner(scanner2, 2) // Scanner2 should be picked first
	lb.RegisterScanner(scanner3, 1)

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
		pickedScanner, err := lb.PickLeastLoadedScanner()
		assert.Nil(t, err)
		assert.Equal(t, step.expectedID, pickedScanner.ID)
		assert.Equal(t, step.expectedCreditAfter, lb.ActiveScanners[step.expectedID].AvailableScanCredits)
	}
}
