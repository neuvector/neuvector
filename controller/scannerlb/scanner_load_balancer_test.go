package scannerlb

import (
	"fmt"
	"sync"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

func TestNewScannerLoadBalancer(t *testing.T) {
	lb := NewScannerLoadBalancer()
	assert.NotNil(t, lb)
	assert.Equal(t, 0, len(lb.ActiveScanners))
}

func TestRegisterScanner(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)

	assert.Equal(t, 1, len(lb.ActiveScanners))

	scannerEntry, err := lb.GetScanner(scanner.ID)
	assert.Nil(t, err)
	assert.Equal(t, 2, scannerEntry.AvailableScanCredits)
}

func TestUnregisterScanner(t *testing.T) {
	lb := NewScannerLoadBalancer()
	scanner := &share.CLUSScanner{ID: "scanner1"}

	lb.RegisterScanner(scanner, 2)
	scannerEntry, err := lb.UnregisterScanner(scanner.ID)

	assert.Nil(t, err)
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

	scannerEntry, err := lb.GetScanner(scanner.ID)
	assert.Nil(t, err)
	assert.Equal(t, 3, scannerEntry.AvailableScanCredits)
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
		{"scanner1", 1}, // scanner1 is picked → credits: (scanner1: 1, scanner2: 2, scanner3: 1)
		{"scanner2", 1}, // scanner2 is picked → credits: (scanner1: 1, scanner2: 1, scanner3: 1)
		{"scanner1", 0}, // scanner1 is picked → credits: (scanner1: 0, scanner2: 1, scanner3: 1)
		{"scanner2", 0}, // scanner2 is picked → credits: (scanner1: 0, scanner2: 0, scanner3: 1)
		{"scanner3", 0}, // scanner3 is picked → credits: (scanner1: 0, scanner2: 0, scanner3: 0)
	}

	for _, step := range expectedOrder {
		pickedScanner, err := lb.PickLeastLoadedScanner()
		assert.Nil(t, err)
		assert.NotNil(t, pickedScanner)
		assert.Equal(t, step.expectedID, pickedScanner.ID)
		scannerEntry, err := lb.GetScanner(step.expectedID)
		assert.Nil(t, err)
		assert.Equal(t, step.expectedCreditAfter, scannerEntry.AvailableScanCredits)
	}

	// Try picking when no available scanner
	pickedScanner, err := lb.PickLeastLoadedScanner()
	assert.NotNil(t, err)
	assert.Nil(t, pickedScanner)
}

func prepareScanners(numScanners int) []*share.CLUSScanner {
	scanners := make([]*share.CLUSScanner, numScanners)
	for i := 0; i < numScanners; i++ {
		scanners[i] = &share.CLUSScanner{ID: fmt.Sprintf("scanner%d", i)}
	}
	return scanners
}

func addScannersConcurrently(lb *ScannerLoadBalancer, scanners []*share.CLUSScanner, scanCredits int, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scanners))
	for _, scanner := range scanners {
		go func(s *share.CLUSScanner) {
			defer wg.Done()
			lb.RegisterScanner(s, scanCredits)
		}(scanner)
	}
	wg.Wait()
	if done != nil {
		close(done)
	}
}

func removeScannersConcurrently(t *testing.T, lb *ScannerLoadBalancer, scanners []*share.CLUSScanner, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scanners))
	for _, scanner := range scanners {
		go func(s *share.CLUSScanner) {
			defer wg.Done()
			entry, err := lb.UnregisterScanner(s.ID)
			assert.Nil(t, err)
			assert.NotNil(t, entry)
		}(scanner)
	}
	wg.Wait()
	if done != nil {
		close(done)
	}
}

func pickLeastLoadedScannerConcurrently(t *testing.T, lb *ScannerLoadBalancer, numAcquisitions int, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(numAcquisitions)
	for i := 0; i < numAcquisitions; i++ {
		go func() {
			defer wg.Done()
			pickedScanner, err := lb.PickLeastLoadedScanner()
			assert.Nil(t, err)
			assert.NotNil(t, pickedScanner)
		}()
	}
	wg.Wait()
	if done != nil {
		close(done)
	}
}

func releaseScanCreditConcurrently(t *testing.T, lb *ScannerLoadBalancer, scanners []*share.CLUSScanner, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scanners))
	for _, scanner := range scanners {
		go func(id string) {
			defer wg.Done()
			err := lb.ReleaseScanCredit(id)
			assert.Nil(t, err)
		}(scanner.ID)
	}
	wg.Wait()
	close(done)
}

func TestScannerLoadBalancerConcurrency(t *testing.T) {
	lb := NewScannerLoadBalancer()
	numScanners := 10
	scanCredits := 2

	firstBatchSize := numScanners / 2
	scanners := prepareScanners(numScanners)

	// Test register in parallel
	addScannersConcurrently(lb, scanners[:firstBatchSize], scanCredits, nil)
	assert.Equal(t, firstBatchSize, len(lb.ActiveScanners))

	// Test pick least loaded scanner in parallel
	numAcquisitions := firstBatchSize * scanCredits
	pickLeastLoadedScannerConcurrently(t, lb, numAcquisitions, nil)

	releaseDone := make(chan struct{})
	addDone := make(chan struct{})
	go releaseScanCreditConcurrently(t, lb, scanners[:firstBatchSize], releaseDone)
	go addScannersConcurrently(lb, scanners[firstBatchSize:], scanCredits, addDone)

	// Wait for both operations to complete
	<-releaseDone
	<-addDone

	removeDone := make(chan struct{})
	go removeScannersConcurrently(t, lb, scanners[:firstBatchSize], removeDone)
	<-removeDone

	// Verify that scanners status, if first batch size, should be removed, otherwise should be added
	for i, scanner := range scanners {
		scannerEntry, err := lb.GetScanner(scanner.ID)
		if i < firstBatchSize {
			assert.Nil(t, scannerEntry)
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, scanCredits, scannerEntry.AvailableScanCredits)
		}
	}

	// remove the remaining scanners
	removeScannersConcurrently(t, lb, scanners[firstBatchSize:], nil)
	assert.Equal(t, 0, len(lb.ActiveScanners))
}
