package rpc

import (
	"fmt"
	"sync"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

// initMockScannersEnv initializes a new ScanCreditManager and creates mock scanners.
func initMockScannersEnv(mockMaxConns, scannerCount int) (*ScanCreditManager, []*share.CLUSScanner, []string) {
	mockScannerMgr := NewScanCreditManager(mockMaxConns, scannerCount)
	var mockScanners []*share.CLUSScanner
	var mockScannerIDs []string
	for i := 0; i < scannerCount; i++ {
		mockScanners = append(mockScanners, newMockScanner(i))
		mockScannerIDs = append(mockScannerIDs, getMockScannerID(i))
	}
	return mockScannerMgr, mockScanners, mockScannerIDs
}

func getMockScannerID(i int) string {
	return fmt.Sprintf("mock-scanner-%d", i)
}

func newMockScanner(i int) *share.CLUSScanner {
	return &share.CLUSScanner{
		ID: getMockScannerID(i),
	}
}

// verifyActiveScanners
// asserts the activeScanners map has the expected number of scanners
// and that the total number of active scan credits is the expected number
func verifyActiveScanners(t *testing.T, mockScannerMgr *ScanCreditManager, expectedActiveScanners, expectedavailableScanCredits int) {
	assert.Equal(t, expectedActiveScanners, len(mockScannerMgr.scannerLoadBalancer.GetActiveScanners()), "Number of active scanners should match")

	actualavailableScanCredits := 0
	for _, s := range mockScannerMgr.scannerLoadBalancer.GetActiveScanners() {
		actualavailableScanCredits += s.AvailableScanCredits
	}
	assert.Equal(t, expectedavailableScanCredits, actualavailableScanCredits, "Active scanner credits should match")
}

// TestNewScanCreditManager verifies the creation of a new scanner manager.
func TestNewScanCreditManager(t *testing.T) {
	mockMaxConns := 3
	mockScannerCount := 3
	mockScannerMgr, _, _ := initMockScannersEnv(mockMaxConns, mockScannerCount)
	// check the maxConns
	assert.Equal(t, mockMaxConns, mockScannerMgr.maxConns)

	// check the creditPool
	assert.Equal(t, 0, len(mockScannerMgr.creditPool))

	assert.NotNil(t, mockScannerMgr.scannerLoadBalancer.ActiveScanners, "activeScanners map should be initialized")

	expectedCapacity := mockScannerCount * (mockMaxConns + 1)
	assert.Equal(t, expectedCapacity, cap(mockScannerMgr.creditPool), "creditPool should have correct capacity")
}

// TestAddScanner verifies the AddScanner method of the scanner manager.
func TestAddScanner(t *testing.T) {
	mockMaxConns := 3
	mockScannerCount := 3
	mockScannerMgr, mockScanners, _ := initMockScannersEnv(mockMaxConns, mockScannerCount)
	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}

	verifyActiveScanners(t, mockScannerMgr, mockScannerCount, mockMaxConns*mockScannerCount)

	// Verify that creditPool has maxConns * testScannerCount signals
	expectedSignals := mockScannerMgr.maxConns * len(mockScanners)
	actualSignals := len(mockScannerMgr.creditPool)

	assert.Equal(t, expectedSignals, actualSignals)
}

// TestRemoveScanner verifies the RemoveScanner method of the scanner manager.
func TestRemoveScanner(t *testing.T) {
	mockMaxConns := 3
	mockScannerCount := 3
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(mockMaxConns, mockScannerCount)

	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}

	// Simulate the assignment of the first scanner (scanner[0]) to handle a scan task.
	<-mockScannerMgr.creditPool
	mockScannerMgr.scannerLoadBalancer.ActiveScanners[0].AvailableScanCredits--

	// Remove the first scanner
	err := mockScannerMgr.RemoveScanner(mockScannerIDs[0])
	assert.Nil(t, err)

	// Verify that the scanner is removed
	scannerEntry, err := mockScannerMgr.scannerLoadBalancer.GetScanner(mockScannerIDs[0])
	assert.NotNil(t, err)
	assert.Nil(t, scannerEntry)

	// Calculate expected remaining signals
	// Initial signals: maxConns * mockScannerCount = 3 * 3 = 9
	// Assume scanner[0] use it, then we remove the 1st scanner
	// After removing the scanner -> expected remaining = 9 - 1(scanner[0]) - 2(remaining in scanner[0]) = maxConns * (mockScannerCount - 1) = 3 * 2 = 6
	expectedRemainingSignals := (mockScannerMgr.maxConns * (mockScannerCount - 1))

	// Use len to get actual remaining signals
	actualSignals := len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")

	err = mockScannerMgr.RemoveScanner(mockScannerIDs[1])
	assert.Nil(t, err)
	// Remove scanner[1]
	// Init signals: maxConns * (mockScannerCount-1) = 3 * 2 = 6
	// After removing the scanner -> expected remaining = maxConns * (mockScannerCount - 2) = 3 * 1 = 3
	expectedRemainingSignals = (mockScannerMgr.maxConns * (mockScannerCount - 2))

	// Use len to get actual remaining signals
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, expectedRemainingSignals)

	// Remove non exist scanner
	err = mockScannerMgr.RemoveScanner("not exist id")
	assert.NotNil(t, err)
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")
	assert.Equal(t, mockScannerCount-2, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners value in consistent")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, expectedRemainingSignals)

	// Remove the last scanner
	for i := 0; i < mockScannerCount; i++ {
		err := mockScannerMgr.RemoveScanner(mockScannerIDs[i])
		// invariant: remove the first two scanners should be fail
		if i > 1 {
			assert.Nil(t, err)
		} else {
			// invariant: remove the first two scanners should be fail, since we remove the scanner before
			assert.NotNil(t, err)
			actualSignals = len(mockScannerMgr.creditPool)
			assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")
			assert.Equal(t, mockScannerCount-2, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners value in consistent")
			verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, expectedRemainingSignals)
		}
	}
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, 0, actualSignals, "creditPool should be drained correctly after removing a scanner")
	assert.Equal(t, 0, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners should be empty")
	verifyActiveScanners(t, mockScannerMgr, 0, 0)
}

// TestAcquireScanCredit verifies the acquireScanCredit method.
func TestAcquireScanCredit(t *testing.T) {
	maxConns := 2
	mockScannerCount := 2
	scannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	for _, s := range mockScanners {
		scannerMgr.AddScanner(s)
	}

	// Initially, creditPool should have maxConns * mockScannerCount signals
	initialSignals := maxConns * mockScannerCount
	actualSignals := len(scannerMgr.creditPool)
	assert.Equal(t, initialSignals, actualSignals, "creditPool should have initial signals equal to maxConns * number of scanners")

	// Acquire a scanner
	acquiredScanner, err := scannerMgr.acquireScanCredit()
	assert.NoError(t, err, "Should acquire a scanner ID")
	assert.NotEmpty(t, acquiredScanner, "Should acquire a scanner ID")
	assert.Contains(t, mockScannerIDs, acquiredScanner, "Acquired scanner should be in mockScannerIDs")

	// Verify that availableScanCredits for the acquired scanner is incremented
	scannerEntry, err := scannerMgr.scannerLoadBalancer.GetScanner(acquiredScanner)
	assert.Nil(t, err)
	assert.Equal(t, maxConns-1, scannerEntry.AvailableScanCredits, "availableScanCredits should be incremented after acquisition")

	// creditPool should have one less signal
	remainingSignals := initialSignals - 1
	actualSignals = len(scannerMgr.creditPool)
	assert.Equal(t, remainingSignals, actualSignals, "creditPool should have one less signal after acquisition")

	// release the scanner
	scannerMgr.releaseScanCredit(acquiredScanner)
	actualSignals = len(scannerMgr.creditPool)
	assert.Equal(t, initialSignals, actualSignals, "creditPool should have one less signal after acquisition")
}

// TestReleaseScanCredit verifies the releaseScanCredit method.
func TestReleaseScanCredit(t *testing.T) {
	maxConns := 1
	mockScannerCount := 2
	expectedSingals := mockScannerCount * maxConns
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}
	actualSignals := len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedSingals, actualSignals, "creditPool should have %d signals after add all scanners", expectedSingals)

	// Acquire both scanners, and it will cause a signals for each acquireScanCredit
	scannerID1, err := mockScannerMgr.acquireScanCredit()
	expectedSingals--
	assert.NoError(t, err, "Should acquire scanner1")
	assert.NotEmpty(t, scannerID1, "Should acquire scanner1")
	assert.Contains(t, mockScannerIDs, scannerID1, "Acquired scanner1 should be in mockScannerIDs")

	scannerID2, err := mockScannerMgr.acquireScanCredit()
	expectedSingals--
	assert.NoError(t, err, "Should acquire scanner2")
	assert.NotEmpty(t, scannerID2, "Should acquire scanner2")
	assert.Contains(t, mockScannerIDs, scannerID2, "Acquired scanner2 should be in mockScannerIDs")

	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedSingals, actualSignals, "creditPool should have %d signals after acquiring all scanners", expectedSingals)

	mockScanner1, err := mockScannerMgr.scannerLoadBalancer.GetScanner(scannerID1)
	assert.Nil(t, err)
	mockScanner2, err := mockScannerMgr.scannerLoadBalancer.GetScanner(scannerID2)
	assert.Nil(t, err)
	assert.Equal(t, maxConns-1, mockScanner1.AvailableScanCredits, "Acquired scanner1 should exist in activeScanners")
	assert.Equal(t, maxConns-1, mockScanner2.AvailableScanCredits, "Acquired scanner2 should exist in activeScanners")

	// Release scanner1, expectedSingals should increase one singe we have a new one to use
	mockScannerMgr.releaseScanCredit(scannerID1)
	expectedSingals++

	// creditPool should have one signal
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedSingals, actualSignals, "creditPool should have %d signals after acquiring all scanners", expectedSingals)

	// Verify that availableScanCredits for scanner1 is decremented
	mockScanner1, err = mockScannerMgr.scannerLoadBalancer.GetScanner(scannerID1)
	assert.Nil(t, err)
	mockScanner2, err = mockScannerMgr.scannerLoadBalancer.GetScanner(scannerID2)
	assert.Nil(t, err)
	assert.Equal(t, maxConns, mockScanner1.AvailableScanCredits, "availableScanCredits for scanner1 should be decremented after release")
	assert.Equal(t, maxConns-1, mockScanner2.AvailableScanCredits, "availableScanCredits for scanner2 should remain unchanged")
}

// TestLargeScaleScannerManagement verifies the large-scale scanner management of the scanner manager.
func TestLargeScaleScannerManagement(t *testing.T) {
	maxConns := 2
	mockScannerCount := 100
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	// Add all scanners
	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}

	// Verify all scanners are added
	mockScannerMgr.mutex.RLock()
	assert.Equal(t, mockScannerCount, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "All scanners should be added to activeScanners")
	mockScannerMgr.mutex.RUnlock()

	// Acquire a subset of scanners
	numAcquisitions := mockScannerCount * maxConns
	var acquiredScanners []string
	for i := 0; i < numAcquisitions; i++ {
		scannerID, err := mockScannerMgr.acquireScanCredit()
		assert.NoError(t, err, "Should acquire a scanner ID")
		assert.NotEmpty(t, scannerID, "Should acquire a scanner ID")
		acquiredScanners = append(acquiredScanners, scannerID)
	}
	assert.Equal(t, len(acquiredScanners), mockScannerCount*maxConns, "Number of acquired scanners should not exceed max capacity")

	// A goroutine attempts to acquire a scanner by calling `acquireScanCredit()` and sends the result to the `done` channel.
	// To prevent an actual timeout, release one of the previously acquired scanners to make it available for acquisition.
	// This ensures that the test can verify proper handling of blocked acquisitions and scanner availability logic.
	done := make(chan string)
	go func() {
		scannerID, err := mockScannerMgr.acquireScanCredit()
		assert.NoError(t, err, "Should acquire a scanner ID")
		done <- scannerID
	}()

	// Release a scanner to unblock the acquisition process.
	mockScannerMgr.releaseScanCredit(acquiredScanners[0])

	releasedScannerID := <-done
	assert.Equal(t, releasedScannerID, acquiredScanners[0], "Should return empty string on timeout when no scanners are available")

	// Release all acquired scanners
	for _, id := range acquiredScanners {
		mockScannerMgr.releaseScanCredit(id)
	}

	// Now, all scanners should be available again
	for i := 0; i < len(acquiredScanners); i++ {
		scannerID, err := mockScannerMgr.acquireScanCredit()
		assert.NoError(t, err, "Should acquire a scanner ID after releasing")
		assert.NotEmpty(t, scannerID, "Should acquire a scanner ID after releasing")
	}

	// Cleanup: Remove all scanners
	for _, id := range mockScannerIDs {
		err := mockScannerMgr.RemoveScanner(id)
		assert.Nil(t, err)
	}

	// Verify all scanners are removed
	mockScannerMgr.mutex.RLock()
	assert.Equal(t, 0, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "All scanners should be removed")
	mockScannerMgr.mutex.RUnlock()

	// creditPool should have no signals left
	actualSignals := len(mockScannerMgr.creditPool)
	assert.Equal(t, 0, actualSignals, "creditPool should have no remaining signals after all removals")
}

func addScannersConcurrently(mgr *ScanCreditManager, scanners []*share.CLUSScanner, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scanners))

	for _, scanner := range scanners {
		go func(s *share.CLUSScanner) {
			defer wg.Done()
			mgr.AddScanner(s)
		}(scanner)
	}
	wg.Wait()
	if done != nil {
		close(done)
	}
}

func acquireScannersConcurrently(t *testing.T, mgr *ScanCreditManager, count int) []string {
	acquiredScanners := make(chan string, count)
	var wg sync.WaitGroup
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			scannerID, err := mgr.acquireScanCredit()
			assert.NoError(t, err, "Should acquire a scanner ID")
			assert.NotEmpty(t, scannerID, "Acquired scanner ID should not be empty")
			acquiredScanners <- scannerID
		}()
	}

	wg.Wait()
	close(acquiredScanners)

	var result []string
	for scannerID := range acquiredScanners {
		result = append(result, scannerID)
	}
	return result
}

func releaseScannersConcurrently(mgr *ScanCreditManager, scanners []string, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scanners))

	for _, scannerID := range scanners {
		go func(id string) {
			defer wg.Done()
			mgr.releaseScanCredit(id)
		}(scannerID)
	}

	wg.Wait()
	close(done)
}

func removeScannersConcurrently(t *testing.T, mgr *ScanCreditManager, scannerIDs []string, done chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(len(scannerIDs))

	for _, id := range scannerIDs {
		go func(scannerID string) {
			defer wg.Done()
			err := mgr.RemoveScanner(scannerID)
			assert.Nil(t, err)
		}(id)
	}

	wg.Wait()
	if done != nil {
		close(done)
	}
}

// TestConcurrentScannerManagement verifies concurrent scanner management.
// It:
// 1. Adds scanners concurrently.
// 2. Acquires, releases, and removes scanners concurrently.
// 3. Ensures all scanners are correctly removed after operations.
func TestConcurrentScannerManagement(t *testing.T) {
	maxConns := 2
	mockScannerCount := 100
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	firstBatchSize := mockScannerCount / 2

	addScannersConcurrently(mockScannerMgr, mockScanners[:firstBatchSize], nil)
	verifyActiveScanners(t, mockScannerMgr, firstBatchSize, firstBatchSize*maxConns)

	numAcquisitions := firstBatchSize * maxConns
	acquiredScanners := acquireScannersConcurrently(t, mockScannerMgr, numAcquisitions)

	// Verify that all scanners are fully utilized
	assert.Equal(t, numAcquisitions, len(acquiredScanners), "Number of acquired scanners should not exceed max capacity")
	assert.Equal(t, firstBatchSize, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners aize should be equal to firstBatchSize after full acquisition")
	for scannerID := range mockScannerMgr.scannerLoadBalancer.ActiveScanners {
		assert.Equal(t, 0, mockScannerMgr.scannerLoadBalancer.ActiveScanners[scannerID].AvailableScanCredits, "All scanners should have zero available credits")
	}

	releaseDone := make(chan struct{})
	addDone := make(chan struct{})
	go releaseScannersConcurrently(mockScannerMgr, acquiredScanners, releaseDone)
	go addScannersConcurrently(mockScannerMgr, mockScanners[firstBatchSize:], addDone)

	// Wait for both operations to complete
	<-releaseDone
	<-addDone

	removeDone := make(chan struct{})
	go removeScannersConcurrently(t, mockScannerMgr, mockScannerIDs[:firstBatchSize], removeDone)
	<-removeDone

	// Verify that the heap contains all scanners (since we added while releasing)
	verifyActiveScanners(t, mockScannerMgr, firstBatchSize, maxConns*firstBatchSize)
	assert.Equal(t, firstBatchSize, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners should contain all newly added scanners")
	for scannerID := range mockScannerMgr.scannerLoadBalancer.ActiveScanners {
		assert.Equal(t, maxConns, mockScannerMgr.scannerLoadBalancer.ActiveScanners[scannerID].AvailableScanCredits, "Newly added scanners should have max available credits")
	}

	// remove the remaining scanners
	removeScannersConcurrently(t, mockScannerMgr, mockScannerIDs[firstBatchSize:], nil)
	// Verify all scanners are removed
	verifyActiveScanners(t, mockScannerMgr, 0, 0)

	// Ensure no remaining signals in the credit pool
	assert.Equal(t, 0, len(mockScannerMgr.creditPool), "creditPool should have no remaining signals after all removals")
	assert.Equal(t, 0, len(mockScannerMgr.scannerLoadBalancer.ActiveScanners), "activeScanners map should be empty after all removals")
}
