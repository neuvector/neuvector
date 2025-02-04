package rpc

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

// initMockScannersEnv initializes a new ScanCreditManager and creates mock scanners.
func initMockScannersEnv(mockMaxConns, scannerCount int) (*ScanCreditManager, []*share.CLUSScanner, []string) {
	mockScannerMgr := NewScanCreditManager(mockMaxConns)
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

// verifyActiveScanners asserts that the activeScanners map has the expected number of scanners
// and that each scanner has the expected number of active tasks.
func verifyActiveScanners(t *testing.T, mockScannerMgr *ScanCreditManager, expectedActiveScanners, expectedScannerActiveTasks int) {
	assert.Equal(t, expectedActiveScanners, len(mockScannerMgr.activeScanners), "Number of active scanners should match")
	for _, s := range mockScannerMgr.activeScanners {
		assert.Equal(t, expectedScannerActiveTasks, s.activeScanCredits, "Active scanner tasks should match")
	}
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

	assert.NotNil(t, mockScannerMgr.activeScanners, "activeScanners map should be initialized")

	expectedCapacity := scannerChannelCapacity * mockMaxConns
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

	verifyActiveScanners(t, mockScannerMgr, mockMaxConns, 0)

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
	mockScannerMgr.mutex.Lock()
	<-mockScannerMgr.creditPool
	mockScannerMgr.activeScanners[mockScannerIDs[0]].activeScanCredits++
	mockScannerMgr.mutex.Unlock()

	// Remove the first scanner
	mockScannerMgr.RemoveScanner(mockScannerIDs[0])

	// Verify that the scanner is removed
	mockScannerMgr.mutex.RLock()
	_, exists := mockScannerMgr.activeScanners[mockScannerIDs[0]]
	mockScannerMgr.mutex.RUnlock()
	assert.False(t, exists, "Scanner should be removed from activeScanners")

	// Calculate expected remaining signals
	// Initial signals: maxConns * mockScannerCount = 3 * 3 = 9
	// Assume scanner[0] use it, then we remove the 1st scanner
	// After removing the scanner -> expected remaining = 9 - 1(scanner[0]) - 2(remaining in scanner[0]) = maxConns * (mockScannerCount - 1) = 3 * 2 = 6
	expectedRemainingSignals := (mockScannerMgr.maxConns * (mockScannerCount - 1))

	// Use len to get actual remaining signals
	actualSignals := len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")

	mockScannerMgr.RemoveScanner(mockScannerIDs[1])
	// Remove scanner[1]
	// Init signals: maxConns * (mockScannerCount-1) = 3 * 2 = 6
	// After removing the scanner -> expected remaining = maxConns * (mockScannerCount - 2) = 3 * 1 = 3
	expectedRemainingSignals = (mockScannerMgr.maxConns * (mockScannerCount - 2))

	// Use len to get actual remaining signals
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, 0)

	// Remove non exist scanner
	mockScannerMgr.RemoveScanner("not exist id")
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "creditPool should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, 0)

	// Remove all
	for _, s := range mockScanners {
		mockScannerMgr.RemoveScanner(s.ID)
	}
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, 0, actualSignals, "creditPool should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, 0, 0)
}

// TestacquireScanCredit verifies the acquireScanCredit method.
func TestacquireScanCredit(t *testing.T) {
	maxConns := 2
	mockScannerCount := 2
	scannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	for _, s := range mockScanners {
		scannerMgr.AddScanner(s)
	}

	// Initially, creditPool should have maxConns * 2 signals
	initialSignals := maxConns * mockScannerCount
	actualSignals := len(scannerMgr.creditPool)
	assert.Equal(t, initialSignals, actualSignals, "creditPool should have initial signals equal to maxConns * number of scanners")

	// Acquire a scanner
	acquiredScanner := scannerMgr.acquireScanCredit()
	assert.NotEmpty(t, acquiredScanner, "Should acquire a scanner ID")
	assert.Contains(t, mockScannerIDs, acquiredScanner, "Acquired scanner should be in mockScannerIDs")

	// Verify that activeScanCredits for the acquired scanner is incremented
	scannerMgr.mutex.RLock()
	s, exists := scannerMgr.activeScanners[acquiredScanner]
	scannerMgr.mutex.RUnlock()
	assert.True(t, exists, "Acquired scanner should exist in activeScanners")
	assert.Equal(t, 1, s.activeScanCredits, "activeScanCredits should be incremented after acquisition")

	// creditPool should have one less signal
	remainingSignals := initialSignals - 1
	actualSignals = len(scannerMgr.creditPool)
	assert.Equal(t, remainingSignals, actualSignals, "creditPool should have one less signal after acquisition")
}

// TestreleaseScanCredit verifies the releaseScanCredit method.
func TestreleaseScanCredit(t *testing.T) {
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
	scannerID1 := mockScannerMgr.acquireScanCredit()
	expectedSingals--
	assert.NotEmpty(t, scannerID1, "Should acquire scanner1")
	assert.Contains(t, mockScannerIDs, scannerID1, "Acquired scanner1 should be in mockScannerIDs")

	scannerID2 := mockScannerMgr.acquireScanCredit()
	expectedSingals--
	assert.NotEmpty(t, scannerID2, "Should acquire scanner2")
	assert.Contains(t, mockScannerIDs, scannerID2, "Acquired scanner2 should be in mockScannerIDs")

	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedSingals, actualSignals, "creditPool should have %d signals after acquiring all scanners", expectedSingals)

	// Release scanner1, expectedSingals should increase one singe we have a new one to use
	mockScannerMgr.releaseScanCredit(scannerID1)
	expectedSingals++

	// creditPool should have one signal
	actualSignals = len(mockScannerMgr.creditPool)
	assert.Equal(t, expectedSingals, actualSignals, "creditPool should have %d signals after acquiring all scanners", expectedSingals)

	// Verify that activeScanCredits for scanner1 is decremented
	mockScannerMgr.mutex.RLock()
	s1, exists1 := mockScannerMgr.activeScanners[scannerID1]
	s2, exists2 := mockScannerMgr.activeScanners[scannerID2]
	mockScannerMgr.mutex.RUnlock()
	assert.True(t, exists1, "scanner1 should exist in activeScanners")
	assert.True(t, exists2, "scanner2 should exist in activeScanners")
	assert.Equal(t, 0, s1.activeScanCredits, "activeScanCredits for scanner1 should be decremented after release")
	assert.Equal(t, 1, s2.activeScanCredits, "activeScanCredits for scanner2 should remain unchanged")
}

// TestLargeScaleScannerManagement verifies the large-scale scanner management of the scanner manager.
func TestLargeScaleScannerManagement(t *testing.T) {
	maxConns := 2
	mockScannerCount := 100
	scannerChannelCapacity = mockScannerCount // this limit the size of the channel
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	// Add all scanners
	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}

	// Verify all scanners are added
	mockScannerMgr.mutex.RLock()
	assert.Equal(t, mockScannerCount, len(mockScannerMgr.activeScanners), "All scanners should be added to activeScanners")
	mockScannerMgr.mutex.RUnlock()

	// Acquire a subset of scanners
	numAcquisitions := mockScannerCount * maxConns
	var acquiredScanners []string
	for i := 0; i < numAcquisitions; i++ {
		scannerID := mockScannerMgr.acquireScanCredit()
		assert.NotEmptyf(t, scannerID, "All scannerID should not be empty")
		acquiredScanners = append(acquiredScanners, scannerID)
	}
	assert.Equal(t, len(acquiredScanners), mockScannerCount*maxConns, "Number of acquired scanners should not exceed max capacity")

	// A goroutine attempts to acquire a scanner by calling `acquireScanCredit()` and sends the result to the `done` channel.
	// To prevent an actual timeout, release one of the previously acquired scanners to make it available for acquisition.
	// This ensures that the test can verify proper handling of blocked acquisitions and scanner availability logic.
	done := make(chan string)
	go func() {
		done <- mockScannerMgr.acquireScanCredit()
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
		scannerID := mockScannerMgr.acquireScanCredit()
		assert.NotEmpty(t, scannerID, "Should acquire a scanner ID after releasing")
	}

	// Cleanup: Remove all scanners
	for _, id := range mockScannerIDs {
		mockScannerMgr.RemoveScanner(id)
	}

	// Verify all scanners are removed
	mockScannerMgr.mutex.RLock()
	assert.Equal(t, 0, len(mockScannerMgr.activeScanners), "All scanners should be removed")
	mockScannerMgr.mutex.RUnlock()

	// creditPool should have no signals left
	actualSignals := len(mockScannerMgr.creditPool)
	assert.Equal(t, 0, actualSignals, "creditPool should have no remaining signals after all removals")
}
