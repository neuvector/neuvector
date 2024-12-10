package rpc

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

// initMockScannersEnv initializes a new ScannerManager and creates mock scanners.
func initMockScannersEnv(mockMaxConns, scannerCount int) (*ScannerManager, []*share.CLUSScanner, []string) {
	mockScannerMgr := NewScannerManager(mockMaxConns)
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
func verifyActiveScanners(t *testing.T, mockScannerMgr *ScannerManager, expectedActiveScanners, expectedScannerActiveTasks int) {
	assert.Equal(t, expectedActiveScanners, len(mockScannerMgr.activeScanners), "Number of active scanners should match")
	for _, s := range mockScannerMgr.activeScanners {
		assert.Equal(t, expectedScannerActiveTasks, s.activeScannerTasks, "Active scanner tasks should match")
	}
}

// TestNewScannerManager verifies the creation of a new scanner manager.
func TestNewScannerManager(t *testing.T) {
	mockMaxConns := 3
	mockScannerCount := 3
	mockScannerMgr, _, _ := initMockScannersEnv(mockMaxConns, mockScannerCount)
	// check the maxConns
	assert.Equal(t, mockMaxConns, mockScannerMgr.maxConns)

	// check the availableCh
	assert.Equal(t, 0, len(mockScannerMgr.availableCh))

	assert.NotNil(t, mockScannerMgr.activeScanners, "activeScanners map should be initialized")

	expectedCapacity := scannerChannelCapacity * mockMaxConns
	assert.Equal(t, expectedCapacity, cap(mockScannerMgr.availableCh), "availableCh should have correct capacity")
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

	// Verify that availableCh has maxConns * testScannerCount signals
	expectedSignals := mockScannerMgr.maxConns * len(mockScanners)
	actualSignals := len(mockScannerMgr.availableCh)

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
	<-mockScannerMgr.availableCh
	mockScannerMgr.activeScanners[mockScannerIDs[0]].activeScannerTasks++
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
	actualSignals := len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "availableCh should be drained correctly after removing a scanner")

	mockScannerMgr.RemoveScanner(mockScannerIDs[1])
	// Remove scanner[1]
	// Init signals: maxConns * (mockScannerCount-1) = 3 * 2 = 6
	// After removing the scanner -> expected remaining = maxConns * (mockScannerCount - 2) = 3 * 1 = 3
	expectedRemainingSignals = (mockScannerMgr.maxConns * (mockScannerCount - 2))

	// Use len to get actual remaining signals
	actualSignals = len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "availableCh should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, 0)

	// Remove non exist scanner
	mockScannerMgr.RemoveScanner("not exist id")
	actualSignals = len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedRemainingSignals, actualSignals, "availableCh should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, mockScannerCount-2, 0)

	// Remove all
	for _, s := range mockScanners {
		mockScannerMgr.RemoveScanner(s.ID)
	}
	actualSignals = len(mockScannerMgr.availableCh)
	assert.Equal(t, 0, actualSignals, "availableCh should be drained correctly after removing a scanner")
	verifyActiveScanners(t, mockScannerMgr, 0, 0)
}

// TestAcquireScannerAvailability verifies the acquireScannerAvailability method.
func TestAcquireScannerAvailability(t *testing.T) {
	maxConns := 2
	mockScannerCount := 2
	scannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	for _, s := range mockScanners {
		scannerMgr.AddScanner(s)
	}

	// Initially, availableCh should have maxConns * 2 signals
	initialSignals := maxConns * mockScannerCount
	actualSignals := len(scannerMgr.availableCh)
	assert.Equal(t, initialSignals, actualSignals, "availableCh should have initial signals equal to maxConns * number of scanners")

	// Acquire a scanner
	acquiredScanner := scannerMgr.acquireScannerAvailability()
	assert.NotEmpty(t, acquiredScanner, "Should acquire a scanner ID")
	assert.Contains(t, mockScannerIDs, acquiredScanner, "Acquired scanner should be in mockScannerIDs")

	// Verify that activeScannerTasks for the acquired scanner is incremented
	scannerMgr.mutex.RLock()
	s, exists := scannerMgr.activeScanners[acquiredScanner]
	scannerMgr.mutex.RUnlock()
	assert.True(t, exists, "Acquired scanner should exist in activeScanners")
	assert.Equal(t, 1, s.activeScannerTasks, "activeScannerTasks should be incremented after acquisition")

	// availableCh should have one less signal
	remainingSignals := initialSignals - 1
	actualSignals = len(scannerMgr.availableCh)
	assert.Equal(t, remainingSignals, actualSignals, "availableCh should have one less signal after acquisition")
}

// TestReleaseScannerAvailability verifies the releaseScannerAvailability method.
func TestReleaseScannerAvailability(t *testing.T) {
	maxConns := 1
	mockScannerCount := 2
	expectedSingals := mockScannerCount * maxConns
	mockScannerMgr, mockScanners, mockScannerIDs := initMockScannersEnv(maxConns, mockScannerCount)

	for _, s := range mockScanners {
		mockScannerMgr.AddScanner(s)
	}
	actualSignals := len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedSingals, actualSignals, "availableCh should have %d signals after add all scanners", expectedSingals)

	// Acquire both scanners, and it will cause a signals for each acquireScannerAvailability
	scannerID1 := mockScannerMgr.acquireScannerAvailability()
	expectedSingals--
	assert.NotEmpty(t, scannerID1, "Should acquire scanner1")
	assert.Contains(t, mockScannerIDs, scannerID1, "Acquired scanner1 should be in mockScannerIDs")

	scannerID2 := mockScannerMgr.acquireScannerAvailability()
	expectedSingals--
	assert.NotEmpty(t, scannerID2, "Should acquire scanner2")
	assert.Contains(t, mockScannerIDs, scannerID2, "Acquired scanner2 should be in mockScannerIDs")

	actualSignals = len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedSingals, actualSignals, "availableCh should have %d signals after acquiring all scanners", expectedSingals)

	// Release scanner1, expectedSingals should increase one singe we have a new one to use
	mockScannerMgr.releaseScannerAvailability(scannerID1)
	expectedSingals++

	// availableCh should have one signal
	actualSignals = len(mockScannerMgr.availableCh)
	assert.Equal(t, expectedSingals, actualSignals, "availableCh should have %d signals after acquiring all scanners", expectedSingals)

	// Verify that activeScannerTasks for scanner1 is decremented
	mockScannerMgr.mutex.RLock()
	s1, exists1 := mockScannerMgr.activeScanners[scannerID1]
	s2, exists2 := mockScannerMgr.activeScanners[scannerID2]
	mockScannerMgr.mutex.RUnlock()
	assert.True(t, exists1, "scanner1 should exist in activeScanners")
	assert.True(t, exists2, "scanner2 should exist in activeScanners")
	assert.Equal(t, 0, s1.activeScannerTasks, "activeScannerTasks for scanner1 should be decremented after release")
	assert.Equal(t, 1, s2.activeScannerTasks, "activeScannerTasks for scanner2 should remain unchanged")
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
		scannerID := mockScannerMgr.acquireScannerAvailability()
		assert.NotEmptyf(t, scannerID, "All scannerID should not be empty")
		acquiredScanners = append(acquiredScanners, scannerID)
	}
	assert.Equal(t, len(acquiredScanners), mockScannerCount*maxConns, "Number of acquired scanners should not exceed max capacity")

	// A goroutine attempts to acquire a scanner by calling `acquireScannerAvailability()` and sends the result to the `done` channel.
	// To prevent an actual timeout, release one of the previously acquired scanners to make it available for acquisition.
	// This ensures that the test can verify proper handling of blocked acquisitions and scanner availability logic.
	done := make(chan string)
	go func() {
		done <- mockScannerMgr.acquireScannerAvailability()
	}()

	// Release a scanner to unblock the acquisition process.
	mockScannerMgr.releaseScannerAvailability(acquiredScanners[0])

	releasedScannerID := <-done
	assert.Equal(t, releasedScannerID, acquiredScanners[0], "Should return empty string on timeout when no scanners are available")

	// Release all acquired scanners
	for _, id := range acquiredScanners {
		mockScannerMgr.releaseScannerAvailability(id)
	}

	// Now, all scanners should be available again
	for i := 0; i < len(acquiredScanners); i++ {
		scannerID := mockScannerMgr.acquireScannerAvailability()
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

	// availableCh should have no signals left
	actualSignals := len(mockScannerMgr.availableCh)
	assert.Equal(t, 0, actualSignals, "availableCh should have no remaining signals after all removals")
}
