package rpc

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions for creating mock scanners
func getMockScannerID(i int) string {
	return fmt.Sprintf("mock-scanner-%d", i)
}

func newMockScanner(i int, maxConns int) *share.CLUSScanner {
	return &share.CLUSScanner{
		ID:                           getMockScannerID(i),
		MaxConcurrentScansPerScanner: maxConns,
		ScanCredit:                   maxConns,
		RPCServer:                    "localhost",
		RPCServerPort:                18402,
	}
}

// setupTestManager creates a new ScanCreditManager with MockCluster for testing
func setupTestManager(maxConns, maxExpectedScanners int) (*ScanCreditManager, *kv.MockCluster) {
	mgr := NewScanCreditManager(maxConns, maxExpectedScanners)
	mockHelper := &kv.MockCluster{}
	mockHelper.Init(nil, nil)
	mgr.clusterHelper = mockHelper
	mgr.SetScannerHealthChecker(nil) // Disable health check for most tests
	return mgr, mockHelper
}

// TestNewScanCreditManager verifies basic initialization
func TestNewScanCreditManager(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10

	mgr := NewScanCreditManager(maxConns, maxExpectedScanners)

	assert.NotNil(t, mgr, "ScanCreditManager should be created")
	assert.Equal(t, maxConns, mgr.maxConcurrentScansPerScanner, "maxConcurrentScansPerScanner should match")
	assert.NotNil(t, mgr.creditPool, "creditPool should be initialized")
	assert.Equal(t, maxExpectedScanners*(maxConns+1), cap(mgr.creditPool), "creditPool capacity should be correct")
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty initially")
	assert.NotNil(t, mgr.scannerHealthChecker, "scannerHealthChecker should be initialized")
}

// TestGetMaxConcurrentScansPerScanner verifies the getter method
func TestGetMaxConcurrentScansPerScanner(t *testing.T) {
	maxConns := 5
	maxExpectedScanners := 10
	mgr := NewScanCreditManager(maxConns, maxExpectedScanners)

	assert.Equal(t, maxConns, mgr.GetMaxConcurrentScansPerScanner(), "GetMaxConcurrentScansPerScanner should return correct value")
}

// TestAddScanner verifies that adding a scanner properly initializes credits
func TestAddScanner(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)

	// Initially, creditPool should be empty
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty initially")

	// Add scanner - this should add maxConns signals to creditPool
	mgr.AddScanner(scanner)

	// Verify creditPool has correct number of signals
	assert.Equal(t, maxConns, len(mgr.creditPool), "creditPool should have maxConns signals after adding scanner")
}

// TestRemoveScanner verifies scanner removal and credit draining
func TestRemoveScanner(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Verify initial state: creditPool should have maxConns tokens
	assert.Equal(t, maxConns, len(mgr.creditPool), "creditPool should have maxConns credits initially")

	err := mgr.RemoveScanner(scanner.ID)
	assert.NoError(t, err, "RemoveScanner should succeed")
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be drained correctly")
}

// TestAddMultipleScanners verifies adding multiple scanners
func TestAddRemoveMultipleScanners(t *testing.T) {
	maxConns := 2
	scannerCount := 3
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	// Add multiple scanners
	var wg sync.WaitGroup
	wg.Add(scannerCount)
	for i := 0; i < scannerCount; i++ {
		go func(i int) {
			defer wg.Done()
			scanner := newMockScanner(i, maxConns)
			mockHelper.AddScanner(scanner)
			mgr.AddScanner(scanner)
		}(i)
	}
	wg.Wait()

	// Verify total credits
	expectedCredits := maxConns * scannerCount
	assert.Equal(t, expectedCredits, len(mgr.creditPool), "creditPool should have credits from all scanners")

	// Remove all scanners

	scannerCount -= 1
	// Update expected credits, assume remain 1 scanner
	expectedCredits -= maxConns * scannerCount
	wg.Add(scannerCount)
	for i := 0; i < scannerCount; i++ {
		go func(i int) {
			defer wg.Done()
			scanner := newMockScanner(i, maxConns)
			err := mgr.RemoveScanner(scanner.ID)
			assert.NoError(t, err, "RemoveScanner should succeed")
		}(i)
	}
	wg.Wait()
	assert.Equal(t, expectedCredits, len(mgr.creditPool), "creditPool should have credits from remaining scanners")
}

// TestRemoveScannerWithPartialUtilization verifies removing a partially utilized scanner
func TestRemoveScannerWithPartialUtilization(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10
	numScanners := 3
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	// Create two scanners
	var wg sync.WaitGroup
	wg.Add(numScanners)
	for i := 0; i < numScanners; i++ {
		go func(i int) {
			defer wg.Done()
			scanner := newMockScanner(i, maxConns)
			mockHelper.AddScanner(scanner)
			mgr.AddScanner(scanner)
		}(i)
	}
	wg.Wait()

	expectedCredits := maxConns * numScanners
	// Expected credits is maxConns * numScanners = 9
	assert.Equal(t, expectedCredits, len(mgr.creditPool), "Initial creditPool should have credits from both scanners")

	usedCredits := maxConns
	expectedCredits -= usedCredits
	wg.Add(usedCredits)
	for i := 0; i < usedCredits; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := mgr.acquireScanCredit()
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
	// Expected credits is maxConns * numScanners - usedCredits = 9 - 3 = 6
	assert.Equal(t, expectedCredits, len(mgr.creditPool), "creditPool should have credits from remaining scanners")

	// Remaining credits for all of the scanners are the same, so remove of any scanner will decrease the creditPool by maxConns - 1
	for _, scanner := range mgr.getAllAvailableScanners() {
		assert.Equal(t, maxConns-1, scanner.ScanCredit, "Scanner should have expected credits")
	}

	// Remove the first scanner
	remainingCredits := expectedCredits - (maxConns - 1)
	err := mgr.RemoveScanner(newMockScanner(0, maxConns).ID)
	assert.NoError(t, err, "RemoveScanner should succeed")
	assert.Equal(t, remainingCredits, len(mgr.creditPool), "creditPool should not change after removing any scanner")
}

// TestRemoveScannerFullyUtilized verifies removing a fully utilized scanner
func TestRemoveScannerFullyUtilized(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Simulate scanner fully utilized (all tasks assigned)
	scanner.ScanCredit = maxConns

	// Manually drain all tokens from creditPool to reflect full utilization
	var wg sync.WaitGroup
	for i := 0; i < maxConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mgr.acquireScanCredit()
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty when scanner is fully utilized")

	// Remove scanner
	// Available slots = maxConns - ScanCredit = 3 - 3 = 0
	// RemoveScanner should not drain any tokens (no available slots)
	err := mgr.RemoveScanner(scanner.ID)
	assert.NoError(t, err, "RemoveScanner should succeed")

	// creditPool should remain at 0 since scanner had no available slots
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should remain empty after removing fully utilized scanner")
}

// TestPickLeastLoadedScanner verifies that the least loaded scanner is selected
func TestPickLeastLoadedScanner(t *testing.T) {
	maxConns := 5
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	for _, testCase := range []struct {
		scannerID  int
		scanCredit int
	}{
		{1, 3},
		{2, 2},
		{3, 1},
	} {
		scanner := newMockScanner(testCase.scannerID, testCase.scanCredit)
		mockHelper.AddScanner(scanner)
		mgr.AddScanner(scanner)
	}

	LeastLoadedScannerID := 1
	// Acquire should pick scanne1 (least loaded, i.e., lowest ScanCredit)
	scannerID, err := mgr.acquireScanCredit()
	require.NoError(t, err)
	assert.Equal(t, getMockScannerID(LeastLoadedScannerID), scannerID, "Should pick the least loaded scanner (lowest ScanCredit)")

	// Verify picked scanner's credit was decremented (now has 2 tasks)
	pickedScanner, _, err := mockHelper.GetScannerRev(scannerID)
	require.NoError(t, err)
	assert.Equal(t, 2, pickedScanner.ScanCredit, "Picked scanner's credit should be incremented")

	// Release
	err = mgr.releaseScanCredit(scannerID)
	require.NoError(t, err)

	// Verify credit was decremented back to 1
	releasedScanner, _, err := mockHelper.GetScannerRev(scannerID)
	require.NoError(t, err)
	assert.Equal(t, 3, releasedScanner.ScanCredit, "Released scanner's credit should be decremented back")
}

// TestConcurrentAcquireAndRelease verifies concurrent operations work correctly
func TestConcurrentAcquireAndRelease(t *testing.T) {
	maxConns := 2
	scannerCount := 5
	maxExpectedScanners := 100
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	// Add scanners
	for i := 0; i < scannerCount; i++ {
		scanner := newMockScanner(i, maxConns)
		mockHelper.AddScanner(scanner)
		mgr.AddScanner(scanner)
	}

	totalCapacity := maxConns * scannerCount
	assert.Equal(t, totalCapacity, len(mgr.creditPool), "creditPool should have correct capacity")

	// Concurrently acquire all available credits
	var wg sync.WaitGroup

	for i := 0; i < totalCapacity; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scannerID, err := mgr.acquireScanCredit()
			require.NoError(t, err)
			require.NotEmpty(t, scannerID)
		}(i)
	}

	wg.Wait()
	// creditPool should be empty now
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty after acquiring all")

	// Concurrently release all credits
	for i := 0; i < scannerCount; i++ {
		for j := 0; j < maxConns; j++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				err := mgr.releaseScanCredit(getMockScannerID(i))
				require.NoError(t, err)
			}(i)
		}
	}

	wg.Wait()

	// creditPool should be restored
	assert.Equal(t, totalCapacity, len(mgr.creditPool), "creditPool should be restored after releasing all")
}

// TestAcquireScanCreditBlocking verifies blocking and unblocking behavior
func TestAcquireScanCreditBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blocking test in short mode")
	}

	maxConns := 1
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Acquire the only available credit
	scannerID, err := mgr.acquireScanCredit()
	require.NoError(t, err)
	require.NotEmpty(t, scannerID)

	// Verify creditPool is now empty
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty after acquiring the only credit")

	// Try to acquire again in a goroutine - should block since no credit available
	done := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		id, err := mgr.acquireScanCredit()
		errChan <- err
		done <- id
	}()

	// Verify the goroutine hasn't completed yet (still blocked)
	select {
	case <-done:
		t.Fatal("acquireScanCredit should block when no credit available, but it completed")
	default:
		// Good - still blocked
	}

	// Now release the credit - this should unblock the waiting goroutine
	err = mgr.releaseScanCredit(scannerID)
	require.NoError(t, err)

	// Wait for the goroutine to complete (use generous timeout for CI stability)
	var acquireID string
	var acquireErr error
	select {
	case acquireErr = <-errChan:
		acquireID = <-done
	case <-time.After(2 * time.Second):
		t.Fatal("acquireScanCredit did not complete after release - may be deadlocked")
	}

	// Verify the second acquire succeeded
	require.NoError(t, acquireErr, "Second acquire should succeed after release")
	assert.NotEmpty(t, acquireID, "Should have acquired a scanner ID")
}

// TestNoScannerFound verifies behavior when no scanners exist
func TestNoScannerFound(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, _ := setupTestManager(maxConns, maxExpectedScanners)

	// Don't add any scanners
	// Try to acquire - should timeout quickly since no scanners exist
	done := make(chan bool)
	go func() {
		_, err := mgr.acquireScanCredit()
		assert.Error(t, err, "Should fail when no scanners exist")
		done <- true
	}()

	// Wait a short time to ensure the goroutine is running
	select {
	case <-done:
		t.Fatal("Should not complete immediately - should wait for timeout")
	case <-time.After(100 * time.Millisecond):
		// Expected - goroutine is waiting
	}
}

// TestReleaseScanCreditWithDeletedScanner verifies releasing credit when scanner was deleted
func TestReleaseScanCreditWithDeletedScanner(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Acquire a scanner
	scannerID, err := mgr.acquireScanCredit()
	require.NoError(t, err)

	// Delete the scanner from mock cluster (simulating scanner removal)
	err = mgr.RemoveScanner(scannerID)
	require.NoError(t, err)

	// Release should handle the deleted scanner gracefully
	// The actual helper.go has infinite retry that will detect scanner deletion
	err = mgr.releaseScanCredit(scannerID)
	require.ErrorIs(t, err, common.ErrObjectNotFound)

	// Credit pool should be incremented (signalScanCredit is called)
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should not change even if scanner is deleted")
}

// TestGetAllAvailableScanners verifies retrieving all scanners
func TestGetAllAvailableScanners(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	// Add multiple scanners
	scanner1 := newMockScanner(1, maxConns)
	scanner2 := newMockScanner(2, maxConns)
	scanner3 := newMockScanner(3, maxConns)

	mockHelper.AddScanner(scanner1)
	mockHelper.AddScanner(scanner2)
	mockHelper.AddScanner(scanner3)

	mgr.AddScanner(scanner1)
	mgr.AddScanner(scanner2)
	mgr.AddScanner(scanner3)

	// Get all available scanners
	scanners := mgr.getAllAvailableScanners()

	assert.Equal(t, 3, len(scanners), "Should return all 3 scanners")
	assert.Contains(t, scanners, scanner1.ID, "Should contain scanner1")
	assert.Contains(t, scanners, scanner2.ID, "Should contain scanner2")
	assert.Contains(t, scanners, scanner3.ID, "Should contain scanner3")
}

// TestCountScanners verifies counting busy and idle scanners
func TestCountScanners(t *testing.T) {
	maxConns := 3
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	// Add scanners with different states
	scanner1 := newMockScanner(1, maxConns)
	scanner2 := newMockScanner(2, maxConns)
	scanner3 := newMockScanner(3, maxConns)

	scanner1.ScanCredit = 0 // Idle (no active scans)
	scanner2.ScanCredit = 2 // Busy (has active scans)
	scanner3.ScanCredit = 1 // Busy (has active scans)

	mockHelper.AddScanner(scanner1)
	mockHelper.AddScanner(scanner2)
	mockHelper.AddScanner(scanner3)

	busy, idle := mgr.CountScanners()

	assert.Equal(t, uint32(2), busy, "Should count 2 busy scanners (ScanCredit > 0)")
	assert.Equal(t, uint32(1), idle, "Should count 1 idle scanner (ScanCredit = 0)")
}

// TestHealthCheckIntegration verifies health check integration
func TestHealthCheckIntegration(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Set a custom health checker that always succeeds
	mgr.SetScannerHealthChecker(func(scannerID string, timeout time.Duration) error {
		assert.Equal(t, scanner.ID, scannerID, "Health check should be called with correct scanner ID")
		return nil
	})

	// Acquire scanner - should call health check
	scannerID, err := mgr.acquireScanCredit()
	require.NoError(t, err)
	require.Equal(t, scanner.ID, scannerID)

	// Release
	err = mgr.releaseScanCredit(scannerID)
	require.NoError(t, err)
}

// TestHealthCheckFailure verifies behavior when health check fails
func TestHealthCheckFailure(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Set a health checker that always fails
	mgr.SetScannerHealthChecker(func(scannerID string, timeout time.Duration) error {
		return fmt.Errorf("health check failed")
	})

	// Acquire scanner - should fail due to health check and retry
	// Since we only have one scanner and it always fails health check,
	// this will keep retrying until timeout
	done := make(chan bool)
	go func() {
		_, err := mgr.acquireScanCredit()
		require.Error(t, err)
		done <- true
	}()

	// Wait a short time to ensure it's retrying
	select {
	case <-done:
		t.Fatal("Should not complete immediately - should keep retrying")
	case <-time.After(200 * time.Millisecond):
		// Expected - still retrying
	}
}

// TestEdgeCaseZeroMaxConns verifies behavior with zero max concurrent scans
func TestEdgeCaseZeroMaxConns(t *testing.T) {
	maxConns := 0
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)

	// AddScanner should not add any credits
	mgr.AddScanner(scanner)
	assert.Equal(t, 0, len(mgr.creditPool), "creditPool should be empty with maxConns=0")
}

// TestEdgeCaseMaxCreditCap verifies credit doesn't go below zero
func TestEdgeCaseMaxCreditCap(t *testing.T) {
	maxConns := 2
	maxExpectedScanners := 10
	mgr, mockHelper := setupTestManager(maxConns, maxExpectedScanners)

	scanner := newMockScanner(1, maxConns)
	mockHelper.AddScanner(scanner)
	mgr.AddScanner(scanner)

	// Try to release credit when already at 0 (no tasks to release)
	err := mgr.releaseScanCredit(scanner.ID)
	require.NoError(t, err)

	// Verify credit didn't go below 0
	updatedScanner, _, err := mockHelper.GetScannerRev(scanner.ID)
	require.NoError(t, err)
	assert.Equal(t, maxConns, updatedScanner.ScanCredit, "Credit should not go over maxConns")
}
