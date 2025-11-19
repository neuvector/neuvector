package rpc

import (
	"context"
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
		ScanCredit:                   maxConns, // Initialize with full capacity
		RPCServer:                    "localhost",
		RPCServerPort:                18402,
	}
}

// setupTestManager creates a new ScannerAcquisitionManager with MockCluster for testing
func setupTestManager(maxConns, maxConcurrentRepoScanTasks int) (*ScannerAcquisitionManager, *kv.MockCluster) {
	mockHelper := &kv.MockCluster{}
	mockHelper.Init(nil, nil)
	mgr := NewScannerAcquisitionManager(maxConns, maxConcurrentRepoScanTasks, mockHelper)
	mgr.ScannerHealthChecker = nil // Disable health check for most tests
	return mgr, mockHelper
}

// TestNewScannerAcquisitionManager verifies basic initialization
func TestNewScannerAcquisitionManager(t *testing.T) {
	maxConns := 3
	maxConcurrentRepoScanTasks := 6
	mgr := NewScannerAcquisitionManager(maxConns, maxConcurrentRepoScanTasks, &kv.MockCluster{})

	assert.NotNil(t, mgr, "ScannerAcquisitionManager should be created")
	assert.Equal(t, maxConns, mgr.maxConcurrentScansPerScanner, "maxConcurrentScansPerScanner should match")
	assert.NotNil(t, mgr.ScannerHealthChecker, "ScannerHealthChecker should be initialized")
}

// TestGetMaxConcurrentScansPerScanner verifies the getter method
func TestGetMaxConcurrentScansPerScanner(t *testing.T) {
	maxConns := 5
	maxConcurrentRepoScanTasks := 6
	mgr := NewScannerAcquisitionManager(maxConns, maxConcurrentRepoScanTasks, &kv.MockCluster{})

	assert.Equal(t, maxConns, mgr.GetMaxConcurrentScansPerScanner(), "GetMaxConcurrentScansPerScanner should return correct value")
}

// TestAcquireAndReleaseScanner verifies basic acquire and release flow
func TestAcquireAndReleaseScanner(t *testing.T) {
	maxConns := 3
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	ctx := context.Background()

	scannerID, err := mgr.acquireScanner(ctx)
	require.NoError(t, err)
	assert.Equal(t, scanner.ID, scannerID, "Should return correct scanner ID")

	updatedScanner, _, err := mockHelper.GetScannerRev(scannerID)
	require.NoError(t, err)
	assert.Equal(t, maxConns-1, updatedScanner.ScanCredit, "ScanCredit should decrease by 1")

	err = mgr.releaseScanner(scannerID)
	require.NoError(t, err)

	releasedScanner, _, err := mockHelper.GetScannerRev(scannerID)
	require.NoError(t, err)
	assert.Equal(t, maxConns, releasedScanner.ScanCredit, "ScanCredit should be restored")
}

// TestAcquireMultipleScanners verifies acquiring from multiple scanners
func TestAcquireMultipleScanners(t *testing.T) {
	maxConns := 2
	scannerCount := 3
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	for i := 0; i < scannerCount; i++ {
		scanner := newMockScanner(i, maxConns)
		require.NoError(t, mockHelper.AddScanner(scanner))
	}
	ctx := context.Background()

	// Acquire scanners
	acquiredScanners := make(map[string]int)
	totalAcquires := maxConns * scannerCount

	for i := 0; i < totalAcquires; i++ {
		scannerID, err := mgr.acquireScanner(ctx)
		require.NoError(t, err)
		acquiredScanners[scannerID]++
	}

	// Verify all scanners were utilized
	for i := 0; i < scannerCount; i++ {
		scannerID := getMockScannerID(i)
		count := acquiredScanners[scannerID]
		assert.Equal(t, maxConns, count, fmt.Sprintf("Scanner %s should have been acquired %d times", scannerID, maxConns))
	}

	// Release all
	for scannerID, count := range acquiredScanners {
		for j := 0; j < count; j++ {
			err := mgr.releaseScanner(scannerID)
			require.NoError(t, err)
		}
	}

	// Verify all scanners are back to full capacity
	for i := 0; i < scannerCount; i++ {
		scanner, _, err := mockHelper.GetScannerRev(getMockScannerID(i))
		require.NoError(t, err)
		assert.Equal(t, maxConns, scanner.ScanCredit, "Scanner should be back to full capacity")
	}
}

// TestConcurrentAcquireAndRelease verifies thread safety
func TestConcurrentAcquireAndRelease(t *testing.T) {
	maxConns := 2
	scannerCount := 3
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	// Add scanners
	for i := 0; i < scannerCount; i++ {
		scanner := newMockScanner(i, maxConns)
		require.NoError(t, mockHelper.AddScanner(scanner))
	}

	totalCapacity := maxConns * scannerCount
	ctx := context.Background()

	var wg sync.WaitGroup
	acquiredScanners := make([]string, totalCapacity)
	var mu sync.Mutex

	for i := 0; i < totalCapacity; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scannerID, err := mgr.acquireScanner(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, scannerID)
			mu.Lock()
			acquiredScanners[idx] = scannerID
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	for i, scannerID := range acquiredScanners {
		assert.NotEmpty(t, scannerID, fmt.Sprintf("Index %d should have acquired a scanner", i))
	}

	for i := 0; i < totalCapacity; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := mgr.releaseScanner(acquiredScanners[idx])
			require.NoError(t, err)
		}(i)
	}

	wg.Wait()

	for i := 0; i < scannerCount; i++ {
		scanner, _, err := mockHelper.GetScannerRev(getMockScannerID(i))
		require.NoError(t, err)
		assert.Equal(t, maxConns, scanner.ScanCredit, "Scanner should be back to full capacity")
	}
}

// TestacquireScannerBlocking verifies blocking behavior when all scanners are busy
func TestAcquireScannerBlocking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blocking test in short mode")
	}

	maxConns := 1
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	ctx := context.Background()

	scannerID, err := mgr.acquireScanner(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, scannerID)

	updatedScanner, _, err := mockHelper.GetScannerRev(scannerID)
	require.NoError(t, err)
	require.LessOrEqual(t, updatedScanner.ScanCredit, 0, "Scanner should be at zero capacity")

	// Verify the acquire will fail after the scanner is at full capacity
	shortCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = mgr.acquireScanner(shortCtx)
	require.Error(t, err)
}

// TestNoScannerAvailable verifies behavior when no scanners exist
func TestNoScannerAvailable(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, _ := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := mgr.acquireScanner(ctx)
	assert.Error(t, err, "Should fail when no scanners exist")
}

// TestReleaseScannerWithDeletedScanner verifies releasing scanner when scanner was deleted
func TestReleaseScannerWithDeletedScanner(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	ctx := context.Background()

	// Acquire a scanner
	scannerID, err := mgr.acquireScanner(ctx)
	require.NoError(t, err)

	// Delete the scanner
	err = mockHelper.DeleteScanner(scanner.ID)
	require.NoError(t, err)
	mgr.CleanUpScannerResources(scanner)

	// Release should handle the deleted scanner gracefully
	err = mgr.releaseScanner(scannerID)
	assert.ErrorIs(t, err, common.ErrObjectNotFound, "Should return ErrObjectNotFound for deleted scanner")
}

// TestGetAllAvailableScanners verifies retrieving all scanners
func TestGetAllAvailableScanners(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner1 := newMockScanner(1, maxConns)
	scanner2 := newMockScanner(2, maxConns)
	scanner3 := newMockScanner(3, maxConns)

	err := mockHelper.AddScanner(scanner1)
	require.NoError(t, err)
	err = mockHelper.AddScanner(scanner2)
	require.NoError(t, err)
	err = mockHelper.AddScanner(scanner3)
	require.NoError(t, err)

	scanners := mgr.getAllAvailableScanners()

	assert.Equal(t, 3, len(scanners), "Should return all 3 scanners")
	assert.Contains(t, scanners, scanner1.ID, "Should contain scanner1")
	assert.Contains(t, scanners, scanner2.ID, "Should contain scanner2")
	assert.Contains(t, scanners, scanner3.ID, "Should contain scanner3")
}

// TestCountScanners verifies counting busy and idle scanners
func TestCountScanners(t *testing.T) {
	maxConns := 3
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	// Add scanners with different states
	// Note: In the current implementation, ScanCredit > 0 means busy
	scanner1 := newMockScanner(1, maxConns)
	scanner2 := newMockScanner(2, maxConns)
	scanner3 := newMockScanner(3, maxConns)

	scanner1.ScanCredit = 0 // Idle (no remaining credit, all used up)
	scanner2.ScanCredit = 2 // Has available credit
	scanner3.ScanCredit = 1 // Has available credit

	err := mockHelper.AddScanner(scanner1)
	require.NoError(t, err)
	err = mockHelper.AddScanner(scanner2)
	require.NoError(t, err)
	err = mockHelper.AddScanner(scanner3)
	require.NoError(t, err)

	busy, idle := mgr.CountScanners()

	// Two scanners should be busy (ScanCredit > 0, meaning they have available slots)
	// One scanner should be idle (ScanCredit = 0, fully utilized)
	assert.Equal(t, uint32(1), busy, "Should count 1 busy scanner (ScanCredit > 0)")
	assert.Equal(t, uint32(2), idle, "Should count 2 idle scanners (ScanCredit = 0)")
}

// TestHealthCheckIntegration verifies health check is called during acquire
func TestHealthCheckIntegration(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	healthCheckCalled := false
	mgr.ScannerHealthChecker = func(scannerID string, timeout time.Duration) error {
		healthCheckCalled = true
		assert.Equal(t, scanner.ID, scannerID, "Health check should be called with correct scanner ID")
		return nil
	}

	ctx := context.Background()
	scannerID, err := mgr.acquireScanner(ctx)
	require.NoError(t, err)
	require.Equal(t, scanner.ID, scannerID)

	assert.True(t, healthCheckCalled, "Health check should have been called")

	require.NoError(t, mgr.releaseScanner(scannerID))
}

// TestHealthCheckFailure verifies behavior when health check fails
func TestHealthCheckFailure(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	mgr.ScannerHealthChecker = func(scannerID string, timeout time.Duration) error {
		return fmt.Errorf("health check failed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := mgr.acquireScanner(ctx)
	assert.Error(t, err, "Should fail when health check always fails")
}

// TestEdgeCaseMaxCreditCap verifies credit count doesn't exceed max on extra releases
func TestEdgeCaseMaxCreditCap(t *testing.T) {
	maxConns := 2
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	scanner := newMockScanner(1, maxConns)
	require.NoError(t, mockHelper.AddScanner(scanner))

	// Releasing more times than max should not exceed max credit and should not panic
	for i := 0; i < maxConns+3; i++ {
		_ = mgr.releaseScanner(scanner.ID)
	}

	// Verify credit didn't exceed max
	updatedScanner, _, err := mockHelper.GetScannerRev(scanner.ID)
	require.NoError(t, err)
	assert.LessOrEqual(t, updatedScanner.ScanCredit, maxConns, "ScanCredit should not exceed max")
}

func TestEdgeCaseReleaseScannerWithDeletedScanner(t *testing.T) {
	maxConns := 2
	scannerCount := 3
	var scanners []*share.CLUSScanner
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	for i := 0; i < scannerCount; i++ {
		scanner := newMockScanner(i, maxConns)
		scanners = append(scanners, scanner)
		require.NoError(t, mockHelper.AddScanner(scanner))

		ctx := context.Background()
		for j := 0; j < maxConns; j++ {
			scannerID, err := mgr.acquireScanner(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, scannerID)
		}
	}

	for _, scanner := range scanners {
		require.NoError(t, mockHelper.DeleteScanner(scanner.ID))
	}

	for _, scanner := range scanners {
		for j := 0; j < maxConns; j++ {
			err := mgr.releaseScanner(scanner.ID)
			assert.ErrorIs(t, err, common.ErrObjectNotFound, "Should return ErrObjectNotFound for deleted scanner")
		}
	}
}

func TestAcquireAndReleaseAllScanners(t *testing.T) {
	maxConns := 2
	scannerCount := 3
	var scanners []*share.CLUSScanner
	maxConcurrentRepoScanTasks := 6
	mgr, mockHelper := setupTestManager(maxConns, maxConcurrentRepoScanTasks)

	for i := 0; i < scannerCount; i++ {
		scanner := newMockScanner(i, maxConns)
		scanners = append(scanners, scanner)
		require.NoError(t, mockHelper.AddScanner(scanner))

		ctx := context.Background()
		for j := 0; j < maxConns; j++ {
			scannerID, err := mgr.acquireScanner(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, scannerID)
		}
	}

	for _, scanner := range scanners {
		for j := 0; j < maxConns; j++ {
			require.NoError(t, mgr.releaseScanner(scanner.ID))
		}
	}
}
