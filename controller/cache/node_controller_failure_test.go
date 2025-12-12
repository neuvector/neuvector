package cache

import (
	"testing"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
)

// setupControllerFailureTest initializes the test environment for controller failure tests
func setupControllerFailureTest(failingControllerID string) *kv.MockCluster {
	mockHelper := &kv.MockCluster{}
	mockHelper.Init(nil, nil)
	mockHelper.SetID(failingControllerID)
	clusHelper = mockHelper

	cacher.isLeader = true
	return mockHelper
}

// TestScannerCreditRecoveryAfterControllerDeletion simulates a controller is deleted from the cluster, ensures that the scanner credits are recovered.
func TestScannerCreditRecoveryAfterControllerDeletion(t *testing.T) {
	controllerID := "controller-not-leader-001"
	mockHelper := setupControllerFailureTest(controllerID)

	maxConcurrentScansPerScanner := 10
	usedCredit := 2
	cacher.isLeader = true

	// Create controller with credits
	scanner := &share.CLUSScanner{
		ID:                           "scanner-1",
		MaxConcurrentScansPerScanner: maxConcurrentScansPerScanner,
		ScanCredit:                   maxConcurrentScansPerScanner,
		RPCServer:                    "localhost",
		RPCServerPort:                18402,
	}
	require.NoError(t, mockHelper.AddScanner(scanner))

	for i := 0; i < usedCredit; i++ {
		selectedScanner, err := mockHelper.PickLeastLoadedScanner()
		require.NotNil(t, selectedScanner)
		require.NoError(t, err)
	}

	// Verify the credit owners before deletion, value should be usedCredit
	creditOwners := mockHelper.GetCreditOwners(controllerID)
	require.NotNil(t, creditOwners)
	require.Equal(t, 1, len(creditOwners))
	require.Equal(t, usedCredit, creditOwners[scanner.ID])

	// Verify the scanner credit before deletion, value should be maxConcurrentScansPerScanner-usedCredit
	scannerBefore, _, err := mockHelper.GetScannerRev("scanner-1")
	require.NoError(t, err)
	require.Equal(t, maxConcurrentScansPerScanner-usedCredit, scannerBefore.ScanCredit)

	deleteControllerFromCluster("host-1", controllerID, "192.168.1.100")

	// Verify the scanner credit after deletion, should be the max concurrent scans per scanner
	scannerAfter, _, err := mockHelper.GetScannerRev("scanner-1")
	require.NoError(t, err)
	require.Equal(t, maxConcurrentScansPerScanner, scannerAfter.ScanCredit)

	// Verify the credit owners after deletion, should be empty/nil
	creditOwners = mockHelper.GetCreditOwners(controllerID)
	// After recovery, the creditOwners entry should be deleted
	require.Nil(t, creditOwners)
}
