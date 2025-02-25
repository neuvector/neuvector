package scannerlb

import (
	"fmt"
	"sync"

	"github.com/neuvector/neuvector/share"
)

// ScannerLoadBalancer implements a load balancing system for distributing scan workloads
// across multiple scanner instances. It maintains a list of active scanners and their
// available scan credits (capacity for concurrent scans).
//
// Key features:
// - Efficient O(n) selection of least loaded scanner
// - Thread-safe operations via mutex locking
// - Dynamic registration/unregistration of scanners
// - Credit-based workload tracking per scanner
//
// The load balancer ensures optimal resource utilization by:
// 1. Always selecting the scanner with the most available scan credits for new tasks
// 2. Tracking and updating scan credits as tasks complete
// 3. Maintaining an accurate view of system-wide scanner capacity
//
// Usage:
// - Register scanners with initial scan credit allocation
// - Pick scanner for new scan tasks via PickLeastLoadedScanner()
// - Release scan credits when tasks complete via ReleaseScanCredit()
// - Remove scanners via UnregisterScanner() when they go offline

// ScannerEntry represents an active scanner instance and its running tasks.
type ScannerEntry struct {
	Scanner              *share.CLUSScanner
	AvailableScanCredits int // Number of currently running scanner tasks
}

// ScannerLoadBalancer manages scanner workload using a B-tree heap.
type ScannerLoadBalancer struct {
	mutex          sync.RWMutex
	ActiveScanners []*ScannerEntry
}

func NewScannerLoadBalancer() *ScannerLoadBalancer {
	return &ScannerLoadBalancer{
		ActiveScanners: make([]*ScannerEntry, 0),
	}
}

func (lb *ScannerLoadBalancer) RegisterScanner(scanner *share.CLUSScanner, availableScanCredits int) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	entry := &ScannerEntry{Scanner: scanner, AvailableScanCredits: availableScanCredits}
	lb.ActiveScanners = append(lb.ActiveScanners, entry)
}

func (lb *ScannerLoadBalancer) UnregisterScanner(scannerId string) (*ScannerEntry, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	for i, entry := range lb.ActiveScanners {
		if entry.Scanner.ID == scannerId {
			lb.ActiveScanners = append(lb.ActiveScanners[:i], lb.ActiveScanners[i+1:]...)
			return entry, nil
		}
	}
	return nil, fmt.Errorf("scanner %s not found", scannerId)
}

func (lb *ScannerLoadBalancer) GetScanner(scannerId string) (*ScannerEntry, error) {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	for _, entry := range lb.ActiveScanners {
		if entry.Scanner.ID == scannerId {
			return entry, nil
		}
	}
	return nil, fmt.Errorf("scanner %s not found", scannerId)
}

func (lb *ScannerLoadBalancer) GetActiveScanners() []*ScannerEntry {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	return lb.ActiveScanners
}

func (lb *ScannerLoadBalancer) ReleaseScanCredit(scannerId string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	for _, entry := range lb.ActiveScanners {
		if entry.Scanner.ID == scannerId {
			entry.AvailableScanCredits++
			return nil
		}
	}
	return fmt.Errorf("scanner %s not found", scannerId)
}

// No mutex here, because it's called by PickLeastLoadedScanner, which already has a mutex.
// func (lb *ScannerLoadBalancer) acquireScanCredit(scannerId string) error {
// 	return lb.updateScanCredit(scannerId, -1)
// }

func (lb *ScannerLoadBalancer) PickLeastLoadedScanner() (*share.CLUSScanner, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if len(lb.ActiveScanners) == 0 {
		return nil, fmt.Errorf("no scanner found")
	}

	maxScanCredits := -1 // Initialize to an impossible value
	maxScanCreditsIndex := -1

	for i := 0; i < len(lb.ActiveScanners); i++ {
		scanCredits := lb.ActiveScanners[i].AvailableScanCredits
		if (maxScanCreditsIndex == -1 || scanCredits > maxScanCredits) && scanCredits > 0 {
			maxScanCredits = scanCredits
			maxScanCreditsIndex = i
		}
	}

	if maxScanCreditsIndex != -1 {
		lb.ActiveScanners[maxScanCreditsIndex].AvailableScanCredits--
		return lb.ActiveScanners[maxScanCreditsIndex].Scanner, nil
	}

	return nil, fmt.Errorf("no scanner available")
}
