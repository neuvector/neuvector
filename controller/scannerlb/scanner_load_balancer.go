package scannerlb

import (
	"fmt"
	"sync"

	"github.com/google/btree"
	"github.com/neuvector/neuvector/share"
)

// ScannerLoadBalancer implements an efficient scanner workload distribution system
// to address resource imbalance issues when multiple scanners are available.
// It uses a combination of a B-tree and a map to achieve O(log n) performance
// for scanner selection and updates:
//   - B-tree maintains scanners ordered by their available scan credits,
//     enabling quick access to the least loaded scanner
//   - Map provides O(1) lookups for scanner updates and removals
//
// The load balancer ensures that scan tasks are distributed evenly across
// available scanners by always selecting the scanner with the most
// available scan credits for new tasks.

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

// Define sorting order: least running tasks first.
func (a *ScannerEntry) Less(b btree.Item) bool {
	// Compare based on availableScanCredits, and use scanner ID as a tiebreaker
	if a.AvailableScanCredits == b.(*ScannerEntry).AvailableScanCredits {
		return a.Scanner.ID < b.(*ScannerEntry).Scanner.ID
	}
	return a.AvailableScanCredits < b.(*ScannerEntry).AvailableScanCredits
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
