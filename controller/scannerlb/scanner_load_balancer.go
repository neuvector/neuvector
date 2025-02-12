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
	ActiveScanners map[string]*ScannerEntry
	Heap           *btree.BTree
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
		ActiveScanners: make(map[string]*ScannerEntry),
		Heap:           btree.New(2),
	}
}

func (lb *ScannerLoadBalancer) RegisterScanner(scanner *share.CLUSScanner, availableScanCredits int) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	entry := &ScannerEntry{Scanner: scanner, AvailableScanCredits: availableScanCredits}
	lb.ActiveScanners[scanner.ID] = entry
	lb.Heap.ReplaceOrInsert(entry)
}

func (lb *ScannerLoadBalancer) UnregisterScanner(scannerId string) (*ScannerEntry, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	entry, exists := lb.ActiveScanners[scannerId]
	if !exists {
		return nil, fmt.Errorf("scanner %s not found", scannerId)
	}
	lb.Heap.Delete(entry)
	delete(lb.ActiveScanners, scannerId)
	return entry, nil
}

func (lb *ScannerLoadBalancer) updateScanCredit(scannerId string, delta int) error {
	if delta == 0 {
		return fmt.Errorf("delta should not be 0")
	}

	entry, exists := lb.ActiveScanners[scannerId]
	if !exists {
		return fmt.Errorf("scanner %s not found", scannerId)
	}

	lb.Heap.Delete(entry) // Remove outdated entry

	newCredit := entry.AvailableScanCredits + delta
	if newCredit < 0 {
		return fmt.Errorf("scanner %s active scan credits cannot be negative", scannerId)
	}

	entry.AvailableScanCredits = newCredit

	if newCredit > 0 {
		lb.Heap.ReplaceOrInsert(entry) // Reinsert updated entry
	}

	return nil
}

func (lb *ScannerLoadBalancer) GetActiveScanners() map[string]*ScannerEntry {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	return lb.ActiveScanners
}

func (lb *ScannerLoadBalancer) ReleaseScanCredit(scannerId string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	return lb.updateScanCredit(scannerId, 1)
}

// No mutex here, because it's called by PickLeastLoadedScanner, which already has a mutex.
func (lb *ScannerLoadBalancer) AcquireScanCredit(scannerId string) error {
	return lb.updateScanCredit(scannerId, -1)
}

func (lb *ScannerLoadBalancer) PickLeastLoadedScanner() (*share.CLUSScanner, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	if lb.Heap.Len() == 0 {
		return nil, fmt.Errorf("no scanner found")
	}
	entry := lb.Heap.Max().(*ScannerEntry)
	err := lb.AcquireScanCredit(entry.Scanner.ID)
	if err != nil {
		return nil, err
	}

	return entry.Scanner, nil
}
