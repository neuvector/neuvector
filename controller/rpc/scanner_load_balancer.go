package rpc

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

// scannerEntry represents an active scanner instance and its running tasks.
type scannerEntry struct {
	scanner              *share.CLUSScanner
	availableScanCredits int // Number of currently running scanner tasks
}

// ScannerLoadBalancer manages scanner workload using a B-tree heap.
type ScannerLoadBalancer struct {
	mutex          sync.RWMutex
	activeScanners map[string]*scannerEntry
	heap           *btree.BTree
}

// Define sorting order: least running tasks first.
func (a *scannerEntry) Less(b btree.Item) bool {
	// Compare based on availableScanCredits, and use scanner ID as a tiebreaker
	if a.availableScanCredits == b.(*scannerEntry).availableScanCredits {
		return a.scanner.ID < b.(*scannerEntry).scanner.ID
	}
	return a.availableScanCredits < b.(*scannerEntry).availableScanCredits
}

func NewScannerLoadBalancer() *ScannerLoadBalancer {
	return &ScannerLoadBalancer{
		activeScanners: make(map[string]*scannerEntry),
		heap:           btree.New(2),
	}
}

func (lb *ScannerLoadBalancer) RegisterScanner(scanner *share.CLUSScanner, availableScanCredits int) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	entry := &scannerEntry{scanner: scanner, availableScanCredits: availableScanCredits}
	lb.activeScanners[scanner.ID] = entry
	lb.heap.ReplaceOrInsert(entry)
}

func (lb *ScannerLoadBalancer) UnregisterScanner(scannerId string) (*scannerEntry, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()
	entry, exists := lb.activeScanners[scannerId]
	if !exists {
		return nil, fmt.Errorf("scanner %s not found", scannerId)
	}
	lb.heap.Delete(entry)
	delete(lb.activeScanners, scannerId)
	return entry, nil
}

func (lb *ScannerLoadBalancer) updateScanCredit(scannerId string, delta int) error {
	if delta == 0 {
		return fmt.Errorf("delta should not be 0")
	}

	entry, exists := lb.activeScanners[scannerId]
	if !exists {
		return fmt.Errorf("scanner %s not found", scannerId)
	}

	lb.heap.Delete(entry) // Remove outdated entry

	newCredit := entry.availableScanCredits + delta
	if newCredit < 0 {
		return fmt.Errorf("scanner %s active scan credits cannot be negative", scannerId)
	}

	entry.availableScanCredits = newCredit

	if newCredit > 0 {
		lb.heap.ReplaceOrInsert(entry) // Reinsert updated entry
	}

	return nil
}

func (lb *ScannerLoadBalancer) GetActiveScanners() map[string]*scannerEntry {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()
	return lb.activeScanners
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

	if lb.heap.Len() == 0 {
		return nil, fmt.Errorf("no scanner found")
	}
	entry := lb.heap.Max().(*scannerEntry)
	err := lb.AcquireScanCredit(entry.scanner.ID)
	if err != nil {
		return nil, err
	}

	return entry.scanner, nil
}
