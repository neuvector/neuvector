package rpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

type scannerAct struct {
	scanner            *share.CLUSScanner
	activeScannerTasks int // Indicate how much scanner task is currently run
}

type ScannerManager struct {
	activeScanners map[string]*scannerAct
	maxConns       int
	mutex          sync.RWMutex
	availableCh    chan struct{}
}

var ScannerMgr *ScannerManager

// scannerChannelCapacity ensures that the availableCh channel has sufficient capacity to handle task signals without blocking.
var scannerChannelCapacity = 15
var acquireScannerAvailabilityTimeout = time.Minute * 3

func NewScannerManager(maxConns int) *ScannerManager {
	return &ScannerManager{
		activeScanners: make(map[string]*scannerAct),
		maxConns:       maxConns,
		availableCh:    make(chan struct{}, scannerChannelCapacity*maxConns),
	}
}

func (mgr *ScannerManager) signalAvailability() {
	select {
	case mgr.availableCh <- struct{}{}:
		// Singal the pending task
	default:
		// Signal already pending, do not block
	}
}

func (mgr *ScannerManager) AddScanner(scanner *share.CLUSScanner) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.activeScanners[scanner.ID] = &scannerAct{scanner: scanner, activeScannerTasks: 0}

	// Signal availability for this scanner's maximum allowed connections
	for i := 0; i < mgr.maxConns; i++ {
		mgr.signalAvailability()
	}
}

func (mgr *ScannerManager) RemoveScanner(scannerID string) {
	availableSlots := 0
	mgr.mutex.Lock()
	s, ok := mgr.activeScanners[scannerID]
	if ok {
		delete(mgr.activeScanners, scannerID)
		availableSlots = max(0, mgr.maxConns-s.activeScannerTasks)
	}
	mgr.mutex.Unlock()

	// endpoint is also the key
	if s != nil {
		endpoint := mgr.getScannerEndpoint(s.scanner)
		cluster.DeleteGRPCClient(endpoint)

		// Drain availableSlots tokens from availableCh to maintain balance
		for i := 0; i < availableSlots; i++ {
			select {
			case <-mgr.availableCh:
				// Successfully drained one slot
			default:
				// No more slots to drain;
			}
		}
	}
}

func (mgr *ScannerManager) getScannerEndpoint(scanner *share.CLUSScanner) string {
	return fmt.Sprintf("%s:%v", scanner.RPCServer, scanner.RPCServerPort)
}

func (mgr *ScannerManager) createScannerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewScannerServiceClient(conn)
}

func (mgr *ScannerManager) decScanningCount(sid string) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	s, ok := mgr.activeScanners[sid]
	if ok && s.activeScannerTasks > 0 {
		s.activeScannerTasks--
	}
}

func (mgr *ScannerManager) releaseScannerAvailability(sid string) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	s, ok := mgr.activeScanners[sid]
	if ok && s.activeScannerTasks > 0 {
		s.activeScannerTasks--
		mgr.signalAvailability()
	}
}

// acquireScannerAvailability continuously checks for an available scanner with fewer active tasks than the maximum allowed.
// It locks the ScannerManager's mutex to safely access the activeScanners map and iterates through the scanners.
// If it finds a scanner with active tasks less than the maximum connections (maxConns), it increments the active task count,
// unlocks the mutex, and returns the scanner's ID. If no scanner is available, it waits for a signal on the availableCh channel
// indicating that a scanner has become available.
func (mgr *ScannerManager) acquireScannerAvailability() string {
	for {
		// Wait for a scanner to become available or timeout to avoid indefinite blocking
		select {
		case <-mgr.availableCh:
			mgr.mutex.Lock()
			defer mgr.mutex.Unlock()
			for _, s := range mgr.activeScanners {
				if s.activeScannerTasks < mgr.maxConns {
					s.activeScannerTasks++
					return s.scanner.ID
				}
			}
		case <-time.After(acquireScannerAvailabilityTimeout):
			log.Debug("No scanner available, retrying...")
		}
	}
}

// shouldIncrementTask not apply for Ping, if the acquireScannerAvailability is called by ScanImage should be true
func (mgr *ScannerManager) getScannerServiceClient(sid string, shouldIncrementTask bool) (share.ScannerServiceClient, string, error) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	s, ok := mgr.activeScanners[sid]
	if !ok {
		err := fmt.Errorf("Scanner not found")
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
		return nil, sid, err
	}

	// endpoint is also the key
	endpoint := mgr.getScannerEndpoint(s.scanner)
	if cluster.GetGRPCClientEndpoint(endpoint) == "" {
		if err := cluster.CreateGRPCClient(endpoint, endpoint, true, mgr.createScannerServiceWrapper); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CreateGRPCClient")
		}
	}

	c, err := cluster.GetGRPCClient(endpoint, nil, nil)
	if err == nil {
		if shouldIncrementTask {
			s.activeScannerTasks++
		}
		return c.(share.ScannerServiceClient), sid, nil
	} else {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error("Failed to connect to grpc server")
		return nil, sid, err
	}
}

func (mgr *ScannerManager) getAllAvailableScanners() map[string]share.CLUSScanner {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	ret := map[string]share.CLUSScanner{}

	for id, scanner := range mgr.activeScanners {
		if scanner != nil && scanner.scanner != nil {
			ret[id] = *scanner.scanner
		}
	}

	return ret
}

func (mgr *ScannerManager) CountScanners() (busy, idle uint32) {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	for _, s := range mgr.activeScanners {
		if s.activeScannerTasks > 0 {
			busy++
		} else {
			idle++
		}
	}
	return busy, idle
}

// This function performs a task on all scanners.
// This would take a while if the task is time-consuming.
func (mgr *ScannerManager) RunTaskForEachScanner(cb func(share.ScannerServiceClient) error) error {
	activeScanners := mgr.getAllAvailableScanners()

	for id, scanner := range activeScanners {
		endpoint := mgr.getScannerEndpoint(&scanner)
		if cluster.GetGRPCClientEndpoint(endpoint) == "" {
			if err := cluster.CreateGRPCClient(endpoint, endpoint, true, mgr.createScannerServiceWrapper); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("CreateGRPCClient")
			}
		}

		c, err := cluster.GetGRPCClient(endpoint, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to connect to scanner %s: %w", id, err)
		}
		if err = cb(c.(share.ScannerServiceClient)); err != nil {
			return fmt.Errorf("failed to run task for scanner client %s: %w", id, err)
		}
	}
	return nil
}

func Ping(scanner string, timeout time.Duration) error {
	client, _, err := ScannerMgr.getScannerServiceClient(scanner, false)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err = client.Ping(ctx, &share.RPCVoid{})
	return err
}

func ScanRunning(scanner string, agentID, id string, objType share.ScanObjectType, timeout time.Duration) (*share.ScanResult, error) {
	ep := findEnforcerServerEndpoint(agentID)
	if ep == "" {
		return nil, fmt.Errorf("Cannot find enforcer endpoint")
	}

	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer ScannerMgr.decScanningCount(scanner)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := client.ScanRunning(ctx, &share.ScanRunningRequest{
		Type:             objType,
		ID:               id,
		AgentID:          agentID,
		AgentRPCEndPoint: ep,
	})

	clusHelper := kv.GetClusterHelper()
	if err2 := clusHelper.PutScannerStats(scanner, objType, result); err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("PutScannerStats")
	}

	return result, err
}

func ScanPlatform(scanner string, k8sVersion, ocVersion string, timeout time.Duration) (*share.ScanResult, error) {
	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer ScannerMgr.decScanningCount(scanner)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var req share.ScanAppRequest

	var platform, version string
	if ocVersion != "" {
		// in openshift, they patch kubernetes themselves, so use openshift version instead
		req.Packages = append(req.Packages, &share.ScanAppPackage{
			AppName:    "openshift",
			ModuleName: "openshift.kubernetes",
			Version:    ocVersion,
			FileName:   "kubernetes",
		})
		req.Packages = append(req.Packages, &share.ScanAppPackage{
			AppName:    "openshift",
			ModuleName: "openshift",
			Version:    ocVersion,
			FileName:   "openshift",
		})
		platform = "openshift"
		version = ocVersion
	} else if k8sVersion != "" {
		req.Packages = append(req.Packages, &share.ScanAppPackage{
			AppName:    "kubernetes",
			ModuleName: "kubernetes",
			Version:    k8sVersion,
			FileName:   "kubernetes",
		})
		platform = "kubernetes"
		version = k8sVersion
	}

	result, err := client.ScanAppPackage(ctx, &req)
	if result != nil {
		result.Platform = platform
		result.PlatformVersion = version
	}
	return result, err
}

func ScanImage(scanner string, ctx context.Context, req *share.ScanImageRequest) (*share.ScanResult, error) {
	shouldIncrementTask := true
	hasAcquiredScanner := false

	// When scanner is empty, it indicates that the CI plugins are calling the scan.
	// In this case, we set shouldIncrementTask to false to avoid double counting.
	if scanner == "" {
		scanner = ScannerMgr.acquireScannerAvailability()
		shouldIncrementTask = false
		hasAcquiredScanner = true
	}

	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, shouldIncrementTask)
	if err != nil {
		return nil, err
	}

	// Ensure that resources are properly released or task counts are decremented when the function exits
	defer func() {
		if hasAcquiredScanner {
			// Release the scanner slot back to the availability channel
			ScannerMgr.releaseScannerAvailability(scanner)
		} else {
			// Decrement the active task count for the scanner
			ScannerMgr.decScanningCount(scanner)
		}
	}()

	result, err := client.ScanImage(ctx, req)
	if err == nil {
		if result.Labels == nil {
			// grpc convert zero-length map to nil, fix it here.
			result.Labels = make(map[string]string)
		}
	}

	clusHelper := kv.GetClusterHelper()
	if err2 := clusHelper.PutScannerStats(scanner, share.ScanObjectType_IMAGE, result); err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("PutScannerStats")
	}

	return result, err
}

func ScanPackage(ctx context.Context, pkgs []*share.ScanAppPackage) (*share.ScanResult, error) {
	scanner := ScannerMgr.acquireScannerAvailability()
	if scanner == "" {
		err := fmt.Errorf("No scanner available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer ScannerMgr.releaseScannerAvailability(scanner)

	req := &share.ScanAppRequest{
		Packages: pkgs,
	}

	result, err := client.ScanAppPackage(ctx, req)

	clusHelper := kv.GetClusterHelper()
	if err2 := clusHelper.PutScannerStats(scanner, share.ScanObjectType_SERVERLESS, result); err2 != nil {
		log.WithFields(log.Fields{"err": err2}).Error("PutScannerStats")
	}

	return result, err
}

func ScanAwsLambdaFunc(ctx context.Context, funcInput *share.CLUSAwsFuncScanInput) (*share.ScanResult, error) {
	scanner := ScannerMgr.acquireScannerAvailability()
	if scanner == "" {
		err := fmt.Errorf("No scanner available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	req := &share.ScanAwsLambdaRequest{
		ResType:     share.AwsLambdaFunc,
		FuncName:    funcInput.FuncName,
		Region:      funcInput.Region,
		FuncLink:    funcInput.FuncLink,
		ScanSecrets: true, // default: always
	}

	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		err := fmt.Errorf("No scan client available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}
	defer ScannerMgr.releaseScannerAvailability(scanner)

	result, err := client.ScanAwsLambda(ctx, req)
	if err != nil {
		err := fmt.Errorf("scan return error")
		log.WithFields(log.Fields{"error": err}).Error()
	} else {
		if result.Labels == nil {
			// grpc convert zero-length map to nil, fix it here.
			result.Labels = make(map[string]string)
		}
	}

	clusHelper := kv.GetClusterHelper()
	if err2 := clusHelper.PutScannerStats(scanner, share.ScanObjectType_SERVERLESS, result); err2 != nil {
		log.WithFields(log.Fields{"err": err2}).Error("PutScannerStats")
	}

	return result, err
}

func ScanCacheGetStat(scanner string) (*share.ScanCacheStatRes, error) {
	log.WithFields(log.Fields{"scanner": scanner}).Debug()
	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer ScannerMgr.decScanningCount(scanner)
	defer cancel()
	return client.ScanCacheGetStat(ctx, &share.RPCVoid{})
}

func ScanCacheGetData(scanner string) (*share.ScanCacheDataRes, error) {
	client, scanner, err := ScannerMgr.getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer ScannerMgr.decScanningCount(scanner)
	defer cancel()
	return client.ScanCacheGetData(ctx, &share.RPCVoid{})
}
