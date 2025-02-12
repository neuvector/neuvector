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

type ScanCreditManager struct {
	maxConns            int
	mutex               sync.RWMutex
	creditPool          chan struct{}
	scannerLoadBalancer *ScannerLoadBalancer
}

var ScanCreditMgr *ScanCreditManager
var acquireScanCreditTimeout = time.Minute * 3

func NewScanCreditManager(maxConns, scannerLBMax int) *ScanCreditManager {
	return &ScanCreditManager{
		scannerLoadBalancer: NewScannerLoadBalancer(),
		maxConns:            maxConns,
		// scanLBMax*(maxConns+1) ensures that the creditPool channel has sufficient capacity to handle task signals without blocking.
		creditPool: make(chan struct{}, scannerLBMax*(maxConns+1)),
	}
}

func (mgr *ScanCreditManager) decScanningCount(sid string) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	err := mgr.scannerLoadBalancer.ReleaseScanCredit(sid)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
	}
}

func (mgr *ScanCreditManager) releaseScanCredit(sid string) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	err := mgr.scannerLoadBalancer.ReleaseScanCredit(sid)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
	} else {
		mgr.signalScanCredit()
	}
}

// acquireScanCredit continuously checks for an available scanner with fewer active tasks than the maximum allowed.
// It locks the ScanCreditManager's mutex to safely access the activeScanners map and iterates through the scanners.
// If it finds a scanner with active tasks less than the maximum connections (maxConns), it increments the active task count,
// unlocks the mutex, and returns the scanner's ID. If no scanner is available, it waits for a signal on the creditPool channel
// indicating that a scanner has become available.
func (mgr *ScanCreditManager) acquireScanCredit() (string, error) {
	for {
		// Wait for a scanner to become available or timeout to avoid indefinite blocking
		select {
		case <-mgr.creditPool:
			mgr.mutex.Lock()
			defer mgr.mutex.Unlock()

			// Use a heap to find the scanner with the least active tasks
			scanner, err := mgr.scannerLoadBalancer.PickLeastLoadedScanner()
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("PickLeastLoadedScanner")
				return "", err
			}
			return scanner.ID, nil
		case <-time.After(acquireScanCreditTimeout):
			log.Debug("No scanner available, retrying...")
		}
	}
}

func (mgr *ScanCreditManager) signalScanCredit() {
	select {
	case mgr.creditPool <- struct{}{}:
		// Singal the pending task
	default:
		// Signal already pending, do not block
	}
}

func (mgr *ScanCreditManager) AddScanner(scanner *share.CLUSScanner) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.scannerLoadBalancer.RegisterScanner(scanner, mgr.maxConns)

	// Signal availability for this scanner's maximum allowed connections
	for i := 0; i < mgr.maxConns; i++ {
		mgr.signalScanCredit()
	}
}

func (mgr *ScanCreditManager) RemoveScanner(scannerID string) error {
	mgr.mutex.Lock()
	scannerEntry, err := mgr.scannerLoadBalancer.UnregisterScanner(scannerID)
	mgr.mutex.Unlock()

	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": scannerID}).Error()
		return err
	}

	// endpoint is also the key
	if scannerEntry != nil {
		endpoint := mgr.getScannerEndpoint(scannerEntry.scanner)
		cluster.DeleteGRPCClient(endpoint)
		availableSlots := max(0, scannerEntry.availableScanCredits)
		// Drain availableSlots tokens from creditPool to maintain balance
		for i := 0; i < availableSlots; i++ {
			select {
			case <-mgr.creditPool:
				// Successfully drained one slot
			default:
				// No more slots to drain;
			}
		}
	}
	return err
}

func (mgr *ScanCreditManager) getScannerEndpoint(scanner *share.CLUSScanner) string {
	return fmt.Sprintf("%s:%v", scanner.RPCServer, scanner.RPCServerPort)
}

func (mgr *ScanCreditManager) createScannerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewScannerServiceClient(conn)
}

// shouldIncrementTask not apply for Ping, if the acquireScanCredit is called by ScanImage should be true
func (mgr *ScanCreditManager) getScannerServiceClient(sid string, shouldIncrementTask bool) (share.ScannerServiceClient, string, error) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	s, ok := mgr.scannerLoadBalancer.activeScanners[sid]
	if !ok {
		err := fmt.Errorf("scanner not found")
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
			s.availableScanCredits++
		}
		return c.(share.ScannerServiceClient), sid, nil
	} else {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error("Failed to connect to grpc server")
		return nil, sid, err
	}
}

func (mgr *ScanCreditManager) getAllAvailableScanners() map[string]share.CLUSScanner {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	ret := map[string]share.CLUSScanner{}

	for id, scanner := range mgr.scannerLoadBalancer.GetActiveScanners() {
		if scanner != nil && scanner.scanner != nil {
			ret[id] = *scanner.scanner
		}
	}

	return ret
}

func (mgr *ScanCreditManager) CountScanners() (busy, idle uint32) {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	for _, s := range mgr.scannerLoadBalancer.GetActiveScanners() {
		if s.availableScanCredits > 0 {
			busy++
		} else {
			idle++
		}
	}
	return busy, idle
}

// This function performs a task on all scanners.
// This would take a while if the task is time-consuming.
func (mgr *ScanCreditManager) RunTaskForEachScanner(cb func(share.ScannerServiceClient) error) error {
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
	client, _, err := ScanCreditMgr.getScannerServiceClient(scanner, false)
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
		return nil, fmt.Errorf("cannot find enforcer endpoint")
	}

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.decScanningCount(scanner)
	if err != nil {
		return nil, err
	}

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
	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.decScanningCount(scanner)
	if err != nil {
		return nil, err
	}

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
		var err error
		scanner, err = ScanCreditMgr.acquireScanCredit()
		if err != nil {
			return nil, err
		}
		shouldIncrementTask = false
		hasAcquiredScanner = true
	}

	// Ensure that resources are properly released or task counts are decremented when the function exits
	defer func() {
		if hasAcquiredScanner {
			// Release the scanner slot back to the availability channel
			ScanCreditMgr.releaseScanCredit(scanner)
		} else {
			// Decrement the active task count for the scanner
			ScanCreditMgr.decScanningCount(scanner)
		}
	}()

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, shouldIncrementTask)
	if err != nil {
		return nil, err
	}

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
	scanner, err := ScanCreditMgr.acquireScanCredit()
	if err != nil {
		return nil, err
	}

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.releaseScanCredit(scanner)
	if err != nil {
		return nil, err
	}

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
	scanner, err := ScanCreditMgr.acquireScanCredit()
	if err != nil {
		return nil, err
	}

	req := &share.ScanAwsLambdaRequest{
		ResType:     share.AwsLambdaFunc,
		FuncName:    funcInput.FuncName,
		Region:      funcInput.Region,
		FuncLink:    funcInput.FuncLink,
		ScanSecrets: true, // default: always
	}

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.releaseScanCredit(scanner)
	if err != nil {
		err := fmt.Errorf("no scan client available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

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
	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.decScanningCount(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetStat(ctx, &share.RPCVoid{})
}

func ScanCacheGetData(scanner string) (*share.ScanCacheDataRes, error) {
	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner, true)
	defer ScanCreditMgr.decScanningCount(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetData(ctx, &share.RPCVoid{})
}
