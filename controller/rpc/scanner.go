package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

// ScanCreditManager is responsible for managing the scan credit for the scanners.
type ScanCreditManager struct {
	maxConcurrentScansPerScanner int
	creditPool                   chan struct{}
	scannerHealthChecker         ScannerHealthCheckFunc
	clusterHelper                kv.ClusterHelper
}

const acquireScanCreditTimeout = time.Minute * 3

var (
	ScanCreditMgr         *ScanCreditManager
	ErrNoScannerAvailable = errors.New("no scanner available")
	ErrNoScannerFound     = errors.New("no scanner found")
)

// ScannerHealthCheckFunc defines the signature for a scanner health check function
// It pings a scanner to verify it's available before assigning scan tasks to it
type ScannerHealthCheckFunc func(scannerID string, timeout time.Duration) error

func NewScanCreditManager(maxConcurrentScansPerScanner, maxExpectedScanners int) *ScanCreditManager {
	mgr := &ScanCreditManager{
		maxConcurrentScansPerScanner: maxConcurrentScansPerScanner,
		// maxExpectedScanners * (maxConcurrentScansPerScanner + 1) ensures that the creditPool channel
		// has sufficient capacity to handle task signals without blocking.
		creditPool:    make(chan struct{}, maxExpectedScanners*(maxConcurrentScansPerScanner+1)),
		clusterHelper: kv.GetClusterHelper(),
	}
	mgr.SetScannerHealthChecker(mgr.Ping)
	return mgr
}

func (mgr *ScanCreditManager) SetScannerHealthChecker(healthChecker ScannerHealthCheckFunc) {
	mgr.scannerHealthChecker = healthChecker
}

func (mgr *ScanCreditManager) GetMaxConcurrentScansPerScanner() int {
	return mgr.maxConcurrentScansPerScanner
}

func (mgr *ScanCreditManager) releaseScanCredit(sid string) error {
	err := mgr.clusterHelper.ReleaseScanCredit(sid)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
	} else {
		mgr.signalScanCredit()
	}
	return err
}

// acquireScanCredit continuously checks for an available scanner with fewer active tasks than the maximum allowed.
func (mgr *ScanCreditManager) acquireScanCredit() (string, error) {
	for {
		// Wait for a scanner to become available or timeout to avoid indefinite blocking
		select {
		case <-mgr.creditPool:
			// Use helper to find the scanner with the least active tasks
			scanner, err := mgr.clusterHelper.PickLeastLoadedScanner(mgr.scannerHealthChecker)
			if err != nil {

				if errors.Is(err, share.ErrNoScannerAvailable) ||
					errors.Is(err, share.ErrNoScannerFound) {
					// This is expected when all scanners are busy - log at debug level
					log.WithFields(log.Fields{"error": err}).Debug("Failed to pick scanner, will retry")
				} else {
					log.WithFields(log.Fields{"error": err}).Warn("Failed to pick scanner, will retry")
				}

				// Put the token back to creditPool since we didn't successfully acquire a scanner
				mgr.signalScanCredit()
				continue
			}
			return scanner.ID, nil
		case <-time.After(acquireScanCreditTimeout):
			return "", fmt.Errorf("timeout waiting for available scanner after %v", acquireScanCreditTimeout)
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
	// Signal availability for this scanner's maximum allowed connections
	for i := 0; i < scanner.MaxConcurrentScansPerScanner; i++ {
		mgr.signalScanCredit()
	}
}

func (mgr *ScanCreditManager) RemoveScanner(scannerID string) error {
	// Ensure the grpc client is deleted
	scanner, _, err := mgr.clusterHelper.GetScannerRev(scannerID)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": scannerID}).Error()
		return err
	}
	endpoint := mgr.getScannerEndpoint(scanner)
	cluster.DeleteGRPCClient(endpoint)

	err = mgr.clusterHelper.DeleteScanner(scannerID)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": scannerID}).Error()
		return err
	}
	availableSlots := max(0, scanner.ScanCredit)
	// Drain availableSlots tokens from creditPool to maintain balance
	for i := 0; i < availableSlots; i++ {
		select {
		case <-mgr.creditPool:
			// Successfully drained one slot
		default:
			// No more slots to drain;
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

func (mgr *ScanCreditManager) getScannerServiceClient(sid string) (share.ScannerServiceClient, string, error) {
	// Get scanner from KV store
	scanner, _, err := mgr.clusterHelper.GetScannerRev(sid)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
		return nil, sid, err
	}

	// endpoint is also the key
	endpoint := mgr.getScannerEndpoint(scanner)
	if cluster.GetGRPCClientEndpoint(endpoint) == "" {
		if err := cluster.CreateGRPCClient(endpoint, endpoint, true, mgr.createScannerServiceWrapper); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CreateGRPCClient")
		}
	}

	c, err := cluster.GetGRPCClient(endpoint, nil, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error("Failed to connect to grpc server")
		return nil, sid, err
	}
	return c.(share.ScannerServiceClient), sid, nil
}

func (mgr *ScanCreditManager) getAllAvailableScanners() map[string]share.CLUSScanner {
	ret := map[string]share.CLUSScanner{}

	for _, scanner := range mgr.clusterHelper.GetAvailableScanners() {
		ret[scanner.ID] = *scanner
	}

	return ret
}

func (mgr *ScanCreditManager) CountScanners() (busy, idle uint32) {
	for _, scanner := range mgr.clusterHelper.GetAvailableScanners() {
		if scanner.ScanCredit > 0 {
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

func (mgr *ScanCreditManager) Ping(scanner string, timeout time.Duration) error {
	client, _, err := mgr.getScannerServiceClient(scanner)
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

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner)
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
	client, _, err := ScanCreditMgr.getScannerServiceClient(scanner)
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

// ScanImage can  come from CI plugins or from the scanner service.
func ScanImage(scanner string, ctx context.Context, req *share.ScanImageRequest) (*share.ScanResult, error) {
	hasAcquiredScanner := false

	// When scanner is empty, it indicates that the CI plugins are calling the scan.
	// In this case, we set shouldIncrementTask to false to avoid double counting.
	if scanner == "" {
		var err error
		scanner, err = ScanCreditMgr.acquireScanCredit()
		if err != nil {
			return nil, err
		}
		hasAcquiredScanner = true
	}

	// Ensure that resources are properly released or task counts are decremented when the function exits
	if hasAcquiredScanner {
		defer func() {
			if err := ScanCreditMgr.releaseScanCredit(scanner); err != nil {
				log.WithFields(log.Fields{"error": err, "scanner": scanner}).Error("failed to release scan credit")
			}
		}()
	}

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	result, err := client.ScanImage(ctx, req)
	if err == nil {
		if result == nil {
			return nil, fmt.Errorf("scan image returned nil result")
		}

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

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner)
	defer func() {
		if err := ScanCreditMgr.releaseScanCredit(scanner); err != nil {
			log.WithFields(log.Fields{"error": err, "scanner": scanner}).Error("failed to release scan credit")
		}
	}()
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

	client, scanner, err := ScanCreditMgr.getScannerServiceClient(scanner)
	defer func() {
		if err := ScanCreditMgr.releaseScanCredit(scanner); err != nil {
			log.WithFields(log.Fields{"error": err, "scanner": scanner}).Error("failed to release scan credit")
		}
	}()
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
	client, _, err := ScanCreditMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetStat(ctx, &share.RPCVoid{})
}

func ScanCacheGetData(scanner string) (*share.ScanCacheDataRes, error) {
	client, _, err := ScanCreditMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetData(ctx, &share.RPCVoid{})
}
