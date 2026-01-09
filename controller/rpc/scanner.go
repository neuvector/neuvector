package rpc

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

// acquireScannerResult holds the result of a scanner acquisition
type acquireScannerResult struct {
	scannerID string
	err       error
}

// acquireScannerRequest represents a request to acquire a scanner
type acquireScannerRequest struct {
	pullTime     time.Time
	resultChan   chan acquireScannerResult
	attempts     int
	shutdownChan chan struct{}
	backoff      backoff.BackOff
}

// ScannerAcquisitionManager is responsible for managing the scan credit for the scanners.
type ScannerAcquisitionManager struct {
	maxConcurrentScansPerScanner int
	clusterHelper                kv.ClusterHelper
	requestChan                  chan *acquireScannerRequest
	workerStartedOnce            sync.Once
}

var ScannerAcquisitionMgr *ScannerAcquisitionManager

const (
	JitterFactor = 0.2
	BaseDelay    = time.Millisecond * 500
	MaxDelay     = time.Second * 5
)

func NewScannerAcquisitionManager(maxConcurrentScansPerScanner, maxConcurrentRepoScanTasks int, clusterHelper kv.ClusterHelper) *ScannerAcquisitionManager {
	mgr := &ScannerAcquisitionManager{
		maxConcurrentScansPerScanner: maxConcurrentScansPerScanner,
		clusterHelper:                clusterHelper,
		requestChan:                  make(chan *acquireScannerRequest, maxConcurrentRepoScanTasks*2), // Buffer for up to maxConcurrentRepoScanTasks * 2 pending requests,
	}

	mgr.workerStartedOnce.Do(func() {
		go mgr.requestProcessLoop()
	})
	return mgr
}

func (mgr *ScannerAcquisitionManager) GetMaxConcurrentScansPerScanner() int {
	return mgr.maxConcurrentScansPerScanner
}

func (mgr *ScannerAcquisitionManager) GetClusterHelper() kv.ClusterHelper {
	return mgr.clusterHelper
}

func (mgr *ScannerAcquisitionManager) collectPendingRequests() []*acquireScannerRequest {
	pendingRequests := []*acquireScannerRequest{}
	for {
		select {
		case req := <-mgr.requestChan:
			select {
			case <-req.shutdownChan:
				req.resultChan <- acquireScannerResult{err: context.Canceled}
			default:
				pendingRequests = append(pendingRequests, req)
			}
		default:
			return pendingRequests
		}
	}
}

// requestProcessLoop processes scanner acquisition requests in pull-time order
func (mgr *ScannerAcquisitionManager) requestProcessLoop() {
	var pendingRequests []*acquireScannerRequest

	for {
		// If no pending requests, wait for new ones from channel (blocking)
		if len(pendingRequests) == 0 {
			pendingRequests = append(pendingRequests, <-mgr.requestChan)
		}

		pendingRequests = append(pendingRequests, mgr.collectPendingRequests()...)

		// Sort by pullTime to get earliest request first
		slices.SortFunc(pendingRequests, func(req1, req2 *acquireScannerRequest) int {
			return req1.pullTime.Compare(req2.pullTime)
		})

		req := pendingRequests[0]

		// Check if context is still valid
		select {
		case <-req.shutdownChan:
			req.resultChan <- acquireScannerResult{err: context.Canceled}
			pendingRequests = pendingRequests[1:]
			continue
		default:
		}
		scanner, err := mgr.clusterHelper.PickLeastLoadedScanner()

		if err != nil {
			// Retry - add backoff and keep it in queue for next iteration
			req.attempts++
			time.Sleep(req.backoff.NextBackOff())
			continue
		}
		pendingRequests = pendingRequests[1:]
		req.resultChan <- acquireScannerResult{scannerID: scanner.ID, err: nil}
	}
}

// acquireScanner acquires a scanner using priority queue to maintain pull order
func (mgr *ScannerAcquisitionManager) acquireScanner(ctx context.Context) (string, error) {
	// Initialize backoff with default values
	backoff := backoff.NewExponentialBackOff()
	backoff.InitialInterval = BaseDelay
	backoff.MaxInterval = MaxDelay
	backoff.RandomizationFactor = JitterFactor
	backoff.Reset()

	req := &acquireScannerRequest{
		pullTime:     time.Now(),
		resultChan:   make(chan acquireScannerResult, 1),
		attempts:     0,
		shutdownChan: make(chan struct{}),
		backoff:      backoff,
	}
	defer close(req.resultChan)

	mgr.requestChan <- req

	select {
	case result := <-req.resultChan:
		close(req.shutdownChan)
		return result.scannerID, result.err
	case <-ctx.Done():
		close(req.shutdownChan)

		result := <-req.resultChan
		// If the scanner is acquired but timeout, release it.
		if result.scannerID != "" {
			err := mgr.releaseScanner(result.scannerID)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "scanner": result.scannerID}).Error("Failed to release scanner credit in Consul")
			}
		}

		return "", ctx.Err()
	}
}

// releaseScanner releases a scanner and its scan credit.
// Expected outcome: Error if release fails, nil on success.
func (mgr *ScannerAcquisitionManager) releaseScanner(scannerId string) error {
	err := mgr.clusterHelper.ReleaseScanCredit(scannerId, 1)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "scanner": scannerId}).Error("Failed to release scanner credit in Consul")
	}
	return err
}

// CleanUpScannerResources cleans up scanner resources when the cleanup is performed by consul KV.
func (mgr *ScannerAcquisitionManager) CleanUpScannerResources(scanner *share.CLUSScanner) {
	endpoint := mgr.getScannerEndpoint(scanner)
	cluster.DeleteGRPCClient(endpoint)
}

func (mgr *ScannerAcquisitionManager) getScannerEndpoint(scanner *share.CLUSScanner) string {
	return net.JoinHostPort(scanner.RPCServer, strconv.Itoa(int(scanner.RPCServerPort)))
}

func (mgr *ScannerAcquisitionManager) createScannerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewScannerServiceClient(conn)
}

func (mgr *ScannerAcquisitionManager) getScannerServiceClient(sid string) (share.ScannerServiceClient, string, error) {
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

func (mgr *ScannerAcquisitionManager) getAllAvailableScanners() map[string]share.CLUSScanner {
	ret := map[string]share.CLUSScanner{}

	for _, scanner := range mgr.clusterHelper.GetAvailableScanners() {
		ret[scanner.ID] = scanner
	}

	return ret
}

func (mgr *ScannerAcquisitionManager) CountScanners() (busy, idle uint32) {
	for _, scanner := range mgr.clusterHelper.GetAvailableScanners() {
		if scanner.ScanCredit <= 0 {
			busy++
		} else {
			idle++
		}
	}
	return busy, idle
}

// This function performs a task on all scanners.
// This would take a while if the task is time-consuming.
func (mgr *ScannerAcquisitionManager) RunTaskForEachScanner(cb func(share.ScannerServiceClient) error) error {
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

func (mgr *ScannerAcquisitionManager) Ping(scanner string, timeout time.Duration) error {
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

	client, scanner, err := ScannerAcquisitionMgr.getScannerServiceClient(scanner)
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
	client, _, err := ScannerAcquisitionMgr.getScannerServiceClient(scanner)
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
	// When scanner is empty, it indicates that the CI plugins are calling the scan.
	// In this case, we set shouldIncrementTask to false to avoid double counting.
	if scanner == "" {
		var err error
		scanner, err = ScannerAcquisitionMgr.acquireScanner(ctx)
		if err != nil {
			// Return result with error code to enable retry mechanism in REST API
			return &share.ScanResult{Error: share.ScanErrorCode_ScanErrAcquireScannerTimeout}, err
		}

		// Ensure that resources are properly released or task counts are decremented when the function exits
		defer func() {
			if err := ScannerAcquisitionMgr.releaseScanner(scanner); err != nil {
				log.WithFields(log.Fields{"error": err, "scanner": scanner}).Error("failed to release scan credit")
			}
		}()
	}

	client, scanner, err := ScannerAcquisitionMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	result, err := client.ScanImage(ctx, req)
	if err == nil {
		if result == nil {
			return nil, fmt.Errorf("scan image returned nil result from scanner %s", scanner)
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

func ScanCacheGetStat(scanner string) (*share.ScanCacheStatRes, error) {
	log.WithFields(log.Fields{"scanner": scanner}).Debug()
	client, _, err := ScannerAcquisitionMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetStat(ctx, &share.RPCVoid{})
}

func ScanCacheGetData(scanner string) (*share.ScanCacheDataRes, error) {
	client, _, err := ScannerAcquisitionMgr.getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetData(ctx, &share.RPCVoid{})
}
