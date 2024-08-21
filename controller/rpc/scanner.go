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
	scanner  *share.CLUSScanner
	scanning uint32
}

var scanners map[string]*scannerAct = make(map[string]*scannerAct)
var scanMutex sync.RWMutex

func AddScanner(scanner *share.CLUSScanner) {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	scanners[scanner.ID] = &scannerAct{scanner: scanner}
}

func RemoveScanner(scannerID string) {
	scanMutex.Lock()
	s, ok := scanners[scannerID]
	if ok {
		delete(scanners, scannerID)
	}
	scanMutex.Unlock()

	// endpoint is also the key
	if s != nil {
		endpoint := getScannerEndpoint(s.scanner)
		cluster.DeleteGRPCClient(endpoint)
	}
}

func getScannerEndpoint(scanner *share.CLUSScanner) string {
	return fmt.Sprintf("%s:%v", scanner.RPCServer, scanner.RPCServerPort)
}

func createScannerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewScannerServiceClient(conn)
}

func decScanningCount(sid string) {
	scanMutex.RLock()
	defer scanMutex.RUnlock()

	s, ok := scanners[sid]
	if ok && s.scanning > 0 {
		s.scanning--
	}
}

func getScannerServiceClient(sid string, forScan bool) (share.ScannerServiceClient, error) {
	scanMutex.RLock()
	defer scanMutex.RUnlock()

	s, ok := scanners[sid]
	if !ok {
		err := fmt.Errorf("Scanner not found")
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
		return nil, err
	}

	// endpoint is also the key
	endpoint := getScannerEndpoint(s.scanner)
	if cluster.GetGRPCClientEndpoint(endpoint) == "" {
		cluster.CreateGRPCClient(endpoint, endpoint, true, createScannerServiceWrapper)
	}

	c, err := cluster.GetGRPCClient(endpoint, nil, nil)
	if err == nil {
		if forScan {
			s.scanning++
		}
		return c.(share.ScannerServiceClient), nil
	} else {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

func getAllAvailabeScanners() map[string]share.CLUSScanner {
	scanMutex.RLock()
	defer scanMutex.RUnlock()

	ret := map[string]share.CLUSScanner{}

	for id, scanner := range scanners {
		if scanner != nil && scanner.scanner != nil {
			ret[id] = *scanner.scanner
		}
	}

	return ret
}

// This function performs a task on all scanners.
// This would take a while if the task is time-consuming.
func RunTaskForEachScanner(cb func(share.ScannerServiceClient) error) error {
	activeScanners := getAllAvailabeScanners()

	for id, scanner := range activeScanners {
		endpoint := getScannerEndpoint(&scanner)
		if cluster.GetGRPCClientEndpoint(endpoint) == "" {
			cluster.CreateGRPCClient(endpoint, endpoint, true, createScannerServiceWrapper)
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

// scanner can handle multiple requests at a time. It's OK not to check then schedule without lock.
func getAvaliableScanner() string {
	var s *scannerAct

	scanMutex.RLock()
	defer scanMutex.RUnlock()

	// first try to find the idle scanner
	for _, s = range scanners {
		if s.scanning == 0 {
			return s.scanner.ID
		}
	}

	// then locate any scanner
	for _, s = range scanners {
		return s.scanner.ID
	}

	return ""
}

func CountScanners() (busy, idle uint32) {
	scanMutex.RLock()
	defer scanMutex.RUnlock()

	for _, s := range scanners {
		if s.scanning > 0 {
			busy++
		} else {
			idle++
		}
	}
	return busy, idle
}

func Ping(scanner string, timeout time.Duration) error {
	client, err := getScannerServiceClient(scanner, false)
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

	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer decScanningCount(scanner)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := client.ScanRunning(ctx, &share.ScanRunningRequest{
		Type: objType, ID: id, AgentID: agentID, AgentRPCEndPoint: ep,
	})

	clusHelper := kv.GetClusterHelper()
	clusHelper.PutScannerStats(scanner, objType, result)

	return result, err
}

func ScanPlatform(scanner string, k8sVersion, ocVersion string, timeout time.Duration) (*share.ScanResult, error) {
	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer decScanningCount(scanner)

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
	if scanner == "" {
		// This happens when called by ci/cd scan from the REST
		scanner = getAvaliableScanner()
		if scanner == "" {
			err := fmt.Errorf("No scanner available")
			log.WithFields(log.Fields{"error": err}).Error()
			return nil, err
		}
	}

	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer decScanningCount(scanner)

	result, err := client.ScanImage(ctx, req)
	if err == nil {
		if result.Labels == nil {
			// grpc convert zero-length map to nil, fix it here.
			result.Labels = make(map[string]string)
		}
	}

	clusHelper := kv.GetClusterHelper()
	clusHelper.PutScannerStats(scanner, share.ScanObjectType_IMAGE, result)

	return result, err
}

func ScanPackage(ctx context.Context, pkgs []*share.ScanAppPackage) (*share.ScanResult, error) {
	scanner := getAvaliableScanner()
	if scanner == "" {
		err := fmt.Errorf("No scanner available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}
	defer decScanningCount(scanner)

	req := &share.ScanAppRequest{
		Packages: pkgs,
	}

	result, err := client.ScanAppPackage(ctx, req)

	clusHelper := kv.GetClusterHelper()
	clusHelper.PutScannerStats(scanner, share.ScanObjectType_SERVERLESS, result)

	return result, err
}

func ScanAwsLambdaFunc(ctx context.Context, funcInput *share.CLUSAwsFuncScanInput) (*share.ScanResult, error) {
	scanner := getAvaliableScanner()
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

	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		err := fmt.Errorf("No scan client available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}
	defer decScanningCount(scanner)

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
	clusHelper.PutScannerStats(scanner, share.ScanObjectType_SERVERLESS, result)

	return result, err
}

func ScanCacheGetStat(scanner string) (*share.ScanCacheStatRes, error) {
	log.WithFields(log.Fields{"scanner": scanner}).Debug()
	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetStat(ctx, &share.RPCVoid{})
}

func ScanCacheGetData(scanner string) (*share.ScanCacheDataRes, error) {
	client, err := getScannerServiceClient(scanner, true)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	return client.ScanCacheGetData(ctx, &share.RPCVoid{})
}
