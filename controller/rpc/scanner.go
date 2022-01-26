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

var scanners map[string]*share.CLUSScanner = make(map[string]*share.CLUSScanner)
var scanMutex sync.RWMutex

func AddScanner(scanner *share.CLUSScanner) {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	scanners[scanner.ID] = scanner
}

func RemoveScanner(scannerID string) {
	scanMutex.Lock()
	scanner, ok := scanners[scannerID]
	if ok {
		delete(scanners, scannerID)
	}
	scanMutex.Unlock()

	// endpoint is also the key
	if scanner != nil {
		endpoint := getScannerEndpoint(scanner)
		cluster.DeleteGRPCClient(endpoint)
	}
}

func getScannerEndpoint(scanner *share.CLUSScanner) string {
	return fmt.Sprintf("%s:%v", scanner.RPCServer, scanner.RPCServerPort)
}

func createScannerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewScannerServiceClient(conn)
}

func getScannerServiceClient(sid string) (share.ScannerServiceClient, error) {
	scanMutex.RLock()
	scanner, ok := scanners[sid]
	scanMutex.RUnlock()
	if !ok {
		err := fmt.Errorf("Scanner not found")
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error()
		return nil, err
	}

	// endpoint is also the key
	endpoint := getScannerEndpoint(scanner)
	if cluster.GetGRPCClientEndpoint(endpoint) == "" {
		cluster.CreateGRPCClient(endpoint, endpoint, true, createScannerServiceWrapper)
	}

	c, err := cluster.GetGRPCClient(endpoint, nil, nil)
	if err == nil {
		return c.(share.ScannerServiceClient), nil
	} else {
		log.WithFields(log.Fields{"error": err, "scanner": sid}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

func Ping(scanner string, timeout time.Duration) error {
	client, err := getScannerServiceClient(scanner)
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

	client, err := getScannerServiceClient(scanner)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := client.ScanRunning(ctx, &share.ScanRunningRequest{
		Type: objType, ID: id, AgentID: agentID, AgentRPCEndPoint: ep,
	})

	clusHelper := kv.GetClusterHelper()
	clusHelper.PutScannerStats(scanner, objType, result)

	return result, err
}

/*
func ScanImageData(scanner string, data *share.ScanData, timeout time.Duration) (*share.ScanResult, error) {
	client, err := getScannerServiceClient()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return client.ScanImageData(ctx, data)
}
*/

func ScanPlatform(scanner string, k8sVersion, ocVersion string, timeout time.Duration) (*share.ScanResult, error) {
	client, err := getScannerServiceClient(scanner)
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
	if scanner == "" {
		// This happens when called by ci/cd scan from the REST
		var s *share.CLUSScanner
		scanMutex.RLock()
		for _, s = range scanners {
			break
		}
		scanMutex.RUnlock()

		if s == nil {
			err := fmt.Errorf("No scanner available")
			log.WithFields(log.Fields{"error": err}).Error()
			return nil, err
		}

		scanner = s.ID
	}

	client, err := getScannerServiceClient(scanner)
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
	clusHelper.PutScannerStats(scanner, share.ScanObjectType_IMAGE, result)

	return result, err
}

func ScanPackage(ctx context.Context, pkgs []*share.ScanAppPackage) (*share.ScanResult, error) {
	// locate the first scanner
	var scanner *share.CLUSScanner
	scanMutex.RLock()
	for _, scanner = range scanners {
		break
	}
	scanMutex.RUnlock()

	if scanner == nil {
		err := fmt.Errorf("No scanner available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	client, err := getScannerServiceClient(scanner.ID)
	if err != nil {
		return nil, err
	}

	req := &share.ScanAppRequest{
		Packages: pkgs,
	}

	result, err := client.ScanAppPackage(ctx, req)

	clusHelper := kv.GetClusterHelper()
	clusHelper.PutScannerStats(scanner.ID, share.ScanObjectType_SERVERLESS, result)

	return result, err
}

func ScanAwsLambdaFunc(ctx context.Context, funcInput *share.CLUSAwsFuncScanInput) (*share.ScanResult, error) {
	// locate the first scanner
	var scanner *share.CLUSScanner
	scanMutex.RLock()
	for _, scanner = range scanners {
		break
	}
	scanMutex.RUnlock()

	if scanner == nil {
		err := fmt.Errorf("No scanner available")
		log.WithFields(log.Fields{"error": err}).Error()
		return nil, err
	}

	client, err := getScannerServiceClient(scanner.ID)
	if err != nil {
		err := fmt.Errorf("No scan client available")
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
	clusHelper.PutScannerStats(scanner.ID, share.ScanObjectType_SERVERLESS, result)

	return result, err
}
