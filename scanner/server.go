package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

func createEnforcerScanServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewEnforcerScanServiceClient(conn)
}

func findEnforcerServiceClient(ep string) (share.EnforcerScanServiceClient, error) {
	if cluster.GetGRPCClientEndpoint(ep) == "" {
		cluster.CreateGRPCClient(ep, ep, true, createEnforcerScanServiceWrapper)
	}
	c, err := cluster.GetGRPCClient(ep, nil, nil)
	if err == nil {
		return c.(share.EnforcerScanServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

type rpcService struct {
}

func (rs *rpcService) Ping(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	return &share.RPCVoid{}, nil
}

func (rs *rpcService) ScanRunning(ctx context.Context, req *share.ScanRunningRequest) (*share.ScanResult, error) {
	var result *share.ScanResult

	log.WithFields(log.Fields{"id": req.ID, "type": req.Type, "agent": req.AgentRPCEndPoint}).Debug("")

	client, err := findEnforcerServiceClient(req.AgentRPCEndPoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to connect to agent")

		result = &share.ScanResult{Version: cveTools.CveDBVersion, CVEDBCreateTime: cveTools.CveDBCreateTime, Error: share.ScanErrorCode_ScanErrNetwork}
		return result, nil
	}

	data, err := client.ScanGetFiles(ctx, req)
	if ctx.Err() != nil { // context.Canceled: remote cancelled
		// no timeout is set for (enforcer <-> scanner)
		// however, 60 sec timeout is set for (controller <-> scanner), and 5 restries from controller
		// wait for next pulling from ctl and it should return the cache results from enforcer immediately
		log.WithFields(log.Fields{"id": req.ID}).Debug("session expired")
		return nil, nil
	}

	if data != nil && err == nil {
		// actual result from enforcer with only 3 conditions
		switch data.Error {
		case share.ScanErrorCode_ScanErrContainerExit: // no longer live
			result = &share.ScanResult{Version: cveTools.CveDBVersion, CVEDBCreateTime: cveTools.CveDBCreateTime, Error: data.Error}
			return result, nil
		case share.ScanErrorCode_ScanErrInProgress: // in progress
			return nil, nil
		case share.ScanErrorCode_ScanErrNone: // a good result within time, proceed to scan procedure
		}
	} else if data == nil {
		// rpc request not made
		log.WithFields(log.Fields{"error": err}).Error("Fail to make rpc call")
		result = &share.ScanResult{Version: cveTools.CveDBVersion, CVEDBCreateTime: cveTools.CveDBCreateTime, Error: share.ScanErrorCode_ScanErrNetwork}
		return result, nil
	} else if err != nil || data.Error != share.ScanErrorCode_ScanErrNone {
		log.WithFields(log.Fields{"error": err}).Error("Fail to read files")
		result = &share.ScanResult{Version: cveTools.CveDBVersion, CVEDBCreateTime: cveTools.CveDBCreateTime, Error: data.Error}
		return result, nil
	}

	log.WithFields(log.Fields{"id": req.ID, "type": req.Type}).Debug("File read done")
	if scanTasker != nil {
		return scanTasker.Run(ctx, *data)
	}
	return cveTools.ScanImageData(data)
}

func (rs *rpcService) ScanImageData(ctx context.Context, data *share.ScanData) (*share.ScanResult, error) {
	log.Debug("")
	if scanTasker != nil {
		return scanTasker.Run(ctx, *data)
	}
	return cveTools.ScanImageData(data)
}

func (rs *rpcService) ScanImage(ctx context.Context, req *share.ScanImageRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{
		"Registry": req.Registry, "image": fmt.Sprintf("%s:%s", req.Repository, req.Tag),
	}).Debug()

	if scanTasker != nil {
		return scanTasker.Run(ctx, *req)
	}
	return cveTools.ScanImage(ctx, req, "")
}

func (rs *rpcService) ScanAppPackage(ctx context.Context, req *share.ScanAppRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"Packages": req.Packages}).Debug("")
	if scanTasker != nil {
		return scanTasker.Run(ctx, *req)
	}
	return cveTools.ScanAppPackage(req, "")
}

func (rs *rpcService) ScanAwsLambda(ctx context.Context, req *share.ScanAwsLambdaRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"LambdaFunc": req.FuncName}).Debug("")
	if scanTasker != nil {
		return scanTasker.Run(ctx, *req)
	}
	return cveTools.ScanAwsLambda(req, "")
}

func startGRPCServer() *cluster.GRPCServer {
	var grpc *cluster.GRPCServer
	var err error

	port := cluster.DefaultScannerGRPCPort

	log.WithFields(log.Fields{"port": port}).Info("")
	for {
		grpc, err = cluster.NewGRPCServerTCP(fmt.Sprintf(":%d", port))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}

	svc := new(rpcService)
	share.RegisterScannerServiceServer(grpc.GetServer(), svc)
	go grpc.Start()

	log.Info("GRPC server started")
	return grpc
}

const controller string = "controller"

func createControllerScanServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerScanServiceClient(conn)
}

func getControllerServiceClient(joinIP string, joinPort uint16, cb cluster.GRPCCallback) (share.ControllerScanServiceClient, error) {
	if cluster.GetGRPCClientEndpoint(controller) == "" {
		ep := fmt.Sprintf("%s:%v", joinIP, joinPort)
		cluster.CreateGRPCClient(controller, ep, true, createControllerScanServiceWrapper)
	}
	c, err := cluster.GetGRPCClient(controller, nil, cb)
	if err == nil {
		return c.(share.ControllerScanServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

type clientCallback struct {
	shutCh         chan interface{}
	ignoreShutdown bool
}

func (cb *clientCallback) Shutdown() {
	log.Debug()
	if !cb.ignoreShutdown {
		cb.shutCh <- nil
	}
}

const cvedbChunkMax = 32 * 1024

func scannerRegisterStream(ctx context.Context, client share.ControllerScanServiceClient, data *share.ScannerRegisterData) error {
	stream, err := client.ScannerRegisterStream(ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get stream")
		return errors.New("Failed to  to controller")
	}

	// send a block without data to test if stream API is supported
	cvedb := data.CVEDB
	defer func() {
		data.CVEDB = cvedb
	}()

	data.CVEDB = make(map[string]*share.ScanVulnerability)
	err = stream.Send(data)
	if err == io.EOF {
		log.Info("Stream register API is not supported")
		return errors.New("Stream register API is not supported")
	} else if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to send")
		return err
	}

	// clone the cvedb
	clone := make(map[string]*share.ScanVulnerability, len(cvedb))
	for k, v := range cvedb {
		clone[k] = v
	}

	for {
		var count int

		if len(clone) > cvedbChunkMax {
			count = cvedbChunkMax
		} else {
			count = len(clone)
		}

		send := make(map[string]*share.ScanVulnerability, count)

		for k, v := range clone {
			send[k] = v
			delete(clone, k)

			count--
			if count == 0 {
				break
			}
		}

		log.WithFields(log.Fields{"entries": len(send)}).Info("Stream send")

		data.CVEDB = send
		err = stream.Send(data)
		if err == io.EOF {
			log.Info("Stream register API is not supported")
			return errors.New("Stream register API is not supported")
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to send")
			return err
		}

		if len(clone) == 0 {
			break
		}
	}

	log.Info("Stream send done")
	if _, err = stream.CloseAndRecv(); err != nil && err != io.EOF {
		log.WithFields(log.Fields{"error": err}).Error("Failed to close")
		return err
	}

	return nil
}

func scannerRegister(joinIP string, joinPort uint16, data *share.ScannerRegisterData, cb cluster.GRPCCallback) error {
	log.WithFields(log.Fields{
		"join": fmt.Sprintf("%s:%d", joinIP, joinPort), "version": data.CVEDBVersion, "entries": len(data.CVEDB),
	}).Debug()

	client, err := getControllerServiceClient(joinIP, joinPort, cb)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return errors.New("Failed to connect to controller")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	if err = scannerRegisterStream(ctx, client, data); err == nil {
		return nil
	}

	_, err = client.ScannerRegister(ctx, data)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to register")
		return errors.New("Failed to send register request")
	}
	return nil
}

func scannerDeregister(joinIP string, joinPort uint16, id string) error {
	log.Debug()

	client, err := getControllerServiceClient(joinIP, joinPort, nil)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return errors.New("Failed to connect to controller")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, err = client.ScannerDeregister(ctx, &share.ScannerDeregisterData{ID: id})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to deregister")
		return errors.New("Failed to send deregister request")
	}
	return nil
}
