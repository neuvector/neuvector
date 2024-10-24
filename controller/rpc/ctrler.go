package rpc

import (
	"context"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

func getKeyForControllerService(ip string) string {
	return "ctrl:" + ip
}

func createControllerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerCtrlServiceClient(conn)
}

func createControllerServerDest(ip string, port uint16) {
	endpoint := fmt.Sprintf("%s:%v", ip, port)
	key := getKeyForControllerService(ip)
	if err := cluster.CreateGRPCClient(key, endpoint, true, createControllerServiceWrapper); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("CreateGRPCClient")
	}
}

func getControllerServiceClient(ip string, port uint16) (share.ControllerCtrlServiceClient, error) {
	key := getKeyForControllerService(ip)
	if cluster.GetGRPCClientEndpoint(key) == "" {
		createControllerServerDest(ip, port)
	}

	c, err := cluster.GetGRPCClient(key, cluster.IsControllerGRPCCommpressed, nil)
	if err == nil {
		return c.(share.ControllerCtrlServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

func ReqSync(ip string, port uint16, category, from string) (*share.CLUSSyncReply, error) {
	log.WithFields(log.Fields{"target": ip, "sync": category}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.ReqSync(ctx, &share.CLUSSyncRequest{
		Category: category,
		From:     from,
	})
}

func ReqSyncStream(ip string, port uint16, category, from string) (*share.CLUSSyncReply, error) {
	log.WithFields(log.Fields{"target": ip, "sync": category}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	stream, err := client.ReqSyncStream(ctx, &share.CLUSSyncRequest{
		Category: category,
		From:     from,
	})
	if err != nil {
		return nil, err
	}

	reply := &share.CLUSSyncReply{Category: category, Data: make([]byte, 0)}
	for {
		if out, err := stream.Recv(); err == io.EOF {
			break
		} else if err != nil {
			// Could be DeadlineExceeded
			return nil, err
		} else {
			reply.Data = append(reply.Data, out.Data...)
		}
	}

	return reply, nil
}

func ReportConnections(ip string, port uint16, conns []*share.CLUSConnection) (*share.RPCVoid, error) {
	// log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	for i := 0; i < 3; i++ {
		_, err = client.ReportConnections(ctx, &share.CLUSConnectionArray{Connections: conns})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
		} else {
			break
		}
	}
	return &share.RPCVoid{}, err
}

func GetControllerCounter(ip string, port uint16) (*share.CLUSControllerCounter, error) {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetControllerCounter(ctx, &share.RPCVoid{})
}

func DeleteConversation(ip string, port uint16, ops *share.CLUSGraphOps) error {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.DeleteConversation(ctx, ops)
	return err
}

func DeleteEndpoint(ip string, port uint16, ops *share.CLUSGraphOps) error {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.DeleteEndpoint(ctx, ops)
	return err
}

func SetEndpointAlias(ip string, port uint16, ops *share.CLUSGraphOps) error {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.SetEndpointAlias(ctx, ops)
	return err
}

func CheckPolicySyncStatus(ip string, port uint16) (*share.CLUSPolicySyncStatus, error) {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.CheckPolicySyncStatus(ctx, &share.RPCVoid{})
}

func TriggerSync(ip string, port uint16) error {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.TriggerSync(ctx, &share.RPCVoid{})
	return err
}

func ProfileController(ip string, port uint16, req *share.CLUSProfilingRequest) error {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.ProfilingCmd(ctx, req)
	return err
}

func TriggerSyncLearnedPolicy(ip string, port uint16) error {
	//log.WithFields(log.Fields{"target": ip, "port":port,}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.TriggerSyncLearnedPolicy(ctx, &share.RPCVoid{})
	return err
}

func PauseResumeStoreWatcher(ip string, port uint16, req share.CLUSStoreWatcherInfo) error {
	//log.WithFields(log.Fields{"target": ip, "port":port,}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.PauseResumeStoreWatcher(ctx, &req)
	return err
}

func KickLoginSessions(ip string, port uint16, req share.CLUSKickLoginSessionsRequest) error {
	//log.WithFields(log.Fields{"target": ip, "port":port,}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.KickLoginSessions(ctx, &req)
	return err
}

func GetControllerStat(ip string, port uint16) (*share.CLUSStats, error) {
	log.WithFields(log.Fields{"target": ip}).Debug("")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetStats(ctx, &share.RPCVoid{})
}

func ResetLoginTokenTimer(ip string, port uint16, req share.CLUSLoginTokenInfo) error {
	log.WithFields(log.Fields{"target": ip, "port": port}).Debug()

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.ResetLoginTokenTimer(ctx, &req)
	return err

}

func ReportK8SResToOPA(ip string, port uint16, req share.CLUSKubernetesResInfo) error {
	log.WithFields(log.Fields{"target": ip, "port": port}).Debug("rpc.ReportK8SResToOPA")

	client, err := getControllerServiceClient(ip, port)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.ReportK8SResToOPA(ctx, &req)
	return err

}
