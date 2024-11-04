package rpc

import (
	"context"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

const pcapHeaderLen = 24

func getKeyForEnforcerService(id string) string {
	return id
}

func createEnforcerServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewEnforcerServiceClient(conn)
}

func CreateEnforcerServerDest(id string, ip string, port uint16) {
	endpoint := fmt.Sprintf("%s:%v", ip, port)
	key := getKeyForEnforcerService(id)
	if err := cluster.CreateGRPCClient(key, endpoint, false, createEnforcerServiceWrapper); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("CreateGRPCClient")
	}
}

func RemoveEnforcerServerDest(id string) {
	key := getKeyForEnforcerService(id)
	cluster.DeleteGRPCClient(key)
}

func findEnforcerServerEndpoint(id string) string {
	key := getKeyForEnforcerService(id)
	return cluster.GetGRPCClientEndpoint(key)
}

func findEnforcerServiceClient(id string) (share.EnforcerServiceClient, error) {
	key := getKeyForEnforcerService(id)
	c, err := cluster.GetGRPCClient(key, cluster.IsEnforcerGRPCCommpressed, nil)
	if err == nil {
		return c.(share.EnforcerServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

const defaultReqTimeout = time.Second * 8

func Kick(agentID string, ctrlID string, reason string) error {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.Kick(ctx, &share.CLUSKick{CtrlID: ctrlID, Reason: reason})
	return err
}

func GetMeterList(agentID string, f *share.CLUSFilter) ([]*share.CLUSMeter, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	stream, err := client.GetMeterList(ctx, f)
	if err != nil {
		return nil, err
	}

	list := make([]*share.CLUSMeter, 0)
	for {
		if out, err := stream.Recv(); err == io.EOF {
			break
		} else if err != nil {
			// Could be DeadlineExceeded
			return nil, err
		} else {
			list = append(list, out.Meters...)
		}
	}

	return list, nil
}

func GetSessionList(agentID string, f *share.CLUSFilter) ([]*share.CLUSSession, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	stream, err := client.GetSessionList(ctx, f)
	if err != nil {
		return nil, err
	}

	list := make([]*share.CLUSSession, 0)
	for {
		if out, err := stream.Recv(); err == io.EOF {
			break
		} else if err != nil {
			// Could be DeadlineExceeded
			return nil, err
		} else {
			list = append(list, out.Sessions...)
		}
	}

	return list, nil
}

func ClearSession(agentID string, f *share.CLUSFilter) error {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.ClearSession(ctx, f)
	return err
}

func GetStats(agentID string, f *share.CLUSFilter) (*share.CLUSStats, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetStats(ctx, f)
}

func GetGroupStats(agentID string, f *share.CLUSWlIDArray) (*share.CLUSStats, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetGroupStats(ctx, f)
}

func GetSessionCounter(agentID string) (*share.CLUSSessionCounter, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetSessionCounter(ctx, &share.RPCVoid{})
}

func GetDatapathCounter(agentID string) (*share.CLUSDatapathCounter, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetDatapathCounter(ctx, &share.RPCVoid{})
}

func GetDerivedPolicyRules(agentID string, f *share.CLUSFilter) (*share.CLUSDerivedPolicyRuleMap, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetDerivedPolicyRules(ctx, f)
}

func ProbeSummary(agentID string) (*share.CLUSProbeSummary, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.ProbeSummary(ctx, &share.RPCVoid{})
}

func ProbeProcessMap(agentID string) ([]*share.CLUSProbeProcess, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	if res, err := client.ProbeProcessMap(ctx, &share.RPCVoid{}); err != nil {
		return nil, err
	} else {
		return res.Processes, err
	}
}

func ProbeContainerMap(agentID string) ([]*share.CLUSProbeContainer, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	if res, err := client.ProbeContainerMap(ctx, &share.RPCVoid{}); err != nil {
		return nil, err
	} else {
		return res.Containers, err
	}
}

func SnifferCmd(agentID string, req *share.CLUSSnifferRequest) (*share.CLUSSnifferResponse, error) {
	log.WithFields(log.Fields{"agent": agentID}).Debug("")
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.SnifferCmd(ctx, req)
}

func GetSniffers(agentID string, f *share.CLUSSnifferFilter) ([]*share.CLUSSniffer, error) {
	log.WithFields(log.Fields{"agent": agentID, "workload": f.Workload, "id": f.ID}).Debug("")
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	res, err := client.GetSniffers(ctx, f)
	if err != nil {
		return nil, err
	}
	return res.Sniffers, nil
}

func GetSnifferPcap(agentID string, id string, limit int) ([]byte, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	// TODO: how to set overall timeout and per chunk timeout
	pcapReqTimeout := time.Duration(limit/(1024*1024)) * defaultReqTimeout
	ctx, cancel := context.WithTimeout(context.Background(), pcapReqTimeout)
	defer cancel()

	req := &share.CLUSSnifferDownload{ID: id}
	stream, err := client.GetSnifferPcap(ctx, req)
	if err != nil {
		return nil, err
	}

	var byteRcv int
	pcapBuf := make([]byte, 0)
	var pcapStart int
	for {
		if out, err := stream.Recv(); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else if len(out.Pcap) > pcapStart {
			pcapBuf = append(pcapBuf, out.Pcap[pcapStart:]...)
			byteRcv += len(out.Pcap[pcapStart:])
			if byteRcv >= limit {
				break
			}
			//skip the pcap header after the first one
			pcapStart = pcapHeaderLen
		}
	}

	return pcapBuf, nil
}

func GetContainerLogs(agentID, id string, start, limit int) ([]byte, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	//calculate a rough timeout,1MB's timeout is 4 second, 100 bytes per line
	mb := limit*100/(1024*1024) + 1
	logReqTimeout := time.Duration(mb) * defaultReqTimeout
	ctx, cancel := context.WithTimeout(context.Background(), logReqTimeout)
	defer cancel()

	f := &share.CLUSContainerLogReq{
		Id:    id,
		Start: int32(start),
		Limit: uint32(limit),
	}

	stream, err := client.GetContainerLogs(ctx, f)
	if err != nil {
		return nil, err
	}

	logBuf := make([]byte, 0)
	for {
		if out, err := stream.Recv(); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else {
			logBuf = append(logBuf, out.LogZb...)
		}
	}
	return logBuf, nil
}

func RunDockerBench(agentID string) error {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.RunDockerBench(ctx, &share.RPCVoid{})
	return err
}

func RunKubernetesBench(agentID string) error {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.RunKubernetesBench(ctx, &share.RPCVoid{})
	return err
}

func GetFileMonitorFile(agentID string, f *share.CLUSFilter) ([]*share.CLUSFileMonitorFile, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	if file, err := client.GetFileMonitorFile(ctx, f); err != nil {
		return nil, err
	} else {
		return file.Files, err
	}
}

func GetProcess(agentID, id string) ([]*share.CLUSProcess, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	f := &share.CLUSFilter{Workload: id}
	if procs, err := client.GetProcess(ctx, f); err != nil {
		return nil, err
	} else {
		return procs.Processes, err
	}
}

func GetProcessHistory(agentID, id string) ([]*share.CLUSProcess, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	f := &share.CLUSFilter{Workload: id}
	if procs, err := client.GetProcessHistory(ctx, f); err != nil {
		return nil, err
	} else {
		return procs.Processes, err
	}
}

func GetDerivedDlpRules(agentID string, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleMap, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetDerivedDlpRules(ctx, f)
}

func GetDerivedDlpRuleEntries(agentID string, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleEntryArray, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetDerivedDlpRuleEntries(ctx, f)
}

func GetDerivedDlpRuleMacs(agentID string, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleMacArray, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	return client.GetDerivedDlpRuleMacs(ctx, f)
}

func GetDerivedWorkloadProcessRule(agentID, id string) ([]*share.CLUSDerivedProcessRule, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	f := &share.CLUSFilter{Workload: id}
	if profile, err := client.GetDerivedWorkloadProcessRule(ctx, f); err != nil {
		return nil, err
	} else {
		return profile.Rules, nil
	}
}

func GetDerivedWorkloadFileRule(agentID, id string) ([]*share.CLUSDerivedFileRule, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	f := &share.CLUSFilter{Workload: id}
	if profile, err := client.GetDerivedWorkloadFileRule(ctx, f); err != nil {
		return nil, err
	} else {
		return profile.Rules, nil
	}
}

func GetContainerIntercept(agentID, id string) (*share.CLUSWorkloadIntercept, error) {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	f := &share.CLUSFilter{Workload: id}
	if ci, err := client.GetContainerIntercept(ctx, f); err != nil {
		return nil, err
	} else {
		return ci, nil
	}
}

func ProfileEnforcer(agentID string, req *share.CLUSProfilingRequest) error {
	client, err := findEnforcerServiceClient(agentID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
	defer cancel()

	_, err = client.ProfilingCmd(ctx, req)
	return err
}
