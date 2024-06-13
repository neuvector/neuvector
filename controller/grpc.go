package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/httpclient"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const scanImageDataTimeout = time.Second * 45
const repoScanTimeout = time.Minute * 20

type ScanService struct {
}

// Previously, to minimize data size, only the basic info is returned by scanner and saved in the kv store.
// This is problematic, because if a cve of an OS is gone, previously scanned result will be missing metadata.
// So, we build a meta data map with the CVE name as key. These data are from NVD anyway.
func (ss *ScanService) preprocessDB(data *share.ScannerRegisterData) map[string]*share.ScanVulnerability {
	cvedb := make(map[string]*share.ScanVulnerability)
	for name, cve := range data.CVEDB {
		if s := strings.Index(name, ":"); s != -1 {
			n := name[s+1:]
			cvedb[n] = &share.ScanVulnerability{
				Name:             n,
				Description:      cve.Description,
				Link:             cve.Link,
				Score:            cve.Score,
				Vectors:          cve.Vectors,
				ScoreV3:          cve.ScoreV3,
				VectorsV3:        cve.VectorsV3,
				PublishedDate:    cve.PublishedDate,
				LastModifiedDate: cve.LastModifiedDate,
			}
		}
		cvedb[name] = cve
	}
	return cvedb
}

func (ss *ScanService) prepareDBSlots(data *share.ScannerRegisterData, cvedb map[string]*share.ScanVulnerability) ([][]byte, error) {
	// As of now, Feb. 2019, the compressed db size is 3M, while max kv value size is 512K.
	for slots := 128; slots <= 256; slots *= 2 {
		log.WithFields(log.Fields{"slots": slots}).Debug()

		enlarge := false
		dbs := make([]*share.CLUSScannerDB, slots)
		zbs := make([][]byte, slots)
		for i, _ := range dbs {
			dbs[i] = &share.CLUSScannerDB{
				CVEDBVersion:    data.CVEDBVersion,
				CVEDBCreateTime: data.CVEDBCreateTime,
				CVEDB:           make(map[string]*share.ScanVulnerability),
			}
		}

		// hash db to slots
		for name, cve := range cvedb {
			cve.Name = name // fix the record
			i := utils.HashStringToInt32(cve.Name, slots)
			dbs[i].CVEDB[cve.Name] = cve
		}

		for i, db := range dbs {
			value, _ := json.Marshal(db)
			zb := utils.GzipBytes(value)
			log.WithFields(log.Fields{"slot": i, "size": len(zb)}).Debug()
			if len(zb) >= cluster.KVValueSizeMax {
				enlarge = true
				break
			}
			zbs[i] = zb
		}

		if !enlarge {
			return zbs, nil
		}
	}

	return nil, errors.New("Database is too large")
}

func (ss *ScanService) registerFailureCleanup(newDBStore string) {
	// Remove new keys that have been written
	newKeys, _ := cluster.GetStoreKeys(newDBStore)
	for _, key := range newKeys {
		cluster.Delete(key)
	}
}

func (ss *ScanService) ScannerRegisterStream(stream share.ControllerScanService_ScannerRegisterStreamServer) error {
	var data *share.ScannerRegisterData

	for {
		r, err := stream.Recv()
		if err == io.EOF {
			log.Info("Stream receive done")
			break
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Receive error")
			return err
		}
		if data == nil {
			data = r
			// When sender sends an empty map, the receiver gets nil
			if data.CVEDB == nil {
				data.CVEDB = make(map[string]*share.ScanVulnerability)
			}
		} else {
			log.WithFields(log.Fields{"entries": len(r.CVEDB)}).Info("Stream receive")
			for k, v := range r.CVEDB {
				data.CVEDB[k] = v
			}
		}
	}

	return ss.scannerRegister(data)
}

func (ss *ScanService) ScannerRegister(ctx context.Context, data *share.ScannerRegisterData) (*share.RPCVoid, error) {
	if err := ss.scannerRegister(data); err == nil {
		return &share.RPCVoid{}, nil
	} else {
		return nil, err
	}
}

// HealthCheck checks if the scanner is in the list of controller Consul key-value pairs and if the controller is alive
// This function follows the logic from how scannerRegister function puts the scanner into the KV store to retrieve it.
func (ss *ScanService) HealthCheck(ctx context.Context, data *share.ScannerRegisterData) (*share.ScannerAvailable, error) {
	visible := false
	scannerID := data.ID
	if data.RPCServer == "127.0.0.1" {
		// If scanner running in container, the ID should already by controller's ID.
		// This is to cover the case while scanner is not running in container.
		scannerID = Ctrler.ID
	}

	clusHelper := kv.GetClusterHelper()
	s := clusHelper.GetScanner(scannerID, access.NewReaderAccessControl())
	if s != nil {
		visible = true
	}

	return &share.ScannerAvailable{Visible: visible}, nil
}

func (ss *ScanService) scannerRegister(data *share.ScannerRegisterData) error {
	log.WithFields(log.Fields{
		"id": data.ID, "version": data.CVEDBVersion, "create": data.CVEDBCreateTime, "server": data.RPCServer, "entries": len(data.CVEDB),
	}).Info()

	writeDB := false
	newVer, _ := utils.NewVersion(data.CVEDBVersion)

	newScanner := share.CLUSScanner{
		ID:              data.ID,
		CVEDBVersion:    data.CVEDBVersion,
		CVEDBCreateTime: data.CVEDBCreateTime,
		JoinedAt:        time.Now().UTC(),
		RPCServer:       data.RPCServer,
		RPCServerPort:   uint16(data.RPCServerPort),
		BuiltIn:         data.RPCServer == "127.0.0.1",
		CVEDBEntries:    len(data.CVEDB),
	}
	if newScanner.BuiltIn {
		// If scanner running in container, the ID should already by controller's ID.
		// This is to cover the case while scanner is not running in container.
		newScanner.ID = Ctrler.ID
	}

	clusHelper := kv.GetClusterHelper()
	lock, err := clusHelper.AcquireLock(share.CLUSLockScannerKey, time.Second*20)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if the database is newer.
	s := clusHelper.GetScanner(share.CLUSScannerDBVersionID, access.NewReaderAccessControl())
	if s == nil {
		writeDB = true
	} else {
		ver, _ := utils.NewVersion(s.CVEDBVersion)
		if newVer.Compare(ver) > 0 || len(data.CVEDB) > s.CVEDBEntries {
			writeDB = true
		}
	}

	// Write the scanner and db atomically.
	// Consul value size limit is 512K. The limit also applies to the total value size in a transaction.
	// => so we cannot really use transaction to write database.

	oldStores, _ := cluster.GetStoreKeys(share.CLUSScannerDBStore)
	newStore := fmt.Sprintf("%s%s/", share.CLUSScannerDBStore, data.CVEDBVersion)

	txn := cluster.Transact()
	defer txn.Close()

	// Logic is like is, if we figure the db should be updated, we write the scanner record with new db prefix.
	// When the cache handler get notified of the new scanner, if db store is set, it will re-read the db keys.
	if writeDB {
		// Initiate slots
		cvedb := ss.preprocessDB(data)
		zbs, err := ss.prepareDBSlots(data, cvedb)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return err
		}

		for i, zb := range zbs {
			key := fmt.Sprintf("%s%d", newStore, i)
			if err = cluster.PutBinary(key, zb); err != nil {
				log.WithFields(log.Fields{"error": err, "slot": i, "size": len(zb)}).Error()
				ss.registerFailureCleanup(newStore)
				return err
			}
		}

		// The idea is to use a dummy scanner to indicate the new database has been written.
		dbVerScanner := share.CLUSScanner{
			ID:              share.CLUSScannerDBVersionID,
			CVEDBVersion:    data.CVEDBVersion,
			CVEDBCreateTime: data.CVEDBCreateTime,
			CVEDBEntries:    len(data.CVEDB),
		}
		clusHelper.PutScannerTxn(txn, &dbVerScanner)

		log.WithFields(log.Fields{"cvedb": newStore}).Info("CVE database written")
	}

	clusHelper.PutScannerTxn(txn, &newScanner)
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write scanner to the cluster")
		if writeDB {
			ss.registerFailureCleanup(newStore)
		}
		return err
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		return err
	}

	// Remove old stores. Ignore failure, missed keys will be removed the next update.
	if writeDB && len(oldStores) > 0 {
		txn.Reset()
		for _, store := range oldStores {
			txn.DeleteTree(store)
		}
		txn.Apply()
	}

	// Create scanner stats if not exist
	clusHelper.CreateScannerStats(newScanner.ID)

	return nil
}

func (ss *ScanService) ScannerDeregister(ctx context.Context, data *share.ScannerDeregisterData) (*share.RPCVoid, error) {
	log.WithFields(log.Fields{"scanner": data.ID}).Info()

	clusHelper := kv.GetClusterHelper()
	clusHelper.DeleteScanner(data.ID)
	return &share.RPCVoid{}, nil
}

func (ss *ScanService) SubmitScanResult(ctx context.Context, result *share.ScanResult) (*share.RPCVoid, error) {
	log.WithFields(log.Fields{
		"registry": result.Registry, "repository": result.Repository, "tag": result.Tag,
	}).Info()

	err := scanner.StoreRepoScanResult(result)
	return &share.RPCVoid{}, err
}

func (s *ScanService) GetCaps(ctx context.Context, v *share.RPCVoid) (*share.ControllerCaps, error) {
	return &share.ControllerCaps{
		CriticalVul:     false,
		ScannerSettings: true,
	}, nil
}

func (s *ScanService) GetScannerSettings(ctx context.Context, v *share.RPCVoid) (*share.ScannerSettings, error) {
	acc := access.NewReaderAccessControl()
	cfg := cacher.GetSystemConfig(acc)
	return &share.ScannerSettings{
		EnableTLSVerification: cfg.EnableTLSVerification,
		CACerts:               strings.Join(cfg.GlobalCaCerts, "\n"),
		HttpProxy:             httpclient.GetHttpProxy(),
		HttpsProxy:            httpclient.GetHttpsProxy(),
		NoProxy:               "",
	}, nil
}

// --

type ScanAdapterService struct {
}

func (sas *ScanAdapterService) GetScanners(context.Context, *share.RPCVoid) (*share.GetScannersResponse, error) {
	var c share.GetScannersResponse

	acc := access.NewReaderAccessControl()
	cfg := cacher.GetSystemConfig(acc)

	busy, idle := rpc.CountScanners()
	scanners, dbTime, dbVer := cacher.GetScannerCount(acc)
	c.Scanners = uint32(scanners)
	c.IdleScanners = idle
	c.ScannerDBTime = dbTime
	c.ScannerVersion = dbVer

	// MaxScanner means max number of available scanners, including those to be scaled up. The number can be larger than c.Scanners.
	if cfg.ScannerAutoscale.Strategy != api.AutoScaleNone {
		if cfg.ScannerAutoscale.MaxPods > busy {
			c.MaxScanners = cfg.ScannerAutoscale.MaxPods - busy
		}
	} else {
		if c.Scanners > busy {
			c.MaxScanners = c.Scanners - busy
		}
	}

	return &c, nil
}

func (sas *ScanAdapterService) ScanImage(ctx context.Context, req *share.AdapterScanImageRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"request": req}).Debug("Scan image request")

	ctx, cancel := context.WithTimeout(context.Background(), repoScanTimeout)
	defer cancel()

	scanReq := &share.ScanImageRequest{
		Registry:    req.Registry,
		Repository:  req.Repository,
		Tag:         req.Tag,
		Token:       req.Token,
		ScanLayers:  req.ScanLayers,
		ScanSecrets: false,
	}

	result, err := rpc.ScanImage("", ctx, scanReq)
	if result == nil || result.Error != share.ScanErrorCode_ScanErrNone {
		return result, err
	}

	// store the scan result so it can be used by admission control
	scan.FixRegRepoForAdmCtrl(result)
	scanner.StoreRepoScanResult(result)

	// Fill the detail and filter the result
	for _, v := range result.Vuls {
		scanUtils.FillVul(v)
	}
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	result.Vuls = vpf.FilterVuls(result.Vuls, []api.RESTIDName{api.RESTIDName{DisplayName: fmt.Sprintf("%s:%s", result.Repository, result.Tag)}})

	return result, err
}

// --
type CapService struct {
}

func (s *CapService) IsGRPCCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

// --
type UpgradeService struct {
}

const tmpDir string = "/tmp/"
const dstDir string = "/etc/neuvector/db/"

func (s *UpgradeService) SupportUpgradeDB(context.Context, *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: false}, nil
}

func (s *UpgradeService) SupportRegularDB(context.Context, *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (s *UpgradeService) UpgradeScannerDB(stream share.ControllerUpgradeService_UpgradeScannerDBServer) error {
	return status.Error(codes.Unimplemented, "Database update API is deprecated")
}

const reportChanSize = 128

func agentReportWorker(ch chan []*share.CLUSConnection) {
	for {
		select {
		case conns := <-ch:
			cache.UpdateConnections(conns)

			var wg sync.WaitGroup
			eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
			for _, ep := range eps {
				if ep.ID != Ctrler.ID {
					wg.Add(1)
					go func(ClusterIP string, RPCServerPort uint16) {
						// TODO: what if this fail? Or we could just transfer the graph update
						rpc.ReportConnections(ClusterIP, RPCServerPort, conns)
						wg.Done()
					}(ep.ClusterIP, ep.RPCServerPort)
				}
			}
			wg.Wait()
		}
	}
}

type ControllerAgentService struct {
	reportCh chan []*share.CLUSConnection
}

func (as *ControllerAgentService) IsCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (as *ControllerAgentService) RequestAdmission(ctx context.Context, req *share.CLUSAdmissionRequest) (*share.CLUSAdmissionResponse, error) {
	return cache.AgentAdmissionRequest(req), nil
}

func (as *ControllerAgentService) ReportProcProfile(ctx context.Context, profs *share.CLUSProcProfileArray) (*share.CLUSReportResponse, error) {
	//group the request
	if !kv.IsImporting() {
		var ok bool
		gproc := make(map[string][]*share.CLUSProcessProfileEntry)
		for _, prof := range profs.Processes {
			proc := &share.CLUSProcessProfileEntry{
				Name:      prof.Name,
				Path:      prof.Path,
				User:      prof.User,
				Uid:       prof.Uid,
				Hash:      prof.Hash,
				Action:    prof.Action,
				CfgType:   share.Learned,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}

			var procs []*share.CLUSProcessProfileEntry
			if procs, ok = gproc[prof.GroupName]; ok {
				procs = append(procs, proc)
			} else {
				procs = []*share.CLUSProcessProfileEntry{proc}
			}
			gproc[prof.GroupName] = procs
		}

		if ok := cache.AddProcessReport(gproc); !ok {
			return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
		}
	}
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done}, nil
}

func (as *ControllerAgentService) ReportFileAccessRule(ctx context.Context, rarray *share.CLUSFileAccessRuleArray) (*share.CLUSReportResponse, error) {
	if !kv.IsImporting() {
		if ok := cache.AddFileRuleReport(rarray.Rules); !ok {
			return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
		}
	}
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done}, nil
}

// Handling connection report is synchronized because we hold the graph lock, so we put the request
// in a channel so the agent call is not blocked. Throttle logic is also added. We assume,
// in most cases, by reporting with longer interval, number of sessions of each entry will increase,
// but not the number of connection entries.
func (as *ControllerAgentService) ReportConnections(ctx context.Context, rarray *share.CLUSConnectionArray) (*share.CLUSReportResponse, error) {
	if !Ctrler.Leader {
		return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
	}

	hosts := cacher.GetHostCount(access.NewReaderAccessControl())
	interval := (hosts-1)/10*5 + 5
	if hosts > 100 {
		interval = 50
	}

	if len(as.reportCh) >= reportChanSize {
		// TODO: a count to be added
		interval += 25
		return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend, ReportInterval: uint32(interval)}, nil
	}

	as.reportCh <- rarray.Connections
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done, ReportInterval: uint32(interval)}, nil
}

const ctrlSyncChunkSize int = 2 * 1024 * 1024

type ControllerService struct {
}

func (cs *ControllerService) IsCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (cs *ControllerService) ReqSync(ctx context.Context, req *share.CLUSSyncRequest) (*share.CLUSSyncReply, error) {
	log.WithFields(log.Fields{"category": req.Category, "from": req.From}).Debug("Receive sync request")
	data := cache.GetSyncTxData(req.Category)
	return &share.CLUSSyncReply{Category: req.Category, Data: data}, nil
}

func (cs *ControllerService) ReqSyncStream(req *share.CLUSSyncRequest, stream share.ControllerCtrlService_ReqSyncStreamServer) error {
	log.WithFields(log.Fields{"category": req.Category, "from": req.From}).Debug("Receive sync request")

	reply := &share.CLUSSyncReply{Category: req.Category}
	data := cache.GetSyncTxData(req.Category)

	offset := 0
	size := len(data)
	for {
		if size-offset < ctrlSyncChunkSize {
			reply.Data = data[offset:]
			stream.Send(reply)
			break
		} else {
			reply.Data = data[offset : offset+ctrlSyncChunkSize]
			stream.Send(reply)
			offset += ctrlSyncChunkSize
		}
	}
	return nil
}

func (cs *ControllerService) TriggerSync(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	cache.SyncFromLeader()
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) TriggerSyncLearnedPolicy(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	cache.SyncLearnedPolicyFromCluster()
	//schedule a task to remove unused learned group with 0 member
	if Ctrler.Leader {
		cache.SchedulePruneGroups()
	}
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) ProfilingCmd(ctx context.Context, req *share.CLUSProfilingRequest) (*share.RPCVoid, error) {
	go utils.PerfProfile(req, share.ProfileFolder, "ctl.")
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) CheckPolicySyncStatus(ctx context.Context, v *share.RPCVoid) (*share.CLUSPolicySyncStatus, error) {
	ss := cache.CheckPolicySyncStatus()
	return ss, nil
}

func (cs *ControllerService) ReportConnections(ctx context.Context, rarray *share.CLUSConnectionArray) (*share.RPCVoid, error) {
	cache.UpdateConnections(rarray.Connections)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) GetControllerCounter(ctx context.Context, v *share.RPCVoid) (*share.CLUSControllerCounter, error) {
	pid := os.Getpid()
	lsof, _ := sh.Command("lsof", "-Pn", "-p", strconv.Itoa(pid)).Command("grep", "-v", "IPv4\\|IPv6").Output()

	// Finding correct group pid
	var ps []byte
	if name, _ := os.Readlink("/proc/1/exe"); name == "/usr/local/bin/monitor" { // when pid mode != host
		ps, _ = sh.Command("ps", "-o", "pid,ppid,vsz,rss,comm", "-A").Output()
	} else {
		// processes under the controller
		ps, _ = sh.Command("ps", "-o", "pid,ppid,vsz,rss,comm", "-g", strconv.Itoa(Ctrler.Pid)).Output()
	}

	c := share.CLUSControllerCounter{
		GoRoutines: uint32(runtime.NumGoroutine()),
		Lsof:       lsof,
		PS:         ps,
	}
	return &c, nil
}

func (cs *ControllerService) DeleteConversation(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	if ops.From == "" && ops.To == "" {
		cache.DeleteAllConvers()
	} else {
		cache.DeleteConver(ops.From, ops.To)
	}
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) DeleteEndpoint(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	cache.DeleteEndpoint(ops.Endpoint)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) SetEndpointAlias(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	cache.ConfigEndpoint(ops.Endpoint, ops.Alias)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) PauseResumeStoreWatcher(ctx context.Context, ops *share.CLUSStoreWatcherInfo) (*share.RPCVoid, error) {
	cache.PauseResumeStoreWatcher(ops.CtrlerID, ops.Key, ops.Action)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) KickLoginSessions(ctx context.Context, ops *share.CLUSKickLoginSessionsRequest) (*share.RPCVoid, error) {
	rest.KickLoginSessions(ops)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) GetStats(ctx context.Context, v *share.RPCVoid) (*share.CLUSStats, error) {
	stats := share.CLUSStats{
		Interval: statsInterval,
		Total:    &share.CLUSMetry{},
		Span1:    &share.CLUSMetry{},
		Span12:   &share.CLUSMetry{},
		Span60:   &share.CLUSMetry{},
	}

	gInfo.mutex.Lock()
	system.PopulateSystemStats(&stats, &gInfo.stats)
	gInfo.mutex.Unlock()
	return &stats, nil
}

func (cs *ControllerService) ResetLoginTokenTimer(ctx context.Context, ops *share.CLUSLoginTokenInfo) (*share.RPCVoid, error) {
	rest.ResetLoginTokenTimer(ops)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) ReportK8SResToOPA(ctx context.Context, ops *share.CLUSKubernetesResInfo) (*share.RPCVoid, error) {
	rest.ReportK8SResToOPA(ops)
	log.WithFields(log.Fields{"ops": ops}).Debug("ReportK8SResToOPA (gprc-server)")
	return &share.RPCVoid{}, nil
}

func startGRPCServer(port uint16) (*cluster.GRPCServer, uint16) {
	var grpc *cluster.GRPCServer
	var err error

	if port == 0 {
		port = cluster.DefaultControllerGRPCPort
	}

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

	ch := make(chan []*share.CLUSConnection, reportChanSize)
	go agentReportWorker(ch)

	share.RegisterControllerScanServiceServer(grpc.GetServer(), new(ScanService))
	share.RegisterControllerScanAdapterServiceServer(grpc.GetServer(), new(ScanAdapterService))
	share.RegisterControllerCapServiceServer(grpc.GetServer(), new(CapService))
	share.RegisterControllerUpgradeServiceServer(grpc.GetServer(), new(UpgradeService))
	share.RegisterControllerAgentServiceServer(grpc.GetServer(), &ControllerAgentService{reportCh: ch})
	share.RegisterControllerCtrlServiceServer(grpc.GetServer(), new(ControllerService))
	go grpc.Start()

	log.Info("GRPC server started")

	return grpc, port
}
