package cluster

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/cluster/api"
	"github.com/neuvector/neuvector/share/cluster/watch"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

// const consulUIDir string = "/usr/local/bin/ui"
const consulExe string = "/usr/local/bin/consul"
const consulDataDir string = "/tmp/neuvector"
const consulConf string = consulDataDir + "/consul.json"
const consulPeers string = consulDataDir + "/raft/peers.json"

const defaultRPCPort = 18300
const defaultLANPort = 18301

//const defaultWANPort = 18302

const queryKvTimeout = time.Second * 1 // lower to 100 ms?

const shortFailDuration time.Duration = time.Second * 10
const shortFailCountLimit = 10

var shortFailCount int

var watcherFailFunc func() bool
var watcherRecoverFunc func()

type consulMethod struct {
	client    *api.Client
	clusterIP string
	rpcPort   uint
	pid       int // is a pgid
}

var consul consulMethod
var nodeID string

// Copied from hashicorp/raft/peersjson.go
type peerInfoV3 struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	NonVoter bool   `json:"non_voter"`
}

const (
	// consistent with consul member status
	consulStatusAlive = 1
	consulStatusLeft  = 3
	consulStatusFail  = 4
)

func gossipSharedKey() string {
	// Must be 16-byte, encoded in base64, same for every agent
	data := []byte("neuvector")
	data = append(data, 2, 0, 1, 6, 1, 2, 0)
	return base64.StdEncoding.EncodeToString(data)
}

/*
func createPeerFileV2(cc *ClusterConfig) error {
	log.WithFields(log.Fields{"peers": cc.joinAddrList}).Info()

	f, err := os.Create(consulPeers)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create consul peers.info file")
		return err
	}
	defer f.Close()

	peers := []string{cc.AdvertiseAddr}
	data, _ := json.Marshal(peers)

	_, err = f.WriteString(string(data[:]))
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write consul peers.info file")
		return err
	}

	return nil
}
*/

func createPeerFileV3(cc *ClusterConfig) error {
	log.WithFields(log.Fields{"peers": cc.joinAddrList}).Info()

	f, err := os.Create(consulPeers)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create consul peers.info file")
		return err
	}
	defer f.Close()

	peers := make([]peerInfoV3, len(cc.joinAddrList))
	for i, addr := range cc.joinAddrList {
		id := utils.GetStringUUID(utils.GetMd5(addr))
		peers[i] = peerInfoV3{ID: id, Address: fmt.Sprintf("%s:%d", addr, cc.RPCPort), NonVoter: false}
	}

	// peers := []peerInfoV3{peerInfoV3{ID: nodeID, Address: fmt.Sprintf("%s:%d", cc.AdvertiseAddr, cc.RPCPort), NonVoter: false}}
	data, _ := json.Marshal(peers)

	_, err = f.WriteString(string(data[:]))
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write consul peers.info file")
		return err
	}

	return nil
}

func createConfigFile(cc *ClusterConfig) error {
	var rpcPort, lanPort uint
	if rpcPort = cc.RPCPort; rpcPort == 0 {
		rpcPort = defaultRPCPort
		cc.RPCPort = rpcPort
	}
	if lanPort = cc.LANPort; lanPort == 0 {
		lanPort = defaultLANPort
	}

	type tConsulConfigPorts struct {
		Dns      int  `json:"dns"`
		Server   uint `json:"server"`
		Serf_lan uint `json:"serf_lan"`
		Serf_wan int  `json:"serf_wan"`
	}

	type tConsulConfigPerformance struct {
		Rpc_hold_timeout string `json:"rpc_hold_timeout"`
	}

	type tConsulConfig struct {
		//Acl_datacenter          string                   `json:"acl_datacenter"`
		//Acl_default_policy      string                   `json:"acl_default_policy"`
		//Acl_down_policy         string                   `json:"acl_down_policy"`
		//Acl_master_token        string                   `json:"acl_master_token"`
		Enable_debug            bool                     `json:"enable_debug,omitempty"`
		Check_update_interval   string                   `json:"check_update_interval"`
		Disable_update_check    bool                     `json:"disable_update_check"`
		Disable_remote_exec     bool                     `json:"disable_remote_exec"`
		Disable_host_node_id    bool                     `json:"disable_host_node_id"`
		Skip_leave_on_interrupt bool                     `json:"skip_leave_on_interrupt"`
		Leave_on_terminate      bool                     `json:"leave_on_terminate"`
		Encrypt                 string                   `json:"encrypt"`
		Ca_file                 string                   `json:"ca_file"`
		Cert_file               string                   `json:"cert_file"`
		Key_file                string                   `json:"key_file"`
		Verify_incoming         bool                     `json:"verify_incoming"`
		Verify_outgoing         bool                     `json:"verify_outgoing"`
		Log_level               string                   `json:"log_level"`
		Ports                   tConsulConfigPorts       `json:"ports"`
		Tls_cipher_suites       string                   `json:"tls_cipher_suites"`
		Performance             tConsulConfigPerformance `json:"performance"`
	}

	_ = os.MkdirAll(consulDataDir, os.ModePerm)
	f, err := os.Create(consulConf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create consul config file")
		return err
	}
	defer f.Close()

	cfg := tConsulConfig{
		//Acl_datacenter:          "dc1",
		//Acl_default_policy:      "deny",
		//Acl_down_policy:         "deny",
		//Acl_master_token:        consulAclToken,
		Enable_debug:            cc.EnableDebug,
		Check_update_interval:   "0s",
		Disable_update_check:    true,
		Disable_remote_exec:     true,
		Disable_host_node_id:    true,
		Skip_leave_on_interrupt: false,
		Leave_on_terminate:      true,
		Encrypt:                 gossipSharedKey(),
		Ca_file:                 fmt.Sprintf("%s%s", InternalCertDir, InternalCACert),
		Cert_file:               fmt.Sprintf("%s%s", InternalCertDir, InternalCert),
		Key_file:                fmt.Sprintf("%s%s", InternalCertDir, InternalCertKey),
		Verify_incoming:         true,
		Verify_outgoing:         true,
		Ports: tConsulConfigPorts{
			Dns:      -1,
			Server:   rpcPort,
			Serf_lan: lanPort,
			Serf_wan: -1,
		},
		Tls_cipher_suites: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Performance: tConsulConfigPerformance{
			Rpc_hold_timeout: fmt.Sprintf("%ds", 300),
		},
	}
	if cc.Debug {
		cfg.Log_level = "DEBUG"
	} else {
		cfg.Log_level = "ERROR"
	}
	value, _ := json.MarshalIndent(&cfg, "", "    ")
	if _, err := f.WriteString(string(value)); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write consul config file")
		return err
	}

	return nil
}

func isBootstrap(cc *ClusterConfig) bool {
	return len(cc.joinAddrList) == 1 && cc.joinAddrList[0] == cc.AdvertiseAddr
}

func (m *consulMethod) stopRunningInstance() error {
	if m.pid > 0 {
		if err := syscall.Kill((-1)*m.pid, syscall.SIGKILL); err != nil {
			log.WithFields(log.Fields{"pid": m.pid, "error": err}).Error("can not signal")
			return err
		}

		// it should be very soon but we add some buffering time
		nWaitCnt := 10
		for nWaitCnt > 0 {
			if !osutil.IsPidValid(m.pid) {
				break
			}
			time.Sleep(time.Millisecond * 100)
			nWaitCnt--
		}

		if nWaitCnt == 0 {
			log.WithFields(log.Fields{"pid": m.pid}).Error("can not stop")
			return errors.New("Can not stop consul")
		}
		m.pid = 0
	}
	return nil
}

func (m *consulMethod) getClient() (*api.Client, error) {
	if m.client == nil {
		var err error
		m.client, err = api.NewClient(api.DefaultConfig())
		return m.client, err
	}
	return m.client, nil
}

func (m *consulMethod) Start(cc *ClusterConfig, eCh chan error, recover bool) {
	_ = m.stopRunningInstance()

	args := []string{"agent", "-datacenter", cc.DataCenter, "-data-dir", consulDataDir}

	log.WithFields(log.Fields{"config": cc, "recover": recover}).Info()
	if cc.Server {
		args = append(args, "-server")

		// only one server can have bootstrap set in multi-controller case
		// the server that is configured to join only himself is given the flag
		if isBootstrap(cc) {
			args = append(args, "-bootstrap")
		} else {
			var haveSelf bool = false
			for _, ip := range cc.joinAddrList {
				if ip == cc.AdvertiseAddr {
					haveSelf = true
					break
				}
			}
			args = append(args, "-bootstrap-expect")
			if haveSelf {
				args = append(args, fmt.Sprintf("%d", len(cc.joinAddrList)))
			} else {
				args = append(args, fmt.Sprintf("%d", len(cc.joinAddrList)+1))
			}
		}
	}

	args = append(args, "-config-file")
	args = append(args, consulConf)

	if cc.BindAddr != "" {
		args = append(args, "-bind")
		args = append(args, cc.BindAddr)
		args = append(args, "-advertise")
		if cc.AdvertiseAddr != "" {
			m.clusterIP = cc.AdvertiseAddr
			args = append(args, cc.AdvertiseAddr)
		} else {
			m.clusterIP = cc.BindAddr
			args = append(args, cc.BindAddr)
		}
	} else {
		eCh <- fmt.Errorf("No bind address")
		return
	}

	if nodeID == "" {
		nodeID = utils.GetStringUUID(utils.GetMd5(m.clusterIP))
		log.WithFields(log.Fields{"node-id": nodeID}).Info()
	}

	// Use advertise address as node name.
	// We later read node name to get back cluster IP. See GetNodeAddress
	args = append(args, "-node")
	args = append(args, m.clusterIP)
	args = append(args, "-node-id")
	args = append(args, nodeID)
	// Set raft v3 explicitly
	args = append(args, "-raft-protocol")
	args = append(args, "3")
	/*
		if cc.Debug {
			args = append(args, "-ui-dir")
			args = append(args, consulUIDir)
			if cc.BindAddr != "" {
				args = append(args, "-client")
				args = append(args, "0.0.0.0")
			}
		}
	*/

	if !isBootstrap(cc) {
		for _, ip := range cc.joinAddrList {
			if ip != cc.AdvertiseAddr {
				args = append(args, "-retry-join")
				args = append(args, ip)
			}
		}
	}

	if err := createConfigFile(cc); err != nil {
		eCh <- err
	}
	if recover {
		_ = createPeerFileV3(cc)
	}
	m.rpcPort = cc.RPCPort

	log.WithFields(log.Fields{"args": args}).Info("Consul start")

	startTime := time.Now()
	cmd := exec.Command(consulExe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	if err := cmd.Start(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Can not start consul process")
		return
	}
	m.pid = cmd.Process.Pid // as a pgid
	err := cmd.Wait()
	log.WithFields(log.Fields{"error": err}).Error("Consul process exit")
	m.pid = 0 // exited. reset and avoid killing the wrong process

	if time.Since(startTime) < shortFailDuration {
		shortFailCount++
		if shortFailCount > shortFailCountLimit {
			shortFailCount = 0
			if !isBootstrap(cc) {
				rmErr := os.RemoveAll(consulDataDir)
				log.WithFields(log.Fields{"dir": consulDataDir, "error": rmErr}).Error("Remove consul data directory")
			}
		}
	} else {
		shortFailCount = 0
	}

	eCh <- err
}

func (m *consulMethod) leaveRaft(clusterIP string) error {
	addr := fmt.Sprintf("-address=\"%s:%d\"", clusterIP, m.rpcPort)
	cmd := exec.Command(consulExe, "operator", "raft", "remove-peer", addr)
	log.WithFields(log.Fields{"addr": addr}).Info("")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	err := cmd.Run()
	return err
}

func (m *consulMethod) Leave(server bool) error {
	log.Info("Consul process exit")

	if server {
		_ = m.leaveRaft(m.clusterIP)
	}

	cmd := exec.Command(consulExe, "leave")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	err := cmd.Run()
	if err != nil {
		return err
	}

	// time.Sleep(time.Second * 5)
	return nil
}

func (m *consulMethod) ForceLeave(node string, server bool) error {

	if server {
		_ = m.leaveRaft(node)
	}

	c, err := m.getClient()
	if err != nil {
		return err
	}
	agent := c.Agent()
	return agent.ForceLeave(node)
}

func (m *consulMethod) Join(cc *ClusterConfig) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}
	agent := c.Agent()

	for _, ip := range cc.joinAddrList {
		if err := agent.Join(ip, false); err != nil {
			log.WithFields(log.Fields{"error": err, "ip": ip}).Error()
		}
	}

	/*
		members, err := agent.Members(false)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get members")
			return err
		}

		for _, m := range members {
			if m.Status == consulStatusAlive && m.Tags["role"] == "consul" {
				err = agent.Join(m.Addr, false)
				if err != nil {
					log.WithFields(log.Fields{"address": m.Addr, "error": err}).Error("Failed to get members")
				}
			}
		}
	*/

	return nil
}

func (m *consulMethod) Reload(cc *ClusterConfig) error {
	err := createConfigFile(cc)
	if err != nil {
		return err
	}
	cmd := exec.Command(consulExe, "reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to reload consul config")
	}
	return err
}

/*
func ConsulGet(url string) (string, bool) {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error (%v) in Get for %s\n", err, url)
		return "", false
	}
	defer resp.Body.Close()
	log.Printf("Status of Get %s %d for %s", resp.Status, resp.StatusCode, url)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var jsonBody []consulBody
		body, err := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &jsonBody)
		existingValue, err := b64.StdEncoding.DecodeString(jsonBody[0].Value)
		if err != nil {
			return "", false
		}
		return string(existingValue[:]), true
	} else {
		return "", false
	}
}

// Consul KV Store related

const CONSUL_KV_BASE_URL = "http://localhost:8500/v1/kv"

type consulBody struct {
	CreateIndex int    `json:"CreateIndex,omitempty"`
	ModifyIndex int    `json:"ModifyIndex,omitempty"`
	Key         string `json:"Key,omitempty"`
	Flags       int    `json:"Flags,omitempty"`
	Value       string `json:"Value,omitempty"`
}

func GetAll(store string) ([][]byte, []int, bool) {
	if offlineSupport && !started {
		return getAllFromCache(store)
	}
	url := CONSUL_KV_BASE_URL + store + "?recurse"
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error (%v) in Get for %s\n", err, url)
		return nil, nil, false
	}
	defer resp.Body.Close()
	log.Printf("Status of Get %s %d for %s", resp.Status, resp.StatusCode, url)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, nil, false
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var jsonBody []consulBody
		valueArr := make([][]byte, 0)
		indexArr := make([]int, 0)
		body, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &jsonBody)
		for _, body := range jsonBody {
			existingValue, _ := b64.StdEncoding.DecodeString(body.Value)
			valueArr = append(valueArr, existingValue)
			indexArr = append(indexArr, body.ModifyIndex)
		}
		return valueArr, indexArr, true
	} else {
		return nil, nil, false
	}
}
*/

type lockMethod struct {
	lock *api.Lock
	key  string
}

func (l *lockMethod) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	return l.lock.Lock(stopCh)
}

func (l *lockMethod) Unlock() error {
	return l.lock.Unlock()
}

func (l *lockMethod) Key() string {
	return l.key
}

func (m *consulMethod) NewLock(key string, wait time.Duration) (LockInterface, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	opts := &api.LockOptions{Key: key}
	if wait > 0 {
		opts.LockTryOnce = true
		opts.LockWaitTime = wait
	}

	l, err := c.LockOpts(opts)
	if err != nil {
		return nil, err
	}

	return &lockMethod{lock: l, key: key}, nil
}

type sessionMethod struct {
	id string
	c  *api.Client
}

func (s *sessionMethod) Associate(key string) error {
	kv := s.c.KV()
	pair := &api.KVPair{Key: key, Value: []byte(s.id), Session: s.id}
	if ok, _, err := kv.Acquire(pair, nil); err != nil {
		return fmt.Errorf("Failed to hold, err=%s", err.Error())
	} else if !ok {
		return fmt.Errorf("Failed to hold")
	} else {
		return nil
	}
}

func (s *sessionMethod) Disassociate(key string) error {
	kv := s.c.KV()
	pair := &api.KVPair{Key: key, Value: []byte(s.id), Session: s.id}
	if ok, _, err := kv.Release(pair, nil); err != nil {
		return nil
	} else if !ok {
		return fmt.Errorf("Failed to release")
	} else {
		return nil
	}
}

func (m *consulMethod) NewSession(name string, ttl time.Duration) (SessionInterface, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	se := &api.SessionEntry{
		Name:     name,
		Behavior: api.SessionBehaviorDelete,
		TTL:      ttl.String(),
	}

	if id, _, err := c.Session().Create(se, nil); err == nil {
		return &sessionMethod{id: id, c: c}, nil
	} else {
		return nil, err
	}
}

func (m *consulMethod) defaultQueryOption() *api.QueryOptions {
	return &api.QueryOptions{
		//	AllowStale: true,
		WaitTime: queryKvTimeout,
	}
}

// key parameter that doesn't end with '/' : return true if the key exists
// key parameter that end with '/' : return true if the key exist & there is subkey under the key
func (m *consulMethod) Get(key string) ([]byte, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	kv := c.KV()
	pair, _, err := kv.Get(key, m.defaultQueryOption())
	if err != nil {
		return nil, err
	} else if pair == nil {
		return nil, ErrKeyNotFound
	} else {
		return pair.Value, nil
	}
}

func (m *consulMethod) Exist(key string) bool {
	c, err := m.getClient()
	if err == nil {
		kv := c.KV()
		entries, _, err := kv.Keys(key, "", nil)
		if err == nil && len(entries) > 0 {
			return true
		}
	}
	return false
}

func (m *consulMethod) GetKeys(prefix, separater string) ([]string, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	keys, _, err := c.KV().Keys(prefix, separater, m.defaultQueryOption())
	if err != nil {
		return nil, err
	} else if keys == nil {
		return nil, ErrEmptyStore
	}
	return keys, nil
}

func (m *consulMethod) GetRev(key string) ([]byte, uint64, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, 0, err
	}

	kv := c.KV()
	pair, _, err := kv.Get(key, m.defaultQueryOption())
	if err != nil {
		return nil, 0, err
	} else if pair == nil {
		return nil, 0, ErrKeyNotFound
	} else {
		return pair.Value, pair.ModifyIndex, nil
	}
}

func (m *consulMethod) GetStoreKeys(store string) ([]string, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	kv := c.KV()
	keys, _, err := kv.Keys(store, "", m.defaultQueryOption())
	if err != nil {
		return nil, err
	} else if keys == nil {
		return nil, ErrEmptyStore
	} else {
		return keys, nil
	}
}

func (m *consulMethod) Put(key string, value []byte) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}

	kv := c.KV()
	pair := &api.KVPair{Key: key, Value: value}
	_, err = kv.Put(pair, nil)

	return err
}

func (m *consulMethod) PutRev(key string, value []byte, rev uint64) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}

	var success bool
	kv := c.KV()
	pair := &api.KVPair{Key: key, Value: value, ModifyIndex: rev}
	success, _, err = kv.CAS(pair, nil)
	if !success && err == nil {
		err = ErrPutCAS
	}

	return err
}

func (m *consulMethod) PutIfNotExist(key string, value []byte) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}

	kv := c.KV()
	pair := &api.KVPair{Key: key, Value: value, ModifyIndex: 0}
	success, _, err := kv.CAS(pair, nil)
	if !success && err == nil {
		err = ErrPutCAS
	}

	return err
}

func (m *consulMethod) Delete(key string) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}

	kv := c.KV()
	_, err = kv.Delete(key, nil)
	return err
}

func (m *consulMethod) List(keyPrefix string) (api.KVPairs, error) {
	c, err := m.getClient()
	if err != nil {
		return nil, err
	}

	kv := c.KV()
	var opts api.QueryOptions
	pairs, _, err := kv.List(keyPrefix, &opts)
	if err != nil {
		return nil, err
	}

	return pairs, err
}

func (m *consulMethod) DeleteTree(keyPrefix string) error {
	c, err := m.getClient()
	if err != nil {
		return err
	}

	kv := c.KV()
	_, err = kv.DeleteTree(keyPrefix, nil)
	return err
}

func (m *consulMethod) Transact(entries []transactEntry) (bool, error) {
	var ops []*api.KVTxnOp

	for _, e := range entries {
		switch e.verb {
		case clusterTransactPut:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVSet, Key: e.key, Value: e.value})
		case clusterTransactPutRev:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVCAS, Key: e.key, Value: e.value, Index: e.rev})
		case clusterTransactDelete:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVDelete, Key: e.key})
		case clusterTransactDeleteRev:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVDeleteCAS, Key: e.key, Index: e.rev})
		case clusterTransactCheckRev:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVCheckIndex, Key: e.key, Index: e.rev})
		case clusterTransactDeleteTree:
			ops = append(ops, &api.KVTxnOp{Verb: api.KVDeleteTree, Key: e.key})
		default:
			return false, errors.New("Unsupported verb")
		}
	}

	c, err := m.getClient()
	if err != nil {
		return false, err
	}

	kv := c.KV()

	ok, rets, _, err := kv.Txn(ops, nil)
	if err == nil && !ok {
		for _, e := range rets.Errors {
			log.WithFields(log.Fields{"index": e.OpIndex, "what": e.What}).Error()
		}
	}
	return ok, err
}

// Watch related
var watchPlans []*watch.WatchPlan = make([]*watch.WatchPlan, 0)
var watchPlansLock sync.RWMutex

func (m *consulMethod) StopAllWatchers() {
	watchPlansLock.Lock()
	defer watchPlansLock.Unlock()

	for _, wp := range watchPlans {
		wp.Stop()
	}
	watchPlans = watchPlans[:0]
}

func (m *consulMethod) PauseAllWatchers(includeMonitorWatch bool) {
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	for _, wp := range watchPlans {
		if wp.Recover == nil || includeMonitorWatch {
			wp.Pause()
		}
	}
}

func (m *consulMethod) ResumeAllWatchers() {
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	for _, wp := range watchPlans {
		wp.Resume()
	}
}

func (m *consulMethod) PauseWatcher(key string) {
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	for _, wp := range watchPlans {
		if wp.Key == key {
			log.WithFields(log.Fields{"key": wp.Key}).Debug("")
			wp.Pause()
		}
	}
}

func (m *consulMethod) ResumeWatcher(key string) {
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	for _, wp := range watchPlans {
		if wp.Key == key {
			log.WithFields(log.Fields{"key": wp.Key}).Debug("")
			wp.Resume()
		}
	}
}

func (m *consulMethod) SetWatcherCongestionCtl(key string, enabled bool) {
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	for _, wp := range watchPlans {
		if wp.Key == key {
			log.WithFields(log.Fields{"key": wp.Key, "enabled": enabled}).Debug("")
			wp.Pause()
			time.Sleep(time.Second * 1) // avoid collision with read operations
			wp.CongestCtl = enabled
			wp.Resume()
			break
		}
	}
}

func (m *consulMethod) ServerAlive() (bool, error) {
	c, err := m.getClient()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return false, err
	}
	agent := c.Agent()
	curMembers, err := agent.Members(false)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return false, err
	}
	for _, mem := range curMembers {
		if mem.Status == consulStatusAlive && mem.Tags["role"] == "consul" {
			return true, nil
		}
	}
	for _, mem := range curMembers {
		log.WithFields(log.Fields{"name": mem.Name, "status": mem.Status, "role": mem.Tags["role"]}).Debug()
	}

	return false, nil
}

func (m *consulMethod) GetLead() (string, error) {
	c, err := m.getClient()
	if err != nil {
		return "", err
	}
	st := c.Status()
	return st.Leader()
}

func (m *consulMethod) GetAllMembers() []ClusterMemberInfo {
	c, err := m.getClient()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil
	}
	agent := c.Agent()
	curMembers, err := agent.Members(false)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil
	}

	var nodes []ClusterMemberInfo = make([]ClusterMemberInfo, len(curMembers))
	for i, mem := range curMembers {
		nodes[i].Name = mem.Name
		if mem.Tags["role"] == "consul" {
			nodes[i].Role = NodeRoleServer
		} else {
			nodes[i].Role = NodeRoleClient
		}
		switch mem.Status {
		case consulStatusAlive:
			nodes[i].State = NodeStateAlive
		case consulStatusLeft:
			nodes[i].State = NodeStateLeft
		case consulStatusFail:
			nodes[i].State = NodeStateFail
		}
	}
	return nodes
}

func register(params map[string]interface{}, handler watch.HandlerFunc) *watch.WatchPlan {
	// Params will be modifed in function watch.Parse(), so get the key first
	var key string
	switch params["type"].(string) {
	case "nodes":
		key = "nodes"
	case "key":
		key = params["key"].(string)
	case "keyprefix":
		key = params["prefix"].(string)
	case "checks":
		key = "checks"
	}

	// Create the watch
	wp, err := watch.Parse(params)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in parsing watch plan")

		return nil
	}
	wp.Key = key

	watchPlansLock.Lock()

	if len(watchPlans) == 0 {
		wp.Fail = watcherFailFunc
		wp.Recover = watcherRecoverFunc
	}

	watchPlans = append(watchPlans, wp)
	watchPlansLock.Unlock()

	wp.Handler = handler
	// Run the watch
	if err := wp.Run(api.DefaultConfig().Address); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in registering watch")
	}

	return wp
}

var nodeWatchers []NodeWatcher = make([]NodeWatcher, 0)
var nodeCache []*api.Node

func compareNodes(X, Y []*api.Node) []*api.Node {
	m := make(map[string]bool)

	for _, y := range Y {
		m[y.Address] = true
	}

	var ret []*api.Node
	for _, x := range X {
		if _, ok := m[x.Address]; ok {
			continue
		}
		ret = append(ret, x)
	}

	return ret
}

func nodeUpdateCallback(clusterNodes []*api.Node) {
	log.Debug("")

	toDelete := compareNodes(nodeCache, clusterNodes)
	toAdd := compareNodes(clusterNodes, nodeCache)
	nodeCache = clusterNodes
	for _, deleteNode := range toDelete {
		for _, watcher := range nodeWatchers {
			watcher(ClusterNotifyDelete, deleteNode.Address, deleteNode.Node)
		}
	}

	for _, addNode := range toAdd {
		for _, watcher := range nodeWatchers {
			watcher(ClusterNotifyAdd, addNode.Address, addNode.Node)
		}
	}
}

func addNodeWatcher(watcher NodeWatcher) bool {
	v := reflect.ValueOf(nodeWatchers)
	f := reflect.ValueOf(watcher)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).Interface() == f {
			log.Debug("Node watcher has been registered.")
			return false
		}
	}

	nodeWatchers = append(nodeWatchers, watcher)
	return true
}

func registerNodeUpdate() {
	log.Debug("")

	params := make(map[string]interface{})
	params["type"] = "nodes"
	handler := func(idx uint64, data interface{}) {
		nodeUpdateCallback(data.([]*api.Node))
	}

	register(params, handler)
}

func (m *consulMethod) RegisterNodeWatcher(watcher NodeWatcher) {
	w := addNodeWatcher(watcher)
	if !w || len(nodeWatchers) != 1 {
		return
	}

	go registerNodeUpdate()
}

var keyWatchers map[string][]KeyWatcher = make(map[string][]KeyWatcher)
var keyWatcherMutex sync.RWMutex

func keyUpdateCallback(idx uint64, key string, data interface{}) {
	log.Debug("")

	keyWatcherMutex.RLock()
	watchers, ok := keyWatchers[key]
	keyWatcherMutex.RUnlock()
	if !ok {
		return
	}

	var kv *api.KVPair = nil
	var val []byte = nil
	var nType ClusterNotifyType

	if data != nil {
		kv = data.(*api.KVPair)
	}

	var modifyIdx uint64
	if kv == nil {
		nType = ClusterNotifyDelete
	} else {
		nType = ClusterNotifyModify
		if idx == kv.CreateIndex {
			nType = ClusterNotifyAdd
		}
		val = kv.Value
		modifyIdx = kv.ModifyIndex
	}

	for _, watcher := range watchers {
		watcher(nType, key, val, modifyIdx)
	}
}

func addKeyWatcher(key string, watcher KeyWatcher) bool {
	if _, ok := keyWatchers[key]; !ok {
		keyWatchers[key] = make([]KeyWatcher, 0)
	} else {
		v := reflect.ValueOf(keyWatchers[key])
		f := reflect.ValueOf(watcher)
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Interface() == f {
				log.Debug("Key watcher has been registered.")
				return false
			}
		}
	}

	keyWatchers[key] = append(keyWatchers[key], watcher)
	return true
}

func registerKeyUpdate(key string) {
	log.WithFields(log.Fields{"key": key}).Debug("")

	params := make(map[string]interface{})
	params["type"] = "key"
	params["key"] = key
	handler := func(idx uint64, data interface{}) {
		keyUpdateCallback(idx, key, data)
	}

	register(params, handler)
}

func (m *consulMethod) RegisterKeyWatcher(key string, watcher KeyWatcher) {
	keyWatcherMutex.Lock()
	defer keyWatcherMutex.Unlock()

	w := addKeyWatcher(key, watcher)
	if !w || len(keyWatchers[key]) != 1 {
		return
	}

	go registerKeyUpdate(key)
}

var stateWatchers []StateWatcher = make([]StateWatcher, 0)
var stateCache map[string]string = make(map[string]string)

func stateUpdateCallback(checks []*api.HealthCheck) {
	var notif ClusterNotifyType

	for _, check := range checks {
		if oldState, ok := stateCache[check.Node]; ok {
			if oldState == check.Status {
				continue
			} else {
				stateCache[check.Node] = check.Status
			}
		} else {
			stateCache[check.Node] = check.Status
		}

		log.WithFields(log.Fields{"Node": check.Node, "Status": check.Status}).Debug("")
		if check.Status == "passing" {
			notif = ClusterNotifyStateOnline
		} else if check.Status == "critical" {
			notif = ClusterNotifyStateOffline
		} else {
			continue
		}
		for _, watcher := range stateWatchers {
			watcher(notif, check.Node, "")
		}
	}

	// node leaving events are not taken care of by state watcher, so we don't really
	// care it. Thus we can rewrite the cache set only if the difference is large
	if len(stateCache) > (len(checks) + 10) {
		stateCache = nil
		stateCache = make(map[string]string)
		for _, check := range checks {
			stateCache[check.Node] = check.Status
		}
	}
}

func addStateWatcher(watcher StateWatcher) bool {
	v := reflect.ValueOf(stateWatchers)
	f := reflect.ValueOf(watcher)
	for i := 0; i < v.Len(); i++ {
		if v.Index(i).Interface() == f {
			log.Debug("State watcher has been registered.")
			return false
		}
	}

	stateWatchers = append(stateWatchers, watcher)
	return true
}

func registerStateUpdate() {
	params := make(map[string]interface{})
	params["type"] = "checks"
	handler := func(idx uint64, data interface{}) {
		stateUpdateCallback(data.([]*api.HealthCheck))
	}

	register(params, handler)
}

func (m *consulMethod) RegisterStateWatcher(watcher StateWatcher) {
	w := addStateWatcher(watcher)
	if !w || len(stateWatchers) != 1 {
		return
	}

	go registerStateUpdate()
}

var storeWatchers map[string][]StoreWatcher = make(map[string][]StoreWatcher)
var storeWatcherMutex sync.RWMutex
var storeCache map[string]map[string]uint64 = make(map[string]map[string]uint64)
var storeCacheMutex sync.Mutex
var storeWatchersCongestCtl map[string]bool = make(map[string]bool)

func compareStoreKeys(cache map[string]uint64, kvs api.KVPairs) []string {
	m := make(map[string]bool)

	for _, kv := range kvs {
		m[kv.Key] = true
	}

	var ret []string
	for key := range cache {
		if _, ok := m[key]; ok {
			continue
		}
		ret = append(ret, key)
	}

	return ret
}

func storeUpdateCallback(idx uint64, store string, data interface{}) {
	storeWatcherMutex.RLock()
	watchers, ok := storeWatchers[store]
	storeWatcherMutex.RUnlock()
	if !ok {
		return
	}

	var kvs api.KVPairs = nil
	var val []byte = nil
	var nType ClusterNotifyType

	if data != nil {
		kvs = data.(api.KVPairs)
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].ModifyIndex < kvs[j].ModifyIndex })
	}

	storeCacheMutex.Lock()
	cache, ok := storeCache[store]
	if !ok {
		cache = make(map[string]uint64)
		storeCache[store] = cache
	}
	storeCacheMutex.Unlock()

	// Found new or modified key/value pairs
	for _, kv := range kvs {
		var notify bool = false

		_, ok = cache[kv.Key]
		if !ok {
			cache[kv.Key] = kv.ModifyIndex
			if kv.ModifyIndex == kv.CreateIndex {
				nType = ClusterNotifyAdd
			} else {
				nType = ClusterNotifyModify
			}
			val = kv.Value
			notify = true
		} else {
			if kv.ModifyIndex != cache[kv.Key] {
				cache[kv.Key] = kv.ModifyIndex
				nType = ClusterNotifyModify
				val = kv.Value
				notify = true
			}
		}

		if notify {
			for _, watcher := range watchers {
				watcher(nType, kv.Key, val, kv.ModifyIndex)
			}
		}
	}

	// Found deleted key/value pairs
	toDelete := compareStoreKeys(cache, kvs)

	for _, key := range toDelete {
		delete(cache, key)

		for _, watcher := range watchers {
			watcher(ClusterNotifyDelete, key, nil, 0)
		}
	}
}

func addStoreWatcher(store string, watcher StoreWatcher, bCongestCtl bool) bool {
	if _, ok := storeWatchers[store]; !ok {
		storeWatchers[store] = make([]StoreWatcher, 0)
	} else {
		v := reflect.ValueOf(storeWatchers[store])
		f := reflect.ValueOf(watcher)
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Interface() == f {
				log.Debug("Store watcher has been registered")
				return false
			}
		}
	}

	storeWatchers[store] = append(storeWatchers[store], watcher)
	storeWatchersCongestCtl[store] = bCongestCtl
	return true
}

func registerStoreUpdate(store string, bCongestCtl bool) {
	log.WithFields(log.Fields{"store": store}).Debug("")

	params := make(map[string]interface{})
	params["type"] = "keyprefix"
	params["prefix"] = store
	params["congestCtl"] = bCongestCtl
	handler := func(idx uint64, data interface{}) {
		storeUpdateCallback(idx, store, data)
	}

	register(params, handler)
}

func (m *consulMethod) RegisterStoreWatcher(store string, watcher StoreWatcher, bCongestCtl bool) {
	storeWatcherMutex.Lock()
	defer storeWatcherMutex.Unlock()

	w := addStoreWatcher(store, watcher, bCongestCtl)
	if !w || len(storeWatchers[store]) != 1 {
		return
	}

	go registerStoreUpdate(store, bCongestCtl)
}

func (m *consulMethod) RegisterExistingWatchers() {
	log.Debug("")

	if len(nodeWatchers) > 0 {
		go registerNodeUpdate()
	}
	keyWatcherMutex.RLock()
	for key := range keyWatchers {
		go registerKeyUpdate(key)
	}
	keyWatcherMutex.RUnlock()
	if len(stateWatchers) > 0 {
		go registerStateUpdate()
	}
	storeWatcherMutex.RLock()
	for store := range storeWatchers {
		go registerStoreUpdate(store, storeWatchersCongestCtl[store])
	}
	storeWatcherMutex.RUnlock()
}

func (m *consulMethod) RegisterWatcherMonitor(failFunc func() bool, recoverFunc func()) {
	log.Debug("")
	watchPlansLock.RLock()
	defer watchPlansLock.RUnlock()

	watcherFailFunc = failFunc
	watcherRecoverFunc = recoverFunc
	if len(watchPlans) > 0 {
		wp := watchPlans[0]
		wp.Fail = watcherFailFunc
		wp.Recover = watcherRecoverFunc
	}
}

// --

func (m *consulMethod) GetSelfAddress() string {
	if m.clusterIP != "" {
		return m.clusterIP
	}

	// This is used by the enforcer in allinone
	c, err := m.getClient()
	if err != nil {
		return ""
	}
	agent := c.Agent()
	if self, err := agent.Self(); err == nil {
		if _, ok := self["Config"]; !ok {
			return ""
		}
		if _, ok := self["Config"]["NodeName"]; !ok {
			return ""
		}
		return self["Config"]["NodeName"].(string)
	}

	return ""
}
