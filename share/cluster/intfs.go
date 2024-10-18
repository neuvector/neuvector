package cluster

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	consulapi "github.com/neuvector/neuvector/share/cluster/api"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

const InternalCertDir = "/etc/neuvector/certs/internal/"

const InternalCACert string = "ca.cert"
const InternalCert string = "cert.pem"
const InternalCertKey string = "cert.key"
const InternalCertCN string = "NeuVector"

// --

const DefaultControllerGRPCPort = 18400
const DefaultAgentGRPCPort = 18401
const DefaultScannerGRPCPort = 18402
const DefaultMigrationGRPCPort = 18500

const DefaultDataCenter string = "neuvector"

var ErrPutCAS error = errors.New("CAS put error")
var errSizeTooBig error = errors.New("size too big")

const putRetryTimes int = 2
const putRetryInterval time.Duration = time.Millisecond * 500

var errorRestart bool

type ClusterConfig struct {
	ID            string
	Server        bool
	Debug         bool
	Ifaces        map[string][]share.CLUSIPAddr
	JoinAddr      string
	joinAddrList  []string
	BindAddr      string
	AdvertiseAddr string
	DataCenter    string
	RPCPort       uint
	LANPort       uint
	WANPort       uint
	EnableDebug   bool
}

var clusterCfg ClusterConfig

const (
	ClusterNotifyAdd = iota
	ClusterNotifyModify
	ClusterNotifyDelete
	ClusterNotifyStateOnline
	ClusterNotifyStateOffline
)

var ClusterNotifyName = []string{
	ClusterNotifyAdd:          "add",
	ClusterNotifyModify:       "modify",
	ClusterNotifyDelete:       "delete",
	ClusterNotifyStateOnline:  "connect",
	ClusterNotifyStateOffline: "disconnect",
}

type ClusterNotifyType int

const (
	NodeRoleServer = iota
	NodeRoleClient
)

const (
	NodeStateAlive = iota
	NodeStateLeft
	NodeStateFail
)

type ClusterMemberInfo struct {
	Name  string
	Role  int
	State int
}

// cluster operations

const startWaitTime time.Duration = time.Second * 10
const leadCheckInterval time.Duration = time.Second * 60
const retryLimitJoin = 3
const retryLimitRestart = 3

func StartCluster(cc *ClusterConfig) (string, error) {
	log.Debug("")

	if cc == nil {
		lead := waitClusterReady(time.Second*2, 60)
		if lead == "" {
			return "", errors.New("Failed to locate leader")
		}
		return lead, nil
	}

	clusterCfg = *cc

	// Register before start the cluster
	driver.RegisterExistingWatchers()

	errCh := make(chan error)
	go driver.Start(cc, errCh, false)

	select {
	case err := <-errCh:
		log.WithFields(log.Fields{"error": err}).Error("Failed to start cluster")
		return "", err
	case <-time.After(startWaitTime):
	}

	var lead string

	if !cc.Server {
		lead = waitClusterReady(time.Second*2, 60)
		if lead == "" {
			return "", errors.New("Failed to locate leader")
		}
	} else {
		lead = waitClusterReady(time.Second*2, 60)

		// Set ready flag so the controller IP can participate selection after restart
		_ = utils.SetReady("ctrl init done")

		if lead == "" {
			return "", errors.New("Failed to elect leader")
		}
	}

	log.WithFields(log.Fields{"lead": lead}).Info()

	// Monitor cluster lead
	var noLeadChan chan interface{} = make(chan interface{}, 1)
	RegisterLeadChangeWatcher(func(newLead, oldLead string) {
		log.WithFields(log.Fields{"newLead": newLead, "oldLead": oldLead}).Info()
		if newLead == "" {
			noLeadChan <- true
		}
	}, lead)

	go func() {
		errorRestart = true
		retryCluster := 0
		retryLimit := retryLimitJoin
		leadCheckTimer := time.NewTimer(time.Second * 20)

		for {
			select {
			case err := <-errCh:
				if errorRestart {
					log.WithFields(log.Fields{"error": err}).Error("Cluster stopped - will restart")

					addrs, _ := utils.ResolveAddrList(cc.JoinAddr, true)
					for len(addrs) == 0 {
						time.Sleep(time.Second * 5)
						addrs, _ = utils.ResolveAddrList(cc.JoinAddr, true)
					}
					cc.joinAddrList = addrs

					time.Sleep(time.Second * 2)
					go driver.Start(cc, errCh, true)
					retryCluster = 0
					retryLimit = retryLimitRestart
					leadCheckTimer.Reset(leadCheckInterval)
				}
				continue
			case <-noLeadChan:
				log.Info("Lead loss detected")
				retryCluster = 0
				retryLimit = retryLimitJoin
			case <-leadCheckTimer.C:
				log.Info("Lead check timer expired")
				leadCheckTimer.Stop()
			}

			// If cluster cannot elect lead due to dns resolve issue, redo the resolve and
			// restart cluster
			lead, _ := driver.GetLead()
			if lead != "" {
				log.WithFields(log.Fields{"lead": lead}).Info("Lead elected")
				retryCluster = 0
			} else {
				log.WithFields(log.Fields{"join": cc.JoinAddr}).Info("Cannot locate lead")

				addrs, _ := utils.ResolveAddrList(cc.JoinAddr, true)
				for len(addrs) == 0 {
					time.Sleep(time.Second * 5)
					addrs, _ = utils.ResolveAddrList(cc.JoinAddr, true)
				}
				cc.joinAddrList = addrs

				if retryCluster < retryLimit {
					log.WithFields(log.Fields{"JoinAddr": cc.joinAddrList}).Info("Retry join")
					if err := driver.Join(cc); err != nil {
						log.WithFields(log.Fields{"error": err}).Error("Join")
					}
					leadCheckTimer.Reset(time.Second * 30)
					retryCluster++
				} else {
					log.WithFields(log.Fields{"JoinAddr": cc.JoinAddr}).Info("Leave cluster")
					// errCh will trigger restart
					if err := driver.Leave(cc.Server); err != nil {
						log.WithFields(log.Fields{"error": err}).Error("Leave")
					}
				}
			}
		}
	}()

	return lead, nil
}

func LeaveCluster(server bool) {
	log.Debugf("")

	errorRestart = false

	driver.StopAllWatchers()

	if err := driver.Leave(server); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error when leaving cluster")
	}

	clusterCfg.JoinAddr = ""
	clusterCfg.BindAddr = ""
	clusterCfg.AdvertiseAddr = ""
}

// -- watch

type NodeWatcher func(ClusterNotifyType, string, string)
type KeyWatcher func(ClusterNotifyType, string, []byte, uint64)
type StoreWatcher func(ClusterNotifyType, string, []byte, uint64)
type StateWatcher func(ClusterNotifyType, string, string)

func RegisterWatcherMonitor(failFunc func() bool, recoverFunc func()) {
	log.Debug("")
	driver.RegisterWatcherMonitor(failFunc, recoverFunc)
}

func RegisterNodeWatcher(f NodeWatcher) {
	log.Debug("")
	driver.RegisterNodeWatcher(f)
}

func RegisterKeyWatcher(key string, f KeyWatcher) {
	log.WithFields(log.Fields{"key": key}).Debug("")
	driver.RegisterKeyWatcher(key, f)
}

func RegisterStateWatcher(f StateWatcher) {
	log.Debug("")
	driver.RegisterStateWatcher(f)
}

func RegisterStoreWatcher(store string, f StoreWatcher, bCongestCtl bool) {
	log.WithFields(log.Fields{"store": store}).Debug("")
	driver.RegisterStoreWatcher(store, f, bCongestCtl)
}

func PauseAllWatchers(includeMonitorWatch bool) {
	log.Debug("")
	driver.PauseAllWatchers(includeMonitorWatch)
}

func ResumeAllWatchers() {
	log.Debug("")
	driver.ResumeAllWatchers()
}

func PauseWatcher(key string) {
	log.WithFields(log.Fields{"key": key}).Debug("")
	driver.PauseWatcher(key)
}

func ResumeWatcher(key string) {
	log.WithFields(log.Fields{"key": key}).Debug("")
	driver.ResumeWatcher(key)
}

func SetWatcherCongestionCtl(key string, enabled bool) {
	log.WithFields(log.Fields{"key": key, "enabled": enabled}).Debug("")
	driver.SetWatcherCongestionCtl(key, enabled)
}

func ForceLeave(node string, server bool) {
	log.WithFields(log.Fields{"node": node}).Debug("")
	if err := driver.ForceLeave(node, server); err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("")
	}
}

func GetClusterLead() string {
	lead, _ := driver.GetLead()
	if lead != "" {
		idx := strings.Index(lead, ":")
		return lead[:idx]
	}
	return ""
}

func GetAllMembers() []ClusterMemberInfo {
	return driver.GetAllMembers()
}

func waitClusterReady(t time.Duration, maxRetry int) string {
	var lead string
	retry := 0

Wait:
	for {
		lead, _ = driver.GetLead()
		if lead == "" {
			time.Sleep(t)
			retry++
		} else {
			self := driver.GetSelfAddress()
			members := driver.GetAllMembers()
			for _, m := range members {
				if self == m.Name {
					break Wait
				}
			}
			time.Sleep(t)
			retry++
		}
		if maxRetry != 0 && retry > maxRetry {
			return ""
		}
	}

	log.WithFields(log.Fields{"lead": lead}).Debug("cluster ready")
	idx := strings.Index(lead, ":")
	return lead[:idx]
}

type LeadChangeCallback func(string, string)

func RegisterLeadChangeWatcher(fn LeadChangeCallback, lead string) {
	var leaveChan chan string = make(chan string, 1)

	RegisterNodeWatcher(func(nType ClusterNotifyType, memberAddr string, member string) {
		if nType == ClusterNotifyDelete {
			leaveChan <- member
		}
	})

	go func() {
		leadMonitorTicker := time.Tick(time.Second * 5)
		for {
			select {
			case <-leadMonitorTicker:
			case leaveNode := <-leaveChan:
				if lead != "" && leaveNode != lead {
					continue
				}
			}

			newLead := GetClusterLead()
			if newLead != lead {
				fn(newLead, lead)
				lead = newLead
			}
		}
	}()
}

// --

var ErrKeyNotFound error = errors.New("Key not found")
var ErrEmptyStore error = errors.New("Empty store")

var KVValueSizeMax = 512 * 1024

type LockInterface interface {
	Lock(stopCh <-chan struct{}) (<-chan struct{}, error)
	Unlock() error
	Key() string
}

// Session is a mechanism to implement short-lived keys. When the session is created, a TTL value is given.
// Keys are "associated" with the session will be deleted when the session expires.
type SessionInterface interface {
	Associate(key string) error
	Disassociate(key string) error
}

type ClusterDriver interface {
	Start(cc *ClusterConfig, eCh chan error, recover bool)
	Join(cc *ClusterConfig) error
	Leave(server bool) error
	ForceLeave(node string, server bool) error
	Reload(cc *ClusterConfig) error

	GetSelfAddress() string
	GetLead() (string, error)
	ServerAlive() (bool, error)
	GetAllMembers() []ClusterMemberInfo

	NewLock(key string, wait time.Duration) (LockInterface, error)
	NewSession(name string, ttl time.Duration) (SessionInterface, error)

	// KV
	Exist(key string) bool
	GetKeys(prefix, separater string) ([]string, error)
	Get(key string) ([]byte, error)
	GetRev(key string) ([]byte, uint64, error)
	GetStoreKeys(store string) ([]string, error)
	Put(key string, value []byte) error
	PutRev(key string, value []byte, rev uint64) error
	PutIfNotExist(key string, value []byte) error
	Delete(key string) error
	List(keyPrefix string) (consulapi.KVPairs, error)
	DeleteTree(keyPrefix string) error
	Transact([]transactEntry) (bool, error)

	// Watcher
	RegisterKeyWatcher(key string, watcher KeyWatcher)
	RegisterStoreWatcher(store string, watcher StoreWatcher, bCongestCtl bool)
	RegisterStateWatcher(watcher StateWatcher)
	RegisterNodeWatcher(watcher NodeWatcher)
	RegisterWatcherMonitor(failFunc func() bool, recoverFunc func())
	RegisterExistingWatchers()

	StopAllWatchers()
	PauseAllWatchers(includeMonitorWatch bool)
	ResumeAllWatchers()
	PauseWatcher(key string)
	ResumeWatcher(key string)
	SetWatcherCongestionCtl(key string, enabled bool)
}

var driver ClusterDriver = &consul

func NewLock(key string, wait time.Duration) (LockInterface, error) {
	return driver.NewLock(key, wait)
}

func NewSession(name string, ttl time.Duration) (SessionInterface, error) {
	return driver.NewSession(name, ttl)
}

func Exist(key string) bool {
	return driver.Exist(key)
}

func GetKeys(prefix, separater string) ([]string, error) {
	return driver.GetKeys(prefix, separater)
}

func Get(key string) ([]byte, error) {
	// log.WithFields(log.Fields{"key": key}).Debug("")
	return driver.Get(key)
}

func GetRev(key string) ([]byte, uint64, error) {
	// log.WithFields(log.Fields{"key": key}).Debug("")
	return driver.GetRev(key)
}

func GetStoreKeys(store string) ([]string, error) {
	// log.WithFields(log.Fields{"store": store}).Debug("")
	return driver.GetStoreKeys(store)
}

func put(key string, value []byte) error {
	return driver.Put(key, value)
}

func putBinary(key string, value []byte) error {
	// Logging should be done at the caller code
	err := put(key, value)
	if err != nil {
		for i := 0; i < putRetryTimes; i++ {
			time.Sleep(putRetryInterval)
			log.WithFields(log.Fields{"retry": i}).Debug(err)
			err = put(key, value)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"key": key, "error": err}).Error("Failed to put key")
	}
	return err
}

func putRev(key string, value []byte, rev uint64) error {
	err := driver.PutRev(key, value, rev)
	if err != nil && err != ErrPutCAS {
		for i := 0; i < putRetryTimes; i++ {
			time.Sleep(putRetryInterval)
			log.WithFields(log.Fields{"retry": i}).Debug(err)
			err = driver.PutRev(key, value, rev)
			if err == nil || err == ErrPutCAS {
				break
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"key": key, "error": err}).Error("Failed to put key")
	}
	return err
}

func PutQuiet(key string, value []byte) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		err = putBinary(key, value)
	}
	return err
}

func PutBinary(key string, value []byte) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// we assume binary data is already in gzip format so do not try to gzip it again
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		log.WithFields(log.Fields{"key": key}).Debug()
		err = putBinary(key, value)
	}
	return err
}

func PutBinaryRev(key string, value []byte, rev uint64) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// we assume binary data is already in gzip format so do not try to gzip it again
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		log.WithFields(log.Fields{"key": key}).Debug()
		err = putRev(key, value, rev)
	}
	return err
}

func PutQuietRev(key string, value []byte, rev uint64) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		err = putRev(key, value, rev)
	}
	return err
}

func Put(key string, value []byte) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		log.WithFields(log.Fields{"key": key, "value": string(value)}).Debug()
		err = putBinary(key, value)
	}
	return err
}

func PutRev(key string, value []byte, rev uint64) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		log.WithFields(log.Fields{"key": key, "value": string(value), "rev": rev}).Debug()
		err = putRev(key, value, rev)
	}
	return err
}

// The difference between putRev(k, v, 0) and PutIfNotExist(k, v) is the later return nil error
// when the key exists
func PutIfNotExist(key string, value []byte, logKeyOnly bool) error {
	var err error
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		err = errSizeTooBig
		log.WithFields(log.Fields{"key": key, "size": len(value)}).Error(err)
	} else {
		if logKeyOnly {
			log.WithFields(log.Fields{"key": key}).Debug("")
		} else {
			log.WithFields(log.Fields{"key": key, "value": string(value)}).Debug("")
		}

		err = driver.PutIfNotExist(key, value)
		if err != nil && err != ErrPutCAS {
			for i := 0; i < putRetryTimes; i++ {
				time.Sleep(putRetryInterval)
				log.WithFields(log.Fields{"retry": i}).Debug(err)
				err = driver.PutIfNotExist(key, value)
				if err == nil || err == ErrPutCAS {
					break
				}
			}
		}
		if err == ErrPutCAS {
			// no error but key is already existed, ignore the update.
			// Suppress log.
			// log.WithFields(log.Fields{"key": key}).Debug("Put key CAS error")
			err = nil
		} else if err != nil {
			log.WithFields(log.Fields{"key": key, "error": err}).Error("Failed to put key")
		}
	}
	return err
}

func Delete(key string) error {
	log.WithFields(log.Fields{"key": key}).Debug("")

	err := driver.Delete(key)
	if err != nil {
		for i := 0; i < putRetryTimes; i++ {
			time.Sleep(putRetryInterval)
			log.WithFields(log.Fields{"retry": i}).Debug(err)
			err = driver.Delete(key)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"key": key, "error": err}).Error("Failed to delete key")
	}
	return err
}

func List(keyPrefix string) (consulapi.KVPairs, error) {
	log.WithFields(log.Fields{"key": keyPrefix}).Debug("")

	return driver.List(keyPrefix)
}

func DeleteTree(keyPrefix string) error {
	log.WithFields(log.Fields{"keyPrefix": keyPrefix}).Debug("")

	err := driver.DeleteTree(keyPrefix)
	if err != nil {
		for i := 0; i < putRetryTimes; i++ {
			time.Sleep(putRetryInterval)
			log.WithFields(log.Fields{"retry": i}).Debug(err)
			err = driver.DeleteTree(keyPrefix)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"keyPrefix": keyPrefix, "error": err}).Error("Failed to delete kv tree")
	}
	return err
}

// -- Transaction

const (
	clusterTransactPut clusterTransactVerb = iota
	clusterTransactPutRev
	clusterTransactDelete
	clusterTransactDeleteRev
	clusterTransactCheckRev
	clusterTransactDeleteTree
)

type clusterTransactVerb int

type transactEntry struct {
	verb  clusterTransactVerb
	key   string
	value []byte
	rev   uint64
}

type ClusterTransact struct {
	entries []transactEntry
}

func Transact() *ClusterTransact {
	return &ClusterTransact{}
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func (t *ClusterTransact) PutBinary(key string, value []byte) {
	if len(value) >= KVValueSizeMax {
		// we assume binary data is already in gzip format so do not try to gzip it again
		log.WithFields(log.Fields{"key": key, "len": len(value)}).Error(errSizeTooBig)
	} else {
		log.WithFields(log.Fields{"key": key}).Debug("Transact")

		t.entries = append(t.entries, transactEntry{
			verb: clusterTransactPut, key: key, value: value,
		})
	}
}

func (t *ClusterTransact) Put(key string, value []byte) {
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		log.WithFields(log.Fields{"key": key, "len": len(value)}).Error(errSizeTooBig)
	} else {
		log.WithFields(log.Fields{"key": key, "value": string(value)}).Debug("Transact")

		t.entries = append(t.entries, transactEntry{
			verb: clusterTransactPut, key: key, value: value,
		})
	}
}

func (t *ClusterTransact) PutQuiet(key string, value []byte) {
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		log.WithFields(log.Fields{"key": key, "len": len(value)}).Error(errSizeTooBig)
	} else {
		log.WithFields(log.Fields{"key": key}).Debug("Transact")

		t.entries = append(t.entries, transactEntry{
			verb: clusterTransactPut, key: key, value: value,
		})
	}
}

func (t *ClusterTransact) PutRev(key string, value []byte, rev uint64) {
	if len(value) >= KVValueSizeMax {
		// [20220712] for consul limitation
		// future: consider auto-gzip text data if text size >= 512k (kv watcher handler needs to take care auto-unzip)
		log.WithFields(log.Fields{"key": key, "len": len(value)}).Error(errSizeTooBig)
	} else {
		log.WithFields(log.Fields{"key": key, "value": string(value), "rev": rev}).Debug("Transact")

		t.entries = append(t.entries, transactEntry{
			verb: clusterTransactPutRev, key: key, value: value, rev: rev,
		})
	}
}

func (t *ClusterTransact) Delete(key string) {
	log.WithFields(log.Fields{"key": key}).Debug("Transact")

	t.entries = append(t.entries, transactEntry{
		verb: clusterTransactDelete, key: key,
	})
}

func (t *ClusterTransact) DeleteTree(key string) {
	log.WithFields(log.Fields{"key": key}).Debug("Transact")

	t.entries = append(t.entries, transactEntry{
		verb: clusterTransactDeleteTree, key: key,
	})
}

func (t *ClusterTransact) DeleteRev(key string, rev uint64) {
	log.WithFields(log.Fields{"key": key, "rev": rev}).Debug("Transact")

	t.entries = append(t.entries, transactEntry{
		verb: clusterTransactDeleteRev, key: key, rev: rev,
	})
}

func (t *ClusterTransact) CheckRev(key string, rev uint64) {
	log.WithFields(log.Fields{"key": key, "rev": rev}).Debug("Transact")

	t.entries = append(t.entries, transactEntry{
		verb: clusterTransactCheckRev, key: key, rev: rev,
	})
}

func apply(entries []transactEntry) (bool, error) {
	ok, err := driver.Transact(entries)
	if err != nil {
		for i := 0; i < putRetryTimes*2; i++ {
			time.Sleep(putRetryInterval)
			log.WithFields(log.Fields{"retry": i}).Debug(err)
			ok, err = driver.Transact(entries)
			if err == nil {
				return ok, nil
			}
		}
	}
	return ok, err
}

func (t *ClusterTransact) Apply() (bool, error) {
	log.Debug("Transact")

	if len(t.entries) == 0 {
		return true, nil
	}

	if len(t.entries) <= 64 {
		return apply(t.entries)
	} else {
		var errFinal error
		for i := 0; i < len(t.entries); i += 64 {
			entries := t.entries[i:min(i+64, len(t.entries))]
			if _, err := apply(entries); err != nil {
				log.WithFields(log.Fields{"i": i, "len": len(t.entries), "error": err}).Error("Failed to write txn keys")
				// There is no better way to handle one transaction error when there are >64 entries.
				// So we simply iterate the entries in this transaction and re-do them like the non-transaction approach.
				// However, by using transaction, we reduce the driver calls so theoretically we shuld see less error.
				for _, entry := range entries {
					switch entry.verb {
					case clusterTransactDelete:
						if err := Delete(entry.key); err != nil {
							log.WithFields(log.Fields{"key": entry.key, "error": err}).Error("delete")
							errFinal = err
						}
					case clusterTransactPut:
						if err := Put(entry.key, entry.value); err != nil {
							log.WithFields(log.Fields{"key": entry.key, "error": err}).Error("put")
							errFinal = err
						}
					case clusterTransactDeleteTree:
						if err := DeleteTree(entry.key); err != nil {
							log.WithFields(log.Fields{"key": entry.key, "error": err}).Error("delete tree")
							errFinal = err
						}
					}
				}
			}
		}
		if errFinal != nil {
			return false, errFinal
		}
		return true, nil
	}
}

func (t *ClusterTransact) HasData() bool {
	return len(t.entries) > 0
}

func (t *ClusterTransact) Reset() {
	t.entries = nil
}

func (t *ClusterTransact) Close() {
	t.entries = nil
}

func (t *ClusterTransact) Size() int {
	return len(t.entries)
}

// --

func GetSelfAddress() string {
	return driver.GetSelfAddress()
}

func getFirstResolvableAddr(addrStr string) net.IP {
	list := strings.Split(addrStr, ",")
	for _, a := range list {
		if ips, err := utils.ResolveIP(a); err == nil {
			for _, ip := range ips {
				if !ip.IsLoopback() {
					return ip
				}
			}
		}
	}
	return nil
}

func isBindGlobalScope(name string, ip net.IP, ifaces map[string][]share.CLUSIPAddr) bool {
	if addrs, ok := ifaces[name]; !ok {
		return false
	} else {
		for _, addr := range addrs {
			if addr.IPNet.IP.Equal(ip) {
				return addr.Scope == share.CLUSIPAddrScopeGlobal
			}
		}
		return false
	}
}

func ResolveJoinAndBindAddr(joinAddr string, sys *system.SystemTools) (string, string, error) {
	var retry uint = 0

	joinIP := getFirstResolvableAddr(joinAddr)
	for joinIP == nil {
		if retry < 5 {
			time.Sleep(time.Second * (1 << retry))
		} else {
			time.Sleep(time.Second * 30)
		}
		retry++
		log.WithFields(log.Fields{"join": joinAddr, "retry": retry}).Info("resolve")
		joinIP = getFirstResolvableAddr(joinAddr)
	}

	_, bindIPNet := sys.GetBindAddr(joinIP)
	if bindIPNet == nil {
		return joinIP.String(), "", errors.New("Failed to get bind addresses")
	}

	return joinIP.String(), bindIPNet.IP.String(), nil
}

func FillClusterAddrs(cfg *ClusterConfig, sys *system.SystemTools) error {
	log.WithFields(log.Fields{"join": cfg.JoinAddr, "advertise": cfg.AdvertiseAddr}).Info()

	if cfg.JoinAddr != "" {
		var retry uint = 0

		joinIP := getFirstResolvableAddr(cfg.JoinAddr)
		for joinIP == nil {
			if retry < 5 {
				// Set readiness if dns resolve fails, it's more likely this is the first server, make self available
				// for lead election; if dns is resolved, other servers are already running - it's possible it's
				// in the rolling upgrade process, don't make self ready until lead is found.
				if retry == 1 && cfg.Server {
					_ = utils.SetReady("cluster init")
				}
				time.Sleep(time.Second * (1 << retry))
			} else {
				time.Sleep(time.Second * 30)
			}
			retry++
			log.WithFields(log.Fields{"join": cfg.JoinAddr, "retry": retry}).Info("resolve")
			joinIP = getFirstResolvableAddr(cfg.JoinAddr)
		}

		// If dns is resolved in first try, it's more likely to be a new controller, give it more time for the
		// existing server to become leader.

		// Always get bind IP
		iface, bindIPNet := sys.GetBindAddr(joinIP)
		if bindIPNet == nil {
			return errors.New("Failed to get bind addresses")
		}

		if cfg.BindAddr == "" {
			cfg.BindAddr = bindIPNet.IP.String()
		}

		// Get adv. IP if not empty
		var advIP net.IP
		if cfg.AdvertiseAddr == "" {
			ones, _ := bindIPNet.Mask.Size()
			if ones == 0 {
				// joinAddr is a local port. This is must be a bootstrap server, either running
				// in host mode or overlay networking mode. This is allow user to use JOIN_ADDR,
				// instead of ADV_ADDR, for bootstrap server
				advIP = bindIPNet.IP
			} else if bindIPNet.Contains(joinIP) {
				// joinIP and bindIP are in the same subnet, this is client or non-first server,
				// running either in host mode or overlay networking mode.
				advIP = bindIPNet.IP
			} else if isBindGlobalScope(iface, bindIPNet.IP, cfg.Ifaces) {
				advIP = bindIPNet.IP
			} else {
				if adv := sys.GetAdvertiseAddr(joinIP); adv == nil {
					return errors.New("Failed to get advertise addresses")
				} else {
					advIP = adv
				}
			}

			cfg.AdvertiseAddr = advIP.String()
		}

		addrs, _ := utils.ResolveAddrList(cfg.JoinAddr, true)
		for len(addrs) == 0 {
			time.Sleep(time.Second * 5)
			addrs, _ = utils.ResolveAddrList(cfg.JoinAddr, true)
		}
		cfg.joinAddrList = addrs

		log.WithFields(log.Fields{"bind": cfg.BindAddr, "advertise": cfg.AdvertiseAddr}).Debug()
		return nil
	} else {
		// If Bootstrap is set without JoinAddr, assume this is the first server node
		if cfg.AdvertiseAddr != "" {
			// Address specified, other nodes should join with addresses too.
			if cfg.BindAddr == "" {
				_, bindIPNet := sys.GetBindAddr(net.ParseIP(cfg.AdvertiseAddr))
				if bindIPNet != nil {
					cfg.BindAddr = bindIPNet.IP.String()
					log.WithFields(log.Fields{"bind": cfg.BindAddr}).Debug()
					return nil
				} else {
					return errors.New("Failed to get cluster bind addresses")
				}
			}
			// When JoinAddr is not set, we assume it is the first server node, and set
			// its JoinAddr to be the same with AdvertiseAddr
			cfg.JoinAddr = cfg.AdvertiseAddr
			cfg.joinAddrList = []string{cfg.AdvertiseAddr}
			return nil
		} else {
			// Not NAT. Locate a unique phyical port to bind
			if cfg.BindAddr == "" {
				ifaces := sys.GetGlobalAddrs(true)
				// Pick the first address to bind
				for _, ipnets := range ifaces {
					if len(ipnets) > 0 {
						cfg.BindAddr = ipnets[0].IP.String()
						cfg.JoinAddr = cfg.BindAddr
						cfg.joinAddrList = []string{cfg.BindAddr}
						cfg.AdvertiseAddr = cfg.BindAddr
						log.WithFields(log.Fields{"bind": cfg.BindAddr}).Debug()
						return nil
					}
				}
				log.Error("No address to bind")
				return errors.New("No address to bind")
			}

			cfg.JoinAddr = cfg.BindAddr
			cfg.joinAddrList = []string{cfg.BindAddr}
			cfg.AdvertiseAddr = cfg.BindAddr
			return nil
		}
		/*
			} else {
				log.Error("Node should either bootstrap a cluster or join a cluster")
				return errors.New("Node should either bootstrap a cluster or join a cluster")
		*/
	}
}

func Reload(cc *ClusterConfig) error {
	config := cc
	if cc == nil {
		config = &clusterCfg
	}
	return driver.Reload(config)
}

var curLogLevel log.Level = log.InfoLevel

func SetLogLevel(level log.Level) {
	if level == curLogLevel {
		return
	}

	switch level {
	case log.ErrorLevel:
	case log.WarnLevel:
	case log.InfoLevel:
		clusterCfg.Debug = false
	case log.DebugLevel:
		clusterCfg.Debug = true
	default:
		log.WithFields(log.Fields{"level": level}).Error("Not supported")
		return
	}
	// Disable toggling consul debug level
	curLogLevel = level

	/*
		if err := driver.Reload(&clusterCfg); err == nil {
			curLogLevel = level
		}
	*/
}
