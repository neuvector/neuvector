package rest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type RoleRquired int

type cmdResponse struct {
	id     string
	result int
}

const (
	_fedAdminRequired RoleRquired = iota
	_adminRequired
	_localAdminRequired
	_readerRequired
	_fedReaderRequired
)

const (
	_notForward = false
	_isForward  = true
)

const (
	_cmdPollFedRules      = "poll"
	_cmdForcePullFedRules = "force_pull"
)

const (
	FedRoleAny         = "*"
	FedRoleMasterJoint = "~"
)

const (
	_tagJoinFed            = "join"
	_tagVerifyJointCluster = "verify"
	_tagAuthJointCluster   = "auth"
	_tagPingJointCluster   = "ping"
	_tagPollMasterCluster  = "poll"
	_tagDeployFedPolicy    = "deploy" // notify joint clusters to poll fed rules/settings. triggered by fed policy changes implicitly
	_tagFedSyncPolicy      = "sync"   // notify joint clusters to poll fed rules/settings. triggered by explicit REST api request
	_tagKickJointCluster   = "remove"
	_tagLeaveFed           = "leave"
	_tagDismissFed         = "dismiss"
	_tagFedForward         = "forward"
)

const (
	_fedSuccess               = iota // do not change order
	_fedCmdUnknown                   // do not change order
	_fedCmdReceived                  // do not change order
	_fedCmdReqError                  // do not change order
	_fedMasterUpgradeRequired = 101  // do not change
	_fedJointUpgradeRequired  = 102  // do not change
	_fedClusterUpgradeOngoing = 103  // do not change
	_fedJointVersionTooNew    = 104  // do not change
	_fedClusterConnected      = 200  // do not change
	_fedClusterJoined         = 201  // do not change
	_fedClusterOutOfSync      = 202  // do not change
	_fedClusterSynced         = 203  // do not change
	_fedClusterDisconnected   = 204  // do not change
	_fedClusterKicked         = 205  // do not change
	_fedClusterLeft           = 206  // do not change
	_fedLicenseDisallowed     = 207  // do not change
	_fedClusterPinging        = 208  // do not change
	_fedClusterSyncing        = 209  // do not change
	_fedClusterNetworkError   = 300  // do not change. this state is not visible on UI
	_fedClusterImporting      = 301  // do not change. this state is not visible on UI
)

const clusterAuthTimeout = time.Duration(10 * time.Second)
const restForInstantPing = time.Duration(8 * time.Second)

const jsonContentType = "application/json"

const (
	const_no_proxy = iota
	const_https_proxy
	const_http_proxy
)

var _isLeader uint32
var reqTokenLock sync.Mutex

var _fedPingOngoing uint32
var _fedPollOngoing uint32
var _fedDeployCount uint32
var _fedFullPolling uint32                                                                      // 0: modified rules polling, 1: full rules polling
var _fedPollInterval uint32 = 1                                                                 // in minutes
var _fedPollingTimer *time.Timer = time.NewTimer(time.Minute * time.Duration(_fedPollInterval)) // for joint clusters to poll master cluster
var _fedPingInterval uint32 = 1                                                                 // in minutes
var _fedPingTimer *time.Timer = time.NewTimer(time.Minute * time.Duration(_fedPingInterval))    // for master cluster to ping master clusters
var _lastFedMemberPingTime time.Time = time.Now()
var _masterClusterIP string

var _sysHttpsProxy share.CLUSProxy
var _sysHttpProxy share.CLUSProxy
var _proxyOptionHistory = make(map[string]int8)           // key is clusterID. "" means it's for communication with master; value is 0(no proxy), 1(https proxy), 2(http proxy)
var _httpClients []*http.Client = make([]*http.Client, 3) // index is 0(no proxy), 1(https proxy), 2(http proxy)
var _httpClientMutex sync.RWMutex

var jointNWErrCount map[string]int // key: joint cluster id, value: consecutive ping failure count because of http.Client.Do()

var _clusterStatusMap = map[int]string{
	_fedSuccess:               api.FedClusterStatusNone,
	_fedCmdUnknown:            api.FedClusterStatusCmdUnknown,
	_fedCmdReceived:           api.FedClusterStatusCmdReceived,
	_fedCmdReqError:           api.FedClusterStatusCmdReqError,
	_fedMasterUpgradeRequired: api.FedStatusMasterUpgradeRequired,
	_fedJointUpgradeRequired:  api.FedStatusJointUpgradeRequired,
	_fedClusterUpgradeOngoing: api.FedStatusClusterUpgradeOngoing,
	_fedJointVersionTooNew:    api.FedStatusJointVersionTooNew,
	_fedClusterConnected:      api.FedStatusClusterConnected,
	_fedClusterJoined:         api.FedStatusClusterJoined,
	_fedClusterOutOfSync:      api.FedStatusClusterOutOfSync,
	_fedClusterSynced:         api.FedStatusClusterSynced,
	_fedClusterDisconnected:   api.FedStatusClusterDisconnected,
	_fedClusterKicked:         api.FedStatusClusterKicked,
	_fedClusterLeft:           api.FedStatusClusterLeft,
	_fedLicenseDisallowed:     api.FedStatusLicenseDisallowed,
	_fedClusterPinging:        api.FedStatusClusterPinging,
	_fedClusterSyncing:        api.FedStatusClusterSyncing,
}

var ibmSACfg share.CLUSIBMSAConfig

func LeadChangeNotify(leader bool) {
	log.WithFields(log.Fields{"isLeader": leader}).Info()
	if leader {
		atomic.StoreUint32(&_isLeader, 1)
		if k8sPlatform && leader {
			k8sInfo := map[string]string{
				resource.NvAdmSvcName: resource.NvAdmValidatingName,
				resource.NvCrdSvcName: resource.NvCrdValidatingName,
			}
			for svcName, nvAdmName := range k8sInfo {
				cn := fmt.Sprintf("%s.%s.svc", svcName, resource.NvAdmSvcNamespace)
				if cert, _, err := clusHelper.GetObjectCertRev(cn); !cert.IsEmpty() {
					admission.ResetCABundle(svcName, []byte(cert.Cert))
					cacher.SyncAdmCtrlStateToK8s(svcName, nvAdmName)
				} else {
					log.WithFields(log.Fields{"cn": cn, "err": err}).Error("no cert")
				}
			}
		}
	} else {
		atomic.StoreUint32(&_isLeader, 0)
	}
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
		if leader {
			_fedPingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPingInterval)))
		} else {
			_fedPingTimer.Stop()
		}
	} else if fedRole == api.FedRoleJoint {
		if leader {
			_fedPollingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPollInterval)))
		} else {
			_fedPollingTimer.Stop()
		}
	} else {
		_fedPingTimer.Stop()
		_fedPollingTimer.Stop()
	}

	if leader {
		if cfg, _ := clusHelper.GetSystemConfigRev(access.NewReaderAccessControl()); cfg != nil {
			if cfg.IBMSAConfigNV.EpEnabled && cfg.IBMSAConfigNV.EpStart == 1 {
				var param interface{} = &cfg.IBMSAConfig
				StartStopFedPingPoll(share.StartPostToIBMSA, 0, param)
			}
		}
	} else {
		// if this controller just lost leadership, do not post to IBM SA in this controller until it becomes leader again
		StartStopFedPingPoll(share.StopPostToIBMSA, 0, nil)
	}
}

func cacheFedEvent(ev share.TLogEvent, msg, fullname, remote, session string, roles map[string]string) error {
	if ev >= share.CLUSEvFedPromote && ev <= share.CLUSEvFedPolicySync {
		alog := share.CLUSEventLog{
			Event:          ev,
			HostID:         localDev.Host.ID,
			HostName:       localDev.Host.Name,
			ControllerID:   localDev.Ctrler.ID,
			ControllerName: localDev.Ctrler.Name,
			ReportedAt:     time.Now().UTC(),
			User:           fullname,
			UserRoles:      roles,
			UserAddr:       remote,
			UserSession:    session,
			Msg:            msg,
		}
		evqueue.Append(&alog)
	}

	return nil
}

func lockClusKey(w http.ResponseWriter, key string) (cluster.LockInterface, error) {
	lock, err := clusHelper.AcquireLock(key, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "key": key}).Error("Failed to acquire cluster lock")
		if w != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		}
		return nil, err
	} else {
		return lock, err
	}
}

func purgeFedRules() {
	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	cleanFedRules()
}

func FedPollingClient(leader, purgeFedRulesOnJoint bool) {
	if leader {
		atomic.StoreUint32(&_isLeader, 1)
	} else {
		atomic.StoreUint32(&_isLeader, 0)
	}
	if m := clusHelper.GetFedMembership(); m != nil {
		if m.FedRole == api.FedRoleMaster {
			_fedPollingTimer.Stop()
			if leader {
				go pingJointClusters()
			}
		} else if m.FedRole == api.FedRoleJoint {
			_fedPingTimer.Stop()
			if purgeFedRulesOnJoint {
				purgeFedRules()
			}
			pollFedRules(false, 1)
		} else {
			_fedPingTimer.Stop()
			_fedPollingTimer.Stop()
		}
	}
	cSig := make(chan os.Signal, 1)
	signal.Notify(cSig, os.Interrupt, syscall.SIGTERM)
Loop:
	for {
		select {
		case <-_fedPollingTimer.C:
			fullPolling := atomic.SwapUint32(&_fedFullPolling, 0)
			if pollFedRules(fullPolling == 1, 1) {
				if leader := atomic.LoadUint32(&_isLeader); leader == 1 {
					_fedPollingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPollInterval)))
				} else {
					_fedPollingTimer.Stop()
				}
			}
		case <-cSig:
			break Loop
		}
	}
}

func isFedOpAllowed(expectedFedRole string, roleRequired RoleRquired, w http.ResponseWriter, r *http.Request) (*access.AccessControl, *loginSession) {
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return nil, nil
	} else {
		var ok bool
		switch roleRequired {
		case _fedAdminRequired:
			ok = acc.IsFedAdmin()
		case _fedReaderRequired:
			ok = acc.IsFedReader() || acc.IsFedAdmin()
		case _adminRequired:
			ok = acc.CanWriteCluster()
		case _localAdminRequired:
			if acc.CanWriteCluster() && (login.server == "" || strings.HasPrefix(login.mainSessionID, _rancherSessionPrefix)) {
				ok = true
			}
		case _readerRequired:
			ok = acc.HasGlobalPermissions(share.PERMS_CLUSTER_READ, 0)
		}
		if !ok {
			restRespAccessDenied(w, login)
			return nil, nil
		}
	}

	var fedRole string
	var err error
	if acc.IsFedReader() {
		fedRole, err = cacher.GetFedMembershipRole(access.NewFedAdminAccessControl())
	} else {
		fedRole, err = cacher.GetFedMembershipRole(acc)
	}
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return nil, nil
	} else if expectedFedRole == FedRoleMasterJoint {
		if fedRole != api.FedRoleMaster && fedRole != api.FedRoleJoint {
			restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
			return nil, nil
		}
	} else if expectedFedRole != FedRoleAny && fedRole != expectedFedRole {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return nil, nil
	}

	return acc, login
}

func isFedRulesCleanupOngoing(w http.ResponseWriter) bool {
	if m := clusHelper.GetFedMembership(); m != nil && m.FedRole == api.FedRoleNone && m.PendingDismiss {
		if diff := time.Now().Sub(m.PendingDismissAt); diff.Minutes() <= 5 {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrOpNotAllowed, "Federate rules cleanup is still ongoing. Please try again later.")
			return true
		}
	}
	return false
}

// Be careful. This function is only for between-clusters joining/leaving APIs
func isNoAuthFedOpAllowed(expectedFedRole string, w http.ResponseWriter, r *http.Request, acc *access.AccessControl) bool {
	fedRole, err := cacher.GetFedMembershipRole(acc)
	if err != nil || (expectedFedRole != FedRoleAny && fedRole != expectedFedRole) {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return false
	}

	return true
}

func createHttpClient(proxyOption int8, timeout time.Duration) *http.Client {
	// refer to http.DefaultTransport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.WithFields(log.Fields{"proxyOption": proxyOption, "err": err}).Error("creating cookie jar")
	} else {
		httpClient.Jar = jar
	}
	setHttpTransport(proxyOption, httpClient)

	return httpClient
}

func setHttpTransport(proxyOption int8, httpClient *http.Client) {
	if transport, _ := httpClient.Transport.(*http.Transport); transport != nil {
		var proxy share.CLUSProxy

		if proxyOption != const_no_proxy {
			_httpClientMutex.RLock()
			if proxyOption == const_http_proxy {
				proxy = _sysHttpProxy
			} else {
				proxy = _sysHttpsProxy
			}
			_httpClientMutex.RUnlock()
		}
		if !proxy.Enable {
			transport.ProxyConnectHeader = nil
			transport.Proxy = nil
		} else {
			if proxy.Username != "" {
				auth := fmt.Sprintf("%s:%s", proxy.Username, proxy.Password)
				basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
				transport.ProxyConnectHeader = http.Header{}
				transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
			}
			proxyUrl, _ := url.Parse(proxy.URL)
			transport.Proxy = http.ProxyURL(proxyUrl)
		}
	}
}

func getProxyOptions(id, useProxy string, proxyOptions *[]int8) {
	var ok bool
	var lastProxyOption int8
	var cfgProxyOption int8 = const_no_proxy

	_httpClientMutex.RLock()
	lastProxyOption, ok = _proxyOptionHistory[id]
	_httpClientMutex.RUnlock()

	if useProxy != "" {
		cfgProxyOption = const_https_proxy
		if useProxy == "http" {
			cfgProxyOption = const_http_proxy
		}
	}

	if !ok { // this is the first http connection for this cluster
		if cfgProxyOption != const_no_proxy {
			*proxyOptions = append(*proxyOptions, cfgProxyOption)
		}
	} else {
		*proxyOptions = append(*proxyOptions, lastProxyOption)
		if cfgProxyOption != lastProxyOption {
			*proxyOptions = append(*proxyOptions, cfgProxyOption)
		}
	}
	hasNoProxyOption := false
	for _, proxyOption := range *proxyOptions {
		if proxyOption == const_no_proxy {
			hasNoProxyOption = true
			break
		}
	}
	if !hasNoProxyOption {
		*proxyOptions = append(*proxyOptions, const_no_proxy)
	}
}

func sendRestRequest(idTarget string, method, urlStr, token string, cookie *http.Cookie, body []byte,
	logError bool, specificProxy *string, acc *access.AccessControl) ([]byte, int, bool, error) {

	var useProxy string
	var httpClientTemp *http.Client
	var data []byte
	var statusCode int
	var usedProxy bool
	var err error

	if idTarget == "rancher" {
		useProxy = *specificProxy
	} else {
		if specificProxy != nil {
			useProxy = *specificProxy
		} else {
			_, useProxy = cacher.GetFedLocalRestInfo(acc)
		}
	}
	proxyOptions := make([]int8, 0, 4)
	getProxyOptions(idTarget, useProxy, &proxyOptions)
	if strings.HasSuffix(urlStr, "/join_internal") {
		httpClientTemp = createHttpClient(const_no_proxy, clusterAuthTimeout*2+4)
	}

	for _, proxyOption := range proxyOptions {
		var httpClient *http.Client
		if httpClientTemp != nil {
			setHttpTransport(proxyOption, httpClientTemp)
			httpClient = httpClientTemp
		} else {
			_httpClientMutex.RLock()
			httpClient = _httpClients[proxyOption]
			_httpClientMutex.RUnlock()
		}
		if data, statusCode, err = sendRestReqInternal(httpClient, method, urlStr, token, proxyOption, cookie, body, logError); err == nil {
			_httpClientMutex.Lock()
			_proxyOptionHistory[idTarget] = proxyOption
			_httpClientMutex.Unlock()
			if transport, _ := httpClient.Transport.(*http.Transport); transport != nil && transport.Proxy != nil {
				usedProxy = true
			}
			break
		}
	}

	return data, statusCode, usedProxy, err
}

func sendRestReqInternal(httpClient *http.Client, method, urlStr, token string, proxyOption int8,
	cookie *http.Cookie, body []byte, logError bool) ([]byte, int, error) {

	var req *http.Request
	var err error

	switch method {
	case "GET":
		req, err = http.NewRequest(method, urlStr, nil)
	default:
		req, err = http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	}
	if err != nil {
		log.WithFields(log.Fields{"url": urlStr, "error": err, "proxyOption": proxyOption}).Error("Failed to create request")
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	if token != "" {
		req.Header.Set(api.RESTTokenHeader, token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if logError {
			log.WithFields(log.Fields{"url": urlStr, "err": err, "proxyOption": proxyOption, "timeout": httpClient.Timeout}).Error("Failed to make request")
		}
		errMsg := err.Error()
		if idx := strings.Index(errMsg, urlStr); idx >= 0 {
			errMsg = errMsg[idx+len(urlStr):]
			if len(errMsg) > 1 && errMsg[0] == '"' {
				errMsg = errMsg[1:]
			}
			if len(errMsg) > 0 && errMsg[0] == ':' {
				errMsg = errMsg[1:]
			}
			err = errors.New(strings.Trim(errMsg, " "))
		}
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"url": urlStr, "status": resp.Status, "proxyOption": proxyOption}).Error("Read data fail")
		return nil, 0, err
	} else {
		if resp.StatusCode != http.StatusOK {
			if logError {
				log.WithFields(log.Fields{"url": urlStr, "status": resp.Status, "proxyOption": proxyOption, "timeout": httpClient.Timeout}).Error("Request failed")
			}
			err = errors.New(resp.Status)
		} else {
			switch resp.Header.Get("Content-Encoding") {
			case "gzip":
				data = utils.GunzipBytes(data)
			}
		}
		return data, resp.StatusCode, err
	}
}

func RestConfig(cmd, interval uint32, param1 interface{}, param2 interface{}) error {
	var err error
	switch cmd {
	case share.UpdateProxyInfo:
		if param1 != nil || param2 != nil {
			var httpClient *http.Client
			var httpsProxy share.CLUSProxy
			var httpProxy share.CLUSProxy

			_httpClientMutex.RLock()
			httpsProxy = _sysHttpsProxy
			httpProxy = _sysHttpProxy
			_httpClientMutex.RUnlock()

			cfgHttpsProxy, _ := param1.(*share.CLUSProxy)
			cfgHttpProxy, _ := param2.(*share.CLUSProxy)
			cfgProxies := []*share.CLUSProxy{cfgHttpsProxy, cfgHttpProxy}
			proxies := []share.CLUSProxy{httpsProxy, httpProxy}
			cachedProxies := []*share.CLUSProxy{&_sysHttpsProxy, &_sysHttpProxy}
			proxyOptions := []int8{const_https_proxy, const_http_proxy}

			for i := 0; i < len(proxyOptions); i++ {
				if cfgProxies[i] != nil {
					cfgProxy := *(cfgProxies[i])
					if !cfgProxy.Enable {
						cfgProxy = share.CLUSProxy{}
					}
					if cfgProxy != proxies[i] {
						_httpClientMutex.Lock()
						*(cachedProxies[i]) = cfgProxy
						httpClient = _httpClients[proxyOptions[i]]
						_httpClientMutex.Unlock()

						setHttpTransport(proxyOptions[i], httpClient)
					}
				}
			}
		}
	}

	return err
}

func initHttpClients() {
	if cfg, _ := clusHelper.GetSystemConfigRev(access.NewReaderAccessControl()); cfg != nil {
		_httpClientMutex.Lock()
		if cfg.RegistryHttpsProxy.Enable {
			_sysHttpsProxy = cfg.RegistryHttpsProxy
		}
		if cfg.RegistryHttpProxy.Enable {
			_sysHttpProxy = cfg.RegistryHttpProxy
		}
		_httpClientMutex.Unlock()
	}
	for _, proxyOption := range []int8{const_no_proxy, const_https_proxy, const_http_proxy} {
		httpClient := createHttpClient(proxyOption, clusterAuthTimeout)
		_httpClientMutex.Lock()
		if _httpClients[proxyOption] == nil {
			_httpClients[proxyOption] = httpClient
		}
		_httpClientMutex.Unlock()
	}
}

// it returns (headers, statusCode, data, proxyUsed, err)
func sendReqToJointCluster(rc share.CLUSRestServerInfo, clusterID, token, method, request, contentType, tag, txnID string,
	body []byte, forward, remoteExport, logError bool, acc *access.AccessControl) (map[string]string, int, []byte, bool, error) {

	var httpClientTemp *http.Client
	var headers map[string]string
	var statusCode int
	var data []byte
	var usedProxy bool
	var err error

	proxyOptions := make([]int8, 0, 4)
	_, useProxy := cacher.GetFedLocalRestInfo(acc)
	getProxyOptions(clusterID, useProxy, &proxyOptions)

	if method == http.MethodPost && request == "/v1/scan/repository" {
		httpClientTemp = createHttpClient(const_no_proxy, repoScanLingeringDuration+time.Duration(30*time.Second))
	}

	urlStr := fmt.Sprintf("https://%s:%d/%s", rc.Server, rc.Port, request)
	for _, proxyOption := range proxyOptions {
		var httpClient *http.Client
		if httpClientTemp != nil {
			setHttpTransport(proxyOption, httpClientTemp)
			httpClient = httpClientTemp
		} else {
			_httpClientMutex.RLock()
			httpClient = _httpClients[proxyOption]
			_httpClientMutex.RUnlock()
		}
		if headers, statusCode, data, err = sendReqToJointClusterInternal(httpClient, method, urlStr, token,
			contentType, tag, txnID, proxyOption, body, forward, remoteExport, logError); err == nil {
			_httpClientMutex.Lock()
			_proxyOptionHistory[clusterID] = proxyOption
			_httpClientMutex.Unlock()
			if transport, _ := httpClient.Transport.(*http.Transport); transport != nil && transport.Proxy != nil {
				usedProxy = true
			}
			break
		}
	}

	return headers, statusCode, data, usedProxy, err
}

func sendReqToJointClusterInternal(httpClient *http.Client, method, urlStr, token, contentType, tag, txnID string, proxyOption int8,
	body []byte, forward, remoteExport, logError bool) (map[string]string, int, []byte, error) {

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	if err != nil {
		log.WithFields(log.Fields{"url": urlStr, "tag": tag, "error": err, "proxyOption": proxyOption}).Error("Failed to create request")
		return nil, 0, nil, err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept-Encoding", "gzip")
	if token != "" {
		req.Header.Set(api.RESTTokenHeader, token)
	}
	if txnID != "" {
		req.Header.Set("X-Transaction-ID", txnID)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if logError {
			log.WithFields(log.Fields{"url": urlStr, "tag": tag, "error": err, "proxyOption": proxyOption, "timeout": httpClient.Timeout}).Error("Failed to make request")
		}
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if logError {
			log.WithFields(log.Fields{"url": urlStr, "tag": tag, "error": err, "proxyOption": proxyOption, "timeout": httpClient.Timeout}).Error("Read data fail")
		}
		return nil, 0, nil, err
	} else if !forward { // we do decompression only when it's not a forward request because the caller will try to decompress it again
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			data = utils.GunzipBytes(data)
		}
		return nil, resp.StatusCode, data, nil
	} else {
		// it's a forward request
		headers := make(map[string]string, 3)
		hNames := []string{"Content-Encoding", "X-Transaction-ID", "Cache-Control", "Content-Type"}
		if remoteExport {
			hNames = append(hNames, "Content-Disposition")
		}
		for _, hName := range hNames {
			if v := resp.Header.Get(hName); v != "" {
				headers[hName] = v
			}
		}
		return headers, resp.StatusCode, data, nil
	}
}

// called by master cluster only
func getJointClusterToken(rc *share.CLUSFedJointClusterInfo, clusterID string, user *share.CLUSUser, refreshToken bool,
	acc *access.AccessControl, login *loginSession) (string, error) {
	if user == nil || (user.Role != api.UserRoleFedAdmin && user.Role != api.UserRoleFedReader) {
		return "", common.ErrObjectAccessDenied
	}
	reqTokenLock.Lock()
	defer reqTokenLock.Unlock()

	if !refreshToken {
		return cacher.GetFedJoinedClusterToken(clusterID, login.id, acc)
	} else {
		var remoteRole string
		switch user.Role {
		case api.UserRoleFedAdmin:
			remoteRole = api.UserRoleAdmin
		case api.UserRoleFedReader:
			remoteRole = api.UserRoleReader
		default:
			return "", common.ErrObjectAccessDenied
		}
		reqTo := &api.RESTFedAuthData{
			ClientIP:       _masterClusterIP,
			MasterUsername: login.fullname,
			JointUsername:  common.DefaultAdminUser,
			// master token is for requesting regular token from joint cluster. It can be validated by joint cluster based on shared secret/key/cert between master & joint clusters
			MasterToken: jwtGenFedMasterToken(user, login, remoteRole, rc.ID, rc.Secret),
		}
		if reqTo.MasterToken == "" {
			return "", common.ErrObjectAccessDenied
		}

		var err error
		var data []byte
		var statusCode int
		var proxyUsed bool
		body, _ := json.Marshal(reqTo)
		// call joint cluster for generating a regular auth token
		if _, statusCode, data, proxyUsed, err = sendReqToJointCluster(rc.RestInfo, clusterID, "", http.MethodPost, "v1/fed_auth",
			"", jsonContentType, _tagAuthJointCluster, body, _notForward, false, true, acc); err == nil {
			if statusCode != http.StatusOK {
				log.WithFields(log.Fields{"cluster": rc.RestInfo.Server, "status": statusCode, "proxyUsed": proxyUsed}).Error("Unable to authenticate with the cluster")
				err = errors.New("Unable to authenticate with the cluster")
			} else {
				tokenData := api.RESTTokenData{}
				if err = json.Unmarshal(data, &tokenData); err == nil {
					cacher.SetFedJoinedClusterToken(clusterID, login.id, tokenData.Token.Token)
					return tokenData.Token.Token, nil
				} else {
					log.WithFields(log.Fields{"cluster": rc.RestInfo.Server, "proxyUsed": proxyUsed, "error": err}).Error("unmarshal token")
				}
			}
		} else {
			if statusCode == http.StatusUnauthorized {
				reloadJointPubPrivKey(api.FedRoleMaster, clusterID)
			}
		}
		return "", err
	}
}

func talkToJointCluster(rc *share.CLUSFedJointClusterInfo, method, request, id, tag string, body []byte, ch chan<- cmdResponse,
	acc *access.AccessControl, login *loginSession) int {
	log.WithFields(log.Fields{"method": method, "id": id}).Debug()
	user, _, _ := clusHelper.GetUserRev(login.fullname, acc)
	cmdResp := cmdResponse{id: id, result: _fedClusterDisconnected}
	var status int

	// we cache the token for forwarded requests(to joint clusters). so we try the cached token first and ask for a new token if necessary.
	for _, refreshToken := range []bool{false, true} {
		status = http.StatusBadRequest
		if token, err := getJointClusterToken(rc, id, user, refreshToken, acc, login); token != "" { // get a regular token for accessing joint cluster
			if _, statusCode, data, proxyUsed, err := sendReqToJointCluster(rc.RestInfo, id, token, method,
				request, jsonContentType, tag, "", body, _notForward, false, refreshToken, acc); err == nil {
				if statusCode == http.StatusRequestTimeout {
					continue
				} else if statusCode == http.StatusOK || statusCode == http.StatusCreated || statusCode == http.StatusAccepted {
					status = http.StatusOK
					if ch != nil {
						var result api.RESTFedInternalCommandResp
						if err := json.Unmarshal(data, &result); err == nil {
							cmdResp.result = result.Result
						}
					}
					break
				} else {
					status = statusCode
					log.WithFields(log.Fields{"cluster": rc.RestInfo.Server, "status": status, "proxyUsed": proxyUsed}).Error("failed to send")
				}
			}
		} else if refreshToken {
			if err == common.ErrObjectAccessDenied {
				cmdResp.result = _fedCmdReqError
				break
			}
		}
	}
	if ch != nil {
		ch <- cmdResp
	}
	return status
}

// share.CLUSLockFedKey lock is owned by caller
func informFedDismissed(joinedCluster share.CLUSFedJointClusterInfo, bodyTo []byte, ch chan<- bool, acc *access.AccessControl, login *loginSession) {
	talkToJointCluster(&joinedCluster, http.MethodPost, "v1/fed/remove_internal", joinedCluster.ID, _tagDismissFed, bodyTo, nil, acc, login)
	_, jointKeyPath, jointCertPath := kv.GetFedTlsKeyCertPath("", joinedCluster.ID)
	os.Remove(jointKeyPath)
	os.Remove(jointCertPath)
	_setFedJointPrivateKey(joinedCluster.ID, nil)
	clusHelper.DeleteFedJointCluster(joinedCluster.ID)
	ch <- true
}

func revertMappedFedRoles(groupRoleMappings []*share.GroupRoleMapping) {
	for _, groupRoleMapping := range groupRoleMappings {
		if groupRoleMapping.GlobalRole == api.UserRoleFedAdmin {
			groupRoleMapping.GlobalRole = api.UserRoleAdmin
		} else if groupRoleMapping.GlobalRole == api.UserRoleFedReader {
			groupRoleMapping.GlobalRole = api.UserRoleReader
		}
		if groupRoleMapping.RoleDomains != nil {
			if _, ok := groupRoleMapping.RoleDomains[groupRoleMapping.GlobalRole]; ok {
				delete(groupRoleMapping.RoleDomains, groupRoleMapping.GlobalRole)
			}
		}
	}
}

func revertFedRoles(acc *access.AccessControl) {
	fedAdjusted := map[string]string{api.UserRoleFedAdmin: api.UserRoleAdmin, api.UserRoleFedReader: api.UserRoleReader}
	users := clusHelper.GetAllUsers(acc)
	for _, user := range users {
		if adjusted, ok := fedAdjusted[user.Role]; ok {
			clusHelper.ConfigFedRole(user.Fullname, adjusted, acc)
		}
	}

	servers := clusHelper.GetAllServers(acc)
	for _, server := range servers {
		if !isAuthServer(server) {
			continue
		}
		retry := 0
		for retry < retryClusterMax {
			cs, rev, _ := clusHelper.GetServerRev(server.Name, acc)
			if cs != nil {
				if cs.LDAP != nil {
					revertMappedFedRoles(cs.LDAP.GroupMappedRoles)
				} else if cs.SAML != nil {
					revertMappedFedRoles(cs.SAML.GroupMappedRoles)
				} else if cs.OIDC != nil {
					revertMappedFedRoles(cs.OIDC.GroupMappedRoles)
				}
				if err := clusHelper.PutServerRev(cs, rev); err == nil {
					break
				}
			}
			retry++
		}
		if retry >= retryClusterMax {
			log.WithFields(log.Fields{"server": server.Name}).Error("Revert fed role fails")
		}
	}
}

// caller must own share.CLUSLockFedKey lock
func cleanFedRules() {
	admRules := &share.CLUSAdmissionRules{
		RuleMap:   make(map[uint32]*share.CLUSAdmissionRule),
		RuleHeads: []*share.CLUSRuleHead{},
	}
	replaceFedAdmissionRules(share.FedAdmCtrlExceptRulesType, admRules)
	replaceFedAdmissionRules(share.FedAdmCtrlDenyRulesType, admRules)

	resRulesData := &share.CLUSFedResponseRulesData{
		Rules:     make(map[uint32]*share.CLUSResponseRule),
		RuleHeads: make([]*share.CLUSRuleHead, 0),
	}
	replaceFedResponseRules(resRulesData.Rules, resRulesData.RuleHeads)
	cluster.Delete(share.CLUSFedSystemKey)

	deleteFedGroupPolicy()

	clusHelper.UpdateFedRulesRevision(nil)
}

func leaveFedCleanup(masterID, jointID string) {
	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	masterCaCertPath, jointKeyPath, jointCertPath := kv.GetFedTlsKeyCertPath(masterID, jointID)
	os.Remove(masterCaCertPath)
	os.Remove(jointKeyPath)
	os.Remove(jointCertPath)
	clusHelper.DeleteFedJointClusterStatus(masterID)
	clusHelper.DeleteFedJointClusterStatus(jointID)
	delAllFedSessionTokens()
	resetFedJointKeys()
	cleanFedRules()
}

func updateSystemClusterName(newName string, acc *access.AccessControl) string {
	name := cacher.GetSystemConfigClusterName(acc)
	if name == "" && newName == "" {
		// for upgraded nv, use default cluster name if cluster name in system config is empty
		newName = common.DefaultSystemConfig.ClusterName
	}
	if newName != "" && newName != name {
		retry := 0
		for retry < retryClusterMax {
			// Retrieve from the cluster
			cconf, rev := clusHelper.GetSystemConfigRev(acc)
			if cconf != nil {
				cconf.ClusterName = newName
				if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
					log.WithFields(log.Fields{"error": err, "rev": rev}).Error("write to cluster failed")
					retry++
				} else {
					break
				}
			}
		}
		if retry < retryClusterMax {
			name = newName
		}
	}

	return name
}

func updateClusterState(id string, status int, acc *access.AccessControl) bool {
	if status == _fedSuccess {
		return true
	}
	oldStatus := cacher.GetFedJoinedClusterStatus(id, acc)
	if oldStatus != status {
		data := share.CLUSFedClusterStatus{Status: status}
		clusHelper.PutFedJointClusterStatus(id, &data)
	}
	return true
}

func notifyDeployFedRules(acc *access.AccessControl, login *loginSession) {
	myDeployCount := atomic.AddUint32(&_fedDeployCount, 1)
	time.Sleep(time.Second * 10)
	newDeployCount := atomic.LoadUint32(&_fedDeployCount)
	if myDeployCount != newDeployCount {
		// 'myDeployCount != newDeployCount' means another notifyDeployFedRules go-routine is queued in the 10 seconds sleep,
		// yield notification task to the new notifyDeployFedRules go-routine
		return
	}
	notify := 0
	ch := make(chan cmdResponse)
	ids := cacher.GetFedJoinedClusterIdMap(acc)
	if len(ids) > 0 {
		// notify joint clusters to poll fed rules/settings
		reqTo := api.RESTFedInternalCommandReq{
			FedKvVersion: kv.GetFedKvVer(),
			Command:      _cmdPollFedRules,
			User:         login.fullname, // user on master cluster who changes the fed rules settings
			Revisions:    cacher.GetAllFedRulesRevisions(),
		}
		for id, disabled := range ids {
			if !disabled {
				jointCluster := cacher.GetFedJoinedCluster(id, acc)
				if jointCluster.ID == id {
					notify++
					bodyTo, _ := json.Marshal(&reqTo)
					go talkToJointCluster(&jointCluster, http.MethodPost, "v1/fed/command_internal", id, _tagDeployFedPolicy, bodyTo, ch, acc, login)
				}
			}
		}
	}
	for j := 0; j < notify; j++ {
		notifyResult := <-ch
		updateClusterState(notifyResult.id, notifyResult.result, acc)
	}
}

func updateFedRulesRevision(ruleTypes []string, acc *access.AccessControl, login *loginSession) {
	if clusHelper.UpdateFedRulesRevision(ruleTypes) {
		ids := cacher.GetFedJoinedClusterIdMap(acc)
		for id, disabled := range ids {
			if !disabled {
				updateClusterState(id, _fedClusterOutOfSync, acc)
			}
		}
	}
	go notifyDeployFedRules(acc, login)
}

func pingJointCluster(tag, urlStr string, jointCluster share.CLUSFedJointClusterInfo, ch chan<- cmdResponse, acc *access.AccessControl) (int, bool, error) {

	id := jointCluster.ID

	var err error
	var statusCode int
	var proxyUsed bool
	reqTo := api.RESTFedPingReq{
		FedKvVersion: kv.GetFedKvVer(),
	}
	if id != "" {
		reqTo.Token = jwtGenFedPingToken(api.FedRoleMaster, id, jointCluster.Secret, nil)
	}
	bodyTo, _ := json.Marshal(&reqTo)
	cmdResp := cmdResponse{id: id, result: _fedClusterDisconnected}
	var data []byte

	for _, logError := range []bool{false, true} {
		_, statusCode, data, proxyUsed, err = sendReqToJointCluster(jointCluster.RestInfo, id, "", http.MethodPost,
			urlStr, jsonContentType, tag, "", bodyTo, _notForward, false, logError, acc)
		if err == nil {
			if statusCode == http.StatusGone {
				cmdResp.result = _fedClusterLeft
				break
			} else if statusCode == http.StatusOK {
				if tag == _tagVerifyJointCluster {
					log.WithFields(log.Fields{"id": id, "proxyUsed": proxyUsed}).Info("success")
				}
				cmdResp.result = _fedSuccess
				pingResp := api.RESTFedPingResp{}
				if err = json.Unmarshal(data, &pingResp); err == nil {
					cmdResp.result = pingResp.Result
				}
				break
			} else {
				log.WithFields(log.Fields{"statusCode": statusCode, "id": id, "proxyUsed": proxyUsed}).Error("unexpected")
			}
		} else {
			cmdResp.result = _fedClusterNetworkError
		}
		time.Sleep(time.Second * 2)
	}
	if ch != nil {
		ch <- cmdResp
	}

	return statusCode, proxyUsed, err
}

func pingJointClusters() bool {
	if !licenseAllowFed(1) {
		return true
	}

	acc := access.NewReaderAccessControl()
	doPing := atomic.CompareAndSwapUint32(&_fedPingOngoing, 0, 1)
	if doPing {
		ch := make(chan cmdResponse)
		ids := cacher.GetFedJoinedClusterIdMap(acc)
		if len(ids) > 0 {
			if jointNWErrCount == nil {
				jointNWErrCount = make(map[string]int, len(ids))
				for id, _ := range ids {
					jointNWErrCount[id] = 0
				}
			} else if len(jointNWErrCount) != len(ids) {
				for id, _ := range jointNWErrCount {
					if _, ok := ids[id]; !ok {
						delete(jointNWErrCount, id)
					}
				}
			}
			// ping joint clusters
			ping := 0
			for id, disabled := range ids {
				if !disabled {
					jointCluster := cacher.GetFedJoinedCluster(id, acc)
					if jointCluster.ID == id {
						ping++
						go pingJointCluster(_tagPingJointCluster, "v1/fed/ping_internal", jointCluster, ch, acc)
					}
				}
			}
			for j := 0; j < ping; j++ {
				deployResult := <-ch
				state := deployResult.result
				if state == _fedClusterNetworkError {
					if count, ok := jointNWErrCount[deployResult.id]; !ok {
						jointNWErrCount[deployResult.id] = 1
					} else {
						jointNWErrCount[deployResult.id] = count + 1
					}
					if jointNWErrCount[deployResult.id] >= 3 { // change worker cluster's state to disconnected after 5 http.Client.Do() errors
						jointNWErrCount[deployResult.id] = 0
						updateClusterState(deployResult.id, _fedClusterDisconnected, acc)
					}
				} else {
					if state == _fedMasterUpgradeRequired {
						state = _fedJointVersionTooNew
					} else if state == _fedSuccess {
						if oldStatus := cacher.GetFedJoinedClusterStatus(deployResult.id, acc); oldStatus == _fedClusterDisconnected {
							state = _fedClusterConnected
						}
					}
					updateClusterState(deployResult.id, state, acc)
					jointNWErrCount[deployResult.id] = 0
				}
			}
		}
		atomic.StoreUint32(&_fedPingOngoing, 0)
	}
	return doPing
}

// caller must own share.CLUSLockFedKey lock
func preConditionCheck() string {
	nameSet := clusHelper.GetAllGroupNames(share.ScopeFed)
	if nameSet.Cardinality() > 0 {
		cleanFedRules()
		nameSet = clusHelper.GetAllGroupNames(share.ScopeFed)
	}
	if nameSet.Cardinality() == 0 {
		return ""
	}
	groupNames := nameSet.ToStringSlice()
	msg := strings.Join(groupNames[:], ",")
	log.WithFields(log.Fields{"groups": msg}).Error("Group name with reserved prefix for fed exists")
	return msg
}

func handlerGetFedMember(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	acc, login := isFedOpAllowed(FedRoleAny, _readerRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	org, err := cacher.GetFedMember(_clusterStatusMap, acc) // org is type RESTFedMembereshipData
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	if org.FedRole == api.FedRoleMaster {
		t := time.Now()
		if t.After(_lastFedMemberPingTime) {
			clusHelper.FedTriggerInstantPingPoll(share.InstantPingFedJoints, 0)
			_lastFedMemberPingTime = time.Now().Add(restForInstantPing)
		}
	}

	restRespSuccess(w, r, org, acc, login, nil, "Get federation config")
}

func handlerConfigLocalCluster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	acc, login := isFedOpAllowed(FedRoleAny, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var reqData api.RESTFedConfigData
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &reqData); err != nil || (reqData.Name != nil && *reqData.Name == "") ||
		(reqData.RestInfo != nil && (reqData.RestInfo.Server == "" || reqData.RestInfo.Port == 0)) ||
		(reqData.UseProxy != nil && (*reqData.UseProxy != "" && *reqData.UseProxy != "https")) {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	fedRole, _ := cacher.GetFedMembershipRole(acc)
	if fedRole == api.FedRoleMaster {
		if reqData.PingInterval != nil && *reqData.PingInterval != 0 {
			atomic.StoreUint32(&_fedPingInterval, *reqData.PingInterval)
		}
		if reqData.PollInterval != nil && *reqData.PollInterval != 0 {
			atomic.StoreUint32(&_fedPollInterval, *reqData.PollInterval)
		}
	}
	if reqData.Name != nil {
		if currentName := cacher.GetSystemConfigClusterName(acc); currentName != *reqData.Name {
			switch fedRole {
			case api.FedRoleMaster:
				if joined := cacher.GetFedJoinedClusterCount(); joined > 0 {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
						"Cluster name cannot be modified when there is other cluster in the federation")
					return
				}
			case api.FedRoleJoint:
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
					"Cluster name cannot be modified after joining the federation")
				return
			}
			updateSystemClusterName(*reqData.Name, acc)
		}
	}

	if reqData.RestInfo != nil || reqData.UseProxy != nil {
		if m := clusHelper.GetFedMembership(); m != nil {
			if reqData.UseProxy != nil {
				m.UseProxy = *reqData.UseProxy
			}
			if reqData.RestInfo != nil {
				switch m.FedRole {
				case api.FedRoleNone:
					m.LocalRestInfo = *reqData.RestInfo
				case api.FedRoleMaster:
					cluster := cacher.GetFedMasterCluster(acc)
					if cluster.RestInfo.Server != reqData.RestInfo.Server || cluster.RestInfo.Port != reqData.RestInfo.Port {
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
							"Exposed REST server info is read-only when the cluster is the primary cluster")
						return
					}
					if reqData.PingInterval != nil && *reqData.PingInterval > 0 {
						m.PingInterval = *reqData.PingInterval
					}
					if reqData.PollInterval != nil && *reqData.PollInterval > 0 {
						m.PollInterval = *reqData.PollInterval
					}
				case api.FedRoleJoint:
					cluster := cacher.GetFedLocalJointCluster(acc)
					if cluster.RestInfo.Server != reqData.RestInfo.Server || cluster.RestInfo.Port != reqData.RestInfo.Port {
						// do not allow a joined cluster to change exported ip/port(yet)
						// m.JointCluster.RestInfo = *reqData.RestInfo
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
							"Exposed REST server info is read-only because this cluster already joins the federation")
						return
					}
				}
			}
			if err := clusHelper.PutFedMembership(m); err != nil {
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
				return
			}
		}
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Patch local cluster info")
}

func handlerPromoteToMaster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	if isFedRulesCleanupOngoing(w) {
		return
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// local users & rancher users who have admin permission can promote the cluster
	acc, login := isFedOpAllowed(api.FedRoleNone, _localAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	if errMsg := preConditionCheck(); errMsg != "" {
		restRespErrorMessage(w, http.StatusPreconditionRequired, api.RESTErrOpNotAllowed, errMsg)
		return
	}

	var reqData api.RESTFedPromoteReqData
	var restInfo share.CLUSRestServerInfo
	var useProxy string
	var msg string
	body, _ := ioutil.ReadAll(r.Body)
	if err = json.Unmarshal(body, &reqData); err != nil || (reqData.UseProxy != nil && *reqData.UseProxy != "" && *reqData.UseProxy != "https") {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	} else {
		cacheRestInfo, cacheUseProxy := cacher.GetFedLocalRestInfo(acc)
		if reqData.MasterRestInfo != nil {
			restInfo = *reqData.MasterRestInfo
		} else {
			restInfo = cacheRestInfo
		}
		if reqData.UseProxy != nil {
			useProxy = *reqData.UseProxy
		} else {
			useProxy = cacheUseProxy
		}
		var msgProxy string
		if useProxy != "" {
			msgProxy = "(use proxy)"
		}
		msg = fmt.Sprintf("Promote to primary cluster%s", msgProxy)
	}

	if restInfo.Server == "" || restInfo.Port == 0 {
		log.WithFields(log.Fields{"server": restInfo.Server, "port": restInfo.Port}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	updateSystemClusterName(reqData.Name, acc)
	if err = clusHelper.ConfigFedRole(common.DefaultAdminUser, api.UserRoleFedAdmin, acc); err != nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed)
		return
	}
	// do not promote current user to fedAdmin if it's not local user
	if login.fullname != common.DefaultAdminUser && login.server == "" {
		clusHelper.ConfigFedRole(login.fullname, api.UserRoleFedAdmin, acc)
	}

	var masterID string
	for ok := true; ok; ok = false {
		if masterID, err = utils.GetGuid(); err == nil {
			_, err = kv.GetFedCaCertPath(masterID)
			if err == nil {
				break
			}
		}
		revertFedRoles(acc)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
		return
	}

	if reqData.PingInterval > 0 {
		atomic.StoreUint32(&_fedPingInterval, reqData.PingInterval)
	}
	if reqData.PollInterval > 0 {
		atomic.StoreUint32(&_fedPollInterval, reqData.PollInterval)
	}
	secret, _ := utils.GetGuid()
	m := share.CLUSFedMembership{
		FedRole:       api.FedRoleMaster,
		PingInterval:  reqData.PingInterval,
		PollInterval:  reqData.PollInterval,
		LocalRestInfo: restInfo,
		MasterCluster: share.CLUSFedMasterClusterInfo{
			ID:       masterID,
			Secret:   secret,
			User:     login.fullname,
			RestInfo: restInfo,
		},
		UseProxy: useProxy,
	}

	if clusHelper.PutFedMembership(&m) != nil {
		revertFedRoles(acc)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
		return
	}
	kv.CreateDefaultFedGroups()

	resp := api.RESTFedPromoteRespData{
		FedRole: api.FedRoleMaster,
		//NewToken: login.token,
		MasterCluster: api.RESTFedMasterClusterInfo{
			ID:       masterID,
			RestInfo: m.MasterCluster.RestInfo,
		},
		UseProxy: useProxy,
	}

	accFedAdmin := access.NewFedAdminAccessControl()
	cacheFedEvent(share.CLUSEvFedPromote, msg, login.fullname, login.remote, login.id, login.domainRoles)
	user, _, _ := clusHelper.GetUserRev(common.DefaultAdminUser, accFedAdmin)
	if user != nil {
		kickLoginSessions(user)
	}
	// if current user is local non-default admin user or rancher user, kick all related sessions
	if login.fullname != common.DefaultAdminUser || login.server != "" {
		if user, _, _ := clusHelper.GetUserRev(login.fullname, accFedAdmin); user != nil {
			kickLoginSessions(user)
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Promote to primary cluster")
}

func handlerDemoteFromMaster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	// inform all joined clusters that the federation is dismissing
	list := clusHelper.GetFedJointClusterList()
	if list != nil && len(list.IDs) > 0 {
		reqTo := api.RESTFedRemovedReqInternal{
			User: login.fullname, // user on master cluster who issues demote request
		}
		bodyTo, _ := json.Marshal(&reqTo)
		dismiss := 0
		ch := make(chan bool)
		for _, id := range list.IDs {
			joinedCluster := cacher.GetFedJoinedCluster(id, acc)
			if joinedCluster.ID == id {
				dismiss++
				go informFedDismissed(joinedCluster, bodyTo, ch, acc, login)
			}
		}
		for j := 0; j < dismiss; j++ {
			<-ch
		}
	}
	clusHelper.PutFedJointClusterList(&share.CLUSFedJoinedClusterList{})

	masterCluster := cacher.GetFedMasterCluster(acc)
	if masterCaCertPath, _, _ := kv.GetFedTlsKeyCertPath(masterCluster.ID, ""); masterCaCertPath != "" {
		os.Remove(masterCaCertPath)
	}
	m := &share.CLUSFedMembership{
		FedRole:          api.FedRoleNone,
		LocalRestInfo:    masterCluster.RestInfo,
		PendingDismiss:   true,
		PendingDismissAt: time.Now().UTC(),
	}
	if err := clusHelper.PutFedMembership(m); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to demote")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
		return
	}

	cacheFedEvent(share.CLUSEvFedDemote, "Demote from primary cluster", login.fullname, login.remote, login.id, login.domainRoles)
	revertFedRoles(acc)
	cleanFedRules()

	restRespSuccess(w, r, nil, acc, login, nil, "Demote from primary cluster")
}

func handlerGetFedJoinToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	masterCluster := cacher.GetFedMasterCluster(acc)
	if masterCluster.ID == "" {
		restRespError(w, http.StatusInternalServerError, api.RESTErrObjectNotFound)
		return
	}

	query := restParseQuery(r)
	str, _ := query.pairs[api.QueryDuration] // in minutes.
	duration, _ := strconv.Atoi(str)
	if duration <= 0 { // in minute
		duration = 60
	}
	var jwtFedJoinTokenLife time.Duration = time.Minute * time.Duration(duration)
	resp := api.RESTFedJoinToken{JoinToken: base64.StdEncoding.EncodeToString(jwtGenFedJoinToken(&masterCluster, jwtFedJoinTokenLife))}
	if resp.JoinToken == "" {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoteUnauthorized,
			"The join_ticket is either invalid or expires. Please get a new join_ticket from the primary cluster")
		return
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get federation join_token")
}

func handlerJoinFed(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	if isFedRulesCleanupOngoing(w) {
		return
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	acc, login := isFedOpAllowed(api.FedRoleNone, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	if errMsg := preConditionCheck(); errMsg != "" {
		restRespErrorMessage(w, http.StatusPreconditionRequired, api.RESTErrOpNotAllowed, errMsg)
		return
	}

	var req api.RESTFedJoinReq
	var restInfo share.CLUSRestServerInfo
	var useProxy string
	var joinToken joinToken
	var msgProxy string
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || (req.UseProxy != nil && *req.UseProxy != "" && *req.UseProxy != "https") {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	} else {
		fedRestInfo, fedUseProxy := cacher.GetFedLocalRestInfo(acc)
		if req.JointRestInfo != nil {
			restInfo = *req.JointRestInfo
		} else {
			restInfo = fedRestInfo
		}

		if req.UseProxy != nil {
			useProxy = *req.UseProxy
		} else {
			useProxy = fedUseProxy
		}
		if useProxy != "" {
			msgProxy = "(use proxy)"
		}
	}
	//log.WithFields(log.Fields{"useProxy": useProxy}).Debug()

	if tokenBytes, err := base64.StdEncoding.DecodeString(req.JoinToken); err == nil {
		if err := json.Unmarshal(tokenBytes, &joinToken); err == nil {
			if req.Server == "" {
				req.Server = joinToken.MasterServer
			}
			if req.Port == 0 {
				req.Port = joinToken.MasterPort
			}
		}
	}

	var name string
	if req.Name == "" {
		name = cacher.GetSystemConfigClusterName(acc)
	} else {
		name = req.Name
	}
	if name == "" || req.Server == "" || req.Port == 0 || joinToken.JoinTicket == "" || restInfo.Server == "" || restInfo.Port == 0 {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	updateSystemClusterName(name, acc)

	var jointID, jointSecret string
	if jointID, err = utils.GetGuid(); err == nil {
		jointSecret, err = utils.GetGuid()
	}
	if jointID == "" || jointSecret == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
		return
	}

	reqTo := api.RESTFedJoinReqInternal{
		User:         login.fullname, // user on joint cluster who triggered join-federation request
		Remote:       login.remote,
		UserRoles:    login.domainRoles,
		FedKvVersion: kv.GetFedKvVer(),
		RestVersion:  kv.GetRestVer(),
		JoinTicket:   joinToken.JoinTicket,
		JointCluster: api.RESTFedJointClusterInfo{
			Name:     name,
			ID:       jointID,
			Secret:   jointSecret,
			User:     login.fullname, // user on joint cluster who issued join-federation request
			RestInfo: restInfo,
		},
	}

	bodyTo, _ := json.Marshal(&reqTo)
	var data []byte
	var statusCode int
	var proxyUsed bool
	// call master cluster for joining federation
	urlStr := fmt.Sprintf("https://%s:%d/v1/fed/join_internal", req.Server, req.Port)
	data, statusCode, proxyUsed, err = sendRestRequest("", http.MethodPost, urlStr, "", nil, bodyTo, true, &useProxy, acc)
	if err == nil {
		respTo := api.RESTFedJoinRespInternal{}
		if err = json.Unmarshal(data, &respTo); err == nil {
			mtlsAvailable := false
			caCertPath, _, _ := kv.GetFedTlsKeyCertPath(respTo.MasterCluster.ID, jointID)
			if respTo.CACert != "" && respTo.ClientCert != "" && respTo.ClientKey != "" {
				if caCert, err := base64.StdEncoding.DecodeString(respTo.CACert); err == nil {
					if err = ioutil.WriteFile(caCertPath, caCert, 0600); err == nil {
						mtlsAvailable = true
					}
				}
			}
			if !mtlsAvailable {
				caCertPath = ""
			}

			if respTo.PollInterval > 0 {
				atomic.StoreUint32(&_fedPollInterval, respTo.PollInterval)
			}
			// cert/key files store []byte. But the corresponding cert/key are string in CLUSxyz so that they are encrypted when marshalled
			m := share.CLUSFedMembership{
				FedRole:       api.FedRoleJoint,
				PollInterval:  respTo.PollInterval,
				LocalRestInfo: restInfo,
				MasterCluster: share.CLUSFedMasterClusterInfo{
					Name:   respTo.MasterCluster.Name,
					ID:     respTo.MasterCluster.ID,
					CACert: respTo.CACert,
					User:   "", // respTo.MasterCluster.User, do not let joint cluster know who promoted the master cluster
					RestInfo: share.CLUSRestServerInfo{
						Server: req.Server,
						Port:   req.Port,
					},
				},
				JointCluster: share.CLUSFedJointClusterInfo{
					ID:         jointID,
					Secret:     jointSecret,
					ClientKey:  respTo.ClientKey,
					ClientCert: respTo.ClientCert,
					RestInfo:   restInfo,
					User:       login.fullname,
				},
				UseProxy: useProxy,
			}
			if err = clusHelper.PutFedMembership(&m); err == nil {
				updateClusterState(respTo.MasterCluster.ID, _fedClusterConnected, acc)
				updateClusterState(jointID, _fedClusterJoined, acc)
				msg := fmt.Sprintf("Join federation%s and the primary cluster is %s(%s)", msgProxy, respTo.MasterCluster.Name, req.Server)
				cacheFedEvent(share.CLUSEvFedJoin, msg, login.fullname, login.remote, login.id, login.domainRoles)
				atomic.StoreUint32(&_fedFullPolling, 1)
				restRespSuccess(w, r, nil, acc, login, nil, "Join federation")
				return
			}
			if mtlsAvailable { // error happened if it reaches here
				os.Remove(caCertPath)
			}
		}
	} else if statusCode != 0 {
		log.WithFields(log.Fields{"statusCode": statusCode, "data": string(data), "localServer": req.Server, "localPort": req.Port, "proxyUsed": proxyUsed}).Error()
		var restErr api.RESTError
		if json.Unmarshal(data, &restErr) == nil {
			if restErr.Code == _fedMasterUpgradeRequired {
				restRespError(w, statusCode, api.RESTErrMasterUpgradeRequired)
			} else if restErr.Code == _fedJointUpgradeRequired {
				restRespError(w, statusCode, api.RESTErrJointUpgradeRequired)
			} else {
				restRespError(w, statusCode, restErr.Code)
			}
			return
		}
	}
	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
}

func handlerLeaveFed(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	acc, login := isFedOpAllowed(api.FedRoleJoint, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var req api.RESTFedLeaveReq
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	masterCluster := cacher.GetFedMasterCluster(acc)
	jointCluster := cacher.GetFedLocalJointCluster(acc)
	if masterCluster.ID == "" || jointCluster.ID == "" {
		log.WithFields(log.Fields{"master": masterCluster.ID, "joint": jointCluster.ID}).Error("Request error")
		restRespError(w, http.StatusInternalServerError, api.RESTErrObjectNotFound)
		return
	}

	reqTo := api.RESTFedLeaveReqInternal{
		ID:          jointCluster.ID,
		JointTicket: jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife),
		User:        login.fullname, // user on joint cluster who triggered leave-federation request
		Remote:      login.remote,
		UserRoles:   login.domainRoles,
	}
	var err99 error
	if bodyTo, err := json.Marshal(&reqTo); err == nil {
		// call master cluster for leaving federation
		urlStr := fmt.Sprintf("https://%s:%d/v1/fed/leave_internal", masterCluster.RestInfo.Server, masterCluster.RestInfo.Port)
		_, _, _, err = sendRestRequest("", http.MethodPost, urlStr, "", nil, bodyTo, true, nil, acc)
		if err == nil || req.Force {
			m := &share.CLUSFedMembership{
				FedRole:          api.FedRoleNone,
				LocalRestInfo:    jointCluster.RestInfo,
				PendingDismiss:   true,
				PendingDismissAt: time.Now().UTC(),
			}

			if err := clusHelper.PutFedMembership(m); err == nil {
				cacheFedEvent(share.CLUSEvFedLeave, "Leave federation", login.fullname, login.remote, login.id, login.domainRoles)
				go leaveFedCleanup(masterCluster.ID, jointCluster.ID)
				restRespSuccess(w, r, nil, acc, login, nil, "Leave federation")
				return
			} else {
				err99 = err
			}
		} else {
			err99 = err
		}
	} else {
		err99 = err
	}
	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err99.Error())
}

func handlerRemoveJointCluster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	id := ps.ByName("id")
	joinedCluster := cacher.GetFedJoinedCluster(id, acc)
	if joinedCluster.ID == "" { // joint cluster to remove must exist
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return
	}

	updateClusterState(id, _fedClusterKicked, acc) // intermediate state
	reqTo := api.RESTFedRemovedReqInternal{
		User: login.fullname, // user on master cluster who issues remove-from-federation request
	}
	bodyTo, _ := json.Marshal(&reqTo)
	talkToJointCluster(&joinedCluster, http.MethodPost, "v1/fed/remove_internal", id, _tagKickJointCluster, bodyTo, nil, acc, login)

	status, code := removeFromFederation(&joinedCluster) // remove the joint cluster's entry from master cluster
	if status != http.StatusOK {
		restRespErrorMessage(w, status, code, "Fail to dismiss managed cluster")
	} else {
		msg := fmt.Sprintf("Dismiss cluster %s(%s) from federation", joinedCluster.Name, joinedCluster.RestInfo.Server)
		cacheFedEvent(share.CLUSEvFedKick, msg, login.fullname, login.remote, login.id, login.domainRoles)
		restRespSuccess(w, r, nil, acc, login, nil, "Dismiss managed cluster")
	}
}

func handlerJoinFedInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var reqData api.RESTFedJoinReqInternal
	body, _ := ioutil.ReadAll(r.Body)
	for ok := true; ok; ok = false {
		if err := json.Unmarshal(body, &reqData); err == nil {
			masterName := cacher.GetSystemConfigClusterName(accReadAll)
			if masterName == reqData.JointCluster.Name {
				log.WithFields(log.Fields{"master": masterName, "joint": reqData.JointCluster.Name}).Error("non-unique managed cluster name")
				restRespError(w, http.StatusConflict, api.RESTErrFedDuplicateName)
				return
			}
			// join request contains fed kv version for the joining cluster. if it's different from this cluster's fed kv version, it means they are not compatible
			met, result := kv.CheckFedKvVersion("master", reqData.FedKvVersion)
			if met {
				for _, joinedName := range cacher.GetFedJoinedClusterNameList(accReadAll) {
					if joinedName == reqData.JointCluster.Name {
						log.WithFields(log.Fields{"joined": joinedName, "joint": reqData.JointCluster.Name}).Error("non-unique managed cluster name")
						restRespError(w, http.StatusConflict, api.RESTErrFedDuplicateName)
						return
					}
				}
				joinedCluster := cacher.GetFedJoinedCluster(reqData.JointCluster.ID, accReadAll)
				if joinedCluster.ID == "" { // a new joint cluster wants to join
					break
				}
			} else {
				errCode := api.RESTErrFedOperationFailed
				if result == _fedMasterUpgradeRequired || result == _fedJointUpgradeRequired {
					errCode = result
				}
				restRespError(w, http.StatusUpgradeRequired, errCode)
				return
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("Request error")
		}
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	masterCluster := cacher.GetFedMasterCluster(accReadAll)
	if masterCluster.ID == "" {
		restRespError(w, http.StatusInternalServerError, api.RESTErrOpNotAllowed)
		return
	}

	// Validate token
	if err := jwtValidateFedJoinTicket(reqData.JoinTicket, masterCluster.Secret); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespErrorMessage(w, http.StatusExpectationFailed, api.RESTErrFedOperationFailed, err.Error())
		return
	}

	// verify if joint cluster is reachable from master cluster
	var jointCluster share.CLUSFedJointClusterInfo
	jointCluster.RestInfo = reqData.JointCluster.RestInfo
	statusCode, proxyUsed, _ := pingJointCluster(_tagVerifyJointCluster, "v1/fed/joint_test_internal", jointCluster, nil, accReadAll)
	if statusCode != http.StatusOK {
		log.WithFields(log.Fields{"statusCode": statusCode, "rest": reqData.JointCluster.RestInfo}).Error("Managed cluster unreachable")
		restRespError(w, http.StatusServiceUnavailable, api.RESTErrFedJointUnreachable)
		return
	}

	// update kv
	var caCertData, privKeyData, certData []byte
	_, privKeyPath, certPath := kv.GetFedTlsKeyCertPath("", reqData.JointCluster.ID)
	if kv.GenTlsKeyCert(reqData.JointCluster.ID, privKeyPath, certPath, x509.ExtKeyUsageClientAuth) {
		masterCaCertPath, _, _ := kv.GetFedTlsKeyCertPath(masterCluster.ID, "")
		caCertData, err = ioutil.ReadFile(masterCaCertPath)
		if err == nil {
			privKeyData, err = ioutil.ReadFile(privKeyPath)
			if err == nil {
				certData, err = ioutil.ReadFile(certPath)
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Error("read certData failed")
				}
			} else {
				log.WithFields(log.Fields{"err": err}).Error("read privKeyData failed")
			}
		} else {
			log.WithFields(log.Fields{"err": err}).Error("read caCertData failed")
		}
	}
	if caCertData == nil || privKeyData == nil || certData == nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, "Fail to join federation")
		return
	}

	clientKeyStr := base64.StdEncoding.EncodeToString(privKeyData)
	clientCertStr := base64.StdEncoding.EncodeToString(certData)
	joinedCluster := &share.CLUSFedJointClusterInfo{
		Name:          reqData.JointCluster.Name,
		ID:            reqData.JointCluster.ID,
		Secret:        reqData.JointCluster.Secret,
		ClientKey:     clientKeyStr,
		ClientCert:    clientCertStr,
		User:          reqData.JointCluster.User, // user on joint cluster who issue join-federation request
		RestInfo:      reqData.JointCluster.RestInfo,
		ProxyRequired: proxyUsed,
		RestVersion:   reqData.RestVersion,
	}
	if err := clusHelper.PutFedJointCluster(joinedCluster); err != nil {
		msg := fmt.Sprintf("Fail to join federation: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, msg)
		return
	}
	updateClusterState(joinedCluster.ID, _fedClusterJoined, accReadAll)

	list := clusHelper.GetFedJointClusterList()
	if list != nil {
		list.IDs = append(list.IDs, reqData.JointCluster.ID)
	} else {
		list.IDs = []string{reqData.JointCluster.ID}
	}
	if err = clusHelper.PutFedJointClusterList(list); err == nil {
		resp := api.RESTFedJoinRespInternal{
			PollInterval: atomic.LoadUint32(&_fedPollInterval),
			CACert:       base64.StdEncoding.EncodeToString(caCertData),
			ClientKey:    clientKeyStr,
			ClientCert:   clientCertStr,
			MasterCluster: &api.RESTFedMasterClusterInfo{
				Name:     cacher.GetSystemConfigClusterName(accReadAll),
				ID:       masterCluster.ID,
				RestInfo: masterCluster.RestInfo,
			},
		}
		msg := fmt.Sprintf("Cluster %s(%s) joins federation", joinedCluster.Name, joinedCluster.RestInfo.Server)
		cacheFedEvent(share.CLUSEvFedJoin, msg, reqData.User, reqData.Remote, "", reqData.UserRoles)
		restRespSuccess(w, r, &resp, nil, nil, nil, "Join federation by managed cluster's request")
		return
	} else {
		msg := fmt.Sprintf("Fail to join federation: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, msg)
	}
}

func handlerLeaveFedInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var req api.RESTFedLeaveReqInternal
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || req.ID == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var status int
	code := api.RESTErrInvalidRequest
	joinedCluster := cacher.GetFedJoinedCluster(req.ID, accReadAll)
	if joinedCluster.ID == req.ID {
		// Validate token
		if err := jwtValidateFedJoinTicket(req.JointTicket, joinedCluster.Secret); err == nil {
			if status, code = removeFromFederation(&joinedCluster); status == http.StatusOK {
				msg := fmt.Sprintf("Cluster %s(%s) leaves federation", joinedCluster.Name, joinedCluster.RestInfo.Server)
				cacheFedEvent(share.CLUSEvFedLeave, msg, req.User, req.Remote, "", req.UserRoles)
				restRespSuccess(w, r, nil, nil, nil, nil, "Leave federation by managed cluster's request")
				return
			} else {
				status = http.StatusInternalServerError
			}
		} else {
			status = http.StatusBadRequest
		}
	} else {
		status = http.StatusNotFound
	}
	log.WithFields(log.Fields{"status": status}).Error("Fail to leave federation")
	restRespErrorMessage(w, status, code, "Fail to leave federation")
}

func handlerPingJointInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleJoint {
		var req api.RESTFedPingReq
		var resp api.RESTFedPingResp
		body, _ := ioutil.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err == nil {
			accReadAll := access.NewReaderAccessControl()
			if jointCluster := cacher.GetFedLocalJointCluster(accReadAll); jointCluster.ID != "" {
				if _, err := jwtValidateToken(req.Token, jointCluster.Secret, nil); err == nil {
					if met, result := kv.CheckFedKvVersion("joint", req.FedKvVersion); !met {
						resp.Result = result
					}
					restRespSuccess(w, r, &resp, nil, nil, nil, "")
					return
				} else {
					log.WithFields(log.Fields{"err": err}).Debug("validate")
				}
			} else {
				log.Debug("empty cluster id")
			}
		} else {
			log.WithFields(log.Fields{"err": err}).Debug("Unmarshal error")
		}
	} else {
		log.WithFields(log.Fields{"fedRole": fedRole}).Debug("unexpected fedRole")
	}
	restRespError(w, http.StatusGone, api.RESTErrInvalidRequest)
}

func handlerTestJointInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleNone {
		restRespSuccess(w, r, nil, nil, nil, nil, "")
	} else {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

func handlerJointKickedInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockFedKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	acc, login := isFedOpAllowed(api.FedRoleJoint, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	masterCluster := cacher.GetFedMasterCluster(acc)
	jointCluster := cacher.GetFedLocalJointCluster(acc)
	m := &share.CLUSFedMembership{
		FedRole:          api.FedRoleNone,
		LocalRestInfo:    jointCluster.RestInfo,
		PendingDismiss:   true,
		PendingDismissAt: time.Now().UTC(),
	}

	if clusHelper.PutFedMembership(m) != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err.Error())
		return
	}
	cacheFedEvent(share.CLUSEvFedKick, "Dimissed from federation", login.fullname, login.remote, login.id, login.domainRoles)
	go leaveFedCleanup(masterCluster.ID, jointCluster.ID)
	restRespSuccess(w, r, nil, acc, login, nil, "Leave federation by primary cluster's request")
}

// share.CLUSLockFedKey lock is owned by caller
func removeFromFederation(joinedCluster *share.CLUSFedJointClusterInfo) (int, int) { // (status, code)
	if joinedCluster == nil || joinedCluster.ID == "" {
		return http.StatusBadRequest, api.RESTErrInvalidRequest
	}

	// update kv
	if list := clusHelper.GetFedJointClusterList(); list != nil {
		clusterIDs := list.IDs
		for i, id := range clusterIDs {
			if id == joinedCluster.ID {
				clusterIDs[i] = clusterIDs[len(clusterIDs)-1]
				list.IDs = clusterIDs[:len(clusterIDs)-1]
				if err := clusHelper.PutFedJointClusterList(list); err == nil {
					clusHelper.DeleteFedJointCluster(id)
					_, clientKeyPath, clientCertPath := kv.GetFedTlsKeyCertPath("", id)
					os.Remove(clientKeyPath)
					os.Remove(clientCertPath)
					_setFedJointPrivateKey(joinedCluster.ID, nil)
					return http.StatusOK, 0
				}
			}
		}
	}
	return http.StatusInternalServerError, api.RESTErrFedOperationFailed
}

func handlerDeployFedRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	if !licenseAllowFed(1) {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var req api.RESTDeployFedRulesReq
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	idMap := cacher.GetFedJoinedClusterIdMap(acc)
	ids := make([]string, 0, len(idMap))
	if len(req.IDs) > 0 {
		for _, id := range req.IDs {
			if _, ok := idMap[id]; ok {
				ids = append(ids, id)
			}
		}
	} else {
		for id, _ := range idMap {
			ids = append(ids, id)
		}
	}
	resp := api.RESTDeployFedRulesResp{Results: make(map[string]int, len(ids))}

	if len(ids) > 0 {
		// notify joint clusters to poll fed rules/settings
		reqTo := api.RESTFedInternalCommandReq{
			FedKvVersion: kv.GetFedKvVer(),
			Command:      _cmdPollFedRules,
			User:         login.fullname, // user on master cluster who issues remove-from-federation request
			Revisions:    cacher.GetAllFedRulesRevisions(),
		}
		if req.Force {
			reqTo.Command = _cmdForcePullFedRules
		}
		deploy := 0
		ch := make(chan cmdResponse)
		for _, id := range ids {
			jointCluster := cacher.GetFedJoinedCluster(id, acc)
			if jointCluster.ID == id && !jointCluster.Disabled {
				deploy++
				bodyTo, _ := json.Marshal(&reqTo)
				// make sure share.CLUSLockFedKey is not locked because talkToJointCluster may lock it !
				go talkToJointCluster(&jointCluster, http.MethodPost, "v1/fed/command_internal", id, _tagFedSyncPolicy, bodyTo, ch, acc, login)
			} else if jointCluster.Disabled && len(ids) == 1 {
				restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
				return
			}
		}
		oneSuccess := false
		for j := 0; j < deploy; j++ {
			deployResult := <-ch
			resp.Results[deployResult.id] = deployResult.result
			updateClusterState(deployResult.id, deployResult.result, acc)
			if deployResult.result == _fedCmdReceived || deployResult.result == _fedClusterSynced {
				oneSuccess = true
			}
		}
		if oneSuccess {
			restRespSuccess(w, r, &resp, acc, login, nil, "Deploy fed rules to joint clusters")
		} else {
			restRespError(w, http.StatusServiceUnavailable, api.RESTErrFedJointUnreachable)
		}
	} else {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

func workFedRules(fedSettings *api.RESTFedRulesSettings, fedRevs map[string]uint64, localRevs map[string]uint64, acc *access.AccessControl) bool {
	updated := false
	if len(fedRevs) > 0 {
		log.WithFields(log.Fields{"fedRevs": fedRevs, "localRevs": localRevs}).Debug()
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockFedKey); err != nil {
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	// FedGroupType must be the first to be processed
	fedRuleTypes := []string{share.FedGroupType, share.FedSystemConfigType, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType,
		share.FedNetworkRulesType, share.FedResponseRulesType, share.FedFileMonitorProfilesType, share.FedProcessProfilesType}
	for _, fedRuleType := range fedRuleTypes {
		if fedRev, ok := fedRevs[fedRuleType]; ok {
			if jointRev, ok := localRevs[fedRuleType]; ok && fedRev != jointRev {
				applied := false
				switch fedRuleType {
				case share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType:
					if k8sPlatform {
						if rules, ok := fedSettings.AdmCtrlRulesData.Rules[fedRuleType]; ok {
							applied = replaceFedAdmissionRules(fedRuleType, rules)
						}
					} else {
						applied = true
					}
				case share.FedNetworkRulesType:
					if fedSettings.NetworkRulesData.Rules != nil && fedSettings.NetworkRulesData.RuleHeads != nil {
						applied = replaceFedNwRules(fedSettings.NetworkRulesData.Rules, fedSettings.NetworkRulesData.RuleHeads)
					}
				case share.FedResponseRulesType:
					if fedSettings.ResponseRulesData.Rules != nil && fedSettings.ResponseRulesData.RuleHeads != nil {
						applied = replaceFedResponseRules(fedSettings.ResponseRulesData.Rules, fedSettings.ResponseRulesData.RuleHeads)
					}
				case share.FedGroupType:
					applied = replaceFedGroups(fedSettings.GroupsData.Groups, acc)
				case share.FedFileMonitorProfilesType:
					applied = replaceFedFileMonitorProfiles(fedSettings.FileMonitorData.Profiles, fedSettings.FileMonitorData.AccessRules)
				case share.FedProcessProfilesType:
					applied = replaceFedProcessProfiles(fedSettings.ProcessProfilesData.Profiles)
				case share.FedSystemConfigType:
					applied = replaceFedSystemConfig(fedSettings.SystemConfigData.SystemConfig)
				}
				if applied {
					localRevs[fedRuleType] = fedRev
					updated = true
				}
			}
		}
	}
	if updated {
		cacheFedEvent(share.CLUSEvFedPolicySync, "Sync up policy with primary cluster", "", "", "", nil)
		data := share.CLUSFedRulesRevision{Revisions: localRevs}
		clusHelper.PutFedRulesRevision(nil, &data)
		log.WithFields(log.Fields{"revs": localRevs}).Info("applied fed rules")
	}

	return updated
}

func pollFedRules(forcePulling bool, tryTimes int) bool {
	doPoll := atomic.CompareAndSwapUint32(&_fedPollOngoing, 0, 1)
	defer atomic.StoreUint32(&_fedPollOngoing, 0)

	if doPoll {
		accReadAll := access.NewReaderAccessControl()
		reqTo := api.RESTPollFedRulesReq{
			FedKvVersion: kv.GetFedKvVer(),
			RestVersion:  kv.GetRestVer(),
			Name:         cacher.GetSystemConfigClusterName(accReadAll),
		}

		masterCluster := cacher.GetFedMasterCluster(accReadAll)
		jointCluster := cacher.GetFedLocalJointCluster(accReadAll)
		if masterCluster.ID == "" || jointCluster.ID == "" {
			return doPoll
		}
		reqTo.ID = jointCluster.ID
		reqTo.JointTicket = jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife)
		reqTo.Revisions = cacher.GetAllFedRulesRevisions()
		if forcePulling {
			for ruleType, _ := range reqTo.Revisions {
				reqTo.Revisions[ruleType] = 0
			}
		}

		status := _fedClusterDisconnected
		bodyTo, _ := json.Marshal(&reqTo)
		// call master cluster for polling fed rules
		var respData []byte
		var statusCode int
		var proxyUsed bool
		var err error = common.ErrObjectAccessDenied
		urlStr := fmt.Sprintf("https://%s:%d/v1/fed/poll_internal", masterCluster.RestInfo.Server, masterCluster.RestInfo.Port)
		for i := 0; i < tryTimes; i++ {
			if respData, statusCode, proxyUsed, err = sendRestRequest("", http.MethodPost, urlStr,
				"", nil, bodyTo, false, nil, accReadAll); err == nil {
				break
			} else {
				time.Sleep(time.Second)
			}
		}
		if err == nil {
			respTo := api.RESTPollFedRulesResp{}
			if err = json.Unmarshal(respData, &respTo); err == nil {
				if respTo.PollInterval > 0 {
					atomic.StoreUint32(&_fedPollInterval, respTo.PollInterval)
				}
				if respTo.Result == _fedSuccess { // success
					updateClusterState(jointCluster.ID, _fedClusterJoined, accReadAll)
					updateClusterState(masterCluster.ID, _fedClusterConnected, accReadAll)
					status = _fedSuccess
					if respTo.Settings != nil {
						var settings api.RESTFedRulesSettings
						if err = json.Unmarshal(respTo.Settings, &settings); err == nil {
							updateClusterState(jointCluster.ID, _fedClusterSyncing, accReadAll)
							if workFedRules(&settings, respTo.Revisions, reqTo.Revisions, accReadAll) {
								// if any fed rule is updated, re-send polling request simply for updating joint cluster info on master cluster
								reqTo.JointTicket = jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife)
								bodyTo, _ := json.Marshal(&reqTo)
								_, statusCode, _, _ = sendRestRequest("", http.MethodPost, urlStr,
									"", nil, bodyTo, true, nil, accReadAll)
							}
						}
					}
					updateClusterState(jointCluster.ID, _fedClusterJoined, accReadAll)
				} else if respTo.Result == _fedMasterUpgradeRequired {
					updateClusterState(jointCluster.ID, _fedJointVersionTooNew, accReadAll)
				} else if respTo.Result == _fedJointUpgradeRequired {
					updateClusterState(jointCluster.ID, _fedJointUpgradeRequired, accReadAll)
				} else if respTo.Result == _fedClusterImporting {
					status = _fedSuccess
				}
			}
		} else {
			if m := time.Now().Minute() % 10; m == 0 {
				respErr := api.RESTError{}
				json.Unmarshal(respData, &respErr)
				log.WithFields(log.Fields{"err": err, "msg": respErr, "proxyUsed": proxyUsed}).Error("Request failed")
			}
			if statusCode == http.StatusGone {
				updateClusterState(jointCluster.ID, _fedClusterKicked, accReadAll)
			} else if statusCode == http.StatusNotFound {
				var restErr api.RESTError
				if json.Unmarshal(respData, &restErr) == nil {
					if restErr.Code == api.RESTErrLicenseFail {
						updateClusterState(jointCluster.ID, _fedLicenseDisallowed, accReadAll)
					}
				}
			}
		}
		updateClusterState(masterCluster.ID, status, accReadAll)
	}
	return doPoll
}

// handles polling requests on master cluster
func handlerPollFedRulesInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var err error
	var req api.RESTPollFedRulesReq
	body, _ := ioutil.ReadAll(r.Body)
	if err = json.Unmarshal(body, &req); err != nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	// Validate token
	jointCluster := cacher.GetFedJoinedCluster(req.ID, accReadAll)
	if jointCluster.ID != req.ID {
		statusCode := http.StatusBadRequest
		if jointCluster.ID == "" {
			statusCode = http.StatusGone
		}
		restRespError(w, statusCode, api.RESTErrInvalidRequest)
		return
	} else if jointCluster.Disabled {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	if err = jwtValidateFedJoinTicket(req.JointTicket, jointCluster.Secret); err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed, err.Error())
		return
	}

	if kv.IsImporting() {
		// do not give out master's fed policies when master cluster is importing config
		resp := api.RESTPollFedRulesResp{
			Result:       _fedClusterImporting,
			PollInterval: atomic.LoadUint32(&_fedPollInterval),
		}
		restRespSuccess(w, r, &resp, accReadAll, nil, nil, "")
		return
	}

	if (req.Name != "" && req.Name != jointCluster.Name) || req.RestVersion != jointCluster.RestVersion {
		var lock cluster.LockInterface
		if lock, err = lockClusKey(w, share.CLUSLockFedKey); err == nil {
			if c := clusHelper.GetFedJointCluster(jointCluster.ID); c != nil {
				if req.Name != "" && req.Name != jointCluster.Name {
					c.Name = req.Name
				}
				if req.RestVersion != jointCluster.RestVersion {
					c.RestVersion = req.RestVersion
				}
				clusHelper.PutFedJointCluster(c)
			}
			clusHelper.ReleaseLock(lock)
		}
	}

	resp := api.RESTPollFedRulesResp{
		Result:       _fedSuccess,
		PollInterval: atomic.LoadUint32(&_fedPollInterval),
	}
	var status int
	if met, result := kv.CheckFedKvVersion("master", req.FedKvVersion); !met {
		resp.Result = result
		status = result
	} else {
		resp.Settings, resp.Revisions, _ = cacher.GetFedRules(req.Revisions, accReadAll)
		if len(resp.Revisions) > 0 {
			log.WithFields(log.Fields{"id": req.ID, "remote": req.Revisions, "fed": resp.Revisions}).Debug()
			status = _fedClusterOutOfSync
		} else {
			status = _fedClusterSynced
		}
	}
	updateClusterState(jointCluster.ID, status, accReadAll)

	restRespSuccess(w, r, &resp, accReadAll, nil, nil, "") // no event log
}

// handles fed command on joint cluster
func handlerFedCommandInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	acc, login := isFedOpAllowed(api.FedRoleJoint, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var req api.RESTFedInternalCommandReq
	body, _ := ioutil.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	resp := api.RESTFedInternalCommandResp{Result: _fedCmdReceived}
	if len(req.Revisions) > 0 {
		localRevs := cacher.GetAllFedRulesRevisions()
		if len(req.Revisions) == len(localRevs) {
			sameRevs := true
			for k, v := range localRevs {
				if v2, ok := req.Revisions[k]; !ok || v != v2 {
					sameRevs = false
					break
				}
			}
			if sameRevs {
				resp.Result = _fedClusterSynced
			}
		}
	}

	// command request contains fed kv version for the joining cluster. if it's different from this cluster's fed kv version, it means they are not compatible
	if met, result := kv.CheckFedKvVersion("joint", req.FedKvVersion); !met {
		resp.Result = result
	} else {
		switch req.Command {
		case _cmdPollFedRules, _cmdForcePullFedRules:
			var fullPolling uint32 = 0
			if req.Command == _cmdForcePullFedRules {
				fullPolling = 1
			}
			clusHelper.FedTriggerInstantPingPoll(share.InstantPollFedMaster, fullPolling)
		default:
			resp.Result = _fedCmdUnknown
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Received command from primary cluster")
}

func handlerGetJointClusterView(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var resp api.RESTFedView

	jointCluster := cacher.GetFedJoinedCluster(ps.ByName("id"), acc)
	if kv.GetRestVer() == jointCluster.RestVersion {
		resp.Compatible = true
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "")
}

var forbiddenFwUrl = map[string][]string{
	"/v1/fed_auth": []string{http.MethodPost, http.MethodDelete},
	"/v1/user":     []string{http.MethodPost},
	"/v1/role":     []string{http.MethodPost},
}
var forbiddenFwUrlPrefix = map[string][]string{
	"/v1/auth/": []string{http.MethodPost, http.MethodDelete},
	"/v1/user/": []string{http.MethodPatch, http.MethodDelete},
	"/v1/role/": []string{http.MethodPatch, http.MethodDelete},
}

func handlerFedClusterForward(w http.ResponseWriter, r *http.Request, ps httprouter.Params, method string) {
	if !licenseAllowFed(1) {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	accCaller, login := isFedOpAllowed(api.FedRoleMaster, _fedReaderRequired, w, r) // reject non-FedAdmin/FedReader login
	if accCaller == nil || login == nil {
		return
	}

	// fedAdmin & fedReader users can reach here. However, fedReader user can only forward GET requests & PATCH("/v1/auth") to remote clusters
	acc := accCaller
	id := ps.ByName("id")
	request := ps.ByName("request")
	forbidden := false
	regScanTest := false
	txnID := ""
	if accCaller.IsFedReader() {
		if method == http.MethodGet || (method == http.MethodPatch && request == "/v1/auth") {
			// forward is allowed
			// In fedReader user sessions, controller needs to update cluster state as well. So the acc needs to have write permissions for that purpose.
			acc = access.NewFedAdminAccessControl()
		} else {
			restRespAccessDenied(w, login)
			return
		}
	}
	if !forbidden {
		if strings.Index(request, "/v1/fed/") == 0 {
			if request != "/v1/fed/member" {
				forbidden = true
			}
		} else if method != http.MethodGet {
			if verbs, ok := forbiddenFwUrl[request]; ok {
				for _, verb := range verbs {
					if verb == method {
						forbidden = true
						break
					}
				}
			}
			if !forbidden {
				for urlPrefix, verbs := range forbiddenFwUrlPrefix {
					if strings.HasPrefix(request, urlPrefix) {
						for _, verb := range verbs {
							if verb == method {
								forbidden = true
								break
							}
						}
						if forbidden {
							break
						}
					}
				}
			}
			if method == http.MethodPost && (request == "/v1/file/config" || request == "/v1/file/group/config" ||
				request == "/v1/file/admission/config" || request == "/v1/file/waf/config") {
				txnID = r.Header.Get("X-Transaction-ID")
			}
			if txnID == "" && (method == http.MethodPost || method == http.MethodDelete) && strings.HasPrefix(request, "/v1/scan/registry/") {
				if ss := strings.Split(request, "/"); len(ss) == 6 && ss[5] == "test" {
					regScanTest = true
					txnID = r.Header.Get("X-Transaction-ID")
				}
			}
		}
	}
	if forbidden {
		restRespError(w, http.StatusForbidden, api.RESTErrOpNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		request = fmt.Sprintf("%s?%s", request, r.URL.RawQuery)
	}

	rc := cacher.GetFedJoinedCluster(id, acc)
	if rc.ID == "" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrRemoteUnauthorized, "Unable to authenticate with the cluster")
		return
	} else if rc.Disabled {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	user, _, _ := clusHelper.GetUserRev(login.fullname, acc)
	remoteExport := false

	for _, refreshToken := range []bool{false, true} {
		if token, err := getJointClusterToken(&rc, id, user, refreshToken, acc, login); token != "" {
			methodToUse := method
			if request == "/v1/file/group" && method == http.MethodGet {
				methodToUse = http.MethodPost
			}
			contentType := jsonContentType
			if method == http.MethodPost {
				if i := strings.Index(r.URL.String(), "/v1/file/config"); i > len("/v1/file/config") {
					mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
					if err == nil && strings.HasPrefix(mediaType, "multipart/") {
						contentType = r.Header.Get("Content-Type")
					}
				}
			}

			// for export-related APIs thru remote console, we don't override the response header or they cannot be exported successfully
			if method == http.MethodGet {
				if i := strings.Index(r.URL.String(), "/v1/file/config"); i > len("/v1/file/config") {
					remoteExport = true
				} else if request == "/v1/file/group" {
					remoteExport = true
				} else if strings.HasPrefix(request, "/v1/sniffer/") {
					if ss := strings.Split(request, "?"); len(ss) >= 1 {
						if strings.HasSuffix(ss[0], "/pcap") {
							remoteExport = true
						}
					}
				}
			} else if method == http.MethodPatch {
				if i := strings.Index(r.URL.String(), "/v1/system/config"); i > 0 {
					var rconf api.RESTSystemConfigConfigData
					if err := json.Unmarshal(body, &rconf); err == nil {
						if rconf.Config != nil && rconf.Config.IBMSAEpDashboardURL != nil {
							msg := _invalidDashboardURL
							rconf.Config.IBMSAEpDashboardURL = &msg
							if bodyNew, err := json.Marshal(&rconf); err == nil {
								body = bodyNew
							}
						}
					}
				}
			} else if method == http.MethodPost {
				if request == "/v1/file/admission" || request == "/v1/file/waf" {
					remoteExport = true
				}
			}

			if headers, statusCode, data, _, err := sendReqToJointCluster(rc.RestInfo, id, token, methodToUse,
				request, contentType, _tagFedForward, txnID, body, _isForward, remoteExport, refreshToken, acc); err != nil {
				if !refreshToken {
					continue
				}
				updateClusterState(id, _fedClusterDisconnected, acc)
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoterRequestFail, "Unable to forward request to the cluster")
				return
			} else if statusCode != http.StatusRequestTimeout {
				if statusCode != http.StatusOK {
					remoteExport = false
				}
				restRespForward(w, r, statusCode, headers, data, remoteExport, regScanTest)
				return
			}
		} else if refreshToken {
			if err == common.ErrObjectAccessDenied {
				restRespNotFoundLogAccessDenied(w, login, err)
				return
			} else {
				updateClusterState(id, _fedClusterDisconnected, acc)
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoterRequestFail, "Unable to forward request to the cluster")
				return
			}
		}
	}

	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoteUnauthorized, "Unable to authenticate with the cluster")
}

func handlerFedClusterForwardGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	handlerFedClusterForward(w, r, ps, http.MethodGet)
}

func handlerFedClusterForwardPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	handlerFedClusterForward(w, r, ps, http.MethodPost)
}

func handlerFedClusterForwardPatch(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	handlerFedClusterForward(w, r, ps, http.MethodPatch)
}

func handlerFedClusterForwardDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	handlerFedClusterForward(w, r, ps, http.MethodDelete)
}
