package rest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
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
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
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

type tNvHttpClient struct {
	httpClient  *http.Client
	proxyUrlStr string // non-empty for connection thru proxy
	basicAuth   string // non-empty for proxy that requires auth
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
	_tagJoinPending        = "pending"
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

	_headerProxy = "X-NV-Proxy"
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
	_fedClusterJoinPending    = 210  // do not change
	_fedClusterNetworkError   = 300  // do not change. this state is not visible on UI
	_fedClusterImporting      = 301  // do not change. this state is not visible on UI
)

const clusterAuthTimeout = time.Duration(10 * time.Second)
const restForInstantPing = time.Duration(8 * time.Second)

const jsonContentType = "application/json"

const _maxRegCollectCount int = 2

const (
	const_no_proxy = iota
	const_https_proxy
	const_http_proxy
)

var _isLeader uint32
var reqTokenLock sync.Mutex

var _fedPingOngoing uint32
var _fedPollOngoing uint32
var _fedScanDataPollOngoing uint32
var _fedDeployCount uint32
var _fedFullPolling uint32                                                                      // 0: modified rules polling, 1: full rules polling
var _fedPollInterval uint32 = 1                                                                 // in minutes
var _fedPollingTimer *time.Timer = time.NewTimer(time.Minute * time.Duration(_fedPollInterval)) // for joint clusters to poll master cluster
var _fedPingInterval uint32 = 1                                                                 // in minutes
var _fedPingTimer *time.Timer = time.NewTimer(time.Minute * time.Duration(_fedPingInterval))    // for master cluster to ping master clusters
var _lastFedMemberPingTime time.Time = time.Now()
var _masterClusterIP string
var _fixedJoinToken string

var _sysHttpsProxy share.CLUSProxy
var _sysHttpProxy share.CLUSProxy
var _sysProxyMutex sync.RWMutex // for accessing _sysHttpsProxy/_sysHttpProxy

var _proxyOptionHistory = make(map[string]int8) // key is clusterID. "" means it's for communication with master; value is 0(no proxy), 1(https proxy), 2(http proxy)
var _nvHttpClients [3]*tNvHttpClient            // index is 0(no proxy), 1(https proxy), 2(http proxy)
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
	_fedClusterJoinPending:    api.FedStatusClusterPending,
}

var ibmSACfg share.CLUSIBMSAConfig

func LeadChangeNotify(leader bool) {
	log.WithFields(log.Fields{"isLeader": leader, "_isLeader": _isLeader}).Info()
	if leader {
		if k8sPlatform {
			if isOldLeader := atomic.LoadUint32(&_isLeader); isOldLeader == 0 && crdReqMgr != nil {
				// this controller just gains leader role
				crdReqMgr.reloadRecordList()
			}
		}
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
					cacher.SyncAdmCtrlStateToK8s(svcName, nvAdmName, false)
				} else {
					log.WithFields(log.Fields{"cn": cn, "err": err}).Error("no cert")
				}
			}
		}
	} else {
		if k8sPlatform {
			isOldLeader := atomic.LoadUint32(&_isLeader)
			atomic.StoreUint32(&_isLeader, 0)
			if isOldLeader == 1 && crdReqMgr != nil {
				// this controller just lost leader role
				crdReqMgr.reloadRecordList()
			}
		}
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
			ok = acc.IsFedReader() || acc.IsFedAdmin() || acc.HasPermFed()
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

	fedRole, err := cacher.GetFedMembershipRole(acc)
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

// Be careful. This function is only for between-clusters joining/leaving/polling/csp_support APIs
func isNoAuthFedOpAllowed(expectedFedRole string, w http.ResponseWriter, r *http.Request, acc *access.AccessControl) bool {
	fedRole, err := cacher.GetFedMembershipRole(acc)
	if err != nil || (expectedFedRole != FedRoleAny && fedRole != expectedFedRole) {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return false
	}

	return true
}

func getProxyURL(r *http.Request) (*url.URL, error) {
	value := r.Header.Get(_headerProxy)
	r.Header.Del(_headerProxy)
	if value != "" {
		return url.Parse(value)
	}
	return nil, nil
}

func createHttpClient(proxyOption int8, timeout time.Duration) (*http.Client, string, string) {
	var proxyUrlStr string
	var basicAuth string
	var proxy share.CLUSProxy

	// refer to http.DefaultTransport
	transport := &http.Transport{
		Proxy: getProxyURL,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}
	if proxyOption != const_no_proxy {
		_sysProxyMutex.RLock()
		if proxyOption == const_http_proxy {
			proxy = _sysHttpProxy
		} else {
			proxy = _sysHttpsProxy
		}
		_sysProxyMutex.RUnlock()
	}
	if proxyOption != const_no_proxy && proxy.Enable {
		proxyUrlStr = proxy.URL
		if proxy.Username != "" {
			auth := fmt.Sprintf("%s:%s", proxy.Username, proxy.Password)
			basicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			transport.ProxyConnectHeader = http.Header{}
			transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
		}
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

	return httpClient, proxyUrlStr, basicAuth
}

func getProxyOptions(id string, useProxy int8) []int8 {
	var ok bool
	var lastProxyOption int8
	var httpsProxyEnabled bool
	var httpProxyEnabled bool

	_sysProxyMutex.RLock()
	httpsProxyEnabled = _sysHttpsProxy.Enable
	httpProxyEnabled = _sysHttpProxy.Enable
	_sysProxyMutex.RUnlock()

	if (useProxy == const_https_proxy && !httpsProxyEnabled) || (useProxy == const_http_proxy && !httpProxyEnabled) {
		useProxy = const_no_proxy
	}

	_httpClientMutex.RLock()
	lastProxyOption, ok = _proxyOptionHistory[id]
	_httpClientMutex.RUnlock()
	if ok && (lastProxyOption == const_https_proxy && !httpsProxyEnabled) || (lastProxyOption == const_http_proxy && !httpProxyEnabled) {
		lastProxyOption = const_no_proxy
	}

	proxyOptions := make([]int8, 0, 4)
	if !ok {
		// this is the first http connection to this remote ep
		proxyOptions = append(proxyOptions, useProxy)
	} else {
		// we know whether proxy is used in the last http connection to this remote ep
		proxyOptions = append(proxyOptions, lastProxyOption)
		if useProxy != lastProxyOption {
			proxyOptions = append(proxyOptions, useProxy)
		}
	}
	hasNoProxyOption := false
	for _, proxyOption := range proxyOptions {
		if proxyOption == const_no_proxy {
			hasNoProxyOption = true
			break
		}
	}
	if !hasNoProxyOption {
		// we will always try http connection to this remote ep without proxy at the last
		proxyOptions = append(proxyOptions, const_no_proxy)
	}

	return proxyOptions
}

func sendRestRequest(idTarget string, method, urlStr, token, cntType, jointTicket, jointID string, cookie *http.Cookie,
	body []byte, logError bool, specificProxy *int8, acc *access.AccessControl) ([]byte, int, bool, error) {

	var useProxy int8
	var data []byte
	var statusCode int
	var usedProxy bool
	var err error

	if idTarget == "rancher" || idTarget == "telemetry" {
		if strings.HasPrefix(urlStr, "https://") {
			useProxy = const_https_proxy
		} else if strings.HasPrefix(urlStr, "http://") {
			useProxy = const_http_proxy
		}
	} else {
		if specificProxy != nil {
			useProxy = *specificProxy
		} else {
			_, useProxy = cacher.GetFedLocalRestInfo(acc)
		}
	}
	proxyOptions := getProxyOptions(idTarget, useProxy)

	for _, proxyOption := range proxyOptions {
		var nvHttpClient *tNvHttpClient

		_httpClientMutex.RLock()
		nvHttpClient = _nvHttpClients[proxyOption]
		_httpClientMutex.RUnlock()
		if nvHttpClient == nil {
			httpClient, proxyUrlStr, basicAuth := createHttpClient(proxyOption, clusterAuthTimeout)
			nvHttpClient = &tNvHttpClient{
				httpClient:  httpClient,
				proxyUrlStr: proxyUrlStr,
				basicAuth:   basicAuth,
			}
			_httpClientMutex.Lock()
			_nvHttpClients[proxyOption] = nvHttpClient
			_httpClientMutex.Unlock()
		}
		if data, statusCode, err = sendRestReqInternal(nvHttpClient, method, urlStr, token, cntType,
			jointTicket, jointID, proxyOption, cookie, body, logError); err == nil {

			_httpClientMutex.Lock()
			_proxyOptionHistory[idTarget] = proxyOption
			_httpClientMutex.Unlock()
			if proxyOption != const_no_proxy {
				usedProxy = true
			}
			break
		}
	}

	return data, statusCode, usedProxy, err
}

func sendRestReqInternal(nvHttpClient *tNvHttpClient, method, urlStr, token, cntType, jointTicket, jointID string,
	proxyOption int8, cookie *http.Cookie, body []byte, logError bool) ([]byte, int, error) {

	var httpClient *http.Client = nvHttpClient.httpClient
	var req *http.Request
	var gzipped bool
	var err error

	if jointTicket != "" && jointID != "" {
		if len(body) > gzipThreshold {
			body = utils.GzipBytes(body)
			gzipped = true
		}
	}

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
	if cntType == "" {
		req.Header.Set("Accept", jsonContentType)
		req.Header.Set("Content-Type", jsonContentType)
	} else {
		req.Header.Set("Accept", cntType)
		req.Header.Set("Content-Type", cntType)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set(_headerProxy, nvHttpClient.proxyUrlStr)
	if jointTicket != "" {
		req.Header.Set("X-NV-Joint-Ticket", jointTicket)
	}
	if jointID != "" {
		req.Header.Set("X-NV-Joint-ID", jointID)
	}
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
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

	data, err := io.ReadAll(resp.Body)
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
		if param1 != nil && param2 != nil {
			var oldHttpsProxy share.CLUSProxy
			var oldHttpProxy share.CLUSProxy

			_sysProxyMutex.RLock()
			oldHttpsProxy = _sysHttpsProxy
			oldHttpProxy = _sysHttpProxy
			_sysProxyMutex.RUnlock()

			newHttpsProxy, _ := param1.(*share.CLUSProxy)
			newHttpProxy, _ := param2.(*share.CLUSProxy)
			newProxies := []*share.CLUSProxy{newHttpsProxy, newHttpProxy}
			oldProxies := []share.CLUSProxy{oldHttpsProxy, oldHttpProxy}
			cachedProxies := []*share.CLUSProxy{&_sysHttpsProxy, &_sysHttpProxy}
			proxyOptions := []int8{const_https_proxy, const_http_proxy}

			for i := 0; i < len(proxyOptions); i++ {
				proxyOption := proxyOptions[i]
				if newProxy := *(newProxies[i]); newProxy != oldProxies[i] {
					_sysProxyMutex.Lock()
					*(cachedProxies[i]) = newProxy
					_sysProxyMutex.Unlock()

					var newBasicAuth string
					var nvHttpClient *tNvHttpClient

					if newProxy.Username != "" {
						auth := fmt.Sprintf("%s:%s", newProxy.Username, newProxy.Password)
						newBasicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
					}
					_httpClientMutex.RLock()
					nvHttpClient = _nvHttpClients[proxyOption]
					_httpClientMutex.RUnlock()
					// no need to reconstruct a new http client when only proxy url changes.
					// however, if proxy auth changes, we need to reconstruct a new http client because transport ProxyConnectHeader is a map
					if nvHttpClient == nil || newBasicAuth != nvHttpClient.basicAuth {
						newHttpClient, proxyUrlStr, basicAuth := createHttpClient(proxyOption, clusterAuthTimeout)
						newNvHttpClient := &tNvHttpClient{
							httpClient:  newHttpClient,
							proxyUrlStr: proxyUrlStr,
							basicAuth:   basicAuth,
						}
						_httpClientMutex.Lock()
						_nvHttpClients[proxyOption] = newNvHttpClient
						_httpClientMutex.Unlock()
						if nvHttpClient != nil && nvHttpClient.httpClient != nil {
							nvHttpClient.httpClient.CloseIdleConnections()
						}
					} else {
						if nvHttpClient.proxyUrlStr != newProxy.URL {
							// only proxy url changes
							nvHttpClient.proxyUrlStr = newProxy.URL
						}
					}
				}
			}
		}
	}

	return err
}

func initHttpClients() {
	if cfg, _ := clusHelper.GetSystemConfigRev(access.NewReaderAccessControl()); cfg != nil {
		_sysProxyMutex.Lock()
		_sysHttpsProxy = cfg.RegistryHttpsProxy
		_sysHttpProxy = cfg.RegistryHttpProxy
		_sysProxyMutex.Unlock()
	}
	for _, proxyOption := range []int8{const_no_proxy, const_https_proxy, const_http_proxy} {
		httpClient, proxyUrlStr, basicAuth := createHttpClient(proxyOption, clusterAuthTimeout)
		_httpClientMutex.Lock()
		if _nvHttpClients[proxyOption] == nil {
			_nvHttpClients[proxyOption] = &tNvHttpClient{
				httpClient:  httpClient,
				proxyUrlStr: proxyUrlStr,
				basicAuth:   basicAuth,
			}
		}
		_httpClientMutex.Unlock()
	}
}

// it returns (headers, statusCode, data, proxyUsed, err)
func sendReqToJointCluster(rc share.CLUSRestServerInfo, clusterID, token, method, request, contentType, tag, txnID string,
	body []byte, gzipped, forward, remoteExport, logError bool, acc *access.AccessControl) (map[string]string, int, []byte, bool, error) {

	var headers map[string]string
	var statusCode int
	var data []byte
	var usedProxy bool
	var scanRepository bool
	var err error

	_, useProxy := cacher.GetFedLocalRestInfo(acc)
	proxyOptions := getProxyOptions(clusterID, useProxy)

	if method == http.MethodPost && request == "/v1/scan/repository" {
		scanRepository = true
	}

	urlStr := fmt.Sprintf("https://%s:%d/%s", rc.Server, rc.Port, request)
	for _, proxyOption := range proxyOptions {
		var nvHttpClient *tNvHttpClient

		_httpClientMutex.RLock()
		nvHttpClient = _nvHttpClients[proxyOption]
		_httpClientMutex.RUnlock()
		if scanRepository {
			nvHttpClient.httpClient.Timeout = repoScanLingeringDuration + time.Duration(30*time.Second)
		}
		headers, statusCode, data, err = sendReqToJointClusterInternal(nvHttpClient, method, urlStr, token, contentType, tag, txnID,
			proxyOption, body, gzipped, forward, remoteExport, logError)
		if scanRepository {
			nvHttpClient.httpClient.Timeout = clusterAuthTimeout
		}
		if err == nil {
			_httpClientMutex.Lock()
			_proxyOptionHistory[clusterID] = proxyOption
			_httpClientMutex.Unlock()
			if proxyOption != const_no_proxy {
				usedProxy = true
			}
			break
		}
	}

	return headers, statusCode, data, usedProxy, err
}

func sendReqToJointClusterInternal(nvHttpClient *tNvHttpClient, method, urlStr, token, contentType, tag, txnID string,
	proxyOption int8, body []byte, gzipped, forward, remoteExport, logError bool) (map[string]string, int, []byte, error) {

	var httpClient *http.Client = nvHttpClient.httpClient

	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	if err != nil {
		log.WithFields(log.Fields{"url": urlStr, "tag": tag, "error": err, "proxyOption": proxyOption}).Error("Failed to create request")
		return nil, 0, nil, err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set(_headerProxy, nvHttpClient.proxyUrlStr)
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
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

	data, err := io.ReadAll(resp.Body)
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

	if user == nil || (user.Role != api.UserRoleFedAdmin && user.Role != api.UserRoleFedReader && !user.ExtraPermits.HasPermFed()) {
		return "", common.ErrObjectAccessDenied
	}

	var remoteRolePermits share.CLUSRemoteRolePermits
	if user.RemoteRolePermits == nil {
		if user.Role == api.UserRoleFedAdmin {
			remoteRolePermits.DomainRole = map[string]string{access.AccessDomainGlobal: api.UserRoleAdmin}
		} else if user.Role == api.UserRoleFedReader {
			remoteRolePermits.DomainRole = map[string]string{access.AccessDomainGlobal: api.UserRoleReader}
		}
		/* fed access for namespaces is not supported yet
		if user.ExtraPermits.HasPermFed() {
			extraPermits := user.ExtraPermits
			extraPermits.FilterPermits(access.AccessDomainGlobal, "remote", api.FedRoleMaster)
			remoteRolePermits.ExtraPermits = map[string]share.NvPermissions{access.AccessDomainGlobal: extraPermits}
		}
		*/
		user.RemoteRolePermits = &remoteRolePermits
	}

	reqTokenLock.Lock()
	defer reqTokenLock.Unlock()

	if !refreshToken {
		return cacher.GetFedJoinedClusterToken(clusterID, login.id, acc)
	} else {
		reqTo := &api.RESTFedAuthData{
			ClientIP:       _masterClusterIP,
			MasterUsername: login.fullname,
			JointUsername:  common.DefaultAdminUser,
			// master token is for requesting regular jwt token from joint cluster. It can be validated by joint cluster based on shared secret/key/cert between master & joint clusters
			MasterToken: jwtGenFedMasterToken(user, login, rc.ID, rc.Secret),
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
			"", jsonContentType, _tagAuthJointCluster, body, false, _notForward, false, true, acc); err == nil {
			if statusCode != http.StatusOK {
				log.WithFields(log.Fields{"cluster": rc.RestInfo.Server, "status": statusCode, "proxyUsed": proxyUsed}).Error("Unable to authenticate with the cluster")
				err = errors.New("Unable to authenticate with the cluster")
			} else {
				tokenData := api.RESTTokenData{}
				if err = json.Unmarshal(data, &tokenData); err == nil {
					cacher.SetFedJoinedClusterToken(clusterID, login.id, tokenData.Token.Token)

					// apikey - timer to expire the login session
					if login.loginType == loginTypeApikey {
						login.timer = time.AfterFunc(time.Second*time.Duration(user.Timeout), func() { login.expire() })
					}

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
	acc *access.AccessControl, login *loginSession, talkRounds []bool) int {
	log.WithFields(log.Fields{"method": method, "id": id}).Debug()
	user, _, _ := clusHelper.GetUserRev(login.fullname, acc)
	cmdResp := cmdResponse{id: id, result: _fedClusterDisconnected}
	var status int

	if len(talkRounds) == 0 {
		talkRounds = []bool{false, true}
	}
	// we cache the token for forwarded requests(to joint clusters). so we try the cached token first and ask for a new token if necessary.
	for _, refreshToken := range talkRounds {
		status = http.StatusBadRequest
		if token, err := getJointClusterToken(rc, id, user, refreshToken, acc, login); token != "" { // get a regular token for accessing joint cluster
			if _, statusCode, data, proxyUsed, err := sendReqToJointCluster(rc.RestInfo, id, token, method,
				request, jsonContentType, tag, "", body, false, _notForward, false, refreshToken, acc); err == nil {
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
					cacher.SetFedJoinedClusterToken(id, login.id, "")
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
	talkToJointCluster(&joinedCluster, http.MethodPost, "v1/fed/remove_internal", joinedCluster.ID, _tagDismissFed, bodyTo, nil, acc, login, nil)
	_, jointKeyPath, jointCertPath := kv.GetFedTlsKeyCertPath("", joinedCluster.ID)
	os.Remove(jointKeyPath)
	os.Remove(jointCertPath)
	_setFedJointPrivateKey(joinedCluster.ID, nil)
	clusHelper.DeleteFedJointCluster(joinedCluster.ID)
	if ch != nil {
		ch <- true
	}
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

	deleteFedGroupPolicy()

	txn := cluster.Transact()
	defer txn.Close()

	txn.Delete(share.CLUSFedKey(share.CFGEndpointSystem))
	clusHelper.PutFedRulesRevision(txn, share.CLUSEmptyFedRulesRevision())
	clusHelper.PutFedSettings(txn, share.CLUSFedSettings{})
	txn.Delete(share.CLUSScanStateKey(share.CLUSFedScanDataRevSubKey))
	fedRegs := clusHelper.GetAllRegistry(share.ScopeFed)
	for _, reg := range fedRegs {
		clusHelper.DeleteRegistry(txn, reg.Name)
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
	}

}

func leaveFedCleanup(masterID, jointID string, lockAcquired bool) {
	var err error
	var lock cluster.LockInterface
	if !lockAcquired {
		if lock, err = lockClusKey(nil, share.CLUSLockFedKey); err != nil {
			return
		}
		defer clusHelper.ReleaseLock(lock)
	}

	masterCaCertPath, jointKeyPath, jointCertPath := kv.GetFedTlsKeyCertPath(masterID, jointID)
	os.Remove(masterCaCertPath)
	os.Remove(jointKeyPath)
	os.Remove(jointCertPath)
	clusHelper.DeleteFedJointClusterStatus(masterID)
	clusHelper.DeleteFedJointClusterStatus(jointID)
	delAllFedSessionTokens()
	resetFedJointKeys()
	cleanFedRules()
	cluster.Delete(share.CLUSUserKey(common.ReservedFedUser))
	clusHelper.DeleteRegistryKeys(common.RegistryFedRepoScanName)
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

func updateClusterState(id, masterClusterID string, status int, cspUsage *share.CLUSClusterCspUsage, acc *access.AccessControl) bool {
	if status == _fedSuccess {
		return true
	}

	// _fedClusterConnected(200), _fedClusterJoined(201), _fedClusterOutOfSync(202), _fedClusterSynced(203)
	connectedStates := utils.NewSet(_fedClusterConnected, _fedClusterJoined, _fedClusterOutOfSync, _fedClusterSynced)
	changed := false
	cached := cacher.GetFedJoinedClusterStatus(id, acc)
	if connectedStates.Contains(status) {
		now := time.Now()
		duration := time.Duration(cctx.CspPauseInterval*15) * time.Second
		if cached.LastConnectedTime.IsZero() || cached.Status != status || now.After(cached.LastConnectedTime.Add(duration)) {
			cached.LastConnectedTime = now
			cached.SwitchToUnreachable = 0
			changed = true
		}
	}
	if cached.Status != status {
		clusterUnreachable := false
		if status == _fedClusterLeft || status == _fedClusterDisconnected {
			clusterUnreachable = true
		}
		if cached.Status == _fedClusterJoinPending && clusterUnreachable {
			// do not change joint cluster status
		} else {
			if clusterUnreachable {
				if connectedStates.Contains(cached.Status) && cached.SwitchToUnreachable == 0 {
					cached.SwitchToUnreachable++
				}
			}
			cached.Status = status
			changed = true
		}
	}
	if cspUsage != nil {
		if cspUsage.CspType != cached.CspType || cspUsage.Nodes != cached.Nodes {
			cached.CspType = cspUsage.CspType
			cached.Nodes = cspUsage.Nodes
			changed = true
		}
	}
	if changed {
		clusHelper.PutFedJointClusterStatus(id, &cached)
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
					go talkToJointCluster(&jointCluster, http.MethodPost, "v1/fed/command_internal", id, _tagDeployFedPolicy, bodyTo, ch, acc, login, nil)
				}
			}
		}
	}
	for j := 0; j < notify; j++ {
		notifyResult := <-ch
		updateClusterState(notifyResult.id, "", notifyResult.result, nil, acc)
	}
}

func updateFedRulesRevision(ruleTypes []string, acc *access.AccessControl, login *loginSession) {
	if clusHelper.UpdateFedRulesRevision(ruleTypes) {
		ids := cacher.GetFedJoinedClusterIdMap(acc)
		for id, disabled := range ids {
			if !disabled {
				updateClusterState(id, "", _fedClusterOutOfSync, nil, acc)
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
			urlStr, jsonContentType, tag, "", bodyTo, false, _notForward, false, logError, acc)
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
	if tag == _tagJoinPending && cmdResp.result == _fedClusterLeft {
		// even the 1st ping for the joint cluster tells it's not in fed.
		updateClusterState(id, "", _fedClusterJoinPending, nil, acc)
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
						updateClusterState(deployResult.id, "", _fedClusterDisconnected, nil, acc)
					}
				} else {
					if state == _fedMasterUpgradeRequired {
						state = _fedJointVersionTooNew
					} else if state == _fedSuccess {
						if old := cacher.GetFedJoinedClusterStatus(deployResult.id, acc); old.Status == _fedClusterDisconnected {
							state = _fedClusterConnected
						}
					}
					updateClusterState(deployResult.id, "", state, nil, acc)
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
	var msg string

	nameSet := clusHelper.GetAllGroupNames(share.ScopeFed)
	regs := clusHelper.GetAllRegistry(share.ScopeFed)
	if nameSet.Cardinality() > 0 || len(regs) > 0 {
		cleanFedRules()
		nameSet = clusHelper.GetAllGroupNames(share.ScopeFed)
		regs := clusHelper.GetAllRegistry(share.ScopeFed)
		if nameSet.Cardinality() > 0 {
			groupNames := nameSet.ToStringSlice()
			msg = strings.Join(groupNames[:], ",")
			log.WithFields(log.Fields{"groups": msg}).Error("Group name with reserved prefix for fed exists")
		}
		if len(regs) > 0 {
			regNames := make([]string, 0, len(regs))
			for _, reg := range regs {
				regNames = append(regNames, reg.Name)
			}
			msg = strings.Join(regNames[:], ",")
			log.WithFields(log.Fields{"registry": msg}).Error("Registry name with reserved prefix for fed exists")
		}
	}

	return msg
}

func handlerGetFedMember(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc0, login := getAccessControl(w, r, "")
	if acc0 == nil {
		return
	} else if !login.hasFedPermission() && !acc0.HasGlobalPermissions(share.PERMS_CLUSTER_READ, 0) {
		restRespAccessDenied(w, login)
		return
	}
	acc := acc0.BoostPermissions(share.PERM_SYSTEM_CONFIG | share.PERM_FED)

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

	fedCfg := cacher.GetFedSettings()
	org.DeployRepoScanData = fedCfg.DeployRepoScanData

	restRespSuccess(w, r, org, acc, login, nil, "Get federation config")
}

func handlerConfigLocalCluster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := isFedOpAllowed(FedRoleAny, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	fedRole, _ := cacher.GetFedMembershipRole(acc)
	if fedRole == api.FedRoleMaster && !acc.IsFedAdmin() {
		restRespAccessDenied(w, login)
		return
	}

	var reqData api.RESTFedConfigData
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &reqData); err != nil || (reqData.Name != nil && *reqData.Name == "") ||
		(reqData.RestInfo != nil && !reqData.RestInfo.IsValid()) ||
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

	if reqData.DeployRepoScanData != nil {
		if fedRole == api.FedRoleJoint {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
				"Options for scan data deployment can only be configured on primary cluster")
			return
		}
		fedCfg := clusHelper.GetFedSettings()
		newCfg := fedCfg
		if reqData.DeployRepoScanData != nil {
			newCfg.DeployRepoScanData = *reqData.DeployRepoScanData
		}
		if newCfg != fedCfg {
			clusHelper.PutFedSettings(nil, newCfg)
		}
	}

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
						if joined := cacher.GetFedJoinedClusterCount(); joined > 0 {
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed,
								"Exposed REST server info is read-only when there is other cluster in the federation")
							return
						}
						m.LocalRestInfo = *reqData.RestInfo
						m.MasterCluster.RestInfo = *reqData.RestInfo
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

// caller must own share.CLUSLockFedKey
func promoteToMaster(w http.ResponseWriter, acc *access.AccessControl, login *loginSession, reqData api.RESTFedPromoteReqData) (
	share.CLUSFedMembership, int, int, error) {

	var err error
	var restInfo share.CLUSRestServerInfo
	var useProxy string
	var msg string
	var membership share.CLUSFedMembership
	var status int = http.StatusInternalServerError
	var code int = api.RESTErrFedOperationFailed

	cacheRestInfo, cacheUseProxy := cacher.GetFedLocalRestInfo(acc)
	if reqData.MasterRestInfo != nil {
		restInfo = *reqData.MasterRestInfo
	} else {
		restInfo = cacheRestInfo
	}
	if reqData.UseProxy != nil {
		useProxy = *reqData.UseProxy
	} else if cacheUseProxy == const_https_proxy {
		useProxy = "https"
	}
	var msgProxy string
	if useProxy != "" {
		msgProxy = "(use proxy)"
	}
	msg = fmt.Sprintf("Promote to primary cluster%s", msgProxy)

	if reqData.UseProxy != nil && *reqData.UseProxy != "" && *reqData.UseProxy != "https" || !restInfo.IsValid() {
		log.WithFields(log.Fields{"useProxy": useProxy, "restInfo": restInfo}).Error("Request error")
		return membership, http.StatusBadRequest, api.RESTErrInvalidRequest, nil
	}

	updateSystemClusterName(reqData.Name, acc)
	if err = clusHelper.ConfigFedRole(common.DefaultAdminUser, api.UserRoleFedAdmin, acc); err != nil {
		return membership, status, code, err
	}
	// Any admin-role user(local user or not) who promotes a cluster to fed master is automatically promoted to fedAdmin role
	// However, Rancher SSO user's role is defined in Rancher so we don't promote the shadow user created by Rancher SSO
	if login.fullname != common.DefaultAdminUser && login.server != share.FlavorRancher {
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
		return membership, status, code, err
	}

	if reqData.PingInterval > 0 {
		atomic.StoreUint32(&_fedPingInterval, reqData.PingInterval)
	}
	if reqData.PollInterval > 0 {
		atomic.StoreUint32(&_fedPollInterval, reqData.PollInterval)
	}
	secret, _ := utils.GetGuid()
	membership = share.CLUSFedMembership{
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

	if err = clusHelper.PutFedMembership(&membership); err != nil {
		revertFedRoles(acc)
		return membership, status, code, err
	}
	kv.CreateDefaultFedGroups()

	var cfg share.CLUSFedSettings
	if reqData.DeployRepoScanData != nil {
		cfg.DeployRepoScanData = *reqData.DeployRepoScanData
	}
	clusHelper.PutFedSettings(nil, cfg)

	revisions := share.CLUSEmptyFedRulesRevision()
	clusHelper.PutFedRulesRevision(nil, revisions)
	clusHelper.PutFedScanRevisions(&share.CLUSFedScanRevisions{ScannedRegRevs: make(map[string]uint64)}, nil)

	accFedAdmin := access.NewFedAdminAccessControl()
	cacheFedEvent(share.CLUSEvFedPromote, msg, login.fullname, login.remote, login.id, login.domainRoles)
	user, _, _ := clusHelper.GetUserRev(common.DefaultAdminUser, accFedAdmin)
	if user != nil {
		kickLoginSessions(user)
	}
	// if current user is local non-default admin user or rancher user, kick all related sessions
	if w != nil && (login.fullname != common.DefaultAdminUser || login.server != "") {
		if user, _, _ := clusHelper.GetUserRev(login.fullname, accFedAdmin); user != nil {
			kickLoginSessions(user)
		}
	}

	cache.ConfigCspUsages(false, false, api.FedRoleMaster, masterID)

	return membership, http.StatusOK, 0, nil
}

func handlerPromoteToMaster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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
	body, _ := io.ReadAll(r.Body)
	if err = json.Unmarshal(body, &reqData); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if membership, httpStatus, code, err := promoteToMaster(w, acc, login, reqData); httpStatus == http.StatusOK {
		resp := api.RESTFedPromoteRespData{
			FedRole: api.FedRoleMaster,
			MasterCluster: api.RESTFedMasterClusterInfo{
				ID:       membership.MasterCluster.ID,
				RestInfo: membership.MasterCluster.RestInfo,
			},
			UseProxy: membership.UseProxy,
		}
		if reqData.DeployRepoScanData != nil {
			resp.DeployRepoScanData = *reqData.DeployRepoScanData
		}
		restRespSuccess(w, r, &resp, acc, login, nil, "Promote to primary cluster")
	} else {
		var msg string
		if err != nil {
			msg = err.Error()
		}
		restRespErrorMessage(w, httpStatus, code, msg)
	}
}

// caller must own share.CLUSLockFedKey
func demoteFromMaster(w http.ResponseWriter, acc *access.AccessControl, login *loginSession) (
	share.CLUSFedMembership, int, int, error) {

	var membership share.CLUSFedMembership

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
			if joinedCluster := clusHelper.GetFedJointCluster(id); joinedCluster != nil {
				if joinedCluster.ID == id {
					dismiss++
					if w == nil {
						// called by configmap
						informFedDismissed(*joinedCluster, bodyTo, nil, acc, login)
					} else {
						go informFedDismissed(*joinedCluster, bodyTo, ch, acc, login)
					}
				}
			}
		}
		if w != nil {
			for j := 0; j < dismiss; j++ {
				<-ch
			}
		}
	}
	clusHelper.PutFedJointClusterList(&share.CLUSFedJoinedClusterList{})

	masterCluster := cacher.GetFedMasterCluster(acc)
	if masterCaCertPath, _, _ := kv.GetFedTlsKeyCertPath(masterCluster.ID, ""); masterCaCertPath != "" {
		os.Remove(masterCaCertPath)
	}
	membership = share.CLUSFedMembership{
		FedRole:          api.FedRoleNone,
		LocalRestInfo:    masterCluster.RestInfo,
		PendingDismiss:   true,
		PendingDismissAt: time.Now().UTC(),
	}
	if err := clusHelper.PutFedMembership(&membership); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to demote")
		return membership, http.StatusInternalServerError, api.RESTErrFedOperationFailed, err
	}

	cacheFedEvent(share.CLUSEvFedDemote, "Demote from primary cluster", login.fullname, login.remote, login.id, login.domainRoles)
	evqueue.Flush()
	revertFedRoles(acc)
	cleanFedRules()

	cache.ConfigCspUsages(false, false, api.FedRoleNone, "")
	membership.PendingDismiss = false
	membership.PendingDismissAt = time.Time{}
	clusHelper.PutFedMembership(&membership)

	return membership, http.StatusOK, 0, nil
}

func handlerDemoteFromMaster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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

	if _, httpStatus, code, err := demoteFromMaster(w, acc, login); httpStatus == http.StatusOK {
		restRespSuccess(w, r, nil, acc, login, nil, "Demote from primary cluster")
	} else {
		var msg string
		if err != nil {
			msg = err.Error()
		}
		restRespErrorMessage(w, httpStatus, code, msg)
	}
}

func handlerGetFedJoinToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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

// caller must own share.CLUSLockFedKey
func joinFed(w http.ResponseWriter, acc *access.AccessControl, login *loginSession, req api.RESTFedJoinReq) (
	share.CLUSFedMembership, int, int, error) {

	var err error
	var localRestInfo share.CLUSRestServerInfo
	var masterRestInfo share.CLUSRestServerInfo
	var useProxy string
	var specificProxy int8
	var joinToken joinToken
	var msgProxy string
	var membership share.CLUSFedMembership
	var status int = http.StatusInternalServerError
	var code int = api.RESTErrFedOperationFailed

	fedRestInfo, fedUseProxy := cacher.GetFedLocalRestInfo(acc)
	if req.JointRestInfo != nil {
		localRestInfo = *req.JointRestInfo
	} else {
		localRestInfo = fedRestInfo
	}

	if req.UseProxy != nil {
		useProxy = *req.UseProxy
	} else if fedUseProxy == const_https_proxy {
		useProxy = "https"
	}
	if useProxy != "" {
		msgProxy = "(use proxy)"
		specificProxy = const_https_proxy
	}

	if w != nil {
		// called by REST API
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
	} else {
		// called by configmap
		joinToken.JoinTicket = req.JoinToken
	}
	masterRestInfo = share.CLUSRestServerInfo{
		Server: req.Server,
		Port:   req.Port,
	}

	var name string
	if req.Name == "" {
		name = cacher.GetSystemConfigClusterName(acc)
	} else {
		name = req.Name
	}
	if name == "" || !masterRestInfo.IsValid() || (w != nil && joinToken.JoinTicket == "") || !localRestInfo.IsValid() ||
		(req.UseProxy != nil && *req.UseProxy != "" && *req.UseProxy != "https") {
		log.WithFields(log.Fields{"name": name, "localServer": localRestInfo, "masterServer": masterRestInfo}).Error("Request error")
		return membership, http.StatusBadRequest, api.RESTErrInvalidRequest, nil
	}
	updateSystemClusterName(name, acc)

	var jointID, jointSecret string
	if jointID, err = utils.GetGuid(); err == nil {
		jointSecret, err = utils.GetGuid()
	}
	if jointID == "" || jointSecret == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		return membership, status, code, err
	}
	nvUsage := cacher.GetNvUsage(api.FedRoleJoint)

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
			RestInfo: localRestInfo,
		},
		CspType: nvUsage.LocalClusterUsage.CspType, // joint cluster's billing csp type
		Nodes:   nvUsage.LocalClusterUsage.Nodes,
	}

	bodyTo, _ := json.Marshal(&reqTo)
	var data []byte
	var statusCode int
	var proxyUsed bool
	// call master cluster for joining federation
	urlStr := fmt.Sprintf("https://%s:%d/v1/fed/join_internal", masterRestInfo.Server, masterRestInfo.Port)
	data, statusCode, proxyUsed, err = sendRestRequest("", http.MethodPost, urlStr, "", "", "", "", nil, bodyTo, true, &specificProxy, acc)
	if err == nil {
		respTo := api.RESTFedJoinRespInternal{}
		if err = json.Unmarshal(data, &respTo); err == nil {
			mtlsAvailable := false
			caCertPath, _, _ := kv.GetFedTlsKeyCertPath(respTo.MasterCluster.ID, jointID)
			if respTo.CACert != "" && respTo.ClientCert != "" && respTo.ClientKey != "" {
				if caCert, err := base64.StdEncoding.DecodeString(respTo.CACert); err == nil {
					if err = os.WriteFile(caCertPath, caCert, 0600); err == nil {
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
			membership := share.CLUSFedMembership{
				FedRole:       api.FedRoleJoint,
				PollInterval:  respTo.PollInterval,
				LocalRestInfo: localRestInfo,
				MasterCluster: share.CLUSFedMasterClusterInfo{
					Name:   respTo.MasterCluster.Name,
					ID:     respTo.MasterCluster.ID,
					CACert: respTo.CACert,
					User:   "", // respTo.MasterCluster.User, do not let joint cluster know who promoted the master cluster
					RestInfo: share.CLUSRestServerInfo{
						Server: masterRestInfo.Server,
						Port:   masterRestInfo.Port,
					},
				},
				JointCluster: share.CLUSFedJointClusterInfo{
					ID:         jointID,
					Secret:     jointSecret,
					ClientKey:  respTo.ClientKey,
					ClientCert: respTo.ClientCert,
					RestInfo:   localRestInfo,
					User:       login.fullname,
				},
				UseProxy: useProxy,
			}
			if err = clusHelper.PutFedMembership(&membership); err == nil {
				clusHelper.PutFedScanRevisions(&share.CLUSFedScanRevisions{ScannedRegRevs: make(map[string]uint64)}, nil)
				updateClusterState(respTo.MasterCluster.ID, respTo.MasterCluster.ID, _fedClusterConnected, nil, acc)
				updateClusterState(jointID, "", _fedClusterJoined, nil, acc)
				msg := fmt.Sprintf("Join federation%s and the primary cluster is %s(%s)", msgProxy, respTo.MasterCluster.Name, masterRestInfo.Server)
				cacheFedEvent(share.CLUSEvFedJoin, msg, login.fullname, login.remote, login.id, login.domainRoles)
				atomic.StoreUint32(&_fedFullPolling, 1)
				cache.ConfigCspUsages(false, true, api.FedRoleJoint, respTo.MasterCluster.ID)
				return membership, http.StatusOK, 0, nil
			}
			if mtlsAvailable { // error happened if it reaches here
				os.Remove(caCertPath)
			}
		}
	} else if statusCode != 0 {
		log.WithFields(log.Fields{"statusCode": statusCode, "data": string(data), "localServer": localRestInfo, "masterServer": masterRestInfo,
			"proxyUsed": proxyUsed, "kv_version": reqTo.FedKvVersion}).Error()
		var restErr api.RESTError
		if json.Unmarshal(data, &restErr) == nil {
			code := restErr.Code
			if restErr.Code == _fedMasterUpgradeRequired {
				code = api.RESTErrMasterUpgradeRequired
			} else if restErr.Code == _fedJointUpgradeRequired {
				code = api.RESTErrJointUpgradeRequired
			}
			return membership, statusCode, code, fmt.Errorf(restErrMessage[code])
		}
	}

	return membership, status, code, err
}

func handlerJoinFed(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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

	var reqData api.RESTFedJoinReq
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &reqData); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if _, httpStatus, code, err := joinFed(w, acc, login, reqData); httpStatus == http.StatusOK {
		restRespSuccess(w, r, nil, acc, login, nil, "Join federation")
	} else {
		var msg string
		if err != nil {
			msg = err.Error()
		}
		restRespErrorMessage(w, httpStatus, code, msg)
	}
}

// caller must own share.CLUSLockFedKey
func leaveFed(w http.ResponseWriter, acc *access.AccessControl, login *loginSession, req api.RESTFedLeaveReq,
	masterCluster api.RESTFedMasterClusterInfo, jointCluster api.RESTFedJointClusterInfo) (share.CLUSFedMembership, int, int, error) {

	var code int = api.RESTErrFedOperationFailed
	var httpStatus int = http.StatusInternalServerError
	var membership share.CLUSFedMembership

	if masterCluster.ID == "" || jointCluster.ID == "" {
		log.WithFields(log.Fields{"master": masterCluster.ID, "joint": jointCluster.ID}).Error("Request error")
		return membership, http.StatusInternalServerError, api.RESTErrObjectNotFound, common.ErrObjectNotFound
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
		_, _, _, err = sendRestRequest("", http.MethodPost, urlStr, "", "", "", "", nil, bodyTo, true, nil, acc)
		if err == nil || req.Force {
			membership = share.CLUSFedMembership{
				FedRole:          api.FedRoleNone,
				LocalRestInfo:    jointCluster.RestInfo,
				PendingDismiss:   true,
				PendingDismissAt: time.Now().UTC(),
			}

			if err := clusHelper.PutFedMembership(&membership); err == nil {
				cacheFedEvent(share.CLUSEvFedLeave, "Leave federation", login.fullname, login.remote, login.id, login.domainRoles)
				evqueue.Flush()
				if w == nil {
					// called by configmap
					leaveFedCleanup(masterCluster.ID, jointCluster.ID, true)
				} else {
					go leaveFedCleanup(masterCluster.ID, jointCluster.ID, false)
				}
				httpStatus = http.StatusOK
				code = 0
			} else {
				err99 = err
			}
		} else {
			err99 = err
		}
	} else {
		err99 = err
	}

	// after leaving federation, standalone NV reports its usage to CSP
	cache.ConfigCspUsages(false, false, api.FedRoleNone, "")

	return membership, httpStatus, code, err99
}

func handlerLeaveFed(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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

	var reqData api.RESTFedLeaveReq
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &reqData); err != nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	masterCluster := cacher.GetFedMasterCluster(acc)
	jointCluster := cacher.GetFedLocalJointCluster(acc)
	if _, httpStatus, code, err := leaveFed(w, acc, login, reqData, masterCluster, jointCluster); httpStatus == http.StatusOK {
		restRespSuccess(w, r, nil, acc, login, nil, "Leave federation")
	} else {
		var msg string
		if err != nil {
			msg = err.Error()
		}
		restRespErrorMessage(w, httpStatus, code, msg)
	}
}

func handlerRemoveJointCluster(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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

	updateClusterState(id, "", _fedClusterKicked, &share.CLUSClusterCspUsage{}, acc) // intermediate state
	reqTo := api.RESTFedRemovedReqInternal{
		User: login.fullname, // user on master cluster who issues remove-from-federation request
	}
	bodyTo, _ := json.Marshal(&reqTo)
	talkToJointCluster(&joinedCluster, http.MethodPost, "v1/fed/remove_internal", id, _tagKickJointCluster, bodyTo, nil, acc, login, nil)

	status, code := removeFromFederation(&joinedCluster, acc) // remove the joint cluster's entry from master cluster
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
	defer r.Body.Close()

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
	body, _ := io.ReadAll(r.Body)
	for ok := true; ok; ok = false {
		if err := json.Unmarshal(body, &reqData); err == nil {
			masterName := cacher.GetSystemConfigClusterName(accReadAll)
			if masterName == reqData.JointCluster.Name {
				log.WithFields(log.Fields{"master": masterName, "joint": reqData.JointCluster.Name}).Error("non-unique managed cluster name")
				restRespError(w, http.StatusConflict, api.RESTErrFedDuplicateName)
				return
			}
			// join request contains fed kv version for the joining cluster. if it's different from this cluster's fed kv version, it means they are not compatible
			met, result, err := kv.CheckFedKvVersion("master", reqData.FedKvVersion)
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
				log.WithFields(log.Fields{"err": err, "result": result}).Error()
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
	err = nil
	if _fixedJoinToken != "" && reqData.JoinTicket == _fixedJoinToken {
		// fixed join token is enabled thru configmap/secret. always trust it
	} else {
		err = jwtValidateFedJoinTicket(reqData.JoinTicket, masterCluster.Secret)
	}
	if err != nil {
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
		restRespError(w, http.StatusBadRequest, api.RESTErrFedJointUnreachable)
		return
	}

	// update kv
	var caCertData, privKeyData, certData []byte
	_, privKeyPath, certPath := kv.GetFedTlsKeyCertPath("", reqData.JointCluster.ID)
	if err := kv.GenTlsCertWithCaAndStoreInFiles(reqData.JointCluster.ID, certPath, privKeyPath, kv.AdmCACertPath, kv.AdmCAKeyPath, kv.ValidityPeriod{Year: 10}, x509.ExtKeyUsageClientAuth); err == nil {
		masterCaCertPath, _, _ := kv.GetFedTlsKeyCertPath(masterCluster.ID, "")
		caCertData, err = os.ReadFile(masterCaCertPath)
		if err == nil {
			privKeyData, err = os.ReadFile(privKeyPath)
			if err == nil {
				certData, err = os.ReadFile(certPath)
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

	cspType, _ := common.GetMappedCspType(&reqData.CspType, nil)
	cspUsage := share.CLUSClusterCspUsage{
		CspType: cspType, // joint cluster's billing csp type
		Nodes:   reqData.Nodes,
	}
	updateClusterState(joinedCluster.ID, "", _fedClusterJoined, &cspUsage, accReadAll)

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
		_, resp.CspType = common.GetMappedCspType(nil, &cctx.CspType) // master cluster's billing csp type
		msg := fmt.Sprintf("Cluster %s(%s) joins federation", joinedCluster.Name, joinedCluster.RestInfo.Server)
		cacheFedEvent(share.CLUSEvFedJoin, msg, reqData.User, reqData.Remote, "", reqData.UserRoles)
		jointCluster.ID = reqData.JointCluster.ID
		go pingJointCluster(_tagJoinPending, "v1/fed/ping_internal", jointCluster, nil, access.NewAdminAccessControl())
		restRespSuccess(w, r, &resp, nil, nil, nil, "Join federation by managed cluster's request")
		return
	} else {
		msg := fmt.Sprintf("Fail to join federation: %s", err.Error())
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFedOperationFailed, msg)
	}
}

func handlerLeaveFedInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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
	body, _ := io.ReadAll(r.Body)
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
			if status, code = removeFromFederation(&joinedCluster, accReadAll); status == http.StatusOK {
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
	defer r.Body.Close()

	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleJoint {
		var req api.RESTFedPingReq
		var resp api.RESTFedPingResp
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err == nil {
			accReadAll := access.NewReaderAccessControl()
			if jointCluster := cacher.GetFedLocalJointCluster(accReadAll); jointCluster.ID != "" {
				if _, err := jwtValidateToken(req.Token, jointCluster.Secret, nil); err == nil {
					if met, result, _ := kv.CheckFedKvVersion("joint", req.FedKvVersion); !met {
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
	defer r.Body.Close()

	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleNone {
		restRespSuccess(w, r, nil, nil, nil, nil, "")
	} else {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

func handlerJointKickedInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

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
	userName := fmt.Sprintf("%s (primary cluster)", login.mainSessionUser)
	cacheFedEvent(share.CLUSEvFedKick, "Dimissed from federation", userName, login.remote, login.id, login.domainRoles)
	evqueue.Flush()
	go leaveFedCleanup(masterCluster.ID, jointCluster.ID, false)

	// after being kicked out of federation, standalone NV reports its usage to CSP
	cache.ConfigCspUsages(false, false, api.FedRoleNone, "")

	restRespSuccess(w, r, nil, acc, login, nil, "Leave federation by primary cluster's request")
}

// share.CLUSLockFedKey lock is owned by caller
func removeFromFederation(joinedCluster *share.CLUSFedJointClusterInfo, acc *access.AccessControl) (int, int) { // (status, code)
	if joinedCluster == nil || joinedCluster.ID == "" {
		return http.StatusBadRequest, api.RESTErrInvalidRequest
	}

	// update kv
	found := false
	deleted := false
	if list := clusHelper.GetFedJointClusterList(); list != nil {
		clusterIDs := list.IDs
		for i, id := range clusterIDs {
			if id == joinedCluster.ID {
				found = true
				clusterIDs[i] = clusterIDs[len(clusterIDs)-1]
				list.IDs = clusterIDs[:len(clusterIDs)-1]
				if err := clusHelper.PutFedJointClusterList(list); err == nil {
					deleted = true
				}
			}
		}
	}
	if deleted || !found {
		clusHelper.DeleteFedJointCluster(joinedCluster.ID)
		_, clientKeyPath, clientCertPath := kv.GetFedTlsKeyCertPath("", joinedCluster.ID)
		os.Remove(clientKeyPath)
		os.Remove(clientCertPath)
		_setFedJointPrivateKey(joinedCluster.ID, nil)
		for j := 0; j < 3; j++ {
			if c := cacher.GetFedJoinedCluster(joinedCluster.ID, acc); c.ID == joinedCluster.ID {
				time.Sleep(time.Second)
			} else {
				return http.StatusOK, 0
			}
		}
	}
	return http.StatusInternalServerError, api.RESTErrFedOperationFailed
}

func handlerDeployFedRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	if !licenseAllowFed(1) {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var req api.RESTDeployFedRulesReq
	body, _ := io.ReadAll(r.Body)
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
				go talkToJointCluster(&jointCluster, http.MethodPost, "v1/fed/command_internal", id, _tagFedSyncPolicy, bodyTo, ch, acc, login, nil)
			} else if jointCluster.Disabled && len(ids) == 1 {
				restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
				return
			}
		}
		oneSuccess := false
		for j := 0; j < deploy; j++ {
			deployResult := <-ch
			resp.Results[deployResult.id] = deployResult.result
			updateClusterState(deployResult.id, "", deployResult.result, nil, acc)
			if deployResult.result == _fedCmdReceived || deployResult.result == _fedClusterSynced {
				oneSuccess = true
			}
		}
		if oneSuccess {
			restRespSuccess(w, r, &resp, acc, login, nil, "Deploy fed rules to joint clusters")
		} else {
			restRespError(w, http.StatusBadRequest, api.RESTErrFedJointUnreachable)
		}
	} else {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

// called by managed clusters
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
		data := share.CLUSFedRulesRevision{Revisions: localRevs, LastUpdateTime: time.Now().UTC()}
		clusHelper.PutFedRulesRevision(nil, &data)
		log.WithFields(log.Fields{"revs": localRevs}).Info("applied fed rules")
	}

	return updated
}

// only called by managed clusters.
// cachedScanResultMD5 is updated & referenced by the following loops in the same polling session
func workFedScanData(cachedScanResultMD5 map[string]map[string]string, respTo *api.RESTPollFedScanDataResp) (uint32, uint32, uint32) {

	var updated uint32
	var deleted uint32
	var delRegs uint32
	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockFedScanDataKey); err != nil {
		return updated, deleted, delRegs
	}
	defer clusHelper.ReleaseLock(lock)

	if respTo.RegistryCfg != nil {
		replaceFedRegistryConfig(respTo.RegistryCfg.Registries)
	}

	// 1. handle deleted images in fed registry/repo or deleted fed registry/repo
	for regName, imageIDs := range respTo.ScanResultData.DeletedScanResults { // registry name : []image id
		if imageIDs == nil {
			// 1-1. "the fed registry/repo is deleted on master cluster" or "scan result of images in the fed registry/repo should not be deployed to managed cluster"
			delete(cachedScanResultMD5, regName)
			delRegs += 1
			clusHelper.DeleteRegistryKeys(regName)
			if regName != common.RegistryFedRepoScanName {
				clusHelper.DeleteRegistry(nil, regName)
			}
		} else if cachedImagesMD5, ok := cachedScanResultMD5[regName]; ok {
			// 1-2. in this fed registry/repo, some images' scan result has been deleted on master cluster
			for _, imageID := range imageIDs {
				if _, ok := cachedImagesMD5[imageID]; ok {
					if err = clusHelper.DeleteRegistryImageSummaryAndReport(regName, imageID, api.FedRoleJoint); err == nil {
						delete(cachedImagesMD5, imageID)
						deleted += 1
					} else {
						log.WithFields(log.Fields{"registry": regName, "image": imageID, "error": err}).Error("Failed to delete")
					}
				}
			}
		}
	}

	// 2. handle new/updated images scan result in fed registry/repo
	for regName, fedScanResults := range respTo.ScanResultData.UpdatedScanResults { // registry name : image id : scan result
		cachedImagesMD5, ok := cachedScanResultMD5[regName] // image id : scan result md5
		if !ok {
			// it's scan result for a new fed registry
			cachedImagesMD5 = make(map[string]string, len(fedScanResults))
		}
		for imageID, scanResult := range fedScanResults {
			if cachedMD5, ok := cachedImagesMD5[imageID]; !ok || cachedMD5 != scanResult.MD5 {
				// it's "scan result for a new image in fed registry/repo" or "different scan result for an image in fed registry/repo"
				if err = clusHelper.PutRegistryImageSummaryAndReport(regName, imageID, api.FedRoleJoint, scanResult.Summary, scanResult.Report); err == nil {
					cachedImagesMD5[imageID] = scanResult.MD5
					updated += 1
				} else {
					log.WithFields(log.Fields{"registry": regName, "image": imageID, "error": err}).Error("Failed to update")
				}
			}
		}
		if updated > 0 {
			cachedScanResultMD5[regName] = cachedImagesMD5
		} else {
			// this fed registry/repo is already up-to-date. remove it from cachedScanResultMD5 so that it won't be synced in this polling session
			delete(cachedScanResultMD5, regName)
		}
	}

	// 3. if all scan results for a fed registry/repo are update-to-date, remove this fed registry/repo from the md5 cache in this polling session
	for _, regName := range respTo.ScanResultData.UpToDateRegs {
		// this fed registry/repo is already up-to-date. remove it from cachedScanResultMD5 so that it won't be synced in this polling session
		delete(cachedScanResultMD5, regName)
	}

	return updated, deleted, delRegs
}

// return true when both maps have same content
func haveSameContent(src, dest map[string]uint64) bool {
	if len(src) != len(dest) {
		return false
	}
	for k, v1 := range src {
		if v2, ok := dest[k]; !ok || v1 != v2 {
			return false
		}
	}

	return true
}

func pollFedRules(forcePulling bool, tryTimes int) bool {
	nvUsage := cacher.GetNvUsage(api.FedRoleJoint)
	doPoll := atomic.CompareAndSwapUint32(&_fedPollOngoing, 0, 1)
	if doPoll {
		defer atomic.StoreUint32(&_fedPollOngoing, 0)

		accReadAll := access.NewReaderAccessControl()
		reqTo := api.RESTPollFedRulesReq{
			FedKvVersion: kv.GetFedKvVer(),
			RestVersion:  kv.GetRestVer(),
			Name:         cacher.GetSystemConfigClusterName(accReadAll),
			CspType:      nvUsage.LocalClusterUsage.CspType, // joint cluster's billing csp type
			Nodes:        nvUsage.LocalClusterUsage.Nodes,
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
				"", "", "", "", nil, bodyTo, false, nil, accReadAll); err == nil {
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
					updateClusterState(jointCluster.ID, "", _fedClusterJoined, nil, accReadAll)
					var cspUsage share.CLUSClusterCspUsage
					cspUsage.CspType, _ = common.GetMappedCspType(&respTo.CspType, nil)
					updateClusterState(masterCluster.ID, masterCluster.ID, _fedClusterConnected, &cspUsage, accReadAll)
					status = _fedSuccess
					fedCfg := cacher.GetFedSettings()
					if respTo.DeployRepoScanData != fedCfg.DeployRepoScanData {
						// fed scan data deployment option is changed on master cluster.
						// delete fed repo scan result stored on managed cluster if fed repo scan data deployment is disabled on master cluster
						clusHelper.DeleteRegistryKeys(common.RegistryFedRepoScanName)
						for i := 0; i < 3; i++ {
							if scanRevs, rev, err := clusHelper.GetFedScanRevisions(); err == nil {
								scanRevs.ScannedRepoRev = 0
								if err = clusHelper.PutFedScanRevisions(&scanRevs, &rev); err == nil {
									break
								}
								time.Sleep(time.Second * 2)
							}
						}
						fedCfg.DeployRepoScanData = respTo.DeployRepoScanData
						clusHelper.PutFedSettings(nil, fedCfg)
					}
					if respTo.Settings != nil {
						var settings api.RESTFedRulesSettings
						if err = json.Unmarshal(respTo.Settings, &settings); err == nil {
							updateClusterState(jointCluster.ID, "", _fedClusterSyncing, nil, accReadAll)
							if workFedRules(&settings, respTo.Revisions, reqTo.Revisions, accReadAll) {
								// if any fed rule is updated, re-send polling request simply for updating joint cluster info on master cluster
								reqTo.JointTicket = jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife)
								reqTo.Revisions = respTo.Revisions
								bodyTo, _ := json.Marshal(&reqTo)
								_, statusCode, _, _ = sendRestRequest("", http.MethodPost, urlStr, "", "", "", "", nil, bodyTo, true, nil, accReadAll)
							}
						}
					}

					go getFedRegScanData(false, fedCfg, respTo.ScanDataRevs, 1)

					updateClusterState(jointCluster.ID, "", _fedClusterJoined, nil, accReadAll)
				} else if respTo.Result == _fedMasterUpgradeRequired {
					updateClusterState(jointCluster.ID, "", _fedJointVersionTooNew, nil, accReadAll)
				} else if respTo.Result == _fedJointUpgradeRequired {
					updateClusterState(jointCluster.ID, "", _fedJointUpgradeRequired, nil, accReadAll)
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
				updateClusterState(jointCluster.ID, "", _fedClusterKicked, nil, accReadAll)
			} else if statusCode == http.StatusNotFound {
				var restErr api.RESTError
				if json.Unmarshal(respData, &restErr) == nil {
					if restErr.Code == api.RESTErrLicenseFail {
						updateClusterState(jointCluster.ID, "", _fedLicenseDisallowed, nil, accReadAll)
					}
				}
			}
		}
		updateClusterState(masterCluster.ID, masterCluster.ID, status, nil, accReadAll)
	}
	return doPoll
}

// called by managed clusters only
// get fed registry/repo scan data
func getFedRegScanData(forcePulling bool, fedCfg share.CLUSFedSettings, masterScanDataRevs api.RESTFedScanDataRevs, tryTimes int) {

	pollScanData := atomic.CompareAndSwapUint32(&_fedScanDataPollOngoing, 0, 1)
	if pollScanData {
		defer atomic.StoreUint32(&_fedScanDataPollOngoing, 0)

		upToDateRegs := utils.NewSet()
		cachedScanDataRevs, restoring := cacher.GetFedScanDataRevisions(true, true)
		if restoring {
			return
		}
		if forcePulling {
			for regName, _ := range cachedScanDataRevs.ScannedRegRevs {
				cachedScanDataRevs.ScannedRegRevs[regName] = 0
			}
			cachedScanDataRevs.ScannedRepoRev = 0
		} else {
			// fed registry scan data is always deployed
			for regName, rev1 := range masterScanDataRevs.ScannedRegRevs {
				if rev2, ok := cachedScanDataRevs.ScannedRegRevs[regName]; ok && rev1 == rev2 {
					upToDateRegs.Add(regName)
				}
			}
			if fedCfg.DeployRepoScanData {
				if masterScanDataRevs.ScannedRepoRev == cachedScanDataRevs.ScannedRepoRev {
					upToDateRegs.Add(common.RegistryFedRepoScanName)
				}
			}
		}
		if (masterScanDataRevs.RegConfigRev != cachedScanDataRevs.RegConfigRev || !haveSameContent(masterScanDataRevs.ScannedRegRevs, cachedScanDataRevs.ScannedRegRevs)) ||
			(fedCfg.DeployRepoScanData && masterScanDataRevs.ScannedRepoRev != cachedScanDataRevs.ScannedRepoRev) {
			// get scan result md5 of the images in fed registry/repo that have different scan data revision(per fed registry/repo) from what master cluster has
			var cachedScanResultMD5 map[string]map[string]string
			if forcePulling {
				cachedScanResultMD5 = make(map[string]map[string]string)
			} else {
				cachedScanResultMD5 = cacher.GetFedScanResultMD5(cachedScanDataRevs, masterScanDataRevs)
			}
			// those fed registry/repo who have the same scan result md5 as master cluster are removed from cachedScanResultMD5 in each pollFedScanData loop

			i := 0
			var updated uint32
			var deleted uint32
			var delRegs uint32
			var updatedTemp uint32
			var deletedTemp uint32
			var delRegsTemp uint32
			var throttleTime int64 = 100
			var interrupt bool
			for throttleTime != 0 && !interrupt {
				// cachedScanDataRevs.RegConfigRev is updated in each pollFedScanData() if there is fed registry setting change on master cluster
				// cachedScanResultMD5/upToDateRegs are updated in each pollFedScanData()/workFedScanData() as well
				throttleTime, updatedTemp, deletedTemp, delRegsTemp, interrupt = pollFedScanData(&cachedScanDataRevs.RegConfigRev, cachedScanResultMD5, upToDateRegs, fedCfg, 1)
				if throttleTime > 0 {
					time.Sleep(time.Duration(throttleTime) * time.Millisecond)
				}
				updated += updatedTemp
				deleted += deletedTemp
				delRegs += delRegsTemp
				i += 1
			}
			if !interrupt {
				// There could be multiple POST(v1/fed/scan_data_internal) requests in a polling session.
				// For ScannedRegRevs/ScannedRepoRev on managed cluster, we update them with the values returned from POST(v1/fed/poll_internal) intentionally.
				// Reason:
				// If a fed registry/repo's scan result is already up-to-date, managed cluster won't sync that fed registry/repo anymore in the same polling session.
				// This is for reducing the POST(v1/fed/scan_data_internal) request payload size.
				// However, the fed registry/repo scanning could happen on the master concurrently when managed cluster polls for scan result.
				// It's possible that right after managed cluster finishes syncing a fed registry/repo,
				//  a new scan result(A) is added on master cluster & ScannedRegRevs/ScannedRepoRev is increased on master as well.
				// we update ScannedRegRevs/ScannedRepoRev on managed cluster with the values returned from POST(v1/fed/poll_internal) so that the next polling session could get scan result(A)
				// Otherwise, when there is no more new scan result on master cluster for a long time(ScannedRegRevs/ScannedRepoRev do not increase for a long time),
				//  it could take managed cluster a long time to get scan result(A)
				scanRevs := share.CLUSFedScanRevisions{
					RegConfigRev:   cachedScanDataRevs.RegConfigRev,
					ScannedRegRevs: masterScanDataRevs.ScannedRegRevs,
					ScannedRepoRev: masterScanDataRevs.ScannedRepoRev,
				}
				clusHelper.PutFedScanRevisions(&scanRevs, nil)
			}
			log.WithFields(log.Fields{"iter": i, "forcePulling": forcePulling, "updated": updated, "deleted": deleted, "delRegs": delRegs, "interrupt": interrupt}).Info()
		}
	}
}

// for the 1st polling request in this polling session,
// cachedScanResultMD5: contains only the images md5 for fed registry/repo that are remembered by managed clusters & have different scan data revision from what master cluster has.
// upToDateRegs: contains names of those fed registry/repo whose scan result is up-to-date
// in each pollFedScanData(), some scan results are returned & their image md5 entries in cachedScanResultMD5 are updated.
//
//	upToDateRegs is updated as well when a fed registry/repo's scab result becomes up-to-date
func pollFedScanData(cachedRegConfigRev *uint64, cachedScanResultMD5 map[string]map[string]string,
	upToDateRegs utils.Set, fedCfg share.CLUSFedSettings, tryTimes int) (int64, uint32, uint32, uint32, bool) {

	var updated uint32
	var deleted uint32
	var delRegs uint32
	var throttleTime int64

	accReadAll := access.NewReaderAccessControl()
	reqTo := api.RESTPollFedScanDataReq{
		FedKvVersion: kv.GetFedKvVer(),
		RestVersion:  kv.GetRestVer(),
		Name:         cacher.GetSystemConfigClusterName(accReadAll),
	}

	masterCluster := cacher.GetFedMasterCluster(accReadAll)
	jointCluster := cacher.GetFedLocalJointCluster(accReadAll)
	if masterCluster.ID == "" || jointCluster.ID == "" {
		return 0, updated, deleted, delRegs, true
	}

	collectedRegs := 0
	reqScanResultMD5 := make(map[string]map[string]string, _maxRegCollectCount)
	ignoreRegs := make([]string, 0, len(cachedScanResultMD5))
	for regName, reqImagesMD5 := range cachedScanResultMD5 {
		if collectedRegs < _maxRegCollectCount {
			reqScanResultMD5[regName] = reqImagesMD5
		} else {
			ignoreRegs = append(ignoreRegs, regName)
		}
		collectedRegs += 1
	}

	reqTo.ID = jointCluster.ID
	reqTo.JointTicket = jwtGenFedTicket(jointCluster.Secret, jwtFedJointTicketLife)
	reqTo.RegConfigRev = *cachedRegConfigRev
	reqTo.UpToDateRegs = upToDateRegs.ToStringSlice()
	reqTo.ScanResultMD5 = reqScanResultMD5
	reqTo.IgnoreRegs = ignoreRegs

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(&reqTo)
	bodyTo := buf.Bytes()
	// call master cluster for polling fed scan data
	var respData []byte
	var statusCode int
	var proxyUsed bool
	var err error = common.ErrObjectAccessDenied
	urlStr := fmt.Sprintf("https://%s:%d/v1/fed/scan_data_internal", masterCluster.RestInfo.Server, masterCluster.RestInfo.Port)
	for i := 0; i < tryTimes; i++ {
		if respData, statusCode, proxyUsed, err = sendRestRequest("", http.MethodPost, urlStr,
			"", "application/gob", reqTo.JointTicket, reqTo.ID, nil, bodyTo, false, nil, accReadAll); err == nil {
			break
		} else {
			time.Sleep(time.Second)
		}
	}
	if err == nil {
		respTo := api.RESTPollFedScanDataResp{}
		buf := bytes.NewBuffer(respData)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&respTo); err == nil {
			if respTo.Result == _fedSuccess { // success
				if respTo.DeployRepoScanData != fedCfg.DeployRepoScanData {
					// fed scan data deployment option is changed on master cluster. Exit this polling session & let the next session do the sync
					return 0, updated, deleted, delRegs, true
				}
				if respTo.RegistryCfg != nil || len(respTo.ScanResultData.UpdatedScanResults) > 0 || len(respTo.ScanResultData.DeletedScanResults) > 0 {
					for _, regName := range respTo.ScanResultData.UpToDateRegs {
						upToDateRegs.Add(regName)
					}
					updated, deleted, delRegs = workFedScanData(cachedScanResultMD5, &respTo)
					if respTo.HasMoreScanResult {
						// this is not the last request in this polling session yet
						throttleTime = respTo.ThrottleTime
					}
					if respTo.RegistryCfg != nil {
						*cachedRegConfigRev = respTo.RegistryCfg.Revision
					}
				}
			} else {
				log.WithFields(log.Fields{"result": respTo.Result, "statusCode": statusCode, "proxyUsed": proxyUsed}).Error("Request failed")
				return 0, updated, deleted, delRegs, true
			}
		}
	} else {
		if m := time.Now().Minute() % 10; m == 0 {
			respErr := api.RESTError{}
			json.Unmarshal(respData, &respErr)
			log.WithFields(log.Fields{"err": err, "msg": respErr, "statusCode": statusCode, "proxyUsed": proxyUsed}).Error("Request failed")
		}
		return 0, updated, deleted, delRegs, true
	}

	return throttleTime, updated, deleted, delRegs, false
}

// handles polling requests on master cluster
func handlerPollFedRulesInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var err error
	var req api.RESTPollFedRulesReq
	body, _ := io.ReadAll(r.Body)
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

	fedCfg := cacher.GetFedSettings()
	resp := api.RESTPollFedRulesResp{
		Result:             _fedSuccess,
		PollInterval:       atomic.LoadUint32(&_fedPollInterval),
		DeployRepoScanData: fedCfg.DeployRepoScanData,
	}
	_, resp.CspType = common.GetMappedCspType(nil, &cctx.CspType) // master cluster's billing csp type
	if kv.IsImporting() {
		// do not give out master's fed policies when master cluster is importing config
		resp.Result = _fedClusterImporting
	} else {
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

		var status int
		if met, result, _ := kv.CheckFedKvVersion("master", req.FedKvVersion); !met {
			resp.Result = result
			status = result
		} else {
			// return fed registry/repo scan data revisions to managed clusters
			resp.ScanDataRevs, _ = cacher.GetFedScanDataRevisions(true, fedCfg.DeployRepoScanData)
			resp.Settings, resp.Revisions, _ = cacher.GetFedRules(req.Revisions, accReadAll)
			if len(resp.Revisions) > 0 {
				status = _fedClusterOutOfSync
			} else {
				status = _fedClusterSynced
			}
		}

		cspType, _ := common.GetMappedCspType(&req.CspType, nil)
		cspUsage := share.CLUSClusterCspUsage{
			CspType: cspType, // joint cluster's billing csp type
			Nodes:   req.Nodes,
		}
		updateClusterState(jointCluster.ID, "", status, &cspUsage, accReadAll)
	}

	restRespSuccess(w, r, &resp, accReadAll, nil, nil, "") // no event log
}

// handles scan data polling requests on master cluster
func handlerPollFedScanDataInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var err error
	var jointCluster share.CLUSFedJointClusterInfo

	jointID := r.Header.Get("X-NV-Joint-ID")
	jointTicket := r.Header.Get("X-NV-Joint-Ticket")
	if jointTicket != "" && jointID != "" {
		// Validate the request is from a valid joint cluster
		jointCluster = cacher.GetFedJoinedCluster(jointID, accReadAll)
		if jointCluster.ID != jointID {
			statusCode := http.StatusBadRequest
			if jointCluster.ID == "" {
				statusCode = http.StatusGone
			}
			restRespError(w, statusCode, api.RESTErrInvalidRequest)
			return
		} else if jointCluster.Disabled {
			restRespError(w, http.StatusNotFound, api.RESTErrInvalidRequest)
			return
		} else {
			if err = jwtValidateFedJoinTicket(jointTicket, jointCluster.Secret); err != nil {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFedOperationFailed, err.Error())
				return
			}
		}
	} else {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	ct := r.Header.Get("Content-Type")
	ce := r.Header.Get("Content-Encoding")

	var req api.RESTPollFedScanDataReq
	body, _ := io.ReadAll(r.Body)
	if ce == "gzip" {
		body = utils.GunzipBytes(body)
	}
	if ct == "application/gob" {
		buf := bytes.NewBuffer(body)
		dec := gob.NewDecoder(buf)
		err = dec.Decode(&req)
	} else {
		err = fmt.Errorf("unexpected content-type: %s", ct)
	}
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var resp api.RESTPollFedScanDataResp
	if kv.IsImporting() {
		// do not give out master's fed registry/repo scan data when master cluster is importing config
		resp.Result = _fedClusterImporting
	} else {
		if met, result, _ := kv.CheckFedKvVersion("master", req.FedKvVersion); !met {
			resp.Result = result
		} else {
			var getFedRegCfg bool
			_, fedRegs := scanner.GetFedRegistryCache(false, true)
			resp, getFedRegCfg = cacher.GetFedScanResult(req.RegConfigRev, req.ScanResultMD5, req.IgnoreRegs, req.UpToDateRegs, fedRegs)
			if getFedRegCfg && resp.RegistryCfg != nil {
				resp.RegistryCfg.Registries, _ = scanner.GetFedRegistryCache(true, false)
			}
			resp.Result = _fedSuccess
		}
	}
	resp.PollInterval = atomic.LoadUint32(&_fedPollInterval)

	restRespSuccess(w, r, &resp, accReadAll, nil, nil, "") // no event log
}

// handles fed command on joint cluster
func handlerFedCommandInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := isFedOpAllowed(api.FedRoleJoint, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var req api.RESTFedInternalCommandReq
	body, _ := io.ReadAll(r.Body)
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
	if met, result, _ := kv.CheckFedKvVersion("joint", req.FedKvVersion); !met {
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
	defer r.Body.Close()

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

func handlerCspSupportInternal(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleMaster, w, r, accReadAll) {
		return
	}

	var err error
	var req api.RESTFedCspSupportReq
	body, _ := io.ReadAll(r.Body)
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

	resp := resource.GetCspConfig()

	restRespSuccess(w, r, &resp, accReadAll, nil, nil, "")
}

func handlerFedHealthCheck(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
		atomic.LoadUint64(&fedRestServerState)
		if fedRestServerState == _fedRestServerRunning_ {
			restRespSuccess(w, r, nil, nil, nil, nil, "")
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

var forbiddenFwUrl = map[string][]string{
	"/v1/fed_auth": []string{http.MethodPost, http.MethodDelete},
}
var forbiddenFwUrlPrefix = map[string][]string{
	"/v1/auth/": []string{http.MethodPost, http.MethodDelete},
}

type tForbiddenFwUrlInfo struct {
	url       string
	urlPrefix string
	urlRegex  *regexp.Regexp
	verbs     []string
}

var forbiddenFwUrlRegex []tForbiddenFwUrlInfo = []tForbiddenFwUrlInfo{
	tForbiddenFwUrlInfo{
		url:       "/v1/auth/.*",
		urlPrefix: "/v1/auth/",
		verbs:     []string{http.MethodPost, http.MethodDelete},
	},
	tForbiddenFwUrlInfo{
		url:       "/v1/user/.*/password",
		urlPrefix: "/v1/user/",
		verbs:     []string{http.MethodPost},
	},
}

func handlerFedClusterForward(w http.ResponseWriter, r *http.Request, ps httprouter.Params, method string) {
	if !licenseAllowFed(1) {
		restRespError(w, http.StatusNotFound, api.RESTErrLicenseFail)
		return
	}
	accCaller, login := isFedOpAllowed(api.FedRoleMaster, _fedReaderRequired, w, r) // reject non-FedAdmin/FedReader & non-PERM_FED login
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
	if accCaller.IsFedReader() || accCaller.HasPermFedForReadOnly() {
		allowedPost := false
		if method == http.MethodPost {
			exportURIs := utils.NewSetFromStringSlice([]string{
				"/v1/file/group",
				"/v1/file/admission",
				"/v1/file/waf",
				"/v1/file/dlp",
				"/v1/file/compliance/profile",
				"/v1/file/vulnerability/profile",
				"/v1/vulasset",
				"/v1/assetvul",
				"/v2/workload",
			})
			if exportURIs.Contains(request) {
				allowedPost = true
			}
		}
		if method == http.MethodGet || (method == http.MethodPatch && request == "/v1/auth") || allowedPost {
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
				for _, urlInfo := range forbiddenFwUrlRegex {
					if strings.HasPrefix(request, urlInfo.urlPrefix) {
						if urlInfo.urlRegex == nil {
							urlInfo.urlRegex, _ = regexp.Compile(urlInfo.url)
						}
						if urlInfo.urlRegex != nil && urlInfo.urlRegex.MatchString(request) {
							for _, verb := range urlInfo.verbs {
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
			}
			if method == http.MethodPost {
				importURIs := utils.NewSetFromStringSlice([]string{
					"/v1/file/config",
					"/v1/file/group/config",
					"/v1/file/admission/config",
					"/v1/file/waf/config",
					"/v1/file/dlp/config",
					"/v1/file/compliance/profile/config",
					"/v1/file/vulnerability/profile/config",
				})
				if importURIs.Contains(request) {
					txnID = r.Header.Get("X-Transaction-ID")
				}
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
	body, _ := io.ReadAll(r.Body)

	var user *share.CLUSUser
	if login.loginType == loginTypeApikey {
		wrapUser, err := wrapApiKeyAsUser(login)
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrRemoteUnauthorized, "Unable to authenticate")
			return
		}
		user = wrapUser
	} else {
		user, _, _ = clusHelper.GetUserRev(login.fullname, acc)
	}

	remoteExport := false

	for _, refreshToken := range []bool{false, true} {
		if token, err := getJointClusterToken(&rc, id, user, refreshToken, acc, login); token != "" {
			gzipped := false
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
			if ce := r.Header.Get("Content-Encoding"); ce == "gzip" {
				gzipped = true
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
				exportURIs := utils.NewSetFromStringSlice([]string{
					"/v1/file/admission",
					"/v1/file/waf",
					"/v1/file/dlp",
					"/v1/file/compliance/profile",
					"/v1/file/vulnerability/profile",
				})
				if exportURIs.Contains(request) {
					remoteExport = true
				}
			}

			if headers, statusCode, data, _, err := sendReqToJointCluster(rc.RestInfo, id, token, methodToUse,
				request, contentType, _tagFedForward, txnID, body, gzipped, _isForward, remoteExport, refreshToken, acc); err != nil {
				if !refreshToken {
					continue
				}
				updateClusterState(id, "", _fedClusterDisconnected, nil, acc)
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
				updateClusterState(id, "", _fedClusterDisconnected, nil, acc)
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoterRequestFail, "Unable to forward request to the cluster")
				return
			}
		}
	}

	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrRemoteUnauthorized, "Unable to authenticate with the cluster")
}

func handlerFedClusterForwardGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	handlerFedClusterForward(w, r, ps, http.MethodGet)
}

func handlerFedClusterForwardPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	handlerFedClusterForward(w, r, ps, http.MethodPost)
}

func handlerFedClusterForwardPatch(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	handlerFedClusterForward(w, r, ps, http.MethodPatch)
}

func handlerFedClusterForwardDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	handlerFedClusterForward(w, r, ps, http.MethodDelete)
}

func wrapApiKeyAsUser(login *loginSession) (*share.CLUSUser, error) {
	apikey, _, err := clusHelper.GetApikeyRev(login.fullname, access.NewReaderAccessControl())
	if err != nil {
		return nil, err
	}

	user := &share.CLUSUser{}
	user.Fullname = apikey.Name
	user.Username = apikey.Name
	user.Locale = apikey.Locale
	user.Timeout = 300
	user.Role = apikey.Role
	login.fullname = login.fullname + " (API Key)"

	return user, nil
}
