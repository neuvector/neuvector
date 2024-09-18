package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type webhookCache struct {
	c        *common.Webhook
	url      string
	useProxy bool
}

const DefaultScannerConfigUpdateTimeout = time.Minute * 5

var systemConfigCache share.CLUSSystemConfig = common.DefaultSystemConfig
var fedSystemConfigCache share.CLUSSystemConfig = share.CLUSSystemConfig{CfgType: share.FederalCfg}
var webhookCacheMap map[string]*webhookCache = make(map[string]*webhookCache, 0)    // Only the enabled webhooks
var fedWebhookCacheMap map[string]*webhookCache = make(map[string]*webhookCache, 0) // Only the enabled webhooks
var syslogger *common.Syslogger

func workloadConfig(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		id := share.CLUSUniconfKey2ID(key)

		var cconf share.CLUSWorkloadConfig
		json.Unmarshal(value, &cconf)

		cacheMutexLock()
		if cache, ok := wlCacheMap[id]; ok {
			cache.config = &cconf
		}
		cacheMutexUnlock()

		log.WithFields(log.Fields{"config": cconf, "id": id}).Debug("")
	}
}

func agentConfig(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		id := share.CLUSUniconfKey2ID(key)

		var cconf share.CLUSAgentConfig
		json.Unmarshal(value, &cconf)

		cacheMutexLock()
		if cache, ok := agentCacheMap[id]; ok {
			cache.config = &cconf
		}
		cacheMutexUnlock()

		log.WithFields(log.Fields{"config": cconf, "id": id}).Debug("")
	}
}

func setControllerDebug(debug []string, debugCPath bool) {
	var hasCPath, hasConn, hasMutex, hasScan, hasCluster, hasK8sMonitor bool
	if len(debug) == 0 && !debugCPath {
		return
	}
	for _, d := range debug {
		switch d {
		case "cpath":
			hasCPath = true
		case "mutex":
			hasMutex = true
		case "conn":
			hasConn = true
		case "scan":
			hasScan = true
		case "cluster":
			hasCluster = true
		case "k8s_monitor":
			hasK8sMonitor = true
		}
	}
	if debugCPath || hasCPath {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if hasConn {
		cctx.ConnLog.Level = log.DebugLevel
	} else {
		cctx.ConnLog.Level = log.InfoLevel
	}
	if hasScan || debugCPath || hasCPath {
		cctx.ScanLog.Level = log.DebugLevel
	} else {
		cctx.ScanLog.Level = log.InfoLevel
	}
	if hasMutex {
		cctx.MutexLog.Level = log.DebugLevel
	} else {
		cctx.MutexLog.Level = log.InfoLevel
	}
	if hasCluster || debugCPath {
		cluster.SetLogLevel(log.DebugLevel)
	} else {
		cluster.SetLogLevel(log.InfoLevel)
	}
	if hasK8sMonitor {
		cctx.K8sResLog.Level = log.DebugLevel
	} else {
		cctx.K8sResLog.Level = log.InfoLevel
	}

	if debugCPath || hasCPath || hasConn || hasMutex ||
		hasScan || hasCluster || hasK8sMonitor {
		common.CtrlLogLevel = share.LogLevel_Debug
	}
}

func controllerConfig(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		id := share.CLUSUniconfKey2ID(key)

		var cconf share.CLUSControllerConfig
		json.Unmarshal(value, &cconf)

		cacheMutexLock()
		if cache, ok := ctrlCacheMap[id]; ok {
			cache.config = &cconf
		} else {
			ctrlCacheMap[id] = initCtrlCache(id)
			ctrlCacheMap[id].config = &cconf
		}
		cacheMutexUnlock()

		if id == localDev.Ctrler.ID {
			// Log level configuration will override the debug config during runtime,
			// because the CLI only allows one command to be run each time.
			if cconf.LogLevel != "" && cconf.LogLevel != share.LogLevel_Debug {
				if cconf.LogLevel != common.CtrlLogLevel {
					log.SetLevel(share.CLUSGetLogLevel(cconf.LogLevel))
					cctx.ConnLog.Level = share.CLUSGetLogLevel(cconf.LogLevel)
					cctx.ScanLog.Level = share.CLUSGetLogLevel(cconf.LogLevel)
					cctx.MutexLog.Level = share.CLUSGetLogLevel(cconf.LogLevel)
					cluster.SetLogLevel(share.CLUSGetLogLevel(cconf.LogLevel))
					cctx.K8sResLog.Level = share.CLUSGetLogLevel(cconf.LogLevel)
					common.CtrlLogLevel = cconf.LogLevel
				}
			} else {
				setControllerDebug(cconf.Debug, false)
			}
		}

		log.WithFields(log.Fields{"config": cconf, "id": id}).Debug("")
	}
}

func uniconfUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	subject := share.CLUSUniconfKey2Subject(key)
	switch subject {
	case "workload":
		workloadConfig(nType, key, value)
	case "agent":
		agentConfig(nType, key, value)
	case "controller":
		controllerConfig(nType, key, value)
	}
}

func uniconfWorkloadDelete(id string, param interface{}) {
	if isLeader() == false {
		return
	}
	cache := param.(*workloadCache)
	hostID := cache.workload.HostID
	key := share.CLUSUniconfWorkloadKey(hostID, id)
	cluster.Delete(key)
}

func uniconfAgentDelete(id string, param interface{}) {
	if isLeader() == false {
		return
	}
	agent := param.(*agentCache).agent
	key := share.CLUSUniconfAgentKey(agent.HostID, id)
	cluster.Delete(key)
}

func uniconfControllerDelete(id string, param interface{}) {
	if isLeader() == false {
		return
	}
	key := share.CLUSUniconfControllerKey(id, id)
	cluster.Delete(key)
}

func getNewServicePolicyMode() (string, string) {
	return systemConfigCache.NewServicePolicyMode, systemConfigCache.NewServiceProfileMode
}

func getNetServiceStatus() bool {
	return systemConfigCache.NetServiceStatus
}

func getNetServicePolicyMode() string {
	return systemConfigCache.NetServicePolicyMode
}

func getDisableNetPolicyStatus() bool {
	return systemConfigCache.DisableNetPolicy
}

func getNewServiceProfileBaseline() string {
	return systemConfigCache.NewServiceProfileBaseline
}

func (m CacheMethod) GetNewServicePolicyMode() (string, string) {
	return getNewServicePolicyMode()
}

func (m CacheMethod) GetNetServiceStatus() bool {
	return getNetServiceStatus()
}

func (m CacheMethod) GetNetServicePolicyMode() string {
	return getNetServicePolicyMode()
}

func (m CacheMethod) GetDisableNetPolicyStatus() bool {
	return getDisableNetPolicyStatus()
}

func (m CacheMethod) GetNewServiceProfileBaseline() string {
	return getNewServiceProfileBaseline()
}

func getUnusedGroupAging() uint8 {
	return systemConfigCache.UnusedGroupAging
}

func (m CacheMethod) GetUnusedGroupAging() uint8 {
	return getUnusedGroupAging()
}

func getModeAutoD2M() (bool, int64) {
	return systemConfigCache.ModeAutoD2M, systemConfigCache.ModeAutoD2MDuration
}

func (m CacheMethod) GetModeAutoD2M() (bool, int64) {
	return getModeAutoD2M()
}

func getModeAutoM2P() (bool, int64) {
	return systemConfigCache.ModeAutoM2P, systemConfigCache.ModeAutoM2PDuration
}

func (m CacheMethod) GetModeAutoM2P() (bool, int64) {
	return getModeAutoM2P()
}

func (m CacheMethod) GetSystemConfig(acc *access.AccessControl) *api.RESTSystemConfig {
	if !acc.Authorize(&systemConfigCache, nil) {
		return nil
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rconf := api.RESTSystemConfig{
		NewServicePolicyMode:      systemConfigCache.NewServicePolicyMode,
		NewServiceProfileMode:     systemConfigCache.NewServiceProfileMode,
		NewServiceProfileBaseline: systemConfigCache.NewServiceProfileBaseline,
		UnusedGroupAging:          systemConfigCache.UnusedGroupAging,
		SyslogLevel:               systemConfigCache.SyslogLevel,
		SyslogIPProto:             systemConfigCache.SyslogIPProto,
		SyslogPort:                systemConfigCache.SyslogPort,
		SyslogEnable:              systemConfigCache.SyslogEnable,
		SyslogCategories:          systemConfigCache.SyslogCategories,
		SyslogInJSON:              systemConfigCache.SyslogInJSON,
		SingleCVEPerSyslog:        systemConfigCache.SingleCVEPerSyslog,
		SyslogCVEInLayers:         systemConfigCache.SyslogCVEInLayers,
		SyslogServerCert:          systemConfigCache.SyslogServerCert,
		OutputEventToLogs:         systemConfigCache.OutputEventToLogs,
		AuthOrder:                 systemConfigCache.AuthOrder,
		AuthByPlatform:            systemConfigCache.AuthByPlatform,
		RancherEP:                 systemConfigCache.RancherEP,
		InternalSubnets:           systemConfigCache.InternalSubnets,
		ClusterName:               systemConfigCache.ClusterName,
		ControllerDebug:           systemConfigCache.ControllerDebug,
		MonitorServiceMesh:        systemConfigCache.TapProxymesh,
		IBMSAEpEnabled:            systemConfigCache.IBMSAConfigNV.EpEnabled,
		IBMSAEpStart:              systemConfigCache.IBMSAConfigNV.EpStart,
		IBMSAEpDashboardURL:       systemConfigCache.IBMSAConfigNV.EpDashboardURL,
		IBMSAEpConnectedAt:        api.RESTTimeString(systemConfigCache.IBMSAConfigNV.EpConnectedAt),
		XffEnabled:                systemConfigCache.XffEnabled,
		NetServiceStatus:          systemConfigCache.NetServiceStatus,
		NetServicePolicyMode:      systemConfigCache.NetServicePolicyMode,
		DisableNetPolicy:          systemConfigCache.DisableNetPolicy,
		DetectUnmanagedWl:         systemConfigCache.DetectUnmanagedWl,
		ModeAutoD2M:               systemConfigCache.ModeAutoD2M,
		ModeAutoD2MDuration:       systemConfigCache.ModeAutoD2MDuration,
		ModeAutoM2P:               systemConfigCache.ModeAutoM2P,
		ModeAutoM2PDuration:       systemConfigCache.ModeAutoM2PDuration,
		NoTelemetryReport:         systemConfigCache.NoTelemetryReport,
		EnableTLSVerification:     systemConfigCache.EnableTLSVerification,
		GlobalCaCerts:             systemConfigCache.GlobalCaCerts,
	}
	if systemConfigCache.SyslogIP != nil {
		rconf.SyslogServer = systemConfigCache.SyslogIP.String()
	} else {
		rconf.SyslogServer = systemConfigCache.SyslogServer
	}
	if systemConfigCache.SyslogIPProto == 0 {
		rconf.SyslogIPProto = 17
	}

	rconf.Webhooks = make([]api.RESTWebhook, len(systemConfigCache.Webhooks))
	for i, wh := range systemConfigCache.Webhooks {
		rconf.Webhooks[i] = api.RESTWebhook{
			Name:     wh.Name,
			Url:      wh.Url,
			Type:     wh.Type,
			Enable:   wh.Enable,
			UseProxy: wh.UseProxy,
			CfgType:  api.CfgTypeUserCreated,
		}
	}

	rconf.RemoteRepositories = make([]api.RESTRemoteRepository, len(systemConfigCache.RemoteRepositories))
	for i, rr := range systemConfigCache.RemoteRepositories {
		repo := api.RESTRemoteRepository{
			Nickname: rr.Nickname,
			Comment:  rr.Comment,
			Provider: rr.Provider,
			Enable:   rr.Enable,
		}
		if rr.Provider == share.RemoteRepositoryProvider_GitHub && rr.GitHubConfiguration != nil {
			repo.GitHubConfiguration = &api.RESTRemoteRepo_GitHubConfig{
				RepositoryOwnerUsername:          rr.GitHubConfiguration.RepositoryOwnerUsername,
				RepositoryName:                   rr.GitHubConfiguration.RepositoryName,
				RepositoryBranchName:             rr.GitHubConfiguration.RepositoryBranchName,
				PersonalAccessToken:              rr.GitHubConfiguration.PersonalAccessToken,
				PersonalAccessTokenCommitterName: rr.GitHubConfiguration.PersonalAccessTokenCommitterName,
				PersonalAccessTokenEmail:         rr.GitHubConfiguration.PersonalAccessTokenEmail,
			}
		}
		rconf.RemoteRepositories[i] = repo
	}

	proxy := systemConfigCache.RegistryHttpProxy
	rconf.RegistryHttpProxyEnable = proxy.Enable
	rconf.RegistryHttpProxy = api.RESTProxy{
		URL:      proxy.URL,
		Username: proxy.Username,
		Password: proxy.Password,
	}
	proxy = systemConfigCache.RegistryHttpsProxy
	rconf.RegistryHttpsProxyEnable = proxy.Enable
	rconf.RegistryHttpsProxy = api.RESTProxy{
		URL:      proxy.URL,
		Username: proxy.Username,
		Password: proxy.Password,
	}

	autoscale := systemConfigCache.ScannerAutoscale
	rconf.ScannerAutoscale = api.RESTSystemConfigAutoscale{
		Strategy:         autoscale.Strategy,
		MinPods:          autoscale.MinPods,
		MaxPods:          autoscale.MaxPods,
		DisabledByOthers: autoscale.DisabledByOthers,
	}

	return &rconf
}

func (m CacheMethod) GetFedSystemConfig(acc *access.AccessControl) *share.CLUSSystemConfig {
	if !acc.Authorize(&fedSystemConfigCache, nil) {
		return nil
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rconf := share.CLUSSystemConfig{
		Webhooks: make([]share.CLUSWebhook, len(fedSystemConfigCache.Webhooks)),
	}
	for i, wh := range fedSystemConfigCache.Webhooks {
		rconf.Webhooks[i] = wh
	}

	return &rconf
}

func (m CacheMethod) GetIBMSAConfig(acc *access.AccessControl) (*api.RESTIBMSAConfig, error) {
	if !acc.Authorize(&systemConfigCache, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rconf := &api.RESTIBMSAConfig{
		AccountID:         systemConfigCache.IBMSAConfig.AccountID,
		APIKey:            systemConfigCache.IBMSAConfig.APIKey,
		ProviderID:        systemConfigCache.IBMSAConfig.ProviderID,
		FindingsURL:       systemConfigCache.IBMSAConfig.FindingsURL,
		TokenURL:          systemConfigCache.IBMSAConfig.TokenURL,
		OnboardNoteName:   systemConfigCache.IBMSAOnboardData.NoteName,
		OnboardID:         systemConfigCache.IBMSAOnboardData.ID,
		OnboardProviderID: systemConfigCache.IBMSAOnboardData.ProviderID,
	}

	return rconf, nil
}

func (m CacheMethod) GetIBMSAConfigNV(acc *access.AccessControl) (share.CLUSIBMSAConfigNV, error) {
	if !acc.Authorize(&systemConfigCache, nil) {
		return share.CLUSIBMSAConfigNV{}, common.ErrObjectAccessDenied
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	return systemConfigCache.IBMSAConfigNV, nil
}

func (m CacheMethod) GetSystemConfigClusterName(acc *access.AccessControl) string {
	if !acc.Authorize(&systemConfigCache, nil) {
		return ""
	}

	//cacheMutexRLock() //-> TO CHECK
	//defer cacheMutexRUnlock()

	return systemConfigCache.ClusterName
}

func systemConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug()

	var cfg share.CLUSSystemConfig
	bSchedulePolicy := false
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		json.Unmarshal(value, &cfg)
		log.WithFields(log.Fields{"config": cfg}).Debug()

		if cfg.IBMSAConfigNV.EpEnabled && cfg.IBMSAConfigNV.EpStart == 1 {
			if isLeader() {
				var param interface{} = &cfg.IBMSAConfig
				cctx.StartStopFedPingPollFunc(share.StartPostToIBMSA, 0, param)
			}
		} else {
			// customer explicitly disables IBM SA endpoint
			cctx.StartStopFedPingPollFunc(share.StopPostToIBMSA, 0, nil)
		}
		//if global network policy mode enabled/disabled or mode changes
		//shedule policy calculation
		if cfg.NetServiceStatus != systemConfigCache.NetServiceStatus {
			scheduleIPPolicyCalculation(true)
			scheduleDlpRuleCalculation(true)
		} else if systemConfigCache.NetServiceStatus &&
			cfg.NetServicePolicyMode != systemConfigCache.NetServicePolicyMode {
			scheduleIPPolicyCalculation(true)
			scheduleDlpRuleCalculation(true)
		}
		if cfg.DisableNetPolicy != systemConfigCache.DisableNetPolicy && cfg.DisableNetPolicy == false {
			bSchedulePolicy = true
			scheduleDlpRuleCalculation(true)
		}
		automodeConfigUpdate(cfg, systemConfigCache)

		// Setup default TLS config.

		// If GlobalCaCerts is not empty, create a CertPool and assign it to tls.Config.
		// It will replace the default CertPool which comes from system/container image.
		var pool *x509.CertPool
		if len(cfg.GlobalCaCerts) > 0 {
			pool = x509.NewCertPool()
			for _, cacert := range cfg.GlobalCaCerts {
				if ok := pool.AppendCertsFromPEM([]byte(cacert)); !ok {
					log.WithFields(log.Fields{"cacert": cacert}).Warn("failed to parse ca cert")
				}
			}
		}

		// Use configured proxy if available, otherwise use container runtime's settings
		// Note: at the time of writing, these settings are only available in docker.
		httpProxy := httpclient.ParseProxy(&cfg.RegistryHttpProxy)
		httpsProxy := httpclient.ParseProxy(&cfg.RegistryHttpsProxy)

		// NoProxy is empty for now.
		httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				InsecureSkipVerify: !cfg.EnableTLSVerification,
				RootCAs:            pool,
			},
		}, httpProxy, httpsProxy, "")

		go func() {
			scannerConfigTimeout := DefaultScannerConfigUpdateTimeout
			if envvar := os.Getenv("SCANNER_CONFIG_UPDATE_TIMEOUT"); envvar != "" {
				if v, err := time.ParseDuration(envvar); err == nil {
					scannerConfigTimeout = v
				} else {
					log.WithError(err).Warn("failed to load scannerConfigTimeout")
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), scannerConfigTimeout)
			defer cancel()
			err := rpc.RunTaskForEachScanner(func(client share.ScannerServiceClient) error {
				_, err := client.SetScannerSettings(ctx, &share.ScannerSettings{
					EnableTLSVerification: cfg.EnableTLSVerification,
					CACerts:               strings.Join(cfg.GlobalCaCerts, "\n"),
					HttpProxy:             httpclient.GetHttpProxy(),
					HttpsProxy:            httpclient.GetHttpsProxy(),
					NoProxy:               "",
				})
				if err != nil {
					log.WithError(err).Warn("failed to update scanner settings")
					// Note: grpc-go doesn't support errors.Is().  See https://github.com/grpc/grpc-go/issues/3616
					if strings.HasSuffix(err.Error(), "context canceled") || strings.HasSuffix(err.Error(), "context deadline exceeded") {
						return err
					}
				}
				return nil
			})
			if err != nil {
				log.WithError(err).Warn("failed to run RunTaskForEachScanner")
			}
		}()

	case cluster.ClusterNotifyDelete:
		// Triggered at configuration import
		cfg = common.DefaultSystemConfig
	}

	// Only apply debug flags if they change so we can apply the initial debugCPath flag correctly.
	if !utils.CompareSliceWithoutOrder(systemConfigCache.ControllerDebug, cfg.ControllerDebug) {
		setControllerDebug(cfg.ControllerDebug, false)
	}

	if systemConfigCache.RegistryHttpProxy != cfg.RegistryHttpProxy ||
		systemConfigCache.RegistryHttpsProxy != cfg.RegistryHttpsProxy {
		scan.UpdateProxy(&cfg.RegistryHttpProxy, &cfg.RegistryHttpsProxy)
	}

	var oldSyslogCfg share.CLUSSyslogConfig

	cacheMutexLock()
	oldSyslogCfg = systemConfigCache.CLUSSyslogConfig
	systemConfigCache = cfg
	putInternalIPNetToCluseter(true)
	cacheMutexUnlock()

	if bSchedulePolicy {
		scheduleIPPolicyCalculation(true)
	}
	httpsProxy := cfg.RegistryHttpsProxy
	httpProxy := cfg.RegistryHttpProxy
	var param1 interface{} = &httpsProxy
	var param2 interface{} = &httpProxy
	cctx.RestConfigFunc(share.UpdateProxyInfo, 0, param1, param2)

	webhookCachTemp := make(map[string]*webhookCache, 0)
	for _, h := range systemConfigCache.Webhooks {
		if h.Enable {
			webhookCachTemp[h.Name] = &webhookCache{
				c:        common.NewWebHook(h.Url, h.Type),
				url:      h.Url,
				useProxy: h.UseProxy,
			}
		}
	}
	webhookCacheMap = webhookCachTemp

	syslogMutexLock()
	defer syslogMutexUnlock()

	if systemConfigCache.SyslogEnable || systemConfigCache.OutputEventToLogs {
		if !reflect.DeepEqual(oldSyslogCfg, cfg.CLUSSyslogConfig) {
			if syslogger != nil {
				syslogger.Close()
			}
			syslogger = common.NewSyslogger(&systemConfigCache.CLUSSyslogConfig)
			log.Info("new syslog applied")
		}
	} else if syslogger != nil {
		syslogger.Close()
		syslogger = nil
	}
}

func configIcmpPolicy(ctx *Context) {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	retry := 0
	for retry < 3 {
		if cfg == nil {
			if cfg, rev = clusHelper.GetSystemConfigRev(acc); cfg != nil {
				break
			}
			retry++
		} else {
			break
		}
	}
	if cfg == nil {
		cfg = &common.DefaultSystemConfig
		rev = 0
	}
	cfg.EnableIcmpPolicy = ctx.EnableIcmpPolicy

	retry = 0
	for retry < 3 {
		if err := clusHelper.PutSystemConfigRev(cfg, rev); err != nil {
			retry++
		} else {
			break
		}
	}
}

func configInit() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	systemConfigCache = *cfg
	if systemConfigCache.SyslogEnable || systemConfigCache.OutputEventToLogs {
		syslogger = common.NewSyslogger(&systemConfigCache.CLUSSyslogConfig)
	}
	if localDev.Host.Platform == share.PlatformKubernetes && localDev.Host.Flavor == share.FlavorRancher {
		if cctx.RancherSSO {
			systemConfigCache.AuthByPlatform = true
		}
		if cctx.RancherEP != "" && systemConfigCache.RancherEP == "" {
			if u, err := url.ParseRequestURI(cctx.RancherEP); err == nil {
				cctx.RancherEP = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				systemConfigCache.RancherEP = cctx.RancherEP
			}
		}
		retry := 0
		for retry < 3 {
			if cfg.AuthByPlatform == systemConfigCache.AuthByPlatform && cfg.RancherEP == systemConfigCache.RancherEP {
				break
			}
			cfg.AuthByPlatform = systemConfigCache.AuthByPlatform
			cfg.RancherEP = systemConfigCache.RancherEP
			if err := clusHelper.PutSystemConfigRev(cfg, rev); err != nil {
				if cfg, rev = clusHelper.GetSystemConfigRev(acc); cfg == nil {
					break
				}
				retry++
			} else {
				break
			}
		}
	}
	if cfg.IBMSAConfigNV.EpEnabled && cfg.IBMSAConfigNV.EpStart == 1 {
		var param interface{} = &cfg.IBMSAConfig
		cctx.StartStopFedPingPollFunc(share.StartPostToIBMSA, 0, param)
	}
	setControllerDebug(systemConfigCache.ControllerDebug, cctx.DebugCPath)
	scan.UpdateProxy(&systemConfigCache.RegistryHttpProxy, &systemConfigCache.RegistryHttpsProxy)

	// uniconf key deleted when controller exits, no need to recover it.
}
