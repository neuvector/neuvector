package rest

// #include "../../defs.h"
import "C"

import (
	"bufio"
	"compress/gzip"
	"crypto/md5"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const hostSessionIDBase uint64 = 0x100000000
const multipartConfigName = "configuration"
const importBackupDir = "/etc/neuvector/"

func parseWebUrl(l string) error {
	u, err := url.Parse(l)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "url": l}).Error("Failed parse url")
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("Unsupport schema")
	}
	return nil
}

func usage2REST(r *share.CLUSSystemUsageReport) *api.RESTSystemUsageReport {
	return &api.RESTSystemUsageReport{
		Signature:     r.Signature,
		ReportedTS:    r.ReportedAt.Unix(),
		ReportedAt:    api.RESTTimeString(r.ReportedAt),
		Platform:      r.Platform,
		Hosts:         r.Hosts,
		CPUCores:      r.CPUCores,
		Controllers:   r.Controllers,
		Agents:        r.Agents,
		Scanners:      r.Scanners,
		CVEDBVersion:  r.CVEDBVersion,
		Registries:    r.Registries,
		Domains:       r.Domains,
		RunningPods:   r.RunningPods,
		Groups:        r.Groups,
		MonitorGroups: r.MonitorGroups,
		ProtectGroups: r.ProtectGroups,
		PolicyRules:   r.PolicyRules,
		AdmCtrlRules:  r.AdmCtrlRules,
		RespRules:     r.RespRules,
		CRDRules:      r.CRDRules,
		Clusters:      r.Clusters,
		SLessProjs:    r.SLessProjs,
	}
}

func handlerSystemUsage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&api.RESTSystemUsageReport{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	keys, _ := cluster.GetStoreKeys(share.CLUSCtrlUsageReportStore)
	all := make([]*api.RESTSystemUsageReport, 0, len(keys))
	for _, key := range keys {
		if v, err := cluster.Get(key); err == nil {
			var r share.CLUSSystemUsageReport
			if err = json.Unmarshal(v, &r); err == nil {
				all = append(all, usage2REST(&r))
			}
		}
	}

	// small to big
	sort.Slice(all, func(i, j int) bool { return all[i].ReportedTS < all[j].ReportedTS })

	resp := api.RESTSystemUsageReportData{Usage: all}

	if cfg := cacher.GetSystemConfig(acc); cfg != nil && !cfg.NoTelemetryReport {
		resp.TelemetryStatus = api.RESTTeleStatus{
			TeleFreq:       _teleFreq,
			TeleURL:        _teleNeuvectorURL,
			CurrentVersion: cctx.NvAppFullVersion,
		}

		var nvUpgradeInfo share.CLUSCheckUpgradeInfo
		if value, _ := cluster.Get(share.CLUSTelemetryStore + "controller"); value != nil {
			json.Unmarshal(value, &nvUpgradeInfo)
			if nvUpgradeInfo.MinUpgradeVersion.Version != "" {
				resp.TelemetryStatus.MinUpgradeVersion = api.RESTUpgradeVersionInfo{
					Version:     nvUpgradeInfo.MinUpgradeVersion.Version,
					ReleaseDate: nvUpgradeInfo.MinUpgradeVersion.ReleaseDate,
					Tag:         nvUpgradeInfo.MinUpgradeVersion.Tag,
				}
			}
			if nvUpgradeInfo.MaxUpgradeVersion.Version != "" {
				resp.TelemetryStatus.MaxUpgradeVersion = api.RESTUpgradeVersionInfo{
					Version:     nvUpgradeInfo.MaxUpgradeVersion.Version,
					ReleaseDate: nvUpgradeInfo.MaxUpgradeVersion.ReleaseDate,
					Tag:         nvUpgradeInfo.MaxUpgradeVersion.Tag,
				}
			}
			if !nvUpgradeInfo.LastUploadTime.IsZero() {
				resp.TelemetryStatus.LastTeleUploadTime = api.RESTTimeString(nvUpgradeInfo.LastUploadTime)
			}
		}
	} else {
		resp.TelemetryStatus = api.RESTTeleStatus{}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get system usage report")
}

func handlerDebugSystemStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	store := share.CLUSExpiredTokenStore
	expiredTokenKeys, _ := cluster.GetStoreKeys(store)
	store = share.CLUSScanStateStore
	scanStateKeys, _ := cluster.GetStoreKeys(store)
	store = share.CLUSScanDataStore
	scanDataKeys, _ := cluster.GetStoreKeys(store)

	resp := api.RESTSystemStatsData{
		Stats: &api.RESTSystemStats{
			ExpiredTokens: len(expiredTokenKeys),
			ScanStateKeys: len(scanStateKeys),
			ScanDataKeys:  len(scanDataKeys),
		},
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get system stats")
}

func handlerSystemSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// any user can call this API to get system summary, but only users with global 'config' permission can see non-zero host/controller/agent/scanner counters
	accSysConfig := acc.BoostPermissions(share.PERM_SYSTEM_CONFIG)
	summary := &api.RESTSystemSummary{
		Services:    cacher.GetServiceCount(accSysConfig),
		PolicyRules: cacher.GetPolicyRuleCount(accSysConfig),
	}
	summary.Platform, summary.K8sVersion, summary.OCVersion = cacher.GetPlatform()
	if acc.HasGlobalPermissions(share.PERM_SYSTEM_CONFIG, 0) {
		summary.Hosts = cacher.GetHostCount(acc)
		summary.Domains = cacher.GetDomainCount(acc)
		summary.Controllers = cacher.GetControllerCount(acc)
		summary.Agents = cacher.GetAgentCount(acc, "")
		summary.OfflineAgents = cacher.GetAgentCount(acc, api.StateOffline)
		summary.Scanners, _, _ = cacher.GetScannerCount(acc)
		summary.CompoVersions = cacher.GetComponentVersions(acc)
	}
	summary.Workloads, summary.RunningWorkloads, summary.RunningPods = cacher.GetWorkloadCount(accSysConfig)
	sdb := scanUtils.GetScannerDB()
	summary.CVEDBVersion = sdb.CVEDBVersion
	summary.CVEDBCreateTime = sdb.CVEDBCreateTime
	resp := api.RESTSystemSummaryData{Summary: summary}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get system summary")
}

func handlerSystemGetConfigBase(apiVer string, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var rconf *api.RESTSystemConfig
	var fedConf *api.RESTFedSystemConfig
	scope := restParseQuery(r).pairs[api.QueryScope]
	if scope == share.ScopeFed || scope == share.ScopeAll {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster || fedRole == api.FedRoleJoint {
			if cconf := cacher.GetFedSystemConfig(acc); cconf == nil {
				if scope == share.ScopeFed {
					if login.hasFedPermission() {
						resp := api.RESTSystemConfigData{
							FedConfig: &api.RESTFedSystemConfig{},
						}
						restRespSuccess(w, r, &resp, acc, login, nil, "")
					} else {
						restRespAccessDenied(w, login)
					}
					return
				}
			} else {
				fedConf = &api.RESTFedSystemConfig{
					Webhooks: make([]api.RESTWebhook, len(cconf.Webhooks)),
				}
				for i, wh := range cconf.Webhooks {
					fedConf.Webhooks[i] = api.RESTWebhook{
						Name: wh.Name, Url: wh.Url, Enable: wh.Enable, UseProxy: wh.UseProxy,
						Type: wh.Type, CfgType: api.CfgTypeFederal,
					}
				}
				sort.Slice(fedConf.Webhooks, func(i, j int) bool { return fedConf.Webhooks[i].Name < fedConf.Webhooks[j].Name })
			}
		} else {
			fedConf = &api.RESTFedSystemConfig{Webhooks: make([]api.RESTWebhook, 0)}
		}
	}
	if scope == share.ScopeLocal || scope == share.ScopeAll {
		rconf = cacher.GetSystemConfig(acc)
		if rconf == nil {
			restRespAccessDenied(w, login)
			return
		} else {
			sort.Slice(rconf.Webhooks, func(i, j int) bool { return rconf.Webhooks[i].Name < rconf.Webhooks[j].Name })
			sort.Slice(rconf.RemoteRepositories, func(i, j int) bool {
				return rconf.RemoteRepositories[i].Nickname < rconf.RemoteRepositories[j].Nickname
			})
		}
		if !k8sPlatform && scope == share.ScopeLocal {
			rconf.ScannerAutoscale = api.RESTSystemConfigAutoscale{}
			rconf.ScannerAutoscale.Strategy = api.AutoScaleNA
			rconf.ScannerAutoscale.DisabledByOthers = false
		}
		if rconf.ScannerAutoscale.MinPods == 0 {
			rconf.ScannerAutoscale.MinPods = 1
		}
		if rconf.ScannerAutoscale.MaxPods == 0 {
			rconf.ScannerAutoscale.MaxPods = 1
		}
	}

	resp := &api.RESTSystemConfigData{}
	if scope == share.ScopeFed {
		resp.FedConfig = fedConf
	} else if scope == share.ScopeLocal || scope == share.ScopeAll {
		_, rconf.CspType = common.GetMappedCspType(nil, &cctx.CspType)
		if rconf.CspType == "none" || rconf.CspType == "" {
			if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleJoint {
				masterCluster := cacher.GetFedMasterCluster(acc)
				cached := cacher.GetFedJoinedClusterStatus(masterCluster.ID, acc)
				_, rconf.CspType = common.GetMappedCspType(nil, &cached.CspType)
			}
		}
		if scope == share.ScopeAll && fedConf != nil && len(fedConf.Webhooks) > 0 {
			rconf.Webhooks = append(fedConf.Webhooks, rconf.Webhooks...)
		}
		if apiVer == "v2" {
			respV2 := &api.RESTSystemConfigDataV2{
				Config: &api.RESTSystemConfigV2{
					NewSvc: api.RESTSystemConfigNewSvcV2{
						NewServicePolicyMode:      rconf.NewServicePolicyMode,
						NewServiceProfileMode:     rconf.NewServiceProfileMode,
						NewServiceProfileBaseline: rconf.NewServiceProfileBaseline,
					},
					Syslog: api.RESTSystemConfigSyslogV2{
						SyslogServer:       rconf.SyslogServer,
						SyslogIPProto:      rconf.SyslogIPProto,
						SyslogPort:         rconf.SyslogPort,
						SyslogLevel:        rconf.SyslogLevel,
						SyslogEnable:       rconf.SyslogEnable,
						SyslogCategories:   rconf.SyslogCategories,
						SyslogInJSON:       rconf.SyslogInJSON,
						SingleCVEPerSyslog: rconf.SingleCVEPerSyslog,
						SyslogCVEInLayers:  rconf.SyslogCVEInLayers,
						SyslogServerCert:   rconf.SyslogServerCert,
						OutputEventToLogs:  rconf.OutputEventToLogs,
					},
					Auth: api.RESTSystemConfigAuthV2{
						AuthOrder:      rconf.AuthOrder,
						AuthByPlatform: rconf.AuthByPlatform,
						RancherEP:      rconf.RancherEP,
					},
					Misc: api.RESTSystemConfigMiscV2{
						InternalSubnets:    rconf.InternalSubnets,
						UnusedGroupAging:   rconf.UnusedGroupAging,
						ClusterName:        rconf.ClusterName,
						ControllerDebug:    rconf.ControllerDebug,
						MonitorServiceMesh: rconf.MonitorServiceMesh,
						XffEnabled:         rconf.XffEnabled,
						NoTelemetryReport:  rconf.NoTelemetryReport,
						CspType:            rconf.CspType,
					},
					Webhooks:           rconf.Webhooks,
					RemoteRepositories: rconf.RemoteRepositories,
					Proxy: api.RESTSystemConfigProxyV2{
						RegistryHttpProxyEnable:  rconf.RegistryHttpProxyEnable,
						RegistryHttpsProxyEnable: rconf.RegistryHttpsProxyEnable,
						RegistryHttpProxy:        rconf.RegistryHttpProxy,
						RegistryHttpsProxy:       rconf.RegistryHttpsProxy,
						RegistryHttpProxyCfg: api.RESTProxyConfig{
							URL:      &rconf.RegistryHttpProxy.URL,
							Username: &rconf.RegistryHttpProxy.Username,
							Password: &rconf.RegistryHttpProxy.Password,
						},
						RegistryHttpsProxyCfg: api.RESTProxyConfig{
							URL:      &rconf.RegistryHttpsProxy.URL,
							Username: &rconf.RegistryHttpsProxy.Username,
							Password: &rconf.RegistryHttpsProxy.Password,
						},
					},
					IBMSA: api.RESTSystemConfigIBMSAV2{
						IBMSAEpEnabled:      rconf.IBMSAEpEnabled,
						IBMSAEpStart:        rconf.IBMSAEpStart,
						IBMSAEpDashboardURL: rconf.IBMSAEpDashboardURL,
						IBMSAEpConnectedAt:  rconf.IBMSAEpConnectedAt,
					},
					NetSvc: api.RESTSystemConfigNetSvcV2{
						NetServiceStatus:     rconf.NetServiceStatus,
						NetServicePolicyMode: rconf.NetServicePolicyMode,
						DisableNetPolicy:     rconf.DisableNetPolicy,
						DetectUnmanagedWl:    rconf.DetectUnmanagedWl,
					},
					ModeAuto: api.RESTSystemConfigModeAutoV2{
						ModeAutoD2M:         rconf.ModeAutoD2M,
						ModeAutoD2MDuration: rconf.ModeAutoD2MDuration,
						ModeAutoM2P:         rconf.ModeAutoM2P,
						ModeAutoM2PDuration: rconf.ModeAutoM2PDuration,
					},
					ScannerAutoscale: rconf.ScannerAutoscale,
					TlsCfg: api.RESTSystemConfigTls{
						EnableTLSVerification: rconf.EnableTLSVerification,
						GlobalCaCerts:         rconf.GlobalCaCerts,
					},
				},
			}
			if respV2.Config.ModeAuto.ModeAutoD2MDuration == 0 {
				respV2.Config.ModeAuto.ModeAutoD2MDuration = 3600
			}
			if respV2.Config.ModeAuto.ModeAutoM2PDuration == 0 {
				respV2.Config.ModeAuto.ModeAutoM2PDuration = 3600
			}
			restRespSuccess(w, r, respV2, acc, login, nil, "Get system configuration")
			return
		} else {
			resp.Config = rconf
		}
	}
	restRespSuccess(w, r, resp, acc, login, nil, "Get system configuration")
}

func handlerSystemGetConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerSystemGetConfigBase("v1", w, r, ps)
}

func handlerSystemGetConfigV2(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerSystemGetConfigBase("v2", w, r, ps)
}

func handlerSystemRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	// Authz is done when action is taken, setting service policies.

	body, _ := io.ReadAll(r.Body)

	var req api.RESTSystemRequestData
	err := json.Unmarshal(body, &req)
	if err != nil || req.Request == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := req.Request
	if rc.PolicyMode != nil && *rc.PolicyMode == share.PolicyModeEnforce &&
		!licenseAllowEnforce() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}
	if rc.ProfileMode != nil && *rc.ProfileMode == share.PolicyModeEnforce &&
		!licenseAllowEnforce() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}
	policy_mode := ""
	if rc.PolicyMode != nil {
		switch *rc.PolicyMode {
		case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
		default:
			e := "Invalid policy mode"
			log.WithFields(log.Fields{"policy_mode": *rc.PolicyMode}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
		policy_mode = *rc.PolicyMode
	}
	profile_mode := ""
	if rc.ProfileMode != nil {
		switch *rc.ProfileMode {
		case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
		default:
			e := "Invalid profile mode"
			log.WithFields(log.Fields{"profile_mode": *rc.ProfileMode}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
		profile_mode = *rc.ProfileMode
	}
	if err := setServicePolicyModeAll(policy_mode, profile_mode, acc); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to set policy and  profile mode")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if rc.BaselineProfile != nil {
		blValue := strings.ToLower(*rc.BaselineProfile)
		switch blValue {
		case share.ProfileBasic:
			*rc.BaselineProfile = share.ProfileBasic
		case share.ProfileDefault_UNUSED, share.ProfileShield_UNUSED, share.ProfileZeroDrift:
			*rc.BaselineProfile = share.ProfileZeroDrift
		default:
			log.WithFields(log.Fields{"baseline": *rc.BaselineProfile}).Error("Invalid profile baseline")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		if err := setServiceProcessBaslineAll(*rc.BaselineProfile, acc); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to set process basline option")
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}
	}

	if rc.Unquar != nil {
		var wls []*api.RESTWorkloadBrief
		if rc.Unquar.Group != "" {
			if group, err := cacher.GetGroup(rc.Unquar.Group, api.QueryValueViewPod, false, acc); err == nil {
				wls = group.Members
			} else {
				restRespNotFoundLogAccessDenied(w, login, err)
				return
			}
		} else {
			wls = cacher.GetAllWorkloadsBrief(api.QueryValueViewPod, acc)
		}
		for _, wl := range wls {
			if wl.State != api.WorkloadStateQuarantine {
				continue
			}
			if rc.Unquar.RuleID != 0 &&
				!strings.Contains(wl.QuarReason,
					share.QuarantineReasonEvent("", rc.Unquar.RuleID)) {
				continue
			}

			var hostID string
			if workload, err := cacher.GetWorkload(wl.ID, "", acc); err != nil {
				continue
			} else {
				hostID = workload.HostID
			}

			var cconf share.CLUSWorkloadConfig
			key := share.CLUSUniconfWorkloadKey(hostID, wl.ID)

			// Retrieve from the cluster
			value, rev, _ := cluster.GetRev(key)
			if value != nil {
				json.Unmarshal(value, &cconf)
			} else {
				cconf.Wire = share.WireDefault
			}
			cconf.Quarantine = false
			cconf.QuarReason = ""

			value, _ = json.Marshal(&cconf)
			if err = cluster.PutRev(key, value, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
				restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
				return
			}
		}
	}

	restRespSuccess(w, r, nil, acc, login, &req, "System request")
}

func validateWebhook(h *api.RESTWebhook) (int, error) {
	var msg string
	hasFedPrefix := strings.HasPrefix(h.Name, api.FederalGroupPrefix)
	if h.CfgType == "" {
		h.CfgType = api.CfgTypeUserCreated
	}
	switch h.CfgType {
	case api.CfgTypeUserCreated:
		if hasFedPrefix {
			msg = "Webhook name can't start with: 'fed.'"
		}
	case api.CfgTypeFederal:
		if !hasFedPrefix || h.Name == api.FederalGroupPrefix {
			msg = "Federal webhook name must start with 'fed.' but cannot be just 'fed.'"
		}
	default:
		msg = "Invalid webhook configuration type"
	}
	if msg != "" {
		log.WithFields(log.Fields{"name": h.Name}).Error(msg)
		return api.RESTErrInvalidName, errors.New(msg)
	}

	if !isObjectNameValid(h.Name) {
		log.WithFields(log.Fields{"name": h.Name}).Error("Invalid webhook name")
		return api.RESTErrInvalidName, errors.New("Invalid webhook name")
	}
	if err := parseWebUrl(h.Url); err != nil {
		log.WithFields(log.Fields{"name": h.Name, "url": h.Url, "error": err}).Error("Invalid webhook URL")
		return api.RESTErrInvalidRequest, errors.New("Invalid webhook URL")
	}
	if h.Type != "" && h.Type != api.WebhookTypeSlack && h.Type != api.WebhookTypeJSON && h.Type != api.WebhookTypeTeams {
		log.WithFields(log.Fields{"name": h.Name, "type": h.Type}).Error("Invalid webhook type")
		return api.RESTErrInvalidRequest, errors.New("Invalid webhook type")
	}
	return 0, nil
}

func configWebhooks(rcWebhookUrl *string, rcWebhooks *[]*api.RESTWebhook, cconfWebhooks []share.CLUSWebhook,
	cfgType share.TCfgType, acc *access.AccessControl) ([]share.CLUSWebhook, int, error) {

	// WebhookUrl is kept for backward-compatibility, it will be written into the webhook list
	newWebhooks := make([]share.CLUSWebhook, 0)
	newWebhookNames := utils.NewSet()
	if rcWebhookUrl != nil && *rcWebhookUrl != "" {
		if err := parseWebUrl(*rcWebhookUrl); err != nil {
			log.WithFields(log.Fields{"url": *rcWebhookUrl, "error": err}).Error("Invalid webhook URL")
			return nil, api.RESTErrInvalidRequest, errors.New("Invalid webhook URL")
		}

		newWebhookNames.Add(api.WebhookDefaultName)
		h := share.CLUSWebhook{
			Name: api.WebhookDefaultName, Url: *rcWebhookUrl, Enable: true,
			Type: api.WebhookTypeSlack, UseProxy: false, CfgType: cfgType,
		}
		if !acc.Authorize(&h, nil) {
			return nil, api.RESTErrObjectAccessDenied, common.ErrObjectAccessDenied
		}
		newWebhooks = append(newWebhooks, h)
	}
	if rcWebhooks != nil {
		for _, h := range *rcWebhooks {
			/* shouldn't check this, as upgraded config can be sent in the list after the user modify the setting
			if h.Name == api.WebhookDefaultName {
				log.WithFields(log.Fields{"name": h.Name}).Error("Webhook name is not allowed")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, "Webhook name is not allowed")
				return
			}
			*/
			if h.Name == "" || h.Url == "" {
				log.WithFields(log.Fields{"name": h.Name}).Error("Empty webhook name or URL")
				return nil, api.RESTErrInvalidName, errors.New("Empty webhook name or URL")
			}

			if newWebhookNames.Contains(h.Name) {
				log.WithFields(log.Fields{"name": h.Name}).Error("Duplicate webhook name")
				return nil, api.RESTErrInvalidName, errors.New("Duplicate webhook name")
			}
			if code, err := validateWebhook(h); err != nil {
				return nil, code, err
			}

			newWebhookNames.Add(h.Name)
			newWebhooks = append(newWebhooks, share.CLUSWebhook{
				Name: h.Name, Url: h.Url, Enable: h.Enable, UseProxy: h.UseProxy,
				Type: h.Type, CfgType: cfgType,
			})
		}
	}

	// compare webhook change
	oldWebhookNames := utils.NewSet()
	for _, h := range cconfWebhooks {
		oldWebhookNames.Add(h.Name)
	}
	dels := oldWebhookNames.Difference(newWebhookNames)

	// check if deleted webhook is inuse
	if dels.Cardinality() > 0 {
		var policyName string
		if cfgType == share.UserCreated {
			policyName = share.DefaultPolicyName
		} else if cfgType == share.FederalCfg {
			policyName = share.FedPolicyName
		}
		chrs := clusHelper.GetResponseRuleList(policyName)
		for _, crh := range chrs {
			r, _ := clusHelper.GetResponseRule(policyName, crh.ID)
			if r != nil && len(r.Webhooks) > 0 {
				for _, n := range r.Webhooks {
					if dels.Contains(n) {
						log.WithFields(log.Fields{"name": n, "policy": policyName}).Error("Deleted webhook is inuse")
						return nil, api.RESTErrInvalidRequest, errors.New("Deleted webhook is inuse")
					}
				}
			}
		}
	}

	return newWebhooks, 0, nil
}

func handlerSystemWebhookCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTSystemWebhookConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rwh := rconf.Config

	if rwh.Name == "" || rwh.Url == "" {
		log.WithFields(log.Fields{"name": rwh.Name}).Error("Empty webhook name or URL")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Empty webhook name or URL")
		return
	}

	cwh := share.CLUSWebhook{
		Name:     rwh.Name,
		Url:      rwh.Url,
		Enable:   rwh.Enable,
		UseProxy: rwh.UseProxy,
		Type:     rwh.Type,
		CfgType:  share.UserCreated,
	}
	if rwh.CfgType == api.CfgTypeFederal {
		cwh.CfgType = share.FederalCfg
	}
	if !acc.Authorize(&cwh, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if code, err := validateWebhook(rwh); err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, code, err.Error())
		return
	}

	// Acquire servr lock
	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		var cconf *share.CLUSSystemConfig
		var rev uint64
		// Retrieve from the cluster
		if rwh.CfgType == api.CfgTypeFederal {
			cconf, rev = clusHelper.GetFedSystemConfigRev(acc)
		} else {
			cconf, rev = clusHelper.GetSystemConfigRev(acc)
		}
		if cconf == nil {
			restRespAccessDenied(w, login)
			return
		}

		if !acc.Authorize(cconf, nil) {
			restRespAccessDenied(w, login)
			return
		}

		for i := range cconf.Webhooks {
			if cconf.Webhooks[i].Name == rwh.Name {
				log.WithFields(log.Fields{"name": rwh.Name}).Error("Duplicate webhook name")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Duplicate webhook name")
				return
			}
		}

		cconf.Webhooks = append(cconf.Webhooks, cwh)
		var err error
		if rwh.CfgType == api.CfgTypeFederal {
			err = clusHelper.PutFedSystemConfigRev(cconf, rev)
		} else {
			err = clusHelper.PutSystemConfigRev(cconf, rev)
		}
		if err != nil {
			// Write to cluster
			log.WithFields(log.Fields{"error": err, "rev": rev, "cfgType": cwh.CfgType}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if cwh.CfgType == share.FederalCfg {
		updateFedRulesRevision([]string{share.FedSystemConfigType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Create system webhook")
}

func handlerSystemWebhookConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var scope string
	if scope = restParseQuery(r).pairs[api.QueryScope]; scope == "" {
		scope = share.ScopeLocal
	} else if scope != share.ScopeFed && scope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	wh := share.CLUSWebhook{CfgType: share.UserCreated}
	if scope == share.ScopeFed {
		wh.CfgType = share.FederalCfg
	}
	if !acc.Authorize(&wh, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name := ps.ByName("name")

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTSystemWebhookConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rwh := rconf.Config

	if rwh.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"server": rwh.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if rwh.Name == "" || rwh.Url == "" {
		log.WithFields(log.Fields{"name": rwh.Name}).Error("Empty webhook name or URL")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Empty webhook name or URL")
		return
	}
	if code, err := validateWebhook(rwh); err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, code, err.Error())
		return
	}

	// Acquire servr lock
	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		var cconf *share.CLUSSystemConfig
		var rev uint64
		// Retrieve from the cluster
		if scope == share.ScopeFed {
			cconf, rev = clusHelper.GetFedSystemConfigRev(acc)
		} else {
			cconf, rev = clusHelper.GetSystemConfigRev(acc)
		}
		if cconf == nil {
			restRespAccessDenied(w, login)
			return
		}

		if !acc.Authorize(cconf, nil) {
			restRespAccessDenied(w, login)
			return
		}

		var found bool
		for i := range cconf.Webhooks {
			if cconf.Webhooks[i].Name == rwh.Name {
				cconf.Webhooks[i] = share.CLUSWebhook{
					Name:     rwh.Name,
					Url:      rwh.Url,
					Enable:   rwh.Enable,
					UseProxy: rwh.UseProxy,
					Type:     rwh.Type,
				}
				found = true
				break
			}
		}
		if !found {
			log.WithFields(log.Fields{"name": rwh.Name}).Error("Webhook not found")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Webhook not found")
			return
		}

		// Write to cluster
		var err error
		if scope == share.ScopeFed {
			err = clusHelper.PutFedSystemConfigRev(cconf, rev)
		} else {
			err = clusHelper.PutSystemConfigRev(cconf, rev)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev, "scope": scope}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if scope == share.ScopeFed {
		updateFedRulesRevision([]string{share.FedSystemConfigType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure system webhook")
}

func handlerSystemWebhookDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var scope string
	if scope = restParseQuery(r).pairs[api.QueryScope]; scope == "" {
		scope = share.ScopeLocal
	} else if scope != share.ScopeFed && scope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	policyName := share.DefaultPolicyName
	wh := share.CLUSWebhook{CfgType: share.UserCreated}
	if scope == share.ScopeFed {
		wh.CfgType = share.FederalCfg
		policyName = share.FedPolicyName
	}
	if !acc.Authorize(&wh, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name := ps.ByName("name")

	// Acquire servr lock
	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// check if deleted webhook is inuse
	chrs := clusHelper.GetResponseRuleList(policyName)
	for _, crh := range chrs {
		r, _ := clusHelper.GetResponseRule(policyName, crh.ID)
		if r != nil && len(r.Webhooks) > 0 {
			for _, n := range r.Webhooks {
				if n == name {
					log.WithFields(log.Fields{"name": n, "policyName": policyName}).Error("Deleted webhook is inuse")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Deleted webhook is inuse")
					return
				}
			}
		}
	}

	retry := 0
	for retry < retryClusterMax {
		var cconf *share.CLUSSystemConfig
		var rev uint64
		// Retrieve from the cluster
		if scope == share.ScopeFed {
			cconf, rev = clusHelper.GetFedSystemConfigRev(acc)
		} else {
			cconf, rev = clusHelper.GetSystemConfigRev(acc)
		}
		if cconf == nil {
			restRespAccessDenied(w, login)
			return
		}

		if !acc.Authorize(cconf, nil) {
			restRespAccessDenied(w, login)
			return
		}

		var found bool
		for i := range cconf.Webhooks {
			if cconf.Webhooks[i].Name == name {
				// No retain order. Show API sort the webhook list.
				s := len(cconf.Webhooks)
				cconf.Webhooks[i] = cconf.Webhooks[s-1]
				cconf.Webhooks = cconf.Webhooks[:s-1]
				found = true
				break
			}
		}
		if !found {
			log.WithFields(log.Fields{"name": name}).Error("Webhook not found")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Webhook not found")
			return
		}

		// Write to cluster
		var err error
		if scope == share.ScopeFed {
			err = clusHelper.PutFedSystemConfigRev(cconf, rev)
		} else {
			err = clusHelper.PutSystemConfigRev(cconf, rev)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev, "scope": scope}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if scope == share.ScopeFed {
		updateFedRulesRevision([]string{share.FedSystemConfigType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete system webhook")
}

func verifyCACerts(pemCerts []byte) error {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		_, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	}
	return nil
}

func configSystemConfig(w http.ResponseWriter, acc *access.AccessControl, login *loginSession, caller, scope, platform string,
	rconf *api.RESTSystemConfigConfigData) (bool, error) {

	var rc *api.RESTSystemConfigConfig
	if scope == share.ScopeLocal && rconf.Config != nil {
		rc = rconf.Config
		/*
			if rc.NewServicePolicyMode != nil && *rc.NewServicePolicyMode == share.PolicyModeEnforce &&
				licenseAllowEnforce() == false {
				restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
				return
			}
		*/
		if rc.WebhookUrl != nil {
			*rc.WebhookUrl = strings.TrimSpace(*rc.WebhookUrl)
		}

		// Acquire lock if auth order or webhook is changing
		if rc.AuthOrder != nil || (rc.WebhookUrl != nil && *rc.WebhookUrl != "") || rc.Webhooks != nil || rc.RemoteRepositories != nil {
			lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
			if err != nil {
				restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
				return false, err
			}
			defer clusHelper.ReleaseLock(lock)
		}
	}

	var nc *api.RESTSysNetConfigConfig
	if scope == share.ScopeLocal && rconf.NetConfig != nil {
		nc = rconf.NetConfig
	}

	retry := 0
	kick := false
	for retry < retryClusterMax {
		var cconf *share.CLUSSystemConfig
		var rev uint64
		// Retrieve from the cluster
		if scope == share.ScopeFed {
			cconf, rev = clusHelper.GetFedSystemConfigRev(acc)
		} else {
			cconf, rev = clusHelper.GetSystemConfigRev(acc)
		}
		if cconf == nil {
			restRespAccessDenied(w, login)
			return kick, common.ErrObjectAccessDenied
		}

		if scope == share.ScopeLocal && nc != nil {
			//global network service status
			if nc.NetServiceStatus != nil {
				cconf.NetServiceStatus = *nc.NetServiceStatus
			}

			// global network service policy mode
			if nc.NetServicePolicyMode != nil {
				/*
					if *nc.NetServicePolicyMode == share.PolicyModeEnforce &&
						licenseAllowEnforce() == false {
						restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
						return
					}
				*/
				switch *nc.NetServicePolicyMode {
				case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
					cconf.NetServicePolicyMode = *nc.NetServicePolicyMode
				default:
					e := "Invalid network service policy mode"
					log.WithFields(log.Fields{"net_service_policy_mode": *nc.NetServicePolicyMode}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}
			if nc.DisableNetPolicy != nil {
				cconf.DisableNetPolicy = *nc.DisableNetPolicy
			}
			if nc.DetectUnmanagedWl != nil {
				cconf.DetectUnmanagedWl = *nc.DetectUnmanagedWl
			}
		}

		if scope == share.ScopeLocal && rconf.AtmoConfig != nil {
			if rconf.AtmoConfig.ModeAutoD2MDuration != nil {
				if *rconf.AtmoConfig.ModeAutoD2MDuration < 3600 {
					e := fmt.Sprintf("Invalid D2M automate duration time [%d] (minimum 3600 seconds)", *rconf.AtmoConfig.ModeAutoD2MDuration)
					log.WithFields(log.Fields{"d2m duration": *rconf.AtmoConfig.ModeAutoD2MDuration}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
				if rconf.AtmoConfig.ModeAutoD2M != nil {
					cconf.ModeAutoD2M = *rconf.AtmoConfig.ModeAutoD2M
					cconf.ModeAutoD2MDuration = *rconf.AtmoConfig.ModeAutoD2MDuration
				}
			}

			if rconf.AtmoConfig.ModeAutoM2PDuration != nil {
				if *rconf.AtmoConfig.ModeAutoM2PDuration < 3600 {
					e := fmt.Sprintf("Invalid M2P automate duration time [%d] (minimum 3600 seconds)", *rconf.AtmoConfig.ModeAutoM2PDuration)
					log.WithFields(log.Fields{"m2p duration": *rconf.AtmoConfig.ModeAutoM2PDuration}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
				if rconf.AtmoConfig.ModeAutoM2P != nil {
					cconf.ModeAutoM2P = *rconf.AtmoConfig.ModeAutoM2P
					cconf.ModeAutoM2PDuration = *rconf.AtmoConfig.ModeAutoM2PDuration
				}
			}
		}

		if scope == share.ScopeLocal && rc != nil {
			// Cluster name is read-only if the cluster is in fed
			if rc.ClusterName != nil {
				var newName string
				if *rc.ClusterName == "" {
					newName = common.DefaultSystemConfig.ClusterName
				} else {
					newName = *rc.ClusterName
				}
				allowed := false
				if caller == "configmap" {
					allowed = true
				} else {
					if fedRole := cacher.GetFedMembershipRoleNoAuth(); newName == cconf.ClusterName || fedRole == api.FedRoleNone {
						allowed = true
					} else {
						if newName != cconf.ClusterName && fedRole == api.FedRoleMaster {
							if cacher.GetFedJoinedClusterCount() == 0 {
								allowed = true
							}
						}
					}
				}
				if !allowed {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrOpNotAllowed, "cluster name cannot be changed when in the federation")
					return kick, common.ErrUnsupported
				} else {
					cconf.ClusterName = newName
				}
			}

			// New policy mode
			if rc.NewServicePolicyMode != nil {
				switch *rc.NewServicePolicyMode {
				case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
					cconf.NewServicePolicyMode = *rc.NewServicePolicyMode
				default:
					e := "Invalid new service policy mode"
					log.WithFields(log.Fields{"new_service_policy_mode": *rc.NewServicePolicyMode}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}
			// New profile mode
			if rc.NewServiceProfileMode != nil {
				switch *rc.NewServiceProfileMode {
				case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
					cconf.NewServiceProfileMode = *rc.NewServiceProfileMode
				default:
					e := "Invalid new service profile mode"
					log.WithFields(log.Fields{"new_service_profile_mode": *rc.NewServiceProfileMode}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}
			// New baseline profile setting
			if rc.NewServiceProfileBaseline != nil {
				blValue := strings.ToLower(*rc.NewServiceProfileBaseline)
				switch blValue {
				case share.ProfileBasic:
					cconf.NewServiceProfileBaseline = share.ProfileBasic
				case share.ProfileDefault_UNUSED, share.ProfileShield_UNUSED, share.ProfileZeroDrift:
					cconf.NewServiceProfileBaseline = share.ProfileZeroDrift
				default:
					e := "Invalid new service profile baseline"
					log.WithFields(log.Fields{"new_service_profile_baseline": *rc.NewServiceProfileBaseline}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}

			// Unused Group Aging
			if rc.UnusedGroupAging != nil {
				cconf.UnusedGroupAging = *rc.UnusedGroupAging
				if cconf.UnusedGroupAging > share.UnusedGroupAgingMax {
					e := "Invalid unused group aging time."
					log.WithFields(log.Fields{"unused_group_aging": *rc.UnusedGroupAging}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}

			// Syslog
			if rc.SyslogEnable != nil {
				cconf.SyslogEnable = *rc.SyslogEnable
			}

			if rc.SyslogInJSON != nil {
				cconf.SyslogInJSON = *rc.SyslogInJSON
			}

			if rc.SyslogCategories != nil {
				for _, categories := range *rc.SyslogCategories {
					if categories != api.CategoryEvent && categories != api.CategoryRuntime &&
						categories != api.CategoryAudit {
						e := "Invalid syslog Category"
						log.WithFields(log.Fields{"category": categories}).Error(e)
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
						return kick, errors.New(e)
					}
				}
				cconf.SyslogCategories = *rc.SyslogCategories
			}

			if rc.SyslogServer != nil {
				// Both IP and name are kept in the cluster to support backward compatibility
				if *rc.SyslogServer == "" {
					cconf.SyslogServer = ""
					cconf.SyslogIP = nil
				} else if regIPLoose.MatchString(*rc.SyslogServer) {
					if ip := net.ParseIP(*rc.SyslogServer); ip == nil {
						e := "Invalid syslog IP"
						log.WithFields(log.Fields{"ip": *rc.SyslogServer}).Error(e)
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
						return kick, errors.New(e)
					} else {
						cconf.SyslogIP = ip
						cconf.SyslogServer = ""
					}
				} else {
					cconf.SyslogServer = *rc.SyslogServer
					cconf.SyslogIP = nil
				}
			}

			if rc.SyslogIPProto != nil {
				ipproto := *rc.SyslogIPProto
				if ipproto == 0 {
					cconf.SyslogIPProto = syscall.IPPROTO_UDP
				} else if ipproto != syscall.IPPROTO_UDP && ipproto != syscall.IPPROTO_TCP && ipproto != api.SyslogProtocolTCPTLS {
					e := "Invalid syslog protocol"
					log.WithFields(log.Fields{"protocol": ipproto}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				} else {
					cconf.SyslogIPProto = ipproto
				}
			}

			if rc.SyslogServerCert != nil {
				cconf.SyslogServerCert = *rc.SyslogServerCert
			}
			if cconf.SyslogIPProto == api.SyslogProtocolTCPTLS && (rc.SyslogIPProto != nil || rc.SyslogServerCert != nil) {
				if certErr := validateCertificate(cconf.SyslogServerCert); certErr != nil {
					e := "Invalid syslog server certificate"
					log.WithFields(log.Fields{"error": certErr}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				}
			}

			if rc.SyslogPort != nil {
				if *rc.SyslogPort == 0 {
					cconf.SyslogPort = api.SyslogDefaultUDPPort
				} else {
					cconf.SyslogPort = *rc.SyslogPort
				}
			}

			if rc.SyslogLevel != nil {
				if *rc.SyslogLevel == "" {
					cconf.SyslogLevel = api.LogLevelINFO
				} else {
					if _, ok := common.LevelToPrio(*rc.SyslogLevel); !ok {
						e := "Invalid syslog level"
						log.WithFields(log.Fields{"level": *rc.SyslogLevel}).Error(e)
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
						return kick, errors.New(e)
					}
					cconf.SyslogLevel = *rc.SyslogLevel
				}
			}

			if cconf.SyslogEnable && cconf.SyslogIP == nil && cconf.SyslogServer == "" {
				e := "Syslog address is not configured"
				log.Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return kick, errors.New(e)
			}

			if cconf.SyslogPort == 0 {
				cconf.SyslogPort = api.SyslogDefaultUDPPort
			}
			if cconf.SyslogIPProto == 0 {
				cconf.SyslogIPProto = syscall.IPPROTO_UDP
			}
			if cconf.SyslogLevel == "" {
				cconf.SyslogLevel = api.LogLevelINFO
			}

			// SingleCVEPerSyslog
			if rc.SingleCVEPerSyslog != nil {
				cconf.SingleCVEPerSyslog = *rc.SingleCVEPerSyslog
			}
			if rc.SyslogCVEInLayers != nil {
				cconf.SyslogCVEInLayers = *rc.SyslogCVEInLayers
			}

			if rc.OutputEventToLogs != nil {
				cconf.OutputEventToLogs = *rc.OutputEventToLogs
			}

			// Auth order
			if rc.AuthOrder != nil {
				order := make([]string, 0)
				for _, name := range *rc.AuthOrder {
					if name != api.AuthServerLocal {
						if cs, _, _ := clusHelper.GetServerRev(name, acc); cs == nil {
							e := "Authentication server not found"
							log.WithFields(log.Fields{"name": name}).Error(e)
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrObjectNotFound, e)
							return kick, errors.New(e)
						} else if !isPasswordAuthServer(cs) {
							e := "Not a password authentication server"
							log.WithFields(log.Fields{"name": name}).Error(e)
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
							return kick, errors.New(e)
						}
					}

					order = append(order, name)
				}

				cconf.AuthOrder = order
			}

			if rc.AuthByPlatform != nil {
				if cconf.AuthByPlatform && !*rc.AuthByPlatform {
					kick = true
				}
				cconf.AuthByPlatform = *rc.AuthByPlatform
			}
			if rc.RancherEP != nil {
				if u, err := url.ParseRequestURI(*rc.RancherEP); err != nil {
					e := "Invalid endpoint URL"
					log.WithFields(log.Fields{"url": *rc.RancherEP}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return kick, errors.New(e)
				} else {
					cconf.RancherEP = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				}
			}

			/*
				if rc.InternalSubnets != nil {
					for _, subnet := range *rc.InternalSubnets {
						_, _, err := net.ParseCIDR(subnet)
						if err != nil {
							e := "Invalid internal subnets"
							log.WithFields(log.Fields{"subnets": *rc.InternalSubnets}).Error(e)
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
							return
						}
					}
					cconf.InternalSubnets = *rc.InternalSubnets
				}
			*/

			// webhook
			if (rc.WebhookUrl != nil && *rc.WebhookUrl != "") || rc.Webhooks != nil {
				if webhooks, errCode, err := configWebhooks(rc.WebhookUrl, rc.Webhooks, cconf.Webhooks, share.UserCreated, acc); err != nil {
					restRespErrorMessage(w, http.StatusBadRequest, errCode, err.Error())
					return kick, err
				} else {
					cconf.Webhooks = webhooks
				}
			}

			// remote registories
			if rc.RemoteRepositories != nil {
				if len(*rc.RemoteRepositories) == 0 {
					cconf.RemoteRepositories = make([]share.CLUSRemoteRepository, 0)
				} else {
					rr := (*rc.RemoteRepositories)[0]
					if len(cconf.RemoteRepositories) != 1 {
						cconf.RemoteRepositories = make([]share.CLUSRemoteRepository, 1)
					}
					cr := share.CLUSRemoteRepository{
						Nickname: rr.Nickname,
						Provider: rr.Provider,
						Comment:  rr.Comment,
					}
					if rr.GitHubConfiguration != nil {
						githubCfg := *rr.GitHubConfiguration
						cr.GitHubConfiguration = &share.RemoteRepository_GitHubConfiguration{
							RepositoryOwnerUsername:          githubCfg.RepositoryOwnerUsername,
							RepositoryName:                   githubCfg.RepositoryName,
							RepositoryBranchName:             githubCfg.RepositoryBranchName,
							PersonalAccessToken:              githubCfg.PersonalAccessToken,
							PersonalAccessTokenCommitterName: githubCfg.PersonalAccessTokenCommitterName,
							PersonalAccessTokenEmail:         githubCfg.PersonalAccessTokenEmail,
						}
					}
					if len(*rc.RemoteRepositories) > 1 || !cr.IsValid() {
						err := errors.New("Unsupported remote repository nickname or provider")
						log.WithFields(log.Fields{"err": err}).Error()
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
						return kick, err
					}
					cconf.RemoteRepositories[0] = cr
				}
			}

			// Controller debug
			if rc.ControllerDebug != nil {
				cconf.ControllerDebug = *rc.ControllerDebug
			}
			// proxy mesh status
			if rc.MonitorServiceMesh != nil {
				cconf.TapProxymesh = *rc.MonitorServiceMesh
			}

			//xff status
			if rc.XffEnabled != nil {
				cconf.XffEnabled = *rc.XffEnabled
			}

			// registry proxy.  RegistryHttpProxyCfg will take precedence.
			if rc.RegistryHttpProxyCfg != nil {
				if rc.RegistryHttpProxyCfg.URL != nil {
					if *rc.RegistryHttpProxyCfg.URL != "" {
						if _, err := url.ParseRequestURI(*rc.RegistryHttpProxyCfg.URL); err != nil {
							log.WithFields(log.Fields{"error": err}).Error("Invalid HTTP proxy setting")
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid HTTP proxy setting")
							return kick, err
						}
					}
					cconf.RegistryHttpProxy.URL = *rc.RegistryHttpProxyCfg.URL
				}

				if rc.RegistryHttpProxyCfg.Username != nil {
					cconf.RegistryHttpProxy.Username = *rc.RegistryHttpProxyCfg.Username
				}

				if rc.RegistryHttpProxyCfg.Password != nil {
					cconf.RegistryHttpProxy.Password = *rc.RegistryHttpProxyCfg.Password
				}
			} else {
				if rc.RegistryHttpProxy != nil {
					if rc.RegistryHttpProxy.URL != "" {
						if _, err := url.ParseRequestURI(rc.RegistryHttpProxy.URL); err != nil {
							log.WithFields(log.Fields{"error": err}).Error("Invalid HTTP proxy setting")
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid HTTP proxy setting")
							return kick, err
						}
					}
					cconf.RegistryHttpProxy.URL = rc.RegistryHttpProxy.URL
					cconf.RegistryHttpProxy.Username = rc.RegistryHttpProxy.Username
					cconf.RegistryHttpProxy.Password = rc.RegistryHttpProxy.Password
				}
			}

			if rc.RegistryHttpsProxyCfg != nil {
				if rc.RegistryHttpsProxyCfg.URL != nil {
					if *rc.RegistryHttpsProxyCfg.URL != "" {
						if _, err := url.ParseRequestURI(*rc.RegistryHttpsProxyCfg.URL); err != nil {
							log.WithFields(log.Fields{"error": err}).Error("Invalid HTTP proxy setting")
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid HTTP proxy setting")
							return kick, err
						}
					}
					cconf.RegistryHttpsProxy.URL = *rc.RegistryHttpsProxyCfg.URL
				}

				if rc.RegistryHttpsProxyCfg.Username != nil {
					cconf.RegistryHttpsProxy.Username = *rc.RegistryHttpsProxyCfg.Username
				}

				if rc.RegistryHttpsProxyCfg.Password != nil {
					cconf.RegistryHttpsProxy.Password = *rc.RegistryHttpsProxyCfg.Password
				}
			} else {
				if rc.RegistryHttpsProxy != nil {
					if rc.RegistryHttpsProxy.URL != "" {
						if _, err := url.ParseRequestURI(rc.RegistryHttpsProxy.URL); err != nil {
							log.WithFields(log.Fields{"error": err}).Error("Invalid HTTPS proxy setting")
							restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid HTTPS proxy setting")
							return kick, err
						}
					}
					cconf.RegistryHttpsProxy.URL = rc.RegistryHttpsProxy.URL
					cconf.RegistryHttpsProxy.Username = rc.RegistryHttpsProxy.Username
					cconf.RegistryHttpsProxy.Password = rc.RegistryHttpsProxy.Password
				}
			}

			if rc.RegistryHttpProxyEnable != nil {
				cconf.RegistryHttpProxy.Enable = *rc.RegistryHttpProxyEnable
			}
			if rc.RegistryHttpsProxyEnable != nil {
				cconf.RegistryHttpsProxy.Enable = *rc.RegistryHttpsProxyEnable
			}
			if (cconf.RegistryHttpProxy.Enable && cconf.RegistryHttpProxy.URL == "") ||
				(cconf.RegistryHttpsProxy.Enable && cconf.RegistryHttpsProxy.URL == "") {
				e := "Empty proxy URL"
				log.Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return kick, errors.New(e)
			}

			// IBM SA Endpoint
			if rc.IBMSAEpEnabled != nil {
				if !*rc.IBMSAEpEnabled {
					cconf.IBMSAConfig = share.CLUSIBMSAConfig{}
					cconf.IBMSAOnboardData = share.CLUSIBMSAOnboardData{}
					cconf.IBMSAConfigNV.EpConnectedAt = time.Time{}
				}
				cconf.IBMSAConfigNV.EpEnabled = *rc.IBMSAEpEnabled
				if !cconf.IBMSAConfigNV.EpEnabled {
					cconf.IBMSAConfigNV.EpStart = 0
				}
			}
			if rc.IBMSAEpDashboardURL != nil {
				if *rc.IBMSAEpDashboardURL == _invalidDashboardURL {
					if cconf.IBMSAConfigNV.EpDashboardURL == "" {
						cconf.IBMSAConfigNV.EpDashboardURL = _invalidDashboardURL
					}
				} else {
					cconf.IBMSAConfigNV.EpDashboardURL = *rc.IBMSAEpDashboardURL
				}
			}

			// scanner autoscale
			if platform == share.PlatformKubernetes && rc.ScannerAutoscale != nil {
				autoscale := *rc.ScannerAutoscale
				if autoscale.Strategy != nil || autoscale.MinPods != nil || autoscale.MaxPods != nil {
					invalidValue := false
					strategy := cconf.ScannerAutoscale.Strategy
					min := cconf.ScannerAutoscale.MinPods
					max := cconf.ScannerAutoscale.MaxPods
					if autoscale.MinPods != nil {
						min = *autoscale.MinPods
					}
					if autoscale.MaxPods != nil {
						max = *autoscale.MaxPods
					}
					if max > 128 || max < min || min == 0 {
						if strategy == api.AutoScaleNone && min == 0 && max == 0 {
							// allow this in fresh deployment
						} else {
							invalidValue = true
						}
					}
					if !invalidValue && autoscale.Strategy != nil {
						if strategy == api.AutoScaleNone && *autoscale.Strategy != strategy {
							// someone tries to enable autoscaling
							errs, _ := resource.VerifyNvRbacRoleBindings([]string{resource.NvAdminRoleBinding}, false, true)
							if len(errs) > 0 {
								errs, _ = resource.VerifyNvRbacRoleBindings([]string{resource.NvScannerRoleBinding}, false, true)
								errs2, _ := resource.VerifyNvRbacRoles([]string{resource.NvScannerRole}, false)
								errs = append(errs, errs2...)
							}
							if len(errs) > 0 {
								msg := strings.Join(errs, "<p>")
								restRespErrorMessage(w, http.StatusNotFound, api.RESTErrK8sNvRBAC, msg)
								return kick, fmt.Errorf("%s", msg)
							}
							if min == 0 {
								min = 3
							}
							if max == 0 {
								max = 3
							}
							// always reset DisabledByOthers when user intentionally enable autoscale
							cconf.ScannerAutoscale.DisabledByOthers = false
						}
						strategy = *autoscale.Strategy
						allowed := utils.NewSet(api.AutoScaleNone, api.AutoScaleImmediate, api.AutoScaleDelayed)
						if !allowed.Contains(strategy) {
							invalidValue = true
						}
					}
					if invalidValue {
						e := "Invalid autoscale value"
						log.Error(e)
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
						return kick, errors.New(e)
					}
					cconf.ScannerAutoscale.Strategy = strategy
					cconf.ScannerAutoscale.MinPods = min
					cconf.ScannerAutoscale.MaxPods = max
				}
			}

			// telemetry report
			if rc.NoTelemetryReport != nil {
				cconf.NoTelemetryReport = *rc.NoTelemetryReport
			}

			if rc.EnableTLSVerification != nil {
				cconf.EnableTLSVerification = *rc.EnableTLSVerification
			}

			if rc.GlobalCaCerts != nil {
				for _, cacert := range *rc.GlobalCaCerts {
					if err := verifyCACerts([]byte(cacert)); err != nil {
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
						return kick, err
					}
				}
				cconf.GlobalCaCerts = *rc.GlobalCaCerts
			}
		} else if scope == share.ScopeFed && rconf.FedConfig != nil {
			// webhook for fed system config
			if rconf.FedConfig.Webhooks != nil {
				if webhooks, errCode, err := configWebhooks(nil, rconf.FedConfig.Webhooks, cconf.Webhooks, share.FederalCfg, acc); err != nil {
					restRespErrorMessage(w, http.StatusBadRequest, errCode, err.Error())
					return kick, err
				} else {
					cconf.Webhooks = webhooks
				}
			}
		}
		//---

		if !acc.Authorize(cconf, nil) {
			restRespAccessDenied(w, login)
			return kick, common.ErrObjectAccessDenied
		}

		// Write to cluster
		var err error
		if scope == share.ScopeFed {
			err = clusHelper.PutFedSystemConfigRev(cconf, rev)
		} else {
			err = clusHelper.PutSystemConfigRev(cconf, rev)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev, "scope": scope}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return kick, common.ErrClusterWriteFail
	}

	return kick, nil
}

func handlerSystemConfigBase(apiVer string, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	scope := share.ScopeFed
	dummy := share.CLUSSystemConfig{CfgType: share.FederalCfg}
	var rconf api.RESTSystemConfigConfigData
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &rconf)
	if err == nil && apiVer == "v2" {
		if rconf.ConfigV2 != nil {
			config := &api.RESTSystemConfigConfig{}
			configV2 := rconf.ConfigV2
			if configV2.SvcCfg != nil {
				config.NewServicePolicyMode = configV2.SvcCfg.NewServicePolicyMode
				config.NewServiceProfileMode = configV2.SvcCfg.NewServiceProfileMode
				config.NewServiceProfileBaseline = configV2.SvcCfg.NewServiceProfileBaseline
			}
			if configV2.SyslogCfg != nil {
				config.SyslogServer = configV2.SyslogCfg.SyslogServer
				config.SyslogIPProto = configV2.SyslogCfg.SyslogIPProto
				config.SyslogPort = configV2.SyslogCfg.SyslogPort
				config.SyslogLevel = configV2.SyslogCfg.SyslogLevel
				config.SyslogEnable = configV2.SyslogCfg.SyslogEnable
				config.SyslogCategories = configV2.SyslogCfg.SyslogCategories
				config.SyslogInJSON = configV2.SyslogCfg.SyslogInJSON
				config.SingleCVEPerSyslog = configV2.SyslogCfg.SingleCVEPerSyslog
				config.SyslogCVEInLayers = configV2.SyslogCfg.SyslogCVEInLayers
				config.SyslogServerCert = configV2.SyslogCfg.SyslogServerCert
				config.OutputEventToLogs = configV2.SyslogCfg.OutputEventToLogs
			}
			if configV2.AuthCfg != nil {
				config.AuthOrder = configV2.AuthCfg.AuthOrder
				config.AuthByPlatform = configV2.AuthCfg.AuthByPlatform
				config.RancherEP = configV2.AuthCfg.RancherEP
			}
			if configV2.ProxyCfg != nil {
				config.RegistryHttpProxyEnable = configV2.ProxyCfg.RegistryHttpProxyEnable
				config.RegistryHttpsProxyEnable = configV2.ProxyCfg.RegistryHttpsProxyEnable
				config.RegistryHttpProxy = configV2.ProxyCfg.RegistryHttpProxy
				config.RegistryHttpsProxy = configV2.ProxyCfg.RegistryHttpsProxy
				config.RegistryHttpProxyCfg = configV2.ProxyCfg.RegistryHttpProxyCfg
				config.RegistryHttpsProxyCfg = configV2.ProxyCfg.RegistryHttpsProxyCfg
			}
			if configV2.Webhooks != nil {
				config.Webhooks = configV2.Webhooks
			}
			if configV2.RemoteRepositories != nil {
				config.RemoteRepositories = configV2.RemoteRepositories
			}
			if configV2.IbmsaCfg != nil {
				config.IBMSAEpEnabled = configV2.IbmsaCfg.IBMSAEpEnabled
				config.IBMSAEpDashboardURL = configV2.IbmsaCfg.IBMSAEpDashboardURL
			}
			if configV2.MiscCfg != nil {
				config.UnusedGroupAging = configV2.MiscCfg.UnusedGroupAging
				config.ClusterName = configV2.MiscCfg.ClusterName
				config.ControllerDebug = configV2.MiscCfg.ControllerDebug
				config.MonitorServiceMesh = configV2.MiscCfg.MonitorServiceMesh
				config.XffEnabled = configV2.MiscCfg.XffEnabled
				config.NoTelemetryReport = configV2.MiscCfg.NoTelemetryReport
			}

			if configV2.TlsCfg != nil {
				config.EnableTLSVerification = configV2.TlsCfg.EnableTLSVerification
				config.GlobalCaCerts = configV2.TlsCfg.GlobalCaCerts
			}

			config.ScannerAutoscale = configV2.ScannerAutoscale
			rconf.Config = config
		} else {
			rconf.Config = nil
		}
	}
	if err != nil || (rconf.Config == nil && rconf.FedConfig == nil && rconf.NetConfig == nil && rconf.AtmoConfig == nil) {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	} else if rconf.Config != nil || rconf.NetConfig != nil || rconf.AtmoConfig != nil {
		// rconf.Config takes higher priority than rconf.FedConfig
		scope = share.ScopeLocal
		dummy.CfgType = share.UserCreated
	}
	if !acc.Authorize(&dummy, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if kick, err := configSystemConfig(w, acc, login, "rest", scope, localDev.Host.Platform, &rconf); err == nil {
		if scope == share.ScopeFed {
			updateFedRulesRevision([]string{share.FedSystemConfigType}, acc, login)
		}

		if kick {
			server := global.ORCH.GetAuthServerAlias()
			kickAllLoginSessionsByServer(server)
		}

		restRespSuccess(w, r, nil, acc, login, &rconf, "Configure system settings")
	}
}

func handlerSystemConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerSystemConfigBase("v1", w, r, ps)
}

func handlerSystemConfigV2(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerSystemConfigBase("v2", w, r, ps)
}

func session2REST(s *share.CLUSSession) *api.RESTSession {
	var app, xffapp string
	if s.Application == 0 {
		app = utils.GetPortLink(uint8(s.IPProto), uint16(s.ServerPort))
	} else {
		app = common.AppNameMap[s.Application]
	}
	if s.XffApp != 0 {
		xffapp = common.AppNameMap[s.XffApp]
	}
	id := uint64(s.ID)
	if s.HostMode {
		id += hostSessionIDBase
	}
	return &api.RESTSession{
		ID:             id,
		Workload:       s.Workload,
		EtherType:      uint16(s.EtherType),
		IPProto:        uint8(s.IPProto),
		Application:    app,
		ClientMAC:      net.HardwareAddr(s.ClientMAC).String(),
		ServerMAC:      net.HardwareAddr(s.ServerMAC).String(),
		ClientIP:       net.IP(s.ClientIP).String(),
		ServerIP:       net.IP(s.ServerIP).String(),
		ClientPort:     uint16(s.ClientPort),
		ServerPort:     uint16(s.ServerPort),
		ICMPCode:       uint8(s.ICMPCode),
		ICMPType:       uint8(s.ICMPType),
		ClientState:    common.TCPStateString(uint8(s.ClientState)),
		ServerState:    common.TCPStateString(uint8(s.ServerState)),
		ClientPkts:     s.ClientPkts,
		ServerPkts:     s.ServerPkts,
		ClientBytes:    s.ClientBytes,
		ServerBytes:    s.ServerBytes,
		ClientAsmPkts:  s.ClientAsmPkts,
		ServerAsmPkts:  s.ServerAsmPkts,
		ClientAsmBytes: s.ClientAsmBytes,
		ServerAsmBytes: s.ServerAsmBytes,
		Age:            s.Age,
		Idle:           s.Idle,
		Life:           s.Life,
		Ingress:        s.Ingress,
		Tap:            s.Tap,
		MidStream:      s.Mid,
		PolicyID:       s.PolicyId,
		PolicyAction:   common.PolicyActionString(uint8(s.PolicyAction)),
		XffIP:          net.IP(s.XffIP).String(),
		XffApp:         xffapp,
		XffPort:        uint16(s.XffPort),
	}
}

func handlerSessionList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		resp := api.RESTSessionList{Sessions: make([]*api.RESTSession, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get network session list")
		return
	}

	query := restParseQuery(r)

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var csf share.CLUSFilter

	for _, f := range query.filters {
		if f.tag == api.FilterByID && f.op == api.OPeq {
			id, _ := strconv.ParseUint(f.value, 10, 64)
			csf.ID = uint32(id)
		}
	}

	csf.Workload = wlID
	csf.Start = uint32(query.start)
	if query.limit <= 0 {
		csf.Limit = 0
	} else {
		csf.Limit = uint32(query.limit)
	}

	sessions, err := rpc.GetSessionList(agentID, &csf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	resp := api.RESTSessionList{Sessions: make([]*api.RESTSession, 0)}
	for _, s := range sessions {
		resp.Sessions = append(resp.Sessions, session2REST(s))
	}

	log.WithFields(log.Fields{"entries": len(resp.Sessions)}).Debug()
	restRespSuccess(w, r, &resp, acc, login, nil, "Get network session list")
}

func handlerSessionSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)

	agentID, err := getAgentFromFilter(query.filters, acc)
	if err != nil {
		if err == restErrNeedAgentFilter {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrNotEnoughFilter, err.Error())
		} else {
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, err.Error())
		}
		return
	}

	count, err := rpc.GetSessionCounter(agentID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	resp := api.RESTSessionSummaryData{
		Summary: &api.RESTSessionSummary{
			CurSessions:     count.CurSessions,
			CurTCPSessions:  count.CurTCPSessions,
			CurUDPSessions:  count.CurUDPSessions,
			CurICMPSessions: count.CurICMPSessions,
			CurIPSessions:   count.CurIPSessions,
		},
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get network session summary")
}

func handlerSessionDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !acc.Authorize(&share.CLUSSession{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	query := restParseQuery(r)

	var csf share.CLUSFilter

	agentID, err := getAgentFromFilter(query.filters, acc)
	if err != nil {
		if err == restErrNeedAgentFilter {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrNotEnoughFilter, err.Error())
		} else {
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, err.Error())
		}
		return
	}

	for _, f := range query.filters {
		if f.tag == api.FilterByID && f.op == api.OPeq {
			id, _ := strconv.ParseUint(f.value, 10, 64)
			csf.ID = uint32(id)
		}
	}

	err = rpc.ClearSession(agentID, &csf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete network session")
}

func meter2REST(m *share.CLUSMeter) *api.RESTMeter {
	var mType string

	switch m.MeterID {
	case C.METER_ID_SYN_FLOOD:
		mType = api.MeterTypeSYNFlood
	case C.METER_ID_ICMP_FLOOD:
		mType = api.MeterTypeICMPFlood
	case C.METER_ID_IP_SRC_SESSION:
		mType = api.MeterTypeIPSrcSessionLimit
	case C.METER_ID_TCP_NODATA:
		mType = api.MeterTypeTCPNoData
	}

	return &api.RESTMeter{
		Type:       mType,
		Workload:   m.Workload,
		PeerIP:     net.IP(m.PeerIP).String(),
		Count:      m.Count,
		SpanCount:  m.LastCount,
		Span:       uint8(m.Span),
		Idle:       uint16(m.Idle),
		Tap:        m.Tap,
		UpperLimit: m.UpperLimit,
		LowerLimit: m.LowerLimit,
	}
}

func handlerMeterList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)

	var cmf share.CLUSFilter

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	cmf.Workload = wlID
	cmf.Start = uint32(query.start)
	if query.limit <= 0 {
		cmf.Limit = 0
	} else {
		cmf.Limit = uint32(query.limit)
	}

	meters, err := rpc.GetMeterList(agentID, &cmf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	resp := api.RESTMeterList{Meters: make([]*api.RESTMeter, 0)}
	for _, m := range meters {
		resp.Meters = append(resp.Meters, meter2REST(m))
	}

	log.WithFields(log.Fields{"entries": len(resp.Meters)}).Debug()
	restRespSuccess(w, r, &resp, acc, login, nil, "Get meter list")
}
func getNvUpgradeInfo() *api.RESTCheckUpgradeInfo {
	var nvUpgradeInfo share.CLUSCheckUpgradeInfo
	if value, _ := cluster.Get(share.CLUSTelemetryStore + "controller"); value != nil {
		json.Unmarshal(value, &nvUpgradeInfo)
	}

	empty := share.CLUSCheckUpgradeVersion{}
	upgradeInfo := &api.RESTCheckUpgradeInfo{}
	if nvUpgradeInfo.MinUpgradeVersion != empty {
		upgradeInfo.MinUpgradeVersion = &api.RESTUpgradeInfo{
			Version:     nvUpgradeInfo.MinUpgradeVersion.Version,
			ReleaseDate: nvUpgradeInfo.MinUpgradeVersion.ReleaseDate,
			Tag:         nvUpgradeInfo.MinUpgradeVersion.Tag,
		}
	}
	if nvUpgradeInfo.MaxUpgradeVersion != empty {
		upgradeInfo.MaxUpgradeVersion = &api.RESTUpgradeInfo{
			Version:     nvUpgradeInfo.MaxUpgradeVersion.Version,
			ReleaseDate: nvUpgradeInfo.MaxUpgradeVersion.ReleaseDate,
			Tag:         nvUpgradeInfo.MaxUpgradeVersion.Tag,
		}
	}
	if nvUpgradeInfo.MinUpgradeVersion == empty && nvUpgradeInfo.MaxUpgradeVersion == empty {
		return nil
	}

	return upgradeInfo
}

func getAcceptableAlerts(acc *access.AccessControl, login *loginSession) ([]string, []string, []string, []string, []string, map[string]string, utils.Set) {
	var clusterRoleErrors, clusterRoleBindingErrors, roleErrors, roleBindingErrors, nvCrdSchemaErrors []string
	if k8sPlatform {
		clusterRoleErrors, clusterRoleBindingErrors, roleErrors, roleBindingErrors =
			resource.VerifyNvK8sRBAC(localDev.Host.Flavor, "", false)
		if checkCrdSchemaFunc != nil {
			var leader bool
			if lead := atomic.LoadUint32(&_isLeader); lead == 1 {
				leader = true
			}
			nvCrdSchemaErrors = checkCrdSchemaFunc(leader, false, false, cctx.CspType)
		}
	}

	var accepted []string
	if user, _, _ := clusHelper.GetUserRev(common.ReservedNvSystemUser, access.NewReaderAccessControl()); user != nil {
		accepted = user.AcceptedAlerts
	}
	if user, _, _ := clusHelper.GetUserRev(login.fullname, acc); user != nil {
		accepted = append(accepted, user.AcceptedAlerts...)
	}
	acceptedAlerts := utils.NewSetFromStringSlice(accepted)

	fedRole := cacher.GetFedMembershipRoleNoAuth()
	otherAlerts := map[string]string{}
	if (fedRole == api.FedRoleMaster && (acc.IsFedReader() || acc.IsFedAdmin() || acc.HasPermFed())) ||
		(fedRole == api.FedRoleJoint && acc.HasGlobalPermissions(share.PERMS_CLUSTER_READ, 0)) {
		// _fedClusterLeft(206), _fedClusterDisconnected(204)
		//disconnectedStates := utils.NewSet(_fedClusterLeft, _fedClusterDisconnected)
		var ids map[string]bool
		if fedRole == api.FedRoleMaster {
			ids = cacher.GetFedJoinedClusterIdMap(acc)
		} else {
			if m := cacher.GetFedMasterCluster(acc); m.ID != "" {
				ids = map[string]bool{
					m.ID: true,
				}
			}
		}
		if len(ids) > 0 {
			for id := range ids {
				s := cacher.GetFedJoinedClusterStatus(id, acc)
				if elapsed := time.Since(s.LastConnectedTime); s.LastConnectedTime.IsZero() || elapsed > (time.Duration(_teleFreq)*time.Minute) {
					key, alert := getFedDisconnectAlert(fedRole, id, acc)
					if !acceptedAlerts.Contains(key) {
						// this alert has not been accepted yet. put it in the response
						otherAlerts[key] = alert
					}
				}
			}
		}
	}

	return clusterRoleErrors, clusterRoleBindingErrors, roleErrors, roleBindingErrors, nvCrdSchemaErrors, otherAlerts, acceptedAlerts
}

func getAcceptedAlerts(acceptedAlerts utils.Set) []string {
	var acceptedManagerAlerts []string
	for _, key := range []string{share.AlertNvNewVerAvailable, share.AlertNvInMultiVersions, share.AlertCveDbTooOld} {
		if acceptedAlerts.Contains(key) {
			// this manager-generated alert key has been accepted. put it in the response
			acceptedManagerAlerts = append(acceptedManagerAlerts, key)
		}
	}

	return acceptedManagerAlerts
}

func getAlertGroup(alerts []string, alertType api.AlertType, acceptedAlerts utils.Set) *api.RESTNvAlertGroup {
	alertGroup := &api.RESTNvAlertGroup{
		Type: alertType,
	}

	if len(alerts) > 0 {
		for _, alert := range alerts {
			b := md5.Sum([]byte(alert))
			key := hex.EncodeToString(b[:])
			if !acceptedAlerts.Contains(key) {
				alertGroup.Data = append(alertGroup.Data, &api.RESTNvAlert{
					ID:      key,
					Message: alert,
				})
			}
		}
	}

	if len(alertGroup.Data) > 0 {
		return alertGroup
	}

	return nil
}

func getInternalCertExpireAlert(certFilePath string) (string, error) {
	expireThresholdDays := []int{30, 90, 180}
	// Check ca certificate expiration
	for _, expireThresholdDay := range expireThresholdDays {
		certExpired, err := IsCertNearExpired(certFilePath, expireThresholdDay)
		if err != nil {
			return "", err
		}
		if !certExpired {
			continue
		}

		var certExpiredMsg string
		if strings.Contains(certFilePath, "ca.cert") {
			certExpiredMsg = fmt.Sprintf("Internal CA certificate will be expired in %d days", expireThresholdDay)
		} else {
			certExpiredMsg = fmt.Sprintf("Internal certificate will be expired in %d days", expireThresholdDay)
		}

		return certExpiredMsg, nil
	}

	return "", nil
}

func handlerSystemGetAlerts(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var resp api.RESTNvAlerts = api.RESTNvAlerts{
		NvUpgradeInfo: &api.RESTCheckUpgradeInfo{},
	}

	// populate neuvector_upgrade_info
	if nvUpgradeInfo := getNvUpgradeInfo(); nvUpgradeInfo != nil {
		resp.NvUpgradeInfo = nvUpgradeInfo
	} else {
		resp.NvUpgradeInfo = nil
	}

	// populate acceptable_alerts
	clusterRoleAlerts, clusterRoleBindingAlerts, roleAlerts, roleBindingAlerts, nvCrdSchemaAlerts, otherAlerts, acceptedAlerts := getAcceptableAlerts(acc, login)
	resp.AcceptableAlerts = &api.RESTNvAcceptableAlerts{}
	if clusterRoleAlertGroup := getAlertGroup(clusterRoleAlerts, api.AlertTypeRBAC, acceptedAlerts); clusterRoleAlertGroup != nil {
		resp.AcceptableAlerts.ClusterRoleAlerts = clusterRoleAlertGroup
	}
	if clusterRoleBindingAlertGroup := getAlertGroup(clusterRoleBindingAlerts, api.AlertTypeRBAC, acceptedAlerts); clusterRoleBindingAlertGroup != nil {
		resp.AcceptableAlerts.ClusterRoleBindingAlerts = clusterRoleBindingAlertGroup
	}
	if RoleAlertGroup := getAlertGroup(roleAlerts, api.AlertTypeRBAC, acceptedAlerts); RoleAlertGroup != nil {
		resp.AcceptableAlerts.RoleAlerts = RoleAlertGroup
	}
	if RoleBindingAlertGroup := getAlertGroup(roleBindingAlerts, api.AlertTypeRBAC, acceptedAlerts); RoleBindingAlertGroup != nil {
		resp.AcceptableAlerts.RoleBindingAlerts = RoleBindingAlertGroup
	}
	if NvCrdSchemaAlertGroup := getAlertGroup(nvCrdSchemaAlerts, api.AlertTypeRBAC, acceptedAlerts); NvCrdSchemaAlertGroup != nil {
		resp.AcceptableAlerts.NvCrdSchemaAlerts = NvCrdSchemaAlertGroup
	}
	if otherAlerts != nil {
		otherAlertGroup := &api.RESTNvAlertGroup{
			Type: api.AlertTypeRBAC,
		}
		for id, msg := range otherAlerts {
			otherAlertGroup.Data = append(otherAlertGroup.Data, &api.RESTNvAlert{
				ID:      id,
				Message: msg,
			})
		}
		if len(otherAlertGroup.Data) > 0 {
			resp.AcceptableAlerts.OtherAlerts = otherAlertGroup
		}
	}
	certAlertGroup := &api.RESTNvAlertGroup{
		Type: api.AlertTypeTlsCertificate,
	}
	internalCaCertFile := path.Join(cluster.InternalCertDir, cluster.InternalCACert)
	if internalCaCertExpireAlert, err := getInternalCertExpireAlert(internalCaCertFile); err == nil && internalCaCertExpireAlert != "" {
		b := md5.Sum([]byte(internalCaCertExpireAlert))
		key := hex.EncodeToString(b[:])
		if !acceptedAlerts.Contains(key) {
			certAlertGroup.Data = append(certAlertGroup.Data, &api.RESTNvAlert{
				ID:      key,
				Message: internalCaCertExpireAlert,
			})
		}
	}
	internalCertFile := path.Join(cluster.InternalCertDir, cluster.InternalCert)
	if internalCertExpireAlert, err := getInternalCertExpireAlert(internalCertFile); err == nil && internalCertExpireAlert != "" {
		b := md5.Sum([]byte(internalCertExpireAlert))
		key := hex.EncodeToString(b[:])
		if !acceptedAlerts.Contains(key) {
			certAlertGroup.Data = append(certAlertGroup.Data, &api.RESTNvAlert{
				ID:      key,
				Message: internalCertExpireAlert,
			})
		}
	}
	if len(certAlertGroup.Data) > 0 {
		resp.AcceptableAlerts.CertificateAlerts = certAlertGroup
	}

	// populate accepted_alerts
	if acceptedManagerAlerts := getAcceptedAlerts(acceptedAlerts); len(acceptedManagerAlerts) > 0 {
		resp.AcceptedAlerts = acceptedManagerAlerts
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get system alerts")
}

func configLog(ev share.TLogEvent, login *loginSession, msg string) {
	clog := share.CLUSEventLog{
		Event:          ev,
		HostID:         localDev.Host.ID,
		HostName:       localDev.Host.Name,
		ControllerID:   localDev.Ctrler.ID,
		ControllerName: localDev.Ctrler.Name,
		ReportedAt:     time.Now().UTC(),
		User:           login.fullname,
		UserRoles:      login.domainRoles,
		UserAddr:       login.remote,
		UserSession:    login.id,
		Msg:            msg,
	}
	evqueue.Append(&clog)
}

func rawExport(w http.ResponseWriter, sections utils.Set) error {
	log.Info()

	// Not to add gzip encoding, so the client won't automaticially unzip data
	// w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(http.StatusOK)

	gzw := gzip.NewWriter(w)
	defer gzw.Close()

	bufw := bufio.NewWriter(gzw)
	defer bufw.Flush()

	return cfgHelper.Export(bufw, sections)
}

func multipartExport(w http.ResponseWriter, sections utils.Set) error {
	log.WithFields(log.Fields{"sections": sections}).Info()

	// TODO: Use chunk encoding to support real streamming
	mpw := multipart.NewWriter(w)
	defer mpw.Close()

	w.Header().Set("Content-Type", "multipart/form-data; boundary="+mpw.Boundary())
	w.WriteHeader(http.StatusOK)

	now := time.Now()
	filename := now.Format("NV200601021504.conf.gz") // Not fixed name, but a format string
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", multipartConfigName, filename))
	h.Set("Content-Type", "application/x-gzip")
	cfgw, _ := mpw.CreatePart(h)

	gzw := gzip.NewWriter(cfgw)
	defer gzw.Close()

	bufw := bufio.NewWriter(gzw)
	defer bufw.Flush()

	return cfgHelper.Export(bufw, sections)
}

func handlerConfigExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Use system config to authorize but it's not exactly system config here
	if !acc.Authorize(&share.CLUSSystemConfig{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if kv.IsImporting() {
		restRespErrorMessage(w, http.StatusConflict, api.RESTErrFailExport, "Another import is ongoing")
		return
	}

	query := restParseQuery(r)

	sections := utils.NewSet()
	if value, ok := query.pairs[api.QueryKeySection]; ok {
		for _, sec := range strings.Split(value, ",") {
			switch sec {
			case api.ConfSectionAll, api.ConfSectionUser, api.ConfSectionPolicy:
				sections.Add(sec)
			default:
				log.WithFields(log.Fields{"section": sec}).Warn("Unsupported configuration section")
			}
		}
	}
	if sections.Cardinality() == 0 {
		sections.Add(api.ConfSectionAll)
	}

	var err error
	if query.raw {
		err = rawExport(w, sections)
	} else {
		err = multipartExport(w, sections)
	}

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in export")
		msg := fmt.Sprintf("Failed to export configurations of section %s.", sections)
		configLog(share.CLUSEvExportFail, login, msg)
	} else {
		log.Info("Export succeeded")
		msg := fmt.Sprintf("Successfully export configurations of section %s.", sections)
		configLog(share.CLUSEvExport, login, msg)
	}
}

func rawImportRead(r *http.Request, tmpfile *os.File) (int, error) {
	log.Info()

	/*
		re := bufio.NewReader(r.Body)
		body, _ := re.Peek(16)
		log.WithFields(log.Fields{"string": string(body[:]), "body": body}).Error("=====================")
	*/
	lines := 0
	gzr, err := gzip.NewReader(r.Body)
	if err != nil {
		e := "Invalid file format"
		log.WithFields(log.Fields{"error": err}).Error(e)
		return lines, errors.New(e)
	}
	defer gzr.Close()

	reader := bufio.NewReader(gzr)
	writer := bufio.NewWriter(tmpfile)
	for {
		data, err := reader.ReadString('\n')
		if err == io.EOF || err != nil {
			break
		} else if data == "\n" || strings.HasPrefix(data, "#") {
			continue
		}
		writer.WriteString(data)
		lines++
	}
	writer.Flush()
	tmpfile.Close()

	return lines, nil
}

func multipartImportRead(r *http.Request, params map[string]string, tmpfile *os.File) (int, error) {
	log.WithFields(log.Fields{"params": params}).Info()

	var writer *bufio.Writer
	mpr := multipart.NewReader(r.Body, params["boundary"])
	lines := 0

	for {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			e := "Invalid multi-part file format"
			log.WithFields(log.Fields{"error": err}).Error(e)
			return lines, errors.New(e)
		}

		if part.FormName() == multipartConfigName {
			gzr, err := gzip.NewReader(part)
			if err != nil {
				e := "Invalid file format"
				log.WithFields(log.Fields{"error": err}).Error(e)
				return lines, errors.New(e)
			}
			defer gzr.Close()

			reader := bufio.NewReader(gzr)
			if writer == nil {
				writer = bufio.NewWriter(tmpfile)
			}
			for {
				data, err := reader.ReadString('\n')
				if err == io.EOF || err != nil {
					break
				}
				writer.WriteString(data)
				lines++
			}
		}
	}
	writer.Flush()
	tmpfile.Close()

	return lines, nil
}

func _preprocessImportBody(body []byte) []byte {
	bomUtf8 := []byte{0xc3, 0xaf, 0xc2, 0xbb, 0xc2, 0xbf}
	if len(body) >= len(bomUtf8) {
		found := true
		for i, b := range bomUtf8 {
			if b != body[i] {
				found = false
				break
			}
		}
		if found {
			body = body[len(bomUtf8):]
		}
	}

	return body
}

func _importHandler(w http.ResponseWriter, r *http.Request, tid, importType, tempFilePrefix string, acc *access.AccessControl, login *loginSession) {
	importRunning := false
	importNoResponse := false
	importTask, _ := clusHelper.GetImportTask()
	if importTask.TID != "" && (importTask.Status == share.IMPORT_PREPARE || importTask.Status == share.IMPORT_RUNNING) {
		importRunning = true
		if !importTask.LastUpdateTime.IsZero() && time.Now().UTC().Sub(importTask.LastUpdateTime).Seconds() > share.IMPORT_QUERY_INTERVAL {
			importNoResponse = true
		}
	}
	resp := api.RESTImportTaskData{
		Data: &api.RESTImportTask{
			TID:            importTask.TID,
			CtrlerID:       importTask.CtrlerID,
			Percentage:     importTask.Percentage,
			LastUpdateTime: importTask.LastUpdateTime,
			TriggeredBy:    importTask.CallerFullname,
			Status:         share.IMPORT_RUNNING,
		},
	}
	if importRunning && !importNoResponse {
		// import is running
		if tid == "" {
			// caller tries to trigger another import
			restRespErrorMessageEx(w, http.StatusConflict, api.RESTErrFailImport, "Another import is ongoing", resp)
		} else if tid != importTask.TID {
			// caller tries to query the status of non-existing import task
			restRespErrorMessageEx(w, http.StatusGone, api.RESTErrInvalidRequest, "Another import is ongoing", resp)
		} else {
			// caller tries to query the status of the running import task
			time.Sleep(time.Second * 2)
			restRespPartial(w, r, &resp)
		}
		return
	} else if tid != "" {
		resp.Data.Status = importTask.Status
		if importRunning && importNoResponse {
			resp.Data.Status = share.IMPORT_NO_RESPONSE
		}
		if importTask.TID == tid {
			if !importRunning && resp.Data.Status != share.IMPORT_DONE {
				status := http.StatusInternalServerError
				if importTask.Status == "Invalid security rule(s)" {
					status = http.StatusBadRequest
				}
				restRespErrorMessageEx(w, status, api.RESTErrFailImport, importTask.Status, resp)
			} else {
				// import is not running and caller tries to query the last import status
				restRespSuccess(w, r, &resp, acc, login, nil, "")
				if importType == share.IMPORT_TYPE_CONFIG {
					if importTask.Status == share.IMPORT_DONE {
						if r, ok := login.domainRoles[access.AccessDomainGlobal]; ok && r == api.UserRoleImportStatus && len(login.domainRoles) == 1 {
							_kickLoginSessionByToken(utils.HashPassword(login.token))
						}
					}
				}
			}
		} else {
			// import is not running, but caller tries to query different import status
			restRespErrorMessageEx(w, http.StatusGone, api.RESTErrInvalidRequest, "Import is not running now", resp)
		}
		return
	}

	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		log.WithFields(log.Fields{"error": err, "importType": importType}).Error("Error in parsing media type")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailImport, err.Error())
		return
	}

	var tmpfile *os.File
	if tmpfile, err = os.CreateTemp(importBackupDir, tempFilePrefix); err == nil {
		importTask := share.CLUSImportTask{
			TID:            utils.GetRandomID(tidLength, ""),
			ImportType:     importType,
			CtrlerID:       localDev.Ctrler.ID,
			TempFilename:   tmpfile.Name(),
			Percentage:     1,
			LastUpdateTime: time.Now().UTC(),
			Status:         share.IMPORT_PREPARE,
			CallerFullname: login.fullname,
			CallerRemote:   login.remote,
			CallerID:       login.id,
		}
		clusHelper.PutImportTask(&importTask)

		lines := 0
		if importType == share.IMPORT_TYPE_CONFIG {
			if strings.HasPrefix(mediaType, "multipart/") {
				lines, err = multipartImportRead(r, params, tmpfile)
			} else {
				lines, err = rawImportRead(r, tmpfile)
			}
		} else {
			body, _ := io.ReadAll(r.Body)
			body = _preprocessImportBody(body)
			var json_data []byte
			json_data, err = yaml.YAMLToJSON(body)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "importType": importType}).Error("Request error")
				restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
				return
			}
			_, err = tmpfile.Write(json_data)
		}
		if err == nil {
			var tempToken string
			if importType == share.IMPORT_TYPE_CONFIG {
				user := &share.CLUSUser{
					Fullname: login.fullname,
					Username: login.fullname,
					Server:   login.server,
				}
				domainRoles := access.DomainRole{access.AccessDomainGlobal: api.UserRoleImportStatus}
				_, tempToken, _ = jwtGenerateToken(user, domainRoles, nil, login.remote, login.mainSessionID, "", nil)
			}

			importTask.TotalLines = lines
			importTask.Percentage = 3
			importTask.LastUpdateTime = time.Now().UTC()
			clusHelper.PutImportTask(&importTask)
			kv.SetImporting(1)
			eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
			switch importType {
			case share.IMPORT_TYPE_CONFIG:
				value := r.Header.Get("X-As-Standalone")
				ignoreFed, _ := strconv.ParseBool(value)
				go cfgHelper.Import(eps, localDev.Ctrler.ID, localDev.Ctrler.ClusterIP, login.domainRoles, importTask,
					tempToken, revertFedRoles, postImportOp, rpc.PauseResumeStoreWatcher, ignoreFed)
			case share.IMPORT_TYPE_GROUP_POLICY:
				go importGroupPolicy(share.ScopeLocal, login.domainRoles, importTask, postImportOp)
			case share.IMPORT_TYPE_ADMCTRL:
				go importAdmCtrl(share.ScopeLocal, login.domainRoles, importTask, postImportOp)
			case share.IMPORT_TYPE_DLP:
				go importDlp(share.ScopeLocal, login.domainRoles, importTask, postImportOp)
			case share.IMPORT_TYPE_WAF:
				go importWaf(share.ScopeLocal, login.domainRoles, importTask, postImportOp)
			case share.IMPORT_TYPE_VULN_PROFILE:
				option := "merge"
				query := restParseQuery(r)
				if query != nil {
					if value, ok := query.pairs["option"]; ok && value == "replace" {
						option = value
					}
				}
				go importVulnProfile(share.ScopeLocal, option, login.domainRoles, importTask, postImportOp)
			case share.IMPORT_TYPE_COMP_PROFILE:
				go importCompProfile(share.ScopeLocal, login.domainRoles, importTask, postImportOp)
			}

			resp := api.RESTImportTaskData{
				Data: &api.RESTImportTask{
					TID:            importTask.TID,
					CtrlerID:       importTask.CtrlerID,
					Percentage:     importTask.Percentage,
					LastUpdateTime: importTask.LastUpdateTime,
					TriggeredBy:    importTask.CallerFullname,
					Status:         share.IMPORT_PREPARE,
					TempToken:      tempToken,
				},
			}

			restRespPartial(w, r, &resp)
			return
		}
	}

	var msgToken string
	importTask.Status = err.Error()
	clusHelper.PutImportTask(&importTask)
	log.WithFields(log.Fields{"error": err, "importType": importType}).Error("Error in import")
	restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrFailImport, err.Error())
	switch importType {
	case share.IMPORT_TYPE_CONFIG:
		msgToken = "configurations"
	case share.IMPORT_TYPE_GROUP_POLICY:
		msgToken = "group policy"
	case share.IMPORT_TYPE_ADMCTRL:
		msgToken = "admission control configurations"
	case share.IMPORT_TYPE_DLP:
		msgToken = "DLP configurations"
	case share.IMPORT_TYPE_WAF:
		msgToken = "WAF configurations"
	case share.IMPORT_TYPE_VULN_PROFILE:
		msgToken = "vulnerability profile"
	case share.IMPORT_TYPE_COMP_PROFILE:
		msgToken = "compliance profile"
	}
	configLog(share.CLUSEvImportFail, login, fmt.Sprintf("Failed to import %s", msgToken))
}

func handlerConfigImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	if (tid == "" && !acc.CanWriteCluster()) || (tid != "" && !acc.HasGlobalPermissions(share.PERM_SYSTEM_CONFIG, 0)) {
		restRespAccessDenied(w, login)
		return
	} else if tid == "" && acc.HasGlobalPermissions(share.PERM_SYSTEM_CONFIG, share.PERM_SYSTEM_CONFIG) {
		fedRole, _ := cacher.GetFedMembershipRole(acc)
		if fedRole == api.FedRoleMaster && !acc.IsFedAdmin() {
			restRespAccessDenied(w, login)
			return
		}
	}

	_importHandler(w, r, tid, share.IMPORT_TYPE_CONFIG, share.PREFIX_IMPORT_CONFIG, acc, login)
}

func postImportOp(err error, importTask share.CLUSImportTask, loginDomainRoles access.DomainRole, tempToken, importType string) {
	defer kv.SetImporting(0)

	var msgToken string
	switch importType {
	case share.IMPORT_TYPE_CONFIG:
		cacher.SyncAdmCtrlStateToK8s(resource.NvAdmSvcName, resource.NvAdmValidatingName, false)
		msgToken = "configurations"
	case share.IMPORT_TYPE_GROUP_POLICY:
		msgToken = "group policy"
	case share.IMPORT_TYPE_ADMCTRL:
		msgToken = "admission control configurations/rules"
	case share.IMPORT_TYPE_DLP:
		msgToken = "DLP rules"
	case share.IMPORT_TYPE_WAF:
		msgToken = "WAF rules"
	case share.IMPORT_TYPE_VULN_PROFILE:
		msgToken = "vulnerability profile"
	case share.IMPORT_TYPE_COMP_PROFILE:
		msgToken = "compliance profile"
	}

	importTask.LastUpdateTime = time.Now().UTC()
	login := &loginSession{
		fullname:    importTask.CallerFullname,
		remote:      importTask.CallerRemote,
		id:          importTask.CallerID,
		domainRoles: loginDomainRoles,
	}
	if err != nil {
		if tempToken != "" {
			invalidateImportStatusToken(tempToken)
		}
		log.WithFields(log.Fields{"error": err, "importType": importType}).Error("Error in import")
		configLog(share.CLUSEvImportFail, login, fmt.Sprintf("Failed to import %s(%s)", msgToken, err.Error()))
		importTask.Status = err.Error()
		clusHelper.PutImportTask(&importTask)
		return
	}

	if importType == share.IMPORT_TYPE_CONFIG {
		//After import, each ctrl need to sync its
		//lprWrapperMap/lprActiveRuleIDs from cluster
		triggerSyncLearnedPolicyImport()
	}
	configLog(share.CLUSEvImport, login, fmt.Sprintf("Successfully import %s", msgToken))

	if importType == share.IMPORT_TYPE_CONFIG {
		nvCrdInfo := []*resource.NvCrdInfo{
			{
				RscType:       resource.RscTypeCrdSecurityRule,
				SpecNamesKind: resource.NvSecurityRuleKind,
				LockKey:       share.CLUSLockPolicyKey,
				KvCrdKind:     resource.NvSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdClusterSecurityRule,
				SpecNamesKind: resource.NvClusterSecurityRuleKind,
				LockKey:       share.CLUSLockPolicyKey,
				KvCrdKind:     resource.NvSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdAdmCtrlSecurityRule,
				SpecNamesKind: resource.NvAdmCtrlSecurityRuleKind,
				LockKey:       share.CLUSLockAdmCtrlKey,
				KvCrdKind:     resource.NvAdmCtrlSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdDlpSecurityRule,
				SpecNamesKind: resource.NvDlpSecurityRuleKind,
				LockKey:       share.CLUSLockPolicyKey,
				KvCrdKind:     resource.NvDlpSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdWafSecurityRule,
				SpecNamesKind: resource.NvWafSecurityRuleKind,
				LockKey:       share.CLUSLockPolicyKey,
				KvCrdKind:     resource.NvWafSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdVulnProfile,
				SpecNamesKind: resource.NvVulnProfileSecurityRuleKind,
				LockKey:       share.CLUSLockVulnKey,
				KvCrdKind:     resource.NvVulnProfileSecurityRuleKind,
			},
			{
				RscType:       resource.RscTypeCrdCompProfile,
				SpecNamesKind: resource.NvCompProfileSecurityRuleKind,
				LockKey:       share.CLUSLockCompKey,
				KvCrdKind:     resource.NvCompProfileSecurityRuleKind,
			},
		}
		for _, crdInfo := range nvCrdInfo {
			CrossCheckCrd(crdInfo.SpecNamesKind, crdInfo.RscType, crdInfo.KvCrdKind, crdInfo.LockKey, true)
		}
	}

	importTask.Percentage = 100
	importTask.Status = share.IMPORT_DONE
	clusHelper.PutImportTask(&importTask)

	if importType == share.IMPORT_TYPE_CONFIG {
		kickAllLoginSessionsByServer("")
	}
}

func triggerSyncLearnedPolicyImport() {
	log.Debug()

	eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
	for _, ep := range eps {
		go func(ClusterIP string, RPCServerPort uint16) {
			if err := rpc.TriggerSyncLearnedPolicy(ClusterIP, RPCServerPort); err != nil {
				log.WithFields(log.Fields{"ClusterIP": ClusterIP, "RPCServerPort": RPCServerPort, "error": err}).Error("sync request error")
			} else {
				log.WithFields(log.Fields{"ClusterIP": ClusterIP, "RPCServerPort": RPCServerPort}).Debug("sync learned policy succeed")
			}
		}(ep.ClusterIP, ep.RPCServerPort)
	}
}

// caller has been verified for federal admin access right
func replaceFedSystemConfig(newCfg *share.CLUSSystemConfig) bool {
	/*
		lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return false
		}
		defer clusHelper.ReleaseLock(lock)
	*/

	// fed system config
	if err := clusHelper.PutFedSystemConfigRev(newCfg, 0); err != nil {
		// Write to cluster
		log.WithFields(log.Fields{"error": err}).Error()
		return false
	}

	return true
}

func validateCertificate(certificate string) error {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return errors.New("Invalid certificate")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("Invalid certificate")
	}

	// No need to check the specific type of public key; relying on x509.ParseCertificate() should be sufficient.
	// Different signature algorithms have different types.
	// if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
	// 	return errors.New("Invalid certificate, certificate doesn't contain a public key")
	// }
	return nil
}

func getFedDisconnectAlert(fedRole, id string, acc *access.AccessControl) (string, string) {
	var alert string
	if fedRole == api.FedRoleMaster {
		clusterInfo := cacher.GetFedJoinedCluster(id, acc)
		alert = fmt.Sprintf("Managed cluster %s is disconnected from primary cluster", clusterInfo.Name)
	} else {
		alert = "This cluster is disconnected from primary cluster"
	}
	b := md5.Sum([]byte(alert))
	key := hex.EncodeToString(b[:])

	return key, alert
}
