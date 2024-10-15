package kv

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const upgradeClusterLockWait = time.Duration(time.Second * 6)
const retryClusterMax = 5

// Return if structure is upgraded and should it be written back to the kv store.
func upgradeUser(user *share.CLUSUser) (bool, bool) {
	var upd bool
	if user.Fullname == "" {
		user.Fullname = utils.MakeUserFullname(user.Server, user.Username)
		if user.Fullname == "" {
			log.WithFields(log.Fields{"user": user}).Error("Invalid user")
		} else {
			upd = true
		}
	}
	if user.RoleDomains == nil {
		user.RoleDomains = make(map[string][]string)
		upd = true
	}
	return upd, upd
}

func upgradeSystemConfig(cfg *share.CLUSSystemConfig) (bool, bool) {
	var upd bool
	if cfg.NewServicePolicyMode == "" {
		cfg.NewServicePolicyMode = common.DefaultSystemConfig.NewServicePolicyMode
		upd = true
	}
	if cfg.NewServiceProfileMode == "" {
		cfg.NewServiceProfileMode = common.DefaultSystemConfig.NewServiceProfileMode
		upd = true
	}
	if cfg.NewServiceProfileBaseline == "" {
		cfg.NewServiceProfileBaseline = common.DefaultSystemConfig.NewServiceProfileBaseline
		upd = true
	} else {
		blValue := strings.ToLower(cfg.NewServiceProfileBaseline)
		if blValue == share.ProfileDefault_UNUSED || blValue == share.ProfileShield_UNUSED {
			blValue = share.ProfileZeroDrift
		}
		if blValue != cfg.NewServiceProfileBaseline {
			cfg.NewServiceProfileBaseline = blValue
			upd = true
		}
	}
	if cfg.ClusterName == "" {
		cfg.ClusterName = common.DefaultSystemConfig.ClusterName
		upd = true
	}

	replaced := false
	cats := make([]string, 0)
	for _, c := range cfg.SyslogCategories {
		if c == api.CategoryViolation || c == api.CategoryIncident || c == api.CategoryThreat {
			if !replaced {
				cats = append(cats, api.CategoryRuntime)
				replaced = true
			}
		} else {
			cats = append(cats, c)
		}
	}
	if replaced {
		cfg.SyslogCategories = cats
		upd = true
	}

	return upd, upd
}

func upgradeServer(server *share.CLUSServer) (bool, bool) {
	var upd bool
	if server.LDAP != nil && server.LDAP.Type == "" {
		server.LDAP.Type = api.ServerLDAPTypeOpenLDAP
		server.LDAP.GroupMemberAttr = api.LDAPGroupMemberAttrOpenLDAP
		upd = true
	} else if server.OIDC != nil && server.OIDC.Scopes == nil {
		server.OIDC.Scopes = auth.DefaultOIDCScopes
		upd = true
	}
	return upd, upd
}

func upgradeGroup(group *share.CLUSGroup) (bool, bool) {
	var upd bool
	if group.Kind == "" {
		if group.Name == api.LearnedExternal {
			group.Kind = share.GroupKindExternal
		} else if strings.HasPrefix(group.Name, api.LearnedSvcGroupPrefix) {
			group.Kind = share.GroupKindIPService
		} else {
			group.Kind = share.GroupKindContainer
			for _, cr := range group.Criteria {
				if cr.Key == share.CriteriaKeyAddress {
					group.Kind = share.GroupKindAddress
				}
			}
		}
		upd = true
	}

	if group.CfgType == 0 {
		if group.Learned_UNUSED {
			group.CfgType = share.Learned
		} else {
			group.CfgType = share.UserCreated
		}
		upd = true
	}

	if utils.DoesGroupHavePolicyMode(group.Name) {
		if group.PolicyMode == "" {
			group.PolicyMode = share.PolicyModeLearn
			upd = true
		}

		if group.ProfileMode == "" {
			group.ProfileMode = group.PolicyMode
			upd = true
		}

		if group.BaselineProfile == "" {
			if group.Name == api.AllHostGroup {
				group.BaselineProfile = share.ProfileBasic // group "nodes" is always at "basic" baseline profile(not configurable by design)
			} else {
				group.BaselineProfile = share.ProfileZeroDrift // for learned groups, default to zero-drift mode
			}
			upd = true
		}
	} else if group.PolicyMode != "" || group.ProfileMode != "" {
		// This is to take care upgrade case where PolicyMode was set incorrectly
		group.PolicyMode = ""
		group.ProfileMode = ""
		upd = true
	}
	return upd, upd
}

func upgradePolicyRule(rule *share.CLUSPolicyRule) (bool, bool) {
	var upd bool
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
		rule.LastModAt = rule.CreatedAt
		upd = true
	}

	if rule.CfgType == 0 {
		if rule.Learned_UNUSED {
			rule.CfgType = share.Learned
		} else {
			rule.CfgType = share.UserCreated
		}
		upd = true
	}
	return upd, upd
}

func upgradePolicyRuleHead(rules []*share.CLUSRuleHead) (bool, bool) {
	var upd bool
	for _, rule := range rules {
		if rule.CfgType == 0 {
			if rule.Learned_UNUSED {
				rule.CfgType = share.Learned
			} else {
				rule.CfgType = share.UserCreated
			}
			upd = true
		}
	}
	return upd, upd
}

func upgradeRegistry(cfg *share.CLUSRegistryConfig) (bool, bool) {
	var upd bool
	if cfg.Type == share.RegistryTypeRedhat_Deprecate {
		if strings.Contains(cfg.Registry, share.DefaultOpenShiftRegistryURL) {
			cfg.Type = share.RegistryTypeOpenShift
		} else {
			cfg.Type = share.RegistryTypeRedhat
		}
		cfg.Schedule = api.ScanSchManual
		upd = true
	} else if cfg.Type == share.RegistryTypeJFrog && cfg.JfrogMode == "" {
		// we can handle subdomain as repository path
		cfg.JfrogMode = share.JFrogModeRepositoryPath
		upd = true
	}
	if cfg.CfgType == 0 {
		cfg.CfgType = share.UserCreated
		upd = true
	}
	// Don't write back to the cluster yet as we could be in the process of rolling upgrade,
	// old controllers might not accept the new configs.
	return upd, false
}

func upgradeAdmCtrlState(config string, state *share.CLUSAdmissionState) (bool, bool) {
	var upd bool
	if state.DefaultAction == "" {
		state.DefaultAction = share.AdmCtrlActionAllow
		upd = true
	}
	if state.AdmClientMode == "" {
		state.AdmClientMode = share.AdmClientModeSvc
		upd = true
	}
	svcName := resource.NvCrdSvcName
	if config == share.CFGEndpointAdmissionControl {
		svcName = resource.NvAdmSvcName
		if ctrlState := state.CtrlStates[admission.NvAdmValidateType]; ctrlState != nil {
			if ctrlState.Uri != "" && ctrlState.NvStatusUri == "" {
				ss := strings.Split(ctrlState.Uri, "/")
				if len(ss) >= 3 && ss[2] == admission.NvAdmValidateType {
					ss[2] = admission.UriAdmCtrlNvStatus
					ctrlState.NvStatusUri = strings.Join(ss, "/")
					upd = true
				}
			}
		}
	}
	svcFound := false
	if _, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, svcName); err == nil {
		// state.NvDeployStatus[svcName] = true
		svcFound = true
	}
	if len(state.NvDeployStatus) == 0 {
		state.NvDeployStatus = map[string]bool{
			resource.NvDeploymentName: true,
			svcName:                   false,
		}
		upd = true
	}
	if status, ok := state.NvDeployStatus[svcName]; !ok || status != svcFound {
		state.NvDeployStatus[svcName] = svcFound
		upd = true
	}
	if state.CfgType == 0 {
		state.CfgType = share.UserCreated
		upd = true
	}
	return upd, upd
}

func upgradeAdmCtrlRule(rule *share.CLUSAdmissionRule) (bool, bool) {
	var upd bool
	if rule.CfgType == 0 {
		rule.CfgType = share.UserCreated
		upd = true
	}
	return upd, upd
}

func upgradeProcessProfile(cfg *share.CLUSProcessProfile) (bool, bool) {
	var upd bool
	tm := time.Now().UTC()

	// after 3.2: fill the mode to Discover
	if cfg.Group == api.AllHostGroup && cfg.Mode == "" {
		cfg.Mode = share.PolicyModeLearn
		upd = true
	}

	if cfg.CfgType == 0 { // 3.0: per entry types
		cfg.CfgType = utils.EvaluateGroupType(cfg.Group)
		upd = true
	}

	if utils.DoesGroupHavePolicyMode(cfg.Group) {
		if cfg.Baseline == "" {
			if utils.IsGroupNodes(cfg.Group) {
				cfg.Baseline = share.ProfileBasic
			} else {
				cfg.Baseline = share.ProfileZeroDrift
			}
			upd = true
		} else {
			blValue := strings.ToLower(cfg.Baseline)
			if blValue == share.ProfileDefault_UNUSED || blValue == share.ProfileShield_UNUSED {
				blValue = share.ProfileZeroDrift
			}
			if blValue != cfg.Baseline {
				cfg.Baseline = blValue
				upd = true
			}
		}
	}

	for i := range cfg.Process {
		if cfg.Process[i].CreatedAt.IsZero() {
			cfg.Process[i].CreatedAt = tm
			upd = true
		}
		if cfg.Process[i].UpdatedAt.IsZero() {
			cfg.Process[i].UpdatedAt = tm
			upd = true
		}

		if cfg.Process[i].Action == "alert" { // pre-2.5
			cfg.Process[i].Action = share.PolicyActionDeny
			upd = true
		}

		if cfg.CfgType != share.GroundCfg { // exclude for CRD configuration, it was from external k8s request
			if cfg.Process[i].CfgType == 0 { // 3.0: per entry types
				cfg.Process[i].CfgType = cfg.CfgType
				upd = true
			}
		}
		if cfg.Process[i].Uuid == "" { // after 3.2: RuleID
			cfg.Process[i].Uuid = ruleid.NewUuid()
			upd = true
		}
	}
	return upd, upd
}

func upgradeFileMonitorProfile(cfg *share.CLUSFileMonitorProfile) (bool, bool) {
	var upd bool
	if cfg.CfgType == 0 { // 3.0: per entry types
		cfg.CfgType = utils.EvaluateGroupType(cfg.Group)
		upd = true
	}
	return upd, upd
}

func upgradeResponseRule(cfg *share.CLUSResponseRule) (bool, bool) {
	var upd bool
	var wrt bool
	if cfg.CfgType == 0 {
		cfg.CfgType = share.UserCreated
		upd = true
		wrt = true
	}
	if cfg.Event == share.EventIncident || cfg.Event == share.EventThreat || cfg.Event == share.EventViolation {
		cfg.Event = share.EventRuntime
		upd = true
		wrt = true
	}
	if cfg.Event == share.EventBenchmark_UNUSED {
		cfg.Event = share.EventCompliance
		for i, cond := range cfg.Conditions {
			if cond.CondType == share.EventCondTypeBenchNumber {
				cfg.Conditions[i].CondType = share.EventCondTypeName
			}
		}
		upd = true
		wrt = true
	}
	// Don't write back to the cluster as the old controller cannot handle it.
	return upd, wrt
}

func upgradeRuleHead(rules []*share.CLUSRuleHead) (bool, bool) {
	var upd bool
	for _, rule := range rules {
		if rule.CfgType == 0 {
			rule.CfgType = share.UserCreated
			upd = true
		}
	}
	return upd, upd
}

func upgradeAdmissionCert(value []byte) (*share.CLUSAdmissionCertCloaked, bool, bool) {
	// cert in kv is from 2.5
	var certOld share.CLUSAdmissionCert
	if err := json.Unmarshal(value, &certOld); err == nil {
		certNew := share.CLUSAdmissionCertCloaked{
			CN:        certOld.CN,
			CaKeyNew:  string(certOld.CaKey),
			CaCertNew: string(certOld.CaCert),
			KeyNew:    string(certOld.Key),
			CertNew:   string(certOld.Cert),
			Cloaked:   true,
		}
		valueNew, _ := enc.Marshal(&certNew) // valueNew is byte slice of cloaked object
		// we need to do json.Unmarshal here so the return of doUpgrade() can be json.Marshal and wtitten to kv later
		var cert share.CLUSAdmissionCertCloaked
		_ = json.Unmarshal(valueNew, &cert)
		// cert.CaKeyNew / cert.CaCertNew / cert.KeyNew / cert.CertNew are still cloaked
		return &cert, true, true
	} else {
		log.WithFields(log.Fields{"err": err}).Info("Unmarshal")
	}
	return nil, false, false
}

func doUpgrade(key string, value []byte) (interface{}, bool) {
	object := share.CLUSObjectKey2Object(key)

	switch object {
	case "config":
		config := share.CLUSConfigKey2Config(key)

		switch config {
		case share.CFGEndpointUser:
			var user share.CLUSUser
			_ = nvJsonUnmarshal(key, value, &user)
			if upd, wrt := upgradeUser(&user); upd {
				return &user, wrt
			}
		case share.CFGEndpointSystem:
			var cfg share.CLUSSystemConfig
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeSystemConfig(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointServer:
			var cfg share.CLUSServer
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeServer(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointGroup:
			var cfg share.CLUSGroup
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeGroup(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointPolicy:
			if share.CLUSIsPolicyRuleKey(key) {
				var cfg share.CLUSPolicyRule
				_ = nvJsonUnmarshal(key, value, &cfg)
				if upd, wrt := upgradePolicyRule(&cfg); upd {
					return &cfg, wrt
				}
			} else if share.CLUSIsPolicyZipRuleListKey(key) {
				var cfg []*share.CLUSRuleHead
				_ = nvJsonUnmarshal(key, value, &cfg)
				if upd, wrt := upgradePolicyRuleHead(cfg); upd {
					return &cfg, wrt
				}

			}
		case share.CFGEndpointRegistry:
			var cfg share.CLUSRegistryConfig
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeRegistry(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointProcessProfile:
			var cfg share.CLUSProcessProfile
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeProcessProfile(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointFileMonitor:
			var cfg share.CLUSFileMonitorProfile
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeFileMonitorProfile(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointDlpGroup:
			var cfg share.CLUSDlpGroup
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeDlpGroup(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointDlpRule:
			var cfg share.CLUSDlpSensor
			_ = nvJsonUnmarshal(key, value, &cfg)
			if upd, wrt := upgradeDlpSensor(&cfg); upd {
				return &cfg, wrt
			}
		case share.CFGEndpointAdmissionControl, share.CFGEndpointCrd:
			scope := share.CLUSPolicyKey2AdmCfgPolicySubkey(key, false)
			if scope == share.DefaultPolicyName {
				token := share.CLUSPolicyKey2AdmCfgSubkey(key)
				if token == share.CLUSAdmissionCfgState {
					var state share.CLUSAdmissionState
					_ = nvJsonUnmarshal(key, value, &state)
					if upd, wrt := upgradeAdmCtrlState(config, &state); upd {
						return &state, wrt
					}
				} else {
					if config == share.CFGEndpointAdmissionControl {
						if token == share.CLUSAdmissionCfgRule {
							var rule share.CLUSAdmissionRule
							_ = nvJsonUnmarshal(key, value, &rule)
							if upd, wrt := upgradeAdmCtrlRule(&rule); upd {
								return &rule, wrt
							}
						} else if token == share.CLUSAdmissionCfgRuleList {
							var cfg []*share.CLUSRuleHead
							_ = nvJsonUnmarshal(key, value, &cfg)
							if upd, wrt := upgradeRuleHead(cfg); upd {
								return &cfg, wrt
							}
						} else if token == share.CLUSAdmissionCfgCert {
							var cert share.CLUSAdmissionCertCloaked
							err := dec.Unmarshal(value, &cert)
							if err != nil || !cert.Cloaked {
								if cert, upd, wrt := upgradeAdmissionCert(value); upd {
									return cert, wrt
								}
							}
						}
					}
				}
			} else if config == share.CFGEndpointCrd && scope == resource.NvSecurityRuleKind {
				var cfg share.CLUSCrdSecurityRule
				_ = nvJsonUnmarshal(key, value, &cfg)
				if upd, wrt := upgradeCrdSecurityRule(&cfg); upd {
					return &cfg, wrt
				}
			}
		case share.CFGEndpointResponseRule:
			var cfg share.CLUSResponseRule
			_ = nvJsonUnmarshal(key, value, &cfg)
			if share.CLUSIsPolicyRuleKey(key) {
				var cfg share.CLUSResponseRule
				_ = nvJsonUnmarshal(key, value, &cfg)
				if upd, wrt := upgradeResponseRule(&cfg); upd {
					return &cfg, wrt
				}
			} else if share.CLUSIsPolicyRuleListKey(key) {
				var cfg []*share.CLUSRuleHead
				_ = nvJsonUnmarshal(key, value, &cfg)
				if upd, wrt := upgradeRuleHead(cfg); upd {
					return &cfg, wrt
				}
			}
		case share.CFGEndpointVulnerability:
			if key == share.CLUSVulnerabilityProfileKey(share.DefaultVulnerabilityProfileName) {
				var cfg share.CLUSVulnerabilityProfile
				if err := nvJsonUnmarshal(key, value, &cfg); err == nil {
					upd := false
					if cfg.CfgType == 0 {
						cfg.CfgType = share.UserCreated
						upd = true
					}
					if upd {
						return &cfg, upd
					}
				}
			}
		case share.CFGEndpointCompliance:
			if key == share.CLUSComplianceProfileKey(share.DefaultComplianceProfileName) {
				var cfg share.CLUSComplianceProfile
				if err := nvJsonUnmarshal(key, value, &cfg); err == nil {
					upd := false
					if cfg.CfgType == 0 {
						cfg.CfgType = share.UserCreated
						upd = true
					}
					if upd {
						return &cfg, upd
					}
				}
			}
		}
	}

	return nil, false
}

// This is called when we restore the persisted config into kv store
func upgrade(key string, value []byte) ([]byte, error) {
	if len(value) == 0 {
		return value, nil
	}

	v, _ := doUpgrade(key, value)
	if v == nil {
		return value, nil
	}

	return json.Marshal(v)
}

// This is called whenever we read from kv store or get notified by kv changes.
func UpgradeAndConvert(key string, value []byte) ([]byte, error, bool) {
	if len(value) == 0 {
		return value, nil, false
	}
	var v interface{}
	var wrt bool
	var policyListKey bool
	var crdKey bool

	if key == share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName) {
		policyListKey = true
	}
	if strings.HasPrefix(key, share.CLUSCrdProcStore) || strings.HasPrefix(key, share.CLUSConfigCrdStore) {
		crdKey = true
	}
	// [31, 139] is the first 2 bytes of gzip-format data
	if policyListKey || (crdKey && len(value) >= 2 && value[0] == 31 && value[1] == 139) {
		if value = utils.GunzipBytes(value); value == nil {
			log.WithFields(log.Fields{"key": key}).Error("Failed to unzip data")
			return value, nil, false
		}
	}
	v, wrt = doUpgrade(key, value)

	if v != nil && wrt {
		var err error
		newv, _ := json.Marshal(v)
		// currently we only zip nw policy rulelist & longer-than-512k-crd-keys
		if policyListKey || (crdKey && len(newv) >= cluster.KVValueSizeMax) { // 512 * 1024
			new_zb := utils.GzipBytes(newv)
			err = cluster.PutBinary(key, new_zb)
		} else {
			// Write back to the cluster if needed.
			err = cluster.Put(key, newv)
		}
		if err != nil {
			log.WithFields(log.Fields{"key": key}).Error(err)
			wrt = false
		}
	} else {
		wrt = false
	}

	object := share.CLUSObjectKey2Object(key)
	switch object {
	case "cloud":
		cloudType := share.CLUSCloudKey2Type(key)

		switch cloudType {
		case share.CloudAws:
			if share.CLUSKeyLength(key) == 4 {
				if v == nil {
					var r share.CLUSAwsResource
					_ = nvJsonUnmarshal(key, value, &r)
					v = &r
				}
				if err := dec.Uncloak(v); err != nil {
					log.WithFields(log.Fields{"err": err, "key": key}).Error("Uncloak")
				}
			}
		}
	case "config":
		config := share.CLUSConfigKey2Config(key)

		switch config {
		case share.CFGEndpointSystem:
			if v == nil {
				var cfg share.CLUSSystemConfig
				_ = nvJsonUnmarshal(key, value, &cfg)
				v = &cfg
			}
			if err := dec.Uncloak(v); err != nil {
				log.WithFields(log.Fields{"err": err, "key": key}).Error("Uncloak")
			}
		case share.CFGEndpointServer:
			if v == nil {
				var cfg share.CLUSServer
				_ = nvJsonUnmarshal(key, value, &cfg)
				v = &cfg
			}
			if err := dec.Uncloak(v); err != nil {
				log.WithFields(log.Fields{"err": err, "key": key}).Error("Uncloak")
			}
		case share.CFGEndpointRegistry:
			if v == nil {
				var cfg share.CLUSRegistryConfig
				_ = nvJsonUnmarshal(key, value, &cfg)
				v = &cfg
			}
			if err := dec.Uncloak(v); err != nil {
				log.WithFields(log.Fields{"err": err, "key": key}).Error("Uncloak")
			}
		case share.CFGEndpointCloud:
			if v == nil {
				// Currently the only data structure
				var cfg share.CLUSAwsProjectCfg
				_ = nvJsonUnmarshal(key, value, &cfg)
				v = &cfg
			}
			if err := dec.Uncloak(v); err != nil {
				log.WithFields(log.Fields{"err": err, "key": key}).Error("Uncloak")
			}
		}
	}

	if v == nil {
		return value, nil, wrt
	} else {
		value, err := json.Marshal(v)
		return value, err, wrt
	}
}

// --

type kvVersions struct {
	version string
	upgrade func()
}

var phases []kvVersions = []kvVersions{
	// "": Initial version
	{"", createDefaultObjects},

	// enforce kubernetes (non-openshift) network policy at ingress.
	// nv.ip.* groups and rules are removed when upgrade from ""
	{"FCE6E817", createResponseRules},

	// default rules for admission control added
	{"28A0529D", createAdmCtrlRules},

	// by default enable service mesh monitoring
	{"DE2EC0BA", createDefaultServiceMeshMonitor},

	// generate TLS certificates for admission webhook servers
	{"6C6B7374", dummyFunc}, // Move cert kv keys from object/config/... to object/cert/... (outside upgrade phases)

	// default response rules added
	{"EB36BEB3", genFileAccessRule},

	// generate state and TLS certificates for crd webhook validate servers. --> Starting from here are added for version 3.0
	{"A11056E0", genCrdWebhookResource},
	// default response rules added

	{"C2DW2DC2", dummyFunc}, // Move cert kv keys from object/config/... to object/cert/... (outside upgrade phases)

	// create group that selects all containers
	{"444C5052", createAllContainerGroup},

	// default dlp rules added
	{"2D810F0C", createDefDlpRuleSensor},

	{"646C7073", CreateDefaultFedGroups},

	//CompressPolicyRuleList is called twice to
	//cover for both pre 3.2.1 and 3.2.1 case
	{"9ACDAB16", CompressPolicyRuleList},

	{"636F726E", CompressPolicyRuleList},

	// when an admCtrl rule like "cveHighCount:>=:3/publishDays:>=:30"(on 3.2.2+ master cluster) is deployed to old version worker cluster, it's seen as "cveHighCount:>=:3" by old version controller.
	// so we add one dummy phase and also change GetFedKvVer() to prompt customers(on multi-cluster UI page) that some clusters require upgrade before them can get fed rules
	{"475A4950", dummyFunc},
	{"E6451614", dummyFunc},

	{"23A3B118", upgradeDomainRoles},

	{"4F24CF57", createDefaultComplianceProfile},

	{"8B0CA531", createDefaultDomains},

	{"FB23934C", dummyFunc}, // for imageNoOS criterion in admission control rule

	{"9A4B940E", dummyFunc}, // k8s 1.19(+) requires the cert for webhook servers to have SAN. Move cert kv keys from object/config/... to object/cert/... (outside upgrade phases)

	{"603E2563", setDefaultUnusedGroupAging}, //set default unused group aging time

	{"4E4F5633", renameCustomReservedRoles}, // in case a reserved role is created by customers

	{"D0F8B265", createDefaultXffSetting}, // by default enable xff policy match

	{"X8F6F948", createDefaultPwdProfile},

	{"263f7286", upgradeServerGroupRoles}, // change from role->groups mapping to group->{role->domains} mapping

	{"169583CA", upgradeWebhookConfig},

	{"65347e39", dummyFunc},

	{"E907B7AE", createDefaultVulnerabilityProfile},

	{"03749d2c", createDefDlpRuleSensor}, // create default dlp rules with each credit card pattern in different name

	{"4665644B", addAdmCtrlStateStatusUri},

	{"2C05EB31", createDefaultNetServiceSetting},

	{"4C746652", resetDlpCfgType},

	{"825C9419", createDefWafRuleSensor},

	{"7B3D205C", addFmonRpmPackageDB},

	{"168EE3FA", resetRegistryCfgType},

	{"28ea479c", initFedScanRevKey},

	{"FCAB0BF2", upgradeDefSecRisksProfiles},

	{"449EC339", dummyFunc},

	{"D6AD17D4", nil},
}

func latestKVVersion() string {
	l := len(phases)
	if l == 0 {
		return ""
	} else {
		return phases[l-1].version
	}
}

func getControlVersion() *share.CLUSCtrlVersion {
	var ver share.CLUSCtrlVersion

	key := share.CLUSCtrlVerKey
	value, _ := cluster.Get(key)
	if value != nil {
		_ = nvJsonUnmarshal(key, value, &ver)
		return &ver
	}

	return &share.CLUSCtrlVersion{}
}

func putControlVersion(ver *share.CLUSCtrlVersion) error {
	key := share.CLUSCtrlVerKey
	value, _ := json.Marshal(ver)
	return cluster.Put(key, value)
}

// version param is the NV Version embedded in the controller process
func (m clusterHelper) UpgradeClusterKV(version string) (verUpdated bool) {
	var run bool

	lock, err := m.AcquireLock(share.CLUSLockUpgradeKey, upgradeClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer m.ReleaseLock(lock)

	ver := getControlVersion()
	log.WithFields(log.Fields{"version": ver}).Info("Before upgrade")
	if !strings.HasPrefix(version, "interim/") {
		if ver.CtrlVersion != version {
			users := m.GetAllUsersNoAuth()
			for _, user := range users {
				if len(user.AcceptedAlerts) > 0 {
					user.AcceptedAlerts = nil
					_ = m.PutUser(user)
				}
			}
		}
	}

	for i := 0; i < len(phases); i++ {
		phase := &phases[i]
		if ver.KVVersion == phase.version && !run {
			run = true
		}

		if run && phase.upgrade != nil {
			log.WithFields(log.Fields{"phase": phase.version}).Debug()
			phase.upgrade()
		}
	}

	newVer := &share.CLUSCtrlVersion{
		CtrlVersion: m.version,
		KVVersion:   latestKVVersion(),
	}
	if ver != newVer {
		_ = putControlVersion(newVer)
		_ = cfgHelper.writeBackupVersion()

		if !strings.HasPrefix(version, "interim/") {
			if ver.CtrlVersion != version {
				verUpdated = true
			}
		}
	}
	log.WithFields(log.Fields{"version": newVer}).Info("After upgrade")

	return
}

func (m clusterHelper) UpgradeClusterImport(importVer *share.CLUSCtrlVersion) {
	var run bool

	lock, err := m.AcquireLock(share.CLUSLockUpgradeKey, upgradeClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer m.ReleaseLock(lock)

	cur_ver := getControlVersion()

	log.WithFields(log.Fields{"imported": importVer, "current": cur_ver}).Info("Before import upgrade")

	for i := 0; i < len(phases); i++ {
		phase := &phases[i]
		if importVer.KVVersion == phase.version && !run {
			run = true
		}

		if run && phase.upgrade != nil {
			log.WithFields(log.Fields{"phase": phase.version}).Debug()
			phase.upgrade()
		}
	}

	newVer := &share.CLUSCtrlVersion{
		CtrlVersion: m.version,
		KVVersion:   latestKVVersion(),
	}
	if cur_ver == nil || cur_ver.CtrlVersion != newVer.CtrlVersion || cur_ver.KVVersion != newVer.KVVersion {
		_ = putControlVersion(newVer)
		_ = cfgHelper.writeBackupVersion()
		log.WithFields(log.Fields{"new": newVer}).Info("After import write new version")
	}
	log.WithFields(log.Fields{"imported": importVer, "current": cur_ver, "new": newVer}).Info("After import upgrade")
}

func (m clusterHelper) FixMissingClusterKV() {
	lock, err := m.AcquireLock(share.CLUSLockUpgradeKey, upgradeClusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer m.ReleaseLock(lock)

	type keyInitType struct {
		key  string
		init func()
	}
	var keyInits = []keyInitType{ // the order of the slice entries should be the same as defined in var phases
		{share.CLUSConfigUserStore, createDefaultAdminUser},
		{share.CLUSGroupKey(api.LearnedExternal), func() { createDefaultGroup(api.LearnedExternal, share.GroupKindExternal, "") }},
		{share.CLUSGroupKey(api.AllHostGroup), func() { createDefaultGroup(api.AllHostGroup, share.GroupKindNode, share.PolicyModeLearn) }},
		{share.CLUSGroupKey(api.AllContainerGroup), createAllContainerGroup},
		{share.CLUSResponseRuleListKey(share.DefaultPolicyName), createResponseRules},
		{share.CLUSConfigAdmissionControlStore, createAdmCtrlRules},
		{share.CLUSConfigSystemKey, createDefaultServiceMeshMonitor},
		{share.CLUSGroupKey(api.FederalGroupPrefix + api.AllHostGroup), func() {
			if fedRole, _ := getFedRole(); fedRole == api.FedRoleJoint || fedRole == api.FedRoleMaster {
				createDefaultGroup(api.FederalGroupPrefix+api.AllHostGroup, share.GroupKindNode, share.PolicyModeLearn)
			}
		}},
		{share.CLUSGroupKey(api.FederalGroupPrefix + api.AllContainerGroup), func() {
			if fedRole, _ := getFedRole(); fedRole == api.FedRoleJoint || fedRole == api.FedRoleMaster {
				_createAllContainerGroup(api.FederalGroupPrefix + api.AllContainerGroup)
			}
		}},
	}
	for _, keyInit := range keyInits {
		if !cluster.Exist(keyInit.key) {
			log.WithFields(log.Fields{"key": keyInit.key}).Info("Re-create because not found")
			keyInit.init()
		}
	}
}

const (
	_fedSuccess               = iota
	_fedMasterUpgradeRequired = 101 // do not change
	_fedJointUpgradeRequired  = 102 // do not change
	_fedClusterUpgradeOngoing = 103 // do not change
)

func GetControlVersion() share.CLUSCtrlVersion {
	ver := getControlVersion()
	return *ver
}

// check if the request handling cluster can handle request from the requesting cluster
// for "fed kv version":
//  1. the request handling cluster & requesting cluster have the same "fed kv version", it means they can handle requests from each other in the same federation
//  2. if not, it means they shouldn't handle requests from each other
//     2-1: if the requesting cluster's "fed kv version" is in the handler cluster's phases, it means the requesting cluster needs upgrade
//     2-2: if the requesting cluster's "fed kv version" is not in the handler cluster's phases, it means the handler cluster needs upgrade
func CheckFedKvVersion(verifier, reqFedKvVer string) (bool, int, error) {
	ver := getControlVersion()
	if ver.KVVersion != latestKVVersion() {
		// kv version is not the same as the last phase in the running controller because this controller is not upgraded yet in multi-controllers env
		return false, _fedClusterUpgradeOngoing, fmt.Errorf("kv_version: %s, latest: %s", ver.KVVersion, latestKVVersion())
	}
	if GetFedKvVer() == reqFedKvVer {
		return true, _fedSuccess, nil
	} else {
		var retCode int = -1
		for i := 0; i < len(phases); i++ {
			if reqFedKvVer == phases[i].version {
				if verifier == "master" {
					retCode = _fedJointUpgradeRequired
					break
				} else if verifier == "joint" {
					retCode = _fedMasterUpgradeRequired
					break
				}
			}
		}
		if retCode == -1 {
			if verifier == "master" {
				retCode = _fedMasterUpgradeRequired
			} else if verifier == "joint" {
				retCode = _fedJointUpgradeRequired
			}
		}
		log.WithFields(log.Fields{"req": reqFedKvVer, "verifier": verifier, "handler": GetFedKvVer()}).Warn("version not qualified")
		return false, retCode, fmt.Errorf("fed_version: %s, req: %s", GetFedKvVer(), reqFedKvVer)
	}
}

func GetFedKvVer() string { // NV clusters with the same "fed kv version" means they can be in the same federation
	//return "2D810F0C" // for 3.0 ~ 3.2.1
	//return "E6451614" // for 3.2.2
	//return "FB23934C" // for 4.0.0
	//return "9A4B940E" // for 4.0.1
	//return "4E4F5633" // for 4.0.2 ~ 4.2.2
	//return "65347e39" // for 4.2.3 ~ 4.3.1, multi-webhook support
	//return "E907B7AE" // for 4.3.2 ~ 5.0.x
	return "28ea479c" // for 5.1
}

func GetRestVer() string { // NV clusters with the same "rest version" means master cluster can switch UI view to them
	// return "E907B7AE" // for 5.0
	// return "28ea479c" // for 5.1 ~ 5.2.x
	// return "449EC339" // for 5.3 ~ 5.3.x
	return "D6AD17D4" // for 5.4
}

func genFileAccessRule() {
	log.Debug("")
	tm := time.Now().UTC()
	accReadAll := access.NewReaderAccessControl()
	groups := clusHelper.GetAllGroups(share.ScopeLocal, accReadAll)
	for grp, group := range groups {
		if cfg, rev := clusHelper.GetFileMonitorProfile(grp); cfg != nil {
			rconf := &share.CLUSFileAccessRule{
				Filters:    make(map[string]*share.CLUSFileAccessFilterRule),
				FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule),
			}
			cfg.Filters = fsmon.ImportantFiles
			for i, flt := range cfg.Filters {
				// create access rule
				idx := utils.FilterIndexKey(flt.Path, flt.Regex)
				frule := &share.CLUSFileAccessFilterRule{
					Apps:      make([]string, 0),
					CreatedAt: tm,
					UpdatedAt: tm,
					Behavior:  share.FileAccessBehaviorMonitor,
				}
				rconf.Filters[idx] = frule
				cfg.Filters[i].Filter = common.FsmonFilterToRest(flt.Path, flt.Regex)
				cfg.Mode = group.PolicyMode
			}
			if err := clusHelper.PutFileMonitorProfile(grp, cfg, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "group": grp}).Error("put file profile fail")
			}
			if err := clusHelper.PutFileAccessRuleIfNotExist(grp, rconf); err != nil {
				log.WithFields(log.Fields{"error": err, "group": grp}).Error("put file access rule fail")
			}
		}
	}
}

func dummyFunc() {
}

// The 'group' in this function could mean 'domain' as well.
// To remove extra roles assigned to a group/domain configured in pre-4.0
// Starting from 4.0, each group/domain can only be associated with one role
func filterRoleGroupsMapping(roleGroups map[string][]string, caseSensitive bool) bool {
	// Starts from the 'admin' role. If a user belongs to multiple groups that are mapped to different role, use the highest.
	modified := false
	roles := []string{api.UserRoleAdmin, api.UserRoleReader, api.UserRoleCIOps}
	groupRole := make(map[string]string, 16)
	for _, role := range roles {
		if groups, ok := roleGroups[role]; ok {
			gset := utils.NewSet()
			var g string
			for _, g0 := range groups {
				if !caseSensitive {
					g = strings.ToLower(g0)
				} else {
					g = g0
				}
				if _, ok := groupRole[g]; ok {
					// another role for the group is found. ignore it
					modified = true
					continue
				} else {
					// the first assigned role for the group. keep it
					groupRole[g] = role
				}
				gset.Add(g)
			}
			if gset.Cardinality() > 0 {
				roleGroups[role] = gset.ToStringSlice()
			} else {
				delete(roleGroups, role)
			}
		}
	}

	return modified
}

func upgradeDomainRoles() {
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigServerStore)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			server := share.CLUSServer{}
			updated := false
			if err = nvJsonUnmarshal(key, value, &server); err == nil {
				caseSensitive := true
				var roleGroups *map[string][]string
				if server.LDAP != nil {
					roleGroups = &server.LDAP.RoleGroups
					if server.LDAP.Type != api.ServerLDAPTypeOpenLDAP {
						caseSensitive = false
					}
				} else if server.SAML != nil {
					roleGroups = &server.SAML.RoleGroups
				} else if server.OIDC != nil {
					roleGroups = &server.OIDC.RoleGroups
				}
				if len(*roleGroups) > 0 {
					if updated = filterRoleGroupsMapping(*roleGroups, caseSensitive); updated {
						value, _ := json.Marshal(&server)
						if err = cluster.Put(key, value); err != nil {
							log.WithFields(log.Fields{"server": server.Name, "error": err}).Error("Failed to upgrade server for custom roles")
						}
					}
				}
			}
		}
	}
}

func restoreKeyCertFromOldKvKey(certSvcNames []string, svcName, cn, keyPath, certPath string) bool { // return 'restored to new kv key'
	var keyData, certData []byte
	var err1, err2 error
	var oldCert *share.CLUSAdmissionCertCloaked

	// read cert/key from old kv key first
	for _, certSvcName := range certSvcNames {
		if oldCert, _ = clusHelper.GetAdmissionCertRev(certSvcName); oldCert != nil {
			break
		}
	}
	if oldCert != nil { // [B]
		if cn == share.CLUSRootCAKey {
			keyData = oldCert.CaKey
			certData = oldCert.CaCert
		} else {
			keyData = oldCert.Key
			certData = oldCert.Cert
		}
	}

	if cn != share.CLUSRootCAKey {
		if len(keyData) > 0 && len(certData) > 0 {
			// verify whether the tls cert is valid
			if valid := verifyWebServerCert(cn, certData); !valid {
				// must delete existing invalid key/cert files
				os.Remove(keyPath)
				os.Remove(certPath)
				log.WithFields(log.Fields{"cn": cn}).Info("invalid cert")
				return false
			}
		}
	}
	if len(keyData) == 0 || len(certData) == 0 {
		log.WithFields(log.Fields{"cn": cn, "len1": len(keyData), "len2": len(certData), "err1": err1, "err2": err2}).Info("no cert/key")
		return false
	}
	cert := &share.CLUSX509Cert{
		CN:   cn,
		Key:  string(keyData),
		Cert: string(certData),
	}
	if err := clusHelper.PutObjectCert(cn, keyPath, certPath, cert); err == nil {
		if cn == share.CLUSRootCAKey && len(cert.Key) > 0 && len(cert.Cert) > 0 {
			certData := []byte(cert.Cert)
			err1 := os.WriteFile(keyPath, []byte(cert.Key), 0600)
			err2 := os.WriteFile(certPath, certData, 0600)
			if err1 == nil && err2 == nil {
				return true
			} else {
				log.WithFields(log.Fields{"err1": err1, "err2": err2, "svcName": svcName, "cn": cn}).Error()
			}
		}
	}

	return false
}

func ValidateWebhookCert() {
	log.Info()

	type keyCertInfo struct {
		cn           string
		svcName      string
		certSvcNames []string // for old kv key
		keyPath      string
		certPath     string
		store        string
		verified     bool
		k8sEnvOnly   bool
	}

	// starting from 4.2, cert is literally not stored under object/config/... for webhook servers anymore.
	// for a fresh deployment + pv(from 4.2+), after restoring pv there will be no cert in kv anymore.
	// in this case, we need to explicitly generate those key/cert if they are not found in kv(object/cert/)
	// i.e. we do not do this in upgrade phases anymore!
	admKeyPath, admCertPath := resource.GetTlsKeyCertPath(resource.NvAdmSvcName, resource.NvAdmSvcNamespace)
	crdKeyPath, crdCertPath := resource.GetTlsKeyCertPath(resource.NvCrdSvcName, resource.NvAdmSvcNamespace)
	certsInfo := []*keyCertInfo{
		{
			cn:           share.CLUSRootCAKey,
			svcName:      share.CLUSRootCAKey,
			certSvcNames: []string{resource.NvAdmSvcName, resource.NvCrdSvcName}, // for old kv key
			keyPath:      AdmCAKeyPath,
			certPath:     AdmCACertPath,
			k8sEnvOnly:   false,
		},
		{
			cn:           fmt.Sprintf("%s.%s.svc", resource.NvAdmSvcName, resource.NvAdmSvcNamespace),
			svcName:      resource.NvAdmSvcName,
			certSvcNames: []string{resource.NvAdmSvcName}, // for old kv key
			keyPath:      admKeyPath,
			certPath:     admCertPath,
			store:        share.CLUSConfigAdmissionControlStore,
			k8sEnvOnly:   true,
		},
		{
			cn:           fmt.Sprintf("%s.%s.svc", resource.NvCrdSvcName, resource.NvAdmSvcNamespace),
			svcName:      resource.NvCrdSvcName,
			certSvcNames: []string{resource.NvCrdSvcName}, // for old kv key
			keyPath:      crdKeyPath,
			certPath:     crdCertPath,
			store:        share.CLUSConfigCrdStore,
			k8sEnvOnly:   true,
		},
	}
	// don't know why: after rolling upgrade(replicas/maxSurge=3), there could be a short period that controller cannot get/put kv
	// (get returns "Key not found" error & put gets "CAS put error" & PutIfNotExist returns nil : is it because kv is not syned yet?)
	// there is no good solution about this and we should not proceed when we see this error.
	// currently we re-try 15 times & hopefully kv is available after 15 retries
	for i := 0; i < 16; i++ {
		for _, certInfo := range certsInfo {
			if certInfo.k8sEnvOnly && orchPlatform != share.PlatformKubernetes {
				certInfo.verified = true
				continue
			}
			if !certInfo.verified {
				if cert, _, _ := clusHelper.GetObjectCertRev(certInfo.cn); cert.IsEmpty() {
					// cert is not found under new kv key
					if !restoreKeyCertFromOldKvKey(certInfo.certSvcNames, certInfo.svcName, certInfo.cn, certInfo.keyPath, certInfo.certPath) {
						// cert is still not found under new kv key after restoring from old kv key. re-gen key/cert.
						log.WithFields(log.Fields{"cn": certInfo.cn}).Info("regen")
						switch certInfo.svcName {
						case share.CLUSRootCAKey:
							if err := CreateCAFilesAndStoreInKv(AdmCACertPath, AdmCAKeyPath); err != nil {
								// Make it retry.
								log.WithError(err).Error("failed to create CA file")
								continue
							}

						case resource.NvAdmSvcName, resource.NvCrdSvcName:
							if orchPlatform == share.PlatformKubernetes {
								tlsKeyPath, tlsCertPath := resource.GetTlsKeyCertPath(certInfo.svcName, resource.NvAdmSvcNamespace)

								if err := GenTlsCertWithCaAndStoreInKv(certInfo.cn,
									tlsCertPath, tlsKeyPath,
									AdmCACertPath, AdmCAKeyPath, ValidityPeriod{Year: 10}); err != nil {
									// Make it retry.
									log.WithError(err).Error("failed to generate Webhook certs")
									continue
								}
							}
						}
					} else {
						certInfo.verified = true
					}
				} else {
					if certInfo.svcName == resource.NvAdmSvcName || certInfo.svcName == resource.NvCrdSvcName {
						if orchPlatform == share.PlatformKubernetes {
							if valid := verifyWebServerCert(certInfo.cn, []byte(cert.Cert)); !valid {
								// must delete existing invalid key/cert files
								os.Remove(certInfo.keyPath)
								os.Remove(certInfo.certPath)
								log.WithFields(log.Fields{"cn": certInfo.cn}).Info("invalid cert")
								tlsKeyPath, tlsCertPath := resource.GetTlsKeyCertPath(certInfo.svcName, resource.NvAdmSvcNamespace)

								if err := GenTlsCertWithCaAndStoreInKv(certInfo.cn, tlsCertPath, tlsKeyPath, AdmCACertPath, AdmCAKeyPath, ValidityPeriod{Year: 10, Month: 0, Day: 0}); err != nil {
									log.WithError(err).Error("failed to generate Webhook certs in ValidateWebhookCert()")
								}
								cert, _, _ = clusHelper.GetObjectCertRev(certInfo.cn)
							}
						}
					} else {
						if cert != nil {
							err1 := os.WriteFile(certInfo.keyPath, []byte(cert.Key), 0600)
							err2 := os.WriteFile(certInfo.certPath, []byte(cert.Cert), 0600)
							log.WithFields(log.Fields{"err1": err1, "err2": err2}).Info()
						}
					}
					if cert != nil {
						b := md5.Sum([]byte(cert.Cert))
						log.WithFields(log.Fields{"cn": certInfo.cn, "cert": hex.EncodeToString(b[:])}).Info("md5")
						certInfo.verified = true
					}
				}
			}
		}
		if certsInfo[0].verified && certsInfo[1].verified && certsInfo[2].verified {
			break
		}
		time.Sleep(time.Second)
	}
	for _, certInfo := range certsInfo {
		if certInfo.k8sEnvOnly && orchPlatform != share.PlatformKubernetes {
			continue
		}
		if cert, _, _ := clusHelper.GetObjectCertRev(certInfo.cn); !cert.IsEmpty() {
			certData := []byte(cert.Cert)
			err1 := os.WriteFile(certInfo.keyPath, []byte(cert.Key), 0600)
			err2 := os.WriteFile(certInfo.certPath, certData, 0600)
			if err1 == nil && err2 == nil {
				if certInfo.cn != share.CLUSRootCAKey {
					if orchPlatform == share.PlatformKubernetes {
						admission.SetCABundle(certInfo.svcName, certData)
					}
					// cert migration in kv is done. delete old kv key
					_ = cluster.Delete(share.CLUSAdmissionCertKey(certInfo.store, share.DefaultPolicyName))
				} else if orchPlatform != share.PlatformKubernetes {
					// if it's non-k8s env, delete the old cert keys
					_ = cluster.Delete(share.CLUSAdmissionCertKey(share.CLUSConfigAdmissionControlStore, share.DefaultPolicyName))
					_ = cluster.Delete(share.CLUSAdmissionCertKey(share.CLUSConfigCrdStore, share.DefaultPolicyName))
				}
			} else {
				log.WithFields(log.Fields{"err1": err1, "err2": err2, "svcName": certInfo.svcName}).Error("failed to restore files")
			}
		}
	}
}

// To re-assign custom role(with reserved role name) configured in pre-4.1
func reassignCustomReservedRoles(roleGroups map[string][]string, roleNameMapping map[string]string) bool {
	modified := false
	for oldRoleName, newRoleName := range roleNameMapping {
		if groups, ok := roleGroups[oldRoleName]; ok {
			delete(roleGroups, oldRoleName)
			roleGroups[newRoleName] = groups
			modified = true
		}
	}

	return modified
}

func reassignMappedUserRoles(user *share.CLUSUser, roleNameMapping map[string]string) bool {
	updated1, updated2 := false, false
	if newRoleName, ok := roleNameMapping[user.Role]; ok {
		updated1 = true
		user.Role = newRoleName
	}
	if len(user.RoleDomains) > 0 {
		updated2 = reassignCustomReservedRoles(user.RoleDomains, roleNameMapping)
	}
	return (updated1 || updated2)
}

func reassignMappedServerRoles(server *share.CLUSServer, roleNameMapping map[string]string) bool {
	var defaultRole *string
	var roleGroups *map[string][]string
	if server.LDAP != nil {
		defaultRole = &server.LDAP.DefaultRole
		roleGroups = &server.LDAP.RoleGroups
	} else if server.SAML != nil {
		defaultRole = &server.SAML.DefaultRole
		roleGroups = &server.SAML.RoleGroups
	} else if server.OIDC != nil {
		defaultRole = &server.OIDC.DefaultRole
		roleGroups = &server.OIDC.RoleGroups
	}
	updated1, updated2 := false, false
	if defaultRole != nil {
		if newRoleName, ok := roleNameMapping[*defaultRole]; ok {
			*defaultRole = newRoleName
			updated1 = true
		}
	}
	if roleGroups != nil && len(*roleGroups) > 0 {
		updated2 = reassignCustomReservedRoles(*roleGroups, roleNameMapping)
	}
	return (updated1 || updated2)
}

func renameCustomReservedRoles() {
	accAdmin := access.NewAdminAccessControl()
	reservedRoleNames := access.GetReservedRoleNames()
	roleNameMapping := make(map[string]string, reservedRoleNames.Cardinality())
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigUserRoleStore)
	for _, key := range keys {
		roleName := key[len(share.CLUSConfigUserRoleStore):]
		// a pre-existing custom role with reserved name is found
		if reservedRoleNames.Contains(roleName) {
			log.WithFields(log.Fields{"roleName": roleName}).Info("Found pre-existing custom role with reserved name")
			if role, _, _ := clusHelper.GetCustomRoleRev(roleName, accAdmin); role != nil {
				newRoleName := roleName + "-renamed"
				roleNameMapping[roleName] = newRoleName
				role.Name = newRoleName
				role.Comment += " (renamed)"
				_ = clusHelper.CreateCustomRole(role, accAdmin)
				_ = clusHelper.DeleteCustomRole(roleName)
			}
		}
	}
	if len(roleNameMapping) <= 0 {
		return
	}

	keys, _ = cluster.GetStoreKeys(share.CLUSConfigUserStore)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			user := share.CLUSUser{}
			if err = nvJsonUnmarshal(key, value, &user); err == nil {
				if updated := reassignMappedUserRoles(&user, roleNameMapping); updated {
					value, _ := json.Marshal(&user)
					if err = cluster.Put(key, value); err != nil {
						log.WithFields(log.Fields{"user": user.Fullname, "error": err}).Error("Failed to upgrade user roles mapping")
					} else {
						log.WithFields(log.Fields{"user": user.Fullname}).Info("Remapped user roles")
					}
				}
			}
		}
	}

	keys, _ = cluster.GetStoreKeys(share.CLUSConfigServerStore)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			server := share.CLUSServer{}
			if err = nvJsonUnmarshal(key, value, &server); err == nil {
				if updated := reassignMappedServerRoles(&server, roleNameMapping); updated {
					value, _ := json.Marshal(&server)
					if err = cluster.Put(key, value); err != nil {
						log.WithFields(log.Fields{"server": server.Name, "error": err}).Error("Failed to upgrade server for custom roles mapping")
					} else {
						log.WithFields(log.Fields{"server": server.Name}).Info("Remapped server roles")
					}
				}
			}
		}
	}
}

func ConvertRoleGroupsToGroupRoleDomains(roleGroups map[string][]string) ([]*share.GroupRoleMapping, error) {
	// in pre-4.2, each group's mapped role means it's a role for global domain & no mapped group roles for the group
	mappedGroups := utils.NewSet()
	groupRoleMappings := make([]*share.GroupRoleMapping, 0)
	for role, groups := range roleGroups {
		for _, group := range groups {
			if mappedGroups.Contains(group) {
				return nil, fmt.Errorf("Multiple roles for group %s", group)
			}
			mappedGroups.Add(group)
			groupRoleMapping := &share.GroupRoleMapping{
				Group:      group,
				GlobalRole: role,
			}
			groupRoleMappings = append(groupRoleMappings, groupRoleMapping)
		}
	}
	sort.Slice(groupRoleMappings, func(p, q int) bool {
		if groupRoleMappings[p].GlobalRole == api.UserRoleAdmin {
			if groupRoleMappings[q].GlobalRole != api.UserRoleAdmin {
				return true
			}
		} else if groupRoleMappings[p].GlobalRole == api.UserRoleReader {
			if groupRoleMappings[q].GlobalRole == api.UserRoleAdmin {
				return false
			} else if groupRoleMappings[q].GlobalRole != api.UserRoleReader {
				return true
			}
		} else {
			if groupRoleMappings[q].GlobalRole == api.UserRoleAdmin || groupRoleMappings[q].GlobalRole == api.UserRoleReader {
				return false
			}
		}
		return groupRoleMappings[p].Group < groupRoleMappings[q].Group
	})

	return groupRoleMappings, nil
}

func upgradeServerGroupRoles() {
	var err error
	var updated bool

	acc := access.NewAdminAccessControl()
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigServerStore)
	for _, key := range keys {
		updated = false
		name := key[len(share.CLUSConfigServerStore):]
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs != nil {
			if cs.LDAP != nil {
				if len(cs.LDAP.RoleGroups) > 0 {
					if cs.LDAP.GroupMappedRoles, err = ConvertRoleGroupsToGroupRoleDomains(cs.LDAP.RoleGroups); err == nil {
						cs.LDAP.RoleGroups = nil
						updated = true
					}
				}
			} else if cs.SAML != nil {
				if len(cs.SAML.RoleGroups) > 0 {
					if cs.SAML.GroupMappedRoles, err = ConvertRoleGroupsToGroupRoleDomains(cs.SAML.RoleGroups); err == nil {
						cs.SAML.RoleGroups = nil
						updated = true
					}
				}
			} else if cs.OIDC != nil {
				if len(cs.OIDC.RoleGroups) > 0 {
					if cs.OIDC.GroupMappedRoles, err = ConvertRoleGroupsToGroupRoleDomains(cs.OIDC.RoleGroups); err == nil {
						cs.OIDC.RoleGroups = nil
						updated = true
					}
				}
			}
			if updated {
				if err := clusHelper.PutServerRev(cs, rev); err != nil {
					log.WithFields(log.Fields{"error": err, "rev": rev, "name": name}).Error("upgrade fail")
				}
			}
		}
	}
}

func upgradeWebhookConfig() {
	acc := access.NewAdminAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	if cfg.WebhookUrl_UNUSED != "" {
		retry := 0
		for {
			cfg.Webhooks = []share.CLUSWebhook{
				// WebhookEnable_UNUSED was not used. Always enable the entry.
				{Name: api.WebhookDefaultName, Url: cfg.WebhookUrl_UNUSED, Enable: true, Type: api.WebhookTypeSlack},
			}
			cfg.WebhookUrl_UNUSED = ""
			cfg.WebhookEnable_UNUSED = false

			if err := clusHelper.PutSystemConfigRev(cfg, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "retry": retry}).Error("Failed to upgrade system config webhooks")
				retry++

				if retry < retryClusterMax {
					cfg, rev = clusHelper.GetSystemConfigRev(acc)
				} else {
					return
				}
			} else {
				log.Info("System config webhook upgraded")
				break
			}
		}

		crhs := clusHelper.GetResponseRuleList(share.DefaultPolicyName)
		if len(crhs) > 0 {
			for _, crh := range crhs {
				if r, _ := clusHelper.GetResponseRule(share.DefaultPolicyName, crh.ID); r != nil {
					for _, act := range r.Actions {
						if act == share.EventActionWebhook {
							r.Webhooks = []string{api.WebhookDefaultName}
							if err := clusHelper.PutResponseRule(share.DefaultPolicyName, r); err != nil {
								log.WithFields(log.Fields{"error": err, "rule": r.ID}).Error("Failed to upgrade response rule's webhook action")
							} else {
								log.WithFields(log.Fields{"rule": r.ID}).Info("Response rule's webhook action upgraded")
							}
							break
						}
					}
				}
			}
		}
	}

	// As we don't do anything if webhookUrl is empty, it is in theory possible that the response rules
	// have webhook action but without webhook endpoint.
}

func upgradeCrdSecurityRule(cfg *share.CLUSCrdSecurityRule) (bool, bool) {
	if len(cfg.Groups) == 1 && !utils.HasGroupProfiles(cfg.Groups[0]) {
		return false, false
	}
	var upd bool
	if utils.DoesGroupHavePolicyMode(cfg.ProfileName) {
		if cfg.ProcessProfile == nil {
			cfg.ProcessProfile = &share.CLUSCrdProcessProfile{}
		}
		if cfg.ProcessProfile.Baseline != share.ProfileBasic && cfg.ProcessProfile.Baseline != share.ProfileZeroDrift {
			cfg.ProcessProfile.Baseline = share.ProfileZeroDrift
			upd = true
		}
	}
	return upd, upd
}

func upgradeDlpGroup(cfg *share.CLUSDlpGroup) (bool, bool) {
	if cfg.CfgType == 0 {
		key := share.CLUSGroupKey(cfg.Name)
		if value, err := cluster.Get(key); err == nil {
			var group share.CLUSGroup
			_ = nvJsonUnmarshal(key, value, &group)
			cfg.CfgType = group.CfgType
			return true, true
		}
	}
	return false, false
}

func upgradeDlpSensor(cfg *share.CLUSDlpSensor) (bool, bool) {
	if cfg.CfgType == 0 {
		if cfg.Predefine {
			cfg.CfgType = share.SystemDefined
			if cfg.Name == defaultSensorAllDlpRule.Name {
				for _, cdr_list := range cfg.PreRuleList {
					for _, cdr := range cdr_list {
						if cdr.CfgType == 0 {
							cdr.CfgType = share.SystemDefined
						}
					}
				}
				for _, cdr := range cfg.RuleList {
					if cdr.CfgType == 0 {
						cdr.CfgType = share.UserCreated
					}
				}
			}
		} else {
			cfg.CfgType = share.UserCreated
		}
		return true, true
	}
	return false, false
}

func resetDlpCfgType() {
	clusHelper.GetAllDlpSensors()
	clusHelper.GetAllGroups(share.ScopeLocal, access.NewReaderAccessControl())
}

func addFmonRpmPackageDB() {
	// additional file monitor entry
	addPredefinedFileRule(share.FileAccessBehaviorMonitor, "/var/lib/rpm/Packages.db", "")
}

func resetRegistryCfgType() {
	clusHelper.GetAllRegistry(share.ScopeLocal)
}

func initFedScanRevKey() {
	if m := clusHelper.GetFedMembership(); m != nil && (m.FedRole == api.FedRoleMaster || m.FedRole == api.FedRoleJoint) {
		if _, _, err := clusHelper.GetFedScanRevisions(); err == cluster.ErrKeyNotFound {
			var currName string
			var currRev uint64
			var regConfigRev uint64
			var scannedRepoRev uint64
			scannedRegRevs := make(map[string]uint64)
			keys, _ := cluster.GetStoreKeys(share.CLUSScanDataStore)
			for _, key := range keys {
				regName := share.CLUSKeyNthToken(key, 3)
				if !strings.HasPrefix(regName, api.FederalGroupPrefix) {
					continue
				} else if currName == "" {
					currName = regName
					if currName != common.RegistryFedRepoScanName {
						regConfigRev += 1
					}
				} else if regName != currName {
					if currName == common.RegistryFedRepoScanName {
						scannedRepoRev = currRev
					} else {
						scannedRegRevs[currName] = currRev
						regConfigRev += 1
					}
					currName = regName
					currRev = 0
				}
				currRev += 1
			}
			if currName != "" {
				if currName == common.RegistryFedRepoScanName {
					scannedRepoRev = currRev
				} else {
					scannedRegRevs[currName] = currRev
				}
			}
			_ = clusHelper.PutFedScanRevisions(&share.CLUSFedScanRevisions{
				RegConfigRev:   regConfigRev,
				ScannedRegRevs: scannedRegRevs,
				ScannedRepoRev: scannedRepoRev,
			}, nil)
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to read scan revision key")
		}
	}
}

func upgradeDefSecRisksProfiles() {
	acc := access.NewAdminAccessControl()
	// vulnerability profile
	_, _, _ = clusHelper.GetVulnerabilityProfile(share.DefaultVulnerabilityProfileName, acc)
	// compliance profile
	_, _, _ = clusHelper.GetComplianceProfile(share.DefaultComplianceProfileName, acc)
}
