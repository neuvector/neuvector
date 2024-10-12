package kv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	commentDefaultRule1 = "Allow deployments in system namespaces."
	commentDefaultRule2 = "Allow deployments in NeuVector namespace"
)

const (
	commentSsnSensor        = "Sensor for SSN detection"
	commentCcSensor         = "Sensor for Credit Card detection, Credit Card includes visa, master, discover, american express, diner and jcb"
	commentDefaultSensor    = "Hidden default sensor"
	commentLog4shSensor     = "Log4Shell - 0Day RCE exploit found in Log4j"
	commentSpr4shSensor     = "Spring4Shell - 0day RCE Vulnerability found in Java Spring Framework"
	commentDefaultWafSensor = "Hidden default waf sensor"
)

func createDefaultAdminUser() {
	// Default admin user
	admin := share.CLUSUser{
		Fullname:     common.DefaultAdminUser,
		Username:     common.DefaultAdminUser,
		PasswordHash: utils.HashPassword(common.DefaultAdminPass),
		Domain:       "",
		Role:         api.UserRoleAdmin,
		Timeout:      common.DefaultIdleTimeout,
		RoleDomains:  make(map[string][]string),
		Locale:       common.OEMDefaultUserLocale,
		PwdResetTime: time.Now().UTC(),
	}
	value, _ := json.Marshal(admin)
	key := share.CLUSUserKey(common.DefaultAdminUser)
	for {
		if err := cluster.PutIfNotExist(key, value, false); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
		}
		v, err := cluster.Get(key)
		if err == nil && v != nil {
			break
		}
		time.Sleep(time.Second)
	}
}

func createDefaultGroup(name, kind, policyMode string) {
	cg := share.CLUSGroup{
		Name:           name,
		CfgType:        share.Learned,
		Learned_UNUSED: true,
		Reserved:       true,
		Criteria:       []share.CLUSCriteriaEntry{},
		Kind:           kind,
		PolicyMode:     policyMode,
		ProfileMode:    policyMode, // sync to policy mode
	}
	if strings.HasPrefix(name, api.FederalGroupPrefix) {
		cg.CfgType = share.FederalCfg
		cg.Learned_UNUSED = false
	}

	// Write group definition into key-value store. Although we checked the cache,
	// to avoid lock, we still need make sure group doesn't exist.
	if err := clusHelper.PutGroup(&cg, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return
	}
	log.WithFields(log.Fields{"group": name}).Debug("Create group")
}

func _createAllContainerGroup(name string) {
	cg := share.CLUSGroup{
		Name:           name,
		CfgType:        share.UserCreated,
		Learned_UNUSED: false,
		Reserved:       true,
		Criteria: []share.CLUSCriteriaEntry{
			{Key: share.CriteriaKeyWorkload, Value: "*", Op: share.CriteriaOpEqual},
		},
		Kind: share.GroupKindContainer,
	}
	if strings.HasPrefix(name, api.FederalGroupPrefix) {
		cg.CfgType = share.FederalCfg
	}

	// Write group definition into key-value store. Although we checked the cache,
	// to avoid lock, we still need make sure group doesn't exist.
	if err := clusHelper.PutGroup(&cg, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return
	}
	log.WithFields(log.Fields{"group": cg.Name}).Debug("Create group")
}

func createAllContainerGroup() {
	_createAllContainerGroup(api.AllContainerGroup)
}

func createDefaultObjects() {
	createDefaultAdminUser()
	createDefaultGroup(api.LearnedExternal, share.GroupKindExternal, "")
	createDefaultGroup(api.AllHostGroup, share.GroupKindNode, share.PolicyModeLearn)
}

var defaultResponseRules []share.CLUSResponseRule = []share.CLUSResponseRule{
	{
		Event:   share.EventRuntime,
		Actions: []string{share.EventActionWebhook},
		Disable: true,
		CfgType: share.UserCreated,
	},
	{
		Event: share.EventRuntime,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeLevel,
				CondValue: api.LogLevelERR,
			},
		},
		Actions: []string{share.EventActionWebhook},
		Disable: true,
		CfgType: share.UserCreated,
	},
	{
		Event: share.EventRuntime,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeName,
				CondValue: api.EventNameContainerPrivilEscalate,
			},
		},
		Actions: []string{share.EventActionQuarantine},
		Disable: true,
		CfgType: share.UserCreated,
	},
	{
		Event: share.EventCVEReport,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeCVEHigh,
				CondValue: "10",
			},
		},
		Actions: []string{share.EventActionQuarantine},
		Disable: true,
		CfgType: share.UserCreated,
	},
	{
		Event: share.EventEvent,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeName,
				CondValue: api.EventNameContainerQuarantined,
			},
		},
		Actions: []string{share.EventActionWebhook},
		Disable: true,
		CfgType: share.UserCreated,
	},
	{
		Event: share.EventCompliance,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeName,
				CondValue: "D.5.4",
			},
		},
		Actions: []string{share.EventActionWebhook},
		Disable: true,
		CfgType: share.UserCreated,
	},
}

var defaultAdmCtrlResponseRules []share.CLUSResponseRule = []share.CLUSResponseRule{
	{
		Event: share.EventAdmCtrl,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeName,
				CondValue: api.EventNameAdmCtrlK8sReqDenied,
			},
		},
		Actions: []string{share.EventActionWebhook},
		Disable: true,
		CfgType: share.UserCreated,
	},
}

func createResponseRules() {
	clusterLockWait := time.Duration(time.Second * 4)
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	crhs := clusHelper.GetResponseRuleList(share.DefaultPolicyName)
	if len(crhs) == 0 {
		txn := cluster.Transact()
		defer txn.Close()

		crhs = make([]*share.CLUSRuleHead, len(defaultResponseRules))
		for i, r := range defaultResponseRules {
			r.ID = uint32(i + 1)
			crhs[i] = &share.CLUSRuleHead{
				ID:      r.ID,
				CfgType: share.UserCreated,
			}
			_ = clusHelper.PutResponseRuleTxn(share.DefaultPolicyName, txn, &r)
		}
		_ = clusHelper.PutResponseRuleListTxn(share.DefaultPolicyName, txn, crhs)
		if _, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
		}
	}
}

func createDefAdmCtrlRules() {
	var defaultAdmCtrlK8sAllowRules = []*share.CLUSAdmissionRule{
		{
			Category: admission.AdmRuleCatK8s,
			Comment:  commentDefaultRule1,
			Criteria: []*share.CLUSAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyNamespace,
					Op:    share.CriteriaOpContainsAny,
					Value: "kube-system,kube-public,istio-system",
				},
			},
			Disable:  false,
			Critical: true,
			RuleType: api.ValidatingExceptRuleType,
			CfgType:  share.UserCreated,
		},
		{
			Category: admission.AdmRuleCatK8s,
			Comment:  commentDefaultRule2,
			Criteria: []*share.CLUSAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyNamespace,
					Op:    share.CriteriaOpContainsAny,
					Value: resource.NvAdmSvcNamespace,
				},
			},
			Disable:  false,
			Critical: true,
			RuleType: api.ValidatingExceptRuleType,
			CfgType:  share.UserCreated,
		},
	}
	var defaultAdmCtrlOpenshiftAllowRules = []*share.CLUSAdmissionRule{
		{
			Category: admission.AdmRuleCatK8s,
			Comment:  commentDefaultRule1,
			Criteria: []*share.CLUSAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyNamespace,
					Op:    share.CriteriaOpContainsAny,
					Value: "openshift-node,openshift-sdn",
				},
			},
			Disable:  false,
			Critical: true,
			RuleType: api.ValidatingExceptRuleType,
			CfgType:  share.UserCreated,
		},
	}

	lenRules := len(defaultAdmCtrlK8sAllowRules)
	switch orchFlavor {
	case share.FlavorOpenShift:
		lenRules = lenRules + len(defaultAdmCtrlOpenshiftAllowRules)
	}
	defaultRules := make([]*share.CLUSAdmissionRule, 0, lenRules)
	defaultRules = append(defaultRules, defaultAdmCtrlK8sAllowRules...)
	switch orchFlavor {
	case share.FlavorOpenShift:
		defaultRules = append(defaultRules, defaultAdmCtrlOpenshiftAllowRules...)
	}
	arhs := make([]*share.CLUSRuleHead, 0, len(defaultRules))

	for i, r := range defaultRules {
		r.ID = uint32(i + 1)
		_ = clusHelper.PutAdmissionRule(admission.NvAdmValidateType, api.ValidatingExceptRuleType, r)
		arh := &share.CLUSRuleHead{
			ID:      r.ID,
			CfgType: share.UserCreated,
		}
		arhs = append(arhs, arh)
	}
	if err := clusHelper.PutAdmissionRuleList(admission.NvAdmValidateType, api.ValidatingExceptRuleType, arhs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func createDefAdmCtrlResponseRule() {
	var maxID uint32
	crhs := clusHelper.GetResponseRuleList(share.DefaultPolicyName)
	for _, r := range crhs {
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	if crhs == nil {
		crhs = make([]*share.CLUSRuleHead, len(defaultAdmCtrlResponseRules))
	}

	txn := cluster.Transact()
	defer txn.Close()
	for _, r := range defaultAdmCtrlResponseRules {
		r.ID = maxID + 1
		_ = clusHelper.PutResponseRuleTxn(share.DefaultPolicyName, txn, &r)
		crh := &share.CLUSRuleHead{
			ID:      r.ID,
			CfgType: share.UserCreated,
		}
		crhs = append(crhs, crh)
		maxID = r.ID
	}
	_ = clusHelper.PutResponseRuleListTxn(share.DefaultPolicyName, txn, crhs)
	if _, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func CreateAdmCtrlStateByName(svcName string, enable bool) {
	retry := 0
	for retry < 3 {
		modified := false
		var ctrlState *share.CLUSAdmCtrlState
		state, rev := clusHelper.GetAdmissionStateRev(svcName)
		if state != nil && state.CtrlStates != nil {
			ctrlState = state.CtrlStates[admission.NvAdmValidateType]
			if state.Mode == "" {
				state.Mode = share.AdmCtrlModeMonitor
				modified = true
			}
			if state.DefaultAction == "" {
				state.DefaultAction = share.AdmCtrlActionAllow
				modified = true
			}
			if state.AdmClientMode == "" {
				state.AdmClientMode = share.AdmClientModeSvc
				modified = true
			}
		} else {
			state = &share.CLUSAdmissionState{
				Mode:          share.AdmCtrlModeMonitor,
				DefaultAction: share.AdmCtrlActionAllow,
				AdmClientMode: share.AdmClientModeSvc,
				CtrlStates:    make(map[string]*share.CLUSAdmCtrlState),
			}
			modified = true
		}
		state.Enable = enable
		if len(state.NvDeployStatus) == 0 && svcName == resource.NvAdmSvcName {
			state.NvDeployStatus = map[string]bool{
				resource.NvDeploymentName: true,
				svcName:                   false,
			}
			if _, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, svcName); err == nil {
				state.NvDeployStatus[svcName] = true
				modified = true
			}
		}
		if ctrlState == nil || ctrlState.Uri == "" {
			random := fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), time.Now().UTC().UnixNano())
			for _, admType := range admission.GetAdmissionCtrlTypes(share.PlatformKubernetes) {
				ctrlState = &share.CLUSAdmCtrlState{Enable: enable}
				ctrlState.Uri = fmt.Sprintf("%s/%s/%s", admission.UriAdmCtrlPrefix, admType, random)
				state.CtrlStates[admType] = ctrlState
			}
			modified = true
		}
		if modified {
			err := clusHelper.PutAdmissionStateRev(svcName, state, rev)
			if err == nil {
				return
			}
		} else {
			return
		}
		retry++
	}
	log.Error("failed to init AdmCtrl state")
}

func createAdmCtrlRules() {
	if orchPlatform == share.PlatformKubernetes {
		createDefAdmCtrlRules()
		createDefAdmCtrlResponseRule()
		CreateAdmCtrlStateByName(resource.NvAdmSvcName, false)
	}
}
func createDefaultServiceMeshMonitor() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	if !cfg.TapProxymesh {
		cfg.TapProxymesh = true
		_ = clusHelper.PutSystemConfigRev(cfg, rev)
	}
}

var preDlpRuleSsn = []*share.CLUSDlpRule{
	{
		Name: share.DlpRuleNameSsn,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b(?!\\b(\\d)\\1+-?(\\d)\\1+-?(\\d)\\1+\\b)(?!123-?45-?6789|219-?09-?9999|078-?05-?1120)(?!666|000|9\\d{2})\\d{3}-?(?!00)\\d{2}-?(?!0{4})\\d{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcAxp = []*share.CLUSDlpRule{
	{ //american express
		Name: share.DlpRuleNameCcAxp,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b3[47]\\d{2}([ -]?)(?!(\\d)\\2{5}|123456|234567|345678)\\d{6}\\1(?!(\\d)\\3{4}|12345|56789)\\d{5}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcDiscover = []*share.CLUSDlpRule{
	{ //discover
		Name: share.DlpRuleNameCcDiscover,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b6(?:011\\d{2}|5\\d{4}|4[4-9]\\d{3}|22(?:1(?:2[6-9]|[3-9]\\d)|[2-8]\\d{2}|9(?:[01]\\d|2[0-5])))\\d{10}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcMaster = []*share.CLUSDlpRule{
	{ //master
		Name: share.DlpRuleNameCcMaster,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b5([1-5]\\d{2})(?!\\1{3})([ -]?)(?!(\\d)\\3{3})(\\d{4})\\2(?!\\4|(\\d)\\5{3}|1234|2345|3456|5678|7890)(\\d{4})\\2(?!\\6|(\\d)\\7{3}|1234|3456)\\d{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcVisa = []*share.CLUSDlpRule{
	{ //visa
		Name: share.DlpRuleNameCcVisa,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b4(\\d{3})(?!\\1{3})([ -]?)(?!(\\d)\\3{3})(\\d{4})\\2(?!\\4|(\\d)\\5{3}|1234|2345|3456|5678|7890)(\\d{4})\\2(?!\\6|(\\d)\\7{3}|1234|3456)\\d{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcDinerV1 = []*share.CLUSDlpRule{
	{ //diners track1
		Name: share.DlpRuleNameCcDinerV1,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b(36|38)[0-9]{2}(\\s|-)?[0-9]{6}(\\s|-)?[0-9]{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcDinerV2 = []*share.CLUSDlpRule{
	{ //diner track2
		Name: share.DlpRuleNameCcDinerV2,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b30[0-5][0-9](\\s|-)?[0-9]{6}(\\s|-)?[0-9]{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var preDlpRuleCcJcb = []*share.CLUSDlpRule{
	{ //jcb
		Name: share.DlpRuleNameCcJcb,
		Patterns: []share.CLUSDlpCriteriaEntry{
			{
				Key:   "pattern",
				Op:    share.CriteriaOpRegex,
				Value: "\\b3[0-9]{3}(\\s|-)?[0-9]{4}(\\s|-)?[0-9]{4}(\\s|-)?[0-9]{4}\\b",
			},
		},
		CfgType: share.SystemDefined,
	},
}

var SsnSensorDlpRule = &share.CLUSDlpSensor{
	Name:        share.CLUSDlpSsnSensor,
	Groups:      make(map[string]string),
	RuleList:    make(map[string]*share.CLUSDlpRule),
	PreRuleList: make(map[string][]*share.CLUSDlpRule),
	RuleListNames: map[string]string{
		share.DlpRuleNameSsn: share.DlpRuleNameSsn,
	},
	Comment:   commentSsnSensor,
	Predefine: true,
	CfgType:   share.SystemDefined,
}

var CreditCardSensorDlpRule = &share.CLUSDlpSensor{
	Name:        share.CLUSDlpCcSensor,
	Groups:      make(map[string]string),
	RuleList:    make(map[string]*share.CLUSDlpRule),
	PreRuleList: make(map[string][]*share.CLUSDlpRule),
	RuleListNames: map[string]string{
		share.DlpRuleNameCcAxp:      share.DlpRuleNameCcAxp,
		share.DlpRuleNameCcDiscover: share.DlpRuleNameCcDiscover,
		share.DlpRuleNameCcMaster:   share.DlpRuleNameCcMaster,
		share.DlpRuleNameCcVisa:     share.DlpRuleNameCcVisa,
		share.DlpRuleNameCcDinerV1:  share.DlpRuleNameCcDinerV1,
		share.DlpRuleNameCcDinerV2:  share.DlpRuleNameCcDinerV2,
		share.DlpRuleNameCcJcb:      share.DlpRuleNameCcJcb,
	},
	Comment:   commentCcSensor,
	Predefine: true,
	CfgType:   share.SystemDefined,
}

var PreDlpSensors = []*share.CLUSDlpSensor{
	SsnSensorDlpRule,
	CreditCardSensorDlpRule,
}

func CreatePreDlpSensor(withlock bool) {
	if !withlock {
		clusterLockWait := time.Duration(time.Second * 4)
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return
		}
		defer clusHelper.ReleaseLock(lock)

		for _, cdr := range PreDlpSensors {
			dlpsensor := clusHelper.GetDlpSensor(cdr.Name)
			if dlpsensor != nil {
				for _, rname := range dlpsensor.RuleListNames {
					if rname != share.DlpRuleNameCreditCard {
						cdr.RuleListNames[rname] = rname
					}
				}
				_ = clusHelper.PutDlpSensor(cdr, false)
			} else {
				_ = clusHelper.PutDlpSensor(cdr, true)
			}
		}
	} else {
		for _, cdr := range PreDlpSensors {
			dlpsensor := clusHelper.GetDlpSensor(cdr.Name)
			if dlpsensor != nil {
				for _, rname := range dlpsensor.RuleListNames {
					if rname != share.DlpRuleNameCreditCard {
						cdr.RuleListNames[rname] = rname
					}
				}
				_ = clusHelper.PutDlpSensor(cdr, false)
			} else {
				_ = clusHelper.PutDlpSensor(cdr, true)
			}
		}
	}
}

var defaultSensorAllDlpRule = &share.CLUSDlpSensor{
	Name:     share.CLUSDlpDefaultSensor,
	Groups:   make(map[string]string),
	RuleList: make(map[string]*share.CLUSDlpRule),
	PreRuleList: map[string][]*share.CLUSDlpRule{
		share.DlpRuleNameSsn:        preDlpRuleSsn,
		share.DlpRuleNameCcAxp:      preDlpRuleCcAxp,
		share.DlpRuleNameCcDiscover: preDlpRuleCcDiscover,
		share.DlpRuleNameCcMaster:   preDlpRuleCcMaster,
		share.DlpRuleNameCcVisa:     preDlpRuleCcVisa,
		share.DlpRuleNameCcDinerV1:  preDlpRuleCcDinerV1,
		share.DlpRuleNameCcDinerV2:  preDlpRuleCcDinerV2,
		share.DlpRuleNameCcJcb:      preDlpRuleCcJcb,
	},
	Comment:   commentDefaultSensor,
	Predefine: true,
	CfgType:   share.SystemDefined,
}

func CreateDefDlpRules(withlock bool) {
	var idx uint32 = 0

	for _, rulearray := range defaultSensorAllDlpRule.PreRuleList {
		for i, rule := range rulearray {
			if i == 0 {
				if len(rule.Name) >= api.DlpRuleNameMaxLen {
					log.WithFields(log.Fields{"name": rule.Name, "name_len": len(rule.Name)}).Debug("Invalid rule name")
					return
				}
			}

			if len(rule.Patterns) == 0 {
				log.WithFields(log.Fields{"name": rule.Name}).Debug("Failed to creat default rule: dlp rule must have pattern")
				return
			}
			if len(rule.Patterns) > api.DlpRulePatternMaxNum {
				log.WithFields(log.Fields{"name": rule.Name}).Debug("Failed to creat default rule: dlp rule must have no more than 2 patterns")
				return
			}
			for _, pt := range rule.Patterns {
				if pt.Op == share.CriteriaOpRegex || pt.Op == share.CriteriaOpNotRegex {
					if _, err := pcre.Compile(pt.Value, 0); err != nil {
						log.WithFields(log.Fields{"error": err}).Debug("Failed to creat default rule: invalid regex in pattern criteria")
						return
					}
				}
			}
			/*
			 * assign rule id for predefined dlp rule
			 * by design predefined rule id start from
			 * api.MinDlpPredefinedRuleID
			 */
			if i == 0 {
				rule.ID = uint32(api.MinDlpPredefinedRuleID) + idx
				idx++
			}
		}
	}

	if !withlock {
		clusterLockWait := time.Duration(time.Second * 4)
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return
		}
		defer clusHelper.ReleaseLock(lock)

		dlpsensor := clusHelper.GetDlpSensor(defaultSensorAllDlpRule.Name)
		if dlpsensor != nil {
			for rname, cdr := range dlpsensor.RuleList {
				if _, ok := defaultSensorAllDlpRule.RuleList[rname]; !ok {
					defaultSensorAllDlpRule.RuleList[rname] = cdr
				}
			}
			for rname, cdr_list := range dlpsensor.PreRuleList {
				if _, ok := defaultSensorAllDlpRule.PreRuleList[rname]; !ok && rname != share.DlpRuleNameCreditCard {
					defaultSensorAllDlpRule.PreRuleList[rname] = cdr_list
				}
			}
			_ = clusHelper.PutDlpSensor(defaultSensorAllDlpRule, false)
		} else {
			_ = clusHelper.PutDlpSensor(defaultSensorAllDlpRule, true)
		}
	} else {
		dlpsensor := clusHelper.GetDlpSensor(defaultSensorAllDlpRule.Name)
		if dlpsensor != nil {
			for rname, cdr := range dlpsensor.RuleList {
				if _, ok := defaultSensorAllDlpRule.RuleList[rname]; !ok {
					defaultSensorAllDlpRule.RuleList[rname] = cdr
				}
			}
			for rname, cdr_list := range dlpsensor.PreRuleList {
				if _, ok := defaultSensorAllDlpRule.PreRuleList[rname]; !ok && rname != share.DlpRuleNameCreditCard {
					defaultSensorAllDlpRule.PreRuleList[rname] = cdr_list
				}
			}
			_ = clusHelper.PutDlpSensor(defaultSensorAllDlpRule, false)
		} else {
			_ = clusHelper.PutDlpSensor(defaultSensorAllDlpRule, true)
		}
	}
}

func createDefDlpRuleSensor() {
	CreateDefDlpRules(false)
	CreatePreDlpSensor(false)
}

var preWafRuleLog4sh = &share.CLUSWafRule{
	Name: common.GetInternalWafRuleName(share.WafRuleNameLog4sh, share.CLUSWafLog4shSensor),
	Patterns: []share.CLUSWafCriteriaEntry{
		{
			Key:     "pattern",
			Op:      share.CriteriaOpRegex,
			Context: share.DlpPatternContextHEAD,
			Value:   "\\$\\{((\\$|\\{|lower|upper|[a-zA-Z]|\\:|\\-|\\})*[jJ](\\$|\\{|lower|upper|[a-zA-Z]|\\:|\\-|\\})*[nN](\\$|\\{|lower|upper|[a-zA-Z]|\\:|\\-|\\})*[dD](\\$|\\{|lower|upper|[a-zA-Z]|\\:|\\-|\\})*[iI])((\\$|\\{|lower|upper|[a-zA-Z]|\\:|\\-|\\}|\\/)|[ldapLDAPrmiRMInsNShtHTcobCOB])*.*",
		},
	},
	CfgType: share.UserCreated,
}

var Log4shWafSensor = &share.CLUSWafSensor{
	Name:        share.CLUSWafLog4shSensor,
	Groups:      make(map[string]string),
	RuleList:    make(map[string]*share.CLUSWafRule),
	PreRuleList: make(map[string][]*share.CLUSWafRule),
	RuleListNames: map[string]string{
		preWafRuleLog4sh.Name: preWafRuleLog4sh.Name,
	},
	Comment:   commentLog4shSensor,
	Predefine: false,
	CfgType:   share.UserCreated,
}

var preWafRuleSpring4sh = &share.CLUSWafRule{
	Name: common.GetInternalWafRuleName(share.WafRuleNameSpr4sh, share.CLUSWafSpr4shSensor),
	Patterns: []share.CLUSWafCriteriaEntry{
		{
			Key:     "pattern",
			Op:      share.CriteriaOpRegex,
			Context: share.DlpPatternContextBODY,
			Value:   "if.*equals.*request\\.getParameter.*pwd.*getRuntime.*exec.*request\\.getParameter.*cmd.*getInputStream.*read.*print.*classLoader",
		},
	},
	CfgType: share.UserCreated,
}

var Spring4shWafSensor = &share.CLUSWafSensor{
	Name:        share.CLUSWafSpr4shSensor,
	Groups:      make(map[string]string),
	RuleList:    make(map[string]*share.CLUSWafRule),
	PreRuleList: make(map[string][]*share.CLUSWafRule),
	RuleListNames: map[string]string{
		preWafRuleSpring4sh.Name: preWafRuleSpring4sh.Name,
	},
	Comment:   commentSpr4shSensor,
	Predefine: false,
	CfgType:   share.UserCreated,
}

var PreWafSensors = []*share.CLUSWafSensor{
	Log4shWafSensor,
	Spring4shWafSensor,
}

func CreatePreWafSensor(withlock bool) {
	if !withlock {
		clusterLockWait := time.Duration(time.Second * 4)
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return
		}
		defer clusHelper.ReleaseLock(lock)
	}
	for _, cdr := range PreWafSensors {
		wafsensor := clusHelper.GetWafSensor(cdr.Name)
		if wafsensor == nil {
			_ = clusHelper.PutWafSensor(cdr, true)
		}
	}
}

var defaultSensorAllWafRule = &share.CLUSWafSensor{
	Name:   share.CLUSWafDefaultSensor,
	Groups: make(map[string]string),
	RuleList: map[string]*share.CLUSWafRule{
		preWafRuleLog4sh.Name:    preWafRuleLog4sh,
		preWafRuleSpring4sh.Name: preWafRuleSpring4sh,
	},
	PreRuleList: make(map[string][]*share.CLUSWafRule),
	Comment:     commentDefaultWafSensor,
	Predefine:   true,
	CfgType:     share.SystemDefined,
}

func CreateDefWafRules(withlock bool) {
	for _, rule := range defaultSensorAllWafRule.RuleList {
		if len(rule.Name) >= api.DlpRuleNameMaxLen {
			log.WithFields(log.Fields{"name": rule.Name, "name_len": len(rule.Name)}).Debug("Invalid rule name")
			return
		}

		if len(rule.Patterns) == 0 {
			log.WithFields(log.Fields{"name": rule.Name}).Debug("Failed to creat default rule: waf rule must have pattern")
			return
		}
		if len(rule.Patterns) > api.DlpRulePatternMaxNum {
			log.WithFields(log.Fields{"name": rule.Name}).Debug("Failed to creat default rule: waf rule must have no more than 16 patterns")
			return
		}
		for _, pt := range rule.Patterns {
			if pt.Op == share.CriteriaOpRegex || pt.Op == share.CriteriaOpNotRegex {
				if _, err := pcre.Compile(pt.Value, 0); err != nil {
					log.WithFields(log.Fields{"error": err}).Debug("Failed to creat default waf rule: invalid regex in pattern criteria")
					return
				}
			}
		}
	}

	if !withlock {
		clusterLockWait := time.Duration(time.Second * 4)
		lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return
		}
		defer clusHelper.ReleaseLock(lock)
	}
	wafsensor := clusHelper.GetWafSensor(defaultSensorAllWafRule.Name)
	if wafsensor != nil {
		for rname, cdr := range wafsensor.RuleList {
			if _, ok := defaultSensorAllWafRule.RuleList[rname]; !ok {
				defaultSensorAllWafRule.RuleList[rname] = cdr
			}
		}
		for _, rule := range defaultSensorAllWafRule.RuleList {
			if rule.ID == 0 {
				rule.ID = common.GetWafRuleID(defaultSensorAllWafRule)
			}
		}
		_ = clusHelper.PutWafSensor(defaultSensorAllWafRule, false)
	} else {
		for _, rule := range defaultSensorAllWafRule.RuleList {
			rule.ID = common.GetWafRuleID(defaultSensorAllWafRule)
		}
		_ = clusHelper.PutWafSensor(defaultSensorAllWafRule, true)
	}
}

func createDefWafRuleSensor() {
	CreateDefWafRules(false)
	CreatePreWafSensor(false)
}

func CreateDefaultFedGroups() {
	if fedRole, _ := getFedRole(); fedRole == api.FedRoleJoint || fedRole == api.FedRoleMaster {
		createDefaultGroup(api.FederalGroupPrefix+api.AllHostGroup, share.GroupKindNode, share.PolicyModeLearn)
		_createAllContainerGroup(api.FederalGroupPrefix + api.AllContainerGroup)
	}
}

// compress for existing rulelist pre-3.2.1 and 3.2.1
func CompressPolicyRuleList() {
	//since 3.2.1 rulelist key is changed to
	//CLUSPolicyZipRuleListKey from
	//CLUSPolicyRuleListKey
	rulelistkey := share.CLUSPolicyRuleListKey(share.DefaultPolicyName)
	ziprulelistkey := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)

	value, err := cluster.Get(rulelistkey)

	if err != nil || value == nil {
		return
	}

	//check whether value is in gzip format or not
	uzb := utils.GunzipBytes(value)
	if uzb == nil {
		//compress rulelist before put to cluster using new ziprulelistkey
		if err = clusHelper.PutPolicyRuleListZip(ziprulelistkey, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error writing ziprulelistkey to the cluster during upgrade")
			return
		}
	} else {
		//rulelist value in rulelistkey is already compressed, put to cluster using new ziprulelistkey key
		if err = cluster.Put(ziprulelistkey, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error from original key writing ziprulelist to the cluster during upgrade")
			return
		}
	}
	log.Debug("rulelist upgrade to ziprulelistkey successfully")
}

func createDefaultComplianceProfile() {
	cp := share.CLUSComplianceProfile{
		Name:          share.DefaultComplianceProfileName,
		DisableSystem: false,
		Entries:       make(map[string]share.CLUSComplianceProfileEntry),
	}
	if err := clusHelper.PutComplianceProfileIfNotExist(&cp); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

func createDefaultDomains() {
	_ = clusHelper.PutDomain(&share.CLUSDomain{Name: api.DomainContainers, Dummy: true, Tags: []string{}, Labels: map[string]string{}}, nil)
	_ = clusHelper.PutDomain(&share.CLUSDomain{Name: api.DomainNodes, Dummy: true, Tags: []string{}, Labels: map[string]string{}}, nil)
	_ = clusHelper.PutDomain(&share.CLUSDomain{Name: api.DomainImages, Dummy: true, Tags: []string{}, Labels: map[string]string{}}, nil)
}

func setDefaultUnusedGroupAging() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	if cfg == nil {
		return
	}
	cfg.UnusedGroupAging = share.UnusedGroupAgingDefault
	_ = clusHelper.PutSystemConfigRev(cfg, rev)
}

func createDefaultXffSetting() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	if !cfg.XffEnabled {
		cfg.XffEnabled = true
		_ = clusHelper.PutSystemConfigRev(cfg, rev)
	}
}

func EnforceNetSysConfig() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	if cfg.XffEnabled || cfg.DisableNetPolicy || cfg.DetectUnmanagedWl {
		_ = clusHelper.PutSystemConfigRev(cfg, rev)
	}
}

func createDefaultNetServiceSetting() {
	acc := access.NewReaderAccessControl()
	cfg, rev := clusHelper.GetSystemConfigRev(acc)
	cfg.NetServiceStatus = false
	cfg.NetServicePolicyMode = share.PolicyModeLearn
	_ = clusHelper.PutSystemConfigRev(cfg, rev)
}

func createDefaultVulnerabilityProfile() {
	key := share.CLUSVulnerabilityProfileKey(share.DefaultVulnerabilityProfileName)
	profile := &share.CLUSVulnerabilityProfile{
		Name:    share.DefaultVulnerabilityProfileName,
		Entries: make([]*share.CLUSVulnerabilityProfileEntry, 0),
	}
	value, _ := json.Marshal(profile)
	_ = cluster.Put(key, value)
}

func createDefaultPwdProfile() {
	key := share.CLUSPwdProfileKey(share.CLUSDefPwdProfileName)
	profile := &share.CLUSPwdProfile{
		Name:                        share.CLUSDefPwdProfileName,
		Comment:                     share.CLUSDefPwdProfileName,
		MinLen:                      8,
		MinUpperCount:               1,
		MinLowerCount:               1,
		MinDigitCount:               1,
		MinSpecialCount:             0,
		EnablePwdExpiration:         false,
		PwdExpireAfterDays:          0,
		EnablePwdHistory:            false,
		PwdHistoryCount:             0,
		EnableBlockAfterFailedLogin: true,
		BlockAfterFailedCount:       5,
		BlockMinutes:                60,
	}
	value, _ := json.Marshal(profile)
	_ = cluster.Put(key, value)

	cfg := &share.CLUSActivePwdProfileConfig{
		Name: share.CLUSDefPwdProfileName,
	}
	value, _ = json.Marshal(cfg)
	_ = cluster.Put(share.CLUSConfigPwdProfileStore, value)

	// for rolling upgrade, enumerate all users & set their PwdResetTime to now
	acc := access.NewAdminAccessControl()
	users := clusHelper.GetAllUsers(acc)
	for _, user := range users {
		user.FailedLoginCount = 0
		user.BlockLoginSince = time.Time{}
		user.PwdResetTime = time.Now().UTC()
		_ = clusHelper.PutUser(user)
	}
}

func addAdmCtrlStateStatusUri() {
	var ctrlState *share.CLUSAdmCtrlState
	state, rev := clusHelper.GetAdmissionStateRev(resource.NvAdmSvcName)
	if state != nil && state.CtrlStates != nil {
		ctrlState = state.CtrlStates[admission.NvAdmValidateType]
		ctrlState.NvStatusUri = strings.Replace(ctrlState.Uri, "validate", admission.UriAdmCtrlNvStatus, 1)
		if err := clusHelper.PutAdmissionStateRev(resource.NvAdmSvcName, state, rev); err == nil {
			return
		}
	}
	log.Error("failed to update AdmCtrl state")
}

func addPredefinedFileRule(behavior, path, regexStr string) {
	tm := time.Now().UTC()
	fmps := clusHelper.GetAllFileMonitorProfile()
	for group, fmp := range fmps {
		if !utils.DoesGroupHavePolicyMode(group) {
			continue
		}

		found := false
		for _, rule := range fmp.Filters {
			if rule.Path == path {
				found = true
				break
			}
		}

		if !found {
			// file monitor rule
			flt := share.CLUSFileMonitorFilter{Behavior: behavior, Path: path, Regex: regexStr}
			flt.Filter = common.FsmonFilterToRest(flt.Path, flt.Regex)
			fmp.Filters = append(fmp.Filters, flt)
			_ = clusHelper.PutFileMonitorProfile(group, fmp, 0)

			// file access rule
			far, rev := clusHelper.GetFileAccessRule(group) // associated with "mon"
			if far == nil {
				far = &share.CLUSFileAccessRule{
					Filters:    make(map[string]*share.CLUSFileAccessFilterRule),
					FiltersCRD: make(map[string]*share.CLUSFileAccessFilterRule),
				}
			}

			idx := utils.FilterIndexKey(flt.Path, flt.Regex)
			far.Filters[idx] = &share.CLUSFileAccessFilterRule{Apps: make([]string, 0), CreatedAt: tm, UpdatedAt: tm, Behavior: behavior}
			_ = clusHelper.PutFileAccessRule(group, far, rev)
		}
	}
}
