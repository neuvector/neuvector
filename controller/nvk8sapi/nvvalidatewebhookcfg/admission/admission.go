package nvsysadmission

import (
	"encoding/json"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	AdmCtrlActionAllow = iota
	AdmCtrlActionDeny
)

const (
	AuditLogPropMessage     = "Message"
	AuditLogPropUser        = "User"
	AuditLogPropImage       = "Image"
	AuditLogPropImageID     = "ImageID"
	AuditLogPropRegistry    = "Registry"
	AuditLogPropRepository  = "Repository"
	AuditLogPropTag         = "Tag"
	AuditLogPropBaseOS      = "BaseOS"
	AuditLogPropHighVulsCnt = "HighVulsCnt"
	AuditLogPropMedVulsCnt  = "MedVulsCnt"
	AuditLogPropNamespace   = "Namespace"
	AuditLogPropFirstLogAt  = "FirstLogAt"
	AuditLogPropLastLogAt   = "LastLogAt"
)

type ScannedImageSummary struct {
	ImageID         string
	BaseOS          string
	Registry        string
	RegName         string
	Digest          string
	Author          string
	ScannedAt       time.Time
	Result          int32
	HighVuls        int
	MedVuls         int
	HighVulsWithFix int
	VulScore        float32
	VulNames        utils.Set
	Scanned         bool
	Signed          bool
	RunAsRoot       bool
	EnvVars         map[string]string
	Labels          map[string]string
	HighVulInfo     map[string]share.CLUSScannedVulInfo // key is vul name
	MediumVulInfo   map[string]share.CLUSScannedVulInfo // key is vul name
	LowVulInfo      []share.CLUSScannedVulInfoSimple    // only care about score
	SetIDPermCnt    int                                 // setuid and set gid from image scan
	SecretsCnt      int                                 // secrets from image scan
	Modules         []*share.ScanModule
}

type AdmContainerInfo struct {
	Name                     string                `json:"name"`
	Image                    string                `json:"image"` // original spec.container.image value in the yaml file
	ImageRegistry            utils.Set             `json:"image_registry"`
	ImageRepo                string                `json:"image_repo"`
	ImageTag                 string                `json:"image_tag"`
	Privileged               bool                  `json:"privileged,omitempty"`
	RunAsUser                int64                 `json:"run_as_user,omitempty"`
	VolMounts                utils.Set             `json:"vol_mounts,omitempty"`
	EnvVars                  map[string]string     `json:"env_vars,omitempty"`
	EnvSecrets               []share.ScanSecretLog `json:"env_secrets,omitempty"`
	HostNetwork              bool                  `json:"host_network,omitempty"`
	HostPID                  bool                  `json:"host_pid,omitempty"`
	HostIPC                  bool                  `json:"host_ipc,omitempty"`
	AllowPrivilegeEscalation bool                  `json:"allow_privilege_escalation,omitempty"`
	CpuLimits                float64               `json:"cpu_limits"`
	CpuRequests              float64               `json:"cpu_requests"`
	MemoryLimits             int64                 `json:"memory_limits"`
	MemoryRequests           int64                 `json:"memory_requests"`
}

type JSONAdmContainerInfo struct { // for debugging purpose only
	Name                     string            `json:"name"`
	Image                    string            `json:"image"`
	ImageRegistry            []string          `json:"image_registry"`
	ImageRepo                string            `json:"image_repo"`
	ImageTag                 string            `json:"image_tag"`
	Privileged               bool              `json:"privileged,omitempty"`
	RunAsUser                int64             `json:"run_as_user,omitempty"`
	VolMounts                []string          `json:"vol_mounts,omitempty"`
	EnvVars                  map[string]string `json:"env_vars,omitempty"`
	HostNetwork              bool              `json:"host_network,omitempty"`
	HostPID                  bool              `json:"host_pid,omitempty"`
	HostIPC                  bool              `json:"host_ipc,omitempty"`
	AllowPrivilegeEscalation bool              `json:"allow_privilege_escalation,omitempty"`
}

type AdmUriState struct {
	AdmType       string // ex: NvAdmValidateType
	Category      string // ex: AdmRuleCatK8s
	Mode          string // "monitor" or "protect". Empty string means monitor as well
	Enabled       bool
	DefaultAction int // AdmCtrlActionAllow or AdmCtrlActionDeny
}

type AdmResult struct { // AdmResult is per-image
	MatchDeny       bool
	FinalDeny       bool
	ImageNotScanned bool
	NoLogging       bool
	MatchFedRule    bool
	RuleID          uint32
	RuleCategory    string
	RuleCfgType     share.TCfgType
	User            string
	AdmRule         string
	Msg             string
	Image           string // the image specified in yaml
	ImageID         string // starting from this field, the following fields are available when the scan result for the image is available
	Registry        string
	Repository      string
	Tag             string
	BaseOS          string
	UnscannedImages string
	MatchedSource   string
	HighVulsCnt     int
	MedVulsCnt      int
}

type AdmResObject struct {
	ValidUntil int64 // seconds since the epoch
	Kind       string
	Name       string
	Namespace  string
	UserName   string
	Groups     utils.Set
	OwnerUIDs  []string
	Labels     map[string]string
	Containers []*AdmContainerInfo // related containers info in this resource object
	//AdmResults map[string]*AdmResult // key is image repo. comment out because we do not re-use the matching result of owners anymore
}

type matchState int
type AdmMatchData struct {
	RootAvail  bool
	MatchState matchState
}

const (
	ReqAllowed = iota
	ReqDenied
	ReqErrored
	ReqIgnored
)

const (
	MatchedNone  matchState = 0
	MatchedAllow matchState = 1
	MatchedDeny  matchState = 2
)

//var admMutatingKind = resource.RscKindMutatingWebhookConfiguration

var admRuleTypeOptions map[string]*api.RESTAdmCatOptions           // key is rules type, like "deny", "exception"
var admK8sDenyRuleOptions map[string]*api.RESTAdmissionRuleOption  // key is criterion name
var admK8sExcptRuleOptions map[string]*api.RESTAdmissionRuleOption // key is criterion name

var allSetOps = []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan}
var setOps1 = []string{share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny}
var boolOps = []string{"true", "false"}
var boolTrueOp = []string{"true"}

func (info AdmContainerInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(*newJSONAdmContainerInfo(&info))
}

func newJSONAdmContainerInfo(cinfo *AdmContainerInfo) *JSONAdmContainerInfo {
	return &JSONAdmContainerInfo{
		Name:                     cinfo.Name,
		Image:                    cinfo.Image,
		ImageRegistry:            cinfo.ImageRegistry.ToStringSlice(),
		ImageRepo:                cinfo.ImageRepo,
		ImageTag:                 cinfo.ImageTag,
		Privileged:               cinfo.Privileged,
		RunAsUser:                cinfo.RunAsUser,
		VolMounts:                cinfo.VolMounts.ToStringSlice(),
		EnvVars:                  cinfo.EnvVars,
		HostNetwork:              cinfo.HostNetwork,
		HostPID:                  cinfo.HostPID,
		HostIPC:                  cinfo.HostIPC,
		AllowPrivilegeEscalation: cinfo.AllowPrivilegeEscalation,
	}
}

func getAdmK8sDenyRuleOptions() map[string]*api.RESTAdmissionRuleOption {
	if admK8sDenyRuleOptions == nil {
		subOptions := map[string]*api.RESTAdmissionRuleOption{
			share.SubCriteriaPublishDays: &api.RESTAdmissionRuleOption{
				Name: share.SubCriteriaPublishDays,
				Ops:  []string{share.CriteriaOpBiggerEqualThan},
			},
		}
		subOptions2 := map[string]*api.RESTAdmissionRuleOption{
			share.SubCriteriaCount: &api.RESTAdmissionRuleOption{
				Name: share.SubCriteriaCount,
				Ops:  []string{share.CriteriaOpBiggerEqualThan},
			},
		}
		admK8sDenyRuleOptions = map[string]*api.RESTAdmissionRuleOption{
			share.CriteriaKeyImage: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImage,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyImageRegistry: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageRegistry,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyNamespace: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyNamespace,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyUser: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyUser,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyK8sGroups: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyK8sGroups,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyLabels: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyLabels,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyMountVolumes: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyMountVolumes,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyEnvVars: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyEnvVars,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyCVENames: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVENames,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyCVEHighCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEHighCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			share.CriteriaKeyCVEMediumCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEMediumCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			share.CriteriaKeyCVEHighWithFixCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEHighWithFixCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			share.CriteriaKeyCVEScoreCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEScoreCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions2,
			},
			/*share.CriteriaKeyCVEScore: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEScore,
				Ops:      []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},*/
			share.CriteriaKeyImageScanned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageScanned,
				Ops:      []string{share.CriteriaOpEqual},
				MatchSrc: api.MatchSrcImage,
				Values:   boolOps,
			},
			share.CriteriaKeyRunAsPrivileged: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyRunAsPrivileged,
				Ops:      []string{share.CriteriaOpEqual},
				MatchSrc: api.MatchSrcYaml,
				Values:   boolOps,
			},
			share.CriteriaKeyRunAsRoot: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyRunAsRoot,
				Ops:      []string{share.CriteriaOpEqual},
				MatchSrc: api.MatchSrcBoth,
				Values:   boolOps,
			},
			/*share.CriteriaKeyBaseImage: &api.RESTAdmissionRuleOption{ //->
				Name:     share.CriteriaKeyBaseImage,
				Ops:      []string{share.CriteriaOpEqual, share.CriteriaOpNotEqual},
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyImageSigned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageSigned,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},*/
			share.CriteriaKeyImageCompliance: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageCompliance,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyEnvVarSecrets: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyEnvVarSecrets,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyImageNoOS: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageNoOS,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeySharePidWithHost: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeySharePidWithHost,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyShareIpcWithHost: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyShareIpcWithHost,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyShareNetWithHost: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyShareNetWithHost,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyAllowPrivEscalation: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyAllowPrivEscalation,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolTrueOp,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyPspCompliance: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyPspCompliance,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolTrueOp,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyRequestLimit: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyRequestLimit,
				Ops:      []string{},
				MatchSrc: api.MatchSrcYaml,
				SubOptions: map[string]*api.RESTAdmissionRuleOption{
					share.SubCriteriaCpuRequest: &api.RESTAdmissionRuleOption{
						Name: share.SubCriteriaCpuRequest,
						Ops:  []string{share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan},
					},
					share.SubCriteriaCpuLimit: &api.RESTAdmissionRuleOption{
						Name: share.SubCriteriaCpuLimit,
						Ops:  []string{share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan},
					},
					share.SubCriteriaMemoryRequest: &api.RESTAdmissionRuleOption{
						Name: share.SubCriteriaMemoryRequest,
						Ops:  []string{share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan},
					},
					share.SubCriteriaMemoryLimit: &api.RESTAdmissionRuleOption{
						Name: share.SubCriteriaMemoryLimit,
						Ops:  []string{share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan},
					},
				},
			},
			share.CriteriaKeyModules: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyModules,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcImage,
			},
		}
	}
	return admK8sDenyRuleOptions
}

func getAdmK8sExceptRuleOptions() map[string]*api.RESTAdmissionRuleOption { // for allow rules
	if admK8sExcptRuleOptions == nil {
		admK8sExcptRuleOptions = map[string]*api.RESTAdmissionRuleOption{
			share.CriteriaKeyImage: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImage,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyImageRegistry: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageRegistry,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyNamespace: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyNamespace,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyUser: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyUser,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyK8sGroups: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyK8sGroups,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyLabels: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyLabels,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyMountVolumes: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyMountVolumes,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyEnvVars: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyEnvVars,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyCVENames: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVENames,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyCVEHighCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEHighCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyCVEMediumCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEMediumCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyCVEHighWithFixCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEHighWithFixCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			/*share.CriteriaKeyCVEScore: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEScore,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},*/
			share.CriteriaKeyImageScanned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageScanned,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyRunAsPrivileged: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyRunAsPrivileged,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyRunAsRoot: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyRunAsRoot,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcBoth,
			},
			/*share.CriteriaKeyBaseImage: &api.RESTAdmissionRuleOption{ //->
				Name:     share.CriteriaKeyBaseImage,
				Ops:      []string{share.CriteriaOpEqual, share.CriteriaOpNotEqual},
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyImageSigned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageSigned,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},*/
			share.CriteriaKeyImageCompliance: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageCompliance,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyEnvVarSecrets: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyEnvVarSecrets,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyModules: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyModules,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcImage,
			},
		}
	}
	return admK8sExcptRuleOptions
}

func GetAdmRuleTypeOptions(ruleType string) *api.RESTAdmCatOptions {
	if admRuleTypeOptions == nil {
		admRuleTypeOptions = map[string]*api.RESTAdmCatOptions{
			api.ValidatingDenyRuleType:   &api.RESTAdmCatOptions{},
			api.ValidatingExceptRuleType: &api.RESTAdmCatOptions{},
		}
		for _, admType := range admission.GetAdmissionCtrlTypes(share.PlatformKubernetes) {
			switch admType {
			case admission.NvAdmValidateType:
				admRuleTypeOptions[api.ValidatingDenyRuleType].K8sOptions = &api.RESTAdmRuleOptions{RuleOptions: getAdmK8sDenyRuleOptions()}
				admRuleTypeOptions[api.ValidatingExceptRuleType].K8sOptions = &api.RESTAdmRuleOptions{RuleOptions: getAdmK8sExceptRuleOptions()}
			}
		}
	}
	return admRuleTypeOptions[ruleType]
}
