package nvsysadmission

import (
	"encoding/json"
	"os"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"

	corev1 "k8s.io/api/core/v1"
)

const (
	AdmCtrlActionAllow = iota
	AdmCtrlActionDeny
)

const (
	AuditLogPropMessage         = "Message"
	AuditLogPropUser            = "User"
	AuditLogPropImage           = "Image"
	AuditLogPropImageID         = "ImageID"
	AuditLogPropRegistry        = "Registry"
	AuditLogPropRepository      = "Repository"
	AuditLogPropTag             = "Tag"
	AuditLogPropBaseOS          = "BaseOS"
	AuditLogPropCriticalVulsCnt = "CriticalVulsCnt"
	AuditLogPropHighVulsCnt     = "HighVulsCnt"
	AuditLogPropMedVulsCnt      = "MedVulsCnt"
	AuditLogPropNamespace       = "Namespace"
	AuditLogPropFirstLogAt      = "FirstLogAt"
	AuditLogPropLastLogAt       = "LastLogAt"
	AuditLogPropPVCName         = "PVCName"
	AuditLogPVCStorageClassName = "PVCNameStorageClassName"
)

type ScannedImageSummary struct {
	ImageID             string
	BaseOS              string
	Registry            string
	RegName             string
	Digest              string
	Author              string
	ScannedAt           time.Time
	Result              int32
	CriticalVuls        int
	HighVuls            int
	MedVuls             int
	CriticalVulsWithFix int
	HighVulsWithFix     int
	VulScore            float32
	VulNames            utils.Set
	Scanned             bool
	Signed              bool
	Verifiers           []string
	RunAsRoot           bool
	EnvVars             map[string]string
	Labels              map[string]string
	CriticalVulInfo     map[string]share.CLUSScannedVulInfo // key is vul name
	HighVulInfo         map[string]share.CLUSScannedVulInfo // key is vul name
	MediumVulInfo       map[string]share.CLUSScannedVulInfo // key is vul name
	LowVulInfo          []share.CLUSScannedVulInfoSimple    // only care about score
	SetIDPermCnt        int                                 // setuid and set gid from image scan
	SecretsCnt          int                                 // secrets from image scan
	Modules             []*share.ScanModule
}

type K8sContainerType string

const (
	K8sStandardContainer  K8sContainerType = "standard"
	K8sInitContainer      K8sContainerType = "init"
	K8SEphemeralContainer K8sContainerType = "ephemeral"
)

type LinuxCapabilities struct {
	Add  []string
	Drop []string
}

type SELinuxOptions struct {
	Type string
	User string
	Role string
}

type AdmContainerInfo struct {
	Name                     string                     `json:"name"`
	Image                    string                     `json:"image"` // original spec.container.image value in the yaml file
	ImageRegistry            utils.Set                  `json:"image_registry"`
	ImageRepo                string                     `json:"image_repo"`
	ImageTag                 string                     `json:"image_tag"`
	Privileged               bool                       `json:"privileged,omitempty"`
	RunAsUser                int64                      `json:"run_as_user,omitempty"`
	VolMounts                utils.Set                  `json:"vol_mounts,omitempty"`
	EnvVars                  map[string]string          `json:"env_vars,omitempty"`
	EnvSecrets               []share.ScanSecretLog      `json:"env_secrets,omitempty"`
	HostNetwork              bool                       `json:"host_network,omitempty"`
	HostPID                  bool                       `json:"host_pid,omitempty"`
	HostIPC                  bool                       `json:"host_ipc,omitempty"`
	AllowPrivilegeEscalation bool                       `json:"allow_privilege_escalation,omitempty"`
	CpuLimits                float64                    `json:"cpu_limits"`
	CpuRequests              float64                    `json:"cpu_requests"`
	MemoryLimits             int64                      `json:"memory_limits"`
	MemoryRequests           int64                      `json:"memory_requests"`
	Type                     K8sContainerType           `json:"type"`
	Capabilities             LinuxCapabilities          `json:"capabilities"`
	Volumes                  []corev1.Volume            `json:"volumes"`
	HostPorts                []int32                    `json:"host_ports"`
	AppArmorProfile          *string                    `json:"app_armor_profile"`
	SELinuxOptions           SELinuxOptions             `json:"se_linux_options"`
	ProcMount                string                     `json:"proc_mount"`
	SeccompProfileType       *corev1.SeccompProfileType `json:"seccomp_profile"`
	Sysctls                  []string                   `json:"sysctls"`
	RunAsNonRoot             bool                       `json:"run_as_non_root"`
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

type AdmCtrlMatchedImageInfo struct {
	ImageScanned    bool
	ImageID         string // starting from this field, the following fields are available when the scan result for the image is available
	Registry        string
	BaseOS          string
	CriticalVulsCnt int // critical vuls # of the image that gets allow/deny action or monitor
	HighVulsCnt     int // high     vuls # of the image that gets allow/deny action or monitor
	MedVulsCnt      int // medium   vuls # of the image that gets allow/deny action or monitor
}

// AdmCtrlMatchedResult is for each matched occurrence.
// One rule could be matched multiple times when there are multiple containers in a request
type AdmCtrlMatchedResult struct {
	ContainerImage  string
	RuleID          uint32                  // matched rule's id
	IsFedRule       bool                    // whether the matched rule is a fed rule
	IsDenyRuleType  bool                    // whether the matched rule is a deny rule
	IsMatchMonitor  bool                    // whether the matched deny rule gets "monitor" action (neither "allow" nor "deny")
	IsCriticalMatch bool                    // whether this result is from a matched rule that decides "allow"/"deny" action
	Disabled        bool                    // whether the matched rule is a disabled rule. for assessment, disabled rules are evaluated as well.
	RuleDetails     string                  // matched rule's criteria description in plain-text
	RuleMode        string                  // matched deny rule's per-rule mode. could be ""/"monitor"/"protect"
	ImageInfo       AdmCtrlMatchedImageInfo // info of the image that matches a rule
	RuleCfgType     share.TCfgType
}

func (r AdmCtrlMatchedResult) IsMatchedMode(globalMode, matchedMode string) bool {
	if r.RuleMode == matchedMode || (r.RuleMode == "" && globalMode == matchedMode) {
		return true
	}
	return false
}

type AdmCtrlContainerImageInfo struct {
	ImageScanned    bool   // true when at least one image scan summary says so
	Name            string // container name specified in yaml
	Image           string // the image specified in yaml
	Repository      string
	Tag             string
	CriticalVulsCnt int // the max critical vuls # in the (multiple) image scan summary
	HighVulsCnt     int // the max high     vuls # in the (multiple) image scan summary
	MedVulsCnt      int // the max medium   vuls # in the (multiple) image scan summary
}

type AdmCtrlAssessResult struct { // it is for a container-image or pvc
	ContainerImageInfo AdmCtrlContainerImageInfo
	AssessAction       string                  // ""/"allow"/"deny" : action matched for this assessment(container or pvc)
	CriticalMatch      *AdmCtrlMatchedResult   // the match that decides "allow"/"deny" action (not including deny/monitor)
	MatchedResults     []*AdmCtrlMatchedResult // list of matched rules' info for this container. a rule could matched without action taken(i.e. "monitor").
}

type AdmCtrlReqEvalResult struct { // it is for an admission control request
	ReqAction           string // ""/"allow"/"deny" : action matched for this request
	User                string
	Msg                 string
	UnscannedImages     string                 // those images in the request that not scanned, no matter what the container-image match result is
	AllContainerImages  string                 // all images in the request
	ContainersInReq     int                    // total containers in this request
	AllCriticalVulsCnt  int                    // critical vuls count found for all containers in the request
	AllHighVulsCnt      int                    // high     vuls count found for all containers in the request
	AllMedVulsCnt       int                    // medium   vuls count found for all containers in the request
	CriticalAssessment  *AdmCtrlAssessResult   // the container/pvc assessment that decides "allow"/"deny" action (not including deny/monitor)
	AssessResults       []*AdmCtrlAssessResult // list of assessment match results. one entry per-container/pvc
	PVCName             string
	PVCStorageClassName string
}

type AdmResObject struct {
	ValidUntil         int64 // seconds since the epoch
	Kind               string
	Name               string
	Namespace          string
	UserName           string
	Groups             utils.Set
	OwnerUIDs          []string
	Labels             map[string]string
	Annotations        map[string]string
	AllContainers      [3][]*AdmContainerInfo // containers info in this resource object in containers, initContainers, ephemeralContainers order
	ServiceAccountName string
}

type AdmCtrlEvalContext struct {
	RootAvail       bool
	ForTesting      bool
	ContainersInReq int
	GlobalMode      string
	AdmCtrlType     string
	ReqActionSoFar  string
}

const (
	ReqAllowed = iota
	ReqDenied
	ReqErrored
	ReqIgnored
)

var admRuleTypeOptions map[string]*api.RESTAdmCatOptions           // key is rules type, like "deny", "exception"
var admK8sDenyRuleOptions map[string]*api.RESTAdmissionRuleOption  // key is criterion name
var admK8sExcptRuleOptions map[string]*api.RESTAdmissionRuleOption // key is criterion name

var allSetOps = []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan}
var setOps1 = []string{share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny}
var boolOps = []string{"true", "false"}
var boolTrueOp = []string{"true"}
var pssPolicies = []string{share.PssPolicyRestricted, share.PssPolicyBaseline}
var verifierOps = []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny}

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
				Name: share.CriteriaKeyUser,
				Ops: []string{share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny,
					share.CriteriaOpRegex, share.CriteriaOpNotRegex},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyK8sGroups: &api.RESTAdmissionRuleOption{
				Name: share.CriteriaKeyK8sGroups,
				Ops: []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny,
					share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
					share.CriteriaOpRegex, share.CriteriaOpNotRegex},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyLabels: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyLabels,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyAnnotations: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyAnnotations,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
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
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVECriticalCount: &api.RESTAdmissionRuleOption{
			// 	Name:       share.CriteriaKeyCVECriticalCount,
			// 	Ops:        []string{share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc:   api.MatchSrcImage,
			// 	SubOptions: subOptions,
			// },
			share.CriteriaKeyCVEHighCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEHighCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVEHighCountNoCritical: &api.RESTAdmissionRuleOption{
			// 	Name:       share.CriteriaKeyCVEHighCountNoCritical,
			// 	Ops:        []string{share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc:   api.MatchSrcImage,
			// 	SubOptions: subOptions,
			// },
			share.CriteriaKeyCVEMediumCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEMediumCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVECriticalWithFixCount: &api.RESTAdmissionRuleOption{
			// 	Name:       share.CriteriaKeyCVECriticalWithFixCount,
			// 	Ops:        []string{share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc:   api.MatchSrcImage,
			// 	SubOptions: subOptions,
			// },
			share.CriteriaKeyCVEHighWithFixCount: &api.RESTAdmissionRuleOption{
				Name:       share.CriteriaKeyCVEHighWithFixCount,
				Ops:        []string{share.CriteriaOpBiggerEqualThan},
				MatchSrc:   api.MatchSrcImage,
				SubOptions: subOptions,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVEHighWithFixCountNoCritical: &api.RESTAdmissionRuleOption{
			// 	Name:       share.CriteriaKeyCVEHighWithFixCountNoCritical,
			// 	Ops:        []string{share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc:   api.MatchSrcImage,
			// 	SubOptions: subOptions,
			// },
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
			},*/
			share.CriteriaKeyImageSigned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageSigned,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
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
			share.CriteriaKeyHasPssViolation: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyHasPssViolation,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   pssPolicies,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyCustomPath: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCustomPath,
				Ops:      []string{},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeySaBindRiskyRole: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeySaBindRiskyRole,
				Ops:      []string{share.CriteriaOpContainsTagAny},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyImageVerifiers: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageVerifiers,
				Ops:      verifierOps,
				MatchSrc: api.MatchSrcImage,
			},
			share.CriteriaKeyStorageClassName: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyStorageClassName,
				Ops:      setOps1,
				MatchSrc: api.MatchSrcYaml,
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
				Name: share.CriteriaKeyUser,
				Ops: []string{share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny,
					share.CriteriaOpRegex, share.CriteriaOpNotRegex},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyK8sGroups: &api.RESTAdmissionRuleOption{
				Name: share.CriteriaKeyK8sGroups,
				Ops: []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny,
					share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
					share.CriteriaOpRegex, share.CriteriaOpNotRegex},
				MatchSrc: api.MatchSrcYaml,
			},
			share.CriteriaKeyLabels: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyLabels,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcBoth,
			},
			share.CriteriaKeyAnnotations: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyAnnotations,
				Ops:      allSetOps,
				MatchSrc: api.MatchSrcYaml,
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
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVECriticalCount: &api.RESTAdmissionRuleOption{
			// 	Name:     share.CriteriaKeyCVECriticalCount,
			// 	Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc: api.MatchSrcImage,
			// },
			share.CriteriaKeyCVEHighCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEHighCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVEHighCountNoCritical: &api.RESTAdmissionRuleOption{
			// 	Name:     share.CriteriaKeyCVEHighCountNoCritical,
			// 	Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc: api.MatchSrcImage,
			// },
			share.CriteriaKeyCVEMediumCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEMediumCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVECriticalWithFixCount: &api.RESTAdmissionRuleOption{
			// 	Name:     share.CriteriaKeyCVECriticalWithFixCount,
			// 	Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc: api.MatchSrcImage,
			// },
			share.CriteriaKeyCVEHighWithFixCount: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyCVEHighWithFixCount,
				Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
				MatchSrc: api.MatchSrcImage,
			},
			// NVSHAS-8242: temporary reversion
			// share.CriteriaKeyCVEHighWithFixCountNoCritical: &api.RESTAdmissionRuleOption{
			// 	Name:     share.CriteriaKeyCVEHighWithFixCountNoCritical,
			// 	Ops:      []string{share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan},
			// 	MatchSrc: api.MatchSrcImage,
			// },
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
			},*/
			share.CriteriaKeyImageSigned: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageSigned,
				Ops:      []string{share.CriteriaOpEqual},
				Values:   boolOps,
				MatchSrc: api.MatchSrcImage,
			},
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
			share.CriteriaKeyImageVerifiers: &api.RESTAdmissionRuleOption{
				Name:     share.CriteriaKeyImageVerifiers,
				Ops:      verifierOps,
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

func GetCustomCriteriaOptions() []*api.RESTAdminCustomCriteriaOptions {
	options := make([]*api.RESTAdminCustomCriteriaOptions, 0)

	// add key type (when no value is selected)
	options = append(options, &api.RESTAdminCustomCriteriaOptions{
		ValueType: "key",
		Ops:       []string{share.CriteriaOpExist, share.CriteriaOpNotExist},
	})

	// add string type
	options = append(options, &api.RESTAdminCustomCriteriaOptions{
		ValueType: "string",
		Ops:       []string{share.CriteriaOpExist, share.CriteriaOpNotExist, share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan},
	})

	// add number type
	options = append(options, &api.RESTAdminCustomCriteriaOptions{
		ValueType: "number",
		Ops:       []string{share.CriteriaOpExist, share.CriteriaOpNotExist, share.CriteriaOpEqual, share.CriteriaOpNotEqual, share.CriteriaOpBiggerEqualThan, share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan},
	})

	// add boolean type
	options = append(options, &api.RESTAdminCustomCriteriaOptions{
		ValueType: "boolean",
		Ops:       []string{share.CriteriaOpExist, share.CriteriaOpNotExist, share.CriteriaOpEqual},
		Values:    boolOps,
	})

	return options
}

func GetCustomCriteriaTemplates() []*api.RESTAdminCriteriaTemplate {
	templates := make([]*api.RESTAdminCriteriaTemplate, 0)

	sources := map[string]string{
		"podTemplate": "/etc/neuvector/templates/podTemplate.json",
	}

	for k, v := range sources {
		bytesData, err := os.ReadFile(v)
		if err != nil {
			return templates
		}

		template := api.RESTAdminCriteriaTemplate{
			Kind:    k,
			RawJson: string(bytesData),
		}

		templates = append(templates, &template)
	}
	return templates
}
