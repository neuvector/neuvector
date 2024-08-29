package resource

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neuvector/k8s"
	log "github.com/sirupsen/logrus"
	admregv1 "k8s.io/api/admissionregistration/v1"
	admregv1b1 "k8s.io/api/admissionregistration/v1beta1"
	apiv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1b1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1b1 "k8s.io/api/rbac/v1beta1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1b1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/utils"
)

const kubeWatchRetry = time.Second * 5

const (
	k8sAllApiGroup                = "*"
	k8sAdmApiGroup                = "admissionregistration.k8s.io"
	k8sCrdApiGroup                = "apiextensions.k8s.io"
	k8sRbacApiGroup               = "rbac.authorization.k8s.io"
	k8sAllApiVersion              = "*"
	K8sApiVersionV1               = "v1"
	K8sApiVersionV1Beta1          = "v1beta1"
	K8sApiVersionV1Beta2          = "v1beta2"
	K8sResCronjobs                = "cronjobs"
	K8sResCronjobsFinalizer       = "cronjobs/finalizers"
	K8sResDaemonsets              = "daemonsets"
	K8sResDeployments             = "deployments"
	K8sResDeploymentConfigs       = "deploymentconfigs"
	K8sResJobs                    = "jobs"
	K8sResPods                    = "pods"
	K8sResNodes                   = "nodes"
	K8sResReplicationControllers  = "replicationcontrollers"
	K8sResReplicasets             = "replicasets"
	K8sResServices                = "services"
	k8sResNamespaces              = "namespaces"
	k8sResConfigMaps              = "configmaps"
	k8sResSecrets                 = "secrets"
	K8sResStatefulSets            = "statefulsets"
	K8sResRoles                   = "roles"
	K8sResRolebindings            = "rolebindings"
	K8sResClusterRoles            = "clusterroles"
	K8sResClusterRolebindings     = "clusterrolebindings"
	K8sResRbacRoles               = "roles.rbac.authorization.k8s.io"
	K8sResRbacClusterRoles        = "clusterroles.rbac.authorization.k8s.io"
	K8sResRbacRolebindings        = "rolebindings.rbac.authorization.k8s.io"
	K8sResRbacClusterRolebindings = "clusterrolebindings.rbac.authorization.k8s.io"
	K8sResPersistentVolumeClaims  = "persistentvolumeclaims"
)

const (
	NvDeploymentName = "neuvector-controller-pod"
	NvDaemonSetName  = "neuvector-allinone-pod"
)

const (
	nvOperatorsRole             = "neuvector-binding-co"
	nvOperatorsRoleBinding      = nvOperatorsRole
	NvAppRole                   = "neuvector-binding-app"
	nvAppRoleBinding            = NvAppRole
	NvRbacRole                  = "neuvector-binding-rbac"
	nvRbacRoleBinding           = NvRbacRole
	NvAdmCtrlRole               = "neuvector-binding-admission"
	nvAdmCtrlRoleBinding        = NvAdmCtrlRole
	nvCrdRole                   = "neuvector-binding-customresourcedefinition"
	nvCrdRoleBinding            = nvCrdRole
	nvCrdSecRuleRole            = "neuvector-binding-nvsecurityrules"
	nvCrdSecRoleBinding         = nvCrdSecRuleRole
	nvCrdAdmCtrlRole            = "neuvector-binding-nvadmissioncontrolsecurityrules"
	nvCrdAdmCtrlRoleBinding     = nvCrdAdmCtrlRole
	nvCrdDlpRole                = "neuvector-binding-nvdlpsecurityrules"
	nvCrdDlpRoleBinding         = nvCrdDlpRole
	nvCrdWafRole                = "neuvector-binding-nvwafsecurityrules"
	nvCrdWafRoleBinding         = nvCrdWafRole
	nvCrdVulnProfileRole        = "neuvector-binding-nvvulnerabilityprofiles"
	nvCrdVulnProfileRoleBinding = nvCrdVulnProfileRole
	nvCrdCompProfileRole        = "neuvector-binding-nvcomplianceprofiles"
	nvCrdCompProfileRoleBinding = nvCrdCompProfileRole
	NvScannerRole               = "neuvector-binding-scanner"
	NvScannerRoleBinding        = NvScannerRole
	NvSecretRole                = "neuvector-binding-secret"
	nvSecretRoleBinding         = NvSecretRole
	NvAdminRoleBinding          = "neuvector-admin"
	nvViewRoleBinding           = "neuvector-binding-view"
	NvJobCreationRole           = "neuvector-binding-job-creation"
	NvJobCreationRoleBinding    = NvJobCreationRole
	NvCertUpgraderRole          = "neuvector-binding-cert-upgrader"
	NvCertUpgraderRoleBinding   = NvCertUpgraderRole
)

const (
	k8sClusterRoleView  = "view"
	k8sClusterRoleAdmin = "admin"
)

const (
	nvCspUsageRole        = "neuvector-binding-csp-usages"
	nvCspUsageRoleBinding = nvCspUsageRole
)

const (
	nvAdmMutateType   = "mutate"
	nvAdmValidateType = "validate"
)

const (
	NsSelectorKeyStatusNV  = "statusNeuvector" // written to only neuvector namespace's label
	NsSelectorKeySkipNV    = "skipNeuvectorAdmissionControl"
	NsSelectorKeyCtrlPlane = "control-plane" // AKS writes this label to kube-system ns & our validation webhook

	NsSelectorOpNotExist = "DoesNotExist"
	NsSelectorOpExists   = "Exists"
)

const (
	AdmissionK8sIoV1      = "admission.k8s.io/v1"
	AdmissionK8sIoV1Beta1 = "admission.k8s.io/v1beta1"

	K8sKindAdmissionReview = "AdmissionReview"
)

type resourceWatcher struct {
	watcher *k8s.Watcher
	cancel  context.CancelFunc
	cb      orchAPI.WatchCallback
}

type resourceMaker struct {
	apiVersion string
	newObject  func() metav1.Object
	newList    func() metav1.ListInterface
	xlate      func(obj metav1.Object) (string, interface{})
	xlate2     func(obj metav1.Object, action string)
}

type k8sResource struct {
	apiGroup string
	makers   []*resourceMaker
}

type NvCrdInfo struct {
	RscType           string
	MetaName          string
	SpecScope         string
	SpecGroup         string
	SpecVersion       string
	SpecNamesPlural   string
	SpecNamesKind     string
	SpecNamesSingular string
	SpecNamesListKind string
	LockKey           string
	KvCrdKind         string
	ShortNames        []string
}

// --- for generic types in admissionregistration v1/vebeta1
type K8sAdmRegServiceReference struct {
	Namespace string
	Name      string
	Path      *string
	Port      *int32
}

type K8sAdmRegWebhookClientConfig struct {
	Url      *string
	Service  *K8sAdmRegServiceReference
	CaBundle []byte
}

type K8sAdmRegRule struct {
	ApiGroups   []string
	ApiVersions []string
	Resources   []string
	Scope       *string
}

type K8sAdmRegRuleWithOperations struct {
	Operations []string
	Rule       *K8sAdmRegRule
}

type K8sAdmRegWebhook struct {
	Name                    string
	AdmissionReviewVersions []string
	ClientConfig            *K8sAdmRegWebhookClientConfig
	Rules                   []*K8sAdmRegRuleWithOperations
	FailurePolicy           *string
	NamespaceSelector       *metav1.LabelSelector
	SideEffects             *string
}

type K8sAdmRegValidatingWebhookConfiguration struct {
	Webhooks []*K8sAdmRegWebhook
}

type NvAdmRegRuleSetting struct {
	ApiGroups  utils.Set
	Operations utils.Set
	Resources  utils.Set
	Scope      string
}

type NvQueryK8sVerFunc func()

type NvVerifyK8sNsFunc func(admCtrlEnabled bool, nsName string, nsLabels map[string]string)

//----------------------------------------------------------

var NvAdmSvcName = "neuvector-svc-admission-webhook"
var NvCrdSvcName = "neuvector-svc-crd-webhook"
var NvAdmSvcNamespace = "neuvector"
var NvListKind = "List"

// List all mutating application name here and join the list
var NvAdmMutatingWebhookName string
var NvMutatingWebhookNameList = []string{NvAdmMutatingWebhookName}

// List all validating application name here and join the list
var NvAdmValidatingWebhookName string
var NvCrdValidatingWebhookName string
var NvStatusValidatingWebhookName string
var NvValidatingWebhookNameList []string

var allApiGroups = utils.NewSet(k8sAllApiGroup)
var rbacApiGroups = utils.NewSet(k8sRbacApiGroup)

var opCreateDelete = utils.NewSet(Create, Update)

var admResForCreateSet = utils.NewSet(K8sResCronjobs, K8sResDaemonsets, K8sResDeployments, K8sResJobs, K8sResPods, K8sResReplicasets, K8sResReplicationControllers, K8sResStatefulSets, K8sResPersistentVolumeClaims)
var admResForUpdateSet = utils.NewSet(K8sResDaemonsets, K8sResDeployments, K8sResReplicationControllers, K8sResStatefulSets, K8sResPods)
var admRbacResForCreateUpdate1 = utils.NewSet(K8sResRoles, K8sResRolebindings)
var admRbacResForCreateUpdate2 = utils.NewSet(K8sResClusterRoles, K8sResClusterRolebindings)
var AdmResForOpsSettings = []*NvAdmRegRuleSetting{
	// do not change the order of the following elements!
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Create),
		Resources:  admResForCreateSet,
		Scope:      string(apiv1beta1.NamespacedScope),
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Update),
		Resources:  admResForUpdateSet,
		Scope:      string(apiv1beta1.NamespacedScope),
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  rbacApiGroups,
		Operations: opCreateDelete,
		Resources:  admRbacResForCreateUpdate1,
		Scope:      string(apiv1beta1.NamespacedScope),
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  rbacApiGroups,
		Operations: opCreateDelete,
		Resources:  admRbacResForCreateUpdate2,
		Scope:      string(apiv1beta1.AllScopes),
	},
}

var crdResForAllOpSet = utils.NewSet(RscTypeCrdSecurityRule, RscTypeCrdClusterSecurityRule, RscTypeCrdAdmCtrlSecurityRule, RscTypeCrdDlpSecurityRule,
	RscTypeCrdWafSecurityRule, RscTypeCrdVulnProfile, RscTypeCrdCompProfile)
var CrdResForOpsSettings = []*NvAdmRegRuleSetting{
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Create, Update, Delete),
		Resources:  crdResForAllOpSet,
		Scope:      string(apiv1beta1.AllScopes),
	},
}

var statusResForCreateUpdateSet = utils.NewSet(K8sResServices)
var statusResForDeleteSet = utils.NewSet(K8sResDaemonsets, K8sResDeployments, K8sResServices, K8sResStatefulSets)
var StatusResForOpsSettings = []*NvAdmRegRuleSetting{
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: opCreateDelete,
		Resources:  statusResForCreateUpdateSet,
		Scope:      string(apiv1beta1.NamespacedScope),
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Delete),
		Resources:  statusResForDeleteSet,
		Scope:      string(apiv1beta1.NamespacedScope),
	},
}

var k8sVersionMajor int
var k8sVersionMinor int
var ocVersionMajor int

var cacheEventFunc common.CacheEventFunc

var nvQueryK8sVerFunc NvQueryK8sVerFunc
var nvVerifyK8sNsFunc NvVerifyK8sNsFunc
var isLeader bool
var cspType share.TCspType

var watchFailedFlag int32

const (
	k8sRscTypeRole            = "k8s-role"
	K8sRscTypeClusRole        = "k8s-cluster-role"
	k8sRscTypeRoleBinding     = "k8s-role-binding"
	K8sRscTypeClusRoleBinding = "k8s-cluster-role-binding"
)

var resourceMakers map[string]k8sResource = map[string]k8sResource{
	RscTypeNode: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.Node) },
				func() metav1.ListInterface { return new(corev1.NodeList) },
				xlateNode,
				nil,
			},
		},
	},
	RscTypeNamespace: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.Namespace) },
				func() metav1.ListInterface { return new(corev1.NamespaceList) },
				xlateNamespace,
				nil,
			},
		},
	},
	RscTypeService: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.Service) },
				func() metav1.ListInterface { return new(corev1.ServiceList) },
				xlateService,
				nil,
			},
		},
	},
	RscTypePod: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.Pod) },
				func() metav1.ListInterface { return new(corev1.PodList) },
				xlatePod,
				nil,
			},
		},
	},
	RscTypeDeployment: k8sResource{
		apiGroup: "apps",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(appsv1.Deployment) },
				func() metav1.ListInterface { return new(appsv1.DeploymentList) },
				xlateDeployment,
				nil,
			},
		},
	},
	RscTypeDaemonSet: k8sResource{
		apiGroup: "apps",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(appsv1.DaemonSet) },
				func() metav1.ListInterface { return new(appsv1.DaemonSetList) },
				xlateDaemonSet,
				nil,
			},
		},
	},
	RscTypeReplicaSet: k8sResource{
		apiGroup: "apps",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(appsv1.ReplicaSet) },
				func() metav1.ListInterface { return new(appsv1.ReplicaSetList) },
				xlateReplicaSet,
				nil,
			},
		},
	},
	RscTypeStatefulSet: k8sResource{
		apiGroup: "apps",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(appsv1.StatefulSet) },
				func() metav1.ListInterface { return new(appsv1.StatefulSetList) },
				xlateStatefulSet,
				nil,
			},
		},
	},
	RscTypeCronJob: k8sResource{
		apiGroup: "batch",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(batchv1b1.CronJob) },
				func() metav1.ListInterface { return new(batchv1b1.CronJobList) },
				xlateCronJob,
				nil,
			},
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(batchv1.CronJob) },
				func() metav1.ListInterface { return new(batchv1.CronJobList) },
				xlateCronJob,
				nil,
			},
		},
	},
	RscTypeImage: k8sResource{
		apiGroup: "image.openshift.io",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(ocImageStream) },
				func() metav1.ListInterface { return new(ocImageStreamList) },
				xlateImage,
				nil,
			},
		},
	},
	k8sRscTypeRole: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(rbacv1.Role) },
				func() metav1.ListInterface { return new(rbacv1.RoleList) },
				xlateRole,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(rbacv1b1.Role) },
				func() metav1.ListInterface { return new(rbacv1b1.RoleList) },
				xlateRole,
				nil,
			},
		},
	},
	K8sRscTypeClusRole: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(rbacv1.ClusterRole) },
				func() metav1.ListInterface { return new(rbacv1.ClusterRoleList) },
				xlateClusRole,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(rbacv1b1.ClusterRole) },
				func() metav1.ListInterface { return new(rbacv1b1.ClusterRoleList) },
				xlateClusRole,
				nil,
			},
		},
	},
	k8sRscTypeRoleBinding: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(rbacv1.RoleBinding) },
				func() metav1.ListInterface { return new(rbacv1.RoleBindingList) },
				xlateRoleBinding,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(rbacv1b1.RoleBinding) },
				func() metav1.ListInterface { return new(rbacv1b1.RoleBindingList) },
				xlateRoleBinding,
				nil,
			},
		},
	},
	K8sRscTypeClusRoleBinding: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(rbacv1.ClusterRoleBinding) },
				func() metav1.ListInterface { return new(rbacv1.ClusterRoleBindingList) },
				xlateClusRoleBinding,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(rbacv1b1.ClusterRoleBinding) },
				func() metav1.ListInterface { return new(rbacv1b1.ClusterRoleBindingList) },
				xlateClusRoleBinding,
				nil,
			},
		},
	},
	RscTypeCrd: k8sResource{
		apiGroup: k8sCrdApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(apiextv1b1.CustomResourceDefinition) },
				func() metav1.ListInterface { return new(apiextv1b1.CustomResourceDefinitionList) },
				xlateCrd,
				nil,
			},
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(apiextv1.CustomResourceDefinition) },
				func() metav1.ListInterface { return new(apiextv1.CustomResourceDefinitionList) },
				xlateCrd,
				nil,
			},
		},
	},
	RscTypeCrdSecurityRule: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvSecurityRule) },
				func() metav1.ListInterface { return new(NvSecurityRuleList) },
				xlateCrdNvSecurityRule,
				nil,
			},
		},
	},

	RscTypeCrdClusterSecurityRule: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvClusterSecurityRule) },
				func() metav1.ListInterface { return new(NvClusterSecurityRuleList) },
				xlateCrdNvClusterSecurityRule,
				nil,
			},
		},
	},
	RscTypeCrdAdmCtrlSecurityRule: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvAdmCtrlSecurityRule) },
				func() metav1.ListInterface { return new(NvAdmCtrlSecurityRuleList) },
				xlateCrdAdmCtrlRule,
				nil,
			},
		},
	},
	RscTypeCrdDlpSecurityRule: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvDlpSecurityRule) },
				func() metav1.ListInterface { return new(NvDlpSecurityRuleList) },
				xlateCrdDlpSecurityRule,
				nil,
			},
		},
	},
	RscTypeCrdWafSecurityRule: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvWafSecurityRule) },
				func() metav1.ListInterface { return new(NvWafSecurityRuleList) },
				xlateCrdWafSecurityRule,
				nil,
			},
		},
	},
	RscTypeCrdVulnProfile: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvVulnProfileSecurityRule) },
				func() metav1.ListInterface { return new(NvVulnProfileSecurityRuleList) },
				xlateCrdVulnProfile,
				nil,
			},
		},
	},
	RscTypeCrdCompProfile: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvCompProfileSecurityRule) },
				func() metav1.ListInterface { return new(NvCompProfileSecurityRuleList) },
				xlateCrdCompProfile,
				nil,
			},
		},
	},
	RscTypeCrdNvCspUsage: k8sResource{
		apiGroup: "susecloud.net",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(NvCspUsage) },
				func() metav1.ListInterface { return new(NvCspUsageList) },
				xlateCrdCspUsage,
				nil,
			},
		},
	},
	RscTypeConfigMap: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.ConfigMap) },
				func() metav1.ListInterface { return new(corev1.ConfigMapList) },
				xlateConfigMap,
				nil,
			},
		},
	},
	RscTypeSecret: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.Secret) },
				func() metav1.ListInterface { return new(corev1.SecretList) },
				nil, // xlateSecret,
				nil,
			},
		},
	},
	/*RscTypeMutatingWebhookConfiguration: k8sResource{
			apiGroup: k8sAdmApiGroup,
			makers: []*resourceMaker{
				&resourceMaker{
					"v1",
					func() metav1.Object { return new(admregv1.MutatingWebhookConfiguration) },
					func() metav1.ListInterface { return new(admregv1.MutatingWebhookConfigurationList) },
					xlateMutatingWebhookConfiguration,
					nil,
				},
	            &resourceMaker{
					"v1beta1",
					func() metav1.Object { return new(admregv1b1.MutatingWebhookConfiguration) },
					func() metav1.ListInterface { return new(admregv1b1.MutatingWebhookConfigurationList) },
					xlateMutatingWebhookConfiguration,
					nil,
				},
			},
		},*/
	RscTypeValidatingWebhookConfiguration: k8sResource{
		apiGroup: k8sAdmApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(admregv1.ValidatingWebhookConfiguration) },
				func() metav1.ListInterface { return new(admregv1.ValidatingWebhookConfigurationList) },
				xlateValidatingWebhookConfiguration,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() metav1.Object { return new(admregv1b1.ValidatingWebhookConfiguration) },
				func() metav1.ListInterface { return new(admregv1b1.ValidatingWebhookConfigurationList) },
				xlateValidatingWebhookConfiguration,
				nil,
			},
		},
	},
	RscTypePersistentVolumeClaim: k8sResource{
		apiGroup: "",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() metav1.Object { return new(corev1.PersistentVolumeClaim) },
				func() metav1.ListInterface { return new(corev1.PersistentVolumeClaimList) },
				xlatePersistentVolumeClaim,
				nil,
			},
		},
	},
}

const (
	k8sNodeTypeInternalIP = "InternalIP"
	k8sNodeTypeHostname   = "Hostname"
)

type kubernetes struct {
	*noop

	lock      sync.RWMutex
	rbacLock  sync.RWMutex
	client    *k8s.Client
	discovery *k8s.Discovery
	version   *k8s.Version
	watchers  map[string]*resourceWatcher

	userCache map[k8sSubjectObjRef]utils.Set         // k8s user -> set of k8sRoleRef
	roleCache map[k8sObjectRef]string                // k8s (cluster)role -> nv reserved role
	rbacCache map[k8sSubjectObjRef]map[string]string // k8s user -> (domain -> nv reserved role). it's updated after rbacEvaluateUser() call

	// for Rancher SSO only.
	permitsCache     map[k8sObjectRef]share.NvPermissions                   // k8s (cluster)role -> nv permissions.
	permitsRbacCache map[k8sSubjectObjRef]map[string]share.NvFedPermissions // k8s user -> (domain -> extra nv permissions). it's updated after rbacEvaluateUser() call
}

func newKubernetesDriver(platform, flavor, network string) *kubernetes {
	d := &kubernetes{
		noop:             newNoopDriver(platform, flavor, network),
		watchers:         make(map[string]*resourceWatcher),
		roleCache:        make(map[k8sObjectRef]string),
		userCache:        make(map[k8sSubjectObjRef]utils.Set),
		rbacCache:        make(map[k8sSubjectObjRef]map[string]string),
		permitsCache:     make(map[k8sObjectRef]share.NvPermissions),
		permitsRbacCache: make(map[k8sSubjectObjRef]map[string]share.NvFedPermissions),
	}
	return d
}

/*
// Node add and remove
event=Add node=&{UID:2d39e6bb-267f-11e8-8d3e-0800273d5dc6 Name:host3 IPNets:[{IP:10.254.101.103 Mask:ffffffff}]}
event=Delete node=&{UID:2d39e6bb-267f-11e8-8d3e-0800273d5dc6 Name:host3 IPNets:[{IP:10.254.101.103 Mask:ffffffff}]}
*/

func xlateNode(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*corev1.Node); ok {
		r := &Node{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			IPNets: make([]net.IPNet, 0),
		}
		addrs := o.Status.Addresses
		for _, addr := range addrs {
			if addr.Type == k8sNodeTypeInternalIP {
				if ip := net.ParseIP(addr.Address); ip != nil {
					if utils.IsIPv4(ip) {
						r.IPNets = append(r.IPNets, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
					} else {
						r.IPNets = append(r.IPNets, net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
					}
				}
			}
		}
		r.Labels = o.GetLabels()
		r.Annotations = o.GetAnnotations()
		// special handling for IBM cloud because it customizes the k8s node name to using IP, but not the system hostname
		if strings.HasPrefix(o.Spec.ProviderID, "ibm://") {
			// [ex] ibm-cloud.kubernetes.io/worker-id: kube-c40msj4d0tb4oeriggqg-atibmcluste-default-000001f1
			if hostname, ok := r.Labels["ibm-cloud.kubernetes.io/worker-id"]; ok {
				r.IBMCloudWorkerID = hostname
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateNamespace(obj metav1.Object) (string, interface{}) {
	if _, ok := obj.(*corev1.Namespace); ok {
		r := &Namespace{
			UID:    string(obj.GetUID()),
			Name:   obj.GetName(),
			Labels: obj.GetLabels(),
		}
		return r.UID, r
	}

	return "", nil
}

/*
// Service with no IP create and remove
event=Add service=&{UID:5de2fe39-2659-11e8-aa34-0800273d5dc6 Name:nginx Domain: IP:<nil> Selector:map[app:nginx]}
event=Delete service=&{UID:5de2fe39-2659-11e8-aa34-0800273d5dc6 Name:nginx Domain: IP:<nil> Selector:map[app:nginx]}

// Service with IP is create and remove
event=Add service=&{UID:35dcd76f-267d-11e8-8d3e-0800273d5dc6 Name:nginx-webui Domain: IP:10.97.170.48 Selector:map[app:nginx-pod]}
event=Delete service=&{UID:35dcd76f-267d-11e8-8d3e-0800273d5dc6 Name:nginx-webui Domain: IP:10.97.170.48 Selector:map[app:nginx-pod]}
*/
func xlateService(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*corev1.Service); ok {
		r := &Service{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			Domain: o.GetNamespace(),
			Labels: make(map[string]string),
		}
		r.IPs = make([]net.IP, 0)
		if tip := net.ParseIP(o.Spec.ClusterIP); tip != nil {
			r.IPs = append(r.IPs, tip)
		}
		r.Selector = o.Spec.Selector
		r.Type = string(o.Spec.Type)
		r.ExternalIPs = make([]net.IP, len(o.Spec.ExternalIPs))
		for i, e := range o.Spec.ExternalIPs {
			r.ExternalIPs[i] = net.ParseIP(e)
		}
		return r.UID, r
	}

	return "", nil
}

/*
// Pod is create and remove
event=Add pod=&{UID:5dff5793-2659-11e8-aa34-0800273d5dc6 Name:web-0 Domain:default IPNet:{IP:<nil> Mask:ffffffff} Running:false OwnerUID: OwnerName: OwnerType:}
event=Modify pod=&{UID:5dff5793-2659-11e8-aa34-0800273d5dc6 Name:web-0 Domain:default IPNet:{IP:192.168.184.67 Mask:ffffffff} Running:true OwnerUID: OwnerName: OwnerType:}
event=Add pod=&{UID:5dff5793-2659-11e8-aa34-0800273d5dc6 Name:web-0 Domain:default IPNet:{IP:192.168.184.67 Mask:ffffffff} Running:true OwnerUID: OwnerName: OwnerType:}
event=Modify pod=&{UID:5dff5793-2659-11e8-aa34-0800273d5dc6 Name:web-0 Domain:default IPNet:{IP:<nil> Mask:ffffffff} Running:false OwnerUID: OwnerName: OwnerType:}
event=Delete pod=&{UID:5dff5793-2659-11e8-aa34-0800273d5dc6 Name:web-0 Domain:default IPNet:{IP:<nil> Mask:ffffffff} Running:false OwnerUID: OwnerName: OwnerType:}
*/
func xlatePod(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*corev1.Pod); ok {
		r := &Pod{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			Domain: o.GetNamespace(),
			Labels: o.GetLabels(),
		}
		if len(o.OwnerReferences) >= 1 {
			owner := o.OwnerReferences[0]
			r.OwnerUID = string(owner.UID)
			r.OwnerName = owner.Name
			r.OwnerType = owner.Kind
		}

		r.Node = o.Spec.NodeName
		r.HostNet = o.Spec.HostNetwork
		for _, c := range o.Spec.Containers {
			var ctr Container
			ctr.Name = c.Name
			if c.LivenessProbe != nil && c.LivenessProbe.Exec != nil {
				ctr.LivenessCmds = c.LivenessProbe.Exec.Command
			}
			if c.ReadinessProbe != nil && c.ReadinessProbe.Exec != nil {
				ctr.ReadinessCmds = c.ReadinessProbe.Exec.Command
			}
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil {
				ctr.Privileged = *c.SecurityContext.Privileged
			}
			if memory, ok := c.Resources.Requests["memory"]; ok {
				ctr.RequestMemory = memory.String()
			}
			if memory, ok := c.Resources.Limits["memory"]; ok {
				ctr.LimitMemory = memory.String()
			}
			r.Containers = append(r.Containers, ctr)
		}
		if r.SA = o.Spec.ServiceAccountName; r.SA == "" {
			r.SA = o.Spec.DeprecatedServiceAccount
		}
		if r.SA == "" {
			r.SA = "default" // see https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
		}

		if ip := net.ParseIP(o.Status.PodIP); ip != nil {
			if utils.IsIPv4(ip) {
				r.IPNet = net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				r.IPNet = net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		if o.Status.Phase == "Running" {
			r.Running = true
		}

		if r.Domain != NvAdmSvcNamespace && len(o.Status.ContainerStatuses) > 0 {
			for i, cs := range o.Status.ContainerStatuses {
				var id string
				containerID := cs.ContainerID
				for _, prefix := range []string{"docker://", "containerd://", "cri-o://"} {
					if strings.HasPrefix(containerID, prefix) {
						id = containerID[len(prefix):]
						r.ContainerIDs = append(r.ContainerIDs, id)
					}
				}
				if i < len(r.Containers) {
					r.Containers[i].Id = id
				} else {
					log.WithFields(log.Fields{"id": id, "containers": r.Containers}).Error("Not matched")
				}
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateDeployment(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*appsv1.Deployment); ok && o != nil {
		if o.GetNamespace() != NvAdmSvcNamespace {
			return "", nil
		}
		r := &Deployment{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			Domain: o.GetNamespace(),
		}
		if o.Spec.Replicas != nil {
			r.Replicas = *o.Spec.Replicas
		}
		return r.UID, r
	}

	return "", nil
}

func xlateDaemonSet(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*appsv1.DaemonSet); ok && o != nil {
		if o.GetNamespace() != NvAdmSvcNamespace || o.GetName() != "neuvector-enforcer-pod" {
			return "", nil
		}
		r := &DaemonSet{
			UID:    string(obj.GetUID()),
			Name:   obj.GetName(),
			Domain: obj.GetNamespace(),
			SA:     "default",
		}
		spec := o.Spec.Template.Spec
		if spec.ServiceAccountName != "" {
			r.SA = spec.ServiceAccountName
		} else if spec.DeprecatedServiceAccount != "" {
			r.SA = spec.DeprecatedServiceAccount
		}
		return r.UID, r
	}

	return "", nil
}

func xlateReplicaSet(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*appsv1.ReplicaSet); ok && o != nil {
		r := &ReplicaSet{
			UID:    string(obj.GetUID()),
			Name:   obj.GetName(),
			Domain: obj.GetNamespace(),
		}
		return r.UID, r
	}

	return "", nil
}

func xlateStatefulSet(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*appsv1.StatefulSet); ok && o != nil {
		r := &StatefulSet{
			UID:    string(obj.GetUID()),
			Name:   obj.GetName(),
			Domain: obj.GetNamespace(),
		}
		return r.UID, r
	}

	return "", nil
}

func xlateCronJob(obj metav1.Object) (string, interface{}) {
	var r *CronJob = &CronJob{
		UID:    string(obj.GetUID()),
		Name:   obj.GetName(),
		Domain: obj.GetNamespace(),
		SA:     "default",
	}
	var spec *corev1.PodSpec

	if o, ok := obj.(*batchv1b1.CronJob); ok && o != nil {
		spec = &o.Spec.JobTemplate.Spec.Template.Spec
	} else if o, ok := obj.(*batchv1.CronJob); ok && o != nil {
		spec = &o.Spec.JobTemplate.Spec.Template.Spec
	}

	if spec != nil {
		if spec.ServiceAccountName != "" {
			r.SA = spec.ServiceAccountName
		} else if spec.DeprecatedServiceAccount != "" {
			r.SA = spec.DeprecatedServiceAccount
		}
		return r.UID, r
	}

	return "", nil
}

func xlateImageRemoveURL(repo string) string {
	if !strings.Contains(repo, share.DefaultOpenShiftRegistryURL) && !strings.Contains(repo, ":") {
		return repo
	}

	// remove the first section
	slash := strings.Index(repo, "/")
	return repo[slash+1:]
}

func xlateImage(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*ocImageStream); ok {
		r := &Image{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			Domain: o.GetNamespace(),
			Tags:   make([]ImageTag, 0),
		}
		if o.Status != nil {
			r.Repo = xlateImageRemoveURL(o.Status.Repo)
			for _, tag := range o.Status.Tags {
				if tag != nil && len(tag.Items) > 0 {
					r.Tags = append(r.Tags, ImageTag{Tag: tag.Tag, Serial: tag.Items[0].Image})
				}
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateCrd(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*apiextv1b1.CustomResourceDefinition); ok {
		return string(obj.GetUID()), o
	} else if o, ok := obj.(*apiextv1.CustomResourceDefinition); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdNvSecurityRule(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdNvClusterSecurityRule(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvClusterSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdAdmCtrlRule(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvAdmCtrlSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdDlpSecurityRule(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvDlpSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdWafSecurityRule(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvWafSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdVulnProfile(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvVulnProfileSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdCompProfile(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvCompProfileSecurityRule); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateCrdCspUsage(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*NvCspUsage); ok {
		return string(obj.GetUID()), o
	}

	return "", nil
}

func xlateConfigMap(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*corev1.ConfigMap); ok {
		r := &ConfigMap{
			UID:    string(o.GetUID()),
			Name:   o.GetName(),
			Domain: o.GetNamespace(),
			Data:   o.Data,
		}
		return r.UID, r
	}

	return "", nil
}

func xlateMutatingWebhookConfiguration(obj metav1.Object) (string, interface{}) {
	var name string
	var guid string
	if o, ok := obj.(*admregv1.MutatingWebhookConfiguration); ok {
		name = o.GetName()
		guid = string(o.GetUID())
	} else if o, ok := obj.(*admregv1b1.MutatingWebhookConfiguration); ok {
		name = o.GetName()
		guid = string(o.GetUID())
	}
	if name != "" {
		r := &AdmissionWebhookConfiguration{
			AdmType: nvAdmMutateType,
			Name:    name,
		}
		return guid, r
	}
	return "", nil
}

func xlateValidatingWebhookConfiguration(obj metav1.Object) (string, interface{}) {
	var name string
	var guid string
	if o, ok := obj.(*admregv1.ValidatingWebhookConfiguration); ok {
		name = o.GetName()
		guid = string(o.GetUID())
	} else if o, ok := obj.(*admregv1b1.ValidatingWebhookConfiguration); ok {
		name = o.GetName()
		guid = string(o.GetUID())
	}
	if name != "" {
		if name == NvAdmValidatingName || name == NvPruneValidatingName {
			r := &AdmissionWebhookConfiguration{
				AdmType: nvAdmValidateType,
				Name:    name,
			}
			return guid, r
		}
	}
	return "", nil
}

func (d *kubernetes) discoverResource(rt string) (*resourceMaker, error) {
	r, ok := resourceMakers[rt]
	if !ok {
		return nil, fmt.Errorf("Unknown resource name: %s", rt)
	}

	if d.discovery == nil {
		if err := d.newClient(); err != nil {
			return nil, err
		}
	}

	// Don't know how to discover core API group. 'v1' is always supported.
	if r.apiGroup == "" {
		return r.makers[0], nil
	}

	g, err := d.discovery.APIGroup(context.Background(), r.apiGroup)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover API group: %s(%s)", r.apiGroup, err.Error())
	}

	// First, try preferred version
	v := g.PreferredVersion.Version
	for _, maker := range r.makers {
		if v == maker.apiVersion {
			return maker, nil
		}
	}

	// Second, going through versions by our order
	vers := g.Versions
	supported := make([]string, len(vers))
	for _, maker := range r.makers {
		for i, ver := range vers {
			supported[i] = ver.Version
			if supported[i] == maker.apiVersion {
				return maker, nil
			}
		}
	}

	return nil, fmt.Errorf("Supported version not found")
}

// Keep watching until error happens
func (d *kubernetes) watchResource(rt string, maker *resourceMaker, watcher *k8s.Watcher, cb orchAPI.WatchCallback, errCh chan error) {
	for {
		obj := maker.newObject()
		if evt, err := watcher.Next(obj); err != nil {
			errCh <- err
			return
		} else {
			// Keep this line for full object
			// log.WithFields(log.Fields{"resource": rt, "event": evt, "object": obj}).Debug()
			switch evt {
			case "ADDED", "MODIFIED":
				if id, res := maker.xlate(obj); res != nil {
					if ev, old := d.updateResourceCache(rt, id, res); ev != "" {
						cb(rt, ev, res, old)
					}
				}

				if maker.xlate2 != nil {
					maker.xlate2(obj, evt)
				}
			case "DELETED":
				if id, res := maker.xlate(obj); res != nil {
					if ev, old := d.deleteResourceCache(rt, id); ev != "" {
						cb(rt, ev, res, old)
					}
				}

				if maker.xlate2 != nil {
					maker.xlate2(obj, evt)
				}
			}
		}
	}
}

func (d *kubernetes) RegisterResource(rt string) error {
	var err error
	if rt == RscTypeImage {
		_, err = d.discoverResource(rt)
		if err == nil {
			d.lock.Lock()
			k8s.Register("image.openshift.io", "v1", "imagestreams", true, &ocImageStream{})
			k8s.RegisterList("image.openshift.io", "v1", "imagestreams", true, &ocImageStreamList{})
			d.lock.Unlock()
		}
	} else {
		d.lock.Lock()
		switch rt {
		case RscTypeCrdSecurityRule:
			k8s.Register("neuvector.com", "v1", NvSecurityRulePlural, true, &NvSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvSecurityRulePlural, true, &NvSecurityRuleList{})
		case RscTypeCrdClusterSecurityRule:
			k8s.Register("neuvector.com", "v1", NvClusterSecurityRulePlural, false, &NvClusterSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvClusterSecurityRulePlural, false, &NvClusterSecurityRuleList{})
		case RscTypeCrdAdmCtrlSecurityRule:
			k8s.Register("neuvector.com", "v1", NvAdmCtrlSecurityRulePlural, false, &NvAdmCtrlSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvAdmCtrlSecurityRulePlural, false, &NvAdmCtrlSecurityRuleList{})
		case RscTypeCrdDlpSecurityRule:
			k8s.Register("neuvector.com", "v1", NvDlpSecurityRulePlural, false, &NvDlpSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvDlpSecurityRulePlural, false, &NvDlpSecurityRuleList{})
		case RscTypeCrdWafSecurityRule:
			k8s.Register("neuvector.com", "v1", NvWafSecurityRulePlural, false, &NvWafSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvWafSecurityRulePlural, false, &NvWafSecurityRuleList{})
		case RscTypeCrdVulnProfile:
			k8s.Register("neuvector.com", "v1", NvVulnProfileSecurityRulePlural, false, &NvVulnProfileSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvVulnProfileSecurityRulePlural, false, &NvVulnProfileSecurityRuleList{})
		case RscTypeCrdCompProfile:
			k8s.Register("neuvector.com", "v1", NvCompProfileSecurityRulePlural, false, &NvCompProfileSecurityRule{})
			k8s.RegisterList("neuvector.com", "v1", NvCompProfileSecurityRulePlural, false, &NvCompProfileSecurityRuleList{})
		case RscTypeCrdNvCspUsage:
			k8s.Register("susecloud.net", "v1", NvCspUsagePlural, false, &NvCspUsage{})
			k8s.RegisterList("susecloud.net", "v1", NvCspUsagePlural, false, &NvCspUsageList{})
		default:
			err = ErrResourceNotSupported
		}
		d.lock.Unlock()

		if err == nil {
			_, err = d.discoverResource(rt)
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"resource": rt, "error": err}).Error("fail to register")
	}

	return err
}

func (d *kubernetes) ListResource(rt, namespace string) ([]interface{}, error) {
	if rt == RscTypeRBAC {
		return nil, ErrResourceNotSupported
	} else {
		return d.listResource(rt, namespace)
	}
}

func (d *kubernetes) listResource(rt, namespace string) ([]interface{}, error) {
	log.WithFields(log.Fields{"resource": rt}).Debug()

	maker, err := d.discoverResource(rt)
	if err != nil {
		return nil, err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return nil, err
		}
	}

	objs := maker.newList()
	d.lock.Lock()
	err = d.client.List(context.Background(), namespace, objs)
	d.lock.Unlock()
	if err != nil {
		return nil, err
	}

	items := reflect.ValueOf(objs).Elem().FieldByName("Items")
	if items.Kind() != reflect.Slice {
		return nil, err
	}

	list := make([]interface{}, 0, items.Len())
	for i := 0; i < items.Len(); i++ {
		item := items.Index(i).Addr().Interface()
		if o, ok := item.(metav1.Object); ok {
			_, obj := maker.xlate(o)
			list = append(list, obj)
		}
	}

	return list, nil
}

func (d *kubernetes) StartWatchResource(rt, ns string, wcb orchAPI.WatchCallback, scb orchAPI.StateCallback) error {
	var err error
	for range []bool{true} {
		if rt == RscTypeRBAC {
			if err = d.startWatchResource(k8sRscTypeRole, ns, d.cbResourceRole, scb); err != nil {
				d.StopWatchResource(rt)
				break
			}
			if err = d.startWatchResource(K8sRscTypeClusRole, ns, d.cbResourceRole, scb); err != nil {
				d.StopWatchResource(rt)
				break
			}
			if err = d.startWatchResource(k8sRscTypeRoleBinding, ns, d.cbResourceRoleBinding, scb); err != nil {
				d.StopWatchResource(rt)
				break
			}
			if err = d.startWatchResource(K8sRscTypeClusRoleBinding, ns, d.cbResourceRoleBinding, scb); err != nil {
				d.StopWatchResource(rt)
				break
			}
			d.lock.Lock()
			d.watchers[rt] = &resourceWatcher{cb: wcb}
			d.lock.Unlock()
		} else {
			err = d.startWatchResource(rt, ns, wcb, scb)
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"watch": rt, "error": err}).Error()
	}

	return err
}

func (d *kubernetes) startWatchResource(rt, ns string, wcb orchAPI.WatchCallback, scb orchAPI.StateCallback) error {
	log.WithFields(log.Fields{"resource": rt}).Debug()

	maker, err := d.discoverResource(rt)
	if err != nil {
		return err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return err
		}
	}

	go func() {
		// When watcher is closed, watch raises an error, but this goroutine already exits,
		// so size-1 channel is required.
		errCh := make(chan error, 1)

		for {
			ctx, cancel := context.WithCancel(context.Background())
			d.lock.Lock()
			watcher, err := d.client.Watch(ctx, ns, maker.newObject())
			d.lock.Unlock()
			if err != nil {
				errCh <- err
			} else {
				if scb != nil {
					scb(ConnStateConnected, nil)
				}
				d.lock.Lock()
				if d.watchers[rt] != nil {
					d.watchers[rt].cancel()
				}
				w := &resourceWatcher{
					watcher: watcher,
					cancel:  cancel,
					cb:      wcb,
				}
				d.watchers[rt] = w
				d.lock.Unlock()

				if flag := atomic.LoadInt32(&watchFailedFlag); flag == 1 && rt == RscTypePod {
					if nvQueryK8sVerFunc != nil {
						nvQueryK8sVerFunc()
					}
					atomic.StoreInt32(&watchFailedFlag, 0)
				}

				go d.watchResource(rt, maker, watcher, wcb, errCh)
			}

			select {
			case e := <-errCh:
				// If watch returns error because the context is closed, the error won't reach
				// here because the go routine has exited - so we can make error callback here
				if rt == RscTypePod {
					atomic.StoreInt32(&watchFailedFlag, 1)
				}

				// Ignore io.EOF per https://github.com/kubernetes/client-go/issues/623
				if !strings.HasSuffix(e.Error(), io.EOF.Error()) {
					if scb != nil {
						scb(ConnStateDisconnected, e)
					}
					log.WithFields(log.Fields{"resource": rt, "error": e}).Error("Watch failure")
					time.Sleep(kubeWatchRetry)
				}
			case <-ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	return nil
}

func (d *kubernetes) StopWatchResource(rt string) error {
	if rt == RscTypeRBAC {
		d.stopWatchResource(k8sRscTypeRole)
		d.stopWatchResource(K8sRscTypeClusRole)
		d.stopWatchResource(k8sRscTypeRoleBinding)
		d.stopWatchResource(K8sRscTypeClusRoleBinding)
		return nil
	} else {
		return d.stopWatchResource(rt)
	}
}

func (d *kubernetes) stopWatchResource(rt string) error {
	log.Debug()

	d.lock.Lock()
	defer d.lock.Unlock()

	if d.watchers[rt] == nil {
		return errors.New("Service watch not started")
	}
	d.watchers[rt].cancel()
	d.watchers[rt] = nil

	return nil
}

func (d *kubernetes) StopWatchAllResources() error {
	log.Debug()

	d.lock.Lock()
	defer d.lock.Unlock()

	for rt, _ := range d.watchers {
		if d.watchers[rt] != nil && d.watchers[rt].cancel != nil {
			d.watchers[rt].cancel()
			d.watchers[rt] = nil
		}
	}

	return nil
}

/*
func (d *kubernetes) GetVersion() (string, string) {
	// version is read when new client is created
	if d.client == nil {
		if err := d.newClient(); err != nil {
			return "", ""
		}
	}

	var k8sVer string
	if d.version != nil {
		k8sVer = strings.TrimLeft(d.version.GitVersion, "v")
	}
	if k8sVer == "" {
		k8sVer = d.k8sVer
	}
	ocVer := d.ocVer
	log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer}).Debug()
	return k8sVer, ocVer
}
*/

func (d *kubernetes) GetOEMVersion() (string, error) {
	url := common.OEMPlatformVersionURL()
	if url == "" {
		return "", nil
	}
	return getVersion(url)
}

func (d *kubernetes) newClient() error {
	if client, err := k8s.NewInClusterClient(); err != nil {
		return err
	} else {
		d.client = client
		d.discovery = k8s.NewDiscoveryClient(client)

		d.version, _ = d.discovery.Version(context.Background())
	}
	return nil
}

type openshifVersion struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
}

func getVersion(url string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Get Version fail")
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Read data fail")
		return "", err
	}
	var ocv openshifVersion
	err = json.Unmarshal(data, &ocv)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Unmarshal fail")
		return "", err
	}
	return strings.TrimLeft(ocv.GitVersion, "v"), nil
}

func (d *kubernetes) GetResource(rt, namespace, name string) (interface{}, error) {
	switch rt {
	//case RscTypeMutatingWebhookConfiguration:
	case RscTypeNamespace, RscTypeService, K8sRscTypeClusRole, K8sRscTypeClusRoleBinding, k8sRscTypeRole, k8sRscTypeRoleBinding, RscTypeValidatingWebhookConfiguration,
		RscTypeCrd, RscTypeConfigMap, RscTypeCrdSecurityRule, RscTypeCrdClusterSecurityRule, RscTypeCrdAdmCtrlSecurityRule, RscTypeCrdDlpSecurityRule, RscTypeCrdWafSecurityRule,
		RscTypeDeployment, RscTypeReplicaSet, RscTypeStatefulSet, RscTypeCrdNvCspUsage, RscTypeCrdVulnProfile, RscTypeCrdCompProfile, RscTypeSecret, RscTypePersistentVolumeClaim:
		return d.getResource(rt, namespace, name)
	case RscTypePod, RscTypeNode, RscTypeCronJob, RscTypeDaemonSet:
		if r, err := d.getResource(rt, namespace, name); err == nil {
			if maker, err := d.discoverResource(rt); err == nil {
				if _, o := maker.xlate(r.(metav1.Object)); o != nil {
					return o, nil
				}
			}
			return nil, common.ErrObjectNotFound
		} else {
			return nil, err
		}
	}
	return nil, ErrResourceNotSupported
}

func (d *kubernetes) getResource(rt, namespace, name string) (interface{}, error) {
	//log.WithFields(log.Fields{"resource": rt}).Debug()

	maker, err := d.discoverResource(rt)
	if err != nil {
		return nil, err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return nil, err
		}
	}

	obj := maker.newObject()
	d.lock.Lock()
	defer d.lock.Unlock()
	err = d.client.Get(context.Background(), namespace, name, obj)

	return obj, err
}

func (d *kubernetes) AddResource(rt string, res interface{}) error {
	switch rt {
	//case RscTypeMutatingWebhookConfiguration:
	case RscTypeValidatingWebhookConfiguration, RscTypeCrd, RscTypeCrdNvCspUsage:
		return d.addResource(rt, res)
	}
	return ErrResourceNotSupported
}

func (d *kubernetes) addResource(rt string, res interface{}) error {
	log.WithFields(log.Fields{"resource": rt}).Debug()

	_, err := d.discoverResource(rt)
	if err != nil {
		return err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return err
		}
	}

	// Note: Currently(Jan./2019) we only support creating neuvector-validating-admission-webhook resource
	obj, ok := res.(metav1.Object)
	if !ok {
		return ErrResourceNotSupported
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	err = d.client.Create(context.Background(), obj)

	return err
}

func (d *kubernetes) UpdateResource(rt string, res interface{}) error {
	switch rt {
	case RscTypeService:
		svc := res.(*corev1.Service)
		if svc != nil && svc.Name == NvAdmSvcName {
			return d.updateResource(rt, res)
		}
	case RscTypeNamespace:
		ns := res.(*corev1.Namespace)
		if ns != nil {
			return d.updateResource(rt, res)
		}
	case RscTypeDeployment:
		deploy := res.(*appsv1.Deployment)
		if deploy != nil && deploy.Namespace == NvAdmSvcNamespace {
			return d.updateResource(rt, res)
		}
	//case RscTypeMutatingWebhookConfiguration:
	case RscTypeValidatingWebhookConfiguration, RscTypeCrd, RscTypeCrdNvCspUsage:
		return d.updateResource(rt, res)
	}
	return ErrResourceNotSupported
}

func (d *kubernetes) updateResource(rt string, res interface{}) error {
	log.WithFields(log.Fields{"resource": rt}).Debug()
	defer log.WithFields(log.Fields{"resource": rt}).Debug("leave")

	_, err := d.discoverResource(rt)
	if err != nil {
		return err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return err
		}
	}

	obj, ok := res.(metav1.Object)
	if !ok {
		return ErrResourceNotSupported
	}

	d.lock.Lock()
	defer d.lock.Unlock()
	err = d.client.Update(context.Background(), obj)

	return err
}

func (d *kubernetes) DeleteResource(rt string, res interface{}) error {
	switch rt {
	//case RscTypeMutatingWebhookConfiguration:
	case RscTypeValidatingWebhookConfiguration, RscTypeCrd, RscTypeCrdSecurityRule, RscTypeCrdClusterSecurityRule,
		RscTypeCrdAdmCtrlSecurityRule, RscTypeCrdDlpSecurityRule, RscTypeCrdWafSecurityRule, RscTypeCrdNvCspUsage,
		RscTypeCrdVulnProfile, RscTypeCrdCompProfile:
		return d.deleteResource(rt, res)
	}
	return ErrResourceNotSupported
}

func (d *kubernetes) deleteResource(rt string, res interface{}) error {
	log.WithFields(log.Fields{"resource": rt}).Debug()

	_, err := d.discoverResource(rt)
	if err != nil {
		return err
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return err
		}
	}

	// Note: Currently(Jan./2019) we only support deleting neuvector-validating-admission-webhook resource
	obj, ok := res.(metav1.Object)
	if !ok {
		return ErrResourceNotSupported
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	err = d.client.Delete(context.Background(), obj)
	return err
}

func (d *kubernetes) SetFlavor(flavor string) error {
	if d.flavor == "" {
		d.flavor = flavor
		_k8sFlavor = flavor
	}

	return nil
}

// revertCount: how many times the ValidatingWebhookConfiguration resource has been reverted by this controller.
//
//	if it's >= 1, do not revert the ValidatingWebhookConfiguration resource just becuase of unknown matchExpressions keys
func IsK8sNvWebhookConfigured(whName, failurePolicy string, wh *K8sAdmRegWebhook, checkNsSelector bool, revertCount *uint32,
	unexpectedMatchKeys utils.Set) bool {

	var nvOpResources []*NvAdmRegRuleSetting // is for what nv expects
	// key/operator in webhook NamespaceSelector's MatchExpressions.
	selKeyOps := map[string]string{}
	switch whName {
	case NvAdmValidatingWebhookName:
		nvOpResources = AdmResForOpsSettings
		selKeyOps[NsSelectorKeySkipNV] = NsSelectorOpNotExist
	case NvStatusValidatingWebhookName:
		nvOpResources = StatusResForOpsSettings
		selKeyOps[NsSelectorKeyStatusNV] = NsSelectorOpExists
	case NvCrdValidatingWebhookName:
		nvOpResources = CrdResForOpsSettings
		checkNsSelector = false
	default:
		return true // ignore other webhooks for now
	}

	if len(wh.Rules) != len(nvOpResources) || wh.FailurePolicy == nil || *wh.FailurePolicy != failurePolicy {
		return false
	}
	isNvRulesFound := make([]bool, len(nvOpResources))
	expectedApiVersions := utils.NewSet(K8sApiVersionV1, K8sApiVersionV1Beta1, K8sApiVersionV1Beta2)
	for _, k8sWhRule := range wh.Rules {
		foundRule := false
		k8sApiGroups := utils.NewSetFromSliceKind(k8sWhRule.Rule.ApiGroups)
		k8sApiVersions := utils.NewSetFromSliceKind(k8sWhRule.Rule.ApiVersions)
		k8sRuleOperations := utils.NewSetFromSliceKind(k8sWhRule.Operations)
		k8sRuleResources := utils.NewSetFromSliceKind(k8sWhRule.Rule.Resources)
		for j := 0; j < len(nvOpResources); j++ {
			if nvOpResources[j].Resources.Equal(k8sRuleResources) && nvOpResources[j].Operations.Equal(k8sRuleOperations) &&
				expectedApiVersions.Equal(k8sApiVersions) && nvOpResources[j].ApiGroups.Equal(k8sApiGroups) {
				if k8sWhRule.Rule.Scope != nil && *k8sWhRule.Rule.Scope == nvOpResources[j].Scope {
					foundRule = true
					isNvRulesFound[j] = true
					break
				}
			}
		}
		if !foundRule {
			return false
		}
	}
	for _, found := range isNvRulesFound {
		if !found {
			return false
		}
	}
	if checkNsSelector {
		for _, expr := range wh.NamespaceSelector.MatchExpressions {
			key := expr.Key
			op := string(expr.Operator)
			if expectedOp, ok := selKeyOps[key]; !ok || expectedOp != op {
				// an unexpected label(key/op) is found in webhook NamespaceSelector's MatchExpressions
				if revertCount != nil && *revertCount <= 1 {
					unexpectedMatchKeys.Add(key)
					log.WithFields(log.Fields{"key": key, "op": op}).Info("unexpected label")
				}
			} else {
				delete(selKeyOps, key)
			}
		}
		if len(selKeyOps) > 0 {
			unexpectedMatchKeys.Clear()
			return false
		}
	}

	return true
}

func AdjustAdmResForOC() {
	admResForCreateSet.Add(K8sResDeploymentConfigs)
	admResForUpdateSet.Add(K8sResDeploymentConfigs)
	if roleInfo, ok := rbacRolesWanted[NvRbacRole]; ok {
		rule := &k8sRbacRoleRuleInfo{
			apiGroup:  "image.openshift.io",
			resources: utils.NewSet(ocResImageStreams),
			verbs:     rbacRoleVerbs,
		}
		roleInfo.rules = append(roleInfo.rules, rule)
	}
	// ocVersionMajor == 0 : if k8s RBAC neuvector-binding-co is missing, we cannot get oc version. In this case treat it as oc 4.x
	if ocVersionMajor == 0 || ocVersionMajor > 3 {
		rbacRolesWanted[nvOperatorsRole] = &k8sRbacRoleInfo{
			name: nvOperatorsRole,
			rules: []*k8sRbacRoleRuleInfo{
				&k8sRbacRoleRuleInfo{
					apiGroup:  "config.openshift.io",
					resources: utils.NewSet(clusterOperators),
					verbs:     utils.NewSet("get", "list"),
				},
			}}
		rbacRoleBindingsWanted[nvOperatorsRoleBinding] = &k8sRbacBindingInfo{
			subjects: enforcerSubjectsWanted,
			rbacRole: rbacRolesWanted[nvOperatorsRole],
		}
	}
}

func AdjustAdmWebhookName(f1 NvQueryK8sVerFunc, f2 NvVerifyK8sNsFunc, cspType_ share.TCspType) {
	nvQueryK8sVerFunc = f1
	nvVerifyK8sNsFunc = f2
	cspType = cspType_
	NvAdmMutatingWebhookName = fmt.Sprintf("%s.%s.svc", NvAdmMutatingName, NvAdmSvcNamespace)           // ex: neuvector-mutating-admission-webhook.neuvector.svc
	NvAdmValidatingWebhookName = fmt.Sprintf("%s.%s.svc", NvAdmValidatingName, NvAdmSvcNamespace)       // ex: neuvector-validating-admission-webhook.neuvector.svc
	NvCrdValidatingWebhookName = fmt.Sprintf("%s.%s.svc", NvCrdValidatingName, NvAdmSvcNamespace)       // ex: neuvector-validating-crd-webhook.neuvector.svc
	NvStatusValidatingWebhookName = fmt.Sprintf("%s.%s.svc", nvStatusValidatingName, NvAdmSvcNamespace) // ex: neuvector-validating-status-webhook.neuvector.svc
	GetK8sVersion()

	if cspType != share.CSP_NONE {
		// extra rbac settings required by nv on csp
		rbacRolesWanted[nvCspUsageRole] = &k8sRbacRoleInfo{
			name: nvCspUsageRole,
			rules: []*k8sRbacRoleRuleInfo{
				&k8sRbacRoleRuleInfo{
					apiGroup:  "susecloud.net",
					resources: utils.NewSet(RscTypeCrdNvCspUsage),
					verbs:     utils.NewSet("get", "create", "update", "delete"),
				},
			},
		}
		rbacRoleBindingsWanted[nvCspUsageRoleBinding] = &k8sRbacBindingInfo{
			subjects: ctrlerSubjectsWanted,
			rbacRole: rbacRolesWanted[nvCspUsageRole],
		}
	}

	for _, roleInfo := range rbacRolesWanted {
		if roleInfo.namespace == constNvNamespace {
			roleInfo.namespace = NvAdmSvcNamespace
		}
	}
	for _, bindingInfo := range rbacRoleBindingsWanted {
		if bindingInfo.namespace == constNvNamespace {
			bindingInfo.namespace = NvAdmSvcNamespace
		}
	}
}

func GetK8sVersion() (int, int) {
	if k8sVersionMajor == 0 && k8sVersionMinor == 0 {
		k8sVer, ocVer := global.ORCH.GetVersion(false, false)
		SetK8sVersion(k8sVer)
		if ocVersionMajor == 0 {
			if ss := strings.Split(ocVer, "."); len(ss) > 0 {
				ocVersionMajor, _ = strconv.Atoi(ss[0])
			}
		}
	}

	return k8sVersionMajor, k8sVersionMinor
}

func SetK8sVersion(k8sVer string) {
	ss := strings.Split(k8sVer, ".")
	if len(ss) >= 1 {
		var err error
		k8sVersionMajor, err = strconv.Atoi(ss[0])
		if err != nil {
			k8sVersionMajor = 1
		}
	}
	if len(ss) >= 2 {
		k8sVersionMinor, _ = strconv.Atoi(ss[1])
	}
}

func IsRancherFlavor() bool {
	nsName := "cattle-system"
	if _, err := global.ORCH.GetResource(RscTypeNamespace, "", nsName); err != nil {
		log.WithFields(log.Fields{"namespace": nsName, "err": err}).Info("resource no found")
	} else {
		if len(nvRscMapSSO) == 0 {
			svcnames := []string{"cattle-cluster-agent", "rancher", "rancher-prime"}
			nvPermitsRscSSO := utils.NewSetFromStringSlice([]string{
				share.PERM_REG_SCAN_ID,
				share.PERM_CICD_SCAN_ID,
				share.PERM_ADM_CONTROL_ID,
				share.PERM_AUDIT_EVENTS_ID,
				share.PERM_EVENTS_ID,
				share.PERM_AUTHENTICATION_ID,
				share.PERM_AUTHORIZATION_ID,
				share.PERM_SYSTEM_CONFIG_ID,
				share.PERM_VULNERABILITY_ID,
				share.PERMS_RUNTIME_SCAN_ID,
				share.PERMS_RUNTIME_POLICIES_ID,
				share.PERMS_COMPLIANCE_ID,
				share.PERMS_SECURITY_EVENTS_ID,
				share.PERM_FED_ID,
			})
			permIDtoCRD := map[string]string{
				share.PERM_REG_SCAN_ID:          "registryscan",
				share.PERM_CICD_SCAN_ID:         "ciscan",
				share.PERM_ADM_CONTROL_ID:       "admissioncontrol",
				share.PERM_AUDIT_EVENTS_ID:      "auditevents",
				share.PERM_EVENTS_ID:            "events",
				share.PERM_AUTHENTICATION_ID:    "authentication",
				share.PERM_AUTHORIZATION_ID:     "authorization",
				share.PERM_SYSTEM_CONFIG_ID:     "systemconfig",
				share.PERM_VULNERABILITY_ID:     "vulnerability",
				share.PERMS_RUNTIME_SCAN_ID:     "runtimescan",
				share.PERMS_RUNTIME_POLICIES_ID: "runtimepolicy",
				share.PERMS_COMPLIANCE_ID:       "compliance",
				share.PERMS_SECURITY_EVENTS_ID:  "securityevents",
				share.PERM_FED_ID:               "federation",
			}
			for _, svcname := range svcnames {
				if _, err := global.ORCH.GetResource(RscTypeService, nsName, svcname); err == nil {
					log.WithFields(log.Fields{"namespace": nsName, "service": svcname}).Info("resource found")
					// For Rancher SSO only: nv permission crd kind -> nv permission uint32 value
					nvPermitsValueSSO = make(map[string]share.NvPermissions, nvPermitsRscSSO.Cardinality()+len(permIDtoCRD))
					for _, option := range access.PermissionOptions {
						if crdKind, ok := permIDtoCRD[option.ID]; ok || nvPermitsRscSSO.Contains(option.ID) {
							var readPermits uint32
							var writePermits uint32
							if len(option.ComplexPermits) > 0 {
								for _, option2 := range option.ComplexPermits {
									if option.ReadSupported && option2.ReadSupported {
										readPermits |= option2.Value
									}
									if option.WriteSupported && option2.WriteSupported {
										writePermits |= option2.Value
									}
								}
							} else {
								if option.ReadSupported {
									readPermits |= option.Value
								}
								if option.WriteSupported {
									writePermits |= option.Value
								}
							}
							if ok {
								nvPermitsValueSSO[crdKind] = share.NvPermissions{ReadValue: readPermits, WriteValue: writePermits}
								nvPermitsRscSSO.Add(crdKind)
							}
							if nvPermitsRscSSO.Contains(option.ID) {
								optionID := strings.ReplaceAll(option.ID, "_", "-")
								nvPermitsValueSSO[optionID] = share.NvPermissions{ReadValue: readPermits, WriteValue: writePermits}
							}
						}
					}

					nvRscMapSSO = map[string]utils.Set{ // apiGroup -> neuvector permission resources
						"read-only.neuvector.api.io": nvPermitsRscSSO,
						"api.neuvector.com":          nvPermitsRscSSO,
						"permission.neuvector.com":   nvPermitsRscSSO,
						"*":                          nvPermitsRscSSO,
					}

					return true
				}
			}
		} else {
			return true
		}
	}

	return false
}

func SetLeader(lead bool) {
	isLeader = lead
}

func UpdateDeploymentReplicates(name string, replicas int32) error {
	obj, err := global.ORCH.GetResource(RscTypeDeployment, NvAdmSvcNamespace, name)
	if err != nil {
		log.WithFields(log.Fields{"name": name, "err": err}).Error("resource no found")
		return err
	} else {
		if deployObj, ok := obj.(*appsv1.Deployment); ok {
			var old int32
			if deployObj.Spec.Replicas != nil {
				old = *deployObj.Spec.Replicas
			}
			if old != replicas {
				deployObj.Spec.Replicas = &replicas
				err = global.ORCH.UpdateResource(RscTypeDeployment, deployObj)
				if err != nil {
					log.WithFields(log.Fields{"name": name, "err": err}).Error("update resource failed")
					return err
				}
			}
		}
	}

	return nil
}

func CreateNvCrdObject(rt string) (interface{}, error) {
	r, ok := resourceMakers[rt]
	if !ok {
		return nil, fmt.Errorf("Unknown resource name: %s", rt)
	}
	maker := r.makers[0]

	return maker.newObject(), nil
}

func getNeuvectorSvcAccount() {
	// controller's sa is known by k8s token, not by deployment resource
	resInfo := map[string]string{ // resource object name : resource type
		"neuvector-updater-pod":          RscTypeCronJob,
		"neuvector-enforcer-pod":         RscTypeDaemonSet,
		"neuvector-scanner-pod":          RscTypeDeployment,
		"neuvector-registry-adapter-pod": RscTypeDeployment,
		"neuvector-cert-upgrader-pod":    RscTypeCronJob,
	}

	for objName, rt := range resInfo {
		var sa string
		obj, err := global.ORCH.GetResource(rt, NvAdmSvcNamespace, objName)
		if err != nil {
			if objName == "neuvector-registry-adapter-pod" {
				// registry_adapter is not deployed. do not include its sa in the rbac checking/alert
				regAdapterSubjectWanted = ""
			}
			log.WithFields(log.Fields{"name": objName, "rt": rt, "err": err}).Error("resource no found")
			continue
		}
		switch objName {
		case "neuvector-updater-pod", "neuvector-cert-upgrader-pod":
			if cronjobObj, ok := obj.(*CronJob); ok {
				sa = cronjobObj.SA

				switch objName {
				case "neuvector-updater-pod":
					updaterSubjectWanted = sa
					scannerSubjectsWanted[0] = updaterSubjectWanted
					scannerSubjectsWanted[1] = ctrlerSubjectWanted
				case "neuvector-cert-upgrader-pod":
					certUpgraderSubjectWanted = sa
					certUpgraderSubjectsWanted[0] = certUpgraderSubjectWanted
				}
			}
		case "neuvector-enforcer-pod": // get enforcer daemonset service account
			if dsObj, ok := obj.(*DaemonSet); ok {
				enforcerSubjectWanted = dsObj.SA
				sa = enforcerSubjectWanted
				enforcerSubjectsWanted[0] = enforcerSubjectWanted
				enforcerSubjectsWanted[1] = ctrlerSubjectWanted
			}
		case "neuvector-scanner-pod", "neuvector-registry-adapter-pod":
			if o, ok := obj.(*appsv1.Deployment); ok && o != nil {
				sa = "default"
				spec := o.Spec.Template.Spec
				if spec.ServiceAccountName != "" {
					sa = spec.ServiceAccountName
				} else if spec.DeprecatedServiceAccount != "" {
					sa = spec.DeprecatedServiceAccount
				}
				switch objName {
				case "neuvector-scanner-pod": // get scanner deployment service account
					scannerSubjectWanted = sa
				case "neuvector-registry-adapter-pod": // get registry-adapter deployment service account
					regAdapterSubjectWanted = sa
				}
			}
		}
		log.WithFields(log.Fields{"name": objName, "sa": sa}).Info()
		continue
	}
	if regAdapterSubjectWanted == "" {
		// it means neuvector-registry-adapter-pod is not deployed.
		// so the alert message for rolebinding neuvector-binding-secret will not containsa the "registry-adapter" sa
		regAdapterSubjectWanted = ctrlerSubjectWanted
	}

	secretSubjectsWanted[0] = enforcerSubjectWanted
	secretSubjectsWanted[1] = ctrlerSubjectWanted
	secretSubjectsWanted[2] = scannerSubjectWanted
	secretSubjectsWanted[3] = regAdapterSubjectWanted
}

func xlatePersistentVolumeClaim(obj metav1.Object) (string, interface{}) {
	return "", nil
}

func RetrieveBootstrapPassword() string {
	var bootstrapPwd string

	obj, err := global.ORCH.GetResource(RscTypeSecret, NvAdmSvcNamespace, "neuvector-bootstrap-secret")
	if obj != nil && err == nil {
		if s, ok := obj.(*corev1.Secret); ok {
			if s.Data != nil {
				if v, ok := s.Data["bootstrapPassword"]; ok {
					bootstrapPwd = string(v)
				}
			}
		} else {
			err = fmt.Errorf("type conversion failed")
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
	}

	return bootstrapPwd
}

func GetNvControllerPodsNumber() {
	var requestMemory string
	var limitMemory string
	var podsIP []string

	pods, err := global.ORCH.ListResource(RscTypePod, NvAdmSvcNamespace)
	if err == nil {
		for _, obj := range pods {
			if pod, ok := obj.(*Pod); ok && pod != nil {
				if v, ok := pod.Labels["app"]; ok && v == "neuvector-controller-pod" {
					for _, ctr := range pod.Containers {
						if ctr.RequestMemory != requestMemory || ctr.LimitMemory != limitMemory {
							requestMemory = ctr.RequestMemory
							limitMemory = ctr.LimitMemory
						}
					}
					podsIP = append(podsIP, pod.IPNet.String())
				}
			}
		}
	}
	log.WithFields(log.Fields{"pods": strings.Join(podsIP, ","), "requests": requestMemory, "limits": limitMemory, "err": err}).Info()
}
