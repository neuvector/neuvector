package resource

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/neuvector/k8s"
	apiv1 "github.com/neuvector/k8s/apis/admissionregistration/v1"
	apiv1beta1 "github.com/neuvector/k8s/apis/admissionregistration/v1beta1"
	apiextv1 "github.com/neuvector/k8s/apis/apiextensions/v1"
	apiextv1b1 "github.com/neuvector/k8s/apis/apiextensions/v1beta1"
	appsv1 "github.com/neuvector/k8s/apis/apps/v1"
	batchv1b1 "github.com/neuvector/k8s/apis/batch/v1beta1"
	corev1 "github.com/neuvector/k8s/apis/core/v1"
	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	rbacv1 "github.com/neuvector/k8s/apis/rbac/v1"
	rbacv1b1 "github.com/neuvector/k8s/apis/rbac/v1beta1"
	log "github.com/sirupsen/logrus"

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
	K8sResDaemonsets              = "daemonsets"
	K8sResDeployments             = "deployments"
	K8sResDeploymentConfigs       = "deploymentconfigs"
	K8sResJobs                    = "jobs"
	K8sResPods                    = "pods"
	K8sResNodes                   = "nodes"
	K8sResReplicationControllers  = "replicationcontrollers"
	K8sResReplicasets             = "replicasets"
	K8sResServices                = "services"
	K8sResStatefulSets            = "statefulsets"
	K8sResRoles                   = "roles"
	K8sResRolebindings            = "rolebindings"
	K8sResClusterRoles            = "clusterroles"
	K8sResClusterRolebindings     = "clusterrolebindings"
	K8sResRbacRoles               = "roles.rbac.authorization.k8s.io"
	K8sResRbacClusterRoles        = "clusterroles.rbac.authorization.k8s.io"
	K8sResRbacRolebindings        = "rolebindings.rbac.authorization.k8s.io"
	K8sResRbacClusterRolebindings = "clusterrolebindings.rbac.authorization.k8s.io"
)

const (
	NvDeploymentName = "neuvector-controller-pod"
	NvDaemonSetName  = "neuvector-allinone-pod"
)

const (
	nvOperatorsRole         = "neuvector-binding-co"
	nvOperatorsRoleBinding  = nvOperatorsRole
	NvAppRole               = "neuvector-binding-app"
	nvAppRoleBinding        = NvAppRole
	NvRbacRole              = "neuvector-binding-rbac"
	nvRbacRoleBinding       = NvRbacRole
	NvAdmCtrlRole           = "neuvector-binding-admission"
	nvAdmCtrlRoleBinding    = NvAdmCtrlRole
	nvCrdRole               = "neuvector-binding-customresourcedefinition"
	nvCrdRoleBinding        = nvCrdRole
	nvCrdSecRuleRole        = "neuvector-binding-nvsecurityrules"
	nvCrdSecRoleBinding     = nvCrdSecRuleRole
	nvCrdAdmCtrlRole        = "neuvector-binding-nvadmissioncontrolsecurityrules"
	nvCrdAdmCtrlRoleBinding = nvCrdAdmCtrlRole
	nvCrdDlpRole            = "neuvector-binding-nvdlpsecurityrules"
	nvCrdDlpRoleBinding     = nvCrdDlpRole
	nvCrdWafRole            = "neuvector-binding-nvwafsecurityrules"
	nvCrdWafRoleBinding     = nvCrdWafRole
	NvScannerRole           = "neuvector-binding-scanner"
	NvScannerRoleBinding    = NvScannerRole
	NvAdminRoleBinding      = "neuvector-admin"
	nvViewRoleBinding       = "neuvector-binding-view"
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
	newObject  func() k8s.Resource
	newList    func() k8s.ResourceList
	xlate      func(obj k8s.Resource) (string, interface{})
	xlate2     func(obj k8s.Resource, action string)
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

//--- for generic types in admissionregistration v1/vebeta1
type K8sAdmRegServiceReference struct {
	Namespace *string
	Name      *string
	Path      *string
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
	Name                    *string
	AdmissionReviewVersions []string
	ClientConfig            *K8sAdmRegWebhookClientConfig
	Rules                   []*K8sAdmRegRuleWithOperations
	FailurePolicy           *string
	NamespaceSelector       *metav1.LabelSelector
	SideEffects             *string
}

type K8sAdmRegValidatingWebhookConfiguration struct {
	Metadata *metav1.ObjectMeta
	Webhooks []*K8sAdmRegWebhook
}

type NvAdmRegRuleSetting struct {
	ApiGroups  utils.Set
	Operations utils.Set
	Resources  utils.Set
	Scope      string
}

type NvCrdInitFunc func(leader bool, cspType share.TCspType)

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

var admResForCreateSet = utils.NewSet(K8sResCronjobs, K8sResDaemonsets, K8sResDeployments, K8sResJobs, K8sResPods, K8sResReplicasets, K8sResReplicationControllers, K8sResStatefulSets)
var admResForUpdateSet = utils.NewSet(K8sResDaemonsets, K8sResDeployments, K8sResReplicationControllers, K8sResStatefulSets)
var admRbacResForCreateUpdate1 = utils.NewSet(K8sResRoles, K8sResRolebindings)
var admRbacResForCreateUpdate2 = utils.NewSet(K8sResClusterRoles, K8sResClusterRolebindings)
var AdmResForOpsSettings = []*NvAdmRegRuleSetting{
	// do not change the order of the following elements!
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Create),
		Resources:  admResForCreateSet,
		Scope:      apiv1beta1.NamespacedScope,
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Update),
		Resources:  admResForUpdateSet,
		Scope:      apiv1beta1.NamespacedScope,
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  rbacApiGroups,
		Operations: opCreateDelete,
		Resources:  admRbacResForCreateUpdate1,
		Scope:      apiv1beta1.NamespacedScope,
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  rbacApiGroups,
		Operations: opCreateDelete,
		Resources:  admRbacResForCreateUpdate2,
		Scope:      apiv1beta1.AllScopes,
	},
}

var crdResForAllOpSet = utils.NewSet(RscTypeCrdSecurityRule, RscTypeCrdClusterSecurityRule, RscTypeCrdAdmCtrlSecurityRule, RscTypeCrdDlpSecurityRule,
	RscTypeCrdWafSecurityRule)
var CrdResForOpsSettings = []*NvAdmRegRuleSetting{
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Create, Update, Delete),
		Resources:  crdResForAllOpSet,
		Scope:      apiv1beta1.AllScopes,
	},
}

var statusResForCreateUpdateSet = utils.NewSet(K8sResServices)
var statusResForDeleteSet = utils.NewSet(K8sResDaemonsets, K8sResDeployments, K8sResServices, K8sResStatefulSets)
var StatusResForOpsSettings = []*NvAdmRegRuleSetting{
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: opCreateDelete,
		Resources:  statusResForCreateUpdateSet,
		Scope:      apiv1beta1.NamespacedScope,
	},
	&NvAdmRegRuleSetting{
		ApiGroups:  allApiGroups,
		Operations: utils.NewSet(Delete),
		Resources:  statusResForDeleteSet,
		Scope:      apiv1beta1.NamespacedScope,
	},
}

var k8sVersionMajor int
var k8sVersionMinor int
var ocVersionMajor int

var cacheEventFunc common.CacheEventFunc

var nvCrdInitFunc NvCrdInitFunc
var nvQueryK8sVerFunc NvQueryK8sVerFunc
var nvVerifyK8sNsFunc NvVerifyK8sNsFunc
var isLeader bool
var CtrlPlaneOpInWhExpr string
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
				func() k8s.Resource { return new(corev1.Node) },
				func() k8s.ResourceList { return new(corev1.NodeList) },
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
				func() k8s.Resource { return new(corev1.Namespace) },
				func() k8s.ResourceList { return new(corev1.NamespaceList) },
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
				func() k8s.Resource { return new(corev1.Service) },
				func() k8s.ResourceList { return new(corev1.ServiceList) },
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
				func() k8s.Resource { return new(corev1.Pod) },
				func() k8s.ResourceList { return new(corev1.PodList) },
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
				func() k8s.Resource { return new(appsv1.Deployment) },
				func() k8s.ResourceList { return new(appsv1.DeploymentList) },
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
				func() k8s.Resource { return new(appsv1.DaemonSet) },
				func() k8s.ResourceList { return new(appsv1.DaemonSetList) },
				xlateDaemonSet,
				nil,
			},
		},
	},
	RscTypeCronJob: k8sResource{
		apiGroup: "batch",
		makers: []*resourceMaker{
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(batchv1b1.CronJob) },
				func() k8s.ResourceList { return new(batchv1b1.CronJobList) },
				xlateCronJob,
				nil,
			},
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(CronJobV1) },
				func() k8s.ResourceList { return new(CronJobListV1) },
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
				func() k8s.Resource { return new(ocImageStream) },
				func() k8s.ResourceList { return new(ocImageStreamList) },
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
				func() k8s.Resource { return new(rbacv1.Role) },
				func() k8s.ResourceList { return new(rbacv1.RoleList) },
				xlateRole,
				xlateRole2,
			},
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(rbacv1b1.Role) },
				func() k8s.ResourceList { return new(rbacv1b1.RoleList) },
				xlateRole,
				xlateRole2,
			},
		},
	},
	K8sRscTypeClusRole: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(rbacv1.ClusterRole) },
				func() k8s.ResourceList { return new(rbacv1.ClusterRoleList) },
				xlateClusRole,
				xlateClusRole2,
			},
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(rbacv1b1.ClusterRole) },
				func() k8s.ResourceList { return new(rbacv1b1.ClusterRoleList) },
				xlateClusRole,
				xlateClusRole2,
			},
		},
	},
	k8sRscTypeRoleBinding: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(rbacv1.RoleBinding) },
				func() k8s.ResourceList { return new(rbacv1.RoleBindingList) },
				xlateRoleBinding,
				xlateRoleBinding2,
			},
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(rbacv1b1.RoleBinding) },
				func() k8s.ResourceList { return new(rbacv1b1.RoleBindingList) },
				xlateRoleBinding,
				xlateRoleBinding2,
			},
		},
	},
	K8sRscTypeClusRoleBinding: k8sResource{
		apiGroup: k8sRbacApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(rbacv1.ClusterRoleBinding) },
				func() k8s.ResourceList { return new(rbacv1.ClusterRoleBindingList) },
				xlateClusRoleBinding,
				xlateClusRoleBinding2,
			},
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(rbacv1b1.ClusterRoleBinding) },
				func() k8s.ResourceList { return new(rbacv1b1.ClusterRoleBindingList) },
				xlateClusRoleBinding,
				xlateClusRoleBinding2,
			},
		},
	},
	RscTypeCrd: k8sResource{
		apiGroup: k8sCrdApiGroup,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(apiextv1b1.CustomResourceDefinition) },
				func() k8s.ResourceList { return new(apiextv1b1.CustomResourceDefinitionList) },
				xlateCrd,
				nil,
			},
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(apiextv1.CustomResourceDefinition) },
				func() k8s.ResourceList { return new(apiextv1.CustomResourceDefinitionList) },
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
				func() k8s.Resource { return new(NvSecurityRule) },
				func() k8s.ResourceList { return new(NvSecurityRuleList) },
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
				func() k8s.Resource { return new(NvClusterSecurityRule) },
				func() k8s.ResourceList { return new(NvClusterSecurityRuleList) },
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
				func() k8s.Resource { return new(NvAdmCtrlSecurityRule) },
				func() k8s.ResourceList { return new(NvAdmCtrlSecurityRuleList) },
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
				func() k8s.Resource { return new(NvDlpSecurityRule) },
				func() k8s.ResourceList { return new(NvDlpSecurityRuleList) },
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
				func() k8s.Resource { return new(NvWafSecurityRule) },
				func() k8s.ResourceList { return new(NvWafSecurityRuleList) },
				xlateCrdWafSecurityRule,
				nil,
			},
		},
	},
	RscTypeCrdNvCspUsage: k8sResource{
		apiGroup: constApiGroupNV,
		makers: []*resourceMaker{
			&resourceMaker{
				"v1",
				func() k8s.Resource { return new(NvCspUsage) },
				func() k8s.ResourceList { return new(NvCspUsageList) },
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
				func() k8s.Resource { return new(corev1.ConfigMap) },
				func() k8s.ResourceList { return new(corev1.ConfigMapList) },
				xlateConfigMap,
				nil,
			},
		},
	},
	/*RscTypeMutatingWebhookConfiguration: k8sResource{
			apiGroup: k8sAdmApiGroup,
			makers: []*resourceMaker{
				&resourceMaker{
					"v1",
					func() k8s.Resource { return new(apiv1.MutatingWebhookConfiguration) },
					func() k8s.ResourceList { return new(apiv1.MutatingWebhookConfigurationList) },
					xlateMutatingWebhookConfiguration,
					nil,
				},
	            &resourceMaker{
					"v1beta1",
					func() k8s.Resource { return new(apiv1beta1.MutatingWebhookConfiguration) },
					func() k8s.ResourceList { return new(apiv1beta1.MutatingWebhookConfigurationList) },
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
				func() k8s.Resource { return new(apiv1.ValidatingWebhookConfiguration) },
				func() k8s.ResourceList { return new(apiv1.ValidatingWebhookConfigurationList) },
				xlateValidatingWebhookConfiguration,
				nil,
			},
			&resourceMaker{
				"v1beta1",
				func() k8s.Resource { return new(apiv1beta1.ValidatingWebhookConfiguration) },
				func() k8s.ResourceList { return new(apiv1beta1.ValidatingWebhookConfigurationList) },
				xlateValidatingWebhookConfiguration,
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

	roleCache map[k8sObjectRef]string                // role -> nv role
	userCache map[k8sSubjectObjRef]utils.Set         // user -> set of k8sRoleRef
	rbacCache map[k8sSubjectObjRef]map[string]string // user -> (domain -> nv role); it's updated after rbacEvaluateUser() call
}

func newKubernetesDriver(platform, flavor, network string) *kubernetes {
	d := &kubernetes{
		noop:      newNoopDriver(platform, flavor, network),
		watchers:  make(map[string]*resourceWatcher),
		roleCache: make(map[k8sObjectRef]string),
		userCache: make(map[k8sSubjectObjRef]utils.Set),
		rbacCache: make(map[k8sSubjectObjRef]map[string]string),
	}
	return d
}

/*
// Node add and remove
event=Add node=&{UID:2d39e6bb-267f-11e8-8d3e-0800273d5dc6 Name:host3 IPNets:[{IP:10.254.101.103 Mask:ffffffff}]}
event=Delete node=&{UID:2d39e6bb-267f-11e8-8d3e-0800273d5dc6 Name:host3 IPNets:[{IP:10.254.101.103 Mask:ffffffff}]}
*/

func xlateNode(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*corev1.Node); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &Node{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			IPNets: make([]net.IPNet, 0),
		}
		if o.Status != nil {
			addrs := o.Status.GetAddresses()
			for _, addr := range addrs {
				if addr.GetType() == k8sNodeTypeInternalIP {
					if ip := net.ParseIP(addr.GetAddress()); ip != nil {
						if utils.IsIPv4(ip) {
							r.IPNets = append(r.IPNets, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
						} else {
							r.IPNets = append(r.IPNets, net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
						}
					}
				}
			}
		}
		r.Labels = meta.GetLabels()
		r.Annotations = meta.GetAnnotations()
		// special handling for IBM cloud because it customizes the k8s node name to using IP, but not the system hostname
		if o.Spec != nil && o.Spec.ProviderID != nil && strings.HasPrefix(*o.Spec.ProviderID, "ibm://") {
			// [ex] ibm-cloud.kubernetes.io/worker-id: kube-c40msj4d0tb4oeriggqg-atibmcluste-default-000001f1
			if hostname, ok := r.Labels["ibm-cloud.kubernetes.io/worker-id"]; ok {
				r.IBMCloudWorkerID = hostname
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateNamespace(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*corev1.Namespace); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &Namespace{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Labels: meta.GetLabels(),
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
func xlateService(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*corev1.Service); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &Service{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			Labels: make(map[string]string),
		}
		if o.Spec != nil {
			r.IPs = make([]net.IP, 0)
			if tip := net.ParseIP(o.Spec.GetClusterIP()); tip != nil {
				r.IPs = append(r.IPs, tip)
			}
			r.Selector = o.Spec.GetSelector()
			r.Type = o.Spec.GetType()
			r.ExternalIPs = make([]net.IP, len(o.Spec.GetExternalIPs()))
			for i, e := range o.Spec.GetExternalIPs() {
				r.ExternalIPs[i] = net.ParseIP(e)
			}
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
func xlatePod(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*corev1.Pod); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &Pod{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			Labels: meta.GetLabels(),
		}
		if len(meta.OwnerReferences) >= 1 {
			if owner := meta.OwnerReferences[0]; owner != nil {
				r.OwnerUID = owner.GetUid()
				r.OwnerName = owner.GetName()
				r.OwnerType = owner.GetKind()
			}
		}

		if o.Spec != nil {
			r.Node = o.Spec.GetNodeName()
			r.HostNet = o.Spec.GetHostNetwork()
			for _, c := range o.Spec.GetContainers() {
				liveness := c.GetLivenessProbe()
				readiness := c.GetReadinessProbe()
				if liveness != nil || readiness != nil {
					if handler := liveness.GetHandler(); handler != nil {
						if exec := handler.GetExec(); exec != nil {
							r.LivenessCmds = append(r.LivenessCmds, exec.GetCommand())
						}
					}
					if handler := readiness.GetHandler(); handler != nil {
						if exec := handler.GetExec(); exec != nil {
							r.ReadinessCmds = append(r.ReadinessCmds, exec.GetCommand())
						}
					}
				}
			}
			if r.SA = o.Spec.GetServiceAccountName(); r.SA == "" {
				r.SA = o.Spec.GetServiceAccount()
			}
			if r.SA == "" {
				r.SA = "default" // see https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
			}
		}
		if o.Status != nil {
			if ip := net.ParseIP(o.Status.GetPodIP()); ip != nil {
				if utils.IsIPv4(ip) {
					r.IPNet = net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				} else {
					r.IPNet = net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			}
			if o.Status.GetPhase() == "Running" {
				r.Running = true
			}

			if r.Domain != NvAdmSvcNamespace && len(o.Status.ContainerStatuses) > 0 {
				for _, cs := range o.Status.GetContainerStatuses() {
					if cs != nil {
						containerID := cs.GetContainerID()
						for _, prefix := range []string{"docker://", "containerd://", "cri-o://"} {
							if strings.HasPrefix(containerID, prefix) {
								r.ContainerIDs = append(r.ContainerIDs, containerID[len(prefix):])
							}
						}
					}
				}
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateDeployment(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*appsv1.Deployment); ok && o != nil {
		meta := o.Metadata
		if meta == nil || meta.GetNamespace() != NvAdmSvcNamespace || meta.GetName() != "neuvector-scanner-pod" {
			return "", nil
		}
		r := &Deployment{
			UID:      meta.GetUid(),
			Name:     meta.GetName(),
			Domain:   meta.GetNamespace(),
			Replicas: o.Spec.GetReplicas(),
		}
		return r.UID, r
	}

	return "", nil
}

func xlateDaemonSet(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*appsv1.DaemonSet); ok && o != nil {
		meta := o.Metadata
		if meta == nil || meta.GetNamespace() != NvAdmSvcNamespace || meta.GetName() != "neuvector-enforcer-pod" {
			return "", nil
		}
		r := &DaemonSet{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			SA:     "default",
		}
		if o.Spec != nil && o.Spec.Template != nil && o.Spec.Template.Spec != nil {
			spec := o.Spec.Template.Spec
			if spec.ServiceAccountName != nil && *spec.ServiceAccountName != "" {
				r.SA = *spec.ServiceAccountName
			} else if spec.ServiceAccount != nil && *spec.ServiceAccount != "" {
				r.SA = *spec.ServiceAccount
			}
		}
		return r.UID, r
	}

	return "", nil
}

func xlateCronJob(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*batchv1b1.CronJob); ok && o != nil {
		meta := o.Metadata
		if meta == nil || meta.GetNamespace() != NvAdmSvcNamespace || meta.GetName() != "neuvector-updater-pod" {
			return "", nil
		}
		r := &CronJob{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			SA:     "default",
		}
		if o != nil && o.Spec != nil && o.Spec.JobTemplate != nil && o.Spec.JobTemplate.Spec != nil &&
			o.Spec.JobTemplate.Spec.Template != nil && o.Spec.JobTemplate.Spec.Template.Spec != nil {
			spec := o.Spec.JobTemplate.Spec.Template.Spec
			if spec.ServiceAccountName != nil && *spec.ServiceAccountName != "" {
				r.SA = *spec.ServiceAccountName
			} else if spec.ServiceAccount != nil && *spec.ServiceAccount != "" {
				r.SA = *spec.ServiceAccount
			}
		}
		return r.UID, r
	} else if o, ok := obj.(*CronJobV1); ok && o != nil {
		meta := o.GetMetadata()
		if meta == nil || meta.GetNamespace() != NvAdmSvcNamespace || meta.GetName() != "neuvector-updater-pod" {
			return "", nil
		}
		r := &CronJob{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			SA:     "default",
		}
		spec := &o.Spec.JobTemplate.Spec.Template.Spec
		if spec.ServiceAccountName != "" {
			r.SA = spec.ServiceAccountName
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

func xlateImage(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*ocImageStream); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &Image{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
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

func xlateCrd(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*apiextv1b1.CustomResourceDefinition); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
		}
		return r.UID, o
	} else if o, ok := obj.(*apiextv1.CustomResourceDefinition); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdNvSecurityRule(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvSecurityRule); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdNvClusterSecurityRule(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvClusterSecurityRule); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdAdmCtrlRule(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvAdmCtrlSecurityRule); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:  meta.GetUid(),
			Name: meta.GetName(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdDlpSecurityRule(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvDlpSecurityRule); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:  meta.GetUid(),
			Name: meta.GetName(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdWafSecurityRule(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvWafSecurityRule); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:  meta.GetUid(),
			Name: meta.GetName(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateCrdCspUsage(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*NvCspUsage); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &CRD{
			UID:  meta.GetUid(),
			Name: meta.GetName(),
		}
		return r.UID, o
	}

	return "", nil
}

func xlateConfigMap(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*corev1.ConfigMap); ok {
		if o.Metadata == nil {
			return "", nil
		}
		meta := o.Metadata
		r := &ConfigMap{
			UID:    meta.GetUid(),
			Name:   meta.GetName(),
			Domain: meta.GetNamespace(),
			Data:   o.Data,
		}
		return r.UID, r
	}

	return "", nil
}

func xlateMutatingWebhookConfiguration(obj k8s.Resource) (string, interface{}) {
	var meta *metav1.ObjectMeta
	if o, ok := obj.(*apiv1.MutatingWebhookConfiguration); ok {
		meta = o.Metadata
	} else if o, ok := obj.(*apiv1beta1.MutatingWebhookConfiguration); ok {
		meta = o.Metadata
	}
	if meta != nil {
		r := &AdmissionWebhookConfiguration{
			AdmType: nvAdmMutateType,
			Name:    meta.GetName(),
		}
		return meta.GetUid(), r
	}
	return "", nil
}

func xlateValidatingWebhookConfiguration(obj k8s.Resource) (string, interface{}) {
	var meta *metav1.ObjectMeta
	if o, ok := obj.(*apiv1.ValidatingWebhookConfiguration); ok {
		meta = o.Metadata
	} else if o, ok := obj.(*apiv1beta1.ValidatingWebhookConfiguration); ok {
		meta = o.Metadata
	}
	if meta != nil && meta.GetName() == NvAdmValidatingName {
		r := &AdmissionWebhookConfiguration{
			AdmType: nvAdmValidateType,
			Name:    meta.GetName(),
		}
		return meta.GetUid(), r
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
	v := g.GetPreferredVersion().GetVersion()
	for _, maker := range r.makers {
		if v == maker.apiVersion {
			return maker, nil
		}
	}

	// Second, going through versions by our order
	vers := g.GetVersions()
	supported := make([]string, len(vers))
	for _, maker := range r.makers {
		for i, ver := range vers {
			supported[i] = ver.GetVersion()
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
	switch rt {
	case RscTypeImage:
		_, err = d.discoverResource(rt)
		if err == nil {
			d.lock.Lock()
			k8s.Register("image.openshift.io", "v1", "imagestreams", true, &ocImageStream{})
			k8s.RegisterList("image.openshift.io", "v1", "imagestreams", true, &ocImageStreamList{})
			d.lock.Unlock()
		}
	case RscTypeCrdSecurityRule:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvSecurityRulePlural, true, &NvSecurityRule{})
		k8s.RegisterList("neuvector.com", "v1", NvSecurityRulePlural, true, &NvSecurityRuleList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	case RscTypeCrdClusterSecurityRule:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvClusterSecurityRulePlural, false, &NvClusterSecurityRule{})
		k8s.RegisterList("neuvector.com", "v1", NvClusterSecurityRulePlural, false, &NvClusterSecurityRuleList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	case RscTypeCrdAdmCtrlSecurityRule:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvAdmCtrlSecurityRulePlural, false, &NvAdmCtrlSecurityRule{})
		k8s.RegisterList("neuvector.com", "v1", NvAdmCtrlSecurityRulePlural, false, &NvAdmCtrlSecurityRuleList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	case RscTypeCrdDlpSecurityRule:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvDlpSecurityRulePlural, false, &NvDlpSecurityRule{})
		k8s.RegisterList("neuvector.com", "v1", NvDlpSecurityRulePlural, false, &NvDlpSecurityRuleList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	case RscTypeCrdWafSecurityRule:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvWafSecurityRulePlural, false, &NvWafSecurityRule{})
		k8s.RegisterList("neuvector.com", "v1", NvWafSecurityRulePlural, false, &NvWafSecurityRuleList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	case RscTypeCrdNvCspUsage:
		d.lock.Lock()
		k8s.Register("neuvector.com", "v1", NvCspUsagePlural, false, &NvCspUsage{})
		k8s.RegisterList("neuvector.com", "v1", NvCspUsagePlural, false, &NvCspUsageList{})
		d.lock.Unlock()

		_, err = d.discoverResource(rt)
	default:
		err = ErrResourceNotSupported
	}
	if err != nil {
		log.WithFields(log.Fields{"resource": rt, "error": err}).Error("fail to register")
	}

	return err
}

func (d *kubernetes) ListResource(rt string) ([]interface{}, error) {
	if rt == RscTypeRBAC {
		return nil, ErrResourceNotSupported
	} else {
		return d.listResource(rt)
	}
}

func (d *kubernetes) listResource(rt string) ([]interface{}, error) {
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
	err = d.client.List(context.Background(), k8s.AllNamespaces, objs)
	d.lock.Unlock()
	if err != nil {
		return nil, err
	}

	items := reflect.ValueOf(objs).Elem().FieldByName("Items")
	if items.Kind() != reflect.Slice {
		return nil, err
	}

	list := make([]interface{}, items.Len())
	for i := 0; i < len(list); i++ {
		if item, ok := items.Index(i).Interface().(k8s.Resource); ok {
			_, list[i] = maker.xlate(item)
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

				if scb != nil {
					scb(ConnStateDisconnected, e)
				}
				if !strings.HasSuffix(e.Error(), io.EOF.Error()) {
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
	data, err := ioutil.ReadAll(resp.Body)
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
		RscTypeDeployment, RscTypeCrdNvCspUsage:
		return d.getResource(rt, namespace, name)
	case RscTypePod, RscTypeNode, RscTypeCronJob, RscTypeDaemonSet:
		if r, err := d.getResource(rt, namespace, name); err == nil {
			if maker, err := d.discoverResource(rt); err == nil {
				if _, o := maker.xlate(r.(k8s.Resource)); o != nil {
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
	obj, ok := res.(k8s.Resource)
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
		if svc != nil && svc.Metadata != nil && svc.Metadata.Name != nil && *svc.Metadata.Name == NvAdmSvcName {
			return d.updateResource(rt, res)
		}
	case RscTypeNamespace:
		ns := res.(*corev1.Namespace)
		if ns != nil && ns.Metadata != nil {
			return d.updateResource(rt, res)
		}
	case RscTypeDeployment:
		deploy := res.(*appsv1.Deployment)
		if deploy != nil && deploy.Metadata != nil && deploy.Metadata.GetNamespace() == NvAdmSvcNamespace {
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

	obj, ok := res.(k8s.Resource)
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
		RscTypeCrdAdmCtrlSecurityRule, RscTypeCrdDlpSecurityRule, RscTypeCrdWafSecurityRule, RscTypeCrdNvCspUsage:
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
	obj, ok := res.(k8s.Resource)
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

func IsK8sNvWebhookConfigured(whName, failurePolicy string, wh *K8sAdmRegWebhook, checkNsSelector bool) bool {
	var nvOpResources []*NvAdmRegRuleSetting // is for what nv expects
	// key/operator in webhook NamespaceSelector's MatchExpressions.
	selKeyOps := map[string]string{NsSelectorKeyCtrlPlane: NsSelectorOpNotExist}
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
		var ctrlPlaneOpInWhExpr string
		for _, expr := range wh.NamespaceSelector.MatchExpressions {
			key := expr.GetKey()
			value := expr.GetOperator()
			if op, ok := selKeyOps[key]; !ok || op != value {
				// an unexpected label(key/value) is found in webhook NamespaceSelector's MatchExpressions
				log.WithFields(log.Fields{"key": key, "value": value}).Info("unexpected label")
				return false
			}
			if key == NsSelectorKeyCtrlPlane { // "control-plane" key is also in MatchExpressions on AKS
				ctrlPlaneOpInWhExpr = value
			}
			delete(selKeyOps, key)
		}
		if whName == NvAdmValidatingWebhookName && CtrlPlaneOpInWhExpr != ctrlPlaneOpInWhExpr {
			CtrlPlaneOpInWhExpr = ctrlPlaneOpInWhExpr
			log.WithFields(log.Fields{"ctrlPlaneOp": CtrlPlaneOpInWhExpr}).Info()
			if isLeader && nvVerifyK8sNsFunc != nil {
				if objs, err := global.ORCH.ListResource(RscTypeNamespace); len(objs) > 0 {
					for _, obj := range objs {
						if nsObj := obj.(*Namespace); nsObj != nil {
							nvVerifyK8sNsFunc(true, nsObj.Name, nsObj.Labels)
						}
					}
				} else {
					log.WithFields(log.Fields{"err": err}).Error()
				}
			}
		}
		delete(selKeyOps, NsSelectorKeyCtrlPlane)
		if len(selKeyOps) > 0 {
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
			subjects: enforcerSubjecstWanted,
			rbacRole: rbacRolesWanted[nvOperatorsRole],
		}
	}
}

func AdjustAdmWebhookName(f1 NvCrdInitFunc, f2 NvQueryK8sVerFunc, f3 NvVerifyK8sNsFunc, cspType_ share.TCspType) {
	nvCrdInitFunc = f1
	nvQueryK8sVerFunc = f2
	nvVerifyK8sNsFunc = f3
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
					apiGroup:  constApiGroupNV,
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
		svcnames := []string{"cattle-cluster-agent", "rancher"}
		for _, svcname := range svcnames {
			if _, err := global.ORCH.GetResource(RscTypeService, nsName, svcname); err == nil {
				log.WithFields(log.Fields{"namespace": nsName, "service": svcname}).Info("resource found")
				nvPermissions := []string{"*"}
				/* Rancher SSO:
				nvPermissions := []string{"*", "admctrl", "audit_events", "authentication", "authorization", "ci_scan",
					"compliance", "config", "events", "reg_scan", "rt_policy", "rt_scan", "vulnerability", "security_events"}
				nvPermissionIndex = make(map[string]int, len(nvPermissions)+1) // permission -> index in the pseudo role's [pseudo name]
				nvIndexPermission = make(map[int]string, len(nvPermissions)+1) // index -> permission in the pseudo role's [pseudo name]
				// reserve [0] in pseudo role's pseudo name
				for i, p := range nvPermissions {
					nvPermissionIndex[p] = i + 1
					nvIndexPermission[i+1] = p
				}*/
				nvPermissionRscs = utils.NewSetFromSliceKind(nvPermissions)
				nvRscsMap = map[string]utils.Set{ // apiGroup to resources
					"read-only.neuvector.api.io": nvPermissionRscs,
					"*":                          nvPermissionRscs,
				}
				return true
			}
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
		deployObj := obj.(*appsv1.Deployment)
		if deployObj != nil && deployObj.Spec != nil && deployObj.Spec.GetReplicas() != replicas {
			deployObj.Spec.Replicas = &replicas
			err = global.ORCH.UpdateResource(RscTypeDeployment, deployObj)
			if err != nil {
				log.WithFields(log.Fields{"name": name, "err": err}).Error("update resource failed")
				return err
			}
		}
	}

	return nil
}

func getNeuvectorSvcAccount(resInfo map[string]string) {
	// controller's sa is known by k8s token, not by deployment resource
	for objName, rt := range resInfo {
		var sa string
		obj, err := global.ORCH.GetResource(rt, NvAdmSvcNamespace, objName)
		if err != nil {
			log.WithFields(log.Fields{"name": objName, "rt": rt, "err": err}).Error("resource no found")
			continue
		}
		switch objName {
		case "neuvector-updater-pod": // get updater cronjob service account
			if cronjobObj, ok := obj.(*CronJob); ok {
				sa = cronjobObj.SA
				if updaterSubjectWanted != sa {
					updaterSubjectWanted = sa
					scannerSubjecstWanted[0] = ctrlerSubjectWanted
					scannerSubjecstWanted[1] = updaterSubjectWanted
				}
			}
		case "neuvector-enforcer-pod": // get enforcer daemonset service account
			if dsObj, ok := obj.(*DaemonSet); ok {
				sa = dsObj.SA
				if enforcerSubjectWanted != sa {
					enforcerSubjectWanted = sa
					enforcerSubjecstWanted[0] = ctrlerSubjectWanted
					enforcerSubjecstWanted[1] = enforcerSubjectWanted
				}
			}
		}
		log.WithFields(log.Fields{"name": objName, "sa": sa}).Info()
		continue
	}
}
