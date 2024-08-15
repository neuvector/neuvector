package resource

import (
	"errors"
	"net"

	"github.com/neuvector/neuvector/share"
)

var ErrMethodNotSupported = errors.New("Method not supported")
var ErrResourceNotSupported = errors.New("Method on resource not supported")
var ErrUserNotFound = errors.New("User not found")

type Event struct {
	Event        string
	ResourceType string
	ResourceOld  interface{}
	ResourceNew  interface{}
	Status       string
	LastError    string
}

const (
	RscTypeNode                           = "node"
	RscTypeNamespace                      = "namespace"
	RscTypeService                        = "service"
	RscTypePod                            = "pod"
	RscTypeRBAC                           = "rbac"
	RscTypeImage                          = "image"
	RscTypeSecret                         = "secret"
	RscTypeCrd                            = "customresourcedefinition"
	RscTypeConfigMap                      = "configmap"
	RscTypeMutatingWebhookConfiguration   = "mutatingwebhookconfiguration"   // case sensitive!
	RscTypeValidatingWebhookConfiguration = "validatingwebhookconfiguration" // case sensitive!
	RscTypeCrdSecurityRule                = "nvsecurityrules"
	RscTypeCrdClusterSecurityRule         = "nvclustersecurityrules"
	RscTypeCrdAdmCtrlSecurityRule         = "nvadmissioncontrolsecurityrules"
	RscTypeCrdDlpSecurityRule             = "nvdlpsecurityrules"
	RscTypeCrdWafSecurityRule             = "nvwafsecurityrules"
	RscTypeCrdNvCspUsage                  = "cspadapterusagerecords" // case sensitive
	RscTypeCrdVulnProfile                 = "nvvulnerabilityprofiles"
	RscTypeCrdCompProfile                 = "nvcomplianceprofiles"
	RscTypeRbacRoles                      = "roles"
	RscTypeRbacClusterRoles               = "clusterroles"
	RscTypeRbacRolebindings               = "rolebindings"
	RscTypeRbacClusterRolebindings        = "clusterrolebindings"
	RscTypeDeployment                     = "deployment"
	RscTypeCronJob                        = "cronjob"
	RscTypeDaemonSet                      = "daemonset"
	RscTypeReplicaSet                     = "replicaset"
	RscTypeStatefulSet                    = "statefulset"
	RscTypePersistentVolumeClaim          = "persistentvolumeclaim"
)

const (
	RscNameMutatingWebhookConfigurations   = "mutatingwebhookconfigurations"   // case sensitive!
	RscNameValidatingWebhookConfigurations = "validatingwebhookconfigurations" // case sensitive!
	RscNameCustomResourceDefinitions       = "customresourcedefinitions"       // case sensitive!

	RscKindMutatingWebhookConfiguration   = "MutatingWebhookConfiguration"   // case sensitive!
	RscKindValidatingWebhookConfiguration = "ValidatingWebhookConfiguration" // case sensitive!
)

const RscCspUsageName = "neuvector-usage"

// ValidatingWebhookConfiguration resource instance (neuvector-validating-admission-webhook) contains 2 webhooks:
//  1. neuvector-validating-admission-webhook.neuvector.svc
//  2. neuvector-validating-status-webhook.neuvector.svc
var NvAdmMutatingName = "neuvector-mutating-admission-webhook"     // ValidatingWebhookConfiguration resource instance metadata name
var NvAdmValidatingName = "neuvector-validating-admission-webhook" // ValidatingWebhookConfiguration resource instance metadata name
var NvCrdValidatingName = "neuvector-validating-crd-webhook"       // ValidatingWebhookConfiguration resource instance metadata name
var nvStatusValidatingName = "neuvector-validating-status-webhook" // for composing webhook name only, not for ValidatingWebhookConfiguration resource instance metadata name
var NvPruneValidatingName = "neuvector-prune-orphan-crd-groups"    // for manually pruning orphan crd groups only

const (
	WatchEventAdd    = "ResourceAdd"
	WatchEventModify = "ResourceModify"
	WatchEventDelete = "ResourceDelete"
	WatchEventState  = "StateUpdate"
)

const (
	ConnStateNone         = ""
	ConnStateConnected    = "connected"
	ConnStateDisconnected = "disconnected"
)

type Node struct {
	UID              string
	Name             string
	IPNets           []net.IPNet
	Labels           map[string]string
	Annotations      map[string]string
	IBMCloudWorkerID string // for IBM cloud only: the hostname(before the 1st dot character) of the node
}

type Namespace struct {
	UID    string
	Name   string
	Labels map[string]string
}

type Service struct {
	UID         string
	Name        string
	Domain      string
	Labels      map[string]string
	IPs         []net.IP
	Selector    map[string]string
	Type        string
	ExternalIPs []net.IP
}

type Container struct {
	Id            string
	Name          string
	RequestMemory string
	LimitMemory   string
	Privileged    bool
	LivenessCmds  []string
	ReadinessCmds []string
}

type Pod struct {
	UID          string
	Name         string
	Domain       string
	Node         string
	IPNet        net.IPNet
	HostNet      bool
	Running      bool
	OwnerUID     string
	OwnerName    string
	OwnerType    string
	Containers   []Container
	SA           string   // service account of this pod
	ContainerIDs []string // all workload id
	Labels       map[string]string
}

type Deployment struct {
	UID      string
	Name     string
	Domain   string
	Replicas int32
}

type DaemonSet struct {
	UID    string
	Name   string
	Domain string
	SA     string
}

type ReplicaSet struct {
	UID    string
	Name   string
	Domain string
}

type StatefulSet struct {
	UID    string
	Name   string
	Domain string
}

type CronJob struct {
	UID    string
	Name   string
	Domain string
	SA     string
}

type ImageTag struct {
	Tag    string
	Serial string
}

type Image struct {
	UID    string
	Name   string
	Domain string
	Repo   string
	Tags   []ImageTag
}

type RBAC struct {
	Name          string
	Domain        string
	DomainRoles   map[string]string                 // domain -> nv reserved role
	DomainPermits map[string]share.NvFedPermissions // domain -> extra nv permissions. for Rancher SSO custom roles only
}

type ConfigMap struct {
	UID    string
	Name   string
	Domain string
	Data   map[string]string
}

type AdmissionWebhookConfiguration struct {
	AdmType string // "validate" (for ValidatingWebhookConfiguration) or "mutate" (for MutatingWebhookConfiguration)
	Name    string // k8s resource metadata name, like "neuvector-validating-admission-webhook" or "neuvector-validating-crd-webhook"
}
