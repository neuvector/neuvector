package resource

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1b1 "k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	SUBJECT_USER  = 0
	SUBJECT_GROUP = 1
	//	SUBJECT_SERVICEACCOUNT = 2

	VERB_NONE  = 0
	VERB_READ  = 1
	VERB_WRITE = 2
)

const globalRolePrefix string = "cattle-globalrole-"
const nvPermRscPrefix string = "nv-perm."

const constNvNamespace string = "{nv}"

type k8sObjectRef struct {
	name   string
	domain string
}

type k8sSubjectObjRef struct {
	name    string
	domain  string
	subType uint8
}

type k8sRoleRef struct {
	role   k8sObjectRef
	domain string // effective domain
}

type k8sRole struct {
	uid       string
	name      string
	domain    string
	nvRole    string              // deduced nv reserved role
	nvPermits share.NvPermissions // deduced nv permissions, for Rancher SSO only
}

type k8sRoleBinding struct {
	uid         string
	name        string
	domain      string
	role        k8sObjectRef
	users       []k8sSubjectObjRef
	svcAccounts []k8sObjectRef
	roleKind    string
}

type k8sRbacRoleRuleInfo struct { // for rules in role & cluster role
	apiGroup  string
	resources utils.Set // empty for k8s-reserved roles
	verbs     utils.Set // empty for k8s-reserved roles
}

type k8sRbacRoleInfo struct { // for role & cluster role
	k8sReserved   bool      // true when it's k8s-reserved role
	namespace     string    // "{nv}" means neuvector namespace. "" means cluster role
	supersetRoles utils.Set // non-empty for k8s-reserved roles
	name          string
	rules         []*k8sRbacRoleRuleInfo
}

type k8sRbacBindingInfo struct {
	namespace string // "" means cluster rolebinding
	subjects  []string
	rbacRole  *k8sRbacRoleInfo
}

var ocAdminRscsMap map[string]utils.Set = map[string]utils.Set{ // apiGroup to resources
	"":     utils.NewSet("pods", "services", "*"),
	"apps": utils.NewSet("daemonsets", "deployments", "replicasets", "statefulsets", "*"),
	"*":    utils.NewSet("*"),
}

var ocAdminVerbs utils.Set = utils.NewSet(
	"create",
	"delete",
	"deletecollection",
	"edit",
	"patch",
	"post",
	"put",
	"update",
	"*",
)

var ocReaderVerbs utils.Set = utils.NewSet(
	"get",
	"list",
	"watch",
)

// Rancher SSO: apiGroup									resources		verbs
// ------------------------------------------------------------------------------------------------
// fedAdmin:    in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"*"}    // "cattle-globalrole-....." clusterrole(with clusterrolebinding)
// fedReader:   in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"get}   // "cattle-globalrole-....." clusterrole(with clusterrolebinding)
// admin:       in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"*"}    // clusterrole(with clusterrolebinding)
// reader:      in {"read-only.neuvector.api.io", "*"}		"*"				in {"get"}  // clusterrole(with clusterrolebinding)
// ns admin:    in {"read-only.neuvector.api.io", "*"}		"*"				in {"*"}    // clusterrole(with rolebinding) or role
// ns reader:   in {"read-only.neuvector.api.io", "*"}		"*"				in {"get"}  // clusterrole(with rolebinding) or role
var nvReadVerbSSO utils.Set = utils.NewSet("get")                                                          // for view in SSO role/permissions mapping
var nvWriteVerbSSO utils.Set = utils.NewSet("create", "delete", "get", "list", "patch", "update", "watch") // for modify in SSO role/permissions mapping
var nvRscMapSSO map[string]utils.Set                                                                       // key is apiGroup, value is (nv-perm) resources
var nvPermitsValueSSO map[string]share.NvPermissions                                                       // for Rancher SSO

var appRoleVerbs utils.Set = utils.NewSet("get", "list", "update", "watch")
var rbacRoleVerbs utils.Set = utils.NewSet("get", "list", "watch")
var admissionRoleVerbs utils.Set = utils.NewSet("create", "delete", "get", "list", "update", "watch")
var crdRoleVerbs utils.Set = utils.NewSet("create", "get", "update", "watch")
var crdPolicyRoleVerbs utils.Set = utils.NewSet("delete", "get", "list")

var ctrlerSubjectWanted string = "controller"
var updaterSubjectWanted string = "updater"
var enforcerSubjectWanted string = "enforcer"
var ctrlerSubjectsWanted []string = []string{"controller"}
var scannerSubjecstWanted []string = []string{"updater", "controller"}
var enforcerSubjecstWanted []string = []string{"enforcer", "controller"}

var _k8sFlavor string // share.FlavorRancher or share.FlavorOpenShift

var rbacRolesWanted map[string]*k8sRbacRoleInfo = map[string]*k8sRbacRoleInfo{ // (cluster) role settings required by nv
	NvAppRole: &k8sRbacRoleInfo{
		name: NvAppRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  "",
				resources: utils.NewSet(RscNamespaces, K8sResNodes, K8sResPods, RscServices),
				verbs:     appRoleVerbs,
			},
		},
	},
	NvRbacRole: &k8sRbacRoleInfo{
		name: NvRbacRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  k8sRbacApiGroup,
				resources: utils.NewSet(RscTypeRbacClusterRolebindings, RscTypeRbacClusterRoles, RscTypeRbacRolebindings, RscTypeRbacRoles),
				verbs:     rbacRoleVerbs,
			},
		},
	},
	NvAdmCtrlRole: &k8sRbacRoleInfo{
		name: NvAdmCtrlRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  k8sAdmApiGroup,
				resources: utils.NewSet(RscNameMutatingWebhookConfigurations, RscNameValidatingWebhookConfigurations),
				verbs:     admissionRoleVerbs,
			},
		},
	},
	nvCrdRole: &k8sRbacRoleInfo{
		name: nvCrdRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  k8sCrdApiGroup,
				resources: utils.NewSet(RscNameCustomResourceDefinitions),
				verbs:     crdRoleVerbs,
			},
		},
	},
	nvCrdSecRuleRole: &k8sRbacRoleInfo{
		name: nvCrdSecRuleRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdClusterSecurityRule, RscTypeCrdSecurityRule),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	nvCrdAdmCtrlRole: &k8sRbacRoleInfo{
		name: nvCrdAdmCtrlRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdAdmCtrlSecurityRule),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	nvCrdDlpRole: &k8sRbacRoleInfo{
		name: nvCrdDlpRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdDlpSecurityRule),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	nvCrdWafRole: &k8sRbacRoleInfo{
		name: nvCrdWafRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdWafSecurityRule),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	nvCrdVulnProfileRole: &k8sRbacRoleInfo{
		name: nvCrdVulnProfileRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdVulnProfile),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	nvCrdCompProfileRole: &k8sRbacRoleInfo{
		name: nvCrdCompProfileRole,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  constApiGroupNV,
				resources: utils.NewSet(RscTypeCrdCompProfile),
				verbs:     crdPolicyRoleVerbs,
			},
		},
	},
	NvScannerRole: &k8sRbacRoleInfo{ // it's actually for updater pod
		name:      NvScannerRole,
		namespace: constNvNamespace,
		rules: []*k8sRbacRoleRuleInfo{
			&k8sRbacRoleRuleInfo{
				apiGroup:  "apps",
				resources: utils.NewSet(RscDeployments),
				verbs:     utils.NewSet("get", "watch", "patch", "update"),
			},
		},
	},
	k8sClusterRoleView: &k8sRbacRoleInfo{
		k8sReserved:   true,
		name:          k8sClusterRoleView,
		supersetRoles: utils.NewSet("cluster-admin", "admin", "edit", "view"),
	},
	k8sClusterRoleAdmin: &k8sRbacRoleInfo{
		k8sReserved:   true,
		name:          k8sClusterRoleAdmin,
		supersetRoles: utils.NewSet("cluster-admin", "admin"),
	},
}

// clusterrolebinding can only binds to clusterrole
// rolebinding can binds to either role or clusterrole
var rbacRoleBindingsWanted map[string]*k8sRbacBindingInfo = map[string]*k8sRbacBindingInfo{ // cluster rolebindings -> cluster role settings required by nv
	nvAppRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[NvAppRole],
	},
	nvRbacRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[NvRbacRole],
	},
	nvAdmCtrlRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[NvAdmCtrlRole],
	},
	nvCrdRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdRole],
	},
	nvCrdSecRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdSecRuleRole],
	},
	nvCrdAdmCtrlRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdAdmCtrlRole],
	},
	nvCrdDlpRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdDlpRole],
	},
	nvCrdWafRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdWafRole],
	},
	nvCrdVulnProfileRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdVulnProfileRole],
	},
	nvCrdCompProfileRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[nvCrdCompProfileRole],
	},
	nvViewRoleBinding: &k8sRbacBindingInfo{
		subjects: ctrlerSubjectsWanted,
		rbacRole: rbacRolesWanted[k8sClusterRoleView],
	},
	NvScannerRoleBinding: &k8sRbacBindingInfo{ // for updater pod
		namespace: constNvNamespace,
		subjects:  scannerSubjecstWanted,
		rbacRole:  rbacRolesWanted[NvScannerRole],
	},
	NvAdminRoleBinding: &k8sRbacBindingInfo{ // for updater pod (5.1.x-)
		namespace: constNvNamespace,
		subjects:  scannerSubjecstWanted,
		rbacRole:  rbacRolesWanted[k8sClusterRoleAdmin],
	},
}

// Reset unnessary permissions for
// 1. roles fedAdmin/admin & PERM_FED(w) permission
// 2. roles fedReader/reader & PERM_FED(r) permission
func workFedPermit(rbacRoleName, domain, nvRole string, nvPermits share.NvPermissions) (string, share.NvPermissions) {

	nvRoleIn := nvRole
	nvPermitsIn := nvPermits
	// Reset unnessary permissions for roles fedAdmin/admin & PERM_FED(w) permission
	if nvRole == api.UserRoleAdmin && (nvPermits.WriteValue&share.PERM_FED != 0) {
		nvRole = api.UserRoleFedAdmin
	}
	if nvRole == api.UserRoleFedAdmin {
		nvPermits = share.NvPermissions{}
	} else if nvRole == api.UserRoleAdmin {
		// It's possible to have admin role + PERM_FED(r) permission
		nvPermits.ReadValue &= share.PERM_FED
		nvPermits.WriteValue = 0
	}

	// Reset unnessary permissions for roles fedReader/reader & PERM_FED(r) permission
	if nvRole == api.UserRoleReader && (nvPermits.ReadValue&share.PERM_FED != 0) {
		nvRole = api.UserRoleFedReader
	}
	if nvRole == api.UserRoleFedReader || nvRole == api.UserRoleReader {
		if nvPermits.WriteValue == 0 {
			// There is no write permission. So just take the fedReader/reader role
			nvPermits.ReadValue = 0
		} else {
			// There is write permission. Move fedReader/reader role to permissions
			nvPermits.ReadValue = share.PERMS_CLUSTER_READ
			if nvRole == api.UserRoleFedReader {
				nvPermits.ReadValue = share.PERMS_FED_READ
			}
			nvRole = api.UserRoleNone
		}
	}

	if nvRole != nvRoleIn || nvPermits != nvPermitsIn {
		log.WithFields(log.Fields{"k8sRole": rbacRoleName, "domain": domain, "role_in": nvRoleIn, "permits_in": nvPermitsIn, "role_adjusted": nvRole, "permits_adjusted": nvPermits}).Debug()
	}

	return nvRole, nvPermits
}

// Map a k8s rbac policyrule to (nv fedAdmin/fedReader/admin/reader role, nv permissions)
// Both the returned nvRole & nvPermits could be non-empty value
//
// rscs: 	   pre-defined NV permission resources for role/permissions mapping
// readVerbs:  pre-defined view verbs for role/permissions mapping
// writeVerbs: pre-defined modify verbs for role/permissions mapping
// r2v:        resource -> verbs content in the k8s clusterrole/role object
func k8s2NVRolePermits(k8sFlavor, rbacRoleName string, rscs, readVerbs, writeVerbs utils.Set, r2v map[string]utils.Set) (
	string, share.NvPermissions) {

	var nvPermits share.NvPermissions
	if k8sFlavor == share.FlavorRancher {
		var nvRole string
		for rsc, verbs := range r2v {
			if rsc == "*" {
				if verbs.Contains("*") || writeVerbs.Intersect(verbs).Cardinality() == writeVerbs.Cardinality() {
					nvRole = api.UserRoleAdmin
				} else if readVerbs.Intersect(verbs).Cardinality() != 0 && nvRole == api.UserRoleNone {
					nvRole = api.UserRoleReader
				}
			} else if strings.HasPrefix(rsc, nvPermRscPrefix) {
				rsc = rsc[len(nvPermRscPrefix):]
				if v, ok := nvPermitsValueSSO[rsc]; ok {
					if verbs.Contains("*") || writeVerbs.Intersect(verbs).Cardinality() == writeVerbs.Cardinality() {
						nvPermits.ReadValue |= v.ReadValue
						nvPermits.WriteValue |= v.WriteValue
					} else if readVerbs.Intersect(verbs).Cardinality() != 0 {
						nvPermits.ReadValue |= v.ReadValue
					}
				}
			}
		}
		// Now both nvRole & nvPermits could be non-empty value

		// When SSO happens on NV master cluster,
		// 1. * verb on             * resource in Rancher Global  Role maps to fedAdmin
		// 2. * verb on *,nv-perm.fed resource in Rancher Cluster Role maps to fedAdmin
		// 3. * verb on             * resource in Rancher Cluster Role maps to admin
		// When SSO happens on NV non-master cluster,
		// 1. * verb on             * resource in Rancher Cluster Role maps to admin
		// 2. nv-perm.fed resource is ignored
		// Rancher's Global/Cluster/Project Roles are represented by k8s clusterrole.
		// Unlike for Global Role, from k8s clusterrole name we we cannot tell it's for Rancher Cluster Role or Project Role.
		// Rancher Cluster Role supports nv-perm.fed resource but Rancher Project Role doesn't(yet)
		// So we treat every non-GlobalRole k8s clusterrole the same in this function.
		// The actual user role/permission will be adjusted in rbacEvaluateUser()
		if strings.HasPrefix(rbacRoleName, globalRolePrefix) {
			if nvRole == api.UserRoleAdmin {
				nvRole = api.UserRoleFedAdmin
			} else if nvRole == api.UserRoleReader {
				nvRole = api.UserRoleFedReader
			}
		}
		nvRole, nvPermits = workFedPermit(rbacRoleName, "n/a", nvRole, nvPermits)

		return nvRole, nvPermits
	} else {
		//
		// Both Kubernetes and OpenShift mapping goes here, keep these two using the same behavior.
		// As v5.0, we do not support Kubernetes login.
		// When it comes to support Kubernetes login, we should consider to provide more granular on the mapping.
		//
		for rsc, verbs := range r2v {
			if rscs.Contains(rsc) && writeVerbs.Intersect(verbs).Cardinality() != 0 {
				return api.UserRoleAdmin, nvPermits
			}
		}

		for rsc, verbs := range r2v {
			if rscs.Contains(rsc) && readVerbs.Intersect(verbs).Cardinality() != 0 {
				return api.UserRoleReader, nvPermits
			}
		}
	}

	return api.UserRoleNone, nvPermits
}

// Returns deduced (nv reserved role, nv permissions) for a k8s (cluster)role
// Both returned values could be non-empty value
// Rancher's Global/Cluster/Project Role is always represented by k8s clusterrole (param rbacRoleDomain is "")
func deduceRoleRules(k8sFlavor, rbacRoleName, rbacRoleDomain string, objs interface{}) (string, share.NvPermissions) {

	_, getVerbs := rbacRolesWanted[rbacRoleName]
	ag2r2v := make(map[string]map[string]utils.Set) // apiGroup -> (resource -> verbs)
	if rules, ok := objs.([]rbacv1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.Verbs)

			if verbs.Cardinality() == 0 && len(rule.Resources) == 0 {
				continue
			}
			var apiGroup string
			if len(rule.APIGroups) > 0 {
				apiGroup = rule.APIGroups[0]
			}
			r2v, ok := ag2r2v[apiGroup]

			if !ok {
				r2v = make(map[string]utils.Set)
				ag2r2v[apiGroup] = r2v
			}
			for _, rsc := range rule.Resources {
				if v, ok := r2v[rsc]; ok {
					r2v[rsc] = v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
	} else if rules, ok := objs.([]rbacv1b1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.Verbs)
			if verbs.Cardinality() == 0 && len(rule.Resources) == 0 {
				continue
			}
			var apiGroup string
			if len(rule.APIGroups) > 0 {
				apiGroup = rule.APIGroups[0]
			}
			r2v, ok := ag2r2v[apiGroup]
			if !ok {
				r2v = make(map[string]utils.Set)
				ag2r2v[apiGroup] = r2v
			}
			for _, rsc := range rule.Resources {
				if v, ok := r2v[rsc]; ok {
					r2v[rsc] = v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
	}
	if len(ag2r2v) > 0 {
		var nvRole string                                 // deduced nv reserved role
		var nvPermits share.NvPermissions                 // deduced nv permissions
		var rscsMap map[string]utils.Set = ocAdminRscsMap // apiGroup -> set of resources
		var readVerbs utils.Set = ocReaderVerbs
		var writeVerbs utils.Set = ocAdminVerbs // users who has these verbs on specified resources are nv admin
		if k8sFlavor == share.FlavorRancher {
			rscsMap = nvRscMapSSO
			readVerbs = nvReadVerbSSO
			writeVerbs = nvWriteVerbSSO
		}
		for apiGroup, r2v := range ag2r2v {
			if len(r2v) == 0 {
				continue
			}
			if rscs, ok := rscsMap[apiGroup]; ok {
				nvRoleTemp, nvPermitsTemp := k8s2NVRolePermits(k8sFlavor, rbacRoleName, rscs, readVerbs, writeVerbs, r2v)
				// nvRoleMapped is empty value, or nvPermitsTemp is empty value, or both are empty value !
				if nvRoleTemp != api.UserRoleNone {
					if k8sFlavor == share.FlavorRancher {
						switch nvRoleTemp {
						case api.UserRoleFedAdmin:
							nvRole = api.UserRoleFedAdmin
						case api.UserRoleFedReader:
							if nvRole == api.UserRoleReader || nvRole == api.UserRoleNone {
								nvRole = api.UserRoleFedReader
							} else if nvRole == api.UserRoleAdmin {
								// This Rancher role maps to admin & fedReader roles.
								// Take admin role and move PERM_FED(r) to permissions
								nvPermits.ReadValue = share.PERM_FED
							}
						case api.UserRoleAdmin:
							if nvRole == api.UserRoleReader || nvRole == api.UserRoleNone {
								nvRole = api.UserRoleAdmin
							} else if nvRole == api.UserRoleFedReader {
								// This Rancher role maps to admin & fedReader roles.
								// Take admin role and move PERM_FED(r) to permissions
								nvRole = api.UserRoleAdmin
								nvPermits.ReadValue = share.PERM_FED
							}
						case api.UserRoleReader:
							if nvRole == api.UserRoleNone {
								nvRole = api.UserRoleReader
							}
						}
					} else {
						// it's mapped from k8s (cluster)role on non-Rancer
						if (nvRoleTemp == api.UserRoleAdmin && nvRole != api.UserRoleAdmin) ||
							(nvRoleTemp == api.UserRoleReader && nvRole == api.UserRoleNone) {
							nvRole = nvRoleTemp
						}
						// no other nv reserved role could be mapped
					}
					if nvRoleTemp == api.UserRoleFedAdmin {
						break
					}
				}
				if !nvPermitsTemp.IsEmpty() {
					// this k8s rbac policyrule is mapped to nv permissions
					if k8sFlavor == share.FlavorRancher {
						nvPermits.ReadValue |= nvPermitsTemp.ReadValue
						nvPermits.WriteValue |= nvPermitsTemp.WriteValue
					}
				}
			}
		}

		// Adjustment between fedAdmin/fedReader/admin/reader roles & PERM_FED permission
		nvRole, nvPermits = workFedPermit(rbacRoleName, "n/a", nvRole, nvPermits)

		if roleInfo, ok := rbacRolesWanted[rbacRoleName]; !ok || roleInfo.k8sReserved || !getVerbs {
			ag2r2v = nil
		}
		return nvRole, nvPermits
	} else {
		return api.UserRoleNone, share.NvPermissions{}
	}
}

func collectRoleResVerbs(roleName string) ([]string, []string) {
	var resources []string
	var verbs []string
	if roleInfo, ok := rbacRolesWanted[roleName]; ok && !roleInfo.k8sReserved {
		if roleName == NvRbacRole {
			for _, roleInfoRule := range roleInfo.rules {
				for rsc := range roleInfoRule.resources.Iter() {
					resources = append(resources, fmt.Sprintf("%s.%s", rsc, roleInfoRule.apiGroup))
				}
			}
		} else {
			resources = roleInfo.rules[0].resources.ToStringSlice()
		}
		sort.Strings(resources)
		verbs = roleInfo.rules[0].verbs.ToStringSlice()
		sort.Strings(verbs)
	}

	return resources, verbs
}

func checkNvRbacRoleRules(roleName, rbacRoleDesc string, objs interface{}) error {
	roleInfo, ok := rbacRolesWanted[roleName]
	if !ok {
		return fmt.Errorf(`Kubernetes %s "%s" is not required`, rbacRoleDesc, roleName)
	} else if roleInfo.k8sReserved {
		return nil
	}
	ag2r2v := make(map[string]map[string]utils.Set) // collected apiGroup -> (resource -> verbs) in k8s rbac
	if rules, ok := objs.([]rbacv1.PolicyRule); ok {
		for _, rule := range rules {
			for _, roleInfoRule := range roleInfo.rules {
				var apiGroup string
				if len(rule.APIGroups) > 0 {
					apiGroup = rule.APIGroups[0]
				}
				if roleInfoRule.apiGroup != apiGroup {
					continue
				}
				r2v, ok := ag2r2v[apiGroup]
				if !ok {
					r2v = make(map[string]utils.Set)
					ag2r2v[apiGroup] = r2v
				}
				verbs := utils.NewSetFromSliceKind(rule.Verbs)
				for _, rsc := range rule.Resources {
					if roleInfoRule.resources.Contains(rsc) {
						if v, ok := r2v[rsc]; ok {
							r2v[rsc] = v.Union(verbs)
						} else {
							r2v[rsc] = verbs
						}
					}
				}
			}
		}
	} else if rules, ok := objs.([]rbacv1b1.PolicyRule); ok {
		for _, rule := range rules {
			for _, roleInfoRule := range roleInfo.rules {
				var apiGroup string
				if len(rule.APIGroups) > 0 {
					apiGroup = rule.APIGroups[0]
				}
				if roleInfoRule.apiGroup != apiGroup {
					continue
				}
				r2v, ok := ag2r2v[apiGroup]
				if !ok {
					r2v = make(map[string]utils.Set)
					ag2r2v[apiGroup] = r2v
				}
				verbs := utils.NewSetFromSliceKind(rule.Verbs)
				for _, rsc := range rule.Resources {
					if roleInfoRule.resources.Contains(rsc) {
						if v, ok := r2v[rsc]; ok {
							r2v[rsc] = v.Union(verbs)
						} else {
							r2v[rsc] = verbs
						}
					}
				}
			}
		}
	}

	var wrongRBAC bool
CHECK:
	for _, roleInfoRule := range roleInfo.rules {
		if r2v, ok := ag2r2v[roleInfoRule.apiGroup]; !ok {
			wrongRBAC = true
			break CHECK
		} else {
			foundResources := utils.NewSet()
			for rt, _ := range r2v {
				foundResources.Add(rt)
			}
			if !foundResources.IsSuperset(roleInfoRule.resources) && !foundResources.Contains("*") {
				wrongRBAC = true
				break
			} else {
				for rt, verbs := range r2v {
					if roleInfoRule.resources.Contains(rt) || rt == "*" {
						if !verbs.IsSuperset(roleInfoRule.verbs) && !verbs.Contains("*") {
							wrongRBAC = true
							break CHECK
						}
					}
				}
			}
		}
	}
	if wrongRBAC {
		if resources, verbs := collectRoleResVerbs(roleName); len(resources) > 0 && len(verbs) > 0 {
			return fmt.Errorf(`Kubernetes %s "%s" is required to grant %s permission(s) on %s resource(s).`,
				rbacRoleDesc, roleName, strings.Join(verbs, ","), strings.Join(resources, ","))
		}
	}

	return nil
}

func xlateRole(obj metav1.Object) (string, interface{}) {
	var ver string
	var role k8sRole
	var rules interface{}

	if o, ok := obj.(*rbacv1.Role); ok {
		ver = "v1"
		role = k8sRole{
			uid:    string(o.GetUID()),
			name:   o.GetName(),
			domain: o.GetNamespace(),
		}
		rules = o.Rules
	} else if o, ok := obj.(*rbacv1b1.Role); ok {
		ver = "v1beta1"
		role = k8sRole{
			uid:    string(o.GetUID()),
			name:   o.GetName(),
			domain: o.GetNamespace(),
		}
		rules = o.Rules
	}

	if rules != nil {
		role.nvRole, role.nvPermits = deduceRoleRules(_k8sFlavor, role.name, role.domain, rules)
		if role.nvRole != api.UserRoleNone || !role.nvPermits.IsEmpty() { // only for reducing debug logs
			log.WithFields(log.Fields{"role": role}).Debug(ver)
		}
		return role.uid, &role
	}

	return "", nil
}

func xlateClusRole(obj metav1.Object) (string, interface{}) {
	var ver string
	var role k8sRole
	var rules interface{}

	if o, ok := obj.(*rbacv1.ClusterRole); ok {
		ver = "v1"
		role = k8sRole{
			uid:  string(o.GetUID()),
			name: o.GetName(),
		}
		rules = o.Rules
	} else if o, ok := obj.(*rbacv1b1.ClusterRole); ok {
		ver = "v1beta1"
		role = k8sRole{
			uid:  string(o.GetUID()),
			name: o.GetName(),
		}
		rules = o.Rules
	}

	if rules != nil {
		role.nvRole, role.nvPermits = deduceRoleRules(_k8sFlavor, role.name, access.AccessDomainGlobal, rules)
		if role.nvRole != api.UserRoleNone || !role.nvPermits.IsEmpty() { // only for reducing debug logs
			log.WithFields(log.Fields{"clusterrole": role}).Debug(ver)
		}
		return role.uid, &role
	}

	return "", nil
}

func xlateRoleBinding(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*rbacv1.RoleBinding); ok {
		role := o.RoleRef
		subjects := o.Subjects
		roleBind := &k8sRoleBinding{
			uid:    string(o.GetUID()),
			name:   o.GetName(),
			domain: o.GetNamespace(),
		}

		switch role.Kind {
		case "Role":
			roleBind.role = k8sObjectRef{name: role.Name, domain: roleBind.domain}
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.Name}
		default:
			log.WithFields(log.Fields{"role": role.Kind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.Kind

		for _, s := range subjects {
			ns := s.Namespace
			switch s.Kind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.Name, domain: ns, subType: SUBJECT_USER}
				if s.Kind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if ns == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.Name, domain: ns}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}
		if len(roleBind.users) > 0 || len(roleBind.svcAccounts) > 0 { // only for reducing debug logs
			log.WithFields(log.Fields{"rolebinding": roleBind}).Debug("v1")
		}
		return roleBind.uid, roleBind
	} else if o, ok := obj.(*rbacv1b1.RoleBinding); ok {
		role := o.RoleRef
		subjects := o.Subjects
		roleBind := &k8sRoleBinding{
			uid:    string(o.GetUID()),
			name:   o.GetName(),
			domain: o.GetNamespace(),
		}

		switch role.Kind {
		case "Role":
			roleBind.role = k8sObjectRef{name: role.Name, domain: roleBind.domain}
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.Name}
		default:
			log.WithFields(log.Fields{"role": role.Kind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.Kind

		for _, s := range subjects {
			ns := s.Namespace
			switch s.Kind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.Name, domain: ns, subType: SUBJECT_USER}
				if s.Kind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if ns == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.Name, domain: ns}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}
		if len(roleBind.users) > 0 || len(roleBind.svcAccounts) > 0 { // only for reducing debug logs
			log.WithFields(log.Fields{"rolebinding": roleBind}).Debug("v1beta1")
		}
		return roleBind.uid, roleBind
	}

	return "", nil
}

func xlateClusRoleBinding(obj metav1.Object) (string, interface{}) {
	if o, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
		role := o.RoleRef
		subjects := o.Subjects
		roleBind := &k8sRoleBinding{
			uid:  string(o.GetUID()),
			name: o.GetName(),
		}

		switch role.Kind {
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.Name}
		default:
			log.WithFields(log.Fields{"role": role.Kind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.Kind

		for _, s := range subjects {
			ns := s.Namespace
			switch s.Kind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.Name, domain: ns, subType: SUBJECT_USER}
				if s.Kind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if ns == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.Name, domain: ns}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}
		if len(roleBind.users) > 0 || len(roleBind.svcAccounts) > 0 { // only for reducing debug logs
			if _, ok := rbacRoleBindingsWanted[roleBind.name]; !ok {
				log.WithFields(log.Fields{"clusterrolebinding": roleBind}).Debug("v1")
			}
		}
		return roleBind.uid, roleBind
	} else if o, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok {
		role := o.RoleRef
		subjects := o.Subjects
		roleBind := &k8sRoleBinding{
			uid:  string(o.GetUID()),
			name: o.GetName(),
		}

		switch role.Kind {
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.Name}
		default:
			log.WithFields(log.Fields{"role": role.Kind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.Kind

		for _, s := range subjects {
			ns := s.Namespace
			switch s.Kind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.Name, domain: ns, subType: SUBJECT_USER}
				if s.Kind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if ns == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.Name, domain: ns}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}
		if len(roleBind.users) > 0 || len(roleBind.svcAccounts) > 0 { // only for reducing debug logs
			if _, ok := rbacRoleBindingsWanted[roleBind.name]; !ok {
				log.WithFields(log.Fields{"clusterrolebinding": roleBind}).Debug("v1beta1")
			}
		}
		return roleBind.uid, roleBind
	}

	return "", nil
}

func cacheRbacEvent(flavor, msg string, existOnly bool) {
	if cacheEventFunc != nil {
		cacheEventFunc(share.CLUSEvK8sNvRBAC, msg)
	}
}

func (d *kubernetes) cbResourceRole(rt string, event string, res interface{}, old interface{}) {
	d.rbacLock.Lock()
	defer d.rbacLock.Unlock()

	var n, o *k8sRole
	if event == WatchEventDelete {
		o = old.(*k8sRole)
		ref := k8sObjectRef{name: o.name, domain: o.domain}
		affectedUsers := utils.NewSet()
		nvRole, ok1 := d.roleCache[ref]
		nvPermits, ok2 := d.permitsCache[ref]
		if ok1 || ok2 {
			for u, roleRefs := range d.userCache { // roleRefs: set of k8sRoleRef
				for roleRef := range roleRefs.Iter() {
					if roleRef.(k8sRoleRef).role == ref { // the deleted k8s (cluster)role affects a user in userCache
						log.WithFields(log.Fields{"k8s-role": ref, "user": u, "left": roleRefs}).Debug("Reset roleRef")
						if !affectedUsers.Contains(u) {
							affectedUsers.Add(u)
						}
					}
				}
			}
			d.roleCache[ref] = api.UserRoleNone
			d.permitsCache[ref] = share.NvPermissions{}
			log.WithFields(log.Fields{"k8s-role": ref, "nv-role": nvRole, "nv-perms": nvPermits}).Debug("Delete role")
		}

		// re-evaluate users who bind to the deleted (cluster)role
		for u := range affectedUsers.Iter() {
			d.rbacEvaluateUser(u.(k8sSubjectObjRef))
		}

		if roleInfo, ok := rbacRolesWanted[o.name]; ok && !roleInfo.k8sReserved {
			evLog := true
			if o.name == NvScannerRole {
				if _, err := global.ORCH.GetResource(RscTypeCronJob, NvAdmSvcNamespace, "neuvector-updater-pod"); err != nil {
					evLog = false
				} else if errs, _ := VerifyNvRbacRoleBindings([]string{NvAdminRoleBinding}, false, false); len(errs) == 0 {
					// when neuvector-admin rolebinding is configured correctly, do not report event about role neuvector-binding-scanner being deleted
					evLog = false
				}
			}
			if evLog {
				desc := "role"
				if o.domain == access.AccessDomainGlobal {
					desc = "clusterrole"
				}
				msg := fmt.Sprintf(`Kubernetes %s "%s" is deleted.`, desc, o.name)
				log.Warn(msg)
				cacheRbacEvent(d.flavor, msg, false)
			}
		}
	} else {
		n = res.(*k8sRole)
		ref := k8sObjectRef{name: n.name, domain: n.domain}
		if n.nvRole != api.UserRoleNone {
			d.roleCache[ref] = n.nvRole
			if n.nvPermits.IsEmpty() {
				delete(d.permitsCache, ref)
			}
		}
		if !n.nvPermits.IsEmpty() {
			d.permitsCache[ref] = n.nvPermits
			if n.nvRole == api.UserRoleNone {
				delete(d.roleCache, ref)
			}
		}
		if n.nvRole == api.UserRoleNone && n.nvPermits.IsEmpty() {
			delete(d.roleCache, ref)
			delete(d.permitsCache, ref)
		}
		if old == nil || *(old.(*k8sRole)) != *n { // only for reducing debug logs
			log.WithFields(log.Fields{"k8s-role": ref, "nv-role": n.nvRole, "nv-perms": n.nvPermits}).Debug("Update role")
		}

		// starting from 5.1.3, we do not upgrade CRD schema anymore
		/*
			// in case the clusterrole neuvector-binding-customresourcedefinition is recreated/updated(after nv 5.0 deployment)
			// to have "update" verb so that nv can upgrade the CRD schema
			if n.name == nvCrdRole && n.apiRtVerbs != nil && nvCrdInitFunc != nil {
				if roleInfo, ok := rbacRolesWanted[n.name]; ok && !roleInfo.k8sReserved {
					if nRtVerbs, ok1 := n.apiRtVerbs[roleInfo.rules[0].apiGroup]; ok1 {
						if nVerbs, ok1 := nRtVerbs[RscNameCustomResourceDefinitions]; ok1 {
							if old == nil {
								nvCrdInitFunc(isLeader, false, false, cspType)
							} else {
								if o = old.(*k8sRole); o.apiRtVerbs != nil {
									if oRtVerbs, ok2 := o.apiRtVerbs[roleInfo.rules[0].apiGroup]; ok2 {
										if oVerbs, ok2 := oRtVerbs[RscNameCustomResourceDefinitions]; ok2 {
											if (nVerbs.Contains("update") || nVerbs.Contains("*")) &&
												(!oVerbs.Contains("update") && !oVerbs.Contains("*")) {
												nvCrdInitFunc(isLeader, false, false, cspType)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		*/

		// re-evaluate users who bind to the updated (cluster)role
		for u, roleRefs := range d.userCache {
			for roleRef := range roleRefs.Iter() {
				if roleRef.(k8sRoleRef).role == ref { // a user in k8s is affected
					d.rbacEvaluateUser(u)
					break
				}
			}
		}

		// if it's nv-required k8s rbac (cluster)role, check whether its configuration meets nv's need
		if roleInfo, ok := rbacRolesWanted[n.name]; ok && !roleInfo.k8sReserved {
			checkRBAC := true
			if n.name == NvScannerRole {
				if _, err := global.ORCH.GetResource(RscTypeCronJob, NvAdmSvcNamespace, "neuvector-updater-pod"); err != nil {
					checkRBAC = false
				} else if errs, _ := VerifyNvRbacRoleBindings([]string{NvAdminRoleBinding}, false, false); len(errs) == 0 {
					// when neuvector-admin rolebinding is configured correctly, do not care role neuvector-binding-scanner's settings
					checkRBAC = false
				}
			}
			if checkRBAC {
				if errs, _ := VerifyNvRbacRoles([]string{n.name}, false); len(errs) > 0 {
					log.Warn(errs[0])
					cacheRbacEvent(d.flavor, errs[0], false)
				}
			}
		}
	}
}

func (d *kubernetes) cbResourceRoleBinding(rt string, event string, res interface{}, old interface{}) {
	d.rbacLock.Lock()
	defer d.rbacLock.Unlock()

	var n, o *k8sRoleBinding
	var newRoleRef, oldRoleRef k8sRoleRef
	if event == WatchEventDelete {
		o = old.(*k8sRoleBinding)
		oldRoleRef := k8sRoleRef{role: o.role, domain: o.domain}
		if bindingInfo, ok := rbacRoleBindingsWanted[o.name]; ok && o.domain == bindingInfo.namespace {
			evLog := true
			if o.name == NvAdminRoleBinding || o.name == NvScannerRoleBinding {
				if _, err := global.ORCH.GetResource(RscTypeCronJob, NvAdmSvcNamespace, "neuvector-updater-pod"); err != nil {
					evLog = false
				} else {
					// when one of (neuvector-admin, neuvector-binding-scanner) rolebinding is configured correctly, do not care another rolebinding is deleted
					var checkName string
					if o.name == NvAdminRoleBinding {
						checkName = NvScannerRoleBinding
					} else {
						checkName = NvAdminRoleBinding
					}
					if errs, _ := VerifyNvRbacRoleBindings([]string{checkName}, false, false); len(errs) == 0 {
						evLog = false
					}
				}
			}
			if evLog {
				var rtName string
				if o.domain == access.AccessDomainGlobal {
					rtName = "clusterrolebinding"
				} else {
					rtName = "rolebinding"
				}
				msg := fmt.Sprintf(`Kubernetes %s "%s" is deleted.`, rtName, o.name)
				log.WithFields(log.Fields{"role": o.role.name, "roleKind": o.roleKind, "domain": o.domain}).Warn(msg)
				cacheRbacEvent(d.flavor, msg, false)
			}
		}
		for _, u := range o.users {
			if roleRefs, ok := d.userCache[u]; ok && roleRefs.Contains(oldRoleRef) { // the deleted k8s (cluster)rolebinding affects a user in userCache
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"name": o.name, "k8s-role": oldRoleRef, "user": u, "left": roleRefs, "op": "delete"}).Debug()

				if roleRefs.Cardinality() == 0 {
					// delete user
					delete(d.userCache, u)
					log.WithFields(log.Fields{"user": u}).Debug("Delete user")
				}
				d.rbacEvaluateUser(u)
			}
		}
	} else {
		n = res.(*k8sRoleBinding)
		newRoleRef = k8sRoleRef{role: n.role, domain: n.domain}

		// sometimes Rancher doesn't delete a user's rolebinding, {user_id}-global-catalog-binding(in cattle-global-data ns), when the Rancher user is deleted.
		// so we simply ignore rolebinding {user_id}-global-catalog-binding(binds a k8s user to global-catalog role in cattle-global-data ns)
		if d.flavor == share.FlavorRancher {
			if newRoleRef.role.name == "global-catalog" && strings.HasSuffix(n.name, "-global-catalog-binding") && newRoleRef.role.domain == "cattle-global-data" {
				return
			}
		}

		// user list or binding role changed
		// 1. Get a list of users that are removed from the binding
		var oldUsers utils.Set
		if old != nil {
			o = old.(*k8sRoleBinding)
			oldRoleRef = k8sRoleRef{role: o.role, domain: o.domain}
			oldUsers = utils.NewSetFromSliceKind(o.users)
		} else {
			oldUsers = utils.NewSet()
		}
		newUsers := utils.NewSetFromSliceKind(n.users)

		// 2. Delete roles for users removed from the binding. When there is no role for a user, remove the user entry from userCache.
		deletes := oldUsers.Difference(newUsers)
		for u := range deletes.Iter() {
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; ok && roleRefs.Contains(oldRoleRef) { // the updated k8s (cluster)rolebinding affects a user in userCache
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": oldRoleRef, "user": userRef, "left": roleRefs, "op": "delete"}).Debug()

				if roleRefs.Cardinality() == 0 {
					// delete user
					delete(d.userCache, userRef)
					log.WithFields(log.Fields{"user": userRef}).Debug("Delete user")
				}

				d.rbacEvaluateUser(userRef)
			}
		}

		// 3. For new binding users - because role binding can use cluster role, we use role itself to refer
		//    to the object, and save the working domain separately.
		creates := newUsers.Difference(oldUsers)
		for u := range creates.Iter() {
			op := "create"
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
			} else {
				op = "add"
				roleRefs.Add(newRoleRef)
			}
			log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef, "op": op}).Debug()

			d.rbacEvaluateUser(userRef)
		}

		// 4. For users whose bindings, role binding references (cluster) role, or cluster role binding references cluster role, are changed
		changes := newUsers.Difference(creates)
		for u := range changes.Iter() {
			op := "create"
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
			} else if o.role != n.role {
				// o won't be nil when we get here
				op = "add"
				roleRefs.Add(newRoleRef)
			}
			if oldRoleRef != newRoleRef { // only for reducing debug logs
				log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef, "op": op}).Debug()
			}

			d.rbacEvaluateUser(userRef)
		}

		// 5. nv-required clusterrolebinding check
		{
			if bindingInfo, ok := rbacRoleBindingsWanted[n.name]; ok && n.domain == bindingInfo.namespace {
				var errs []string
				if n.name == NvAdminRoleBinding || n.name == NvScannerRoleBinding {
					if _, err := global.ORCH.GetResource(RscTypeCronJob, NvAdmSvcNamespace, "neuvector-updater-pod"); err == nil {
						// rolebinding neuvector-binding-scanner is preferred in 5.2(+)
						// rolebinding neuvector-admin is majorly for backward compatibility
						if errs, _ = VerifyNvRbacRoleBindings([]string{NvAdminRoleBinding}, false, false); len(errs) > 0 {
							// access denied for reading rolebinding resources, rolebinding neuvector-admin is not found or it's incorrectly configured
							if errs2, k8sRbac403 := VerifyNvRbacRoleBindings([]string{NvScannerRoleBinding}, false, true); !k8sRbac403 && len(errs) > 0 {
								// rolebinding neuvector-binding-scanner is not found or it's incorrectly configured
								errs = errs2
							}
						}
					}
				} else {
					errs, _ = VerifyNvRbacRoleBindings([]string{n.name}, false, true)
				}
				if len(errs) > 0 {
					log.WithFields(log.Fields{"role": n.role.name}).Warn(errs[0])
					cacheRbacEvent(d.flavor, errs[0], false)
				}
			}
		}
	}
}

// Called with rbacLock
func (d *kubernetes) rbacEvaluateUser(user k8sSubjectObjRef) {
	subj := k8sSubjectObjRef{
		name:    user.name,
		subType: user.subType,
	}

	if roleRefs, ok := d.userCache[user]; !ok {
		// there is no entry in the cache for this user yet
		rbacRoles, ok1 := d.rbacCache[subj]
		rbacPermits, ok2 := d.permitsRbacCache[subj]
		if ok1 || ok2 {
			if ok1 {
				delete(d.rbacCache, subj)
			}
			if ok2 {
				delete(d.permitsRbacCache, subj)
			}
			log.WithFields(log.Fields{"user": user}).Debug("Delete rbac user")

			d.lock.Lock()
			w, ok := d.watchers[RscTypeRBAC]
			d.lock.Unlock()
			if ok && w.cb != nil {
				w.cb(RscTypeRBAC, WatchEventDelete,
					nil,
					&RBAC{Name: user.name, Domain: user.domain, DomainRoles: rbacRoles, DomainPermits: rbacPermits},
				) //-> calls cbResourceWatcher("rbac", ...)
			}
		}
	} else {
		// found an entry in userCache for this user
		domainRole := make(map[string]string)                 // domain -> nv reserved role
		domainPermits := make(map[string]share.NvPermissions) // domain -> nv permissions
		// iterate thru all k8s (cluster)roles for this user to see what their domainRole/domainPermits should be
		for r := range roleRefs.Iter() {
			movePermFedRead := false
			roleRef := r.(k8sRoleRef)
			nvRole, ok1 := d.roleCache[roleRef.role] // d.roleCache : k8s (cluster)role -> nv reserved role
			if ok1 {
				// This k8s (cluster)role is in roleCache (i.e. it has a mpped nv reserved role).
				// In k8s2NVRolePermits() we cannot tell a k8s clusterrole is for Rancher Cluster Role or Project Role.
				// It's possible that nvRole is fedAdmin/fedReader even it's Rancher Project Role which is not allowed.
				// If found, downgrade nvRole to admin/reader(for namespace)
				if roleRef.domain != "" {
					// This k8s (cluster)role is bound to the user by k8s rolebinding(i.e. it's Rancher Project Role)
					if nvRole == api.UserRoleFedAdmin {
						nvRole = api.UserRoleAdmin
					} else if nvRole == api.UserRoleFedReader {
						nvRole = api.UserRoleReader
					}
				}
				// Merge this nv role into this domain's nv role
				if currNVRole, ok := domainRole[roleRef.domain]; ok && currNVRole != nvRole {
					if (currNVRole == api.UserRoleReader && nvRole != api.UserRoleNone) || (currNVRole == api.UserRoleNone) || (nvRole == api.UserRoleFedAdmin) {
						// nvRole has higher auth than currNVRole
					} else if (currNVRole == api.UserRoleFedReader && nvRole == api.UserRoleAdmin) ||
						(currNVRole == api.UserRoleAdmin && nvRole == api.UserRoleFedReader) {
						// role mapping priority: admin > fedReader
						nvRole = api.UserRoleAdmin
						if roleRef.domain == "" {
							// move PERM_FED(r) to permissions if it's global domain (we don't support PERM_FED for namespace yet)
							movePermFedRead = true
						}
					} else {
						// nvRole has lower auth than currNVRole
						nvRole = currNVRole
					}
				}
			} else {
				nvRole, _ = domainRole[roleRef.domain]
			}

			nvPermits, ok2 := d.permitsCache[roleRef.role] // d.permitsCache : k8s (cluster)role -> nv permissions
			if ok2 {
				// This k8s (cluster)role is in permitsCache (i.e. it has mapped nv permissions).
				// In k8s2NVRolePermits() we cannot tell a k8s clusterrole is for Rancher Cluster Role or Project Role.
				// It's possible that nvPermits contains PERM_FED even it's Rancher Project Role which is not allowed.
				// If found, remove PERM_FED from nvPermits(for namespace)
				if roleRef.domain != "" {
					// This k8s (cluster)role is bound to the user by k8s rolebinding(i.e. it's Rancher Project Role)
					nvPermits.ReadValue ^= share.PERM_FED
					nvPermits.WriteValue ^= share.PERM_FED
				} else if movePermFedRead {
					nvPermits.ReadValue |= share.PERM_FED
				}
				// Merge this nv permissions into this domain's nv permissions
				if currNVPermits, ok := domainPermits[roleRef.domain]; ok && currNVPermits != nvPermits {
					nvPermits.ReadValue |= currNVPermits.ReadValue
					nvPermits.WriteValue |= currNVPermits.WriteValue
				}
			} else {
				nvPermits, _ = domainPermits[roleRef.domain]
				if movePermFedRead {
					nvPermits.ReadValue = share.PERM_FED
					ok2 = true
				}
			}

			if ok1 || ok2 {
				// Adjustment between fedAdmin/fedReader/admin/reader roles & PERM_FED permission for this domain
				nvRole, nvPermits = workFedPermit(roleRef.role.name, roleRef.domain, nvRole, nvPermits)
				if nvRole != api.UserRoleNone {
					domainRole[roleRef.domain] = nvRole
				} else {
					delete(domainRole, roleRef.domain)
				}
				if !nvPermits.IsEmpty() {
					domainPermits[roleRef.domain] = nvPermits
				} else {
					delete(domainPermits, roleRef.domain)
				}
			}
		}

		// For namespace permissions, delete empty-value entries and those entries that have the subset permission value of global domain's nv permission value
		// Because we don't support PERM_FED for namespace yet, reset PERM_FED if found
		var gpReduced share.NvPermissions // global domain's reduced nv permission value(for comparing with namespace permissions)
		if nvRole, ok := domainRole[access.AccessDomainGlobal]; ok && nvRole != api.UserRoleNone {
			switch nvRole {
			case api.UserRoleFedAdmin, api.UserRoleAdmin:
				gpReduced.WriteValue = share.PERMS_DOMAIN_WRITE
			case api.UserRoleFedReader, api.UserRoleReader:
				gpReduced.ReadValue = share.PERMS_DOMAIN_READ
			}
		} else {
			if gp, ok := domainPermits[access.AccessDomainGlobal]; ok {
				gpReduced.ReadValue = gp.ReadValue & share.PERMS_DOMAIN_READ
				gpReduced.WriteValue = gp.WriteValue & share.PERMS_DOMAIN_WRITE
			}
		}
		for d, p := range domainPermits {
			if d != access.AccessDomainGlobal {
				if p.IsEmpty() {
					delete(domainPermits, d)
				} else {
					p.ReadValue = p.ReadValue & share.PERMS_DOMAIN_READ
					p.WriteValue = p.WriteValue & share.PERMS_DOMAIN_WRITE
					if p == gpReduced {
						// This namespace's nv permission value is the subset of global domain's nv permission value
						delete(domainPermits, d)
					} else {
						domainPermits[d] = p
					}
				}
			}
		}

		// For namespace role, delete empty-value entries that don't have nv permission entries.
		// Because we don't support fedAdmin/fedReader roles for namespace scope, downgrade to admin/reader if found
		for d, r := range domainRole {
			if d != access.AccessDomainGlobal {
				if r == api.UserRoleNone {
					if _, ok := domainPermits[d]; !ok {
						// There is no nv reserved role/permission for this namespace
						delete(domainRole, d)
					}
				} else if r == api.UserRoleFedAdmin {
					// We don't support PERM_FED for namespace yet
					domainRole[d] = api.UserRoleAdmin
				} else if r == api.UserRoleFedReader {
					// We don't support PERM_FED for namespace yet
					domainRole[d] = api.UserRoleReader
				}
			}
		}

		// If global domain has nv reserved role, delete unnecessary namespace role/permission entries(either unnecessary entries or having the same role)
		if nvRole, ok := domainRole[access.AccessDomainGlobal]; ok {
			if nvRole == api.UserRoleFedAdmin || nvRole == api.UserRoleAdmin {
				// If the user is admin or fed admin role on global domain, it is the admin of all namespaces
				// However, admin role on global domain could still have PERM_FED(r) permission
				domainRole = map[string]string{access.AccessDomainGlobal: nvRole}
				if nvRole == api.UserRoleFedAdmin {
					domainPermits = make(map[string]share.NvPermissions)
				} else {
					nvPermits, ok := domainPermits[access.AccessDomainGlobal]
					domainPermits = make(map[string]share.NvPermissions)
					if ok && nvPermits.ReadValue&share.PERM_FED > 0 {
						domainPermits = map[string]share.NvPermissions{
							access.AccessDomainGlobal: share.NvPermissions{ReadValue: share.PERM_FED},
						}
					}
				}
			} else if nvRole == api.UserRoleFedReader || nvRole == api.UserRoleReader {
				// If the user is cluster reader or fed reader, it is the reader of all namespaces
				for domain, nvDomainRole := range domainRole {
					if domain != access.AccessDomainGlobal && nvDomainRole == api.UserRoleReader {
						delete(domainRole, domain)
					}
				}
				// If the user is cluster reader or fed reader, those domain permission entries for read-only permissions are unnecessary
				for domain, permits := range domainPermits {
					if domain != access.AccessDomainGlobal && permits.WriteValue == 0 {
						delete(domainPermits, domain)
					}
				}
			}
		}

		// Check whether both nv reserved role & permissions are assigne to a domain
		for d, nvRole := range domainRole {
			if nvRole != api.UserRoleNone {
				if nvPermits, ok := domainPermits[d]; ok {
					// Adjustment between fedAdmin/fedReader/admin/reader roles & PERM_FED permission
					nvRole, nvPermits = workFedPermit("", d, nvRole, nvPermits)
					if nvRole == api.UserRoleNone {
						delete(domainRole, d)
					} else {
						domainRole[d] = nvRole
					}
					if nvPermits.IsEmpty() {
						delete(domainPermits, d)
					} else {
						domainPermits[d] = nvPermits
					}
				}
			}
		}
		for d, nvPermits := range domainPermits {
			if nvPermits.IsEmpty() {
				delete(domainPermits, d)
			}
		}

		if _, ok := domainRole[access.AccessDomainGlobal]; !ok {
			domainRole[access.AccessDomainGlobal] = api.UserRoleNone
		}

		oldDomainRole, _ := d.rbacCache[subj]
		oldDomainPermits, _ := d.permitsRbacCache[subj]

		// callback
		if len(domainPermits) > 0 || len(domainRole) > 0 || len(oldDomainPermits) > 0 || len(oldDomainRole) > 0 { // only for reducing debug logs
			log.WithFields(log.Fields{"domainRole": domainRole, "oldDomainRole": oldDomainRole, "domainPermits": domainPermits, "oldDomainPermits": oldDomainPermits, "user": user}).Debug()
		}
		domainRoleUnchanged := false
		domainPermitsUnchanged := false
		if reflect.DeepEqual(oldDomainRole, domainRole) {
			domainRoleUnchanged = true
		} else if len(domainRole) > 0 {
			d.rbacCache[subj] = domainRole
		} else {
			delete(d.rbacCache, subj)
		}
		if reflect.DeepEqual(oldDomainPermits, domainPermits) {
			domainPermitsUnchanged = true
		} else if len(domainPermits) > 0 {
			d.permitsRbacCache[subj] = domainPermits
		} else {
			delete(d.permitsRbacCache, subj)
		}
		if domainRoleUnchanged && domainPermitsUnchanged {
			return
		}

		d.lock.Lock()
		w, ok := d.watchers[RscTypeRBAC]
		d.lock.Unlock()
		if ok && w.cb != nil {
			if oldDomainRole == nil && oldDomainPermits == nil {
				w.cb(RscTypeRBAC, WatchEventAdd,
					&RBAC{Name: user.name, Domain: user.domain, DomainRoles: domainRole, DomainPermits: domainPermits},
					nil,
				)
			} else {
				w.cb(RscTypeRBAC, WatchEventModify,
					&RBAC{Name: user.name, Domain: user.domain, DomainRoles: domainRole, DomainPermits: domainPermits},
					&RBAC{Name: user.name, Domain: user.domain, DomainRoles: oldDomainRole, DomainPermits: oldDomainPermits},
				)
			}
		}
	}
}

func (d *kubernetes) GetUserRoles(user string, subType uint8) (map[string]string, map[string]share.NvPermissions, error) {

	var domainRole map[string]string
	var domainPermits map[string]share.NvPermissions
	userRef := k8sSubjectObjRef{name: user, domain: "", subType: subType}

	d.rbacLock.RLock()
	defer d.rbacLock.RUnlock()

	userDomainRole, ok1 := d.rbacCache[userRef]
	if ok1 {
		domainRole = make(map[string]string, len(userDomainRole))
	}
	userDomainPermits, ok2 := d.permitsRbacCache[userRef]
	if ok2 {
		domainPermits = make(map[string]share.NvPermissions, len(userDomainPermits))
	}

	if !ok1 && !ok2 {
		return nil, nil, ErrUserNotFound
	} else {
		// if there is no role/permission in any domain, return nil for domainRoles / domainPermits
		// if a namespace's role/permissions entry is empty value, remove it from the corresponding map
		for d, r := range userDomainRole {
			if r == api.UserRoleNone && d != access.AccessDomainGlobal {
				delete(domainRole, d)
				continue
			}
			domainRole[d] = r
		}
		for d, p := range userDomainPermits {
			if p.IsEmpty() {
				delete(domainPermits, d)
			} else {
				domainPermits[d] = p
			}
		}

		if len(domainRole) == 0 {
			domainRole = nil
		}
		if len(domainPermits) == 0 {
			domainPermits = nil
		}

		return domainRole, domainPermits, nil
	}
}

func (d *kubernetes) ListUsers() []orchAPI.UserRBAC {
	size := len(d.rbacCache)
	if len(d.permitsRbacCache) > size {
		size = len(d.permitsRbacCache)
	}

	allUsers := make(map[k8sSubjectObjRef]*orchAPI.UserRBAC, size)

	d.rbacLock.RLock()
	defer d.rbacLock.RUnlock()

	for userRef, rbac := range d.rbacCache {
		// rbac is replaced as a whole -> no need to clone
		var domainRole map[string]string = map[string]string{}
		for d, r := range rbac {
			if r != api.UserRoleNone {
				domainRole[d] = r
			}
		}
		if len(domainRole) == 0 {
			domainRole = nil
		}
		allUsers[userRef] = &orchAPI.UserRBAC{Name: userRef.name, Domain: userRef.domain, RBAC: domainRole}
	}

	for userRef, rbac := range d.permitsRbacCache {
		domainPermits := make(map[string]share.NvPermissions)
		for d, p := range rbac {
			if !p.IsEmpty() {
				domainPermits[d] = p
			}
		}
		if len(domainPermits) > 0 {
			if userRBAC, _ := allUsers[userRef]; rbac != nil {
				userRBAC.RBAC2 = domainPermits
			} else {
				allUsers[userRef] = &orchAPI.UserRBAC{Name: userRef.name, Domain: userRef.domain, RBAC2: domainPermits}
			}
		}
	}

	i := 0
	list := make([]orchAPI.UserRBAC, len(allUsers))
	for _, userRBAC := range allUsers {
		list[i] = *userRBAC
		i++
	}

	return list
}

// https://kubernetes.io/docs/reference/using-api/deprecation-guide/
// The rbac.authorization.k8s.io/v1beta1 API version of ClusterRole, ClusterRoleBinding, Role, and RoleBinding is no longer served as of v1.22.
func VerifyNvRbacRoles(roleNames []string, existOnly bool) ([]string, bool) { // returns (error string slice, is 403 error)
	var k8sRbac403 bool
	errors := make([]string, 0, len(roleNames))
	for _, roleName := range roleNames {
		var err error

		if roleWanted, ok := rbacRolesWanted[roleName]; ok {
			if !roleWanted.k8sReserved {
				var rt string
				var rbacRoleDesc string
				var obj interface{}

				if roleWanted.namespace == "" {
					rbacRoleDesc = "clusterrole"
					rt = K8sRscTypeClusRole
				} else {
					rbacRoleDesc = "role"
					rt = k8sRscTypeRole
				}
				if obj, err = global.ORCH.GetResource(rt, roleWanted.namespace, roleName); err == nil {
					if !existOnly {
						var ruleObj interface{}
						if roleWanted.namespace == "" {
							if r, ok := obj.(*rbacv1.ClusterRole); ok && r != nil {
								ruleObj = r.Rules
							} else if r, ok := obj.(*rbacv1b1.ClusterRole); ok && r != nil {
								ruleObj = r.Rules
							}
						} else {
							if r, ok := obj.(*rbacv1.Role); ok && r != nil {
								ruleObj = r.Rules
							} else if r, ok := obj.(*rbacv1b1.Role); ok && r != nil {
								ruleObj = r.Rules
							}
						}
						if ruleObj != nil {
							err = checkNvRbacRoleRules(roleName, rbacRoleDesc, ruleObj)
						} else {
							err = fmt.Errorf(`Unknown object type for Kubernetes %s "%s".`, rbacRoleDesc, roleName)
						}
					}
				} else {
					err = fmt.Errorf(`Cannot find Kubernetes %s "%s"(%s).`, rbacRoleDesc, roleName, err.Error())
				}
				if err != nil {
					log.WithFields(log.Fields{"type": rbacRoleDesc, "name": roleName, "error": err}).Error()
					k8sRbac403 = strings.Contains(err.Error(), " 403 ")
					if k8sRbac403 {
						err = fmt.Errorf(`Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
							nvRbacRoleBinding, NvRbacRole, NvAdmSvcNamespace, ctrlerSubjectWanted)
						log.WithFields(log.Fields{"error": err}).Error()
						errors = append(errors, err.Error())
						break
					} else if !strings.Contains(err.Error(), " 404 ") {
						if resources, verbs := collectRoleResVerbs(roleName); len(resources) > 0 && len(verbs) > 0 {
							err = fmt.Errorf(`Kubernetes %s "%s" is required to grant %s permission(s) on %s resource(s).`,
								rbacRoleDesc, roleName, strings.Join(verbs, ","), strings.Join(resources, ","))
						}
					}
				}
			}
		} else {
			err = fmt.Errorf(`Kubernetes clusterrole/role "%s" is not required.`, roleName)
		}
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	return errors, k8sRbac403
}

func VerifyNvRbacRoleBindings(bindingNames []string, existOnly, logging bool) ([]string, bool) { // returns (error string slice, is 403 error)
	var k8sRbac403 bool
	errors := make([]string, 0, len(bindingNames))
	for _, bindingName := range bindingNames {
		var err error

		if bindingWanted, ok := rbacRoleBindingsWanted[bindingName]; ok {
			var rt string
			var rbacRoleDesc string
			var rbacRoleBindingDesc string
			var rbacRoleBind interface{}
			var obj interface{}
			var foundSAs bool

			if bindingWanted.namespace == "" {
				rbacRoleBindingDesc = "clusterrolebinding"
				rt = K8sRscTypeClusRoleBinding
			} else {
				rbacRoleBindingDesc = "rolebinding"
				rt = k8sRscTypeRoleBinding
			}
			if bindingWanted.rbacRole.namespace == "" {
				rbacRoleDesc = "clusterrole"
			} else {
				rbacRoleDesc = "role"
			}

			if obj, err = global.ORCH.GetResource(rt, bindingWanted.namespace, bindingName); err == nil {
				if !existOnly {
					if bindingWanted.namespace == "" {
						if rb, ok := obj.(*rbacv1.ClusterRoleBinding); ok && rb != nil {
							_, rbacRoleBind = xlateClusRoleBinding(rb)
						} else if rb, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok && rb != nil {
							_, rbacRoleBind = xlateClusRoleBinding(rb)
						}
					} else {
						if rb, ok := obj.(*rbacv1.RoleBinding); ok && rb != nil {
							_, rbacRoleBind = xlateRoleBinding(rb)
						} else if rb, ok := obj.(*rbacv1b1.RoleBinding); ok && rb != nil {
							_, rbacRoleBind = xlateRoleBinding(rb)
						}
					}
					if rbacRoleBind != nil {
						var wrongBinding bool
						binding, _ := rbacRoleBind.(*k8sRoleBinding)
						if binding.role.name == bindingWanted.rbacRole.name && binding.role.domain == bindingWanted.rbacRole.namespace {
							if roleWanted, ok := rbacRolesWanted[binding.role.name]; ok {
								if roleWanted.k8sReserved {
									// this (cluster) role binding binds to k8s reserved cluster role
									if !roleWanted.supersetRoles.Contains(binding.role.name) {
										wrongBinding = true
									}
								} else if binding.role.name != roleWanted.name || binding.role.domain != roleWanted.namespace {
									wrongBinding = true
								}
							} else {
								err = fmt.Errorf(`[Internal Error] %s is not defined in rbacRolesWanted.`, bindingWanted.rbacRole.name)
							}
						} else {
							wrongBinding = true
						}
						if !wrongBinding && err == nil {
							foundSAs = true
							for _, saWanted := range bindingWanted.subjects {
								found := false
								for _, sa := range binding.svcAccounts {
									if saWanted == sa.name && NvAdmSvcNamespace == sa.domain {
										found = true
										break
									}
								}
								if !found {
									foundSAs = false
									break
								}
							}
						}
						if err == nil && (!foundSAs || wrongBinding) {
							subjects := getSubjectsString(NvAdmSvcNamespace, bindingWanted.subjects)
							if roleWanted, ok := rbacRolesWanted[bindingWanted.rbacRole.name]; ok && roleWanted.k8sReserved {
								err = fmt.Errorf(`Kubernetes %s "%s" is required to bind %s "%s" to service account(s) %s.`,
									rbacRoleBindingDesc, bindingName, rbacRoleDesc, bindingWanted.rbacRole.name, subjects)
							} else {
								err = fmt.Errorf(`Kubernetes %s "%s" is required to grant the permissions defined in %s "%s" to service account(s) %s.`,
									rbacRoleBindingDesc, bindingName, rbacRoleDesc, bindingWanted.rbacRole.name, subjects)
							}
						}
					} else {
						err = fmt.Errorf(`Unknown object type for Kubernetes %s "%s".`, rbacRoleBindingDesc, bindingName)
					}
				}
			} else {
				err = fmt.Errorf(`Cannot find Kubernetes %s "%s"(%s).`, rbacRoleBindingDesc, bindingName, err.Error())
			}
			if err != nil {
				if logging {
					log.WithFields(log.Fields{"type": rbacRoleBindingDesc, "name": bindingName, "error": err}).Error()
				}
				k8sRbac403 = strings.Contains(err.Error(), " 403 ")
				if k8sRbac403 {
					err = fmt.Errorf(`Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
						nvRbacRoleBinding, NvRbacRole, NvAdmSvcNamespace, ctrlerSubjectWanted)
					if logging {
						log.WithFields(log.Fields{"error": err}).Error()
					}
					errors = append(errors, err.Error())
					break
				}
			}
		} else {
			err = fmt.Errorf(`Kubernetes clusterrolebinding/rolebinding "%s" is not required.`, bindingName)
		}
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	return errors, k8sRbac403
}

func GetSaFromJwtToken(tokenStr string) (string, error) {
	var sa string
	var err error

	if token, _ := jwt.Parse(tokenStr, nil); token != nil {
		claims, _ := token.Claims.(jwt.MapClaims)
	LOOP:
		for k, v := range claims {
			if k == "kubernetes.io/serviceaccount/service-account.name" {
				sa = v.(string)
				break LOOP
			} else if k == "kubernetes.io" {
				vTemp := reflect.ValueOf(v)
				if vTemp.Kind() == reflect.Map {
					for _, k2Temp := range vTemp.MapKeys() {
						if k2, ok := k2Temp.Interface().(string); ok && k2 == "serviceaccount" {
							if v2Temp := reflect.ValueOf(vTemp.MapIndex(k2Temp)); v2Temp.Kind() == reflect.Struct {
								if saStruct := fmt.Sprintf("%v\n", v2Temp.Interface()); strings.HasPrefix(saStruct, "map[name:") {
									saStruct = saStruct[len("map[name:"):]
									if ss := strings.Split(saStruct, " "); len(ss) > 0 {
										sa = ss[0]
										break LOOP
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		err = fmt.Errorf("invalid token")
		log.WithFields(log.Fields{"len": len(tokenStr), "error": err}).Error()
	}

	return sa, err
}

func GetNvCtrlerServiceAccount(objFunc common.CacheEventFunc) {
	cacheEventFunc = objFunc
	nvControllerSA := ctrlerSubjectWanted
	filePath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if data, err := os.ReadFile(filePath); err == nil {
		if sa, err := GetSaFromJwtToken(string(data)); err == nil {
			nvControllerSA = sa
		}
	} else {
		log.WithFields(log.Fields{"filePath": filePath, "error": err}).Error()
	}
	if nvControllerSA != ctrlerSubjectWanted {
		ctrlerSubjectWanted = nvControllerSA
		ctrlerSubjectsWanted[0] = ctrlerSubjectWanted
		scannerSubjecstWanted[0] = ctrlerSubjectWanted
		scannerSubjecstWanted[1] = updaterSubjectWanted
		enforcerSubjecstWanted[0] = ctrlerSubjectWanted
		enforcerSubjecstWanted[1] = enforcerSubjectWanted
	}
	log.WithFields(log.Fields{"nvControllerSA": ctrlerSubjectWanted}).Info()

	return
}

func getSubjectsString(ns string, subjects []string) string {
	fullSubjects := make([]string, len(subjects))
	for i, s := range subjects {
		fullSubjects[i] = fmt.Sprintf("%s:%s", ns, s)
	}
	return strings.Join(fullSubjects, ", ")
}

func VerifyNvK8sRBAC(flavor, csp string, existOnly bool) ([]string, []string, []string, []string) {
	var k8sRbac403 bool
	var k8sClusterRoles []string
	var k8sClusterRoleBindings []string
	var k8sRoles []string
	var k8sRoleBindings []string
	var errs []string

	emptySlice := make([]string, 0)
	clusterRoleErrors := emptySlice
	clusterRoleBindingErrors := emptySlice
	roleErrors := emptySlice
	roleBindingErrors := emptySlice

	resInfo := map[string]string{ // resource object name : resource type
		"neuvector-updater-pod":  RscTypeCronJob,
		"neuvector-enforcer-pod": RscTypeDaemonSet,
	}
	getNeuvectorSvcAccount(resInfo)

	// check neuvector-updater-pod cronjob exists in k8s or not. if it exists, check rolebinding neuvector-binding-scanner / neuvector-admin
	// rolebinding neuvector-binding-scanner is preferred in 5.2(+)
	// rolebinding neuvector-admin is majorly for backward compatibility
	if _, err := global.ORCH.GetResource(RscTypeCronJob, NvAdmSvcNamespace, "neuvector-updater-pod"); err == nil {
		// updater cronjob is found
		if errs, _ := VerifyNvRbacRoleBindings([]string{NvAdminRoleBinding}, existOnly, false); len(errs) > 0 {
			// access denied for reading rolebinding resources, rolebinding neuvector-admin is not found or it's incorrectly configured
			if errs, k8sRbac403 := VerifyNvRbacRoleBindings([]string{NvScannerRoleBinding}, existOnly, true); len(errs) > 0 {
				if !k8sRbac403 {
					// rolebinding neuvector-binding-scanner is not found or it's incorrectly configured
					roleBindingErrors = errs
				} else {
					// 403 error reading k8s rolebinding means clusterrolebinding "neuvector-binding-rbac" is incorrect
					clusterRoleBindingErrors = errs
				}
			}
			if errs, k8sRbac403 := VerifyNvRbacRoles([]string{NvScannerRole}, existOnly); len(errs) > 0 {
				if !k8sRbac403 {
					roleErrors = errs
				} else if len(clusterRoleBindingErrors) == 0 {
					// 403 error reading k8s role means clusterrolebinding "neuvector-binding-rbac" is incorrect
					clusterRoleBindingErrors = errs
				}
			}
		}
	}

	for name, role := range rbacRolesWanted {
		if name == NvScannerRole || role.k8sReserved {
			continue
		}
		if role.namespace == "" {
			k8sClusterRoles = append(k8sClusterRoles, name)
		} else {
			k8sRoles = append(k8sRoles, name)
		}
	}

	for name, binding := range rbacRoleBindingsWanted {
		if name == NvScannerRoleBinding || name == NvAdminRoleBinding {
			continue
		}
		if binding.namespace == "" {
			k8sClusterRoleBindings = append(k8sClusterRoleBindings, name)
		} else {
			k8sRoleBindings = append(k8sRoleBindings, name)
		}
	}

	if errs, k8sRbac403 = VerifyNvRbacRoles(k8sClusterRoles, existOnly); !k8sRbac403 {
		clusterRoleErrors = append(clusterRoleErrors, errs...)
		if errs, k8sRbac403 = VerifyNvRbacRoles(k8sRoles, existOnly); !k8sRbac403 {
			roleErrors = append(roleErrors, errs...)
			if errs, k8sRbac403 = VerifyNvRbacRoleBindings(k8sClusterRoleBindings, existOnly, true); !k8sRbac403 {
				clusterRoleBindingErrors = append(clusterRoleBindingErrors, errs...)
				if errs, k8sRbac403 = VerifyNvRbacRoleBindings(k8sRoleBindings, existOnly, true); !k8sRbac403 {
					roleBindingErrors = append(roleBindingErrors, errs...)
				} else if len(errs) > 0 && len(clusterRoleBindingErrors) == 0 {
					// 403 error reading k8s rolebinding means clusterrolebinding "neuvector-binding-rbac" is incorrect
					clusterRoleBindingErrors = errs
				}
			} else if len(errs) > 0 && len(clusterRoleBindingErrors) == 0 {
				// 403 error reading k8s clusterrolebinding means clusterrolebinding "neuvector-binding-rbac" is incorrect
				clusterRoleBindingErrors = errs
			}
		} else if len(errs) > 0 && len(clusterRoleBindingErrors) == 0 {
			// 403 error reading k8s role means clusterrolebinding "neuvector-binding-rbac" is incorrect
			clusterRoleBindingErrors = errs
		}
	} else if len(errs) > 0 && len(clusterRoleBindingErrors) == 0 {
		// 403 error reading k8s clusterrole means clusterrolebinding "neuvector-binding-rbac" is incorrect
		clusterRoleBindingErrors = errs
	}

	return clusterRoleErrors, clusterRoleBindingErrors, roleErrors, roleBindingErrors
}

func xlateRole2(obj metav1.Object, action string) {
	var namespace string
	var name string
	var rbacBytes []byte

	if o, ok := obj.(*rbacv1.Role); ok {
		namespace = o.GetNamespace()
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	} else if o, ok := obj.(*rbacv1b1.Role); ok {
		namespace = o.GetNamespace()
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	}

	if name != "" {
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/roles/%s.%s", namespace, name)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacBytes))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateRoleBinding2(obj metav1.Object, action string) {
	var namespace string
	var name string
	var rbacBytes []byte

	if o, ok := obj.(*rbacv1.RoleBinding); ok {
		namespace = o.GetNamespace()
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	} else if o, ok := obj.(*rbacv1b1.RoleBinding); ok {
		namespace = o.GetNamespace()
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	}

	if name != "" {
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/rolebindings/%s.%s", namespace, name)
		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacBytes))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateClusRole2(obj metav1.Object, action string) {
	var name string
	var rbacBytes []byte

	if o, ok := obj.(*rbacv1.ClusterRole); ok {
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	} else if o, ok := obj.(*rbacv1b1.ClusterRole); ok {
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	}

	if name != "" {
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterroles/%s", name)
		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacBytes))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateClusRoleBinding2(obj metav1.Object, action string) {
	var name string
	var rbacBytes []byte

	if o, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	} else if o, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok {
		name = o.GetName()
		rbacBytes, _ = json.Marshal(o)
	}

	if name != "" {
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterrolebindings/%s", name)
		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacBytes))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}
