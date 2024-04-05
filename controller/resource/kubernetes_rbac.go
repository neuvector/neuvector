package resource

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"
	"strings"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1b1 "k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	uid        string
	name       string
	domain     string
	nvRole     string
	apiRtVerbs map[string]map[string]utils.Set // apiGroup -> (resource -> verbs), for nv-related k8sRole only
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
//------------------------------------------------------------------------------------------------
// fedAdmin:    in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"*"}    // "cattle-globalrole-....." clusterrole(with clusterrolebinding)
// fedReader:   in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"get}   // "cattle-globalrole-....." clusterrole(with clusterrolebinding)
// admin:       in {"read-only.neuvector.api.io", "*"}	 	"*"				in {"*"}    // clusterrole(with clusterrolebinding)
// reader:      in {"read-only.neuvector.api.io", "*"}		"*"				in {"get"}  // clusterrole(with clusterrolebinding)
// ns admin:    in {"read-only.neuvector.api.io", "*"}		"*"				in {"*"}    // clusterrole(with rolebinding) or role
// ns reader:   in {"read-only.neuvector.api.io", "*"}		"*"				in {"get"}  // clusterrole(with rolebinding) or role
var nvReadVerbs utils.Set = utils.NewSet("get")
var nvWriteVerbs utils.Set = utils.NewSet("*")
var nvPermissionRscs utils.Set
var nvRscsMap map[string]utils.Set // key is apiGroup, value is (permission) resources

//Rancher SSO : (phase-2) custom roles. Pseudo role has name "custom_:[pseudo name]"
//var nvPermissionIndex map[string]int // For rancher only: permission -> index in the pseudo role's [pseudo name]
//var nvIndexPermission map[int]string // For rancher only: index -> permission in the pseudo role's [pseudo name]

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

// Rancher SSO : (future) custom role?
func k8s2NVRole(k8sFlavor string, rscs, readVerbs, writeVerbs utils.Set, r2v map[string]utils.Set) string {

	if k8sFlavor == share.FlavorRancher {
		var nvRole string
		for rsc, verbs := range r2v {
			if rscs.Contains(rsc) {
				if rsc == "*" {
					if writeVerbs.Intersect(verbs).Cardinality() != 0 {
						return api.UserRoleAdmin
					} else if readVerbs.Intersect(verbs).Cardinality() != 0 {
						nvRole = api.UserRoleReader
					}
				} else { // for custom roles
					/* Rancher SSO => TO DO
					v := VERB_NONE
					if readVerbs.Intersect(verbs).Cardinality() != 0 {
						v = VERB_READ
					} else if writeVerbs.Intersect(verbs).Cardinality() != 0 {
						v = VERB_WRITE
					}
					nvRole = updatePseudoRole(nvRole, rsc, v)
					*/
				}
			}
		}
		return nvRole
	}

	//
	// Both Kubernetes and OpenShift mapping goes here, keep these two using the same behavior.
	// As v5.0, we do not support Kubernetes login.
	// When it comes to support Kubernetes login, we should consider to provide more granular on the mapping.
	//
	for rsc, verbs := range r2v {
		if rscs.Contains(rsc) && writeVerbs.Intersect(verbs).Cardinality() != 0 {
			return api.UserRoleAdmin
		}
	}

	for rsc, verbs := range r2v {
		if rscs.Contains(rsc) && readVerbs.Intersect(verbs).Cardinality() != 0 {
			return api.UserRoleReader
		}
	}

	return api.UserRoleNone
}

func deduceRoleRules(k8sFlavor, rbacRoleName, roleDomain string, objs interface{}) (string, map[string]map[string]utils.Set) {

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
					v.Union(verbs)
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
					v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
	}
	if len(ag2r2v) > 0 {
		var nvRole string
		var rscsMap map[string]utils.Set = ocAdminRscsMap
		var readVerbs utils.Set = ocReaderVerbs
		var writeVerbs utils.Set = ocAdminVerbs // users who has these verbs on specified resources are nv admin
		if k8sFlavor == share.FlavorRancher {
			rscsMap = nvRscsMap
			readVerbs = nvReadVerbs
			writeVerbs = nvWriteVerbs
		}
		gAdjusted := map[string]string{api.UserRoleAdmin: api.UserRoleFedAdmin, api.UserRoleReader: api.UserRoleFedReader}
		for apiGroup, rscs := range rscsMap {
			if r2v, ok := ag2r2v[apiGroup]; ok && len(r2v) > 0 {
				nvRoleTemp := k8s2NVRole(k8sFlavor, rscs, readVerbs, writeVerbs, r2v)

				if roleDomain == "" && k8sFlavor == share.FlavorRancher && strings.HasPrefix(rbacRoleName, globalRolePrefix) {
					if adjusted, ok := gAdjusted[nvRoleTemp]; ok {
						nvRole = adjusted
						break
					}
				}
				if (nvRoleTemp == api.UserRoleAdmin && nvRole != api.UserRoleAdmin) ||
					(nvRoleTemp == api.UserRoleReader && nvRole == api.UserRoleNone) {
					nvRole = nvRoleTemp
				} else if strings.HasPrefix(nvRoleTemp, "custom_:") {
					// Rancher SSO => TO DO
					//nvRole = mergePesudoRoles(nvRole, nvRoleTemp)
				}
			}
		}
		if roleInfo, ok := rbacRolesWanted[rbacRoleName]; !ok || roleInfo.k8sReserved || !getVerbs {
			ag2r2v = nil
		}
		return nvRole, ag2r2v
	} else {
		return api.UserRoleNone, nil
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
		role.nvRole, role.apiRtVerbs = deduceRoleRules(_k8sFlavor, role.name, role.domain, rules)
		log.WithFields(log.Fields{"role": role}).Debug(ver)
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
		role.nvRole, role.apiRtVerbs = deduceRoleRules(_k8sFlavor, role.name, "", rules)
		log.WithFields(log.Fields{"clusterrole": role}).Debug(ver)
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

		log.WithFields(log.Fields{"rolebinding": roleBind}).Debug("v1")
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

		log.WithFields(log.Fields{"rolebinding": roleBind}).Debug("v1beta1")
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

		log.WithFields(log.Fields{"clusterrolebinding": roleBind}).Debug("v1")
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

		log.WithFields(log.Fields{"clusterrolebinding": roleBind}).Debug("v1beta1")
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
		if nvRole, ok := d.roleCache[ref]; ok {
			users := utils.NewSet()
			for u, roleRefs := range d.userCache {
				for roleRef := range roleRefs.Iter() {
					if roleRef.(k8sRoleRef).role == ref {
						roleRefs.Remove(roleRef)
						log.WithFields(log.Fields{"k8s-role": ref, "user": u, "left": roleRefs}).Debug("Delete roleRef")
						if !users.Contains(u) {
							users.Add(u)
						}
					}
				}
				if roleRefs.Cardinality() == 0 {
					// delete user
					delete(d.userCache, u)
					log.WithFields(log.Fields{"user": u}).Debug("Delete user")
				}
			}
			delete(d.roleCache, ref)
			log.WithFields(log.Fields{"k8s-role": ref, "nv-role": nvRole}).Debug("Delete role")

			// re-evaluate users who bind to the deleted role
			for u := range users.Iter() {
				d.rbacEvaluateUser(u.(k8sSubjectObjRef))
			}
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
				if o.domain == "" {
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
		if n.nvRole != "" {
			d.roleCache[ref] = n.nvRole
		} else {
			delete(d.roleCache, ref)
		}
		log.WithFields(log.Fields{"k8s-role": ref, "nv-role": n.nvRole}).Debug("Update role")

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

		// re-evaluate users who bind to the role
		for u, roleRefs := range d.userCache {
			for roleRef := range roleRefs.Iter() {
				if roleRef.(k8sRoleRef).role == ref {
					d.rbacEvaluateUser(u)
					break
				}
			}
		}

		// if it's nv-required role, check whether its configuration meets nv's need
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
				if o.domain == "" {
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
			if roleRefs, ok := d.userCache[u]; ok && roleRefs.Contains(oldRoleRef) {
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"name": o.name, "k8s-role": oldRoleRef, "user": u, "left": roleRefs}).Debug("Delete role binding")

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

		// 2. Delete roles for users removed from the binding
		deletes := oldUsers.Difference(newUsers)
		for u := range deletes.Iter() {
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; ok && roleRefs.Contains(oldRoleRef) {
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": oldRoleRef, "user": userRef, "left": roleRefs}).Debug("Delete role binding")

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
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef}).Debug("Create user role binding")
			} else {
				roleRefs.Add(newRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef}).Debug("Add user role binding")
			}

			d.rbacEvaluateUser(userRef)
		}

		// 4. For users whose bindings are changed
		changes := newUsers.Difference(creates)
		for u := range changes.Iter() {
			userRef := u.(k8sSubjectObjRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef}).Debug("Create user role binding")
			} else if o.role != n.role {
				// o won't be nil when we get here
				roleRefs.Add(newRoleRef)
				log.WithFields(log.Fields{"name": n.name, "k8s-role": newRoleRef, "user": userRef}).Debug("Add user role binding")
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
		if rbac, ok := d.rbacCache[subj]; ok {
			delete(d.rbacCache, subj)
			log.WithFields(log.Fields{"user": user}).Debug("Delete rbac user")

			d.lock.Lock()
			w, ok := d.watchers[RscTypeRBAC]
			d.lock.Unlock()
			if ok && w.cb != nil {
				w.cb(RscTypeRBAC, WatchEventDelete,
					nil,
					&RBAC{Name: user.name, Domain: user.domain, Roles: rbac},
				)
			}
		}
	} else {
		rbac := make(map[string]string) // domain -> nvRole

		for r := range roleRefs.Iter() {
			roleRef := r.(k8sRoleRef)

			if newNVRole, ok := d.roleCache[roleRef.role]; ok {
				if oldNVRole, ok := rbac[roleRef.domain]; !ok {
					rbac[roleRef.domain] = newNVRole
				} else if oldNVRole != newNVRole {
					if (oldNVRole == api.UserRoleReader && newNVRole != api.UserRoleNone) || (oldNVRole == api.UserRoleNone) || (newNVRole == api.UserRoleFedAdmin) {
						rbac[roleRef.domain] = newNVRole
					}
				}
			}
		}

		for d, r := range rbac {
			if d != "" {
				if r == api.UserRoleNone {
					delete(rbac, d)
				} else if r == api.UserRoleFedAdmin {
					rbac[d] = api.UserRoleAdmin
				} else if r == api.UserRoleFedReader {
					rbac[d] = api.UserRoleReader
				}
			}
		}

		if nvRole, ok := rbac[""]; ok {
			if nvRole == api.UserRoleFedAdmin || nvRole == api.UserRoleAdmin {
				// If the user is cluster admin or fed admin, it is the admin of all namespaces
				rbac = map[string]string{"": nvRole}
			} else if nvRole == api.UserRoleFedReader || nvRole == api.UserRoleReader {
				// If the user is cluster reader or fed reader, it is the reader of all namespaces
				for domain, nvDomainRole := range rbac {
					if domain != "" && nvDomainRole == api.UserRoleReader {
						delete(rbac, domain)
					}
				}
			}
		} else if len(rbac) > 0 {
			rbac[""] = api.UserRoleNone
		}

		oldrbac, _ := d.rbacCache[subj]

		// callback
		log.WithFields(log.Fields{"rbac": rbac, "oldrbac": oldrbac, "user": user}).Debug()
		if reflect.DeepEqual(oldrbac, rbac) {
			return
		} else if len(rbac) > 0 {
			d.rbacCache[subj] = rbac
		} else {
			delete(d.rbacCache, subj)
		}

		d.lock.Lock()
		w, ok := d.watchers[RscTypeRBAC]
		d.lock.Unlock()
		if ok && w.cb != nil {
			if oldrbac == nil {
				w.cb(RscTypeRBAC, WatchEventAdd,
					&RBAC{Name: user.name, Domain: user.domain, Roles: rbac},
					nil,
				)
			} else {
				w.cb(RscTypeRBAC, WatchEventModify,
					&RBAC{Name: user.name, Domain: user.domain, Roles: rbac},
					&RBAC{Name: user.name, Domain: user.domain, Roles: oldrbac},
				)
			}
		}
	}
}

func (d *kubernetes) GetUserRoles(user string, subType uint8) (map[string]string, error) {
	userRef := k8sSubjectObjRef{name: user, domain: "", subType: subType}

	d.rbacLock.RLock()
	defer d.rbacLock.RUnlock()

	if rbac, ok := d.rbacCache[userRef]; ok {
		// rbac is replaced as a whole -> no need to clone
		return rbac, nil
	}

	return nil, ErrUserNotFound
}

func (d *kubernetes) ListUsers() []orchAPI.UserRBAC {
	list := make([]orchAPI.UserRBAC, len(d.rbacCache))
	i := 0

	d.rbacLock.RLock()
	defer d.rbacLock.RUnlock()

	for userRef, rbac := range d.rbacCache {
		// rbac is replaced as a whole -> no need to clone
		list[i] = orchAPI.UserRBAC{Name: userRef.name, Domain: userRef.domain, RBAC: rbac}
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
	if data, err := ioutil.ReadFile(filePath); err == nil {
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
