package resource

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/neuvector/k8s"
	rbacv1 "github.com/neuvector/k8s/apis/rbac/v1"
	rbacv1b1 "github.com/neuvector/k8s/apis/rbac/v1beta1"
	log "github.com/sirupsen/logrus"

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

	VERB_NONE  = 0
	VERB_READ  = 1
	VERB_WRITE = 2
)

const globalRolePrefix string = "cattle-globalrole-"

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

type k8sRoleBindingInfo struct {
	roleKind string
	roleName string
}

type k8sClusterRoleRuleInfo struct {
	apiGroup  string
	resources utils.Set
	verbs     utils.Set
}

type k8sClusterRoleInfo struct {
	rules []*k8sClusterRoleRuleInfo
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
var crdPolicyRoleVerbs utils.Set = utils.NewSet("delete", "list")

var nvSA string = "default"

var _k8sFlavor string // share.FlavorRancher or share.FlavorOpenShift

var k8sClusterRoles map[string]utils.Set = map[string]utils.Set{ // default k8s clusterrole -> superset of this default clusterrole
	"view":  utils.NewSet("cluster-admin", "admin", "edit"),
	"admin": utils.NewSet("cluster-admin"),
}

var nvClusterRoles map[string]*k8sClusterRoleInfo = map[string]*k8sClusterRoleInfo{ // role -> role configuration
	NvAppRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "",
			resources: utils.NewSet(RscNamespaces, K8sResNodes, K8sResPods, RscServices),
			verbs:     appRoleVerbs,
		},
	}},
	NvRbacRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "rbac.authorization.k8s.io",
			resources: utils.NewSet(RscTypeRbacClusterRolebindings, RscTypeRbacClusterRoles, RscTypeRbacRolebindings, RscTypeRbacRoles),
			verbs:     rbacRoleVerbs,
		},
	}},
	NvAdmCtrlRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "admissionregistration.k8s.io",
			resources: utils.NewSet(RscNameMutatingWebhookConfigurations, RscNameValidatingWebhookConfigurations),
			verbs:     admissionRoleVerbs,
		},
	}},
	NvCrdRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "apiextensions.k8s.io",
			resources: utils.NewSet(RscNameCustomResourceDefinitions),
			verbs:     crdRoleVerbs,
		},
	}},
	NvCrdSecRuleRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "neuvector.com",
			resources: utils.NewSet(RscTypeCrdClusterSecurityRule, RscTypeCrdSecurityRule),
			verbs:     crdPolicyRoleVerbs,
		},
	}},
	NvCrdAdmCtrlRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "neuvector.com",
			resources: utils.NewSet(RscTypeCrdAdmCtrlSecurityRule),
			verbs:     crdPolicyRoleVerbs,
		},
	}},
	NvCrdDlpRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "neuvector.com",
			resources: utils.NewSet(RscTypeCrdDlpSecurityRule),
			verbs:     crdPolicyRoleVerbs,
		},
	}},
	NvCrdWafRole: &k8sClusterRoleInfo{rules: []*k8sClusterRoleRuleInfo{
		&k8sClusterRoleRuleInfo{
			apiGroup:  "neuvector.com",
			resources: utils.NewSet(RscTypeCrdWafSecurityRule),
			verbs:     crdPolicyRoleVerbs,
		},
	}},
}

var nvClusterRoleBindings map[string]string = map[string]string{ // rolebindings -> role
	NvAppRoleBinding:        NvAppRole,
	NvRbacRoleBinding:       NvRbacRole,
	NvAdmCtrlRoleBinding:    NvAdmCtrlRole,
	NvCrdRoleBinding:        NvCrdRole,
	NvCrdSecRoleBinding:     NvCrdSecRuleRole,
	NvCrdAdmCtrlRoleBinding: NvCrdAdmCtrlRole,
	NvCrdDlpRoleBinding:     NvCrdDlpRole,
	NvCrdWafRoleBinding:     NvCrdWafRole,
	NvViewRoleBinding:       "view",
}

var nvRoleBindings map[string]*k8sRoleBindingInfo = map[string]*k8sRoleBindingInfo{
	NvAdminRoleBinding: &k8sRoleBindingInfo{
		roleKind: "ClusterRole", // case-sensitive
		roleName: "admin",
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

func deduceRoleRules(k8sFlavor, clusRoleName, roleDomain string, objs interface{}, getVerbs bool) (string, map[string]map[string]utils.Set) {

	ag2r2v := make(map[string]map[string]utils.Set) // apiGroup -> (resource -> verbs)
	if rules, ok := objs.([]*rbacv1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			rscs := rule.GetResources()

			if verbs.Cardinality() == 0 && len(rscs) == 0 {
				continue
			}
			var apiGroup string
			if apiGroups := rule.GetApiGroups(); len(apiGroups) > 0 {
				apiGroup = apiGroups[0]
			}
			r2v, ok := ag2r2v[apiGroup]

			if !ok {
				r2v = make(map[string]utils.Set)
				ag2r2v[apiGroup] = r2v
			}
			for _, rsc := range rscs {
				if v, ok := r2v[rsc]; ok {
					v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
	} else if rules, ok := objs.([]*rbacv1b1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			rscs := rule.GetResources()
			if verbs.Cardinality() == 0 && len(rscs) == 0 {
				continue
			}
			var apiGroup string
			if apiGroups := rule.GetApiGroups(); len(apiGroups) > 0 {
				apiGroup = apiGroups[0]
			}
			r2v, ok := ag2r2v[apiGroup]
			if !ok {
				r2v = make(map[string]utils.Set)
				ag2r2v[apiGroup] = r2v
			}
			for _, rsc := range rscs {
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

				if roleDomain == "" && k8sFlavor == share.FlavorRancher && strings.HasPrefix(clusRoleName, globalRolePrefix) {
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
		if _, ok := nvClusterRoles[clusRoleName]; !ok || !getVerbs {
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
	if roleInfo, ok := nvClusterRoles[roleName]; ok {
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

func checkNvClusterRoleRules(roleName string, objs interface{}) error {
	roleInfo, ok := nvClusterRoles[roleName]
	if !ok {
		return fmt.Errorf(`Kubernetes clusterrole "%s" is not required`, roleName)
	}
	ag2r2v := make(map[string]map[string]utils.Set) // collected apiGroup -> (resource -> verbs) in k8s rbac
	if rules, ok := objs.([]*rbacv1.PolicyRule); ok {
		for _, rule := range rules {
			for _, roleInfoRule := range roleInfo.rules {
				var apiGroup string
				if apiGroups := rule.GetApiGroups(); len(apiGroups) > 0 {
					apiGroup = apiGroups[0]
				}
				if roleInfoRule.apiGroup != apiGroup {
					continue
				}
				r2v, ok := ag2r2v[apiGroup]
				if !ok {
					r2v = make(map[string]utils.Set)
					ag2r2v[apiGroup] = r2v
				}
				verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
				for _, rsc := range rule.GetResources() {
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
	} else if rules, ok := objs.([]*rbacv1b1.PolicyRule); ok {
		for _, rule := range rules {
			for _, roleInfoRule := range roleInfo.rules {
				var apiGroup string
				if apiGroups := rule.GetApiGroups(); len(apiGroups) > 0 {
					apiGroup = apiGroups[0]
				}
				if roleInfoRule.apiGroup != apiGroup {
					continue
				}
				r2v, ok := ag2r2v[apiGroup]
				if !ok {
					r2v = make(map[string]utils.Set)
					ag2r2v[apiGroup] = r2v
				}
				verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
				for _, rsc := range rule.GetResources() {
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
			return fmt.Errorf(`Kubernetes clusterrole "%s" is required to grant %s permission(s) on %s resource(s).`,
				roleName, strings.Join(verbs, ","), strings.Join(resources, ","))
		}
	}

	return nil
}

func xlateRole(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*rbacv1.Role); ok {
		meta := o.GetMetadata()
		if meta == nil {
			log.Warn("Metadat not present")
			return "", nil
		}
		role := &k8sRole{
			uid:    meta.GetUid(),
			name:   meta.GetName(),
			domain: meta.GetNamespace(),
		}

		rules := o.GetRules()
		role.nvRole, _ = deduceRoleRules(_k8sFlavor, "", role.domain, rules, false)

		log.WithFields(log.Fields{"role": role}).Debug("v1")
		return role.uid, role
	} else if o, ok := obj.(*rbacv1b1.Role); ok {
		meta := o.GetMetadata()
		if meta == nil {
			log.Warn("Metadat not present")
			return "", nil
		}
		role := &k8sRole{
			uid:    meta.GetUid(),
			name:   meta.GetName(),
			domain: meta.GetNamespace(),
		}

		rules := o.GetRules()
		role.nvRole, _ = deduceRoleRules(_k8sFlavor, "", role.domain, rules, false)

		log.WithFields(log.Fields{"role": role}).Debug("v1beta1")
		return role.uid, role
	}

	return "", nil
}

func xlateClusRole(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*rbacv1.ClusterRole); ok {
		meta := o.GetMetadata()
		if meta == nil {
			log.Warn("Metadat not present")
			return "", nil
		}
		role := &k8sRole{
			uid:  meta.GetUid(),
			name: meta.GetName(),
		}

		rules := o.GetRules()
		_, getVerbs := nvClusterRoles[role.name]
		role.nvRole, role.apiRtVerbs = deduceRoleRules(_k8sFlavor, role.name, "", rules, getVerbs)

		log.WithFields(log.Fields{"role": role}).Debug("v1")
		return role.uid, role
	} else if o, ok := obj.(*rbacv1b1.ClusterRole); ok {
		meta := o.GetMetadata()
		if meta == nil {
			log.Warn("Metadat not present")
			return "", nil
		}
		role := &k8sRole{
			uid:  meta.GetUid(),
			name: meta.GetName(),
		}

		rules := o.GetRules()
		_, getVerbs := nvClusterRoles[role.name]
		role.nvRole, role.apiRtVerbs = deduceRoleRules(_k8sFlavor, role.name, "", rules, getVerbs)

		log.WithFields(log.Fields{"role": role}).Debug("v1beta1")
		return role.uid, role
	}

	return "", nil
}

func xlateRoleBinding(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*rbacv1.RoleBinding); ok {
		meta := o.Metadata
		role := o.GetRoleRef()
		subjects := o.GetSubjects()
		if meta == nil || role == nil {
			log.Warn("Metadat or role not present")
			return "", nil
		}

		roleBind := &k8sRoleBinding{
			uid:    meta.GetUid(),
			name:   meta.GetName(),
			domain: meta.GetNamespace(),
		}

		var roleKind, subKind string
		switch roleKind = role.GetKind(); roleKind {
		case "Role":
			roleBind.role = k8sObjectRef{name: role.GetName(), domain: roleBind.domain}
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.GetName()}
		default:
			log.WithFields(log.Fields{"role": roleKind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.GetKind()

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.GetName(), domain: s.GetNamespace(), subType: SUBJECT_USER}
				if subKind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if s.GetName() == nvSA && s.GetNamespace() == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}

		log.WithFields(log.Fields{"binding": roleBind}).Debug("v1")
		return roleBind.uid, roleBind
	} else if o, ok := obj.(*rbacv1b1.RoleBinding); ok {
		meta := o.Metadata
		role := o.GetRoleRef()
		subjects := o.GetSubjects()
		if meta == nil || role == nil {
			log.Warn("Metadat or role not present")
			return "", nil
		}

		roleBind := &k8sRoleBinding{
			uid:    meta.GetUid(),
			name:   meta.GetName(),
			domain: meta.GetNamespace(),
		}

		var roleKind, subKind string
		switch roleKind = role.GetKind(); roleKind {
		case "Role":
			roleBind.role = k8sObjectRef{name: role.GetName(), domain: roleBind.domain}
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.GetName()}
		default:
			log.WithFields(log.Fields{"role": roleKind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.GetKind()

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.GetName(), domain: s.GetNamespace(), subType: SUBJECT_USER}
				if subKind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if s.GetName() == nvSA && s.GetNamespace() == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}

		log.WithFields(log.Fields{"binding": roleBind}).Debug("v1beta1")
		return roleBind.uid, roleBind
	}

	return "", nil
}

func xlateClusRoleBinding(obj k8s.Resource) (string, interface{}) {
	if o, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
		meta := o.Metadata
		role := o.GetRoleRef()
		subjects := o.GetSubjects()
		if meta == nil || role == nil {
			log.Warn("Metadat or role not present")
			return "", nil
		}

		roleBind := &k8sRoleBinding{
			uid:  meta.GetUid(),
			name: meta.GetName(),
		}

		var roleKind, subKind string
		switch roleKind = role.GetKind(); roleKind {
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.GetName()}
		default:
			log.WithFields(log.Fields{"role": roleKind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.GetKind()

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.GetName(), domain: s.GetNamespace(), subType: SUBJECT_USER}
				if subKind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if s.GetName() == nvSA && s.GetNamespace() == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}

		log.WithFields(log.Fields{"binding": roleBind}).Debug("v1")
		return roleBind.uid, roleBind
	} else if o, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok {
		meta := o.Metadata
		role := o.GetRoleRef()
		subjects := o.GetSubjects()
		if meta == nil || role == nil {
			log.Warn("Metadat or role not present")
			return "", nil
		}

		roleBind := &k8sRoleBinding{
			uid:  meta.GetUid(),
			name: meta.GetName(),
		}

		var roleKind, subKind string
		switch roleKind = role.GetKind(); roleKind {
		case "ClusterRole":
			roleBind.role = k8sObjectRef{name: role.GetName()}
		default:
			log.WithFields(log.Fields{"role": roleKind}).Warn("Unknown role kind")
			return "", nil
		}
		roleBind.roleKind = role.GetKind()

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User", "Group":
				objRef := k8sSubjectObjRef{name: s.GetName(), domain: s.GetNamespace(), subType: SUBJECT_USER}
				if subKind == "Group" {
					objRef.subType = SUBJECT_GROUP
				}
				roleBind.users = append(roleBind.users, objRef)
			case "ServiceAccount":
				if s.GetName() == nvSA && s.GetNamespace() == NvAdmSvcNamespace {
					objRef := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
					roleBind.svcAccounts = append(roleBind.svcAccounts, objRef)
				}
			}
		}

		log.WithFields(log.Fields{"binding": roleBind}).Debug("v1beta1")
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

		if _, ok := nvClusterRoles[o.name]; ok && o.domain == "" {
			msg := fmt.Sprintf(`Kubernetes clusterrole "%s" is deleted.`, o.name)
			log.Warn(msg)
			cacheRbacEvent(d.flavor, msg, false)
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

		// in case the clusterrole neuvector-binding-customresourcedefinition is recreated/updated(after nv 5.0 deployment)
		// to have "update" verb so that nv can upgrade the CRD schema
		if n.name == NvCrdRole && n.apiRtVerbs != nil && nvCrdInitFunc != nil {
			if roleInfo, ok := nvClusterRoles[n.name]; ok {
				if nRtVerbs, ok1 := n.apiRtVerbs[roleInfo.rules[0].apiGroup]; ok1 {
					if nVerbs, ok1 := nRtVerbs[RscNameCustomResourceDefinitions]; ok1 {
						if old == nil {
							nvCrdInitFunc(isLeader)
						} else {
							if o = old.(*k8sRole); o.apiRtVerbs != nil {
								if oRtVerbs, ok2 := o.apiRtVerbs[roleInfo.rules[0].apiGroup]; ok2 {
									if oVerbs, ok2 := oRtVerbs[RscNameCustomResourceDefinitions]; ok2 {
										if (nVerbs.Contains("update") || nVerbs.Contains("*")) &&
											(!oVerbs.Contains("update") && !oVerbs.Contains("*")) {
											nvCrdInitFunc(isLeader)
										}
									}
								}
							}
						}
					}
				}
			}
		}

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
		if roleInfo, ok := nvClusterRoles[n.name]; ok {
			evtLog := false
			for _, roleInfoRule := range roleInfo.rules {
				found := false
				for apiGroup, rtVerbs := range n.apiRtVerbs {
					if apiGroup != "*" && apiGroup != roleInfoRule.apiGroup {
						continue
					}
					foundResources := utils.NewSet()
					for rt, verbs := range rtVerbs {
						if verbs.IsSuperset(roleInfoRule.verbs) || verbs.Contains("*") {
							foundResources.Add(rt)
						}
					}
					if foundResources.IsSuperset(roleInfoRule.resources) || foundResources.Contains("*") {
						found = true
						break
					}
				}
				if !found {
					evtLog = true
					break
				}
			}
			if evtLog {
				if resources, verbs := collectRoleResVerbs(n.name); len(resources) > 0 && len(verbs) > 0 {
					msg := fmt.Sprintf(`Kubernetes clusterrole "%s" is required to grant %s permission(s) on %s resource(s).`,
						n.name, strings.Join(verbs, ","), strings.Join(resources, ","))
					log.Warn(msg)
					cacheRbacEvent(d.flavor, msg, false)
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
		evLog := false
		var rtName string
		if _, ok := nvClusterRoleBindings[o.name]; ok && o.domain == "" {
			evLog = true
			rtName = "clusterrolebinding"
		} else if _, ok := nvRoleBindings[o.name]; ok && o.domain == NvAdmSvcNamespace {
			evLog = true
			rtName = "rolebinding"
		}
		if evLog {
			msg := fmt.Sprintf(`Kubernetes %s "%s" is deleted.`, rtName, o.name)
			log.WithFields(log.Fields{"role": o.role.name, "roleKind": o.roleKind, "domain": o.domain}).Warn(msg)
			cacheRbacEvent(d.flavor, msg, false)
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
			var ok bool
			var role string
			var rtName string
			evtLog := true
			if role, ok = nvClusterRoleBindings[n.name]; ok && n.domain == "" {
				rtName = "clusterrolebinding"
				if superRoles, _ := k8sClusterRoles[role]; role == n.role.name || (superRoles != nil && superRoles.Contains(n.role.name)) {
					for _, sa := range n.svcAccounts {
						if sa.name == nvSA && sa.domain == NvAdmSvcNamespace {
							evtLog = false
							break
						}
					}
				}
			} else if info, ok := nvRoleBindings[n.name]; ok && n.domain == NvAdmSvcNamespace {
				rtName = "rolebinding"
				role = info.roleName
				if info.roleKind == n.roleKind {
					if superRoles, _ := k8sClusterRoles[role]; role == n.role.name || (superRoles != nil && superRoles.Contains(n.role.name)) {
						for _, sa := range n.svcAccounts {
							if sa.name == nvSA && sa.domain == NvAdmSvcNamespace {
								evtLog = false
								break
							}
						}
					}
				}
			} else {
				evtLog = false
			}
			if evtLog {
				var msg string
				_, ok1 := nvClusterRoles[role]
				_, ok2 := k8sClusterRoles[role]
				if !ok1 && !ok2 {
					msg = fmt.Sprintf(`Kubernetes %s "%s" is required to grant clusterrole "%s" to service account %s:%s.`,
						rtName, n.name, role, NvAdmSvcNamespace, nvSA)
				} else {
					msg = fmt.Sprintf(`Kubernetes %s "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
						rtName, n.name, role, NvAdmSvcNamespace, nvSA)
				}
				log.WithFields(log.Fields{"role": n.role.name}).Warn(msg)
				cacheRbacEvent(d.flavor, msg, false)
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
func VerifyNvClusterRoles(roleNames []string, existOnly bool) ([]string, bool) { // returns (error string slice, is 403 error)
	var k8sRbac403 bool
	errors := make([]string, 0, len(roleNames))
	for _, roleName := range roleNames {
		var err error
		var obj interface{}
		if obj, err = global.ORCH.GetResource(K8sRscTypeClusRole, k8s.AllNamespaces, roleName); err == nil {
			if !existOnly {
				if r, ok := obj.(*rbacv1.ClusterRole); ok && r != nil {
					err = checkNvClusterRoleRules(roleName, r.GetRules())
				} else if r, ok := obj.(*rbacv1b1.ClusterRole); ok && r != nil {
					err = checkNvClusterRoleRules(roleName, r.GetRules())
				} else {
					errors = append(errors, fmt.Sprintf(`Unknown object type for Kubernetes clusterrole "%s".`, roleName))
					continue
				}
			}
		} else {
			err = fmt.Errorf(`Cannot find Kubernetes clusterrole "%s"(%s).`, roleName, err.Error())
		}
		if err != nil {
			log.WithFields(log.Fields{"clusterrole": roleName, "error": err}).Error()
			k8sRbac403 = strings.Contains(err.Error(), " 403 ")
			if k8sRbac403 {
				err = fmt.Errorf(`Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
					NvRbacRoleBinding, NvRbacRole, NvAdmSvcNamespace, nvSA)
				log.WithFields(log.Fields{"error": err}).Error()
				errors = append(errors, err.Error())
				break
			}
			if resources, verbs := collectRoleResVerbs(roleName); len(resources) > 0 && len(verbs) > 0 {
				err = fmt.Errorf(`Kubernetes clusterrole "%s" is required to grant %s permission(s) on %s resource(s).`,
					roleName, strings.Join(verbs, ","), strings.Join(resources, ","))
			}
			errors = append(errors, err.Error())
		}
	}

	return errors, k8sRbac403
}

func VerifyNvClusterRoleBindings(bindingNames []string, existOnly bool) ([]string, bool) { // returns (error string slice, is 403 error)
	var k8sRbac403 bool
	errors := make([]string, 0, len(bindingNames))
	for _, bindingName := range bindingNames {
		var err error
		if rolename, ok := nvClusterRoleBindings[bindingName]; ok {
			var obj interface{}
			if obj, err = global.ORCH.GetResource(K8sRscTypeClusRoleBinding, k8s.AllNamespaces, bindingName); err == nil {
				if !existOnly {
					var found bool
					var clusRoleBind interface{}
					var k8sDefaultRole bool
					var binding *k8sRoleBinding
					if rb, ok := obj.(*rbacv1.ClusterRoleBinding); ok && rb != nil {
						_, clusRoleBind = xlateClusRoleBinding(rb)
					} else if rb, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok && rb != nil {
						_, clusRoleBind = xlateClusRoleBinding(rb)
					}
					if clusRoleBind != nil {
						binding = clusRoleBind.(*k8sRoleBinding)
					}
					if binding != nil {
						ok = false
						if binding.role.name == rolename {
							ok = true
						} else if superRoles, _ := k8sClusterRoles[rolename]; superRoles != nil {
							k8sDefaultRole = true
							if superRoles.Contains(binding.role.name) {
								ok = true
							}
						}
						if ok {
							for _, sa := range binding.svcAccounts {
								if sa.name == nvSA && sa.domain == NvAdmSvcNamespace {
									found = true
									break
								}
							}
						}
					} else {
						err = fmt.Errorf(`Unknown object type for Kubernetes clusterrolebinding "%s".`, bindingName)
					}
					if err == nil && !found {
						var fmtStr string
						if k8sDefaultRole {
							fmtStr = `Kubernetes clusterrolebinding "%s" is required to bind clusterrole "%s" to service account %s:%s.`
						} else {
							fmtStr = `Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`
						}
						err = fmt.Errorf(fmtStr, bindingName, rolename, NvAdmSvcNamespace, nvSA)
					}
				}
			} else {
				err = fmt.Errorf(`Cannot find Kubernetes clusterrolebinding "%s"(%s).`, bindingName, err.Error())
			}
		} else {
			err = fmt.Errorf(`clusterrolebinding "%s" is not required.`, bindingName)
		}
		if err != nil {
			log.WithFields(log.Fields{"clusterrolebinding": bindingName, "error": err}).Error()
			k8sRbac403 = strings.Contains(err.Error(), " 403 ")
			if k8sRbac403 {
				err = fmt.Errorf(`Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
					NvRbacRoleBinding, NvRbacRole, NvAdmSvcNamespace, nvSA)
				log.WithFields(log.Fields{"error": err}).Error()
			}
			errors = append(errors, err.Error())
			if k8sRbac403 {
				break
			}
		}
	}

	return errors, k8sRbac403
}

func VerifyNvRoleBinding(bindingName, namespace string, existOnly bool) error {
	var err error
	if bindingInfo, ok := nvRoleBindings[bindingName]; ok {
		var obj interface{}
		if obj, err = global.ORCH.GetResource(k8sRscTypeRoleBinding, namespace, bindingName); err == nil {
			if !existOnly {
				var found bool
				var k8sDefaultRole bool
				var roleBind interface{}
				var binding *k8sRoleBinding
				if rb, ok := obj.(*rbacv1.RoleBinding); ok && rb != nil {
					_, roleBind = xlateRoleBinding(rb)
				} else if rb, ok := obj.(*rbacv1b1.RoleBinding); ok && rb != nil {
					_, roleBind = xlateRoleBinding(rb)
				}
				if roleBind != nil {
					binding = roleBind.(*k8sRoleBinding)
				}
				if binding != nil {
					if binding.roleKind == bindingInfo.roleKind {
						ok = false
						if binding.role.name == bindingInfo.roleName {
							ok = true
						} else if superRoles, _ := k8sClusterRoles[bindingInfo.roleName]; superRoles != nil {
							k8sDefaultRole = true
							if superRoles.Contains(binding.role.name) {
								ok = true
							}
						}
						if ok {
							for _, sa := range binding.svcAccounts {
								if sa.name == nvSA && sa.domain == NvAdmSvcNamespace {
									found = true
									break
								}
							}
						}
					}
				} else {
					err = fmt.Errorf(`Unknown object type for Kubernetes rolebinding "%s".`, bindingName)
				}
				if err == nil && !found {
					var fmtStr string
					if k8sDefaultRole {
						fmtStr = `Kubernetes rolebinding "%s" is required to bind %s "%s" to service account %s:%s.`
					} else {
						fmtStr = `Kubernetes rolebinding "%s" is required to grant the permissions defined in %s "%s" to service account %s:%s.`
					}
					err = fmt.Errorf(fmtStr, bindingName, strings.ToLower(bindingInfo.roleKind), bindingInfo.roleName, NvAdmSvcNamespace, nvSA)
				}
			}
		} else {
			err = fmt.Errorf(`Cannot find Kubernetes rolebinding "%s"(%s).`, bindingName, err.Error())
		}
		if err != nil {
			log.WithFields(log.Fields{"rolebinding": bindingName, "error": err}).Error()
			if strings.Contains(err.Error(), " 403 ") {
				err = fmt.Errorf(`Kubernetes clusterrolebinding "%s" is required to grant the permissions defined in clusterrole "%s" to service account %s:%s.`,
					NvRbacRoleBinding, NvRbacRole, NvAdmSvcNamespace, nvSA)
				log.WithFields(log.Fields{"error": err}).Error()
			}
		}
	} else {
		err = fmt.Errorf(`rolebinding "%s" is not required.`, bindingName)
	}

	return err
}

func GetNvServiceAccount(objFunc common.CacheEventFunc) {
	cacheEventFunc = objFunc
	filePath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if data, err := ioutil.ReadFile(filePath); err == nil {
		if token, _ := jwt.Parse(string(data), nil); token != nil {
			claims, _ := token.Claims.(jwt.MapClaims)
			for k, v := range claims {
				if k == "kubernetes.io/serviceaccount/service-account.name" {
					nvSA = v.(string)
					log.WithFields(log.Fields{"nvSA": nvSA}).Info()
					return
				} else if k == "kubernetes.io" {
					vTemp := reflect.ValueOf(v)
					if vTemp.Kind() == reflect.Map {
						for _, k2Temp := range vTemp.MapKeys() {
							if k2, ok := k2Temp.Interface().(string); ok && k2 == "serviceaccount" {
								if v2Temp := reflect.ValueOf(vTemp.MapIndex(k2Temp)); v2Temp.Kind() == reflect.Struct {
									if saStruct := fmt.Sprintf("%v\n", v2Temp.Interface()); strings.HasPrefix(saStruct, "map[name:") {
										saStruct = saStruct[len("map[name:"):]
										if ss := strings.Split(saStruct, " "); len(ss) > 0 {
											nvSA = ss[0]
											log.WithFields(log.Fields{"nvSA": nvSA}).Info()
											return
										}
									}
								}
							}
						}
					}
				}
			}
		} else {
			log.WithFields(log.Fields{"filePath": filePath}).Error("invalid token")
		}
	} else {
		log.WithFields(log.Fields{"filePath": filePath, "error": err}).Error()
	}

	return
}

func VerifyNvK8sRBAC(flavor string, existOnly bool) ([]string, []string, []string) {
	emptySlice := make([]string, 0)
	clusterRoleErrors := emptySlice
	clusterRoleBindingErrors := emptySlice
	roleBindingErrors := emptySlice

	var k8sRbac403 bool
	k8sClusterRoleBindings := []string{NvRbacRoleBinding, NvAppRoleBinding, NvAdmCtrlRoleBinding,
		NvCrdRoleBinding, NvCrdSecRoleBinding, NvCrdAdmCtrlRoleBinding, NvCrdDlpRoleBinding, NvCrdWafRoleBinding}
	if flavor == share.FlavorOpenShift && (ocVersionMajor > 3 || ocVersionMajor == 0) {
		k8sClusterRoleBindings = append(k8sClusterRoleBindings, NvOperatorsRoleBinding)
	}
	clusterRoleErrors, k8sRbac403 = VerifyNvClusterRoles(k8sClusterRoleBindings, existOnly)
	if !k8sRbac403 {
		k8sClusterRoleBindings = append(k8sClusterRoleBindings, NvViewRoleBinding)
		clusterRoleBindingErrors, k8sRbac403 = VerifyNvClusterRoleBindings(k8sClusterRoleBindings, existOnly)
		if !k8sRbac403 {
			errors := make([]string, 0, 1)
			if err := VerifyNvRoleBinding(NvAdminRoleBinding, NvAdmSvcNamespace, existOnly); err != nil {
				errors = append(errors, err.Error())
			}
			roleBindingErrors = errors
		}
	}

	return clusterRoleErrors, clusterRoleBindingErrors, roleBindingErrors
}

func xlateRole2(obj k8s.Resource, action string) {
	if o, ok := obj.(*rbacv1.Role); ok {

		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/roles/%s.%s", *o.Metadata.Namespace, *o.Metadata.Name)
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}

	} else if o, ok := obj.(*rbacv1b1.Role); ok {
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/roles/%s.%s", *o.Metadata.Namespace, *o.Metadata.Name)
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateRoleBinding2(obj k8s.Resource, action string) {
	if o, ok := obj.(*rbacv1.RoleBinding); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/rolebindings/%s.%s", meta.GetNamespace(), meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	} else if o, ok := obj.(*rbacv1b1.RoleBinding); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/rolebindings/%s.%s", meta.GetNamespace(), meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateClusRole2(obj k8s.Resource, action string) {
	if o, ok := obj.(*rbacv1.ClusterRole); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterroles/%s", meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	} else if o, ok := obj.(*rbacv1b1.ClusterRole); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterroles/%s", meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}

func xlateClusRoleBinding2(obj k8s.Resource, action string) {
	if o, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterrolebindings/%s", meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	} else if o, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok {
		meta := o.Metadata
		docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterrolebindings/%s", meta.GetName())
		rbacv1, _ := json.Marshal(o)

		if action == "ADDED" || action == "MODIFIED" {
			opa.AddDocument(docKey, string(rbacv1))
		} else if action == "DELETED" {
			opa.DeleteDocument(docKey)
		}
	}
}
