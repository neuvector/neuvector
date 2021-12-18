package resource

import (
	"fmt"
	"reflect"

	"github.com/ericchiang/k8s"
	rbacv1 "github.com/ericchiang/k8s/apis/rbac/v1"
	rbacv1b1 "github.com/ericchiang/k8s/apis/rbac/v1beta1"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/utils"
)

type k8sObjectRef struct {
	name   string
	domain string
}

type k8sRoleRef struct {
	role   k8sObjectRef
	domain string // effective domain
}

type k8sRole struct {
	uid    string
	name   string
	domain string
	nvRole string
}

type k8sRoleBinding struct {
	uid    string
	name   string
	domain string
	role   k8sObjectRef
	users  []k8sObjectRef
}

var adminRscs utils.Set = utils.NewSet(
	"pods",
	"daemonsets",
	"deployments",
	"replicasets",
	"statefulsets",
	"services",
	"*",
)

var adminVerbs utils.Set = utils.NewSet(
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

var appRoleVerbs utils.Set = utils.NewSet(
	"get",
	"list",
	"watch",
	"update",
)

var admissionRoleVerbs utils.Set = utils.NewSet(
	"get",
	"list",
	"watch",
	"create",
	"update",
	"delete",
)

var crdRoleVerbs utils.Set = utils.NewSet(
	"watch",
	"create",
	"get",
)

var nvRequiredRscVerbs map[string]utils.Set = map[string]utils.Set{
	RscNameMutatingWebhookConfigurations:   admissionRoleVerbs,
	RscNameValidatingWebhookConfigurations: admissionRoleVerbs,
	RscNamespaces:                          appRoleVerbs,
	RscServices:                            appRoleVerbs,
	RscNameCustomResourceDefinitions:       crdRoleVerbs,
}

func k8s2NVRole(r2v map[string]utils.Set) string {
	for rsc, verbs := range r2v {
		if adminRscs.Contains(rsc) && adminVerbs.Intersect(verbs).Cardinality() != 0 {
			return api.UserRoleAdmin
		}
	}
	return api.UserRoleReader
}

func deduceRoleRules(objs interface{}) string {
	if rules, ok := objs.([]*rbacv1.PolicyRule); ok {
		r2v := make(map[string]utils.Set) // resource -> verbs
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			rscs := rule.GetResources()
			for _, rsc := range rscs {
				if v, ok := r2v[rsc]; ok {
					v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
		return k8s2NVRole(r2v)
	} else if rules, ok := objs.([]*rbacv1b1.PolicyRule); ok {
		r2v := make(map[string]utils.Set) // resource -> verbs
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			rscs := rule.GetResources()
			for _, rsc := range rscs {
				if v, ok := r2v[rsc]; ok {
					v.Union(verbs)
				} else {
					r2v[rsc] = verbs
				}
			}
		}
		return k8s2NVRole(r2v)
	}

	return ""
}

func DeduceAdmCtrlRoleRules(rscsToCheck utils.Set, objs interface{}) error {
	r2v := make(map[string]utils.Set) // collected resource -> verbs in k8s rbac
	if rules, ok := objs.([]*rbacv1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			// apiGroups is [admissionregistration.k8s.io] for mutatingwebhookconfigurations/validatingwebhookconfigurations
			for _, rsc := range rule.GetResources() {
				if rscsToCheck.Contains(rsc) {
					if v, ok := r2v[rsc]; ok {
						r2v[rsc] = v.Union(verbs)
					} else {
						r2v[rsc] = verbs
					}
				}
			}
		}
	} else if rules, ok := objs.([]*rbacv1b1.PolicyRule); ok {
		for _, rule := range rules {
			verbs := utils.NewSetFromSliceKind(rule.GetVerbs())
			// apiGroups is [admissionregistration.k8s.io] for mutatingwebhookconfigurations/validatingwebhookconfigurations
			for _, rsc := range rule.GetResources() {
				if rscsToCheck.Contains(rsc) {
					if v, ok := r2v[rsc]; ok {
						r2v[rsc] = v.Union(verbs)
					} else {
						r2v[rsc] = verbs
					}
				}
			}
		}
	}
	errMsgMap := make(map[string]string)
	for rsc := range rscsToCheck.Iter() {
		rscString, _ := rsc.(string)
		if requiredVerbs, ok2 := nvRequiredRscVerbs[rscString]; ok2 {
			if verbs, ok := r2v[rscString]; ok {
				if requiredVerbs.Intersect(verbs).Cardinality() == requiredVerbs.Cardinality() || verbs.Contains("*") {
					continue
				}
			}
			errMsgMap[rscString] = fmt.Sprintf("Permissions %s are required", requiredVerbs.String())
		} else {
			errMsgMap[rscString] = fmt.Sprintf("No permission verb is defined")
		}
	}

	if len(errMsgMap) > 0 {
		var msg string
		for rsc, rscMsg := range errMsgMap {
			msg += fmt.Sprintf("%s for %s. ", rscMsg, rsc)
		}
		return fmt.Errorf(msg)
	} else {
		return nil
	}
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
		role.nvRole = deduceRoleRules(rules)

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
		role.nvRole = deduceRoleRules(rules)

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
		role.nvRole = deduceRoleRules(rules)

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
		role.nvRole = deduceRoleRules(rules)

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

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User":
				user := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
				roleBind.users = append(roleBind.users, user)
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

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User":
				user := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
				roleBind.users = append(roleBind.users, user)
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

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User":
				user := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
				roleBind.users = append(roleBind.users, user)
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

		for _, s := range subjects {
			switch subKind = s.GetKind(); subKind {
			case "User":
				user := k8sObjectRef{name: s.GetName(), domain: s.GetNamespace()}
				roleBind.users = append(roleBind.users, user)
			}
		}

		log.WithFields(log.Fields{"binding": roleBind}).Debug("v1beta1")
		return roleBind.uid, roleBind
	}

	return "", nil
}

func (d *kubernetes) cbResourceRole(rt string, event string, res interface{}, old interface{}) {
	d.rbacLock.Lock()
	defer d.rbacLock.Unlock()

	var n, o *k8sRole
	if event == WatchEventDelete {
		o = old.(*k8sRole)
		ref := k8sObjectRef{name: o.name, domain: o.domain}
		if nvRole, ok := d.roleCache[ref]; ok {
			delete(d.roleCache, ref)
			log.WithFields(log.Fields{"k8s-role": ref, "nv-role": nvRole}).Debug("Delete role")
			if ref.name == NvAdmCtrlRole {
				log.WithFields(log.Fields{"role": ref.name}).Warn("Critical role is deleted")
			}
		}
	} else {
		n = res.(*k8sRole)
		ref := k8sObjectRef{name: n.name, domain: n.domain}
		d.roleCache[ref] = n.nvRole
		log.WithFields(log.Fields{"k8s-role": ref, "nv-role": n.nvRole}).Debug("Update role")
		if ref.name == NvAdmCtrlRole {
			log.WithFields(log.Fields{"role": ref.name}).Info("Critical role found")
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
		if o.name == NvAdmCtrlRoleBinding && o.role.name == NvAdmCtrlRole {
			log.WithFields(log.Fields{"rolebinding": o.name, "role": o.role.name}).Warn("Critical rolebinding is deleted")
		}
		for _, u := range o.users {
			if roleRefs, ok := d.userCache[u]; ok && roleRefs.Contains(oldRoleRef) {
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"k8s-role": oldRoleRef, "user": u, "left": roleRefs}).Debug("Delete role binding")

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

		if n.name == NvAdmCtrlRoleBinding && n.role.name == NvAdmCtrlRole {
			log.WithFields(log.Fields{"rolebinding": n.name, "role": n.role.name}).Info("Critical rolebinding found")
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
			userRef := u.(k8sObjectRef)
			if roleRefs, ok := d.userCache[userRef]; ok && roleRefs.Contains(oldRoleRef) {
				roleRefs.Remove(oldRoleRef)
				log.WithFields(log.Fields{"k8s-role": oldRoleRef, "user": userRef, "left": roleRefs}).Debug("Delete role binding")

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
			userRef := u.(k8sObjectRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
				log.WithFields(log.Fields{"k8s-role": newRoleRef, "user": userRef}).Debug("Create user role binding")
			} else {
				roleRefs.Add(newRoleRef)
				log.WithFields(log.Fields{"k8s-role": newRoleRef, "user": userRef}).Debug("Add user role binding")
			}

			d.rbacEvaluateUser(userRef)
		}

		// 4. For users whose bindings are changed
		changes := newUsers.Difference(creates)
		for u := range changes.Iter() {
			userRef := u.(k8sObjectRef)
			if roleRefs, ok := d.userCache[userRef]; !ok {
				// create user
				d.userCache[userRef] = utils.NewSet(newRoleRef)
				log.WithFields(log.Fields{"k8s-role": newRoleRef, "user": userRef}).Debug("Create user role binding")
			} else if o.role != n.role {
				// o won't be nil when we get here
				roleRefs.Add(newRoleRef)
				log.WithFields(log.Fields{"k8s-role": newRoleRef, "user": userRef}).Debug("Add user role binding")
			}

			d.rbacEvaluateUser(userRef)
		}
	}
}

// Called with rbacLock
func (d *kubernetes) rbacEvaluateUser(user k8sObjectRef) {
	if roleRefs, ok := d.userCache[user]; !ok {
		if rbac, ok := d.rbacCache[user]; ok {
			delete(d.rbacCache, user)
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
		rbac := make(map[string]string)
		for r := range roleRefs.Iter() {
			roleRef := r.(k8sRoleRef)
			if newNVRole, ok := d.roleCache[roleRef.role]; ok {
				if oldNVRole, ok := rbac[roleRef.domain]; !ok {
					rbac[roleRef.domain] = newNVRole
				} else if oldNVRole == api.UserRoleReader && newNVRole == api.UserRoleAdmin {
					rbac[roleRef.domain] = newNVRole
				}
			}
		}

		if nvRole, ok := rbac[""]; ok {
			if nvRole == api.UserRoleAdmin {
				// If the user is cluster admin, then it is the admin of all namespaces
				rbac = map[string]string{"": api.UserRoleAdmin}
			} else if nvRole == api.UserRoleReader {
				// If the user is cluster reader, then it is the reader of all namespaces
				for domain, nvDomainRole := range rbac {
					if domain != "" && nvDomainRole == api.UserRoleReader {
						delete(rbac, domain)
					}
				}
			}
		}

		oldrbac, _ := d.rbacCache[user]
		d.rbacCache[user] = rbac

		// callback
		log.WithFields(log.Fields{"rbac": rbac, "oldrbac": oldrbac, "user": user}).Debug()
		if reflect.DeepEqual(oldrbac, rbac) {
			return
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

func (d *kubernetes) GetUserRoles(user string) (map[string]string, error) {
	userRef := k8sObjectRef{name: user, domain: ""}

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
