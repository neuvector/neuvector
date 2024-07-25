package resource

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/share/utils"
)

func preTestDebug() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.DebugLevel)
}

func preTest() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.FatalLevel)
}

func postTest() {
	log.SetLevel(log.DebugLevel)
}

func TestRBAC(t *testing.T) {
	preTest()

	d := Register(share.PlatformKubernetes, "", "").(*kubernetes)

	// Add an admin cluster role
	rt := K8sRscTypeClusRole
	r := &k8sRole{uid: "1", name: "edit", domain: "", nvRole: api.UserRoleAdmin}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Add an view cluster role
	rt = K8sRscTypeClusRole
	r = &k8sRole{uid: "2", name: "view", domain: "", nvRole: api.UserRoleReader}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Add an admin role in ns1
	rt = k8sRscTypeRole
	r = &k8sRole{uid: "3", name: "ns1-dev", domain: "ns1", nvRole: api.UserRoleAdmin}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Add a reader role in ns2
	rt = k8sRscTypeRole
	r = &k8sRole{uid: "4", name: "ns2-dev", domain: "ns2", nvRole: api.UserRoleAdmin}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}
	rt = k8sRscTypeRole
	r = &k8sRole{uid: "4", name: "ns2-audit", domain: "ns2", nvRole: api.UserRoleReader}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Create a binding between admin cluster role to 'mike'
	rt = K8sRscTypeClusRoleBinding
	rb := &k8sRoleBinding{
		uid: "11", name: "admin", domain: "", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "mike", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check mike is cluster admin
	rbac, _, _ := d.GetUserRoles("mike", SUBJECT_USER)
	expect := map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Update the role binding with more users - k8s won't create new object, same uid!
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "11", name: "admin", domain: "", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "mike", domain: "", subType: SUBJECT_USER},
			k8sSubjectObjRef{name: "jane", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check new role
	rbac, _, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Update the role binding with less users - k8s won't create new object, same uid!
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "11", name: "admin", domain: "", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "jane", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check jane is cluster admin
	rbac, _, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	// Test: check mike is gone
	rbac, _, _ = d.GetUserRoles("mike", SUBJECT_USER)
	if rbac != nil {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", nil)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	//->
	// Bind 'jane' to a reader cluster role - k8s rejects if binding name is same but role changes
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "12", name: "reader", domain: "", role: k8sObjectRef{name: "view", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "jane", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check jane is cluster admin
	rbac, _, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Bind 'jane' to a reader role in ns2
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "13", name: "ns2-reader", domain: "ns2", role: k8sObjectRef{name: "ns2-audit", domain: "ns2"},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "jane", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check jane is cluster admin
	rbac, _, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Bind 'gary' as cluster reader
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "14", name: "reader-gary", domain: "", role: k8sObjectRef{name: "view", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Bind 'gary' as ns1 admin with cluster role
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "15", name: "dev-gary", domain: "ns1", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check gary is cluster reader and ns1 admin
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Modify role binding for 'gary' from ns1 to ns2 - k8s will create a new binding if namespace is different
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "16", name: "dev-gary", domain: "ns2", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check gary is cluster reader and admin of ns1 and ns2
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin, "ns2": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Remove gary's admin role binding in ns2
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "16", name: "dev-gary", domain: "ns2", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.deleteResourceCache(rt, rb.uid); ev != "" {
		d.cbResourceRoleBinding(rt, ev, nil, old)
	}

	// Test: check gary is cluster reader and admin of ns1
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Bind 'gary' as ns2 admin with role
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "17", name: "ns2-dev-gary", domain: "ns2", role: k8sObjectRef{name: "ns2-dev", domain: "ns2"},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.updateResourceCache(rt, rb.uid, rb); ev != "" {
		d.cbResourceRoleBinding(rt, ev, rb, old)
	}

	// Test: check gary is cluster reader and ns1 and ns2 admin
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin, "ns2": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Change role that binds to gary from admin to reader
	rt = k8sRscTypeRole
	r = &k8sRole{uid: "3", name: "ns2-dev", domain: "ns2", nvRole: api.UserRoleReader}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Test: check gary is cluster reader, ns1 admin and ns2 reader (hidden)
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Change cluster role that binds to gary from admin to reader
	rt = k8sRscTypeRole
	r = &k8sRole{uid: "1", name: "edit", domain: "", nvRole: api.UserRoleReader}
	if ev, old := d.updateResourceCache(rt, r.uid, r); ev != "" {
		d.cbResourceRole(rt, ev, r, old)
	}

	// Test: check gary is cluster reader, ns1 reader (hidden) and ns2 reader (hidden)
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Remove gary's admin role binding in ns2
	rt = K8sRscTypeClusRoleBinding
	rb = &k8sRoleBinding{
		uid: "14", name: "reader-gary", domain: "", role: k8sObjectRef{name: "view", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.deleteResourceCache(rt, rb.uid); ev != "" {
		d.cbResourceRoleBinding(rt, ev, nil, old)
	}

	// Test: check gary is ns1 and ns2 reader
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": "", "ns1": api.UserRoleReader, "ns2": api.UserRoleReader}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	log.Debug("--")

	// Remove gary's role binding in ns1
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "15", name: "dev-gary", domain: "ns1", role: k8sObjectRef{name: "edit", domain: ""},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.deleteResourceCache(rt, rb.uid); ev != "" {
		d.cbResourceRoleBinding(rt, ev, nil, old)
	}

	// Remove gary's role binding in ns2
	rt = k8sRscTypeRoleBinding
	rb = &k8sRoleBinding{
		uid: "17", name: "ns2-dev-gary", domain: "ns2", role: k8sObjectRef{name: "ns2-dev", domain: "ns2"},
		users: []k8sSubjectObjRef{
			k8sSubjectObjRef{name: "gary", domain: "", subType: SUBJECT_USER},
		},
	}
	if ev, old := d.deleteResourceCache(rt, rb.uid); ev != "" {
		d.cbResourceRoleBinding(rt, ev, nil, old)
	}

	// Test: check gary is gone
	rbac, _, _ = d.GetUserRoles("gary", SUBJECT_USER)
	if rbac != nil {
		t.Errorf("Unexpected rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", nil)
		t.Logf("  Actual: %+v\n", rbac)
	}

	postTest()
}

type k8s_unittest struct {
	*kubernetes
}

type tRbacRancherSSO struct {
	t        *testing.T
	d        *k8s_unittest
	caseName string
	caseID   int
}

const (
	update_rbac = "update"
	delete_rbac = "delete"
)

func (d *k8s_unittest) GetResource(rt, namespace, name string) (interface{}, error) {
	switch rt {
	case RscTypeNamespace:
		if namespace == "" && name == "cattle-system" {
			return nil, nil
		}
	case RscTypeService:
		if namespace == "cattle-system" && name == "rancher" {
			return nil, nil
		}
	}
	return nil, ErrResourceNotSupported
}

func new_k8s_unittest() *k8s_unittest {
	return &k8s_unittest{
		kubernetes: &kubernetes{
			noop:             newNoopDriver(share.PlatformKubernetes, share.FlavorRancher, ""),
			watchers:         make(map[string]*resourceWatcher),
			userCache:        make(map[k8sSubjectObjRef]utils.Set),
			roleCache:        make(map[k8sObjectRef]string),
			rbacCache:        make(map[k8sSubjectObjRef]map[string]string),
			permitsCache:     make(map[k8sObjectRef]share.NvPermissions),
			permitsRbacCache: make(map[k8sSubjectObjRef]map[string]share.NvFedPermissions),
		},
	}
}

func register_k8s_unittest(platform, flavor, network string) orchAPI.ResourceDriver {
	return new_k8s_unittest()
}

func genGuid() types.UID {
	objUID, _ := utils.GetGuid()
	return types.UID(objUID)
}

func (r *tRbacRancherSSO) updateK8sRbacResource(obj interface{}, op string) {
	var ok bool
	var rt string
	var name string
	var objR *rbacv1.Role
	var objCR *rbacv1.ClusterRole
	var objRB *rbacv1.RoleBinding
	var objCRB *rbacv1.ClusterRoleBinding
	var id string
	var res interface{}

	if objR, ok = obj.(*rbacv1.Role); ok {
		rt = k8sRscTypeRole
		name = objR.Name
		id, res = xlateRole(objR)
	} else if objCR, ok = obj.(*rbacv1.ClusterRole); ok {
		rt = K8sRscTypeClusRole
		name = objCR.Name
		id, res = xlateClusRole(objCR)
	} else if objRB, ok = obj.(*rbacv1.RoleBinding); ok {
		rt = k8sRscTypeRoleBinding
		name = objRB.Name
		id, res = xlateRoleBinding(objRB)
	} else if objCRB, ok = obj.(*rbacv1.ClusterRoleBinding); ok {
		rt = K8sRscTypeClusRoleBinding
		name = objCRB.Name
		id, res = xlateClusRoleBinding(objCRB)
	} else {
		r.t.Errorf("[%d] invalid obj", r.caseID)
		return
	}

	if ok {
		if res == nil {
			r.t.Errorf("[%d] xlate %s(%s) failed", r.caseID, rt, name)
		} else {
			var ev string
			var old interface{}
			if op == update_rbac {
				ev, old = r.d.updateResourceCache(rt, id, res)
			} else {
				ev, old = r.d.deleteResourceCache(rt, id)
			}
			if ev != "" {
				switch rt {
				case k8sRscTypeRole, K8sRscTypeClusRole:
					r.d.cbResourceRole(rt, ev, res, old)
				case k8sRscTypeRoleBinding, K8sRscTypeClusRoleBinding:
					r.d.cbResourceRoleBinding(rt, ev, res, old)
				}
			} else {
				r.t.Errorf("[%d] empty event for %s(%s)", r.caseID, rt, name)
			}
		}
	} else {
		r.t.Errorf("[%d] type conversion(%s) failed", r.caseID, rt)
	}
}

func (r *tRbacRancherSSO) compareDomainPermits(scope, userName string, expectDomainPerms map[string]share.NvPermissions, actualDomainPerms map[string]share.NvFedPermissions) bool {

	// Test: check user's mapped permissions
	if len(expectDomainPerms) > 0 {
		for d, expectedPermits := range expectDomainPerms {
			var actualPermits share.NvPermissions
			if actual, ok := actualDomainPerms[d]; ok {
				if scope == "local" {
					actualPermits = actual.Local
				} else if scope == "remote" {
					actualPermits = actual.Remote
				}
			}
			if expectedPermits != actualPermits {
				r.t.Logf("<< %s >>\n", r.caseName)
				var dDisplay string
				if d == "" {
					dDisplay = "global domain"
				} else {
					dDisplay = fmt.Sprintf("domain %s", d)
				}
				r.t.Errorf("[%d] Unexpected %s permits rbac for user %s - cache: %+v", r.caseID, scope, userName, r.d.permitsRbacCache)
				r.t.Logf("[%d]   Expect: %s permits %+v for %s\n", r.caseID, scope, expectedPermits, dDisplay)
				r.t.Logf("[%d]   Actual: %s permits %+v for %s\n", r.caseID, scope, actualPermits, dDisplay)
				return false
			}
		}
	} else {
		for d, actual := range actualDomainPerms {
			var actualPermits share.NvPermissions
			if scope == "local" {
				actualPermits = actual.Local
			} else if scope == "remote" {
				actualPermits = actual.Remote
			}
			if !actualPermits.IsEmpty() {
				r.t.Logf("<< %s >>\n", r.caseName)
				var dDisplay string
				if d == "" {
					dDisplay = "global domain"
				} else {
					dDisplay = fmt.Sprintf("domain %s", d)
				}
				r.t.Errorf("[%d] Unexpected %s permits rbac for user %s - cache: %+v", r.caseID, scope, userName, r.d.permitsRbacCache)
				r.t.Logf("[%d]   Expect: %s permits %+v for %s\n", r.caseID, scope, share.NvPermissions{}, dDisplay)
				r.t.Logf("[%d]   Actual: %s permits %+v for %s\n", r.caseID, scope, actualPermits, dDisplay)
				return false
			}
		}
	}

	return true
}

func (r *tRbacRancherSSO) checkK8sUserRoles(userName string, expectDomainRoles map[string]string,
	expectLocalDomainPerms, expectRemoteDomainPerms map[string]share.NvPermissions) {

	// Test: check user's mapped role/permissions
	if thisDomainRoles, thisDomainPerms, err := r.d.GetUserRoles(userName, SUBJECT_USER); err == nil {
		if !reflect.DeepEqual(thisDomainRoles, expectDomainRoles) {
			r.t.Logf("<< %s >>\n", r.caseName)
			r.t.Errorf("[%d] Unexpected role rbac for user %s - cache: %+v", r.caseID, userName, r.d.rbacCache)
			r.t.Logf("[%d]   Expect: %+v\n", r.caseID, expectDomainRoles)
			r.t.Logf("[%d]   Actual: %+v\n", r.caseID, thisDomainRoles)
		}
		r.compareDomainPermits("local", userName, expectLocalDomainPerms, thisDomainPerms)
		r.compareDomainPermits("remote", userName, expectRemoteDomainPerms, thisDomainPerms)
	} else {
		r.t.Logf("<< %s >>\n", r.caseName)
		r.t.Errorf("[%d] Unexpected result - user %s not found: %s", r.caseID, userName, err)
	}
	r.caseID += 1
	log.WithFields(log.Fields{"caseID": r.caseID}).Debug("-------------------------------------------------------------------------------------------------------------------------------------")
}

func (r *tRbacRancherSSO) verifyNvRolePermits(actualDomainRoles, expectDomainRoles map[string]string,
	actualDomainPerms, expectDomainPerms map[string]share.NvFedPermissions) {

	for d, expectedRole := range expectDomainRoles {
		if actualRole, _ := actualDomainRoles[d]; expectedRole != actualRole {
			r.t.Logf("<< %s >>\n", r.caseName)
			var dDisplay string
			if d == "" {
				dDisplay = "global domain"
			} else {
				dDisplay = fmt.Sprintf("domain %s", d)
			}
			r.t.Errorf("[%d] Unexpected role for %s:", r.caseID, dDisplay)
			r.t.Logf("[%d]   Expect: role %s\n", r.caseID, expectedRole)
			r.t.Logf("[%d]   Actual: role %s\n", r.caseID, actualRole)
		}
	}
	for d, expectedPermits := range expectDomainPerms {
		if actualPermits, _ := actualDomainPerms[d]; expectedPermits != actualPermits {
			r.t.Logf("<< %s >>\n", r.caseName)
			var dDisplay string
			if d == "" {
				dDisplay = "global domain"
			} else {
				dDisplay = fmt.Sprintf("domain %s", d)
			}
			r.t.Errorf("[%d] Unexpected permits for %s:", r.caseID, dDisplay)
			r.t.Logf("[%d]   Expect: permits %+v\n", r.caseID, expectedPermits)
			r.t.Logf("[%d]   Actual: permits %+v\n", r.caseID, actualPermits)
		}
	}
	r.caseID += 1
	log.WithFields(log.Fields{"caseID": r.caseID}).Debug("-------------------------------------------------------------------------------------------------------------------------------------")
}

func TestRBACRancherSSO(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSO",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher global role)
		userName1 := "u-cpjv2-1"
		crName1 := "cattle-globalrole-gr-2mmkz-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cattle-globalrolebinding-grb-cxx5n-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL,
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
			}},
			nil,
		)

		//------ [2] add another nv custom permissions objCR2
		crName2 := "cattle-globalrole-gr-abcde-2"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"create", "delete"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"authentication"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "modify"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"authorization"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"auditevents"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create a objCRB2 between custom permissions objCR2 and user 'u-cpjv2' too
		objCRB2 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cattle-globalrolebinding-grb-abcde-2",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB2, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [3] objCR1 is updated to have global reader(fedReader) role in k8s.
		// Because objCR1(referenced by objCRB1) has nv write permission, global reader role is moved to PERMS_FED_READ permission
		objCR1.Rules = append(objCR1.Rules, rbacv1.PolicyRule{ // it's a fedReader role
			Verbs:     []string{"get"},
			APIGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedReader},
			map[string]share.NvPermissions{"": {
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [4] objCR1 is updated to have global admin role in k8s.
		// Because it's "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's treated as fed admin role
		objCR1.Rules = append(objCR1.Rules, rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			APIGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedAdmin},
			nil,
			nil,
		)

		//------ [5] delete objCRB1 in k8s. now only objCRB2 is for user 'u-cpjv2'
		rbacRancherSSO.updateK8sRbacResource(objCRB1, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [6] add back objCRB1 in k8s
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedAdmin},
			nil,
			nil,
		)

		//------ [7] delete objCR1 in k8s. now only objCRB2 is for user 'u-cpjv2'
		rbacRancherSSO.updateK8sRbacResource(objCR1, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [8] add back modified objCR1 in k8s
		objCR1 = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [9] add nv custom permissions objCR9(rancher cluster role)
		crName9 := "rt-wbz96-9"
		objCR9 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName9,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"create"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR9, update_rbac)

		// create a objCRB9 between custom permissions objCR9 and user 'u-cpjv2'.
		// because it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's not treated as fed admin role
		objCRB9 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName9,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB9, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleAdmin},
			nil,
			nil,
		)

		//------ [10] delete objCR9 in k8s
		rbacRancherSSO.updateK8sRbacResource(objCR9, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [11] delete objCRB9 in k8s
		rbacRancherSSO.updateK8sRbacResource(objCRB9, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [12] add back objCR9 in k8s
		rbacRancherSSO.updateK8sRbacResource(objCR9, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
			}},
			nil,
		)

		//------ [13] add objCRB13 but it binds to different user "u-abcef-2" in k8s
		userName2 := "u-abcef-2"
		objCRB13 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-1234567890-13",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName2,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName9,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB13, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
				WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
			}},
			nil,
		)
		rbacRancherSSO.updateK8sRbacResource(objCRB13, delete_rbac)

		//------ [14] add objCR14/objRB14 (ns: test-project-ns-14) in k8s
		crName14 := "rt-gphqk-14"
		objCR14 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName14,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"admissioncontrol"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"securityevents"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"compliance"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR14, update_rbac)

		// add objRB14 which binds objCR14 to userName1 for namespace test-project-ns-14 in k8s
		objRB14 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-77ttz6nyye-14",
				Namespace: "test-project-ns-14",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName14,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB14, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
			},
			nil,
		)

		//------ [15] add objCR15/objRB15 (ns: test-project-ns-15) for userName1 in k8s
		crName15 := "rt-abcde-15"
		objCR15 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName15,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"*"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"compliance"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR15, update_rbac)

		// add rolebinding objRB15 which binds objCR15 to userName1 for namespace test-project-ns-15 in k8s
		objRB15 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-15",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName15,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB15, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"":                   api.UserRoleNone,
				"test-project-ns-15": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
			},
			nil,
		)

		//------ [16] add objCR16/objRB16 (ns: test-project-ns-15) for userName1 in k8s
		crName16 := "rt-abcde-16"
		objCR16 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName16,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"neuvectorvulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"events"}, // supported in global & domain
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR16, update_rbac)

		// add objRB16 which binds objCR16 to userName1 for namespace test-project-ns-15 in k8s.
		// because userName1 is already admin for namespace test-project-ns-15, this binding doesn't affect anything
		objRB16 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-16",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName16,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB16, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"":                   api.UserRoleNone,
				"test-project-ns-15": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
			},
			nil,
		)

		//------ [17] delete objCR15 for userName1 (ns: test-project-ns-15) in k8s in k8s
		rbacRancherSSO.updateK8sRbacResource(objCR15, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
				"test-project-ns-15": {
					ReadValue:  share.PERM_EVENTS,
					WriteValue: 0,
				},
			},
			nil,
		)

		//------ [18] add back objCR15 for userName1 (ns: test-project-ns-15) in k8s in k8s
		rbacRancherSSO.updateK8sRbacResource(objCR15, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"":                   api.UserRoleNone,
				"test-project-ns-15": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
			},
			nil,
		)

		//------ [19] delete objRB15 for userName1 (ns: test-project-ns-15) in k8s in k8s
		rbacRancherSSO.updateK8sRbacResource(objRB15, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION | share.PERM_AUDIT_EVENTS,
					WriteValue: share.PERM_REG_SCAN | share.PERM_AUTHORIZATION,
				},
				"test-project-ns-14": {
					ReadValue:  (share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERMS_SECURITY_EVENTS | share.PERMS_COMPLIANCE) & share.PERMS_DOMAIN_READ,
					WriteValue: share.PERMS_COMPLIANCE & share.PERMS_DOMAIN_WRITE,
				},
				"test-project-ns-15": {
					ReadValue:  share.PERM_EVENTS,
					WriteValue: 0,
				},
			},
			nil,
		)
	}

	postTest()
}

func TestRBACRancherSSOFedAdminReader(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOFedAdminReader",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := "u-cpjv2-1"
		crName1 := "cattle-globalrole-gr-2mmkz-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"}, // it's a fedReader role
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cattle-globalrolebinding-grb-cxx5n-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedReader},
			map[string]share.NvPermissions{"": {
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
			}},
			nil,
		)

		//------ [2] objCR1 is updated(append) to have nv admin role on global domain
		objCR1.Rules = append(objCR1.Rules, rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			APIGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedAdmin, // because it's "cattle-globalrole-gr-xxxxxxx" k8s clusterrole
			},
			nil,
			nil,
		)

		//------ [3] add another nv custom permissions objCR2(rancher cluster role) that maps to nv admin role
		crName2 := "rt-wbz96-9"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create a objCRB2 between custom permissions objCR2 and the same user "u-cpjv2-1"
		// because it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's treated as nv admin role.
		// but because user "u-cpjv2-1" is already mapped to fedAdmin role, objCRB2 doesn't affect anything.
		objCRB2 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB2, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedAdmin,
			},
			nil,
			nil,
		)

		//------ [4] delete objCRB1(nv fedAdmin role on global domain) in k8s. now only objCRB2(nv admin role on global domain) is for user 'u-cpjv2-1'
		rbacRancherSSO.updateK8sRbacResource(objCRB1, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			nil,
			nil,
		)

		//------ [5] add crName3/objRB3 (ns: test-project-ns-15) for userName1 in k8s
		crName3 := "rt-abcde-3"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"neuvectorvulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"events"}, // supported in global & domain
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		objRB3 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-16",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB3, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			nil,
			nil,
		)

		//------ [6] delete objCRB2(nv admin role on global domain) in k8s and reset objCR1/objCRB1 ti without "get/*" rule in objCR1
		// now there is no reserved role mapped for objCR1
		objCR1 = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB2, delete_rbac)
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{ // no permission from objCR1 because objCRB1 was deleted in step 4...
				"test-project-ns-15": {
					ReadValue: share.PERM_EVENTS, // PERM_VULNERABILITY is not supported in non-global domain
				},
			},
			nil,
		)

		//------ [7] add objCRB1 back for user "u-cpjv2-1"
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL,
					WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
				},
				"test-project-ns-15": {
					ReadValue: share.PERM_EVENTS, // PERM_VULNERABILITY is not supported in non-global domain
				},
			},
			nil,
		)
	}

	postTest()
}

// for testing "admin permission on local cluster" + "reader permission on all managed clusters(i.e. fedReader)" in Rancher Cluster Role case
func TestRBACRancherSSOMixedClusterRole(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOMixedClusterRole",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher cluster role) on global domain
		userName1 := "u-william-1"
		crName1 := "rt-abc11-9"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create objCRB1 between custom permissions objCR1 and user "u-william-1"
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-abc11-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERM_REG_SCAN | share.PERM_ADM_CONTROL,
			}},
			nil,
		)

		//------ [2] add 2nd rancher cluster role that has fedReader role on global domain
		crName2 := "rt-abc12-9"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"federation"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create objCRB2 between custom permissions objCR2 and user "u-william-1"
		objCRB2 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-abc12-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB2, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedReader,
			},
			nil,
			nil,
		)

		//------ [3] add 3rd rancher cluster role that has write permission on global domain
		// it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole & user "u-william-1" is mapped to fedReader role + some write permision
		// fedReader role is moved to permissions because there is write permission
		crName3 := "rt-abc13-9"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		// create objCRB3 between custom permissions objCR3 and user "u-william-1"
		objCRB3 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-abc13-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB3, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedReader,
			},
			map[string]share.NvPermissions{"": {
				WriteValue: share.PERM_CICD_SCAN,
			}},
			nil,
		)

		//------ [4] add 4th rancher cluster role that has admin role on global domain
		// it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole & user "u-william-1" is mapped to fedReader role + admin role + some write permision
		// global domain is "admin" & PERMS_FED_READ permission(not fedReader role) is moved to permissions
		crName4 := "rt-abc14-9"
		objCR4 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName4,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR4, update_rbac)

		// create a objCRB4 between custom permissions objCR4 and the same user "u-william-1"
		objCRB4 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-abc14-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName4,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB4, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERMS_FED_READ,
			}},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERMS_CLUSTER_READ,
			}},
		)

		//------ [5] add 5th rancher cluster role that has fedAdmin role on global domain
		crName5 := "rt-abc15-9"
		objCR5 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName5,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR5, update_rbac)

		// create a objCRB4 between custom permissions objCR4 and the same user "u-william-1"
		objCRB5 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-abc15-9",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName5,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB5, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedAdmin,
			},
			nil,
			nil,
		)

		//------ [6] delete k8s cluster role binding objCRB5 that maps fedAdmin role on global domain.
		// then global domain is "admin" & PERMS_FED_READ permission(from objCR2/objCRB2)
		rbacRancherSSO.updateK8sRbacResource(objCRB5, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERMS_FED_READ,
			}},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERMS_CLUSTER_READ,
			}},
		)

		//------ [7] delete k8s cluster role objCR3 that maps ci_scan permission(w) & objCRB4 that maps admin role on global domain.
		// there is no write permission mapping for the user anymore
		// so the global domain is "fedReader"
		rbacRancherSSO.updateK8sRbacResource(objCR3, delete_rbac)
		rbacRancherSSO.updateK8sRbacResource(objCRB4, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedReader,
			},
			nil,
			nil,
		)
	}

	postTest()
}

func TestRBACRancherSSOAdmin(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOAdmin",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := "u-cpjv2-1"
		crName1 := "rt-wbz96-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		crName2 := "rt-abcde-2"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-16",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB2, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL,
					WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
				},
				"test-project-ns-15": {
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
			},
			nil,
		)
	}

	postTest()
}

func TestRBACRancherSSOProjectRoles(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOProjectRoles",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher project role)
		userName1 := "u-cpjw2-1"
		crName1 := "rt-abcdef-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objRB1 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-11",
				Namespace: "nv-1",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB1, update_rbac)

		//------ add nv custom permissions objCR2(rancher project role) that has different permissions from objCR1
		crName2 := "rt-abcdef-2"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-12",
				Namespace: "nv-2",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB2, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"nv-1": {
					ReadValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
				"nv-2": {
					ReadValue: share.PERMS_RUNTIME_POLICIES,
				},
			},
			nil,
		)
	}

	postTest()
}

// Rancher doesn't leverage k8s Role. This test case is just for NV's testing assuming Rancher leverages k8s Role for namespaced role
func TestRBACRancherSSOK8srole(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOK8srole",
		caseID:   1,
	}
	crKind := "ClusterRole"
	rKind := "Role"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := "u-cpjv2-1"
		crName1 := "rt-wbz96-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		rName2 := "rt-abcde-2"
		objR2 := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rName2,
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-2",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     rKind, // k8s doesn't allow a crb binds a role to subject
				Name:     rName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB2, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERM_ADM_CONTROL,
					WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
				},
				"test-project-ns-15": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
			},
			nil,
		)

		//------ [2] delete objCR1 and then create another objR3/objRB3 for the same user "u-cpjv2-1" on the same "test-project-ns-15" namespace
		// now only objR2/objRB2 & objR3/objRB3 are for user "u-cpjv2-1" on "test-project-ns-15" namespace
		rbacRancherSSO.updateK8sRbacResource(objCR1, delete_rbac)
		rName3 := "rt-abcde-3"
		objR3 := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rName3,
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimescan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR3, update_rbac)

		objRB3 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-3",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     rKind, // k8s doesn't allow a crb binds a role to subject
				Name:     rName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB3, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"test-project-ns-15": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERMS_RUNTIME_SCAN,
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
			},
			nil,
		)

		//------ [3] create another objR4/objRB4 for the same user "u-cpjv2-1" on different namespace
		rName4 := "rt-abcde-4"
		objR4 := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rName4,
				Namespace: "test-project-ns-21",
				UID:       genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"runtimescan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR4, update_rbac)

		objRB4 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-4",
				Namespace: "test-project-ns-21",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     rKind, // k8s doesn't allow a crb binds a role to subject
				Name:     rName4,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB4, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{
				"test-project-ns-15": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERMS_RUNTIME_SCAN,
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
				"test-project-ns-21": {
					ReadValue:  (share.PERM_RUNTIME_SCAN_BASIC | share.PERM_WORKLOAD_BASIC | share.PERM_INFRA_BASIC) & share.PERMS_DOMAIN_READ,
					WriteValue: (share.PERM_RUNTIME_SCAN_BASIC | share.PERM_WORKLOAD_BASIC | share.PERM_INFRA_BASIC) & share.PERMS_DOMAIN_WRITE,
				},
			},
			nil,
		)
	}

	postTest()
}

func removeRedundant(domainRole map[string]string, domainPermits map[string]share.NvFedPermissions, fedRole string) (
	map[string]string, map[string]share.NvFedPermissions) {

	allDomainRoles := make(map[string]share.NvReservedUserRole, len(domainRole))
	reservedRoleMapping := map[string]share.NvReservedUserRole{
		api.UserRoleAdmin:     share.UserRoleAdmin,
		api.UserRoleReader:    share.UserRoleReader,
		api.UserRoleFedAdmin:  share.UserRoleFedAdmin,
		api.UserRoleFedReader: share.UserRoleFedReader,
	}

	for d, role := range domainRole {
		m := reservedRoleMapping[role]
		allDomainRoles[d] = allDomainRoles[d] | m
	}

	return RemoveRedundant(allDomainRoles, domainPermits, fedRole)
}

func TestConsolidateNvRolePermits(t *testing.T) {
	preTest()

	//_k8sFlavor = share.FlavorRancher
	//global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	//IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestConsolidateNvRolePermits",
		caseID:   1,
	}

	{
		//------ [1]
		domainRole := map[string]string{
			"":         api.UserRoleFedAdmin,
			"domain-1": api.UserRoleFedAdmin,
			"domain-2": api.UserRoleFedReader,
			"domain-3": api.UserRoleAdmin,
			"domain-4": api.UserRoleReader,
		}
		domainPermits := map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
		}
		expectDomainRoles := map[string]string{
			"": api.UserRoleFedAdmin,
		}
		expectDomainPerms := map[string]share.NvFedPermissions{}
		// only "":fedAdmin is kept
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

		//------ [2]
		domainRole["domain-1"] = api.UserRoleFedAdmin
		domainRole["domain-2"] = api.UserRoleFedReader
		domainRole["domain-3"] = api.UserRoleAdmin
		domainPermits["domain-11"] = share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_FED_READ},
			Remote: share.NvPermissions{ReadValue: share.PERMS_FED_READ},
		}
		// only "":fedAdmin is kept
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

		//------ [3]
		domainRole = map[string]string{
			"":         api.UserRoleAdmin,
			"domain-1": api.UserRoleFedReader,
			"domain-2": api.UserRoleAdmin,
			"domain-3": api.UserRoleReader,
			"domain-4": api.UserRoleFedAdmin,
		}
		domainPermits = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_FED_READ},
				Remote: share.NvPermissions{ReadValue: share.PERMS_FED_READ},
			},
			"domain-12": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_CLUSTER_READ},
				Remote: share.NvPermissions{ReadValue: share.PERMS_CLUSTER_WRITE},
			},
			"domain-13": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_DOMAIN_WRITE},
				Remote: share.NvPermissions{ReadValue: share.PERMS_CLUSTER_WRITE},
			},
		}

		expectDomainRoles = map[string]string{
			"": api.UserRoleAdmin,
		}
		expectDomainPerms = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
		}
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

		//------ [4]
		domainRole = map[string]string{
			"":         api.UserRoleFedReader,
			"domain-1": api.UserRoleFedReader,
			"domain-2": api.UserRoleAdmin,
			"domain-3": api.UserRoleReader,
			"domain-4": api.UserRoleFedAdmin,
		}
		domainPermits = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
		}

		expectDomainRoles = map[string]string{
			"":         api.UserRoleFedReader,
			"domain-2": api.UserRoleAdmin,
			"domain-4": api.UserRoleAdmin,
		}
		expectDomainPerms = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": share.NvFedPermissions{
				Local: share.NvPermissions{WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
			},
		}
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

		//------ [5]
		domainRole = map[string]string{
			"":         api.UserRoleReader,
			"domain-1": api.UserRoleFedReader,
			"domain-2": api.UserRoleAdmin,
			"domain-3": api.UserRoleReader,
			"domain-4": api.UserRoleFedAdmin,
		}
		domainPermits = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
		}

		expectDomainRoles = map[string]string{
			"":         api.UserRoleReader,
			"domain-2": api.UserRoleAdmin,
			"domain-4": api.UserRoleAdmin,
		}
		expectDomainPerms = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": share.NvFedPermissions{
				Local: share.NvPermissions{WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
			},
		}
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

		//------ [6]
		domainRole = map[string]string{
			"":         api.UserRoleNone,
			"domain-1": api.UserRoleFedReader,
			"domain-2": api.UserRoleAdmin,
			"domain-3": api.UserRoleReader,
			"domain-4": api.UserRoleFedAdmin,
		}
		domainPermits = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
		}

		expectDomainRoles = map[string]string{
			"":         api.UserRoleNone,
			"domain-2": api.UserRoleAdmin,
			"domain-4": api.UserRoleAdmin,
		}
		expectDomainPerms = map[string]share.NvFedPermissions{
			"": share.NvFedPermissions{
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": share.NvFedPermissions{
				Local: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
			},
		}
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)
	}

	postTest()
}

func TestRancherMultiplePrinciples(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRancherMultiplePrinciples",
		caseID:   1,
	}

	//------ [1]
	allDomainRoles := map[string]share.NvReservedUserRole{
		"":         share.UserRoleFedAdmin | share.UserRoleAdmin | share.UserRoleFedReader | share.UserRoleReader,
		"domain-1": share.UserRoleAdmin | share.UserRoleReader,
		"domain-2": share.UserRoleFedReader | share.UserRoleReader,
		"domain-3": share.UserRoleAdmin,
		"domain-4": share.UserRoleReader,
		"domain-5": 0,
	}
	domainPermits := map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles := map[string]string{
		"": api.UserRoleFedAdmin,
	}
	expectDomainPerms := map[string]share.NvFedPermissions{}

	domainRole, domainPermits := RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleMaster)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [2]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"":         share.UserRoleFedAdmin | share.UserRoleAdmin | share.UserRoleFedReader | share.UserRoleReader,
		"domain-1": share.UserRoleAdmin | share.UserRoleReader,
		"domain-2": share.UserRoleFedReader | share.UserRoleReader,
		"domain-3": share.UserRoleAdmin,
		"domain-4": share.UserRoleReader,
		"domain-5": 0,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleAdmin,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleJoint)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [3]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": share.UserRoleAdmin | share.UserRoleFedReader | share.UserRoleReader,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleAdmin,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_FED_READ, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_CLUSTER_READ, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleMaster)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [4]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": share.UserRoleAdmin | share.UserRoleFedReader | share.UserRoleReader,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleAdmin,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleJoint)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [5]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": share.UserRoleFedReader | share.UserRoleReader,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleFedReader,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": share.NvFedPermissions{
			Local: share.NvPermissions{WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleMaster)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [6]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": share.UserRoleFedReader | share.UserRoleReader,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleReader,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": share.NvFedPermissions{
			Local: share.NvPermissions{WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleJoint)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [7]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": 0,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleNone,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": share.NvFedPermissions{
			Local: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleMaster)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	//------ [8]
	allDomainRoles = map[string]share.NvReservedUserRole{
		"": 0,
	}
	domainPermits = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": share.NvFedPermissions{
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleNone,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": share.NvFedPermissions{
			Local: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": share.NvFedPermissions{
			Local: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleJoint)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	postTest()
}

func TestRBACRancherSSOFedPermit(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOFedPermit",
		caseID:   1,
	}
	crKind := "ClusterRole"
	userKind := "User"
	rbacApiGroup := "rbac.authorization.k8s.io"

	{
		//------ [1] add nv custom permissions objCR1(rancher cluster role) that has fed & some write permissions
		userName1 := "u-cpjv2-1"
		crName1 := "rt-wbz96-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2-1'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB2 which binds objCR2 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because fed permission is not supported for namespaces yet, "federation" is ignored in objCR2
		crName2 := "rt-abcde-2"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-16",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB2, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-25 in k8s.
		// because fed permission is not supported for namespaces yet, "federation" is ignored in objCR3
		// get/cluster means domain reader for namespace test-project-ns-25
		crName3 := "rt-abcde-3"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"cluster"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		objRB3 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-36",
				Namespace: "test-project-ns-25",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB3, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"":                   "",
				"test-project-ns-25": api.UserRoleReader,
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL | share.PERM_FED,
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
				},
				"test-project-ns-15": {
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				},
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_ADM_CONTROL,
				},
			},
		)
	}

	{
		//------ [2] add nv custom permissions objCR1(rancher cluster role) that has fed & some write permissions
		userName1 := "u-cpjv2-12"
		crName1 := "rt-wbz96-1"
		objCR1 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName1,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"}, // "federation" in the next rule also applies to this rule; but "*" verbs in the next rule doesn't affect this rule
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2-1'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-1",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB2 which binds objCR2 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because fed permission is not supported for namespaces yet, "federation" is ignored in objCR2
		crName2 := "rt-abcde-2"
		objCR2 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName2,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"events"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"auditevents"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"*"},
					Resources: []string{"securityevents"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"ciscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"admissioncontrol"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-16",
				Namespace: "test-project-ns-15",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName2,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB2, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-25 in k8s.
		// because fed permission is not supported for namespaces yet, "federation" is ignored in objCR3
		// get/cluster means domain reader for namespace test-project-ns-25
		crName3 := "rt-abcde-3"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"neuvector.api.io"}, // not supported
					Resources: []string{"compliance", "cluster", "*"},
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"neuvectorcluster"}, // not supported for namespaces
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"nvauthentication"}, // not supported for namespaces
				},
				{
					Verbs:     []string{"*", "create", "delete", "get", "list", "patch", "update", "watch", "post"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"authorization"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "post"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"systemconfig"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		objRB3 := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rb-bcdefghij-36",
				Namespace: "test-project-ns-25",
				UID:       genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB3, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": "",
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED,
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED,
				},
				"test-project-ns-15": {
					ReadValue: share.PERM_EVENTS | share.PERMS_SECURITY_EVENTS | share.PERM_AUDIT_EVENTS,
				},
				"test-project-ns-25": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHORIZATION | share.PERM_SYSTEM_CONFIG,
					WriteValue: share.PERM_AUTHORIZATION,
				},
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
					WriteValue: share.PERMS_RUNTIME_POLICIES,
				},
			},
		)
	}

	{
		//------ [3] about "federation" for global domain
		userName31 := "u-cpjv2-31"
		crName31 := "rt-wbz96-31"
		objCR31 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName31,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"registryscan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"runtimepolicy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"neuvector.api.io", "*"}, // unsupported apiGroup
					Resources: []string{"compliance"},
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"authentication"},
				},
				{
					Verbs:     []string{"get", "post"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"authorization"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"systemconfig"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR31, update_rbac)

		// create a objCRB31 between custom permissions objCR1 and user 'u-cpjv2-31'
		objCRB31 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-31",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName31,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName31,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB31, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName31,
			map[string]string{
				"": "",
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION | share.PERM_AUTHORIZATION | share.PERM_SYSTEM_CONFIG | share.PERM_FED,
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION | share.PERM_FED,
				},
			},
			map[string]share.NvPermissions{
				"": {
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION | share.PERM_AUTHORIZATION | share.PERM_SYSTEM_CONFIG,
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION,
				},
			},
		)

		//------ [4]
		objCR31.Rules[0].Resources = []string{"cluster"}
		rbacRancherSSO.updateK8sRbacResource(objCR31, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName31,
			map[string]string{
				"": api.UserRoleFedReader,
			},
			map[string]share.NvPermissions{
				"": {
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION | share.PERM_FED,
				},
			},
			map[string]share.NvPermissions{
				"": {
					WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_AUTHENTICATION,
				},
			},
		)

		//------ [5]
		objCR31.Rules[0].Verbs = []string{"*"}
		objCR31.Rules[len(objCR31.Rules)-1].Verbs = []string{"*"}

		rbacRancherSSO.updateK8sRbacResource(objCR31, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName31,
			map[string]string{
				"": api.UserRoleFedAdmin,
			},
			nil,
			nil,
		)
	}

	{
		//------ [6] about "federation" for global domain
		userName61 := "u-cpjv2-61"
		crName61 := "rt-wbz96-61"
		objCR61 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName61,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"permission.neuvector.com"},
					Resources: []string{"federation"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR61, update_rbac)

		// create a objCRB61 between custom permissions objCR1 and user 'u-cpjv2-61'
		objCRB61 := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "crb-w3pkgod7le-61",
				UID:  genGuid(),
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     userKind,
					APIGroup: rbacApiGroup,
					Name:     userName61,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName61,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB61, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName61,
			map[string]string{
				"": api.UserRoleFedReader,
			},
			map[string]share.NvPermissions{"": {
				WriteValue: share.PERM_FED,
			}},
			nil,
		)

		//------ [7]
		objCR61.Rules = []rbacv1.PolicyRule{
			{
				Verbs:     []string{"*"},
				APIGroups: []string{"permission.neuvector.com"},
				Resources: []string{"*"},
			},
			{
				Verbs:     []string{"get"},
				APIGroups: []string{"permission.neuvector.com"},
				Resources: []string{"federation"},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR61, update_rbac)

		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName61,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERM_FED,
			}},
			nil,
		)
	}

}
