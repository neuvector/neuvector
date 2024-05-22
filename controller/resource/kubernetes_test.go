package resource

import (
	"os"
	"reflect"
	"testing"

	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	rbacv1 "github.com/neuvector/k8s/apis/rbac/v1"
	log "github.com/sirupsen/logrus"
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
			permitsRbacCache: make(map[k8sSubjectObjRef]map[string]share.NvPermissions),
		},
	}
}

func register_k8s_unittest(platform, flavor, network string) orchAPI.ResourceDriver {
	return new_k8s_unittest()
}

func genGuid() *string {
	objUID, _ := utils.GetGuid()
	id := string(types.UID(objUID))
	return &id
}

func getStringPtr(str string) *string {
	s := str
	return &s
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
		name = objR.Metadata.GetName()
		id, res = xlateRole(objR)
	} else if objCR, ok = obj.(*rbacv1.ClusterRole); ok {
		rt = K8sRscTypeClusRole
		name = objCR.Metadata.GetName()
		id, res = xlateClusRole(objCR)
	} else if objRB, ok = obj.(*rbacv1.RoleBinding); ok {
		rt = k8sRscTypeRoleBinding
		name = objRB.Metadata.GetName()
		id, res = xlateRoleBinding(objRB)
	} else if objCRB, ok = obj.(*rbacv1.ClusterRoleBinding); ok {
		rt = K8sRscTypeClusRoleBinding
		name = objCRB.Metadata.GetName()
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

func (r *tRbacRancherSSO) checkK8sUserRoles(pUserName *string, expectDomainRoles map[string]string, expectDomainPerms map[string]share.NvPermissions) {

	userName := *pUserName
	// Test: check user's mapped role/permissions
	if thisDomainRoles, thisDomainPerms, err := r.d.GetUserRoles(userName, SUBJECT_USER); err == nil {
		if !reflect.DeepEqual(thisDomainRoles, expectDomainRoles) {
			r.t.Logf("[ %s ]\n", r.caseName)
			r.t.Errorf("[%d] Unexpected role rbac - cache: %+v", r.caseID, r.d.rbacCache)
			r.t.Logf("[%d]   Expect: %+v\n", r.caseID, expectDomainRoles)
			r.t.Logf("[%d]   Actual: %+v\n", r.caseID, thisDomainRoles)
		}
		if !reflect.DeepEqual(thisDomainPerms, expectDomainPerms) {
			r.t.Logf("[ %s ]\n", r.caseName)
			r.t.Errorf("[%d] Unexpected perms rbac - cache: %+v", r.caseID, r.d.rbacCache)
			r.t.Logf("[%d]   Expect: %+v\n", r.caseID, expectDomainPerms)
			r.t.Logf("[%d]   Actual: %+v\n", r.caseID, thisDomainPerms)
		}
	} else if expectDomainRoles == nil && expectDomainPerms == nil {
		// User not found. expected error
	} else {
		r.t.Logf("[ %s ]\n", r.caseName)
		r.t.Errorf("[%d] Unexpected result - user %s not found: %s", r.caseID, userName, err)
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
	crKind := getStringPtr("ClusterRole")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher global role)
		userName1 := getStringPtr("u-cpjv2-1")
		crName1 := getStringPtr("cattle-globalrole-gr-2mmkz-1")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("cattle-globalrolebinding-grb-cxx5n-1"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [2] add another nv custom permissions objCR2
		crName2 := getStringPtr("cattle-globalrole-gr-abcde-2")
		objCR2 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName2,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"create", "delete"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.authentication"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "modify"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.authorization"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.audit-events"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create a objCRB2 between custom permissions objCR2 and user 'u-cpjv2' too
		objCRB2 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("cattle-globalrolebinding-grb-abcde-2"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [3] objCR1 is updated to have global reader role in k8s.
		// Because objCR1(referenced by objCRB1) has nv write permission, global reader role is moved to PERM_FED permission
		objCR1.Rules = append(objCR1.Rules, &rbacv1.PolicyRule{
			Verbs:     []string{"get"},
			ApiGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERMS_CLUSTER_READ | share.PERM_FED,
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL | share.PERM_AUTHORIZATION,
			}},
		)

		//------ [4] objCR1 is updated to have global admin role in k8s.
		// Because it's "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's treated as fed admin role
		objCR1.Rules = append(objCR1.Rules, &rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			ApiGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedAdmin},
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
		)

		//------ [6] add back objCRB1 in k8s
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleFedAdmin},
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
		)

		//------ [8] add back modified objCR1 in k8s
		objCR1 = &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
		)

		//------ [9] add nv custom permissions objCR9(rancher cluster role)
		crName9 := getStringPtr("rt-wbz96-9")
		objCR9 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName9,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"create"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR9, update_rbac)

		// create a objCRB9 between custom permissions objCR9 and user 'u-cpjv2'.
		// because it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's not treated as fed admin role
		objCRB9 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-w3pkgod7le-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName9,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB9, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": api.UserRoleAdmin},
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
		)

		//------ [13] add objCRB13 but it binds to different user "u-abcef-2" in k8s
		userName2 := getStringPtr("u-abcef-2")
		objCRB13 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-1234567890-13"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName2,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)
		rbacRancherSSO.updateK8sRbacResource(objCRB13, delete_rbac)

		//------ [14] add objCR14/objRB14 (ns: test-project-ns-14) in k8s
		crName14 := getStringPtr("rt-gphqk-14")
		objCR14 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName14,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.security-events"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.compliance"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR14, update_rbac)

		// add objRB14 which binds objCR14 to userName1 for namespace test-project-ns-14 in k8s
		objRB14 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-77ttz6nyye-14"),
				Namespace: getStringPtr("test-project-ns-14"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [15] add objCR15/objRB15 (ns: test-project-ns-15) for userName1 in k8s
		crName15 := getStringPtr("rt-abcde-15")
		objCR15 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName15,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"*"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.compliance"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR15, update_rbac)

		// add rolebinding objRB15 which binds objCR15 to userName1 for namespace test-project-ns-15 in k8s
		objRB15 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-15"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [16] add objCR16/objRB16 (ns: test-project-ns-15) for userName1 in k8s
		crName16 := getStringPtr("rt-abcde-16")
		objCR16 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName16,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.vulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.events"}, // supported in global & domain
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR16, update_rbac)

		// add objRB16 which binds objCR16 to userName1 for namespace test-project-ns-15 in k8s.
		// because userName1 is already admin for namespace test-project-ns-15, this binding doesn't affect anything
		objRB16 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-16"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
	crKind := getStringPtr("ClusterRole")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := getStringPtr("u-cpjv2-1")
		crName1 := getStringPtr("cattle-globalrole-gr-2mmkz-1")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("cattle-globalrolebinding-grb-cxx5n-1"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""}, // because it has write permissions, fedReader role on global domain is converted to fed read permission on global domain
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERMS_FED_READ,
				WriteValue: share.PERM_CICD_SCAN | share.PERM_ADM_CONTROL,
			}},
		)

		//------ [2] objCR1 is updated(append) to have nv admin role on global domain
		objCR1.Rules = append(objCR1.Rules, &rbacv1.PolicyRule{
			Verbs:     []string{"*"},
			ApiGroups: []string{"read-only.neuvector.api.io"},
			Resources: []string{"*"},
		})
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleFedAdmin, // because it's "cattle-globalrole-gr-xxxxxxx" k8s clusterrole
			},
			nil,
		)

		//------ [3] add another nv custom permissions objCR2(rancher cluster role) that maps to nv admin role
		crName2 := getStringPtr("rt-wbz96-9")
		objCR2 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName2,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create a objCRB2 between custom permissions objCR2 and the same user "u-cpjv2-1"
		// because it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole, it's treated as nv admin role.
		// but because user "u-cpjv2-1" is already mapped to fedAdmin role, objCRB2 doesn't affect anything.
		objCRB2 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-w3pkgod7le"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [4] delete objCRB1(nv fedAdmin role on global domain) in k8s. now only objCRB2(nv admin role on global domain) is for user 'u-cpjv2-1'
		rbacRancherSSO.updateK8sRbacResource(objCRB1, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			nil,
		)

		//------ [5] add crName3/objRB3 (ns: test-project-ns-15) for userName1 in k8s
		crName3 := getStringPtr("rt-abcde-3")
		objCR3 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName3,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.vulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.events"}, // supported in global & domain
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		objRB3 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-16"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [6] delete objCRB2(nv admin role on global domain) in k8s and reset objCR1/objCRB1 ti without "get/*" rule in objCR1
		// now there is no reserved role mapped for objCR1
		objCR1 = &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
	crKind := getStringPtr("ClusterRole")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher cluster role) on global domain
		userName1 := getStringPtr("u-william-1")
		crName1 := getStringPtr("rt-abc11-9")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create objCRB1 between custom permissions objCR1 and user "u-william-1"
		objCRB1 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-abc11-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [2] add 2nd rancher cluster role that has fedReader role on global domain
		crName2 := getStringPtr("rt-abc12-9")
		objCR2 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName2,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				&rbacv1.PolicyRule{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.fed"},
				},
				&rbacv1.PolicyRule{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		// create objCRB2 between custom permissions objCR2 and user "u-william-1"
		objCRB2 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-abc12-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [3] add 3rd rancher cluster role that has write permission on global domain
		// it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole & user "u-william-1" is mapped to fedReader role + some write permision
		// fedReader role is moved to permissions because there is write permission
		crName3 := getStringPtr("rt-abc13-9")
		objCR3 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName3,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				&rbacv1.PolicyRule{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR3, update_rbac)

		// create objCRB3 between custom permissions objCR3 and user "u-william-1"
		objCRB3 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-abc13-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName3,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB3, update_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{"": ""},
			map[string]share.NvPermissions{"": {
				ReadValue:  share.PERMS_FED_READ,
				WriteValue: share.PERM_CICD_SCAN,
			}},
		)

		//------ [4] add 4th rancher cluster role that has admin role on global domain
		// it's not "cattle-globalrole-gr-xxxxxxx" k8s clusterrole & user "u-william-1" is mapped to fedReader role + admin role + some write permision
		// global domain is "admin" & PERM_FED permission(not fedReader role) is moved to permissions
		crName4 := getStringPtr("rt-abc14-9")
		objCR4 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName4,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				&rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR4, update_rbac)

		// create a objCRB4 between custom permissions objCR4 and the same user "u-william-1"
		objCRB4 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-abc14-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
				ReadValue: share.PERM_FED,
			}},
		)

		//------ [5] add 5th rancher cluster role that has fedAdmin role on global domain
		crName5 := getStringPtr("rt-abc15-9")
		objCR5 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName5,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				&rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				&rbacv1.PolicyRule{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR5, update_rbac)

		// create a objCRB4 between custom permissions objCR4 and the same user "u-william-1"
		objCRB5 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-abc15-9"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [6] delete k8s cluster role binding objCRB5 that maps fedAdmin role on global domain.
		// then global domain is "admin" & PERM_FED permission(from objCR2/objCRB2)
		rbacRancherSSO.updateK8sRbacResource(objCRB5, delete_rbac)
		// Test: check updated role
		rbacRancherSSO.checkK8sUserRoles(userName1,
			map[string]string{
				"": api.UserRoleAdmin,
			},
			map[string]share.NvPermissions{"": {
				ReadValue: share.PERM_FED,
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
	crKind := getStringPtr("ClusterRole")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := getStringPtr("u-cpjv2-1")
		crName1 := getStringPtr("rt-wbz96-1")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-w3pkgod7le-1"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		crName2 := getStringPtr("rt-abcde-2")
		objCR2 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName2,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-16"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
					ReadValue:  share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
					WriteValue: share.PERM_REG_SCAN | share.PERMS_RUNTIME_POLICIES,
				}},
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
	crKind := getStringPtr("ClusterRole")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher project role)
		userName1 := getStringPtr("u-cpjw2-1")
		crName1 := getStringPtr("rt-abcdef-1")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objRB1 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-11"),
				Namespace: getStringPtr("nv-1"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objRB1, update_rbac)

		//------ add nv custom permissions objCR2(rancher project role) that has different permissions from objCR1
		crName2 := getStringPtr("rt-abcdef-2")
		objCR2 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName2,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-12"),
				Namespace: getStringPtr("nv-2"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
				}},
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
	crKind := getStringPtr("ClusterRole")
	rKind := getStringPtr("Role")
	userKind := getStringPtr("User")
	rbacApiGroup := getStringPtr("rbac.authorization.k8s.io")

	{
		//------ [1] add nv custom permissions objCR1(rancher global role) that has fedReader role & some write permissions
		userName1 := getStringPtr("u-cpjv2-1")
		crName1 := getStringPtr("rt-wbz96-1")
		objCR1 := &rbacv1.ClusterRole{
			Metadata: &metav1.ObjectMeta{
				Name: crName1,
				Uid:  genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR1, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2'
		objCRB1 := &rbacv1.ClusterRoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name: getStringPtr("crb-w3pkgod7le-1"),
				Uid:  genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
				Kind:     crKind,
				Name:     crName1,
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

		// add objRB3 which binds objCR3 to the same user "u-cpjv2-1" for namespace test-project-ns-15 in k8s.
		// because user "u-cpjv2-1" is admin on global domain, user "u-cpjv2-1" is admin on all domains.
		// it means for namespace test-project-ns-15, this objCR3/objRB3 binding doesn't affect anything
		rName2 := getStringPtr("rt-abcde-2")
		objR2 := &rbacv1.Role{
			Metadata: &metav1.ObjectMeta{
				Name:      rName2,
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR2, update_rbac)

		objRB2 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-2"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [2] delete objCR1 and then create another objR3/objRB3 for the same user "u-cpjv2-1" on the same "test-project-ns-15" namespace
		// now only objR2/objRB2 & objR3/objRB3 are for user "u-cpjv2-1" on "test-project-ns-15" namespace
		rbacRancherSSO.updateK8sRbacResource(objCR1, delete_rbac)
		rName3 := getStringPtr("rt-abcde-3")
		objR3 := &rbacv1.Role{
			Metadata: &metav1.ObjectMeta{
				Name:      rName3,
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					ApiGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-scan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR3, update_rbac)

		objRB3 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-3"),
				Namespace: getStringPtr("test-project-ns-15"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)

		//------ [3] create another objR4/objRB4 for the same user "u-cpjv2-1" on different namespace
		rName4 := getStringPtr("rt-abcde-4")
		objR4 := &rbacv1.Role{
			Metadata: &metav1.ObjectMeta{
				Name:      rName4,
				Namespace: getStringPtr("test-project-ns-21"),
				Uid:       genGuid(),
			},
			Rules: []*rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					ApiGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.rt-scan"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objR4, update_rbac)

		objRB4 := &rbacv1.RoleBinding{
			Metadata: &metav1.ObjectMeta{
				Name:      getStringPtr("rb-bcdefghij-4"),
				Namespace: getStringPtr("test-project-ns-21"),
				Uid:       genGuid(),
			},
			Subjects: []*rbacv1.Subject{
				{
					Kind:     userKind,
					ApiGroup: rbacApiGroup,
					Name:     userName1,
				},
			},
			RoleRef: &rbacv1.RoleRef{
				ApiGroup: rbacApiGroup,
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
		)
	}

	postTest()
}
