package resource

import (
	"os"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	//orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"github.com/neuvector/neuvector/controller/api"
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
	rbac, _ := d.GetUserRoles("mike", SUBJECT_USER)
	expect := map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", expect)
		t.Logf("  Actual: %+v\n", rbac)
	}

	// Test: check mike is gone
	rbac, _ = d.GetUserRoles("mike", SUBJECT_USER)
	if rbac != nil {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("jane", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin, "ns2": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin, "ns2": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader, "ns1": api.UserRoleAdmin}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": api.UserRoleReader}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	expect = map[string]string{"": "", "ns1": api.UserRoleReader, "ns2": api.UserRoleReader}
	if !reflect.DeepEqual(rbac, expect) {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
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
	rbac, _ = d.GetUserRoles("gary", SUBJECT_USER)
	if rbac != nil {
		t.Errorf("Unexpacted rbac - cache: %+v", d.rbacCache)
		t.Logf("  Expect: %+v\n", nil)
		t.Logf("  Actual: %+v\n", rbac)
	}

	postTest()
}
