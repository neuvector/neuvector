package resource

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
)

func TestRBACRancherSSOv2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOv2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
					Resources: []string{"nv-perm.authentication"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "modify"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.authorization"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.audit-events"},
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"*"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"create"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.security-events"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.compliance"},
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
					Resources: []string{"nv-perm.compliance"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.vulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.events"}, // supported in global & domain
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

func TestRBACRancherSSOFedAdminReaderV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOFedAdminReaderV2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
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
					APIGroups: []string{"api.neuvector.com"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.vulnerability"}, // supported in global only
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.events"}, // supported in global & domain
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
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
func TestRBACRancherSSOMixedClusterRoleV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOMixedClusterRoleV2",
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.fed"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
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
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
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
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
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
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"*"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
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

func TestRBACRancherSSOAdminV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOAdminV2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
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

func TestRBACRancherSSOProjectRolesV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOProjectRolesV2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
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
func TestRBACRancherSSOK8sroleV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOK8sroleV2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
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
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-scan"},
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
					Resources: []string{"nv-perm.rt-scan"},
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

/*
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
*/
func TestConsolidateNvRolePermitsV2(t *testing.T) {
	preTest()

	//_k8sFlavor = share.FlavorRancher
	//global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	//IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestConsolidateNvRolePermitsV2",
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": {
				Local:  share.NvPermissions{ReadValue: share.PERMS_FED_READ},
				Remote: share.NvPermissions{ReadValue: share.PERMS_FED_READ},
			},
			"domain-12": {
				Local:  share.NvPermissions{ReadValue: share.PERMS_CLUSTER_READ},
				Remote: share.NvPermissions{ReadValue: share.PERMS_CLUSTER_WRITE},
			},
			"domain-13": {
				Local:  share.NvPermissions{ReadValue: share.PERMS_DOMAIN_WRITE},
				Remote: share.NvPermissions{ReadValue: share.PERMS_CLUSTER_WRITE},
			},
		}

		expectDomainRoles = map[string]string{
			"": api.UserRoleAdmin,
		}
		expectDomainPerms = map[string]share.NvFedPermissions{
			"": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": {
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
			"": {
				Local:  share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-11": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			},
			"domain-12": {
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
			"": {
				Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
				Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
			},
			"domain-12": {
				Local: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
			},
		}
		domainRole, domainPermits = removeRedundant(domainRole, domainPermits, api.FedRoleMaster)
		rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)
	}

	postTest()
}

func TestRancherMultiplePrinciplesV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRancherMultiplePrinciplesV2",
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleAdmin,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleFedReader,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": {
			Local:  share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleReader,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": {
			Local: share.NvPermissions{WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleNone,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": {
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
		"": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-11": {
			Local:  share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL | share.PERM_FED, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
		"domain-12": {
			Local:  share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
			Remote: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN | share.PERM_FED, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES | share.PERM_FED},
		},
	}

	expectDomainRoles = map[string]string{
		"": api.UserRoleNone,
	}
	expectDomainPerms = map[string]share.NvFedPermissions{
		"": {
			Local: share.NvPermissions{ReadValue: share.PERM_ADM_CONTROL, WriteValue: share.PERM_ADM_CONTROL | share.PERMS_RUNTIME_POLICIES},
		},
		"domain-12": {
			Local: share.NvPermissions{ReadValue: share.PERMS_RUNTIME_SCAN, WriteValue: share.PERMS_RUNTIME_SCAN | share.PERMS_RUNTIME_POLICIES},
		},
	}

	domainRole, domainPermits = RemoveRedundant(allDomainRoles, domainPermits, api.FedRoleJoint)
	rbacRancherSSO.verifyNvRolePermits(domainRole, expectDomainRoles, domainPermits, expectDomainPerms)

	postTest()
}

func TestRBACRancherSSOFedPermitV2(t *testing.T) {
	preTest()

	_k8sFlavor = share.FlavorRancher
	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", _k8sFlavor, "1.24", "", register_k8s_unittest)
	d := new_k8s_unittest()
	IsRancherFlavor()

	var rbacRancherSSO tRbacRancherSSO = tRbacRancherSSO{
		t:        t,
		d:        d,
		caseName: "TestRBACRancherSSOFedPermitV2",
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.fed"},
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
		// because fed permission is not supported for namespaces yet, "nv-perm.fed" is ignored in objCR2
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.fed"},
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
		// because fed permission is not supported for namespaces yet, "nv-perm.fed" is ignored in objCR3
		// get/nv-perm.all-permissions means domain reader for namespace test-project-ns-25
		crName3 := "rt-abcde-3"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.all-permissions"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.fed"},
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
					Resources: []string{"nv-perm.reg-scan"}, // "nv-perm.fed" in the next rule also applies to this rule; but "*" verbs in the next rule doesn't affect this rule
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
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
		// because fed permission is not supported for namespaces yet, "nv-perm.fed" is ignored in objCR2
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
					Resources: []string{"nv-perm.events"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.audit-events"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.security-events"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.ci-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"nv-perm.admctrl"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
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
		// because fed permission is not supported for namespaces yet, "nv-perm.fed" is ignored in objCR3
		// get/nv-perm.all-permissions means domain reader for namespace test-project-ns-25
		crName3 := "rt-abcde-3"
		objCR3 := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: crName3,
				UID:  genGuid(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"neuvector.api.io"}, // not supported
					Resources: []string{"nv-perm.compliance", "nv-perm.all-permissions", "*"},
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.allall-permissions"}, // not supported for namespaces
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"authentication"}, // not supported for namespaces
				},
				{
					Verbs:     []string{"*", "create", "delete", "get", "list", "patch", "update", "watch", "post"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.authorization"},
				},
				{
					Verbs:     []string{"create", "delete", "get", "list", "patch", "update", "watch", "post"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.config"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
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
		//------ [3] about "nv-perm.fed" for global domain
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
					Resources: []string{"nv-perm.reg-scan"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.rt-policy"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"neuvector.api.io", "*"}, // unsupported apiGroup
					Resources: []string{"nv-perm.compliance"},
				},
				{
					Verbs:     []string{"*", "get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.authentication"},
				},
				{
					Verbs:     []string{"get", "post"},
					APIGroups: []string{"read-only.neuvector.api.io"},
					Resources: []string{"nv-perm.authorization"},
				},
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.config"},
				},
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"api.neuvector.com"},
					Resources: []string{"nv-perm.fed"},
				},
			},
		}
		rbacRancherSSO.updateK8sRbacResource(objCR31, update_rbac)

		// create a objCRB1 between custom permissions objCR1 and user 'u-cpjv2-31'
		objCRB1 := &rbacv1.ClusterRoleBinding{
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
		rbacRancherSSO.updateK8sRbacResource(objCRB1, update_rbac)

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
		objCR31.Rules[0].Resources = []string{"nv-perm.all-permissions"}
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
}
