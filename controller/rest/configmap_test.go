package rest

import (
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

func TestCustomRoleCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	// test variation of  white space before/after value etc

	yaml_data := `roles:
  - Comment: custom role 1
    #name can have ^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$
    Name: role1
    Permissions:
      - id: rt_scan
        read: true
        write: false
      - id: reg_scan
        read: true
        write: false
      - id: ci_scan
        write: true
  - Comment: custom role 2
    Name: role2
    Permissions:
      - id: authentication
        read: true
        write: true
      - id: admctrl
        read: true
        write: false
  - Comment: custom role 3
    Name: role3
    Permissions:
    - id: rt_policy
      read: true
      write: true
    - id: audit_events
      read: true
      write: false
    - id: security_events
      read: true
      write: false`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlecustomrolecfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlerolecfg return error:%v\n", err)
	}

	s1, _, _ := clusHelper.GetCustomRoleRev("role1", accAdmin)
	if s1 == nil {
		t.Errorf("Failed to get role1 config\n")
	}

	s2, _, _ := clusHelper.GetCustomRoleRev("role2", accAdmin)
	if s2 == nil {
		t.Errorf("Failed to get role2 config")
	}

	s3, _, _ := clusHelper.GetCustomRoleRev("role3", accAdmin)
	if s3 == nil {
		t.Errorf("Failed to get role3 config")
	}

	postTest()
}

func TestInvalidCustomRoleCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	// test variation of  white space before/after value etc

	yaml_data := `roles:
  - Comment: custom role 1
    #name can have ^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$
    Name: role1
    Permissions:
      - id: rt_scan
        read: true
        write: false
      - id: reg_scan
        read: true
        write: false
      - id: ibm_sa # invalid value
        read: true
        write: false
  - Comment: custom role 2
    Name: role2
    Permissions:
      - id: authentication
        read: true
        write: true
      - id: admctrl
        read: true
        write: false
      - id: security_events
        read: true
        write: true # invalid value
  - Comment: custom role admin
    Name: admin # invalid value, reserved
    Permissions:
      - id: authentication
        read: true
        write: true
  - Comment: custom role fedAdmin
    Name: fedAdmin # invalid value, reserved
    Permissions:
      - id: authentication
        read: true
        write: true
  - Comment: custom role fedReader
    Name: fedReader # invalid value, reserved
    Permissions:
      - id: authentication
        read: true
        write: true
  - Comment: custom role ibmsa
    Name: ibmsa # invalid value, reserved
    Permissions:
      - id: authentication
        read: true
        write: true
  - Comment: custom role reader
    Name: reader # invalid value, reserved
    Permissions:
      - id: authentication
        read: true
        write: true
  - Comment: custom role ciops
    Name: ciops # invalid value, reserved
    Permissions:
    - id: rt_policy
      read: true
      write: true
    - id: audit_events
      read: true
      write: false
    - id: admctrl
      read: true
      write: false`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlecustomrolecfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlerolecfg return error:%v\n", err)
	}

	customRoles := []string{"role1", "role2", "admin", "fedAdmin", "fedReader", "ibmsa", "reader", "ciops"}
	for _, role := range customRoles {
		s1, _, _ := clusHelper.GetCustomRoleRev(role, accAdmin)
		if s1 != nil {
			t.Errorf("Should fail to get %s config\n", role)
		}
	}

	postTest()
}

func TestPwdProfileCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	// test variation of  white space before/after value etc

	yaml_data := `pwd_profiles:
- name: default
  comment: default from configMap
  min_len: 10
  min_uppercase_count: 2
  min_lowercase_count: 2
  min_digit_count: 2
  min_special_count: 2
  enable_block_after_failed_login: True
  block_after_failed_login_count: 3
  block_minutes: 30
  enable_password_expiration: True
  password_expire_after_days: 90
  enable_password_history: True
  password_keep_history_count: 5
  session_timeout: 789
- name: profile2
  Comment: profile2 from configMap
  min_len:  6
  min_uppercase_count: 1
  min_digit_count: 1
  min_special_count: 1
- name: profile3
  min_len:  8
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlepwdprofilecfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlepwdprofilecfg return error:%v\n", err)
	}

	allExpected := []*share.CLUSPwdProfile{
		{
			Name:                        "default",
			Comment:                     "default from configMap",
			MinLen:                      10,
			MinUpperCount:               2,
			MinLowerCount:               2,
			MinSpecialCount:             2,
			MinDigitCount:               2,
			EnablePwdExpiration:         true,
			PwdExpireAfterDays:          90,
			EnablePwdHistory:            true,
			PwdHistoryCount:             5,
			EnableBlockAfterFailedLogin: true,
			BlockAfterFailedCount:       3,
			BlockMinutes:                30,
			SessionTimeout:              789,
		},
		/*&share.CLUSPwdProfile{	//-> stage 2/3
			Name:              "profile2",
			Comment:           "profile2 from configMap",
			MinLen:            6,
			MinUpperCount: 1,
			MinSpecialCount:   1,
			MinDigitCount:     1,
		},
		&share.CLUSPwdProfile{
			Name:   "profile3",
			MinLen: 8,
		},*/
	}

	if profiles := clusHelper.GetAllPwdProfiles(accAdmin); len(profiles) != len(allExpected) {
		t.Errorf("Got %d profiles but expect only %d profiles\n", len(profiles), len(allExpected))
	}
	for idx, expected := range allExpected {
		s, _, _ := clusHelper.GetPwdProfileRev(allExpected[idx].Name, accAdmin)
		if s == nil {
			t.Errorf("Failed to get %s config\n", allExpected[idx].Name)
		} else {
			if *expected != *s {
				t.Errorf("[%d] Got %v but expect %v\n", idx, *s, *expected)
			}
		}
	}

	{
		yaml_data := `pwd_profiles:
- name: default
  comment: default from configMap
  min_len: 10
  min_uppercase_count: 2
  min_lowercase_count: 2
  min_digit_count: 2
  min_special_count: 2
  enable_block_after_failed_login: True
  block_after_failed_login_count: 3
  block_minutes: 30
  enable_password_expiration: True
  password_expire_after_days: 90
  enable_password_history: True
  password_keep_history_count: 5
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handlepwdprofilecfg(yaml_byte, true, &skip, &context)
		if err != nil {
			t.Errorf("handlepwdprofilecfg return error:%v\n", err)
		}

		expected := share.CLUSPwdProfile{
			Name:                        "default",
			Comment:                     "default from configMap",
			MinLen:                      10,
			MinUpperCount:               2,
			MinLowerCount:               2,
			MinSpecialCount:             2,
			MinDigitCount:               2,
			EnablePwdExpiration:         true,
			PwdExpireAfterDays:          90,
			EnablePwdHistory:            true,
			PwdHistoryCount:             5,
			EnableBlockAfterFailedLogin: true,
			BlockAfterFailedCount:       3,
			BlockMinutes:                30,
			SessionTimeout:              300,
		}

		s, _, _ := clusHelper.GetPwdProfileRev(expected.Name, accAdmin)
		if s == nil {
			t.Errorf("(2) Failed to get %s config\n", expected.Name)
		} else {
			if expected != *s {
				t.Errorf("(2) Got %v but expect %v\n", *s, expected)
			}
		}
	}

	postTest()
}

func TestUserCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()
	mockCacheInstance := &mockCache{
		activePwdProfile: share.CLUSDefPwdProfileName,
		pwdProfiles: map[string]*share.CLUSPwdProfile{
			share.CLUSDefPwdProfileName: {
				Name:            share.CLUSDefPwdProfileName,
				Comment:         share.CLUSDefPwdProfileName,
				MinLen:          6,
				MinUpperCount:   0,
				MinLowerCount:   0,
				MinDigitCount:   0,
				MinSpecialCount: 0,
			},
		},
	}
	cacher = mockCacheInstance
	cache.MockCacheInit()
	mockCluster.SetCacheMockCallback(share.CLUSConfigUserRoleStore, cache.MockUserRoleConfigUpdate)

	defProfile := mockCacheInstance.pwdProfiles[share.CLUSDefPwdProfileName]
	_ = clusHelper.PutPwdProfileRev(defProfile, 0)

	var context configMapHandlerContext
	// test variation of  white space before/after value etc
	yaml_data0 := `roles:
- Comment: custom role 123
  #name can have ^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$
  Name: testRole123
  Permissions:
  - id: rt_scan
    read: true
    write: false
  - id: reg_scan
    read: true
    write: false
  - id: ci_scan
    write: true
`
	// create referenced custom role first
	yaml_byte0 := []byte(yaml_data0)
	_ = handlecustomrolecfg(yaml_byte0, true, &skip, &context)
	if s1, _, _ := clusHelper.GetCustomRoleRev("testRole123", accAdmin); s1 == nil {
		t.Errorf("Fail to get testRole123 config\n")
	}

	yaml_data := `
users:
#add multiple users below
-
  EMail: computer_sun1@yahoo.com
  #username can have ^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$
  Fullname: user1
  Locale: en
  #password length minimal 6
  Password: password1
  # admin or reader or leave empty
  Role: admin
  Role_Domains:
    admin:
      - xiaoldapadmingroup
    reader:
      - xiaoldapreadergroup
  #value between 30 -- 3600  default 300
  Timeout: 200
-
  EMail: computer_sun2@yahoo.com
  Fullname: user2
  Locale: zh_cn
  Password: password2
  Role: reader
  Role_Domains:
    admin:
      - user2ldapadmingroup
    reader:
      - user2ldapreadergroup
  Timeout: 200
-
  EMail: computer_sun2@yahoo.com
  Fullname: user3
  Locale: en
  Password: password2
  Role: ~
  Role_Domains:
    admin:
      - user3ldapadmingroup
    reader:
      - uer4ldapreadergroup
    testRole123:
      - testgroup
  Timeout: 200
`

	yaml_byte := []byte(yaml_data)
	err := handleusercfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleusercfg return error:%v\n", err)
	}

	s1, _, _ := clusHelper.GetUserRev("user1", accAdmin)
	if s1 == nil {
		t.Errorf("Failed to get user1 config\n")
	}

	s2, _, _ := clusHelper.GetUserRev("user2", accAdmin)
	if s2 == nil {
		t.Errorf("Failed to get user2 config")
	}

	s3, _, _ := clusHelper.GetUserRev("user3", accAdmin)
	if s3 == nil {
		t.Errorf("Failed to get user3 config")
	}

	// clean up custom role/user
	restCall("DELETE", "/v1/user/user3", nil, api.UserRoleAdmin)
	restCall("DELETE", "/v1/user_role/testRole123", nil, api.UserRoleAdmin)

	postTest()
}

func TestUserCfgNegative(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()
	mockCacheInstance := &mockCache{
		activePwdProfile: share.CLUSDefPwdProfileName,
		pwdProfiles: map[string]*share.CLUSPwdProfile{
			share.CLUSDefPwdProfileName: {
				Name:            share.CLUSDefPwdProfileName,
				Comment:         share.CLUSDefPwdProfileName,
				MinLen:          6,
				MinUpperCount:   0,
				MinLowerCount:   0,
				MinDigitCount:   0,
				MinSpecialCount: 0,
			},
		},
	}

	cacher = mockCacheInstance
	defProfile := mockCacheInstance.pwdProfiles[share.CLUSDefPwdProfileName]
	_ = clusHelper.PutPwdProfileRev(defProfile, 0)

	// negative test about user assigned a non-existing custom role

	yaml_data := `
users:
#add multiple users below
-
  EMail: computer_sun1@yahoo.com
  #username can have ^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$
  Fullname: user1
  Locale: locale1
  #password length minimal 6
  Password: password1
  # admin or reader or leave empty
  Role: admin
  Role_Domains:
    admin:
      - xiaoldapadmingroup
    reader:
      - xiaoldapreadergroup
    testRole101:
      - testgroup
  #value between 30 -- 3600  default 300
  Timeout: 200
-
  EMail: computer_sun2@yahoo.com
  Fullname: user2
  Locale: locale
  Password: password2
  Role: ~
  Role_Domains:
    admin:
      - user3ldapadmingroup
    reader:
      - uer4ldapreadergroup
    testRole123:
      - testgroup
  Timeout: 200  
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handleusercfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleusercfg return error:%v\n", err)
	}

	s1, _, _ := clusHelper.GetUserRev("user1", accAdmin)
	if s1 != nil {
		t.Errorf("Succeeded to get user1 config. Expect failure\n")
	}

	s2, _, _ := clusHelper.GetUserRev("user2", accAdmin)
	if s2 != nil {
		t.Errorf("Succeeded to get user2 config. Expect failure\n")
	}

	postTest()
}

func TestLdapCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	// test variation of  white space before/after value etc

	{
		// negative testing: invalid config map (unserver's default role is unknown)
		yaml_data := `# OpenLDAP or MicrosoftAD
directory: OpenLDAP
Hostname: neuvector.com
Port: 8888
#true or false
SSL: false
base_dn: DC=neuvectorTldap,DC=com
bind_dn: ldap
bind_password: ldappassword
group_member_attr: groupMAttr
username_attr: userMAttr
#true or false
Enable: true
#admin or reader
Default_Role: wrongadmin
Role_Groups:
  admin:
  - sampleldapadmingroup
  reader:
  - sampleldapreadergroup
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handleldapcfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handleldapcfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `# OpenLDAP or MicrosoftAD
directory: OpenLDAP
Hostname: neuvector.com
Port: 8888
#true or false
SSL: false
base_dn: DC=neuvectorTldap,DC=com
bind_dn: ldap
bind_password: ldappassword
group_member_attr: groupMAttr
username_attr: userMAttr
#true or false
Enable: true
#admin or reader
Default_Role: admin
Role_Groups:
  admin:
  - sampleldapadmingroup
  reader:
  - sampleldapreadergroup
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handleldapcfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleldapcfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("ldap1", accAdmin)
	if s == nil || s.LDAP == nil {
		t.Errorf("Failed to get ldap config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "sampleldapadmingroup",
				GlobalRole: "admin",
			},
			{
				Group:      "sampleldapreadergroup",
				GlobalRole: "reader",
			},
		}
		compareGroupMappedData("TestLdapCfg", s.LDAP.GroupMappedRoles, expect, t)
	}
	postTest()
}

func TestLdapCfgWithGroupRoleDomains(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	cacher = &mockCache{}

	// test variation of  white space before/after value etc

	{
		// negative testing: invalid config map (server's default role is unknown)
		yaml_data := `# OpenLDAP or MicrosoftAD
		directory: OpenLDAP
		hostname: neuvector.com
		port: 8888
		# true or false
		ssl: false
		base_dn: DC=neuvectorTldap,DC=com
		bind_dn: ldap
		bind_password: ldappassword
		group_member_attr: groupMAttr
		username_attr: userMAttr
		# true or false
		enable: true
		Default_Role: wrongreader
		group_mapped_roles:
		  - group: sampleldapadmingroup
			global_role: admin
		  - group: sampleldapreadergroup
			global_role: reader
			role_domains:
			  ciops:
				- ns1
				- ns2
			  admin:
				- ns3
		`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handleldapcfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handleldapcfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `# OpenLDAP or MicrosoftAD
directory: OpenLDAP
hostname: neuvector.com
port: 8888
# true or false
ssl: false
base_dn: DC=neuvectorTldap,DC=com
bind_dn: ldap
bind_password: ldappassword
group_member_attr: groupMAttr
username_attr: userMAttr
# true or false
enable: true
group_mapped_roles:
  - group: sampleldapadmingroup
    global_role: admin
  - group: sampleldapreadergroup
    global_role: reader
    role_domains:
      ciops:
        - ns1
        - ns2
      admin:
        - ns3
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handleldapcfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleldapcfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("ldap1", accAdmin)
	if s == nil || s.LDAP == nil {
		t.Errorf("Failed to get ldap config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "sampleldapadmingroup",
				GlobalRole: "admin",
			},
			{
				Group:      "sampleldapreadergroup",
				GlobalRole: "reader",
				RoleDomains: map[string][]string{
					"ciops": {"ns1", "ns2"},
					"admin": {"ns3"},
				},
			},
		}
		compareGroupMappedData("TestLdapCfgWithGroupRoleDomains", s.LDAP.GroupMappedRoles, expect, t)
	}
	postTest()
}

func TestSamlCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})
	remoteAuther = &mockAuther

	// test variation of  white space before/after value etc

	{
		// negative testing: invalid config map (group's role is unknown)
		yaml_data := `SSO_URL: http://neuvector.com
Issuer: http://samplesamlissuer
X509_Cert: |
  -----BEGIN CERTIFICATE-----
  MIIFBjCCAu4CCQC+6KhoSGafijANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJB
  VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
  cyBQdHkgTHRkMB4XDTE5MDQxOTE5NTY0M1oXDTIwMDQxODE5NTY0M1owRTELMAkG
  A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
  IFdpZGdpdHMgUHR5IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
  AM3zOIDIljWHrU00S0ZWNX5YNExoWNejIonjMTj+qewMPZELS+sYBNmFnC1GUd3P
  ZnRiTZJG0+Gg7oeEKPUysbytT5YeNGDo6CSVo4TWMV0MGq8oB9aT5GxILQqxFmYZ
  AmNG2SEul9VFEROGixkEa0aPB9rdqp/iLVCB3ffw3ymiVEDH03LbmnWNAwy+ctmB
  uFg0OgdMwBYtslavM2STCCqA9QLWIHeDlrfv+ZPyYpD9o1xjFv25XKRETo7Tr7D1
  GjPBzm2AkRIeyVdYFqwA4YmFvxojuo9As4XfVngRHz2dZPKpfGSkfV0tFwxWkW1C
  Kf1iC/L/dDN3vVdfN1w9IEy+UrH+4HCmCZ4q3P65dgMCvYACFymL13TxXFlKXmvH
  epwVto/YOl3s9DyHlp5AWO/wKU3qQySkwoEbOZHVYvhVEmyunxfAFR+Xv2W9y8vH
  klT9JurMpKJ8AqcmAzGJyTLvusZOmprUyK4dydoQEgTZNQTFXBr0IZSjNWOtUfyP
  SFfXTBuIxANkwL9vfhDAVoZdsZkDJeUDxuCBv7UKTzvVuSwgSvW8wWhgrAomT50w
  grOUlvJ8A9uH4M5AYpZ9Oq/7eWbIt772R04PHW0hsRdC0pbYvkmHGKLdfIc6EbLy
  cyoQ5sr/skdW/ApKZzYkuwfXHMzp3Zz0PRKzkqAjzm+tAgMBAAEwDQYJKoZIhvcN
  AQELBQADggIBAKRsSzS98FtlPnprx/neLzkM5g1LCNaQ5eFx/jTdN1zHkZlRAuc9
  XWGKQ47sKt4ilQUM07Xf8hnVk9b1/7MvG7xFZahDJ3XTvVoPhJ3KyVTVc4Ivyv7v
  C3wkJHLe7UUQcrtF4HpfWmPbsNv5H1ke5gs3JgDhqAUJrM8vdBLxnp3xYd4sPtvH
  yCTsWiejhXcm7IRYtazG4xANFzWeGJlzeYnU/48hdAym3oJOm8weX8UOoYExi0mA
  FzGa5w79SrvQ0IbpMsqKjSn3ciI9xsGqTl3LV1jENgCf6j2sdzwRDgGUFWzgvZ2s
  oIPdYgWCywa3hDs31qLPziKbCerAr3RJajclaKoCTaaraC4iAML4ZiQ6yzOWsm20
  6zESOHowCkZ5DTUmqXSuORlOY5NJmgrOFF6CNZpSjS+c1AM9syyoJ4lkXuXLhC2w
  iwB/mgK9QWwr0RfT+1NmuJTQn7/N36FLiZ67Pk5GKBlLZSQTie+e/+/hNkHtHoFu
  CXYHlq6Q/6ZifdsVsgHoBNNNlmS9H4W9jWI5P8kLyMWo1Au5lDmcKfiE7FoFB8hl
  hI72hMq6FvwqfkYxObnBCQCQoCtf9cJbqd8n1wLlEvZ59fXnJyZkBhRpzjz0w4iI
  HOw7Qv4qlnM6Q7hhRfUzR7TsdqTi1tDUv30fENXn7tgd6dFi3pNmBUnB
  -----END CERTIFICATE-----
#true or false
Enable: true
#admin or reader
Default_Role: admin
Role_Groups:
  wrongadmin:
  - samplesamladmingroup
  reader:
  - samplesamlreadergroup
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handlesamlcfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handlesamlcfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `SSO_URL: http://neuvector.com
Issuer: http://samplesamlissuer
X509_Cert: |
  -----BEGIN CERTIFICATE-----
  MIIFBjCCAu4CCQC+6KhoSGafijANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJB
  VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
  cyBQdHkgTHRkMB4XDTE5MDQxOTE5NTY0M1oXDTIwMDQxODE5NTY0M1owRTELMAkG
  A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
  IFdpZGdpdHMgUHR5IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
  AM3zOIDIljWHrU00S0ZWNX5YNExoWNejIonjMTj+qewMPZELS+sYBNmFnC1GUd3P
  ZnRiTZJG0+Gg7oeEKPUysbytT5YeNGDo6CSVo4TWMV0MGq8oB9aT5GxILQqxFmYZ
  AmNG2SEul9VFEROGixkEa0aPB9rdqp/iLVCB3ffw3ymiVEDH03LbmnWNAwy+ctmB
  uFg0OgdMwBYtslavM2STCCqA9QLWIHeDlrfv+ZPyYpD9o1xjFv25XKRETo7Tr7D1
  GjPBzm2AkRIeyVdYFqwA4YmFvxojuo9As4XfVngRHz2dZPKpfGSkfV0tFwxWkW1C
  Kf1iC/L/dDN3vVdfN1w9IEy+UrH+4HCmCZ4q3P65dgMCvYACFymL13TxXFlKXmvH
  epwVto/YOl3s9DyHlp5AWO/wKU3qQySkwoEbOZHVYvhVEmyunxfAFR+Xv2W9y8vH
  klT9JurMpKJ8AqcmAzGJyTLvusZOmprUyK4dydoQEgTZNQTFXBr0IZSjNWOtUfyP
  SFfXTBuIxANkwL9vfhDAVoZdsZkDJeUDxuCBv7UKTzvVuSwgSvW8wWhgrAomT50w
  grOUlvJ8A9uH4M5AYpZ9Oq/7eWbIt772R04PHW0hsRdC0pbYvkmHGKLdfIc6EbLy
  cyoQ5sr/skdW/ApKZzYkuwfXHMzp3Zz0PRKzkqAjzm+tAgMBAAEwDQYJKoZIhvcN
  AQELBQADggIBAKRsSzS98FtlPnprx/neLzkM5g1LCNaQ5eFx/jTdN1zHkZlRAuc9
  XWGKQ47sKt4ilQUM07Xf8hnVk9b1/7MvG7xFZahDJ3XTvVoPhJ3KyVTVc4Ivyv7v
  C3wkJHLe7UUQcrtF4HpfWmPbsNv5H1ke5gs3JgDhqAUJrM8vdBLxnp3xYd4sPtvH
  yCTsWiejhXcm7IRYtazG4xANFzWeGJlzeYnU/48hdAym3oJOm8weX8UOoYExi0mA
  FzGa5w79SrvQ0IbpMsqKjSn3ciI9xsGqTl3LV1jENgCf6j2sdzwRDgGUFWzgvZ2s
  oIPdYgWCywa3hDs31qLPziKbCerAr3RJajclaKoCTaaraC4iAML4ZiQ6yzOWsm20
  6zESOHowCkZ5DTUmqXSuORlOY5NJmgrOFF6CNZpSjS+c1AM9syyoJ4lkXuXLhC2w
  iwB/mgK9QWwr0RfT+1NmuJTQn7/N36FLiZ67Pk5GKBlLZSQTie+e/+/hNkHtHoFu
  CXYHlq6Q/6ZifdsVsgHoBNNNlmS9H4W9jWI5P8kLyMWo1Au5lDmcKfiE7FoFB8hl
  hI72hMq6FvwqfkYxObnBCQCQoCtf9cJbqd8n1wLlEvZ59fXnJyZkBhRpzjz0w4iI
  HOw7Qv4qlnM6Q7hhRfUzR7TsdqTi1tDUv30fENXn7tgd6dFi3pNmBUnB
  -----END CERTIFICATE-----
#true or false
Enable: true
#admin or reader
Default_Role: admin
Role_Groups:
  admin:
  - samplesamladmingroup
  reader:
  - samplesamlreadergroup
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlesamlcfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlesamlcfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("saml1", accAdmin)
	if s == nil || s.SAML == nil {
		t.Errorf("Failed to get saml config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "samplesamladmingroup",
				GlobalRole: "admin",
			},
			{
				Group:      "samplesamlreadergroup",
				GlobalRole: "reader",
			},
		}
		compareGroupMappedData("TestSamlCfg", s.SAML.GroupMappedRoles, expect, t)
	}

	postTest()
}

func TestSamlCfgWithGroupRoleDomains(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	cacher = &mockCache{}

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})
	remoteAuther = &mockAuther

	// test variation of  white space before/after value etc

	{
		// negative testing: invalid config map (group's global role is unknown)
		yaml_data := `SSO_URL: http://neuvector.com
Issuer: http://samplesamlissuer
X509_Cert: |
  -----BEGIN CERTIFICATE-----
  MIIFBjCCAu4CCQC+6KhoSGafijANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJB
  VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
  cyBQdHkgTHRkMB4XDTE5MDQxOTE5NTY0M1oXDTIwMDQxODE5NTY0M1owRTELMAkG
  A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
  IFdpZGdpdHMgUHR5IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
  AM3zOIDIljWHrU00S0ZWNX5YNExoWNejIonjMTj+qewMPZELS+sYBNmFnC1GUd3P
  ZnRiTZJG0+Gg7oeEKPUysbytT5YeNGDo6CSVo4TWMV0MGq8oB9aT5GxILQqxFmYZ
  AmNG2SEul9VFEROGixkEa0aPB9rdqp/iLVCB3ffw3ymiVEDH03LbmnWNAwy+ctmB
  uFg0OgdMwBYtslavM2STCCqA9QLWIHeDlrfv+ZPyYpD9o1xjFv25XKRETo7Tr7D1
  GjPBzm2AkRIeyVdYFqwA4YmFvxojuo9As4XfVngRHz2dZPKpfGSkfV0tFwxWkW1C
  Kf1iC/L/dDN3vVdfN1w9IEy+UrH+4HCmCZ4q3P65dgMCvYACFymL13TxXFlKXmvH
  epwVto/YOl3s9DyHlp5AWO/wKU3qQySkwoEbOZHVYvhVEmyunxfAFR+Xv2W9y8vH
  klT9JurMpKJ8AqcmAzGJyTLvusZOmprUyK4dydoQEgTZNQTFXBr0IZSjNWOtUfyP
  SFfXTBuIxANkwL9vfhDAVoZdsZkDJeUDxuCBv7UKTzvVuSwgSvW8wWhgrAomT50w
  grOUlvJ8A9uH4M5AYpZ9Oq/7eWbIt772R04PHW0hsRdC0pbYvkmHGKLdfIc6EbLy
  cyoQ5sr/skdW/ApKZzYkuwfXHMzp3Zz0PRKzkqAjzm+tAgMBAAEwDQYJKoZIhvcN
  AQELBQADggIBAKRsSzS98FtlPnprx/neLzkM5g1LCNaQ5eFx/jTdN1zHkZlRAuc9
  XWGKQ47sKt4ilQUM07Xf8hnVk9b1/7MvG7xFZahDJ3XTvVoPhJ3KyVTVc4Ivyv7v
  C3wkJHLe7UUQcrtF4HpfWmPbsNv5H1ke5gs3JgDhqAUJrM8vdBLxnp3xYd4sPtvH
  yCTsWiejhXcm7IRYtazG4xANFzWeGJlzeYnU/48hdAym3oJOm8weX8UOoYExi0mA
  FzGa5w79SrvQ0IbpMsqKjSn3ciI9xsGqTl3LV1jENgCf6j2sdzwRDgGUFWzgvZ2s
  oIPdYgWCywa3hDs31qLPziKbCerAr3RJajclaKoCTaaraC4iAML4ZiQ6yzOWsm20
  6zESOHowCkZ5DTUmqXSuORlOY5NJmgrOFF6CNZpSjS+c1AM9syyoJ4lkXuXLhC2w
  iwB/mgK9QWwr0RfT+1NmuJTQn7/N36FLiZ67Pk5GKBlLZSQTie+e/+/hNkHtHoFu
  CXYHlq6Q/6ZifdsVsgHoBNNNlmS9H4W9jWI5P8kLyMWo1Au5lDmcKfiE7FoFB8hl
  hI72hMq6FvwqfkYxObnBCQCQoCtf9cJbqd8n1wLlEvZ59fXnJyZkBhRpzjz0w4iI
  HOw7Qv4qlnM6Q7hhRfUzR7TsdqTi1tDUv30fENXn7tgd6dFi3pNmBUnB
  -----END CERTIFICATE-----
#true or false
Enable: true
Default_Role: ciops
group_mapped_roles:
  - group: sampleldapadmingroup
    global_role: admin
  - group: sampleldapreadergroup
    global_role: wrongreader
    role_domains:
      reader:
        - ns1
        - ns2
      admin:
        - ns3
        - ns4
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handlesamlcfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handlesamlcfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `SSO_URL: http://neuvector.com
Issuer: http://samplesamlissuer
X509_Cert: |
  -----BEGIN CERTIFICATE-----
  MIIFBjCCAu4CCQC+6KhoSGafijANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJB
  VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
  cyBQdHkgTHRkMB4XDTE5MDQxOTE5NTY0M1oXDTIwMDQxODE5NTY0M1owRTELMAkG
  A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
  IFdpZGdpdHMgUHR5IEx0ZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
  AM3zOIDIljWHrU00S0ZWNX5YNExoWNejIonjMTj+qewMPZELS+sYBNmFnC1GUd3P
  ZnRiTZJG0+Gg7oeEKPUysbytT5YeNGDo6CSVo4TWMV0MGq8oB9aT5GxILQqxFmYZ
  AmNG2SEul9VFEROGixkEa0aPB9rdqp/iLVCB3ffw3ymiVEDH03LbmnWNAwy+ctmB
  uFg0OgdMwBYtslavM2STCCqA9QLWIHeDlrfv+ZPyYpD9o1xjFv25XKRETo7Tr7D1
  GjPBzm2AkRIeyVdYFqwA4YmFvxojuo9As4XfVngRHz2dZPKpfGSkfV0tFwxWkW1C
  Kf1iC/L/dDN3vVdfN1w9IEy+UrH+4HCmCZ4q3P65dgMCvYACFymL13TxXFlKXmvH
  epwVto/YOl3s9DyHlp5AWO/wKU3qQySkwoEbOZHVYvhVEmyunxfAFR+Xv2W9y8vH
  klT9JurMpKJ8AqcmAzGJyTLvusZOmprUyK4dydoQEgTZNQTFXBr0IZSjNWOtUfyP
  SFfXTBuIxANkwL9vfhDAVoZdsZkDJeUDxuCBv7UKTzvVuSwgSvW8wWhgrAomT50w
  grOUlvJ8A9uH4M5AYpZ9Oq/7eWbIt772R04PHW0hsRdC0pbYvkmHGKLdfIc6EbLy
  cyoQ5sr/skdW/ApKZzYkuwfXHMzp3Zz0PRKzkqAjzm+tAgMBAAEwDQYJKoZIhvcN
  AQELBQADggIBAKRsSzS98FtlPnprx/neLzkM5g1LCNaQ5eFx/jTdN1zHkZlRAuc9
  XWGKQ47sKt4ilQUM07Xf8hnVk9b1/7MvG7xFZahDJ3XTvVoPhJ3KyVTVc4Ivyv7v
  C3wkJHLe7UUQcrtF4HpfWmPbsNv5H1ke5gs3JgDhqAUJrM8vdBLxnp3xYd4sPtvH
  yCTsWiejhXcm7IRYtazG4xANFzWeGJlzeYnU/48hdAym3oJOm8weX8UOoYExi0mA
  FzGa5w79SrvQ0IbpMsqKjSn3ciI9xsGqTl3LV1jENgCf6j2sdzwRDgGUFWzgvZ2s
  oIPdYgWCywa3hDs31qLPziKbCerAr3RJajclaKoCTaaraC4iAML4ZiQ6yzOWsm20
  6zESOHowCkZ5DTUmqXSuORlOY5NJmgrOFF6CNZpSjS+c1AM9syyoJ4lkXuXLhC2w
  iwB/mgK9QWwr0RfT+1NmuJTQn7/N36FLiZ67Pk5GKBlLZSQTie+e/+/hNkHtHoFu
  CXYHlq6Q/6ZifdsVsgHoBNNNlmS9H4W9jWI5P8kLyMWo1Au5lDmcKfiE7FoFB8hl
  hI72hMq6FvwqfkYxObnBCQCQoCtf9cJbqd8n1wLlEvZ59fXnJyZkBhRpzjz0w4iI
  HOw7Qv4qlnM6Q7hhRfUzR7TsdqTi1tDUv30fENXn7tgd6dFi3pNmBUnB
  -----END CERTIFICATE-----
#true or false
Enable: true
Default_Role: ciops
group_mapped_roles:
  - group: sampleldapadmingroup
    global_role: admin
  - group: sampleldapreadergroup
    global_role: reader
    role_domains:
      reader:
        - ns1
        - ns2
      admin:
        - ns3
        - ns4
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlesamlcfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlesamlcfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("saml1", accAdmin)
	if s == nil || s.SAML == nil {
		t.Errorf("Failed to get saml config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "sampleldapadmingroup",
				GlobalRole: "admin",
			},
			{
				Group:      "sampleldapreadergroup",
				GlobalRole: "reader",
				RoleDomains: map[string][]string{
					"admin": {"ns3", "ns4"},
				},
			},
		}
		compareGroupMappedData("TestSamlCfgWithGroupRoleDomains", s.SAML.GroupMappedRoles, expect, t)
	}

	postTest()
}

func TestOidcCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})
	remoteAuther = &mockAuther

	// test variation of  white space before/after value etc

	{
		// negative testing: invalid config map (group's role is unknown)
		yaml_data := `#issuer http url
Issuer: https://login.microsoftonline.com/b40b09ae-edb6-4114-8f95-56a566b8d956/v2.0
Client_ID: f53c56ec-bc2e-41f1-86ca-e4e2e1e755de
Client_Secret: FIrxEghxAi+nH1AEzXPQkc+ubqOQ1CG5XElPPXhjJzI8zuUASYfbrxuCaK4Yqf1g6+OWl5g6qW//uOuH
Scopes:
  - scop1
  - scop2
#true or false
Enable: true
#admin or reader
Default_Role: ciops
Role_Groups:
  admin:
  - sampleoidcadmingroup
  wrongreader:
  - sampleoidcreadergroup
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handleoidccfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handleoidccfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `#issuer http url
Issuer: https://login.microsoftonline.com/b40b09ae-edb6-4114-8f95-56a566b8d956/v2.0
Client_ID: f53c56ec-bc2e-41f1-86ca-e4e2e1e755de
Client_Secret: FIrxEghxAi+nH1AEzXPQkc+ubqOQ1CG5XElPPXhjJzI8zuUASYfbrxuCaK4Yqf1g6+OWl5g6qW//uOuH
Scopes:
  - scop1
  - scop2
#true or false
Enable: true
#admin or reader
Default_Role: admin
Role_Groups:
  admin:
  - sampleoidcadmingroup
  reader:
  - sampleoidcreadergroup
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handleoidccfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleoidccfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("openId1", accAdmin)
	if s == nil || s.OIDC == nil {
		t.Errorf("Failed to get oidc config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "sampleoidcadmingroup",
				GlobalRole: "admin",
			},
			{
				Group:      "sampleoidcreadergroup",
				GlobalRole: "reader",
			},
		}
		compareGroupMappedData("TestOidcCfg", s.OIDC.GroupMappedRoles, expect, t)
	}

	postTest()
}

func TestOidcCfgWithGroupRoleDomains(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	cacher = &mockCache{}

	mockAuther := mockRemoteAuth{users: make(map[string]*passwordUser)}
	// User group membership doesn't match role group mapping
	mockAuther.addPasswordUser("user", "pass", []string{"group1"})
	remoteAuther = &mockAuther

	// test variation of  white space before/after value etc
	{
		// negative testing: invalid config map (group's domain role is unknown)
		yaml_data := `#issuer http url
Issuer: https://login.microsoftonline.com/b40b09ae-edb6-4114-8f95-56a566b8d956/v2.0
Client_ID: f53c56ec-bc2e-41f1-86ca-e4e2e1e755de
Client_Secret: FIrxEghxAi+nH1AEzXPQkc+ubqOQ1CG5XElPPXhjJzI8zuUASYfbrxuCaK4Yqf1g6+OWl5g6qW//uOuH
Scopes:
  - scop1
  - scop2
#true or false
Enable: true
group_mapped_roles:
  - group: sampleldapadmingroup
    global_role: ciops
    role_domains:
      reader:
        - ns1
        - ns3
      wrongadmin:
        - ns2
        - ns4
  - group: sampleldapreadergroup
`

		var context configMapHandlerContext
		yaml_byte := []byte(yaml_data)
		err := handleoidccfg(yaml_byte, true, &skip, &context)
		if err == nil {
			t.Errorf("handleoidccfg return success(expect failure):%v\n", err)
		}
	}

	yaml_data := `#issuer http url
Issuer: https://login.microsoftonline.com/b40b09ae-edb6-4114-8f95-56a566b8d956/v2.0
Client_ID: f53c56ec-bc2e-41f1-86ca-e4e2e1e755de
Client_Secret: FIrxEghxAi+nH1AEzXPQkc+ubqOQ1CG5XElPPXhjJzI8zuUASYfbrxuCaK4Yqf1g6+OWl5g6qW//uOuH
Scopes:
  - scop1
  - scop2
#true or false
Enable: true
group_mapped_roles:
  - group: sampleldapadmingroup
    global_role: ciops
    role_domains:
      reader:
        - ns1
        - ns3
      admin:
        - ns2
        - ns4
  - group: sampleldapreadergroup
`

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handleoidccfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handleoidccfg return error:%v\n", err)
	}
	s, _, _ := clusHelper.GetServerRev("openId1", accAdmin)
	if s == nil || s.OIDC == nil {
		t.Errorf("Failed to get oidc config\n")
	} else {
		expect := []*share.GroupRoleMapping{
			{
				Group:      "sampleldapadmingroup",
				GlobalRole: "ciops",
				RoleDomains: map[string][]string{
					"reader": {"ns1", "ns3"},
					"admin":  {"ns2", "ns4"},
				},
			},
		}
		compareGroupMappedData("TestOidcCfgWithGroupRoleDomains", s.OIDC.GroupMappedRoles, expect, t)
	}

	postTest()
}

func TestSystemCfg(t *testing.T) {
	preTest()

	var skip bool
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	accAdmin := access.NewAdminAccessControl()

	// test variation of wrong ip, wrong proto, wrong port add white space before/after value etc
	yaml_data := "#Discover or Monitor  or Protect\nNew_Service_Policy_Mode: Protect \n#input valid ipv4 address\nSyslog_ip: 10.1.12.61\n#default UDP or input 17 or 6 here for upd or tcp\nSyslog_IP_Proto:  17 \nSyslog_Port: 8999\n#default level Info, or chose between  Alert/Critical/Error/Warning/Notice/Info/Debug\nSyslog_Level: Alert\n# true or false\nSyslog_status: true\nSyslog_Categories:\n# can chose multiple between event/incident/violation/threat/audit\n      - event\n      - security-event\n#true or false\nAuth_By_Platform: true\n#true or false\nWebhook_Status: true\nWebhook_Url: http://webhook.neuvector.com\nCluster_Name: clustername\nController_Debug:\n        - debug1\n        - debug2\n#true or false\nMonitor_Service_Mesh: true\n#true or false\nRegistry_Http_Proxy_Status: true\n#true or false\nRegistry_Https_Proxy_Status: true\nRegistry_Http_Proxy:\n    URL: http://testurl.com\n    Username: uname\n    Password: pword\nRegistry_Https_Proxy:\n    URL: https://testurl.com\n    Username: unames\n    Password: pwords\n"

	var context configMapHandlerContext
	yaml_byte := []byte(yaml_data)
	err := handlesystemcfg(yaml_byte, true, &skip, &context)
	if err != nil {
		t.Errorf("handlesystemccfg return error:%v\n", err)
	}
	s, _ := clusHelper.GetSystemConfigRev(accAdmin)

	if s == nil {
		t.Errorf("Failed to get system config\n")
	}

	postTest()
}
