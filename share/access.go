package share

import "strings"

type GetAccessObjectFunc func(string) AccessObject
type AccessObject interface {
	GetDomain(f GetAccessObjectFunc) ([]string, []string) // ([]string, []string)
}

const HiddenFedDomain string = "$*&().^$"
const (
	AccessAllAsReader = "*" // Namespace user can read, global user follow roles
)

type NvReservedUserRole uint8

const (
	UserRoleAdmin     NvReservedUserRole = 0x01
	UserRoleReader    NvReservedUserRole = 0x02
	UserRoleFedAdmin  NvReservedUserRole = 0x04
	UserRoleFedReader NvReservedUserRole = 0x08
)

const (
	// All PERM_xyz_BASIC permissions can be enabled/disabled indirectly by enabling/disabling some composite permission(s)
	PERM_IBMSA                 = 0x00000001 // hidden(non-configurable by user), only for IBM SA to set up with NV
	PERM_FED                   = 0x00000002 // hidden(non-configurable by user), only for fedAdmin role
	PERM_NV_RESOURCE           = 0x00000004 // hidden(non-configurable by user), for accessing controller/enforcer/scanner. No custom role can have this permission.
	PERM_RUNTIME_SCAN_BASIC    = 0x00000008 // platform/host/container scan. namespaced
	PERM_REG_SCAN              = 0x00000010 // namespaced
	PERM_CICD_SCAN             = 0x00000020 // (modify only) for scanning serverless & container image
	PERM_INFRA_BASIC           = 0x00000040 // for accessing host/platform/domain.
	PERM_NETWORK_POLICY_BASIC  = 0x00000080 // network policy. namespaced
	PERM_SYSTEM_POLICY_BASIC   = 0x00000100 // file/process profiles, response rules, dlp. namespaced
	PERM_GROUP_BASIC           = 0x00000200 // group. namespaced
	PERM_ADM_CONTROL           = 0x00000400
	PERM_COMPLIANCE_BASIC      = 0x00000800 // namespaced
	PERM_AUDIT_EVENTS          = 0x00001000 // (view only) namespaced
	PERM_SECURITY_EVENTS_BASIC = 0x00002000 // (view only) namespaced
	PERM_EVENTS                = 0x00004000 // (view only) namespaced
	PERM_AUTHENTICATION        = 0x00008000 // for ldap/SAML/OpenID configuration
	PERM_AUTHORIZATION         = 0x00010000 // for users/roles configuration. namespaced(None user who is admin of domain A can create/config/delete another None user who has role in dmain A). namespaced
	PERM_SYSTEM_CONFIG         = 0x00020000 // include license
	PERM_CLOUD                 = 0x00040000 // for cloud services like aws lambda
	PERM_WORKLOAD_BASIC        = 0x00080000 // workload(pod). namespaced
	PERM_VULNERABILITY         = 0x00100000 // for vulnerability profile

	// composite permissions (~= permanent boost)
	PERMS_RUNTIME_SCAN     = PERM_RUNTIME_SCAN_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC
	PERMS_RUNTIME_POLICIES = PERM_GROUP_BASIC | PERM_NETWORK_POLICY_BASIC | PERM_SYSTEM_POLICY_BASIC | PERM_WORKLOAD_BASIC
	PERMS_COMPLIANCE       = PERM_COMPLIANCE_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC
	PERMS_SECURITY_EVENTS  = PERM_SECURITY_EVENTS_BASIC | PERM_WORKLOAD_BASIC
	PERMS_PWD_PROFILE      = PERM_AUTHORIZATION | PERM_SYSTEM_CONFIG

	// We don't have a flag to differentiate a role is global role or domain role.
	// There are 3 use cases about role assignment:
	// 1. Reserved role admin/reader/(fedAdmin/fedReader) is assigned to user(global domain). The user can access controller/enforcer/scanner because those reserved roles have PERM_NV_RESOURCE permission
	// 2. Custom role A is assigned to a user(global domain). This user can not access controller/enforcer/scanner because no custom role has PERM_NV_RESOURCE permission
	// 3. A role is assigned to a user's domain.
	//    For 3, when this user tries to access any object, those permissions not supporting domain level are cleared in the sky first.
	//	  All resource types that do not support domain-level access have GetDomain() implemented telling that it cannot be accessed by namespace user.
	//    So how does this user access controller/enforcer/scanner (or some specific objects) in some APIs that require those info?
	//    Engineer should write the API handler to be like:
	//    3-1. Still do access control checking over the major permission(s) required for the API. (refer to compileApiUrisMapping() in controller/access/access.go)
	//	  3-2. Temporarily boost caller's permissions thru out the API for accessing controller/enforcer/scanner objects (or some specific objects). See CompileUriPermitsMapping() in controller/access/access.go
	//         (If the user's global role is 'none', it cannot be boosted on global role)

	// Effective permissions for domain admin/reader roles. Even for the reserved admin/reader roles assigned to domain, they cannot access controller/enforcer objects(PERM_NV_RESOURCE)
	PERMS_DOMAIN_READ = PERM_RUNTIME_SCAN_BASIC | PERM_REG_SCAN | PERM_NETWORK_POLICY_BASIC | PERM_SYSTEM_POLICY_BASIC | PERM_GROUP_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC |
		PERM_COMPLIANCE_BASIC | PERM_AUTHORIZATION | PERM_SYSTEM_CONFIG | PERM_AUDIT_EVENTS | PERM_SECURITY_EVENTS_BASIC | PERM_EVENTS // all read permissions a domain admin could have eventually
	PERMS_DOMAIN_WRITE = PERM_RUNTIME_SCAN_BASIC | PERM_REG_SCAN | PERM_NETWORK_POLICY_BASIC | PERM_SYSTEM_POLICY_BASIC | PERM_GROUP_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC |
		PERM_COMPLIANCE_BASIC | PERM_AUTHORIZATION // all write permissions a domain admin could have eventually
	PERMS_DOMAIN = PERMS_DOMAIN_READ | PERMS_DOMAIN_WRITE // sum of all permissions that are supporedt in domain

	// customer-configurable permissions: (PERM_NV_RESOURCE is non-customer-configurable permission)
	PERMS_GLOBAL_CONFIGURABLE_READ  = PERM_ADM_CONTROL | PERM_AUTHENTICATION | /*PERM_CLOUD |*/ PERM_INFRA_BASIC | PERM_VULNERABILITY | PERMS_DOMAIN_READ                                        // sum of all configurable(non-hidden) read permissions
	PERMS_GLOBAL_CONFIGURABLE_WRITE = PERM_ADM_CONTROL | PERM_AUTHENTICATION | /*PERM_CLOUD |*/ PERM_INFRA_BASIC | PERM_VULNERABILITY | PERMS_DOMAIN_WRITE | PERM_SYSTEM_CONFIG | PERM_CICD_SCAN // sum of all configurable(non-hidden) write permissions

	// Effective permissions for reserved fedAdmin/fedReader/admin/reader roles on global domain, only they have PERM_NV_RESOURCE permission
	PERMS_CLUSTER_READ  = PERM_NV_RESOURCE | PERMS_GLOBAL_CONFIGURABLE_READ
	PERMS_CLUSTER_WRITE = PERM_NV_RESOURCE | PERMS_GLOBAL_CONFIGURABLE_WRITE
	PERMS_CLUSTER       = PERMS_CLUSTER_READ | PERMS_CLUSTER_WRITE // sum of all permissions that are supported in cluster
	PERMS_FED_READ      = PERM_FED | PERMS_CLUSTER_READ
	PERMS_FED_WRITE     = PERM_FED | PERMS_CLUSTER_WRITE
	PERMS_FED           = PERMS_FED_READ | PERMS_FED_WRITE // sum of all permissions that are supported in fed
)

const ( // permission option id, id that ends with "_basic" is used by controller only
	PERM_IBMSA_ID                 = "ibmsa"       // hidden to user in 4.0
	PERM_FED_ID                   = "fed"         // hidden to user when it's not master cluster
	PERM_NV_RESOURCE_ID           = "nv_resource" // hidden to user in 4.0
	PERM_REG_SCAN_ID              = "reg_scan"
	PERM_CICD_SCAN_ID             = "ci_scan"
	PERM_ADM_CONTROL_ID           = "admctrl"
	PERM_AUDIT_EVENTS_ID          = "audit_events"
	PERM_EVENTS_ID                = "events"
	PERM_AUTHENTICATION_ID        = "authentication"
	PERM_AUTHORIZATION_ID         = "authorization"
	PERM_SYSTEM_CONFIG_ID         = "config"
	PERM_CLOUD_ID                 = "cloud"
	PERM_INFRA_BASIC_ID           = "infra_basic"
	PERM_RUNTIME_SCAN_BASIC_ID    = "rt_scan_basic"
	PERM_NETWORK_POLICY_BASIC_ID  = "nw_policy_basic"
	PERM_SYSTEM_POLICY_BASIC_ID   = "sys_policy_basic"
	PERM_GROUP_BASIC_ID           = "group_basic"
	PERM_COMPLIANCE_BASIC_ID      = "compliance_basic"
	PERM_SECURITY_EVENTS_BASIC_ID = "security_events_basic"
	PERM_WORKLOAD_BASIC_ID        = "workload_basic"
	PERM_VULNERABILITY_ID         = "vulnerability"

	// complex permissions, can be seen by customers
	PERMS_RUNTIME_SCAN_ID     = "rt_scan"         // == PERM_RUNTIME_SCAN_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC
	PERMS_RUNTIME_POLICIES_ID = "rt_policy"       // == PERM_GROUP_BASIC + PERM_NETWORK_POLICY_BASIC | PERM_SYSTEM_POLICY_BASIC | PERM_WORKLOAD_BASIC
	PERMS_COMPLIANCE_ID       = "compliance"      // == PERM_COMPLIANCE_BASIC | PERM_WORKLOAD_BASIC | PERM_INFRA_BASIC
	PERMS_SECURITY_EVENTS_ID  = "security_events" // == PERM_SECURITY_EVENTS_BASIC | PERM_WORKLOAD_BASIC
)

// If an object requires fed role for accessing, returns (_fedDomainSlice, _fedDomainSlice) in the object type's GetDomain(f GetAccessObjectFunc)
var _fedDomainSlice = []string{HiddenFedDomain}

const userRoleFedAdmin string = "fedAdmin"
const userRoleFedReader string = "fedReader"

func (o *CLUSUser) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Role != "" { // "" means api.UserRoleNone
		if o.Role == userRoleFedAdmin || o.Role == userRoleFedReader {
			return _fedDomainSlice, _fedDomainSlice
		}
		return nil, nil
	}

	// This is used for listing users. Config needs special handling.
	// If a user has global access, only global users can list it; otherwise,
	// anyone has the read right of one of user's domains can see that user.
	s := make(map[string]interface{})
	for _, domains := range o.RoleDomains {
		for _, d := range domains {
			s[d] = nil
		}
	}

	domains := make([]string, len(s))
	i := 0
	for d := range s {
		domains[i] = d
		i++
	}
	if len(domains) == 0 {
		domains = nil
	}
	return domains, nil
}

func (o *CLUSServer) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSSystemConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		return nil, nil
	}
}

// Modify/delete session can only be done by admin
func (o *CLUSSession) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSController) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSControllerConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAgent) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAgentConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSHost) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSWorkload) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Domain == "" {
		return nil, nil
	} else {
		return []string{o.Domain}, nil
	}
}

func (o *CLUSScanConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSScanner) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSComplianceProfile) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSVulnerabilityProfile) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSDomain) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{o.Name}, nil
}

func (o *CLUSSigstoreRootOfTrust) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSSigstoreVerifier) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSGroup) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		if o.Domain != "" {
			return []string{o.Domain}, nil
		}
		// it's not learned group
		if len(o.CreaterDomains) == 0 && (o.CfgType == UserCreated || o.CfgType == GroundCfg) && o.Kind == GroupKindAddress {
			return []string{AccessAllAsReader}, nil
		}
		return o.CreaterDomains, nil
	}
}

func (o *CLUSDerivedPolicyRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSPolicyRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else if f == nil {
		return nil, nil
	} else {
		var d1, d2 []string
		if fg := f(o.From); fg != nil && fg.(*CLUSGroup) != nil {
			d1, _ = fg.GetDomain(nil)
		}
		if tg := f(o.To); tg != nil && tg.(*CLUSGroup) != nil {
			d2, _ = tg.GetDomain(nil)
		}
		if len(d1) == 0 && len(d2) != 0 {
			d1 = []string{""}
		} else if len(d1) != 0 && len(d2) == 0 {
			d2 = []string{""}
		}
		return d1, d2
	}
}

func (o *CLUSProcessProfile) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else if f == nil {
		return nil, nil
	} else {
		if g := f(o.Group); g != nil && g.(*CLUSGroup) != nil {
			d, _ := g.GetDomain(nil)
			return d, nil
		}
		return nil, nil
	}
}

func (o *ProcRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Rule.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else if f == nil {
		return nil, nil
	} else {
		if g := f(o.Group); g != nil && g.(*CLUSGroup) != nil {
			d, _ := g.GetDomain(nil)
			return d, nil
		}
		return nil, nil
	}
}

func (o *CLUSBenchReport) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSCustomCheck) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if f != nil {
		if g := f(o.Name); g != nil && g.(*CLUSGroup) != nil { // CLUSCustomCheck.Name is group name
			d, _ := g.GetDomain(nil)
			return d, nil
		}
	}
	return nil, nil
}

func (o *CLUSResponseRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else if f == nil {
		return nil, nil
	} else {
		if g := f(o.Group); g != nil && g.(*CLUSGroup) != nil {
			d, _ := g.GetDomain(nil)
			return d, nil
		}
		return nil, nil
	}
}

func (o *CLUSRegistryConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg || strings.HasPrefix(o.Name, "fed.") {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		var domains []string
		// This includes both nil and empty array
		if len(o.Domains) != 0 {
			domains = o.Domains
		} else {
			domains = o.CreaterDomains
		}

		if o.Type == RegistryTypeOpenShift && len(o.ParsedFilters) > 0 {
			domainsMap := make(map[string]bool, len(domains)+len(o.ParsedFilters))
			for _, d := range domains {
				domainsMap[d] = true
			}
			for _, f := range o.ParsedFilters {
				var org string
				if f.Org != "" {
					org = f.Org
				} else if f.Repo == ".*" {
					org = AccessAllAsReader
				}
				if org != "" {
					if _, ok := domainsMap[f.Org]; !ok {
						domains = append(domains, org)
						domainsMap[org] = true
					}
				}
			}
		}

		return domains, nil
	}
}

// for registry filter in openshift registry only
func (o *CLUSRegistryFilter) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Org != "" {
		return []string{o.Org}, nil
	}
	return nil, nil
}

// for images in openshift registry only
func (o *CLUSImage) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Domain != "" {
		return []string{o.Domain}, nil
	}
	return nil, nil
}

// for scan report in openshift registry only
func (o *CLUSScanReport) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if ss := strings.Split(o.Repository, "/"); len(ss) > 1 && ss[0] != "" {
		return []string{ss[0]}, nil
	}
	return nil, nil
}

func (o *CLUSRegistryTypeDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSRegistryImageSummary) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	m := make(map[string]interface{})
	for _, img := range o.Images {
		if img.Domain != "" {
			m[img.Domain] = nil
		}
	}
	if len(m) == 0 {
		if f != nil {
			if r := f(o.RegName); r != nil && r.(*CLUSRegistryConfig) != nil {
				d, _ := r.GetDomain(nil)
				return d, nil
			}
		}
		return nil, nil
	}

	domains := make([]string, len(m))
	i := 0
	for d := range m {
		domains[i] = d
		i++
	}

	return domains, nil
}

func (o *CLUSFileMonitorProfile) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		if f != nil {
			if g := f(o.Group); g != nil && g.(*CLUSGroup) != nil {
				d, _ := g.GetDomain(nil)
				return d, nil
			}
		}
		return nil, nil
	}
}

func (o *CLUSAdmissionState) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAdmissionRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		return nil, nil
	}
}

func (o *CLUSAdmissionStats) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSFedMembership) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSDlpSensor) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSDlpRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSDlpGroup) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if f != nil {
		if g := f(o.Name); g != nil && g.(*CLUSGroup) != nil { // CLUSDlpGroup.Name is group name
			d, _ := g.GetDomain(nil)
			return d, nil
		}
	}
	return nil, nil
}

func (o *CLUSDerivedDlpRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSDerivedDlpRuleEntry) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSDerivedDlpRuleMac) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSWafSensor) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSWafRule) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSWafGroup) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if f != nil {
		if g := f(o.Name); g != nil && g.(*CLUSGroup) != nil { // CLUSWafGroup.Name is group name
			d, _ := g.GetDomain(nil)
			return d, nil
		}
	}
	return nil, nil
}

func (o *CLUSIBMSAConfig) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAwsResource) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAwsProjectCfg) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSAwsFuncScanOutputList) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSUserRole) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSPwdProfile) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSCIScanDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}

func (o *CLUSApplicationListDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSResponseRuleOptionsDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return []string{AccessAllAsReader}, nil
}

func (o *CLUSSnifferDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.WorkloadDomain == "" {
		return nil, nil
	} else {
		return []string{o.WorkloadDomain}, nil
	}
}

func (o *CLUSWorkloadScanDummy) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Domain == "" {
		return nil, nil
	} else {
		return []string{o.Domain}, nil
	}
}

func (o *CLUSWebhook) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.CfgType == FederalCfg {
		return _fedDomainSlice, _fedDomainSlice
	} else {
		return nil, nil
	}
}

func (o *CLUSApikey) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	if o.Role != "" { // "" means api.UserRoleNone
		if o.Role == userRoleFedAdmin || o.Role == userRoleFedReader {
			return _fedDomainSlice, _fedDomainSlice
		}
		return nil, nil
	}

	// This is used for listing users. Config needs special handling.
	// If a user has global access, only global users can list it; otherwise,
	// anyone has the read right of one of user's domains can see that user.
	s := make(map[string]interface{})
	for _, domains := range o.RoleDomains {
		for _, d := range domains {
			s[d] = nil
		}
	}

	domains := make([]string, len(s))
	i := 0
	for d := range s {
		domains[i] = d
		i++
	}
	if len(domains) == 0 {
		domains = nil
	}
	return domains, nil
}

func (r *CLUSRemoteRepository) GetDomain(f GetAccessObjectFunc) ([]string, []string) {
	return nil, nil
}
