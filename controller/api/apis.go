package api

import (
	"time"

	"github.com/neuvector/neuvector/share"
)

const RESTTokenHeader string = "X-Auth-Token"
const RESTNvPageHeader string = "X-Nv-Page"
const RESTRancherTokenHeader string = "X-R-Sess"
const RESTMaskedValue string = "The value is masked"
const RESTAPIKeyHeader string = "X-Auth-Apikey"

const RESTNvPageDashboard string = "dashboard"

// Don't modify value or reorder
const RESTErrNotFound int = 1
const RESTErrMethodNotAllowed int = 2
const RESTErrUnauthorized int = 3
const RESTErrOpNotAllowed int = 4
const RESTErrTooManyLoginUser int = 5
const RESTErrInvalidRequest int = 6
const RESTErrObjectNotFound int = 7
const RESTErrFailWriteCluster int = 8
const RESTErrFailReadCluster int = 9
const RESTErrClusterWrongData int = 10
const RESTErrClusterTimeout int = 11
const RESTErrNotEnoughFilter int = 12
const RESTErrDuplicateName int = 13
const RESTErrWeakPassword int = 14
const RESTErrInvalidName int = 15
const RESTErrObjectInuse int = 16
const RESTErrFailExport int = 17
const RESTErrFailImport int = 18
const RESTErrFailLockCluster int = 19
const RESTErrLicenseFail int = 20
const RESTErrAgentError int = 21
const RESTErrWorkloadNotRunning int = 22
const RESTErrCISBenchError int = 23
const RESTErrClusterRPCError int = 24
const RESTErrObjectAccessDenied int = 25
const RESTErrFailRepoScan int = 26
const RESTErrFailRegistryScan int = 27
const RESTErrFailKubernetesApi int = 28
const RESTErrProxyError int = 29 // Not used
const RESTErrAdmCtrlUnSupported int = 30
const RESTErrK8sNvRBAC int = 31
const RESTErrWebhookSvcForAdmCtrl int = 32
const RESTErrNoUpdatePermission int = 33
const RESTErrK8sApiSrvToWebhook int = 34
const RESTErrNvPermission int = 35
const RESTErrWebhookIsDisabled int = 36
const RESTErrRemoteUnauthorized int = 37
const RESTErrRemoterRequestFail int = 38
const RESTErrFedOperationFailed int = 39
const RESTErrFedJointUnreachable int = 40
const RESTErrFedDuplicateName int = 41
const RESTErrMasterUpgradeRequired int = 42
const RESTErrJointUpgradeRequired int = 43
const RESTErrIBMSATestFailed int = 44
const RESTErrIBMSABadDashboardURL int = 45
const RESTErrReadOnlyRules int = 46
const RESTErrUserLoginBlocked int = 47
const RESTErrPasswordExpired int = 48
const RESTErrPromoteFail int = 49
const RESTErrPlatformAuthDisabled int = 50
const RESTErrRancherUnauthorized int = 51

const FilterPrefix string = "f_"
const SortPrefix string = "s_"

const PageStart string = "start"
const PageLimit string = "limit"
const SupportFlag string = "support"
const BriefFlag string = "brief"
const VerboseFlag string = "verbose"
const RawFlag string = "raw"
const WithCapFlag string = "with_cap"
const FilterServerCategory string = "category"
const FilterServerType string = "type"
const QueryKeySection string = "section"
const QueryKeyView string = "view"
const QueryValueViewPod string = "pod"
const QueryValueViewPodOnly string = "pod_only"
const QueryKeyShow string = "show"
const QueryValueShowAccepted string = "accepted"
const QueryScope string = "scope"
const QueryDuration string = "token_duration"

const OPeq string = "eq"
const OPneq string = "neq"
const OPin string = "in"
const OPgt string = "gt"
const OPgte string = "gte"
const OPlt string = "lt"
const OPlte string = "lte"
const OPprefix string = "prefix"

const SortAsc string = "asc"
const SortDesc string = "desc"

const DefaultControllerRESTAPIPort = 10443

const UserRoleNone string = ""
const UserRoleAdmin string = "admin"
const UserRoleReader string = "reader"
const UserRoleCIOps string = "ciops"
const UserRoleIBMSA string = "ibmsa"                          // it's a hidden role. (no user has this role in kv)
const UserRoleImportStatus string = "_hidden_import_status_#" // it's a hidden role. (no user has this role in kv)

// the following role can only be interactively assigned on master cluster in a federation
const UserRoleFedAdmin string = "fedAdmin"
const UserRoleFedReader string = "fedReader"

const LearnedGroupPrefix string = "nv."
const LearnedSvcGroupPrefix string = "nv.ip."
const FederalGroupPrefix string = "fed."
const LearnedExternal string = "external"
const AllHostGroup string = "nodes"
const AllContainerGroup string = "containers"
const LearnedHostPrefix string = "Host:"
const LearnedWorkloadPrefix string = "Workload:"
const WorkloadTunnelIF string = "Workload:ingress"
const AddrGrpValVhPrefix string = "vh:"

const PolicyDomainNameMaxLen int = 256
const DlpSensorNameMaxLen int = 256
const DlpRuleNameMaxLen int = 256
const DlpRuleCommentMaxLen int = 256
const DlpRulePatternMaxNum int = 16
const DlpRulePatternMaxLen int = 512
const DlpRulePatternTotalMaxLen int = 1024

const ConfSectionAll string = "all"
const ConfSectionUser string = "user"
const ConfSectionPolicy string = "policy"
const ConfSectionConfig string = "config"

const PlatformContainerCore string = "core"
const PlatformContainerAddon string = "addon"

const DomainContainers string = "_containers"
const DomainNodes string = "_nodes"
const DomainImages string = "_images"

const AuthServerLocal string = "local"
const AuthServerPlatform string = "_platform_"

const (
	ServerCatAuth   string = "auth"
	ServerCatNotify string = "notify"
	ServerCatLog    string = "log"

	ServerTypeLDAP string = "ldap"
	ServerTypeSAML string = "saml"
	ServerTypeOIDC string = "oidc"

	ServerLDAPTypeOpenLDAP string = "OpenLDAP"
	ServerLDAPTypeMSAD     string = "MicrosoftAD"

	LDAPGroupMemberAttrOpenLDAP string = "memberUid"
	LDAPGroupMemberAttrMSAD     string = "member"

	LDAPUserNameAttrOpenLDAP string = "uid"
	LDAPUserNameAttrMSAD     string = "sAMAccountName"
)

const (
	BenchCategoryDocker = "docker"
	BenchCategoryKube   = "kubernetes"
	BenchCategoryCustom = "custom"

	BenchTypeMaster    = "master"
	BenchTypeWorker    = "worker"
	BenchTypeHost      = "host"
	BenchTypeContainer = "container"
)

const (
	SnifferStRunning string = "running"
	SnifferStStopped string = "stopped"
	SnifferStFailed  string = "failed"
)

const (
	ScanVulStatusUnpatched  string = "unpatched"
	ScanVulStatusFixExists  string = "fix exists"
	ScanVulStatusWillNotFix string = "will not fix"
	ScanVulStatusUnaffected string = "unaffected"
)

var RESTTimeFomat string = time.RFC3339

func RESTTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

type RESTError struct {
	Code            int                  `json:"code"`
	Error           string               `json:"error"`
	Message         string               `json:"message"`
	PwdProfileBasic *RESTPwdProfileBasic `json:"password_profile_basic,omitempty"`
	ImportTaskData  *RESTImportTaskData  `json:"import_task_data,omitempty"`
}

type RESTErrorReadOnlyRules struct {
	RESTError
	ReadOnlyRuleIDs []uint32 `json:"read_only_rule_ids"`
}

const UserIdleTimeoutMax uint32 = 3600
const UserIdleTimeoutMin uint32 = 30

type RESTAuthPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RESTAuthToken struct {
	Token    string `json:"token"`
	State    string `json:"state"`
	Redirect string `json:"redirect_endpoint"`
}

type RESTAuthData struct {
	ClientIP string            `json:"client_ip"`
	Password *RESTAuthPassword `json:"password,omitempty"`
	Token    *RESTAuthToken    `json:"Token,omitempty"`
}

type RESTFedAuthData struct {
	ClientIP       string `json:"client_ip"`
	MasterUsername string `json:"master_username"`
	JointUsername  string `json:"joint_username"`
	MasterToken    string `json:"master_token"`
}

type RESTTokenRedirect struct {
	Redirect string `json:"redirect_endpoint"`
}

type RESTToken struct {
	Token         string                           `json:"token"`
	GlobalPermits []*RESTRolePermission            `json:"global_permissions"`
	DomainPermits map[string][]*RESTRolePermission `json:"domain_permissions"` // domain -> permissions
	RESTUser
}

type RESTTokenData struct {
	Token               *RESTToken `json:"token"`
	PwdDaysUntilExpire  int        `json:"password_days_until_expire"`  // negative means we don't know it (for ldap/saml/oidc login).
	PwdHoursUntilExpire int        `json:"password_hours_until_expire"` // the hours part beyond PwdDaysUntilExpire, 0 ~ 23
	// If both PwdDaysUntilExpire/PwdDaysUntilExpire are 0, it means the password is already expired
}

type RESTTokenAuthServer struct {
	Name string `json:"server_name"`
	Type string `json:"server_type"`
}

type RESTTokenAuthServersData struct {
	Servers []*RESTTokenAuthServer `json:"servers"`
}

type RESTTokenAuthServerRedirect struct {
	Name        string `json:"server_name"`
	Type        string `json:"server_type"`
	RedirectURL string `json:"redirect_url"`
}

type RESTTokenAuthServersRedirectData struct {
	Redirect *RESTTokenAuthServerRedirect `json:"redirect"`
}

// Used by CLI to set one role mapping at a time.
type RESTServerRoleGroupsConfig struct {
	Name   string   `json:"name"`
	Role   string   `json:"role"`
	Groups []string `json:"groups"`
}

type RESTServerRoleGroupsConfigData struct {
	Config *RESTServerRoleGroupsConfig `json:"config"`
}

// Used by CLI to set one group's role mapping at a time.
type RESTServerGroupRoleDomainsConfig struct {
	Name             string                  `json:"name"` // server name
	GroupRoleMapping *share.GroupRoleMapping `json:"mapped_roles,omitempty"`
}

type RESTServerGroupRoleDomainsConfigData struct {
	Config *RESTServerGroupRoleDomainsConfig `json:"config"`
}

// Used by CLI to set mapped groups order.
type RESTServerGroupsOrderConfig struct {
	Name   string   `json:"name"`   // server name
	Groups []string `json:"groups"` // groups in mapping order
}

type RESTServerGroupsOrderConfigData struct {
	Config *RESTServerGroupsOrderConfig `json:"config"`
}

type RESTServerGroupRoleConfigData struct {
	Groups []string `json:"groups"`
}

type RESTServerLDAP struct {
	Type            string `json:"directory"`
	Hostname        string `json:"hostname"`
	Port            uint16 `json:"port"`
	SSL             bool   `json:"ssl"`
	BaseDN          string `json:"base_dn"`
	BindDN          string `json:"bind_dn"`
	BindPasswd      string `json:"bind_password,cloak"`
	GroupMemberAttr string `json:"group_member_attr"`
	UserNameAttr    string `json:"username_attr"`

	Enable           bool                      `json:"enable"`
	DefaultRole      string                    `json:"default_role"`
	RoleGroups       map[string][]string       `json:"role_groups,omitempty"`        // role -> groups
	GroupMappedRoles []*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
}

type RESTX509CertInfo struct {
	X509Cert          string `json:"x509_cert"`
	IssuerCommonName  string `json:"issuer_cn"`
	SubjectCommonName string `json:"subject_cn"`
	ValidityNotAfter  uint64 `json:"subject_notafter"`
}

type RESTServerSAML struct {
	SSOURL     string             `json:"sso_url"`
	Issuer     string             `json:"issuer"`
	X509Cert   string             `json:"x509_cert,cloak"`
	GroupClaim string             `json:"group_claim"`
	X509Certs  []RESTX509CertInfo `json:"x509_certs"`

	Enable           bool                      `json:"enable"`
	DefaultRole      string                    `json:"default_role"`
	RoleGroups       map[string][]string       `json:"role_groups,omitempty"`        // role -> groups
	GroupMappedRoles []*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
}

type RESTServerOIDC struct {
	Issuer       string   `json:"issuer"`
	AuthURL      string   `json:"authorization_endpoint"`
	TokenURL     string   `json:"token_endpoint"`
	UserInfoURL  string   `json:"user_info_endpoint"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,cloak"`
	GroupClaim   string   `json:"group_claim"`
	Scopes       []string `json:"scopes"`

	Enable           bool                      `json:"enable"`
	DefaultRole      string                    `json:"default_role"`
	RoleGroups       map[string][]string       `json:"role_groups,omitempty"`        // role -> groups
	GroupMappedRoles []*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
}

type RESTServer struct {
	Name string          `json:"server_name"`
	Type string          `json:"server_type"`
	LDAP *RESTServerLDAP `json:"ldap,omitempty"`
	SAML *RESTServerSAML `json:"saml,omitempty"`
	OIDC *RESTServerOIDC `json:"oidc,omitempty"`
}

type RESTServerData struct {
	Server *RESTServer `json:"server"`
}

type RESTMappableRoles struct {
	DefaultRoles     []string `json:"default_roles"`
	GroupRoles       []string `json:"group_roles"`        // mappable roles for group's global domain
	GroupDomainRoles []string `json:"group_domain_roles"` // mappable roles for group's namespaces
}

type RESTServersData struct {
	Servers       []*RESTServer      `json:"servers"`
	MappableRoles *RESTMappableRoles `json:"mappable_roles"`
}

type RESTServerLDAPConfig struct {
	Type            *string `json:"directory,omitempty"`
	Hostname        *string `json:"hostname,omitempty"`
	Port            *uint16 `json:"port,omitempty"`
	SSL             *bool   `json:"ssl,omitempty"`
	BaseDN          *string `json:"base_dn,omitempty"`
	BindDN          *string `json:"bind_dn,omitempty"`
	BindPasswd      *string `json:"bind_password,cloak,omitempty"`
	GroupMemberAttr *string `json:"group_member_attr,omitempty"`
	UserNameAttr    *string `json:"username_attr,omitempty"`

	Enable           *bool                      `json:"enable,omitempty"`
	DefaultRole      *string                    `json:"default_role,omitempty"`
	RoleGroups       *map[string][]string       `json:"role_groups,omitempty"`        // role -> groups. deprecated since 4.2
	GroupMappedRoles *[]*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
}

type RESTServerLDAPConfigCfgMap struct {
	RESTServerLDAPConfig
	AlwaysReload bool `json:"always_reload"`
}

type RESTServerSAMLConfig struct {
	SSOURL     *string `json:"sso_url"`
	Issuer     *string `json:"issuer"`
	X509Cert   *string `json:"x509_cert,cloak"`
	GroupClaim *string `json:"group_claim"`

	Enable           *bool                      `json:"enable,omitempty"`
	DefaultRole      *string                    `json:"default_role,omitempty"`
	RoleGroups       *map[string][]string       `json:"role_groups,omitempty"`        // role -> groups. deprecated since 4.2
	GroupMappedRoles *[]*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
	X509CertExtra    *[]string                  `json:"x509_cert_extra,omitempty"`
}

type RESTServerSAMLConfigCfgMap struct {
	RESTServerSAMLConfig
	AlwaysReload bool `json:"always_reload"`
}

type RESTServerOIDCConfig struct {
	Issuer       *string   `json:"issuer"`
	ClientID     *string   `json:"client_id"`
	ClientSecret *string   `json:"client_secret,cloak"`
	GroupClaim   *string   `json:"group_claim"`
	Scopes       *[]string `json:"scopes,omitempty"`

	Enable           *bool                      `json:"enable"`
	DefaultRole      *string                    `json:"default_role"`
	RoleGroups       *map[string][]string       `json:"role_groups,omitempty"`        // role -> groups. deprecated since 4.2
	GroupMappedRoles *[]*share.GroupRoleMapping `json:"group_mapped_roles,omitempty"` // group -> (role -> domains)
}

type RESTServerOIDCConfigCfgMap struct {
	RESTServerOIDCConfig
	AlwaysReload bool `json:"always_reload"`
}

type RESTServerConfig struct {
	Name string                `json:"name"`
	LDAP *RESTServerLDAPConfig `json:"ldap,omitempty"`
	SAML *RESTServerSAMLConfig `json:"saml,omitempty"`
	OIDC *RESTServerOIDCConfig `json:"oidc,omitempty"`
}

type RESTServerConfigData struct {
	Config *RESTServerConfig `json:"config"`
}

type RESTServerLDAPTest struct {
	Username string `json:"username"`
	Password string `json:"password,cloak"`
}

type RESTServerTest struct {
	Name     string                `json:"name,omitempty"` // either name or one of server configs must present
	LDAP     *RESTServerLDAPConfig `json:"ldap,omitempty"`
	TestLDAP *RESTServerLDAPTest   `json:"test_ldap,omitempty"`
}

type RESTServerTestData struct {
	Test *RESTServerTest `json:"test"`
}

type RESTServerTestResult struct {
	Groups []string `json:"groups"`
}

type RESTServerTestResultData struct {
	Result *RESTServerTestResult `json:"result"`
}

type RESTEULA struct {
	Accepted bool `json:"accepted"`
}

type RESTEULAData struct {
	EULA *RESTEULA `json:"eula"`
}

type RESTList struct {
	Application  []string        `json:"application,omitempty"`
	RegistryType []string        `json:"registry_type,omitempty"`
	Compliance   []RESTBenchMeta `json:"compliance,omitempty"`
}

type RESTListData struct {
	List *RESTList `json:"list"`
}

type RESTGroupExport struct {
	Groups     []string `json:"groups"`
	PolicyMode string   `json:"policy_mode,omitempty"`
}

type RESTAdmCtrlRulesExport struct {
	ExportConfig bool     `json:"export_config"`
	IDs          []uint32 `json:"ids"` // used when ExportRules is true
}

type RESTWafSensorExport struct {
	Names []string `json:"names"`
}

type RESTUser struct {
	Fullname              string              `json:"fullname"`
	Server                string              `json:"server"`
	Username              string              `json:"username"`
	Password              string              `json:"password,cloak"`
	EMail                 string              `json:"email"`
	Role                  string              `json:"role"`
	Timeout               uint32              `json:"timeout"`
	Locale                string              `json:"locale"`
	DefaultPWD            bool                `json:"default_password"`       // If the user is using default password
	ModifyPWD             bool                `json:"modify_password"`        // if the password should be modified
	RoleDomains           map[string][]string `json:"role_domains,omitempty"` // role -> domains
	LastLoginTimeStamp    int64               `json:"last_login_timestamp"`
	LastLoginAt           string              `json:"last_login_at"`
	LoginCount            uint32              `json:"login_count"`
	BlockedForFailedLogin bool                `json:"blocked_for_failed_login"`     // if the user is blocked for too mnay failed login
	BlockedForPwdExpired  bool                `json:"blocked_for_password_expired"` // if the user is blocked for expired password
}

type RESTUserConfig struct {
	Fullname    string               `json:"fullname"`
	Password    *string              `json:"password,omitempty,cloak"`
	NewPassword *string              `json:"new_password,omitempty,cloak"`
	PwdProfile  *string              `json:"pwd_profile"`
	EMail       *string              `json:"email,omitempty"`
	Role        *string              `json:"role,omitempty"`
	Timeout     *uint32              `json:"timeout,omitempty"`
	Locale      *string              `json:"locale,omitempty"`
	RoleDomains *map[string][]string `json:"role_domains,omitempty"` // role -> domains
}

type RESTUsersData struct {
	Users       []*RESTUser `json:"users"`
	GlobalRoles []string    `json:"global_roles"`
	DomainRoles []string    `json:"domain_roles"`
}

type RESTUsersDataCfgMap struct {
	RESTUsersData
	AlwaysReload bool `json:"always_reload"`
}

type RESTUserData struct {
	User *RESTUser `json:"user"`
}

type RESTSelfUserData struct {
	User                *RESTUser                        `json:"user"`
	PwdDaysUntilExpire  int                              `json:"password_days_until_expire"`  // negative means password never expires
	PwdHoursUntilExpire int                              `json:"password_hours_until_expire"` // the hours part beyond PwdDaysUntilExpire, 0 ~ 23
	GlobalPermits       []*RESTRolePermission            `json:"global_permissions,omitempty"`
	DomainPermits       map[string][]*RESTRolePermission `json:"domain_permissions,omitempty"` // domain -> permissions
}

type RESTUserConfigData struct {
	Config *RESTUserConfig `json:"config"`
}

type RESTUserPwdConfig struct {
	Fullname         string  `json:"fullname"`
	ClearFailedLogin *bool   `json:"clear_failed_login,omitempty"`
	NewPassword      *string `json:"new_password,omitempty,cloak"`
}

type RESTUserPwdConfigData struct {
	Config *RESTUserPwdConfig `json:"config"`
}

// password profile
type RESTPwdProfile struct {
	Name                        string `json:"name"`
	Comment                     string `json:"comment"`
	MinLen                      int    `json:"min_len"`
	MinUpperCount               int    `json:"min_uppercase_count"` // for alphabet characters
	MinLowerCount               int    `json:"min_lowercase_count"` // for alphabet characters
	MinDigitCount               int    `json:"min_digit_count"`
	MinSpecialCount             int    `json:"min_special_count"`
	EnablePwdExpiration         bool   `json:"enable_password_expiration"`
	PwdExpireAfterDays          int    `json:"password_expire_after_days"` // must be > 0 when EnablePwdExpiration is true
	EnablePwdHistory            bool   `json:"enable_password_history"`
	PwdHistoryCount             int    `json:"password_keep_history_count"`
	EnableBlockAfterFailedLogin bool   `json:"enable_block_after_failed_login"` // for "Block X minutes after N times consecutive failed attempts"
	BlockAfterFailedCount       int    `json:"block_after_failed_login_count"`  // must be > 0 when EnableBlockAfterFailedLogin is true
	BlockMinutes                int    `json:"block_minutes"`                   // must be > 0 when EnableBlockAfterFailedLogin is true
	SessionTimeout              uint32 `json:"session_timeout"`                 // for default user session timeout (in seconds)
}

type RESTPwdProfileBasic struct {
	MinLen          int `json:"min_len"`
	MinUpperCount   int `json:"min_uppercase_count"` // for alphabet characters
	MinLowerCount   int `json:"min_lowercase_count"` // for alphabet characters
	MinDigitCount   int `json:"min_digit_count"`
	MinSpecialCount int `json:"min_special_count"`
}

type RESTPwdProfileConfig struct {
	Name                        string  `json:"name"`
	Active                      *bool   `json:"active,omitempty"`
	Comment                     *string `json:"comment,omitempty"`
	MinLen                      *int    `json:"min_len,omitempty"`
	MinUpperCount               *int    `json:"min_uppercase_count,omitempty"` // for alphabet characters
	MinLowerCount               *int    `json:"min_lowercase_count,omitempty"` // for alphabet characters
	MinDigitCount               *int    `json:"min_digit_count,omitempty"`     // for 0 ~ 9
	MinSpecialCount             *int    `json:"min_special_count,omitempty"`   // !”#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	EnablePwdExpiration         *bool   `json:"enable_password_expiration,omitempty"`
	PwdExpireAfterDays          *int    `json:"password_expire_after_days,omitempty"` // must be > 0 when EnablePwdExpiration is true
	EnablePwdHistory            *bool   `json:"enable_password_history,omitempty"`
	PwdHistoryCount             *int    `json:"password_keep_history_count,omitempty"`
	EnableBlockAfterFailedLogin *bool   `json:"enable_block_after_failed_login,omitempty"` // for "Block X minutes after N times consecutive failed attempts"
	BlockAfterFailedCount       *int    `json:"block_after_failed_login_count,omitempty"`  // must be > 0 when EnableBlockAfterFailedLogin is true
	BlockMinutes                *int    `json:"block_minutes,omitempty"`                   // must be > 0 when EnableBlockAfterFailedLogin is true
	SessionTimeout              *uint32 `json:"session_timeout,omitempty"`                 // for default user session timeout (in seconds)
}

type RESTPwdProfilesData struct {
	PwdProfiles       []*RESTPwdProfile `json:"pwd_profiles"`
	ActiveProfileName string            `json:"active_profile_name"`
}

type RESTPwdProfilesDataCfgMap struct {
	RESTPwdProfilesData
	AlwaysReload bool `json:"always_reload"`
}

type RESTPwdProfileData struct {
	PwdProfile *RESTPwdProfile `json:"pwd_profile"`
}

type RESTPwdProfileConditional struct {
	Name                        *string `json:"name,omitempty"`
	Comment                     *string `json:"comment,omitempty"`
	MinLen                      int     `json:"min_len"`
	MinUpperCount               int     `json:"min_uppercase_count"` // for alphabet characters
	MinLowerCount               int     `json:"min_lowercase_count"` // for alphabet characters
	MinDigitCount               int     `json:"min_digit_count"`
	MinSpecialCount             int     `json:"min_special_count"`
	EnablePwdExpiration         *bool   `json:"enable_password_expiration,omitempty"`
	PwdExpireAfterDays          *int    `json:"password_expire_after_days,omitempty"` // must be > 0 when EnablePwdExpiration is true
	EnablePwdHistory            *bool   `json:"enable_password_history,omitempty"`
	PwdHistoryCount             *int    `json:"password_keep_history_count,omitempty"`
	EnableBlockAfterFailedLogin *bool   `json:"enable_block_after_failed_login,omitempty"` // for "Block X minutes after N times consecutive failed attempts"
	BlockAfterFailedCount       *int    `json:"block_after_failed_login_count,omitempty"`  // must be > 0 when EnableBlockAfterFailedLogin is true
	BlockMinutes                *int    `json:"block_minutes,omitempty"`                   // must be > 0 when EnableBlockAfterFailedLogin is true
	SessionTimeout              *uint32 `json:"session_timeout,omitempty"`                 // for default user session timeout (in seconds)
}

type RESTPwdProfileDataConditional struct {
	PwdProfile *RESTPwdProfileConditional `json:"pwd_profile"`
}

type RESTPwdProfileConfigData struct {
	Config *RESTPwdProfileConfig `json:"config"`
}

// Used by CLI to set one role domain at a time.
type RESTUserRoleDomainsConfig struct {
	Fullname string   `json:"fullname"`
	Role     string   `json:"role"`
	Domains  []string `json:"domains"`
}

type RESTUserRoleDomainsConfigData struct {
	Config *RESTUserRoleDomainsConfig `json:"config"`
}

type RESTProtoPort struct {
	IPProto uint8  `json:"ip_proto"`
	Port    uint16 `json:"port"`
}

type RESTIPAddr struct {
	IP       string `json:"ip"`
	IPPrefix int    `json:"ip_prefix"`
	Gateway  string `json:"gateway"`
}

type RESTIPPort struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type RESTHost struct {
	Name              string                   `json:"name"`
	ID                string                   `json:"id"`
	Runtime           string                   `json:"runtime"`
	RuntimeVer        string                   `json:"runtime_version"`
	RuntimeAPIVer     string                   `json:"runtime_api_version"`
	Platform          string                   `json:"platform"`
	OS                string                   `json:"os"`
	Kernel            string                   `json:"kernel"`
	CPUs              int64                    `json:"cpus"`
	Memory            int64                    `json:"memory"`
	CGroupVersion     int                      `json:"cgroup_version"`
	Containers        int                      `json:"containers"`
	Pods              int                      `json:"pods"`
	Ifaces            map[string][]*RESTIPAddr `json:"interfaces"`
	State             string                   `json:"state"`
	CapDockerBench    bool                     `json:"cap_docker_bench"`
	CapKubeBench      bool                     `json:"cap_kube_bench"`
	DockerBenchStatus string                   `json:"docker_bench_status,omitempty"`
	KubeBenchStatus   string                   `json:"kube_bench_status,omitempty"`
	PolicyMode        string                   `json:"policy_mode"`
	ProfileMode       string                   `json:"profile_mode"`
	ScanSummary       *RESTScanBrief           `json:"scan_summary"`
	StorageDriver     string                   `json:"storage_driver"`
	Labels            map[string]string        `json:"labels"`
	Annotations       map[string]string        `json:"annotations"`
}

type RESTHostsData struct {
	Hosts []*RESTHost `json:"hosts"`
}

type RESTHostData struct {
	Host *RESTHost `json:"host"`
}

// Although we can define shared fields in RESTAgent and RESTController in a common
// struct, it would make filter not working
type RESTAgent struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	HostName    string            `json:"host_name"`
	HostID      string            `json:"host_id"`
	Ver         string            `json:"version"`
	Labels      map[string]string `json:"labels"`
	Domain      string            `json:"domain"`
	PidMode     string            `json:"pid_mode"`
	NetworkMode string            `json:"network_mode"`
	CreatedAt   string            `json:"created_at"`
	StartedAt   string            `json:"started_at"`
	JoinedAt    string            `json:"joined_at"`
	MemoryLimit int64             `json:"memory_limit"`
	CPUs        string            `json:"cpus"`
	ClusterIP   string            `json:"cluster_ip"`
	State       string            `json:"connection_state"`
	DisconnAt   string            `json:"disconnected_at"`
	NvProtect   bool              `json:"nv_protect"`
}

const StateOnline string = "connected"
const StateOffline string = "disconnected"
const StateLeft string = "stopped"
const StateUnmanaged string = "unmanaged"

type RESTAgentsData struct {
	Agents []*RESTAgent `json:"enforcers"`
}

type RESTAgentData struct {
	Agent *RESTAgent `json:"enforcer"`
}

type RESTController struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	DisplayName       string            `json:"display_name"`
	HostName          string            `json:"host_name"`
	HostID            string            `json:"host_id"`
	Ver               string            `json:"version"`
	Labels            map[string]string `json:"labels"`
	Domain            string            `json:"domain"`
	CreatedAt         string            `json:"created_at"`
	StartedAt         string            `json:"started_at"`
	JoinedAt          string            `json:"joined_at"`
	MemoryLimit       int64             `json:"memory_limit"`
	CPUs              string            `json:"cpus"`
	ClusterIP         string            `json:"cluster_ip"`
	Leader            bool              `json:"leader"`
	State             string            `json:"connection_state"`
	DisconnAt         string            `json:"disconnected_at"`
	OrchConnStatus    string            `json:"orch_conn_status"`
	OrchConnLastError string            `json:"orch_conn_last_error"`
}

type RESTControllersData struct {
	Controllers []*RESTController `json:"controllers"`
}

type RESTControllerData struct {
	Controller *RESTController `json:"controller"`
}

type RESTDomain struct {
	Name             string            `json:"name"`
	Workloads        int               `json:"workloads"`
	RunningWorkloads int               `json:"running_workloads"`
	RunningPods      int               `json:"running_pods"`
	Services         int               `json:"services"`
	Tags             []string          `json:"tags"`
	Labels           map[string]string `json:"labels"`
}

type RESTDomainsData struct {
	Domains      []*RESTDomain `json:"domains"`
	TagPerDomain bool          `json:"tag_per_domain"`
}

type RESTDomainEntryConfig struct {
	Name string    `json:"name"`
	Tags *[]string `json:"tags,omitempty"`
}

type RESTDomainEntryConfigData struct {
	Config *RESTDomainEntryConfig `json:"config"`
}

type RESTDomainConfig struct {
	TagPerDomain *bool `json:"tag_per_domain,omitempty"`
}

type RESTDomainConfigData struct {
	Config *RESTDomainConfig `json:"config"`
}

type RESTWorkloadPorts struct {
	RESTProtoPort
	HostIP   string `json:"host_ip"`
	HostPort uint16 `json:"host_port"`
}

const WorkloadStateExit string = "exit"
const WorkloadStateUnmanaged string = "unmanaged"
const WorkloadStateDiscover string = "discover"
const WorkloadStateMonitor string = "monitor"
const WorkloadStateProtect string = "protect"
const WorkloadStateQuarantine string = "quarantined"

type RESTIDName struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	PolicyMode  string   `json:"policy_mode"`
	Domains     []string `json:"domains"`
}

type RESTWorkloadBrief struct { // obsolete, use v2 instead
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	DisplayName        string               `json:"display_name"`
	PodName            string               `json:"pod_name"`
	HostName           string               `json:"host_name"`
	HostID             string               `json:"host_id"`
	Image              string               `json:"image"`
	ImageID            string               `json:"image_id"`
	PlatformRole       string               `json:"platform_role"`
	Domain             string               `json:"domain"`
	State              string               `json:"state"`
	Service            string               `json:"service"`
	Author             string               `json:"author"`
	ServiceGroup       string               `json:"service_group"`
	ShareNSWith        string               `json:"share_ns_with,omitempty"`
	CapSniff           bool                 `json:"cap_sniff"`
	CapQuar            bool                 `json:"cap_quarantine"`
	CapChgMode         bool                 `json:"cap_change_mode"`
	PolicyMode         string               `json:"policy_mode"`
	ProfileMode        string               `json:"profile_mode"`
	ScanSummary        *RESTScanBrief       `json:"scan_summary"`
	Children           []*RESTWorkloadBrief `json:"children"`
	QuarReason         string               `json:"quarantine_reason,omitempty"`
	ServiceMesh        bool                 `json:"service_mesh"`
	ServiceMeshSidecar bool                 `json:"service_mesh_sidecar"`
	Privileged         bool                 `json:"privileged"`
	RunAsRoot          bool                 `json:"run_as_root"`
	BaselineProfile    string               `json:"baseline_profile"`
}

type RESTWorkload struct { // obsolete, use v2 instead
	RESTWorkloadBrief
	AgentID        string                   `json:"enforcer_id"`
	AgentName      string                   `json:"enforcer_name"`
	NetworkMode    string                   `json:"network_mode"`
	CreatedAt      string                   `json:"created_at"`
	StartedAt      string                   `json:"started_at"`
	FinishedAt     string                   `json:"finished_at"`
	Running        bool                     `json:"running"`
	SecuredAt      string                   `json:"secured_at"`
	ExitCode       int                      `json:"exit_code"`
	Ifaces         map[string][]*RESTIPAddr `json:"interfaces"`
	Ports          []*RESTWorkloadPorts     `json:"ports"`
	Labels         map[string]string        `json:"labels"`
	Applications   []string                 `json:"applications"`
	MemoryLimit    int64                    `json:"memory_limit"`
	CPUs           string                   `json:"cpus"`
	Children       []*RESTWorkload          `json:"children"`
	ServiceAccount string                   `json:"service_account"`
}

type RESTWorkloadDetail struct {
	RESTWorkload
	Groups   []string              `json:"groups"`
	AppPorts map[string]string     `json:"app_ports"`
	Children []*RESTWorkloadDetail `json:"children"`
}

type RESTWorkloadsData struct {
	Workloads []*RESTWorkload `json:"workloads"`
}

type RESTWorkloadBriefV2 struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	DisplayName  string `json:"display_name"`
	HostName     string `json:"host_name"`
	HostID       string `json:"host_id"`
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	Domain       string `json:"domain"`
	State        string `json:"state"`
	Service      string `json:"service"`
	Author       string `json:"author"`
	ServiceGroup string `json:"service_group"`
}

type RESTWorkloadSecurityV2 struct {
	CapSniff           bool           `json:"cap_sniff"`
	CapQuar            bool           `json:"cap_quarantine"`
	CapChgMode         bool           `json:"cap_change_mode"`
	ServiceMesh        bool           `json:"service_mesh"`
	ServiceMeshSidecar bool           `json:"service_mesh_sidecar"`
	PolicyMode         string         `json:"policy_mode"`
	ProfileMode        string         `json:"profile_mode"`
	BaselineProfile    string         `json:"baseline_profile"`
	QuarReason         string         `json:"quarantine_reason,omitempty"`
	ScanSummary        *RESTScanBrief `json:"scan_summary"`
}

type RESTWorkloadRtAttribesV2 struct {
	PodName        string                   `json:"pod_name"`
	ShareNSWith    string                   `json:"share_ns_with,omitempty"`
	Privileged     bool                     `json:"privileged"`
	RunAsRoot      bool                     `json:"run_as_root"`
	Labels         map[string]string        `json:"labels"`
	MemoryLimit    int64                    `json:"memory_limit"`
	CPUs           string                   `json:"cpus"`
	ServiceAccount string                   `json:"service_account"`
	NetworkMode    string                   `json:"network_mode"`
	Ifaces         map[string][]*RESTIPAddr `json:"interfaces"`
	Ports          []*RESTWorkloadPorts     `json:"ports"`
	Applications   []string                 `json:"applications"`
}

type RESTWorkloadV2 struct {
	WlBrief        RESTWorkloadBriefV2      `json:"brief"`
	WlSecurity     RESTWorkloadSecurityV2   `json:"security"`
	WlRtAttributes RESTWorkloadRtAttribesV2 `json:"rt_attributes"`
	Children       []*RESTWorkloadV2        `json:"children"`
	AgentID        string                   `json:"enforcer_id"`
	AgentName      string                   `json:"enforcer_name"`
	PlatformRole   string                   `json:"platform_role"`
	CreatedAt      string                   `json:"created_at"`
	StartedAt      string                   `json:"started_at"`
	FinishedAt     string                   `json:"finished_at"`
	Running        bool                     `json:"running"`
	SecuredAt      string                   `json:"secured_at"`
	ExitCode       int                      `json:"exit_code"`
	//ChildrenBrief  []*RESTWorkloadBrief     `json:"children_brief"`
}

type RESTWorkloadDetailMiscV2 struct {
	Groups   []string                `json:"groups"`
	AppPorts map[string]string       `json:"app_ports"`
	Children []*RESTWorkloadDetailV2 `json:"children"`
}

type RESTWorkloadDetailV2 struct {
	RESTWorkloadV2
	Misc RESTWorkloadDetailMiscV2 `json:"misc"`
}

type RESTWorkloadsDataV2 struct {
	Workloads []*RESTWorkloadV2 `json:"workloads"` // for pagination, manager needs each layer in workload object to have <22 members
}

type RESTWorkloadDetailData struct {
	Workload *RESTWorkloadDetail `json:"workload"`
}

type RESTWorkloadDetailDataV2 struct {
	Workload *RESTWorkloadDetailV2 `json:"workload"`
}

type RESTWorkloadsBriefData struct {
	Workloads []*RESTWorkloadBrief `json:"workloads"`
}

const EndpointIngress string = "ingress"

const EndpointKindExternal string = "external"
const EndpointKindContainer string = "container"
const EndpointKindHostIP string = "node_ip"
const EndpointKindWorkloadIP string = "workload_ip"
const EndpointKindAddrGroup string = "address"
const EndpointKindIPSvcGroup string = "ip_service"
const EndpointKindService string = "nv_service" // Used in collapse view

// The difference between Endpoint list and Workload Brief list is, endpoint list
// container nv.host, nv.workload and nv.external.
type RESTConversationEndpoint struct {
	Kind string `json:"kind"`
	RESTWorkloadBrief
}

type RESTConversationEndpointData struct {
	Endpoints []*RESTConversationEndpoint `json:"endpoints"`
}

type RESTConversationEndpointConfig struct {
	ID          string  `json:"id"`
	DisplayName *string `json:"display_name,omitempty"` // Add an alias, empty string to reset to original DisplayName
}

type RESTConversationEndpointConfigData struct {
	Config *RESTConversationEndpointConfig `json:"config"`
}

type RESTConversationReport struct {
	Bytes        uint64   `json:"bytes"`
	Sessions     uint32   `json:"sessions"`
	Severity     string   `json:"severity"`
	PolicyAction string   `json:"policy_action"`
	Protos       []string `json:"protocols,omitempty"`
	Apps         []string `json:"applications,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	SidecarProxy bool     `json:"sidecar_proxy,omitempty"`
	EventType    []string `json:"event_type,omitempty"`
	XffEntry     bool     `json:"xff_entry,omitempty"` //has xff entry
}

type RESTConversation struct {
	From *RESTConversationEndpoint `json:"from"`
	To   *RESTConversationEndpoint `json:"to"`
	*RESTConversationReport
}

type RESTConversationCompact struct {
	From string `json:"from"`
	To   string `json:"to"`
	*RESTConversationReport
}

type RESTConversationEntry struct {
	Bytes        uint64 `json:"bytes"`
	Sessions     uint32 `json:"sessions"`
	Port         string `json:"port"`
	MappedPort   string `json:"mapped_port"`
	Application  string `json:"application"`
	Server       string `json:"Server"`
	ThreatName   string `json:"threat_name"`
	Severity     string `json:"severity"`
	PolicyAction string `json:"policy_action"`
	PolicyID     uint32 `json:"policy_id"`
	LastSeenAt   string `json:"last_seen_at"`
	CIP          string `json:"client_ip"`
	SIP          string `json:"server_ip"`
	Xff          bool   `json:"xff"`
	ToSidecar    bool   `json:"to_sidecar"`
}

type RESTConversationDetail struct {
	*RESTConversation
	Entries []*RESTConversationEntry `json:"entries"`
}

type RESTConversationsData struct {
	Endpoints []*RESTConversationEndpoint `json:"endpoints"`
	Convers   []*RESTConversationCompact  `json:"conversations"`
}

type RESTConversationsVerboseData struct {
	Endpoints []*RESTConversationEndpoint `json:"endpoints"`
	Convers   []*RESTConversation         `json:"conversations"`
}

type RESTConversationsDetailData struct {
	Conver *RESTConversationDetail `json:"conversation"`
}

type RESTConversationQuery struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

type RESTConversationQueryData struct {
	Query *RESTConversationQuery `json:"query"`
}

type RESTCriteriaEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Op    string `json:"op"`
}

const (
	CfgTypeLearned     = "learned"
	CfgTypeUserCreated = "user_created"
	CfgTypeGround      = "ground"
	CfgTypeFederal     = "federal"
	CfgSystemDefined   = "system_defined"
)

type RESTGroupCaps struct {
	// use * and omitempty to make sure 'false' value is returned if requested
	CapChgMode  *bool `json:"cap_change_mode,omitempty"`
	CapScorable *bool `json:"cap_scorable,omitempty"`
}

type RESTGroupBrief struct {
	Name            string   `json:"name"`
	Comment         string   `json:"comment"`
	Learned         bool     `json:"learned"`
	Reserved        bool     `json:"reserved"`
	PolicyMode      string   `json:"policy_mode,omitempty"`
	ProfileMode     string   `json:"profile_mode,omitempty"`
	NotScored       bool     `json:"not_scored"`
	Domain          string   `json:"domain"`
	CreaterDomains  []string `json:"creater_domains"`
	Kind            string   `json:"kind"`
	PlatformRole    string   `json:"platform_role"`
	CfgType         string   `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	BaselineProfile string   `json:"baseline_profile"`
	RESTGroupCaps
}

type RESTGroup struct {
	RESTGroupBrief
	Criteria      []RESTCriteriaEntry  `json:"criteria"`
	Members       []*RESTWorkloadBrief `json:"members"`
	PolicyRules   []uint32             `json:"policy_rules"`
	ResponseRules []uint32             `json:"response_rules"`
}

type RESTGroupDetail struct {
	RESTGroupBrief
	Criteria      []RESTCriteriaEntry  `json:"criteria"`
	Members       []*RESTWorkloadBrief `json:"members"`
	PolicyRules   []*RESTPolicyRule    `json:"policy_rules"`
	ResponseRules []*RESTResponseRule  `json:"response_rules"`
}

type RESTGroupConfig struct {
	Name     string               `json:"name"`
	Comment  *string              `json:"comment"`
	Criteria *[]RESTCriteriaEntry `json:"criteria,omitempty"`
	CfgType  string               `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
}

type RESTCrdGroupConfig struct {
	OriginalName string               `json:"original_name"`
	Name         string               `json:"name"`
	Comment      string               `json:"comment"`
	Criteria     *[]RESTCriteriaEntry `json:"criteria,omitempty"`
}

type RESTGroupsData struct {
	Groups []*RESTGroup `json:"groups"`
}

type RESTGroupsBriefData struct {
	Groups []*RESTGroupBrief `json:"groups"`
}

type RESTGroupData struct {
	Group *RESTGroupDetail `json:"group"`
}

type RESTGroupConfigData struct {
	Config *RESTGroupConfig `json:"config"`
}

type RESTGroupBatchDelete struct {
	Groups []string `json:"groups"`
}

const PolicyPortAny string = "any"
const PolicyAppAny string = "any"
const PolicyLearnedIDBase uint32 = share.PolicyLearnedIDBase
const PolicyGroundRuleIDBase uint32 = share.PolicyGroundRuleIDBase
const PolicyGroundRuleIDMax uint32 = share.PolicyGroundRuleIDMax
const PolicyFedRuleIDBase uint32 = share.PolicyFedRuleIDBase
const PolicyFedRuleIDMax uint32 = share.PolicyFedRuleIDMax
const PolicyAutoID uint32 = 0

type RESTPolicyRule struct {
	ID           uint32   `json:"id"`
	Comment      string   `json:"comment"`
	From         string   `json:"from"`  // group name
	To           string   `json:"to"`    // group name
	Ports        string   `json:"ports"` // free-style port list
	Action       string   `json:"action"`
	Applications []string `json:"applications"`
	Learned      bool     `json:"learned"`
	Disable      bool     `json:"disable"`
	CreatedTS    int64    `json:"created_timestamp"`
	LastModTS    int64    `json:"last_modified_timestamp"`
	CfgType      string   `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	Priority     uint32   `json:"priority"`
}

type RESTPolicyRuleData struct {
	Rule *RESTPolicyRule `json:"rule"`
}
type RESTPolicyRulesData struct {
	Rules []*RESTPolicyRule `json:"rules"`
}

type RESTPolicyRuleMove struct {
	// nil: last; 0: first; +id: after rule 'id'; -id: before rule 'id'
	After *int   `json:"after,omitempty"`
	ID    uint32 `json:"id"`
}

type RESTPolicyRuleInsert struct {
	// nil: last; 0: first; +id: after rule 'id'; -id: before rule 'id'
	After *int              `json:"after,omitempty"`
	Rules []*RESTPolicyRule `json:"rules"`
}

type RESTPolicyRuleActionData struct {
	Move   *RESTPolicyRuleMove   `json:"move,omitempty"`
	Insert *RESTPolicyRuleInsert `json:"insert,omitempty"`
	Rules  *[]*RESTPolicyRule    `json:"rules,omitempty"`
	Delete *[]uint32             `json:"delete,omitempty"`
}

// Omit fields indicate that it's not modified.
type RESTPolicyRuleConfig struct {
	ID           uint32    `json:"id"`
	Comment      *string   `json:"comment,omitempty"`
	From         *string   `json:"from,omitempty"`  // group name
	To           *string   `json:"to,omitempty"`    // group name
	Ports        *string   `json:"ports,omitempty"` // free-style port list
	Action       *string   `json:"action,omitempty"`
	Applications *[]string `json:"applications,omitempty"`
	Disable      *bool     `json:"disable,omitempty"`
	CfgType      string    `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	Priority     uint32    `json:"priority,omitempty"`
}

type RESTPolicyRuleConfigData struct {
	Config    *RESTPolicyRuleConfig `json:"config"`
	Replicate bool                  `json:"replicate,omitempty"`
}

const (
	WireInline  string = share.WireInline
	WireDefault string = share.WireDefault
)

// Omit fields indicate that it's not modified.
type RESTWorkloadConfigCfg struct {
	Wire       *string `json:"wire,omitempty"`
	Quarantine *bool   `json:"quarantine,omitempty"`
}

type RESTWorkloadConfigCfgData struct {
	Config *RESTWorkloadConfigCfg `json:"config"`
}

type RESTWorkloadConfig struct {
	Wire       string `json:"wire,omitempty"`
	Quarantine bool   `json:"quarantine"`
	QuarReason string `json:"quarantine_reason,omitempty"`
}

type RESTWorkloadConfigData struct {
	Config *RESTWorkloadConfig `json:"config"`
}

type RESTWorkloadRequest struct {
	Command string `json:"command,omitempty"`
}

type RESTWorkloadRequestData struct {
	Request RESTWorkloadRequest `json:"request"`
}

type RESTMetry struct {
	CPU           float64 `json:"cpu"`
	Memory        uint64  `json:"memory"`
	SessionIn     uint32  `json:"session_in"`
	SessionOut    uint32  `json:"session_out"`
	SessionCurIn  uint32  `json:"cur_session_in,omitempty"`
	SessionCurOut uint32  `json:"cur_session_out,omitempty"`
	PacketIn      uint64  `json:"packet_in"`
	PacketOut     uint64  `json:"packet_out"`
	ByteIn        uint64  `json:"byte_in"`
	ByteOut       uint64  `json:"byte_out"`
}

type RESTStats struct {
	Interval uint32    `json:"interval"`
	Total    RESTMetry `json:"total"`
	Span1    RESTMetry `json:"span_1"`
	Span12   RESTMetry `json:"span_12"`
	Span60   RESTMetry `json:"span_60"`
}

type RESTWorkloadStatsData struct {
	ID     string     `json:"id"`
	ReadAt string     `json:"read_at"`
	Stats  *RESTStats `json:"stats"`
}

type RESTAgentStatsData struct {
	ID     string     `json:"id"`
	ReadAt string     `json:"read_at"`
	Stats  *RESTStats `json:"stats"`
}

type RESTAgentCounter struct {
	RXPackets           uint64   `json:"rx_packets"`
	RXDropPackets       uint64   `json:"rx_drop_packets"`
	TXPackets           uint64   `json:"tx_packets"`
	TXDropPackets       uint64   `json:"tx_drop_packets"`
	ErrorPackets        uint64   `json:"error_packets"`
	NoWorkloadPackets   uint64   `json:"no_workload_packets"`
	IPv4Packets         uint64   `json:"ipv4_packets"`
	IPv6Packets         uint64   `json:"ipv6_packets"`
	TCPPackets          uint64   `json:"tcp_packets"`
	TCPNoSessionPackets uint64   `json:"tcp_no_session_packets"`
	UDPPackets          uint64   `json:"udp_packets"`
	ICMPPackets         uint64   `json:"icmp_packets"`
	OtherPackets        uint64   `json:"other_packets"`
	Assemblys           uint64   `json:"total_assemblys"`
	FreedAssemblys      uint64   `json:"freed_assemblys"`
	Fragments           uint64   `json:"total_fragments"`
	FreedFragments      uint64   `json:"freed_fragments"`
	TimeoutFragments    uint64   `json:"timeout_fragments"`
	TotalSessions       uint64   `json:"total_sessions"`
	TCPSessions         uint64   `json:"tcp_sessions"`
	UDPSessions         uint64   `json:"udp_sessions"`
	ICMPSessions        uint64   `json:"icmp_sessions"`
	IPSessions          uint64   `json:"ip_sessions"`
	ParserSessions      []uint64 `json:"parser_sessions"`
	ParserPackets       []uint64 `json:"parser_packets"`
	DropMeters          uint64   `json:"drop_meters"`
	ProxyMeters         uint64   `json:"proxy_meters"`
	CurMeters           uint64   `json:"cur_meters"`
	CurLogCaches        uint64   `json:"cur_log_caches"`
	LimitDropConns      uint64   `json:"limit_drop_conns"`
	LimitPassConns      uint64   `json:"limit_pass_conns"`
	PolicyType1Rules    uint32   `json:"policy_type1_rules"`
	PolicyType2Rules    uint32   `json:"policy_type2_rules"`
	PolicyDomains       uint32   `json:"policy_domains"`
	PolicyDomainIPs     uint32   `json:"policy_domain_ips"`
	GoRoutines          uint32   `json:"goroutines"`
	LsofOutput          []string `json:"lsof"`
	PSOutput            []string `json:"ps"`
}

type RESTAgentCounterData struct {
	Counter *RESTAgentCounter `json:"counter"`
}

type RESTAgentConfig struct {
	Debug            *[]string `json:"debug,omitempty"`
	DisableNvProtect *bool     `json:"disable_nvprotect,omitempty"`
	DisableKvCCtl    *bool     `json:"disable_kvcctl,omitempty"`
}

type RESTAgentConfigData struct {
	Config *RESTAgentConfig `json:"config"`
}

type RESTControllerCounter struct {
	GraphNodes uint32   `json:"graph_nodes"`
	GoRoutines uint32   `json:"goroutines"`
	ScanTasks  uint32   `json:"scan_tasks"`
	LsofOutput []string `json:"lsof"`
	PSOutput   []string `json:"ps"`
}

type RESTControllerCounterData struct {
	Counter *RESTControllerCounter `json:"counter"`
}

type RESTControllerConfig struct {
	Debug *[]string `json:"debug,omitempty"`
}

type RESTControllerConfigData struct {
	Config *RESTControllerConfig `json:"config"`
}

const FilterByHost string = "node"
const FilterByAgent string = "enforcer"
const FilterByWorkload string = "workload"
const FilterByGroup string = "group"
const FilterByDomain string = "domain"
const FilterByID string = "id"

type RESTSession struct {
	ID             uint64 `json:"id"`
	Workload       string `json:"workload_id"`
	EtherType      uint16 `json:"ether_type"`
	Application    string `json:"application"`
	ClientMAC      string `json:"client_mac"`
	ServerMAC      string `json:"server_mac"`
	ClientIP       string `json:"client_ip"`
	ServerIP       string `json:"server_ip"`
	ClientPort     uint16 `json:"client_port"`
	ServerPort     uint16 `json:"server_port"`
	ICMPCode       uint8  `json:"icmp_code"`
	ICMPType       uint8  `json:"icmp_type"`
	IPProto        uint8  `json:"ip_proto"`
	ClientState    string `json:"client_state"`
	ServerState    string `json:"server_state"`
	ClientPkts     uint32 `json:"client_pkts"`
	ServerPkts     uint32 `json:"server_pkts"`
	ClientBytes    uint64 `json:"client_bytes"`
	ServerBytes    uint64 `json:"server_bytes"`
	ClientAsmPkts  uint32 `json:"client_asm_pkts"`
	ServerAsmPkts  uint32 `json:"server_asm_pkts"`
	ClientAsmBytes uint64 `json:"client_asm_bytes"`
	ServerAsmBytes uint64 `json:"server_asm_bytes"`
	Age            uint32 `json:"age"`
	Idle           uint32 `json:"idle"`
	Life           uint32 `json:"life"`
	Ingress        bool   `json:"ingress"`
	Tap            bool   `json:"tap"`
	MidStream      bool   `json:"mid_stream"`
	PolicyID       uint32 `json:"policy_id"`
	PolicyAction   string `json:"policy_action"`
	XffIP          string `json:"xff_ip"`
	XffApp         string `json:"xff_app"`
	XffPort        uint16 `json:"xff_port"`
}

type RESTSessionList struct {
	Sessions []*RESTSession `json:"sessions"`
}

type RESTSessionSummary struct {
	CurSessions     uint32 `json:"cur_sessions"`
	CurTCPSessions  uint32 `json:"cur_tcp_sessions"`
	CurUDPSessions  uint32 `json:"cur_udp_sessions"`
	CurICMPSessions uint32 `json:"cur_icmp_sessions"`
	CurIPSessions   uint32 `json:"cur_ip_sessions"`
}

type RESTSessionSummaryData struct {
	Summary *RESTSessionSummary `json:"summary"`
}

const MeterTypeSYNFlood string = "syn_flood"
const MeterTypeICMPFlood string = "icmp_flood"
const MeterTypeIPSrcSessionLimit string = "ip_src_session_limit"
const MeterTypeTCPNoData string = "tcp_nodata"

type RESTMeter struct {
	Type       string `json:"type"`
	Workload   string `json:"workload_id"`
	PeerIP     string `json:"peer_ip"`
	Count      uint32 `json:"cur_count"`
	SpanCount  uint32 `json:"span_count"`
	Span       uint8  `json:"span"`
	Tap        bool   `json:"tap"`
	Idle       uint16 `json:"idle"`
	UpperLimit uint32 `json:"upper_limit"`
	LowerLimit uint32 `json:"lower_limit"`
}

type RESTMeterList struct {
	Meters []*RESTMeter `json:"meters"`
}

type RESTEventsData struct {
	Events []*Event `json:"events"`
}

type RESTSecurityData struct {
	Threats    []*Threat    `json:"threats"`
	Incidents  []*Incident  `json:"incidents"`
	Violations []*Violation `json:"violations"`
}

type RESTThreatsData struct {
	Threats []*Threat `json:"threats"`
}

type RESTThreatData struct {
	Threat *Threat `json:"threat"`
}

type RESTIncidentsData struct {
	Incidents []*Incident `json:"incidents"`
}

type RESTAuditsData struct {
	Audits []*Audit `json:"audits"`
}

type RESTPolicyViolationsData struct {
	Violations []*Violation `json:"violations"`
}

type RESTViolationWorkload struct {
	Workload *RESTWorkloadBrief `json:"workload"`
	Count    int                `json:"count"`
}

type RESTPolicyViolationsWLData struct {
	ViolationWorkloads []*RESTViolationWorkload `json:"violation_workloads"`
}

type RESTSystemUsageReport struct {
	Signature      string `json:"signature"`
	ReportedTS     int64  `json:"reported_timestamp"`
	ReportedAt     string `json:"reported_at"`
	Platform       string `json:"platform"`
	Hosts          int    `json:"hosts"`
	CPUCores       int    `json:"cores"`
	Controllers    int    `json:"controllers"`
	Agents         int    `json:"enforcers"`
	Scanners       int    `json:"scanners"`
	CVEDBVersion   string `json:"cvedb_version"`
	Registries     int    `json:"registries"`
	Domains        int    `json:"domains"`
	RunningPods    int    `json:"running_pods"`
	Groups         int    `json:"groups"`
	MonitorGroups  int    `json:"monitor_groups"`
	ProtectGroups  int    `json:"protect_groups"`
	PolicyRules    int    `json:"policy_rules"`
	AdmCtrlRules   int    `json:"adm_ctrl_rules"`
	RespRules      int    `json:"response_rules"`
	CRDRules       int    `json:"crd_rules"`
	Clusters       int    `json:"clusters"`
	SLessProjs     int    `json:"sl_projs"`
	InstallationID string `json:"installation_id"`
}

type RESTSystemUsageReportData struct {
	Usage           []*RESTSystemUsageReport `json:"usage"`
	TelemetryStatus RESTTeleStatus           `json:"telemetry_status"`
}

type RESTUpgradeVersionInfo struct {
	Version     string `json:"version"`
	ReleaseDate string `json:"release_date"`
	Tag         string `json:"tag"`
}

type RESTTeleStatus struct {
	TeleFreq           uint                   `json:"telemetry_freq"`
	TeleURL            string                 `json:"telemetry_url"`
	CurrentVersion     string                 `json:"current_version"`
	MinUpgradeVersion  RESTUpgradeVersionInfo `json:"min_upgrade_version"`
	MaxUpgradeVersion  RESTUpgradeVersionInfo `json:"max_upgrade_version"`
	LastTeleUploadTime string                 `json:"last_telemetry_upload_time"`
}

type RESTSystemSummary struct {
	Hosts            int      `json:"hosts"`
	Controllers      int      `json:"controllers"`
	Agents           int      `json:"enforcers"`
	OfflineAgents    int      `json:"disconnected_enforcers"`
	Domains          int      `json:"domains"`
	Workloads        int      `json:"workloads"`
	RunningWorkloads int      `json:"running_workloads"`
	RunningPods      int      `json:"running_pods"`
	Services         int      `json:"services"`
	PolicyRules      int      `json:"policy_rules"`
	Scanners         int      `json:"scanners"`
	Platform         string   `json:"platform"`
	K8sVersion       string   `json:"kube_version"`
	OCVersion        string   `json:"openshift_version"`
	CVEDBVersion     string   `json:"cvedb_version"`
	CVEDBCreateTime  string   `json:"cvedb_create_time"`
	CompoVersions    []string `json:"component_versions"`
}

type RESTSystemSummaryData struct {
	Summary *RESTSystemSummary `json:"summary"`
}

type RESTSystemStats struct {
	ExpiredTokens int `json:"expired_tokens"`
	ScanStateKeys int `json:"scan_state_keys"`
	ScanDataKeys  int `json:"scan_data_keys"`
}

type RESTSystemStatsData struct {
	Stats *RESTSystemStats `json:"stats"`
}

type RESTProxy struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password,cloak"`
}

const (
	WebhookDefaultName = "default"
	WebhookTypeSlack   = "Slack"
	WebhookTypeJSON    = "JSON"
	WebhookTypeTeams   = "Teams"
)

type RESTWebhook struct {
	Name    string `json:"name"`
	Url     string `json:"url"`
	Enable  bool   `json:"enable"`
	Type    string `json:"type"`
	CfgType string `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeFederal (see above)
}

type RESTSystemWebhookConfigData struct {
	Config *RESTWebhook `json:"config"`
}

const (
	AutoScaleNone      = ""
	AutoScaleImmediate = "immediate"
	AutoScaleDelayed   = "delayed"
	AutoScaleNA        = "n/a"
)

type RESTSystemConfigConfig struct {
	NewServicePolicyMode      *string                          `json:"new_service_policy_mode,omitempty"`
	NewServiceProfileBaseline *string                          `json:"new_service_profile_baseline,omitempty"`
	UnusedGroupAging          *uint8                           `json:"unused_group_aging,omitempty"`
	SyslogServer              *string                          `json:"syslog_ip,omitempty"`
	SyslogIPProto             *uint8                           `json:"syslog_ip_proto,omitempty"`
	SyslogPort                *uint16                          `json:"syslog_port,omitempty"`
	SyslogLevel               *string                          `json:"syslog_level,omitempty"`
	SyslogEnable              *bool                            `json:"syslog_status,omitempty"`
	SyslogCategories          *[]string                        `json:"syslog_categories,omitempty"`
	SyslogInJSON              *bool                            `json:"syslog_in_json,omitempty"`
	SyslogServerCert          *string                          `json:"syslog_server_cert,omitempty"`
	SingleCVEPerSyslog        *bool                            `json:"single_cve_per_syslog,omitempty"`
	AuthOrder                 *[]string                        `json:"auth_order,omitempty"`
	AuthByPlatform            *bool                            `json:"auth_by_platform,omitempty"`
	RancherEP                 *string                          `json:"rancher_ep,omitempty"`
	WebhookEnable             *bool                            `json:"webhook_status,omitempty"` // deprecated, kept for backward-compatibility, skip docs
	WebhookUrl                *string                          `json:"webhook_url,omitempty"`    // deprecated, kept for backward-compatibility, skip docs
	Webhooks                  *[]*RESTWebhook                  `json:"webhooks,omitempty"`
	ClusterName               *string                          `json:"cluster_name,omitempty"`
	ControllerDebug           *[]string                        `json:"controller_debug,omitempty"`
	MonitorServiceMesh        *bool                            `json:"monitor_service_mesh,omitempty"`
	RegistryHttpProxyEnable   *bool                            `json:"registry_http_proxy_status,omitempty"`
	RegistryHttpsProxyEnable  *bool                            `json:"registry_https_proxy_status,omitempty"`
	RegistryHttpProxy         *RESTProxy                       `json:"registry_http_proxy,omitempty"`
	RegistryHttpsProxy        *RESTProxy                       `json:"registry_https_proxy,omitempty"`
	IBMSAEpEnabled            *bool                            `json:"ibmsa_ep_enabled,omitempty"`
	IBMSAEpDashboardURL       *string                          `json:"ibmsa_ep_dashboard_url,omitempty"`
	XffEnabled                *bool                            `json:"xff_enabled,omitempty"`
	ScannerAutoscale          *RESTSystemConfigAutoscaleConfig `json:"scanner_autoscale,omitempty"`
	NoTelemetryReport         *bool                            `json:"no_telemetry_report,omitempty"`
	// InternalSubnets      *[]string `json:"configured_internal_subnets,omitempty"`
}

type RESTFedSystemConfigConfig struct {
	Webhooks *[]*RESTWebhook `json:"webhooks,omitempty"`
}

type RESTSysNetConfigConfig struct {
	NetServiceStatus     *bool   `json:"net_service_status,omitempty"`
	NetServicePolicyMode *string `json:"net_service_policy_mode,omitempty"`
	DisableNetPolicy     *bool   `json:"disable_net_policy,omitempty"`
	DetectUnmanagedWl    *bool   `json:"detect_unmanaged_wl,omitempty"`
}

type RESTSysAtmoConfigConfig struct {
	ModeAutoD2M         *bool  `json:"mode_auto_d2m"`
	ModeAutoD2MDuration *int64 `json:"mode_auto_d2m_duration"`
	ModeAutoM2P         *bool  `json:"mode_auto_m2p"`
	ModeAutoM2PDuration *int64 `json:"mode_auto_m2p_duration"`
}

type RESTSystemConfigConfigCfgMap struct {
	RESTSystemConfigConfig
	RESTSysNetConfigConfig
	RESTSysAtmoConfigConfig
	ScanConfig   *RESTScanConfigConfig `json:"scan_config,omitempty"`
	AlwaysReload bool                  `json:"always_reload"`
}

const SyslogProtocolTCPTLS = 66

type RESTSystemConfigConfigData struct {
	Config     *RESTSystemConfigConfig    `json:"config,omitempty"`
	ConfigV2   *RESTSystemConfigConfigV2  `json:"config_v2,omitempty"`
	FedConfig  *RESTFedSystemConfigConfig `json:"fed_config,omitempty"`
	NetConfig  *RESTSysNetConfigConfig    `json:"net_config,omitempty"`
	AtmoConfig *RESTSysAtmoConfigConfig   `json:"atmo_config,omitempty"`
}

type RESTSystemConfigSvcCfgV2 struct {
	NewServicePolicyMode      *string `json:"new_service_policy_mode,omitempty"`
	NewServiceProfileBaseline *string `json:"new_service_profile_baseline,omitempty"`
}

type RESTSystemConfigSyslogCfgV2 struct {
	SyslogServer       *string   `json:"syslog_ip,omitempty"`
	SyslogIPProto      *uint8    `json:"syslog_ip_proto,omitempty"`
	SyslogPort         *uint16   `json:"syslog_port,omitempty"`
	SyslogLevel        *string   `json:"syslog_level,omitempty"`
	SyslogEnable       *bool     `json:"syslog_status,omitempty"`
	SyslogCategories   *[]string `json:"syslog_categories,omitempty"`
	SyslogInJSON       *bool     `json:"syslog_in_json,omitempty"`
	SingleCVEPerSyslog *bool     `json:"single_cve_per_syslog"`
	SyslogServerCert   *string   `json:"syslog_server_cert,omitempty"`
}

type RESTSystemConfigAuthCfgV2 struct {
	AuthOrder      *[]string `json:"auth_order,omitempty"`
	AuthByPlatform *bool     `json:"auth_by_platform,omitempty"`
	RancherEP      *string   `json:"rancher_ep,omitempty"`
}

type RESTSystemConfigProxyCfgV2 struct {
	RegistryHttpProxyEnable  *bool      `json:"registry_http_proxy_status,omitempty"`
	RegistryHttpsProxyEnable *bool      `json:"registry_https_proxy_status,omitempty"`
	RegistryHttpProxy        *RESTProxy `json:"registry_http_proxy,omitempty"`
	RegistryHttpsProxy       *RESTProxy `json:"registry_https_proxy,omitempty"`
}

type RESTSystemConfigMiscCfgV2 struct {
	// InternalSubnets      *[]string `json:"configured_internal_subnets,omitempty"`
	UnusedGroupAging   *uint8    `json:"unused_group_aging,omitempty"`
	ClusterName        *string   `json:"cluster_name,omitempty"`
	ControllerDebug    *[]string `json:"controller_debug,omitempty"`
	MonitorServiceMesh *bool     `json:"monitor_service_mesh,omitempty"`
	XffEnabled         *bool     `json:"xff_enabled,omitempty"`
	NoTelemetryReport  *bool     `json:"no_telemetry_report,omitempty"`
}

type RESTSystemConfigIBMSAVCfg2 struct {
	IBMSAEpEnabled      *bool   `json:"ibmsa_ep_enabled,omitempty"`
	IBMSAEpDashboardURL *string `json:"ibmsa_ep_dashboard_url,omitempty"`
}

type RESTSystemConfigConfigV2 struct {
	SvcCfg           *RESTSystemConfigSvcCfgV2        `json:"svc_cfg,omitempty"`
	SyslogCfg        *RESTSystemConfigSyslogCfgV2     `json:"svslog_cfg,omitempty"`
	AuthCfg          *RESTSystemConfigAuthCfgV2       `json:"auth_cfg,omitempty"`
	ProxyCfg         *RESTSystemConfigProxyCfgV2      `json:"proxy_cfg,omitempty"`
	Webhooks         *[]*RESTWebhook                  `json:"webhooks,omitempty"`
	IbmsaCfg         *RESTSystemConfigIBMSAVCfg2      `json:"ibmsa_cfg,omitempty"`
	ScannerAutoscale *RESTSystemConfigAutoscaleConfig `json:"scanner_autoscale_cfg,omitempty"`
	MiscCfg          *RESTSystemConfigMiscCfgV2       `json:"misc_cfg,omitempty"`
}

type RESTUnquarReq struct {
	RuleID uint32 `json:"response_rule,omitempty"`
	Group  string `json:"group,omitempty"`
}

type RESTSystemRequest struct {
	PolicyMode      *string        `json:"policy_mode,omitempty"`
	BaselineProfile *string        `json:"baseline_profile,omitempty"`
	Unquar          *RESTUnquarReq `json:"unquarantine,omitempty"`
}

type RESTSystemRequestData struct {
	Request *RESTSystemRequest `json:"request"`
}

// If more log servers needed, they can be defined as servers.
type RESTSystemConfig struct {
	NewServicePolicyMode      string                    `json:"new_service_policy_mode"`
	NewServiceProfileBaseline string                    `json:"new_service_profile_baseline"`
	UnusedGroupAging          uint8                     `json:"unused_group_aging"`
	SyslogServer              string                    `json:"syslog_ip"`
	SyslogIPProto             uint8                     `json:"syslog_ip_proto"`
	SyslogPort                uint16                    `json:"syslog_port"`
	SyslogLevel               string                    `json:"syslog_level"`
	SyslogEnable              bool                      `json:"syslog_status"`
	SyslogCategories          []string                  `json:"syslog_categories"`
	SyslogInJSON              bool                      `json:"syslog_in_json"`
	SyslogServerCert          string                    `json:"syslog_server_cert"`
	SingleCVEPerSyslog        bool                      `json:"single_cve_per_syslog"`
	AuthOrder                 []string                  `json:"auth_order"`
	AuthByPlatform            bool                      `json:"auth_by_platform"`
	RancherEP                 string                    `json:"rancher_ep"`
	InternalSubnets           []string                  `json:"configured_internal_subnets,omitempty"`
	Webhooks                  []RESTWebhook             `json:"webhooks"`
	ClusterName               string                    `json:"cluster_name"`
	ControllerDebug           []string                  `json:"controller_debug"`
	MonitorServiceMesh        bool                      `json:"monitor_service_mesh"`
	RegistryHttpProxyEnable   bool                      `json:"registry_http_proxy_status"`
	RegistryHttpsProxyEnable  bool                      `json:"registry_https_proxy_status"`
	RegistryHttpProxy         RESTProxy                 `json:"registry_http_proxy"`
	RegistryHttpsProxy        RESTProxy                 `json:"registry_https_proxy"`
	IBMSAEpEnabled            bool                      `json:"ibmsa_ep_enabled"`
	IBMSAEpStart              uint32                    `json:"ibmsa_ep_start"`
	IBMSAEpDashboardURL       string                    `json:"ibmsa_ep_dashboard_url"`
	IBMSAEpConnectedAt        string                    `json:"ibmsa_ep_connected_at"`
	XffEnabled                bool                      `json:"xff_enabled"`
	NetServiceStatus          bool                      `json:"net_service_status"`
	NetServicePolicyMode      string                    `json:"net_service_policy_mode"`
	DisableNetPolicy          bool                      `json:"disable_net_policy"`
	DetectUnmanagedWl         bool                      `json:"detect_unmanaged_wl"`
	ModeAutoD2M               bool                      `json:"mode_auto_d2m"`
	ModeAutoD2MDuration       int64                     `json:"mode_auto_d2m_duration"`
	ModeAutoM2P               bool                      `json:"mode_auto_m2p"`
	ModeAutoM2PDuration       int64                     `json:"mode_auto_m2p_duration"`
	ScannerAutoscale          RESTSystemConfigAutoscale `json:"scanner_autoscale"`
	NoTelemetryReport         bool                      `json:"no_telemetry_report"`
}

type RESTSystemConfigData struct {
	Config    *RESTSystemConfig    `json:"config"`
	FedConfig *RESTFedSystemConfig `json:"fed_config"`
}

type RESTSystemConfigNewSvcV2 struct {
	NewServicePolicyMode      string `json:"new_service_policy_mode"`
	NewServiceProfileBaseline string `json:"new_service_profile_baseline"`
}

type RESTSystemConfigSyslogV2 struct {
	SyslogServer       string   `json:"syslog_ip"`
	SyslogIPProto      uint8    `json:"syslog_ip_proto"`
	SyslogPort         uint16   `json:"syslog_port"`
	SyslogLevel        string   `json:"syslog_level"`
	SyslogEnable       bool     `json:"syslog_status"`
	SyslogCategories   []string `json:"syslog_categories"`
	SyslogInJSON       bool     `json:"syslog_in_json"`
	SingleCVEPerSyslog bool     `json:"single_cve_per_syslog"`
	SyslogServerCert   string   `json:"syslog_server_cert"`
}

type RESTSystemConfigAuthV2 struct {
	AuthOrder      []string `json:"auth_order"`
	AuthByPlatform bool     `json:"auth_by_platform"`
	RancherEP      string   `json:"rancher_ep"`
}

type RESTSystemConfigMiscV2 struct {
	InternalSubnets    []string `json:"configured_internal_subnets,omitempty"`
	UnusedGroupAging   uint8    `json:"unused_group_aging"`
	ClusterName        string   `json:"cluster_name"`
	ControllerDebug    []string `json:"controller_debug"`
	MonitorServiceMesh bool     `json:"monitor_service_mesh"`
	XffEnabled         bool     `json:"xff_enabled"`
	NoTelemetryReport  bool     `json:"no_telemetry_report"`
	CspType            string   `json:"csp_type"`
}

// for scanner autoscaling
type RESTSystemConfigAutoscaleConfig struct {
	Strategy *string `json:"strategy,omitempty"`
	MinPods  *uint32 `json:"min_pods,omitempty"`
	MaxPods  *uint32 `json:"max_pods,omitempty"`
}

type RESTSystemConfigAutoscale struct {
	Strategy string `json:"strategy"`
	MinPods  uint32 `json:"min_pods"`
	MaxPods  uint32 `json:"max_pods"`
}

type RESTSystemConfigProxyV2 struct {
	RegistryHttpProxyEnable  bool      `json:"registry_http_proxy_status"`
	RegistryHttpsProxyEnable bool      `json:"registry_https_proxy_status"`
	RegistryHttpProxy        RESTProxy `json:"registry_http_proxy"`
	RegistryHttpsProxy       RESTProxy `json:"registry_https_proxy"`
}

type RESTSystemConfigIBMSAV2 struct {
	IBMSAEpEnabled      bool   `json:"ibmsa_ep_enabled"`
	IBMSAEpStart        uint32 `json:"ibmsa_ep_start"`
	IBMSAEpDashboardURL string `json:"ibmsa_ep_dashboard_url"`
	IBMSAEpConnectedAt  string `json:"ibmsa_ep_connected_at"`
}

type RESTSystemConfigNetSvcV2 struct {
	NetServiceStatus     bool   `json:"net_service_status"`
	NetServicePolicyMode string `json:"net_service_policy_mode"`
	DisableNetPolicy     bool   `json:"disable_net_policy"`
	DetectUnmanagedWl    bool   `json:"detect_unmanaged_wl"`
}

type RESTSystemConfigModeAutoV2 struct {
	ModeAutoD2M         bool  `json:"mode_auto_d2m"`
	ModeAutoD2MDuration int64 `json:"mode_auto_d2m_duration"`
	ModeAutoM2P         bool  `json:"mode_auto_m2p"`
	ModeAutoM2PDuration int64 `json:"mode_auto_m2p_duration"`
}

type RESTSystemConfigV2 struct {
	NewSvc           RESTSystemConfigNewSvcV2   `json:"new_svc"`
	Syslog           RESTSystemConfigSyslogV2   `json:"syslog"`
	Auth             RESTSystemConfigAuthV2     `json:"auth"`
	Misc             RESTSystemConfigMiscV2     `json:"misc"`
	Webhooks         []RESTWebhook              `json:"webhooks"`
	Proxy            RESTSystemConfigProxyV2    `json:"proxy"`
	IBMSA            RESTSystemConfigIBMSAV2    `json:"ibmsa"`
	NetSvc           RESTSystemConfigNetSvcV2   `json:"net_svc"`
	ModeAuto         RESTSystemConfigModeAutoV2 `json:"mode_auto"`
	ScannerAutoscale RESTSystemConfigAutoscale  `json:"scanner_autoscale"`
}

type RESTIBMSAConfig struct {
	AccountID         string `json:"account_id"`
	APIKey            string `json:"apikey"`
	ProviderID        string `json:"provider_id"` // service-id
	FindingsURL       string `json:"findings_url"`
	TokenURL          string `json:"token_url"`
	OnboardNoteName   string `json:"onboard_note_name"`
	OnboardID         string `json:"onboard_id"`
	OnboardProviderID string `json:"onboard_provider_id"`
}

type RESTSystemConfigDataV2 struct {
	Config    *RESTSystemConfigV2  `json:"config"`
	FedConfig *RESTFedSystemConfig `json:"fed_config"`
}

type RESTIBMSASetupUrl struct {
	URL string `json:"url"`
}

type RESTIBMSASetupToken struct {
	AccessToken string `json:"access_token"`
}

type RESTInternalSubnets struct {
	ConfiguredInternalSubnets []string `json:"configured_internal_subnets,omitempty"`
	LearnedInternalSubnets    []string `json:"learned_internal_subnets,omitempty"`
	EffectiveInternalSubnets  []string `json:"effective_internal_subnets,omitempty"`
}

type RESTInternalSubnetsData struct {
	InternalSubnets *RESTInternalSubnets `json:"internal_subnets"`
}

type RESTServiceConfig struct {
	Name            string  `json:"name"`
	Domain          string  `json:"domain"`
	Comment         *string `json:"comment"`
	PolicyMode      *string `json:"policy_mode,omitempty"`
	BaselineProfile *string `json:"baseline_profile,omitempty"`
	NotScored       *bool   `json:"not_scored,omitempty"`
}

type RESTServiceConfigData struct {
	Config *RESTServiceConfig `json:"config"`
}

type RESTService struct {
	Name            string               `json:"name"`
	Comment         string               `json:"comment"`
	PolicyMode      string               `json:"policy_mode"`
	ProfileMode     string               `json:"profile_mode"`
	NotScored       bool                 `json:"not_scored"`
	Domain          string               `json:"domain"`
	PlatformRole    string               `json:"platform_role"`
	Members         []*RESTWorkloadBrief `json:"members"`
	PolicyRules     []*RESTPolicyRule    `json:"policy_rules"`
	ResponseRules   []*RESTResponseRule  `json:"response_rules"`
	ServiceAddr     *RESTIPPort          `json:"service_addr,omitempty"`
	IngressExposure bool                 `json:"ingress_exposure"`
	EgressExposure  bool                 `json:"egress_exposure"`
	BaselineProfile string               `json:"baseline_profile"`
	RESTGroupCaps
}

type RESTServicesData struct {
	Services []*RESTService `json:"services"`
}

type RESTServiceData struct {
	Service *RESTService `json:"service"`
}

type RESTServiceBatchConfig struct {
	Services        []string `json:"services,omitempty"`
	PolicyMode      *string  `json:"policy_mode,omitempty"`
	BaselineProfile *string  `json:"baseline_profile,omitempty"`
	NotScored       *bool    `json:"not_scored,omitempty"`
}

type RESTServiceBatchConfigData struct {
	Config *RESTServiceBatchConfig `json:"config"`
}

type RESTScanConfig struct {
	AutoScan bool `json:"auto_scan"`
}

type RESTScanConfigConfig struct {
	AutoScan *bool `json:"auto_scan"`
}

type RESTScanConfigData struct {
	Config *RESTScanConfig `json:"config"`
}

type RESTScanner struct {
	ID              string `json:"id"`
	CVEDBVersion    string `json:"cvedb_version"`
	CVEDBCreateTime string `json:"cvedb_create_time"`
	JoinedTS        int64  `json:"joined_timestamp"`
	RPCServer       string `json:"server"`
	RPCServerPort   uint16 `json:"port"`
	Containers      int    `json:"scanned_containers"`
	Hosts           int    `json:"scanned_hosts"`
	Images          int    `json:"scanned_images"`
	Serverless      int    `json:"scanned_serverless"`
}

type RESTScannerData struct {
	Scanners []*RESTScanner `json:"scanners"`
}

type RESTScanStatus struct {
	Scanned         int    `json:"scanned"`
	Scheduled       int    `json:"scheduled"`
	Scanning        int    `json:"scanning"`
	Failed          int    `json:"failed"`
	CVEDBVersion    string `json:"cvedb_version"`
	CVEDBCreateTime string `json:"cvedb_create_time"`
}

type RESTScanStatusData struct {
	Status *RESTScanStatus `json:"status"`
}

const ScanStatusIdle string = ""
const ScanStatusScheduled string = "scheduled"
const ScanStatusScanning string = "scanning"
const ScanStatusFinished string = "finished"
const ScanStatusFailed string = "failed"
const ScanStatusUnsupported string = "unsupported"

type RESTScanBrief struct {
	Status           string `json:"status"`
	HighVuls         int    `json:"high"`
	MedVuls          int    `json:"medium"`
	Result           string `json:"result"`
	ScannedTimeStamp int64  `json:"scanned_timestamp"`
	ScannedAt        string `json:"scanned_at"`
	BaseOS           string `json:"base_os"`
	CVEDBVersion     string `json:"scanner_version"`
	CVEDBCreateTime  string `json:"cvedb_create_time"`
}

type RESTScanPlatformSummary struct {
	Platform   string `json:"platform"`
	K8sVersion string `json:"kube_version"`
	OCVersion  string `json:"openshift_version"`
	RESTScanBrief
}

type RESTScanPlatformSummaryData struct {
	Summary []*RESTScanPlatformSummary `json:"platforms"`
}

type RESTScanImageSummary struct {
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	Author  string `json:"author"`
	RESTScanBrief
}

type RESTScanImageSummaryData struct {
	Summary []*RESTScanImageSummary `json:"images"`
}

type RESTModuleCve struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type RESTScanModule struct {
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Source  string           `json:"source"`
	CVEs    []*RESTModuleCve `json:"cves,omitempty"`
	CPEs    []string         `json:"cpes,omitempty"`
}

type RESTScanSecret struct {
	Type       string `json:"type"`       // the secret description
	Evidence   string `json:"evidence"`   // found in a cloaked string
	File       string `json:"path"`       // file path
	Suggestion string `json:"suggestion"` // Todo:
}

type RESTScanSetIdPerm struct {
	Type     string `json:"type"`     // the set id descriptions
	Evidence string `json:"evidence"` // file atributes
	File     string `json:"path"`     // file path
}

type RESTVulnerability struct {
	Name           string   `json:"name"`
	Score          float32  `json:"score"`
	Severity       string   `json:"severity"`
	Vectors        string   `json:"vectors"`
	Description    string   `json:"description"`
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	FixedVersion   string   `json:"fixed_version"`
	Link           string   `json:"link"`
	ScoreV3        float32  `json:"score_v3"`
	VectorsV3      string   `json:"vectors_v3"`
	PublishedTS    int64    `json:"published_timestamp"`
	LastModTS      int64    `json:"last_modified_timestamp"`
	CPEs           []string `json:"cpes,omitempty"`
	CVEs           []string `json:"cves,omitempty"`
	FeedRating     string   `json:"feed_rating"`
	InBaseImage    bool     `json:"in_base_image,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

type RESTVulnPackageVersion struct {
	PackageVersion string `json:"package_version"`
	FixedVersion   string `json:"fixed_version"`
}

type RESTVulnerabilityAsset struct {
	Name        string                              `json:"name"`
	Severity    string                              `json:"severity"`
	Description string                              `json:"description"`
	Packages    map[string][]RESTVulnPackageVersion `json:"packages"`
	Link        string                              `json:"link"`
	Score       float32                             `json:"score"`
	Vectors     string                              `json:"vectors"`
	ScoreV3     float32                             `json:"score_v3"`
	VectorsV3   string                              `json:"vectors_v3"`
	PublishedTS int64                               `json:"published_timestamp"`
	LastModTS   int64                               `json:"last_modified_timestamp"`
	Workloads   []string                            `json:"workloads"`
	Nodes       []string                            `json:"nodes"`
	Images      []string                            `json:"images"`
	Platforms   []string                            `json:"platforms"`
}

type RESTVulnerabilityAssetData struct {
	Vuls      []*RESTVulnerabilityAsset `json:"vulnerabilities"`
	Workloads map[string][]RESTIDName   `json:"workloads"`
	Nodes     map[string][]RESTIDName   `json:"nodes"`
	Images    map[string][]RESTIDName   `json:"images"`
	Platforms map[string][]RESTIDName   `json:"platforms"`
}

type RESTScanReportData struct {
	Report *RESTScanReport `json:"report"`
}

type RESTScanReport struct {
	Vuls    []*RESTVulnerability `json:"vulnerabilities"`
	Modules []*RESTScanModule    `json:"modules,omitempty"`
	Checks  []*RESTBenchItem     `json:"checks,omitempty"`
	Secrets []*RESTScanSecret    `json:"secrets,omitempty"`
	SetIDs  []*RESTScanSetIdPerm `json:"setid_perms,omitempty"`
	Envs    []string             `json:"envs,omitempty"`
	Labels  map[string]string    `json:"labels,omitempty"`
	Cmds    []string             `json:"cmds,omitempty"`
}

type RESTScanLayer struct {
	Digest string               `json:"digest"`
	Cmds   string               `json:"cmds"`
	Vuls   []*RESTVulnerability `json:"vulnerabilities"`
	Size   int64                `json:"size"`
}

type RESTScanLayersReport struct {
	Layers []*RESTScanLayer `json:"layers"`
}

type RESTScanLayersReportData struct {
	Report *RESTScanLayersReport `json:"report"`
}

type RESTScanRepoReport struct {
	Verdict         string           `json:"verdict,omitempty"`
	ImageID         string           `json:"image_id"`
	Registry        string           `json:"registry"`
	Repository      string           `json:"repository"`
	Tag             string           `json:"tag"`
	Digest          string           `json:"digest"`
	Size            int64            `json:"size"`
	Author          string           `json:"author"`
	BaseOS          string           `json:"base_os"`
	CVEDBVersion    string           `json:"cvedb_version"`
	CVEDBCreateTime string           `json:"cvedb_create_time"`
	Layers          []*RESTScanLayer `json:"layers"`
	RESTScanReport
}

type RESTScanRepoReportData struct {
	Report *RESTScanRepoReport `json:"report"`
}

const (
	ScanSourceJenkins    string = "jenkins"
	ScanSourceServerless string = "serverless"
)

type RESTScanMeta struct {
	Source    string `json:"source"`
	User      string `json:"user"`
	Job       string `json:"job"`       // jenkins: job; serverless: service
	Workspace string `json:"workspace"` // jenkins
	Function  string `json:"function"`  // serverless
	Region    string `json:"region"`    // serverless
}

type RESTScanRepoReq struct {
	Metadata   RESTScanMeta `json:"metadata"`
	Registry   string       `json:"registry"`
	Username   string       `json:"username,omitempty"`
	Password   string       `json:"password,omitempty"`
	Repository string       `json:"repository"`
	Tag        string       `json:"tag"`
	ScanLayers bool         `json:"scan_layers"`
	BaseImage  string       `json:"base_image"`
}

type RESTScanRepoReqData struct {
	Request *RESTScanRepoReq `json:"request"`
}

// This is for scanner to summit the scan result
type RESTScanRepoSubmitData struct {
	Result *share.ScanResult `json:"result"`
}

type RESTScanAppPackage struct {
	AppName    string `json:"app_name"`
	ModuleName string `json:"module_name"`
	Version    string `json:"version"`
	FileName   string `json:"file_name"`
}

type RESTScanPackageReqData struct {
	ProjectName  string               `json:"project_name"`
	FunctionName string               `json:"function_name"`
	Region       string               `json:"region"`
	AppPkgs      []RESTScanAppPackage `json:"application_packages"`
}

type RESTScanPkgReport struct {
	Verdict         string               `json:"verdict,omitempty"`
	NvSecId         string               `json:"nv_sec_id"`
	CVEDBVersion    string               `json:"cvedb_version"`
	CVEDBCreateTime string               `json:"cvedb_create_time"`
	Vuls            []*RESTVulnerability `json:"vulnerabilities"`
}

type RESTScanPkgReportData struct {
	Report *RESTScanPkgReport `json:"report"`
}

const LicenseIDTypeHost string = "host"

type RESTLicenseRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type RESTLicenseRequestData struct {
	Request *RESTLicenseRequest `json:"license_request"`
}

type RESTLicenseInfo struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	ID             string `json:"id,omitempty"`
	IDType         string `json:"id_type,omitempty"`
	InstallationID string `json:"installation_id"` // nv installation id
}

type RESTLicenseShow struct {
	Info *RESTLicenseInfo `json:"info"`
}

type RESTLicenseShowData struct {
	License *RESTLicenseShow `json:"license"`
}

type RESTLicenseKey struct {
	LicenseKey string `json:"license_key,cloak"`
}
type RESTLicenseKeyCfgMap struct {
	RESTLicenseKey
	AlwaysReload bool `json:"always_reload"`
}
type RESTLicenseCode struct {
	LicenseCode string `json:"license_code"`
}

type RESTSnifferArgs struct {
	FileNumber *uint32 `json:"file_number,omitempty"`
	Duration   *uint32 `json:"duration,omitempty"`
	Filter     *string `json:"filter,omitempty"`
}

type RESTSnifferArgsData struct {
	Sniffer *RESTSnifferArgs `json:"sniffer"`
}

type RESTSnifferInfo struct {
	ID         string `json:"id"`
	AgentID    string `json:"enforcer_id"`
	WorkloadID string `json:"container_id"`
	FileNumber uint32 `json:"file_number"`
	Size       int64  `json:"size"`
	Status     string `json:"status"`
	Args       string `json:"args"`
	StartTime  int64  `json:"start_time"`
	StopTime   int64  `json:"stop_time"`
}

type RESTSnifferData struct {
	Sniffer *RESTSnifferInfo `json:"sniffer"`
}

type RESTSniffersData struct {
	Sniffers []*RESTSnifferInfo `json:"sniffers"`
}

type RESTSnifferResult struct {
	ID string `json:"id"`
}

type RESTSnifferResultData struct {
	Result *RESTSnifferResult `json:"result"`
}

type RESTProcessInfo struct {
	Name             string `json:"name"`
	Pid              uint32 `json:"pid"`
	Parent           uint32 `json:"parent"`
	Group            uint32 `json:"group"`
	Session          uint32 `json:"session"`
	Cmdline          string `json:"cmdline"`
	Root             bool   `json:"root"`
	User             string `json:"user"`
	Status           string `json:"status"`
	StartAtTimeStamp int64  `json:"start_timestamp"`
	Action           string `json:"action"`
}

type RESTProcessList struct {
	Processes []*RESTProcessInfo `json:"processes"`
}

type RESTWorkloadInterceptPort struct {
	Port          string `json:"port"`
	Peer          string `json:"peer"`
	MAC           string `json:"mac"`
	UCMAC         string `json:"uc_mac"`
	BCMAC         string `json:"bc_mac"`
	InPort        string `json:"in_port"`
	ExPort        string `json:"ex_port"`
	InPortRules   string `json:"in_rules"`
	ExPortRules   string `json:"ex_rules"`
	EnforcerRules string `json:"enforcer_rules"`
}

type RESTWorkloadIntercept struct {
	ID         string                       `json:"id"`
	Inline     bool                         `json:"inline"`
	Quarantine bool                         `json:"quarantine"`
	Ports      []*RESTWorkloadInterceptPort `json:"ports"`
}

type RESTWorkloadInterceptData struct {
	Intercept *RESTWorkloadIntercept `json:"intercept"`
}

type RESTBenchCheck struct {
	TestNum     string   `json:"test_number"`
	Category    string   `json:"category"`
	Type        string   `json:"type"`
	Profile     string   `json:"profile"`
	Scored      bool     `json:"scored"`
	Automated   bool     `json:"automated"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Tags        []string `json:"tags"`
}

type RESTBenchMeta struct {
	RESTBenchCheck
}

type RESTBenchItem struct {
	RESTBenchCheck
	Level    string   `json:"level"`
	Evidence string   `json:"evidence,omitempty"`
	Location string   `json:"location,omitempty"`
	Message  []string `json:"message"`
	Group    string   `json:"group,omitempty"`
}

type RESTBenchReport struct {
	RunAtTimeStamp int64            `json:"run_timestamp"`
	RunAt          string           `json:"run_at"`
	Version        string           `json:"cis_version"`
	Items          []*RESTBenchItem `json:"items"`
}

type RESTComplianceData struct {
	RunAtTimeStamp int64            `json:"run_timestamp"`
	RunAt          string           `json:"run_at"`
	KubeVersion    string           `json:"kubernetes_cis_version"`
	DockerVersion  string           `json:"docker_cis_version"`
	Items          []*RESTBenchItem `json:"items"`
}

type RESTComplianceAsset struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Type        string   `json:"type"`
	Level       string   `json:"level"`
	Profile     string   `json:"profile"`
	Scored      bool     `json:"scored"`
	Description string   `json:"description"`
	Message     []string `json:"message"`
	Remediation string   `json:"remediation"`
	Group       string   `json:"group"`
	Tags        []string `json:"tags"`
	Workloads   []string `json:"workloads"`
	Nodes       []string `json:"nodes"`
	Images      []string `json:"images"`
	Platforms   []string `json:"platforms"`
}

type RESTComplianceAssetData struct {
	Compliances   []*RESTComplianceAsset  `json:"compliances"`
	Workloads     map[string][]RESTIDName `json:"workloads"`
	Nodes         map[string][]RESTIDName `json:"nodes"`
	Images        map[string][]RESTIDName `json:"images"`
	Platforms     map[string][]RESTIDName `json:"platforms"`
	KubeVersion   string                  `json:"kubernetes_cis_version"`
	DockerVersion string                  `json:"docker_cis_version"`
}

const (
	ComplianceTemplateAll   = "all"
	ComplianceTemplatePCI   = "PCI"
	ComplianceTemplateGDPR  = "GDPR"
	ComplianceTemplateHIPAA = "HIPAA"
	ComplianceTemplateNIST  = "NIST" // NIST SP 800-190
)

type RESTComplianceProfileEntry struct {
	TestNum string   `json:"test_number"`
	Tags    []string `json:"tags"`
}

type RESTComplianceProfile struct {
	Name          string                       `json:"name"`
	DisableSystem bool                         `json:"disable_system"`
	Entries       []RESTComplianceProfileEntry `json:"entries"`
}

type RESTComplianceProfileData struct {
	Profile *RESTComplianceProfile `json:"profile"`
}

type RESTComplianceProfilesData struct {
	Profiles []*RESTComplianceProfile `json:"profiles"`
}

type RESTComplianceProfileConfig struct {
	Name          string                         `json:"name"`
	DisableSystem *bool                          `json:"disable_system,omitempty"`
	Entries       *[]*RESTComplianceProfileEntry `json:"entries,omitempty"`
}

type RESTComplianceProfileConfigData struct {
	Config *RESTComplianceProfileConfig `json:"config"`
}

type RESTComplianceProfileEntryConfigData struct {
	Config *RESTComplianceProfileEntry `json:"config"`
}

const (
	VulnerabilityNameRecent           = "_RecentVuln"
	VulnerabilityNameRecentWithoutFix = "_RecentVulnWithoutFix"
)

type RESTVulnerabilityProfileEntry struct {
	ID      uint32   `json:"id"`
	Name    string   `json:"name"`
	Comment string   `json:"comment"`
	Days    uint     `json:"days"` // Only used for 'recent' vuln entries
	Domains []string `json:"domains"`
	Images  []string `json:"images"`
}

type RESTVulnerabilityProfile struct {
	Name    string                          `json:"name"`
	Entries []RESTVulnerabilityProfileEntry `json:"entries"`
}

type RESTVulnerabilityProfileData struct {
	Profile *RESTVulnerabilityProfile `json:"profile"`
}

type RESTVulnerabilityProfilesData struct {
	Profiles []*RESTVulnerabilityProfile `json:"profiles"`
}

type RESTVulnerabilityProfileConfig struct {
	Name    string                            `json:"name"`
	Entries *[]*RESTVulnerabilityProfileEntry `json:"entries,omitempty"`
}

type RESTVulnerabilityProfileConfigData struct {
	Config *RESTVulnerabilityProfileConfig `json:"config"`
}

type RESTVulnerabilityProfileEntryConfigData struct {
	Config *RESTVulnerabilityProfileEntry `json:"config"`
}

// Custom check
type RESTCustomCheck struct {
	Name   string `json:"name"`
	Script string `json:"script"`
}

type RESTCustomChecks struct {
	Group   string             `json:"group"`
	Scripts []*RESTCustomCheck `json:"scripts"`
}

type RESTCustomCheckConfig struct {
	Add    *RESTCustomChecks `json:"add"`
	Del    *RESTCustomChecks `json:"delete"`
	Update *RESTCustomChecks `json:"update"`
}

type RESTCustomCheckConfigData struct {
	Config *RESTCustomCheckConfig `json:"config"`
}

type RESTCustomCheckData struct {
	Config *RESTCustomChecks `json:"config"`
}

type RESTCustomCheckListData struct {
	Configs []*RESTCustomChecks `json:"configs"`
}

type RESTPolicyMismatch struct {
	ClusterRule *RESTPolicyRule `json:"cluster_rule"`
	LearnedRule *RESTPolicyRule `json:"learned_rule"`
}

type RESTResponseRuleOptions struct {
	Types         []string            `json:"types"`
	Name          []string            `json:"name,omitempty"`
	Level         []string            `json:"level,omitempty"`
	DisabledProps map[string][]string `json:"disabled_props,omitempty"`
}

type RESTResponseRuleOptionData struct {
	Options  map[string]*RESTResponseRuleOptions `json:"response_rule_options"`
	Webhooks []string                            `json:"webhooks"`
}

type RESTResponseRule struct {
	ID         uint32                     `json:"id"`
	Event      string                     `json:"event"`
	Comment    string                     `json:"comment"`
	Group      string                     `json:"group"`
	Conditions []share.CLUSEventCondition `json:"conditions"`
	Actions    []string                   `json:"actions"`
	Webhooks   []string                   `json:"webhooks"`
	Disable    bool                       `json:"disable"`
	CfgType    string                     `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
}

type RESTResponseRuleData struct {
	Rule *RESTResponseRule `json:"rule"`
}

type RESTResponseRulesData struct {
	Rules []*RESTResponseRule `json:"rules"`
}

type RESTResponseRuleInsert struct {
	// nil: last; 0: first; +id: after rule 'id'; -id: before rule 'id'
	After *int                `json:"after,omitempty"`
	Rules []*RESTResponseRule `json:"rules"`
}

type RESTResponseRuleActionData struct {
	Insert *RESTResponseRuleInsert `json:"insert,omitempty"`
}

// Omit fields indicate that it's not modified.
type RESTResponseRuleConfig struct {
	ID         uint32                      `json:"id"`
	Comment    *string                     `json:"comment,omitempty"`
	Group      *string                     `json:"group,omitempty"`
	Event      *string                     `json:"event,omitempty"`
	Conditions *[]share.CLUSEventCondition `json:"conditions,omitempty"`
	Actions    *[]string                   `json:"actions,omitempty"`
	Webhooks   *[]string                   `json:"webhooks,omitempty"`
	Disable    *bool                       `json:"disable,omitempty"`
	CfgType    string                      `json:"cfg_type"` // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
}

type RESTResponseRuleConfigData struct {
	Config *RESTResponseRuleConfig `json:"config"`
}

type RESTProcessProfileEntryConfig struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Action          string `json:"action"`
	Group           string `json:"group"`
	AllowFileUpdate bool   `json:"allow_update"`
}

type RESTProcessProfileEntry struct {
	Name             string `json:"name"`
	Path             string `json:"path,omitempty"`
	User             string `json:"user,omitempty"`
	Uid              int32  `json:"uid,omitempty"`
	Action           string `json:"action"`
	CfgType          string `json:"cfg_type"`
	Uuid             string `json:"uuid"`
	Group            string `json:"group,omitempty"`
	AllowFileUpdate  bool   `json:"allow_update"`
	CreatedTimeStamp int64  `json:"created_timestamp"`
	UpdatedTimeStamp int64  `json:"last_modified_timestamp"`
}

type RESTProcessProfile struct {
	Group        string                     `json:"group"`
	AlertDisable bool                       `json:"alert_disabled,omitempty"`
	HashEnable   bool                       `json:"hash_enabled,omitempty"`
	Baseline     string                     `json:"baseline"`
	Mode         string                     `json:"mode"`
	ProcessList  []*RESTProcessProfileEntry `json:"process_list"`
}

type RESTProcessProfileData struct {
	Profile *RESTProcessProfile `json:"process_profile"`
}

type RESTProcessProfilesData struct {
	Profiles []*RESTProcessProfile `json:"process_profiles"`
}

type RESTProcessProfileConfig struct {
	Group          string                           `json:"group"`
	AlertDisable   *bool                            `json:"alert_disabled,omitempty"`
	HashEnable     *bool                            `json:"hash_enabled,omitempty"`
	Baseline       *string                          `json:"baseline,omitempty"`
	ProcessChgList *[]RESTProcessProfileEntryConfig `json:"process_change_list,omitempty"`
	ProcessDelList *[]RESTProcessProfileEntryConfig `json:"process_delete_list,omitempty"`
	ProcessRepList *[]RESTProcessProfileEntryConfig `json:"process_replace_list,omitempty"`
}

type RESTProcessProfileConfigData struct {
	Config *RESTProcessProfileConfig `json:"process_profile_config"`
}

const MinDlpRuleID = 20000
const MinDlpPredefinedRuleID = 30000
const MaxDlpPredefinedRuleID = 40000

type RESTDlpCriteriaEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Op      string `json:"op"`
	Context string `json:"context,omitempty"`
}

type RESTDlpRule struct {
	Name     string                 `json:"name"`
	ID       uint32                 `json:"id"`
	Patterns []RESTDlpCriteriaEntry `json:"patterns"`
	CfgType  string                 `json:"cfg_type"`
}

type RESTDlpRuleDetail struct {
	Sensors []string       `json:"sensors"`
	Rules   []*RESTDlpRule `json:"rules"`
}

type RESTDlpRuleData struct {
	Rule *RESTDlpRuleDetail `json:"rule"`
}

type RESTDlpRulesData struct {
	Rules []*RESTDlpRule `json:"rules"`
}

type RESTDlpSetting struct {
	Name      string `json:"name"`
	Action    string `json:"action"`
	Exist     bool   `json:"exist"`
	Predefine bool   `json:"predefine"`
	Comment   string `json:"comment,omitempty"`
	CfgType   string `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround. It's from the DLP sensor's cfgType
}

type RESTDlpGroup struct {
	Name    string            `json:"name"`
	Status  bool              `json:"status"`
	Sensors []*RESTDlpSetting `json:"sensors"`
	CfgType string            `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround
}

type RESTDlpGroupData struct {
	DlpGroup *RESTDlpGroup `json:"dlp_group"`
}

type RESTDlpGroupsData struct {
	DlpGroups []*RESTDlpGroup `json:"dlp_groups"`
}

type RESTDlpConfig struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Comment string `json:"comment,omitempty"`
}

type RESTDlpGroupConfig struct {
	Name       string           `json:"name"`
	Status     *bool            `json:"status,omitempty"`
	DelSensors *[]string        `json:"delete,omitempty"`  //delete list used by CLI
	Sensors    *[]RESTDlpConfig `json:"sensors,omitempty"` //change list used by CLI
	RepSensors *[]RESTDlpConfig `json:"replace,omitempty"` //replace list used by GUI
}

type RESTDlpGroupConfigData struct {
	Config *RESTDlpGroupConfig `json:"config"`
}

type RESTDlpSensor struct {
	Name      string         `json:"name"`
	GroupList []string       `json:"groups"`
	RuleList  []*RESTDlpRule `json:"rules"`
	Comment   string         `json:"comment"`
	Predefine bool           `json:"predefine"`
	CfgType   string         `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround
}

type RESTDlpSensorData struct {
	Sensor *RESTDlpSensor `json:"sensor"`
}

type RESTDlpSensorsData struct {
	Sensors []*RESTDlpSensor `json:"sensors"`
}

type RESTDlpSensorConfig struct {
	Name        string         `json:"name"`
	RuleChgList *[]RESTDlpRule `json:"change,omitempty"` //change list used by CLI
	RuleDelList *[]RESTDlpRule `json:"delete,omitempty"` //delete list used by CLI
	Rules       *[]RESTDlpRule `json:"rules,omitempty"`  //replace list used by GUI
	Comment     *string        `json:"comment,omitempty"`
}

type RESTDlpSensorConfigData struct {
	Config *RESTDlpSensorConfig `json:"config"`
}

type RESTDlpRuleConfig struct {
	Name     string                 `json:"name"`
	Patterns []RESTDlpCriteriaEntry `json:"patterns"`
}

type RESTDlpRuleConfigData struct {
	Config *RESTDlpRuleConfig `json:"config"`
}

type RESTCrdDlpGroupSetting struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type RESTCrdDlpGroupConfig struct {
	Status     bool                     `json:"status,omitempty"`
	RepSensors []RESTCrdDlpGroupSetting `json:"replace,omitempty"` //replace list used by GUI
}

type RESTDlpSensorExport struct {
	Names []string `json:"names"`
}

type RESTDerivedWorkloadDlpRule struct {
	DlpWorkload *RESTWorkloadBrief `json:"dlp_workload"`
	Mode        string             `json:"mode,omitempty"`
	DefAct      uint32             `json:"defact,omitempty"`
	ApplyDir    int32              `json:"applydir,omitempty"`
	DlpMacs     []string           `json:"dlp_macs"`
	DlpRules    []*RESTDlpSetting  `json:"dlp_rules"`
	WafRules    []*RESTDlpSetting  `json:"waf_rules"`
	Rids        []uint32           `json:"rids"`
	Wafrids     []uint32           `json:"wafrids"`
	RuleType    string             `json:"ruletype"`
}

type RESTDerivedWorkloadDlpRuleData struct {
	Rules []*RESTDerivedWorkloadDlpRule `json:"rules"`
}

type RESTDerivedDlpRule struct {
	Name     string   `json:"name"`
	ID       uint32   `json:"id"`
	Patterns []string `json:"patterns"`
}

type RESTDerivedDlpRuleData struct {
	Rules []*RESTDerivedDlpRule `json:"rules"`
}

type RESTDerivedDlpRuleMac struct {
	Mac string `json:"mac"`
}

type RESTDerivedDlpRuleMacData struct {
	Macs []*RESTDerivedDlpRuleMac `json:"macs"`
}

// waf
const MinWafRuleID = 40000
const MaxWafRuleID = 50000

type RESTWafCriteriaEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Op      string `json:"op"`
	Context string `json:"context,omitempty"`
}

type RESTWafRule struct {
	Name     string                 `json:"name"` // simple rule anme
	ID       uint32                 `json:"id"`
	Patterns []RESTWafCriteriaEntry `json:"patterns"`
	CfgType  string                 `json:"cfg_type"`
}

type RESTWafRuleDetail struct {
	Sensors []string       `json:"sensors"`
	Rules   []*RESTWafRule `json:"rules"`
}

type RESTWafRuleData struct {
	Rule *RESTWafRuleDetail `json:"rule"`
}

type RESTWafRulesData struct {
	Rules []*RESTWafRule `json:"rules"`
}

type RESTWafSensor struct {
	Name      string         `json:"name"`
	GroupList []string       `json:"groups"`
	RuleList  []*RESTWafRule `json:"rules"`
	Comment   string         `json:"comment"`
	Predefine bool           `json:"predefine"`
	CfgType   string         `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround
}

type RESTWafSensorConfig struct {
	Name        string         `json:"name"`
	RuleChgList *[]RESTWafRule `json:"change,omitempty"` //change list used by CLI
	RuleDelList *[]RESTWafRule `json:"delete,omitempty"` //delete list used by CLI
	Rules       *[]RESTWafRule `json:"rules,omitempty"`  //replace list used by GUI
	Comment     *string        `json:"comment,omitempty"`
}

type RESTWafSensorConfigData struct {
	Config *RESTWafSensorConfig `json:"config"`
}

type RESTWafSensorData struct {
	Sensor *RESTWafSensor `json:"sensor"`
}

type RESTWafSensorsData struct {
	Sensors []*RESTWafSensor `json:"sensors"`
}

type RESTWafSetting struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Exist   bool   `json:"exist"`
	Comment string `json:"comment,omitempty"`
	CfgType string `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround. It's from the WAF sensor's cfgType
}

type RESTWafGroup struct {
	Name    string            `json:"name"`
	Status  bool              `json:"status"`
	Sensors []*RESTWafSetting `json:"sensors"`
	CfgType string            `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround
}

type RESTWafGroupData struct {
	WafGroup *RESTWafGroup `json:"waf_group"`
}

type RESTWafGroupsData struct {
	WafGroups []*RESTWafGroup `json:"waf_groups"`
}

type RESTWafConfig struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Comment string `json:"comment,omitempty"`
}

type RESTWafGroupConfig struct {
	Name       string           `json:"name"`
	Status     *bool            `json:"status,omitempty"`
	DelSensors *[]string        `json:"delete,omitempty"`  //delete list used by CLI
	Sensors    *[]RESTWafConfig `json:"sensors,omitempty"` //change list used by CLI
	RepSensors *[]RESTWafConfig `json:"replace,omitempty"` //replace list used by GUI
}

type RESTWafGroupConfigData struct {
	Config *RESTWafGroupConfig `json:"config"`
}

type RESTCrdWafGroupSetting struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type RESTCrdWafGroupConfig struct {
	Status     bool                     `json:"status,omitempty"`
	RepSensors []RESTCrdWafGroupSetting `json:"replace,omitempty"` //replace list used by GUI
}

const (
	RegistryStatusIdle     = "idle"
	RegistryStatusScanning = "scanning"

	RegistryImageSourceOpenShift = "openshift"
)

const (
	ScanSchManual     = "manual"
	ScanSchAuto       = "auto"
	ScanSchPeriodical = "periodical"

	ScanIntervalMin = 5 * 60
	ScanIntervalMax = 7 * 24 * 60 * 60

	ScanPersistImageMax = 8192
)

type RESTScanSchedule struct {
	Schedule string `json:"schedule"`
	Interval int    `json:"interval"`
}

type RESTAWSAccountKey struct {
	ID              string `json:"id"`
	AccessKeyID     string `json:"access_key_id,cloak"`
	SecretAccessKey string `json:"secret_access_key,cloak"`
	Region          string `json:"region"`
}

type RESTAWSAccountKeyConfig struct {
	ID              *string `json:"id,omitempty"`
	AccessKeyID     *string `json:"access_key_id,omitempty,cloak"`
	SecretAccessKey *string `json:"secret_access_key,omitempty,cloak"`
	Region          *string `json:"region,omitempty"`
}

type RESTGCRKey struct {
	JsonKey string `json:"json_key,cloak"`
}

type RESTGCRKeyConfig struct {
	JsonKey *string `json:"json_key,omitempty,cloak"`
}

type RESTRegistry struct {
	Name               string             `json:"name"`
	Type               string             `json:"registry_type"`
	Registry           string             `json:"registry"`
	Username           string             `json:"username"`
	Password           string             `json:"password,cloak"`
	AuthToken          string             `json:"auth_token,cloak"`
	AuthWithToken      bool               `json:"auth_with_token"`
	Domains            []string           `json:"domains"`
	Filters            []string           `json:"filters"`
	RescanImage        bool               `json:"rescan_after_db_update"`
	ScanLayers         bool               `json:"scan_layers"`
	RepoLimit          int                `json:"repo_limit"`
	TagLimit           int                `json:"tag_limit"`
	Schedule           RESTScanSchedule   `json:"schedule"`
	AwsKey             *RESTAWSAccountKey `json:"aws_key,omitempty"`
	GcrKey             *RESTGCRKey        `json:"gcr_key,omitempty"`
	JfrogMode          string             `json:"jfrog_mode"`
	JfrogAQL           bool               `json:"jfrog_aql"`
	GitlabApiUrl       string             `json:"gitlab_external_url"`
	GitlabPrivateToken string             `json:"gitlab_private_token,cloak"`
	IBMCloudTokenURL   string             `json:"ibm_cloud_token_url"`
	IBMCloudAccount    string             `json:"ibm_cloud_account"`
	CfgType            string             `json:"cfg_type"`
}

type RESTRegistryConfig struct {
	Name               string                   `json:"name"`
	Type               string                   `json:"registry_type"`
	Registry           *string                  `json:"registry,omitempty"`
	Domains            *[]string                `json:"domains,omitempty"`
	Filters            *[]string                `json:"filters,omitempty"`
	Username           *string                  `json:"username,omitempty"`
	Password           *string                  `json:"password,omitempty,cloak"`
	AuthToken          *string                  `json:"auth_token,omitempty,cloak"`
	AuthWithToken      *bool                    `json:"auth_with_token,omitempty"`
	RescanImage        *bool                    `json:"rescan_after_db_update,omitempty"`
	ScanLayers         *bool                    `json:"scan_layers,omitempty"`
	RepoLimit          *int                     `json:"repo_limit,omitempty"`
	TagLimit           *int                     `json:"tag_limit,omitempty"`
	Schedule           *RESTScanSchedule        `json:"schedule,omitempty"`
	AwsKey             *RESTAWSAccountKeyConfig `json:"aws_key,omitempty"`
	GcrKey             *RESTGCRKeyConfig        `json:"gcr_key,omitempty"`
	JfrogMode          *string                  `json:"jfrog_mode,omitempty"`
	JfrogAQL           *bool                    `json:"jfrog_aql,omitempty"`
	GitlabApiUrl       *string                  `json:"gitlab_external_url,omitempty"`
	GitlabPrivateToken *string                  `json:"gitlab_private_token,omitempty,cloak"`
	IBMCloudTokenURL   *string                  `json:"ibm_cloud_token_url,omitempty"`
	IBMCloudAccount    *string                  `json:"ibm_cloud_account,omitempty"`
	CfgType            string                   `json:"cfg_type"` // CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
}

type RESTRegistryConfigData struct {
	Config *RESTRegistryConfig `json:"config"`
}

type RESTRegistrySummary struct {
	RESTRegistry
	Status    string `json:"status"`
	ErrMsg    string `json:"error_message"`
	ErrDetail string `json:"error_detail"`
	StartedAt string `json:"started_at"`
	RESTScanStatus
}

type RESTRegistrySummaryData struct {
	Summary *RESTRegistrySummary `json:"summary"`
}

type RESTRegistrySummaryListData struct {
	Summarys []*RESTRegistrySummary `json:"summarys"`
}

type RESTRegistryImageSummary struct {
	Domain     string            `json:"domain"`
	Repository string            `json:"repository"`
	Tag        string            `json:"tag"`
	ImageID    string            `json:"image_id"`
	Digest     string            `json:"digest"`
	Size       int64             `json:"size"`
	Author     string            `json:"author"`
	RunAsRoot  bool              `json:"run_as_root"`
	Envs       []string          `json:"envs"`
	Labels     map[string]string `json:"labels"`
	Layers     []string          `json:"layers"`
	RESTScanBrief
	//Signed           bool   `json:"signed"` // [2019.Apr] comment out until we can accurately tell it
}

type RESTRegistryImageSummaryData struct {
	Images []*RESTRegistryImageSummary `json:"images"`
}

// Admission control
const StartingLocalAdmCtrlRuleID = 1000
const StartingLocalVulProfRuleID = 1000
const StartingFedAdmRespRuleID = 100000
const MaxFedAdmRespRuleID = 110000
const AdmCtrlCrdRuleIDBase = 110000
const AdmCtrlCrdRuleIDMax = 120000

const (
	MatchSrcYaml  = "yaml"
	MatchSrcImage = "image"
	MatchSrcBoth  = "both"
)

type RESTAdmissionRuleOption struct {
	Name       string                              `json:"name"`
	Ops        []string                            `json:"ops"`
	Values     []string                            `json:"values,omitempty"`
	MatchSrc   string                              `json:"match_src,omitempty"` // "yaml", "image", "both"
	SubOptions map[string]*RESTAdmissionRuleOption `json:"sub_options,omitempty"`
}

type RESTAdmRuleOptions struct {
	RuleOptions map[string]*RESTAdmissionRuleOption `json:"rule_options"` // key is criterion name
}

type RESTAdmCatOptions struct {
	K8sOptions *RESTAdmRuleOptions `json:"k8s_options,omitempty"`
}

type RESTAdmRuleTypeOptions struct {
	DenyOptions      *RESTAdmCatOptions      `json:"deny_options"`
	ExceptionOptions *RESTAdmCatOptions      `json:"exception_options"`
	PspCollection    []*RESTAdmRuleCriterion `json:"psp_collection,omitempty"`
	PssCollections   map[string][]string     `json:"pss_collections,omitempty"`
}

type RESTAdmissionState struct {
	Enable               *bool             `json:"enable,omitempty"`
	Mode                 *string           `json:"mode,omitempty"`
	DefaultAction        *string           `json:"default_action,omitempty"`
	AdmClientMode        *string           `json:"adm_client_mode,omitempty"`
	AdmSvcType           *string           `json:"adm_svc_type,omitempty"`
	FailurePolicy        *string           `json:"failure_policy,omitempty"`          // "ignore" / "fail"
	AdmClientModeOptions map[string]string `json:"adm_client_mode_options,omitempty"` // key is AdmClientModeSvc or AdmClientModeUrl
	CtrlStates           map[string]bool   `json:"ctrl_states,omitempty"`             // key is NvAdmValidateType
	CfgType              string            `json:"cfg_type"`                          // CfgTypeUserCreated / CfgTypeGround (see above)
}

type RESTAdmissionConfigData struct {
	State                   *RESTAdmissionState               `json:"state,omitempty"`
	Options                 *RESTAdmRuleTypeOptions           `json:"admission_options,omitempty"`
	K8sEnv                  bool                              `json:"k8s_env"`
	CustomCriteriaOptions   []*RESTAdminCustomCriteriaOptions `json:"admission_custom_criteria_options,omitempty"`
	CustomCriteriaTemplates []*RESTAdminCriteriaTemplate      `json:"admission_custom_criteria_templates,omitempty"`
	PredefinedRiskyRoles    []string                          `json:"predefined_risky_roles,omitempty"`
}

type RESTAdmRuleCriterion struct { // same type CLUSAdmRuleCriterion
	Name        string                  `json:"name"`
	Op          string                  `json:"op"`
	Value       string                  `json:"value"`
	SubCriteria []*RESTAdmRuleCriterion `json:"sub_criteria,omitempty"`
	Type        string                  `json:"type,omitempty"`
	Kind        string                  `json:"template_kind,omitempty"`
	Path        string                  `json:"path,omitempty"`
	ValueType   string                  `json:"value_type,omitempty"`
}

const (
	ValidatingDenyRuleType   = "deny"
	ValidatingExceptRuleType = "exception"
	ValidatingAllowRuleType  = "allow" // same meaning as ValidatingExceptRuleType
)

type RESTAdmissionRule struct { // see type CLUSAdmissionRule
	ID       uint32                  `json:"id"`
	Category string                  `json:"category"`
	Comment  string                  `json:"comment"`
	Criteria []*RESTAdmRuleCriterion `json:"criteria"`
	Disable  bool                    `json:"disable"`
	Critical bool                    `json:"critical"`
	CfgType  string                  `json:"cfg_type"`  // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	RuleType string                  `json:"rule_type"` // ValidatingExceptRuleType / ValidatingDenyRuleType (see above)
	RuleMode string                  `json:"rule_mode"` // "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
}

type RESTAdmissionRuleData struct {
	Rule *RESTAdmissionRule `json:"rule"`
}

type RESTAdmissionRulesData struct {
	Rules []*RESTAdmissionRule `json:"rules"`
}

// Passed from manager to controller. Omit fields indicate that it's not modified.
type RESTAdmissionRuleConfig struct {
	ID       uint32                  `json:"id"`
	Category *string                 `json:"category"`
	Comment  *string                 `json:"comment,omitempty"`
	Criteria []*RESTAdmRuleCriterion `json:"criteria,omitempty"`
	Disable  *bool                   `json:"disable,omitempty"`
	Actions  *[]string               `json:"actions,omitempty"`
	CfgType  string                  `json:"cfg_type"`            // CfgTypeLearned / CfgTypeUserCreated / CfgTypeGround / CfgTypeFederal (see above)
	RuleType string                  `json:"rule_type"`           // ValidatingExceptRuleType / ValidatingDenyRuleType (see above)
	RuleMode *string                 `json:"rule_mode,omitempty"` // only for deny rules: "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
}

type RESTAdmissionRuleConfigData struct {
	Config *RESTAdmissionRuleConfig `json:"config"`
}

type RESTAdmissionStats struct { // see type CLUSAdmissionStats
	K8sAllowedRequests       uint64 `json:"k8s_allowed_requests"`
	K8sDeniedRequests        uint64 `json:"k8s_denied_requests"`
	K8sErroneousRequests     uint64 `json:"k8s_erroneous_requests"`
	K8sIgnoredRequests       uint64 `json:"k8s_ignored_requests"`
	K8sProcessingRequests    int64  `json:"k8s_processing_requests"`
	JenkinsAllowedRequests   uint64 `json:"jenkins_allowed_requests"`   // obsolete
	JenkinsDeniedRequests    uint64 `json:"jenkins_denied_requests"`    // obsolete
	JenkinsErroneousRequests uint64 `json:"jenkins_erroneous_requests"` // obsolete
}

type AdmCtlTimeStamps struct {
	Start      time.Time
	Parsed     time.Time
	GonnaFetch time.Time
	Fetched    time.Time
	Matched    time.Time
	Image      string // the original image specified in the admission request
}

type RESTAdmissionStatsData struct {
	Stats *RESTAdmissionStats `json:"stats"`
}

type RESTAdmCtrlRulesTestResult struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Allowed bool   `json:"allowed"`
}

type RESTAdmCtrlRulesTestResults struct {
	PropsUnavailable []string                      `json:"props_unavailable,omitempty"`
	Results          []*RESTAdmCtrlRulesTestResult `json:"results,omitempty"`
}

const FilterByPredefined string = "predefined"

type RESTFileMonitorFilterConfig struct {
	Filter    string   `json:"filter"`
	Recursive bool     `json:"recursive"`
	Behavior  string   `json:"behavior"`
	Apps      []string `json:"applications"`
	Group     string   `json:"group"`
}

type RESTFileMonitorFilter struct {
	Filter           string   `json:"filter"`
	Recursive        bool     `json:"recursive"`
	Behavior         string   `json:"behavior"`
	Apps             []string `json:"applications"`
	CfgType          string   `json:"cfg_type"`
	Group            string   `json:"group,omitempty"`
	CreatedTimeStamp int64    `json:"created_timestamp"`
	UpdatedTimeStamp int64    `json:"last_modified_timestamp"`
}

type RESTFileMonitorProfile struct {
	Group   string                   `json:"group"`
	Filters []*RESTFileMonitorFilter `json:"filters"`
}

type RESTFileMonitorProfileData struct {
	Profile *RESTFileMonitorProfile `json:"profile"`
}

type RESTFileMonitorConfig struct {
	AddFilters    []*RESTFileMonitorFilterConfig `json:"add_filters,omitempty"`
	DelFilters    []*RESTFileMonitorFilterConfig `json:"delete_filters,omitempty"`
	UpdateFilters []*RESTFileMonitorFilterConfig `json:"update_filters,omitempty"`
}

type RESTFileMonitorConfigData struct {
	Config *RESTFileMonitorConfig `json:"config"`
}

type RESTFileMonitorProfilesData struct {
	Profiles []*RESTFileMonitorProfile `json:"profiles"`
}

type RESTFileMonitorFile struct {
	Path    string   `json:"path"`
	Mask    uint64   `json:"mask"`
	IsDir   bool     `json:"is_dir"`
	Protect bool     `json:"protect"`
	Files   []string `json:"files"`
}

type RESTFileMonitorFileData struct {
	Files []*RESTFileMonitorFile `json:"files"`
}

// uuid for process rules
type RESTProcessUuidEntry struct {
	Active int                     `json:"active"`
	Group  string                  `json:"group"`
	Rule   RESTProcessProfileEntry `json:"rule"`
}

type RESTProcessRuleResp struct {
	Entry *RESTProcessUuidEntry `json:"process_rule"`
}

type RESTProcessRulesResp struct {
	Entries []RESTProcessUuidEntry `json:"process_rules"`
}

// custom role
type RESTUserPermitOption struct {
	ID             string `json:"id"`
	ReadSupported  bool   `json:"read_supported"`
	WriteSupported bool   `json:"write_supported"`
}

type RESTUserPermitOptions struct {
	GlobalOptions []*RESTUserPermitOption `json:"global_options"`
	DomainOptions []*RESTUserPermitOption `json:"domain_options"`
}

type RESTAllUserPermitOptions struct {
	Options RESTUserPermitOptions `json:"options"`
}

type RESTRolePermitOptionInternal struct {
	ID             string
	Value          uint64
	SupportScope   byte // 1: support global scope, 2: support domain scope, 3: support both scopes
	ReadSupported  bool
	WriteSupported bool

	// non-nil only for complex permissions like PERM_RUNTIME_POLICIES. PERM_RUNTIME_POLICIES is visible to client but in controller it's PERM_NETWORK_POLICY + PERM_SYSTEM_POLICY
	ComplexPermits []*RESTRolePermitOptionInternal
}

type RESTRolePermission struct {
	ID    string `json:"id"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}

type RESTUserRole struct {
	Name        string                `json:"name"`
	Comment     string                `json:"comment"`
	Reserved    bool                  `json:"reserved"` // true for pre-defined roles
	Permissions []*RESTRolePermission `json:"permissions"`
}

type RESTUserRoleData struct {
	Role *RESTUserRole `json:"role"`
}

type RESTUserRolesData struct {
	Roles []*RESTUserRole `json:"roles"`
}

type RESTUserRolesDataCfgMap struct {
	RESTUserRolesData
	AlwaysReload bool `json:"always_reload"`
}

type RESTUserRoleConfig struct {
	Name        string                `json:"name"`
	Comment     string                `json:"comment"`
	Permissions []*RESTRolePermission `json:"permissions"`
}

type RESTUserRoleConfigData struct {
	Config *RESTUserRoleConfig `json:"config"`
}

// Import task
type RESTImportTask struct {
	TID            string    `json:"tid"`
	CtrlerID       string    `json:"ctrler_id"`
	LastUpdateTime time.Time `json:"last_update_time,omitempty"`
	Percentage     int       `json:"percentage"`
	TriggeredBy    string    `json:"triggered_by,omitempty"` // fullname of the user who triggers import
	Status         string    `json:"status,omitempty"`
	TempToken      string    `json:"temp_token,omitempty"`
}

type RESTImportTaskData struct {
	Data *RESTImportTask `json:"data"`
}

// fed system config
type RESTFedSystemConfig struct {
	Webhooks []RESTWebhook `json:"webhooks"`
}

type RESTAdmCtrlPromoteRequest struct {
	IDs []uint32 `json:"ids"`
}

type RESTPolicyPromoteRequest struct {
	IDs []uint32 `json:"ids"`
}

type RESTPolicyPromoteRequestData struct {
	Request *RESTPolicyPromoteRequest `json:"request"`
}

type RESTAdmCtrlPromoteRequestData struct {
	Request *RESTAdmCtrlPromoteRequest `json:"request"`
}

type RESTAdminCustomCriteriaOptions struct {
	Ops       []string `json:"ops"`
	Values    []string `json:"values,omitempty"`
	ValueType string   `json:"valuetype"`
}

type RESTAdminCriteriaTemplate struct {
	Kind    string `json:"kind"`
	RawJson string `json:"rawjson"`
}

const (
	ApikeyExpireNever      string = "never"
	ApikeyExpireOneDay     string = "oneday"
	ApikeyExpireOneMonth   string = "onemonth"
	ApikeyExpireOneYear    string = "oneyear"
	ApikeyExpireCustomHour string = "hours"
)

type RESTApikeyData struct {
	Apikey *RESTApikey `json:"apikey"`
}

type RESTApikeyCreationData struct {
	Apikey *RESTApikeyCreation `json:"apikey"`
}

type RESTApikey struct {
	ExpirationType      string              `json:"expiration_type"`
	ExpirationHours     uint32              `json:"expiration_hours"`
	Name                string              `json:"apikey_name"`
	SecretKey           string              `json:"apikey_secret,cloak"`
	Description         string              `json:"description"`
	Role                string              `json:"role"`
	RoleDomains         map[string][]string `json:"role_domains,omitempty"` // role -> domains
	ExpirationTimestamp int64               `json:"expiration_timestamp"`   // used in GET
	CreatedTimestamp    int64               `json:"created_timestamp"`      // used in GET
	CreatedByEntity     string              `json:"created_by_entity"`      // it could be username or apikey (access key)
}

type RESTApikeyCreation struct {
	ExpirationType  string              `json:"expiration_type"`
	ExpirationHours uint32              `json:"expiration_hours"`
	Name            string              `json:"apikey_name"`
	Description     string              `json:"description"`
	Role            string              `json:"role"`
	RoleDomains     map[string][]string `json:"role_domains,omitempty"` // role -> domains
}

type RESTApikeyGeneratedData struct {
	Apikey *RESTApikeyGenerated `json:"apikey"`
}

type RESTApikeyGenerated struct {
	Name      string `json:"apikey_name"`
	SecretKey string `json:"apikey_secret"`
}

type RESTApikeysData struct {
	Apikeys     []*RESTApikey `json:"apikeys"`
	GlobalRoles []string      `json:"global_roles"`
	DomainRoles []string      `json:"domain_roles"`
}

type RESTSelfApikeyData struct {
	Apikey        *RESTApikey                      `json:"apikey"`
	GlobalPermits []*RESTRolePermission            `json:"global_permissions,omitempty"`
	DomainPermits map[string][]*RESTRolePermission `json:"domain_permissions,omitempty"` // domain -> permissions
}
