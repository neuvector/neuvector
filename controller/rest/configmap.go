package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const ldapconfigmap string = "/etc/config/ldapinitcfg.yaml"
const samlconfigmap string = "/etc/config/samlinitcfg.yaml"
const oidcconfigmap string = "/etc/config/oidcinitcfg.yaml"
const eulaconfigmap string = "/etc/config/eulainitcfg.yaml"
const authconfigmap string = "/etc/config/userinitcfg.yaml"
const roleconfigmap string = "/etc/config/roleinitcfg.yaml"
const syscfgconfigmap string = "/etc/config/sysinitcfg.yaml"
const pwdprofileconfigmap string = "/etc/config/passwordprofileinitcfg.yaml"

const maxNameLength = 1024

type configMapHandlerContext struct {
	gotAllCustomRoles bool
	pwdProfile        *share.CLUSPwdProfile
}

func handleeulacfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {

	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("eula config to json convert error")
		return err1
	}

	var req api.RESTLicenseKeyCfgMap
	err := json.Unmarshal(json_data, &req)
	if err != nil || req.LicenseKey == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		return err
	} else if !load && !req.AlwaysReload {
		*skip = true
		return nil
	}

	_, err2 := updateLicense(req.LicenseKey, true, true)
	if err2 != nil {
		log.WithFields(log.Fields{"err": err2}).Error("License update failed")
		return err2
	}
	return nil
}

func handleldapcfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {

	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("ldap config to json convert error")
		return err1
	}

	var rconf api.RESTServerLDAPConfigCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	name := "ldap1"
	accAdmin := access.NewAdminAccessControl()
	if !context.gotAllCustomRoles {
		if roles := clusHelper.GetAllCustomRoles(accAdmin); len(roles) > 0 {
			cacher.PutCustomRoles(roles)
		}
		context.gotAllCustomRoles = true
	}

	cs, _, _ := clusHelper.GetServerRev(name, accAdmin)
	if cs == nil {
		cldap := &share.CLUSServerLDAP{
			Port: DefaultLDAPServerPort,
			CLUSServerAuth: share.CLUSServerAuth{
				RoleGroups:       make(map[string][]string),
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs = &share.CLUSServer{Name: name, LDAP: cldap}
		if err = updateLDAPServer(cs, &rconf.RESTServerLDAPConfig, true, accAdmin, nil); err == nil {
			if err = validateLDAPServer(cs); err == nil {
				err = clusHelper.PutServerIfNotExist(cs)
			}
		}
		if err != nil {
			log.WithFields(log.Fields{"server": name}).Error(err)
			return err
		}
	} else {
		_, _, err := configLDAPServer(name, &rconf.RESTServerLDAPConfig, accAdmin, nil)
		if err != nil {
			log.WithFields(log.Fields{"ldap server failed init cfg": name}).Error(err)
			return err
		}
	}
	return nil
}

func handlesamlcfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {

	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("saml config to json convert error")
		return err1
	}

	var rconf api.RESTServerSAMLConfigCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	name := "saml1"
	accAdmin := access.NewAdminAccessControl()
	if !context.gotAllCustomRoles {
		if roles := clusHelper.GetAllCustomRoles(accAdmin); len(roles) > 0 {
			cacher.PutCustomRoles(roles)
		}
		context.gotAllCustomRoles = true
	}

	cs, _, _ := clusHelper.GetServerRev(name, accAdmin)
	if cs == nil {
		csaml := &share.CLUSServerSAML{
			CLUSServerAuth: share.CLUSServerAuth{
				RoleGroups:       make(map[string][]string),
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs := &share.CLUSServer{Name: name, SAML: csaml}
		if err = updateSAMLServer(cs, &rconf.RESTServerSAMLConfig, accAdmin, nil); err == nil {
			if err = validateSAMLServer(cs); err == nil {
				err = clusHelper.PutServerIfNotExist(cs)
			}
		}
		if err != nil {
			log.WithFields(log.Fields{"server": name}).Error(err)
			return err
		}
	} else {
		_, _, err := configSAMLServer(name, &rconf.RESTServerSAMLConfig, accAdmin, nil)
		if err != nil {
			log.WithFields(log.Fields{"saml server failed init cfg": name}).Error(err)
			return err
		}
	}
	return nil
}

func handleoidccfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {

	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("oidc config to json convert error")
		return err1
	}

	var rconf api.RESTServerOIDCConfigCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	name := "openId1"
	accAdmin := access.NewAdminAccessControl()
	if !context.gotAllCustomRoles {
		if roles := clusHelper.GetAllCustomRoles(accAdmin); len(roles) > 0 {
			cacher.PutCustomRoles(roles)
		}
		context.gotAllCustomRoles = true
	}

	if remoteAuther == nil {
		remoteAuther = auth.NewRemoteAuther()
	}

	cs, _, _ := clusHelper.GetServerRev(name, accAdmin)
	if cs == nil {
		coidc := &share.CLUSServerOIDC{
			Scopes: auth.DefaultOIDCScopes,
			CLUSServerAuth: share.CLUSServerAuth{
				RoleGroups:       make(map[string][]string),
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs := &share.CLUSServer{Name: name, OIDC: coidc}
		retry := 0
		for retry < retryClusterMax {
			if err = updateOIDCServer(cs, &rconf.RESTServerOIDCConfig, accAdmin, nil); err == nil {
				if err = validateOIDCServer(cs); err == nil {
					err = clusHelper.PutServerIfNotExist(cs)
				}
			}
			if err != nil {
				log.WithFields(log.Fields{"server": name}).Error(err)
				retry++
				continue
			}
			break
		}

		if retry >= retryClusterMax {
			return errors.New("Failed to process oidc. Skip.")
		}

	} else {
		_, _, err := configOIDCServer(name, &rconf.RESTServerOIDCConfig, accAdmin, nil)
		if err != nil {
			log.WithFields(log.Fields{"oidc server failed init cfg": name}).Error(err)
			return err
		}
	}

	return nil
}

func handlesystemcfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {

	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("eula config to json convert error")
		return err1
	}

	var rc api.RESTSystemConfigConfigCfgMap
	err := json.Unmarshal(json_data, &rc)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rc.AlwaysReload {
		*skip = true
		return nil
	}

	acc := access.NewAdminAccessControl()

	cconf, rev := clusHelper.GetSystemConfigRev(acc)
	if cconf == nil {
		return errors.New("Initial systemconfig fail: Can't find default system config")
	}

	if rc.NewServicePolicyMode != nil {
		switch *rc.NewServicePolicyMode {
		case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
			cconf.NewServicePolicyMode = *rc.NewServicePolicyMode
		default:
			e := "Invalid new service policy mode"
			log.WithFields(log.Fields{"new_service_policy_mode": *rc.NewServicePolicyMode}).Error(e)
			return errors.New(e)
		}
	}

	if rc.NewServiceProfileBaseline != nil {
		blValue := strings.ToLower(*rc.NewServiceProfileBaseline)
		switch blValue {
		case share.ProfileBasic:
			cconf.NewServiceProfileBaseline = share.ProfileBasic
		case share.ProfileDefault, share.ProfileShield, share.ProfileZeroDrift:
			cconf.NewServiceProfileBaseline = share.ProfileZeroDrift
		default:
			e := "Invalid new service profile baseline"
			log.WithFields(log.Fields{"new_service_profile_baseline": *rc.NewServiceProfileBaseline}).Error(e)
			return errors.New(e)
		}
	}

	// Unused Group Aging
	if rc.UnusedGroupAging != nil {
		cconf.UnusedGroupAging = *rc.UnusedGroupAging
		if cconf.UnusedGroupAging > share.UnusedGroupAgingMax {
			e := "Invalid unused group aging time."
			log.WithFields(log.Fields{"unused_group_aging": *rc.UnusedGroupAging}).Error(e)
			return errors.New(e)
		}
	}

	// Syslog
	if rc.SyslogEnable != nil {
		cconf.SyslogEnable = *rc.SyslogEnable
	}
	if rc.SyslogInJSON != nil {
		cconf.SyslogInJSON = *rc.SyslogInJSON
	}
	if rc.SyslogCategories != nil {
		for _, categories := range *rc.SyslogCategories {
			if categories != api.CategoryEvent && categories != api.CategoryRuntime &&
				categories != api.CategoryAudit {
				e := "Invalid syslog Category"
				log.WithFields(log.Fields{"category": *rc.SyslogCategories}).Error(e)
				return errors.New(e)
			}
		}
		cconf.SyslogCategories = *rc.SyslogCategories
	}
	if rc.SyslogServer != nil {
		// Both IP and name are kept in the cluster to support backward compatibility
		if *rc.SyslogServer == "" {
			cconf.SyslogServer = ""
			cconf.SyslogIP = nil
		} else if regIPLoose.MatchString(*rc.SyslogServer) {
			if ip := net.ParseIP(*rc.SyslogServer); ip == nil {
				e := "Invalid syslog IP"
				log.WithFields(log.Fields{"ip": *rc.SyslogServer}).Error(e)
				return errors.New(e)
			} else {
				cconf.SyslogIP = ip
				cconf.SyslogServer = ""
			}
		} else {
			cconf.SyslogServer = *rc.SyslogServer
			cconf.SyslogIP = nil
		}
	}

	if rc.SyslogIPProto != nil {
		ipproto := *rc.SyslogIPProto
		if ipproto == 0 {
			cconf.SyslogIPProto = syscall.IPPROTO_UDP
		} else if ipproto != syscall.IPPROTO_UDP && ipproto != syscall.IPPROTO_TCP {
			e := "Invalid syslog protocol"
			log.WithFields(log.Fields{"protocol": ipproto}).Error(e)
			return errors.New(e)
		} else {
			cconf.SyslogIPProto = ipproto
		}
	}

	if rc.SyslogPort != nil {
		if *rc.SyslogPort == 0 {
			cconf.SyslogPort = api.SyslogDefaultUDPPort
		} else {
			cconf.SyslogPort = *rc.SyslogPort
		}
	}

	if rc.SyslogLevel != nil {
		if *rc.SyslogLevel == "" {
			cconf.SyslogLevel = api.LogLevelINFO
		} else {
			if _, ok := common.LevelToPrio(*rc.SyslogLevel); !ok {
				e := "Invalid syslog level"
				log.WithFields(log.Fields{"level": *rc.SyslogLevel}).Error(e)
				return errors.New(e)
			}
			cconf.SyslogLevel = *rc.SyslogLevel
		}
	}

	if cconf.SyslogEnable && cconf.SyslogIP == nil && cconf.SyslogServer == "" {
		e := "Syslog address is not configured"
		log.Error(e)
		return errors.New(e)
	}

	if cconf.SyslogPort == 0 {
		cconf.SyslogPort = api.SyslogDefaultUDPPort
	}
	if cconf.SyslogIPProto == 0 {
		cconf.SyslogIPProto = syscall.IPPROTO_UDP
	}
	if cconf.SyslogLevel == "" {
		cconf.SyslogLevel = api.LogLevelINFO
	}

	if rc.AuthByPlatform != nil {
		cconf.AuthByPlatform = *rc.AuthByPlatform
	}

	// webhook
	if webhooks, _, err := configWebhooks(rc.WebhookUrl, rc.Webhooks, cconf.Webhooks, share.UserCreated, acc); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Errors in webhook configurations")
		return err
	} else {
		cconf.Webhooks = webhooks
	}

	// Cluster name
	if rc.ClusterName != nil {
		if *rc.ClusterName == "" {
			cconf.ClusterName = common.DefaultSystemConfig.ClusterName
		} else {
			cconf.ClusterName = *rc.ClusterName
		}
	}

	// Controller debug
	if rc.ControllerDebug != nil {
		cconf.ControllerDebug = *rc.ControllerDebug
	}
	// proxy mesh status
	if rc.MonitorServiceMesh != nil {
		cconf.TapProxymesh = *rc.MonitorServiceMesh
	}
	//xff status
	if rc.XffEnabled != nil {
		cconf.XffEnabled = *rc.XffEnabled
	}

	//global network service status
	if rc.NetServiceStatus != nil {
		cconf.NetServiceStatus = *rc.NetServiceStatus
	}
	// global network service policy mode
	if rc.NetServicePolicyMode != nil {
		if *rc.NetServicePolicyMode == share.PolicyModeEnforce &&
			licenseAllowEnforce() == false {
			return errors.New("Invalid network service license for protect mode")
		}
		switch *rc.NetServicePolicyMode {
		case share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce:
			cconf.NetServicePolicyMode = *rc.NetServicePolicyMode
		default:
			log.WithFields(log.Fields{"net_service_policy_mode": *rc.NetServicePolicyMode}).Error("Invalid network service policy mode")
			return errors.New("Invalid network service policy mode")
		}
	}

	// registry proxy
	if rc.RegistryHttpProxy != nil {
		if rc.RegistryHttpProxy.URL != "" {
			if _, err = url.Parse(rc.RegistryHttpProxy.URL); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Invalid HTTP proxy setting")
				return errors.New("Invalid HTTP proxy setting")
			}
		}
		cconf.RegistryHttpProxy.URL = rc.RegistryHttpProxy.URL
		cconf.RegistryHttpProxy.Username = rc.RegistryHttpProxy.Username
		cconf.RegistryHttpProxy.Password = rc.RegistryHttpProxy.Password
	}
	if rc.RegistryHttpsProxy != nil {
		if rc.RegistryHttpsProxy.URL != "" {
			if _, err = url.Parse(rc.RegistryHttpsProxy.URL); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Invalid HTTPS proxy setting")
				return errors.New("Invalid HTTPS proxy setting")
			}
		}
		cconf.RegistryHttpsProxy.URL = rc.RegistryHttpsProxy.URL
		cconf.RegistryHttpsProxy.Username = rc.RegistryHttpsProxy.Username
		cconf.RegistryHttpsProxy.Password = rc.RegistryHttpsProxy.Password
	}
	if rc.RegistryHttpProxyEnable != nil {
		cconf.RegistryHttpProxy.Enable = *rc.RegistryHttpProxyEnable
	}
	if rc.RegistryHttpsProxyEnable != nil {
		cconf.RegistryHttpsProxy.Enable = *rc.RegistryHttpsProxyEnable
	}
	if (cconf.RegistryHttpProxy.Enable && cconf.RegistryHttpProxy.URL == "") ||
		(cconf.RegistryHttpsProxy.Enable && cconf.RegistryHttpsProxy.URL == "") {
		e := "Empty proxy URL"
		log.Error(e)
		return errors.New(e)
	}

	// Write to cluster
	if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
		return err
	}

	return nil
}

func handlecustomrolecfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {
	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("role config to json convert error")
		return err1
	}

	var rconf api.RESTUserRolesDataCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	accAdmin := access.NewAdminAccessControl()
	reservedRoleNames := access.GetReservedRoleNames()

	for _, rrole := range rconf.Roles {
		if rrole == nil {
			continue
		}
		if len(rrole.Name) > maxNameLength {
			log.WithFields(log.Fields{"len": len(rrole.Name)}).Error("name too long")
			continue
		}
		if rrole.Reserved || reservedRoleNames.Contains(rrole.Name) {
			e := "Reserved role is not allowed"
			log.WithFields(log.Fields{"create": rrole.Name}).Error(e)
			continue
		}
		if !isObjectNameValid(rrole.Name) {
			e := "Invalid characters in rolename"
			log.WithFields(log.Fields{"create": rrole.Name}).Error(e)
			continue
		}
		if role := access.GetRoleDetails(rrole.Name); role != nil {
			if role.Reserved {
				e := "Reserved role already exists"
				log.WithFields(log.Fields{"create": rrole.Name}).Error(e)
				continue
			}
		}
		var newrole bool
		role, rev, _ := clusHelper.GetCustomRoleRev(rrole.Name, accAdmin)
		if role == nil {
			roledata := share.CLUSUserRole{Name: rrole.Name}
			role = &roledata
			newrole = true
		} else {
			newrole = false
		}
		role.Comment = rrole.Comment

		// Check role permissions
		if permissions, err := restPermissionsToCLUS(rrole.Name, rrole.Permissions); err != nil {
			log.WithFields(log.Fields{"name": rrole.Name, "error": err}).Error()
			continue
		} else {
			role.Permissions = permissions
		}

		if newrole {
			if err := clusHelper.CreateCustomRole(role, accAdmin); err != nil {
				e := "Failed to write to the cluster"
				log.WithFields(log.Fields{"error": err}).Error(e)
				continue
			}
		} else {
			if err := clusHelper.PutCustomRoleRev(role, rev, accAdmin); err != nil {
				log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
				continue
			}
		}
	}

	return nil
}

func updateAdminPass(ruser *api.RESTUser, acc *access.AccessControl) {
	user, rev, err := clusHelper.GetUserRev(common.DefaultAdminUser, acc)
	if user == nil {
		log.WithFields(log.Fields{"error": err}).Error("Admin user date not find")
		return
	}

	if user.PasswordHash != utils.HashPassword(common.DefaultAdminPass) {
		e := "already updated"
		log.WithFields(log.Fields{"Password of": common.DefaultAdminUser}).Error(e)
		return
	}

	if weak, _, _, e := isWeakPassword(ruser.Password, utils.HashPassword(common.DefaultAdminPass), nil); weak {
		log.WithFields(log.Fields{"update password of": common.DefaultAdminUser}).Error(e)
		return
	} else {
		user.PasswordHash = utils.HashPassword(ruser.Password)
		user.PwdResetTime = time.Now().UTC()
	}

	if ruser.Timeout == 0 {
		ruser.Timeout = common.DefaultIdleTimeout
	} else if ruser.Timeout > api.UserIdleTimeoutMax ||
		ruser.Timeout < api.UserIdleTimeoutMin {
		e := "Invalid idle timeout value"
		log.WithFields(log.Fields{"create": common.DefaultAdminUser, "timeout": ruser.Timeout}).Error(e)
		return
	}
	user.Timeout = ruser.Timeout

	if ruser.EMail != "" {
		user.EMail = ruser.EMail
	}

	if err := clusHelper.PutUserRev(user, rev); err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
	}
}

func handlepwdprofilecfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {
	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("password profile config to json convert error")
		return err1
	}

	var rconf api.RESTPwdProfilesDataCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	if rconf.ActiveProfileName == "" {
		rconf.ActiveProfileName = share.CLUSDefPwdProfileName
	} else if rconf.ActiveProfileName != share.CLUSDefPwdProfileName {
		log.WithFields(log.Fields{"active_profile": rconf.ActiveProfileName}).Error("invalid value")
		return err
	}

	accAdmin := access.NewAdminAccessControl()
	for _, rprofile := range rconf.PwdProfiles {
		if rprofile == nil {
			continue
		}
		if len(rprofile.Name) > maxNameLength {
			log.WithFields(log.Fields{"len": len(rprofile.Name)}).Error("name too long")
			continue
		}
		if rprofile.Name != share.CLUSDefPwdProfileName /*|| rprofile.Name == share.CLUSSysPwdProfileName*/ {
			continue
		}
		var newprofile bool
		profile, rev, _ := clusHelper.GetPwdProfileRev(rprofile.Name, accAdmin)
		if profile == nil {
			profiledata := share.CLUSPwdProfile{
				Name: rprofile.Name,
			}
			profile = &profiledata
			newprofile = true
		} else {
			newprofile = false
		}

		profile.Comment = rprofile.Comment
		profile.MinLen = rprofile.MinLen
		profile.MinUpperCount = rprofile.MinUpperCount
		profile.MinLowerCount = rprofile.MinLowerCount
		profile.MinDigitCount = rprofile.MinDigitCount
		profile.MinSpecialCount = rprofile.MinSpecialCount
		profile.EnablePwdExpiration = rprofile.EnablePwdExpiration
		profile.PwdExpireAfterDays = rprofile.PwdExpireAfterDays
		profile.EnablePwdHistory = rprofile.EnablePwdHistory
		profile.PwdHistoryCount = rprofile.PwdHistoryCount
		if profile.PwdHistoryCount > _maxPwdHistoryCount {
			profile.PwdHistoryCount = _maxPwdHistoryCount
		}
		profile.EnableBlockAfterFailedLogin = rprofile.EnableBlockAfterFailedLogin
		profile.BlockAfterFailedCount = rprofile.BlockAfterFailedCount
		profile.BlockMinutes = rprofile.BlockMinutes
		if profile.MinLen <= 0 || profile.MinUpperCount < 0 || profile.MinLowerCount < 0 || profile.MinDigitCount < 0 || profile.MinSpecialCount < 0 ||
			(profile.EnablePwdExpiration && profile.PwdExpireAfterDays <= 0) ||
			(profile.EnablePwdHistory && profile.PwdHistoryCount <= 0) ||
			(profile.EnableBlockAfterFailedLogin && (profile.BlockAfterFailedCount <= 0 || profile.BlockMinutes <= 0)) ||
			(profile.MinLen < (profile.MinUpperCount + profile.MinLowerCount + profile.MinDigitCount + profile.MinSpecialCount)) {
			log.WithFields(log.Fields{"rprofile": *rprofile}).Error("invalid value")
			continue
		}
		if activePwdProfileName := clusHelper.GetActivePwdProfileName(); profile.Name == activePwdProfileName && context != nil {
			context.pwdProfile = profile
		}

		if newprofile {
			if err := clusHelper.PutPwdProfileRev(profile, 0); err != nil {
				continue
			}
		} else {
			if err := clusHelper.PutPwdProfileRev(profile, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
				continue
			}
		}
	}

	return nil
}

func handleusercfg(yaml_data []byte, load bool, skip *bool, context *configMapHandlerContext) error {
	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("user config to json convert error")
		return err1
	}

	var rconf api.RESTUsersDataCfgMap
	err := json.Unmarshal(json_data, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
		return err
	} else if !load && !rconf.AlwaysReload {
		*skip = true
		return nil
	}

	accAdmin := access.NewAdminAccessControl()
	if !context.gotAllCustomRoles {
		if roles := clusHelper.GetAllCustomRoles(accAdmin); len(roles) > 0 {
			cacher.PutCustomRoles(roles)
		}
		context.gotAllCustomRoles = true
	}

	var pwdProfiles map[string]*share.CLUSPwdProfile
	activePwdProfileName := clusHelper.GetActivePwdProfileName()
	if context != nil && context.pwdProfile != nil && context.pwdProfile.Name == activePwdProfileName {
		pwdProfiles = map[string]*share.CLUSPwdProfile{context.pwdProfile.Name: context.pwdProfile}
	} else {
		pwdProfiles = clusHelper.GetAllPwdProfiles(accAdmin)
	}
	if activePwdProfileName != "" && len(pwdProfiles) > 0 {
		cacher.PutPwdProfiles(activePwdProfileName, pwdProfiles)
	}

	for _, ruser := range rconf.Users {
		if ruser == nil {
			continue
		}
		if len(ruser.Fullname) > maxNameLength {
			log.WithFields(log.Fields{"create": ruser.Fullname}).Error("name too long")
			continue
		}
		if ruser.Locale == "" {
			ruser.Locale = "en"
		}
		if ruser.Locale != "en" && ruser.Locale != "zh_cn" {
			log.WithFields(log.Fields{"create": ruser.Fullname, "locale": ruser.Locale}).Error("invalid locale")
			continue
		}
		if !isUserNameValid(ruser.Fullname) {
			e := "Invalid characters in username"
			log.WithFields(log.Fields{"create": ruser.Fullname}).Error(e)
			continue
		}
		if e := isValidRoleDomains(ruser.Fullname, ruser.Role, ruser.RoleDomains, false); e != nil {
			continue
		}
		var newuser bool
		username := ruser.Fullname
		user, rev, _ := clusHelper.GetUserRev(username, accAdmin)
		if user == nil {
			userdata := share.CLUSUser{
				Fullname:    utils.MakeUserFullname("", username),
				Username:    username,
				EMail:       ruser.EMail,
				Role:        ruser.Role,
				Timeout:     ruser.Timeout,
				Locale:      ruser.Locale,
				RoleDomains: ruser.RoleDomains,
			}
			user = &userdata
			newuser = true
		} else {
			newuser = false
		}

		if weak, pwdHistoryToKeep, _, e := isWeakPassword(ruser.Password, user.PasswordHash, user.PwdHashHistory); weak {
			log.WithFields(log.Fields{"create": ruser.Fullname}).Error(e)
			continue
		} else {
			if pwdHistoryToKeep <= 1 { // because user.PasswordHash remembers one password hash
				user.PwdHashHistory = nil
			} else {
				user.PwdHashHistory = append(user.PwdHashHistory, user.PasswordHash)
				if i := len(user.PwdHashHistory) - pwdHistoryToKeep; i >= 0 { // len(user.PwdHashHistory) + 1(current password hash) should be <= pwdHistoryToKeep
					user.PwdHashHistory = user.PwdHashHistory[i+1:]
				}
			}
			user.PasswordHash = utils.HashPassword(ruser.Password)
			user.FailedLoginCount = 0
			user.BlockLoginSince = time.Time{}
			user.PwdResetTime = time.Now().UTC()
		}

		if ruser.EMail != "" {
			user.EMail = ruser.EMail
		}

		if ruser.Timeout == 0 {
			ruser.Timeout = common.DefaultIdleTimeout
		} else if ruser.Timeout > api.UserIdleTimeoutMax ||
			ruser.Timeout < api.UserIdleTimeoutMin {
			e := "Invalid idle timeout value"
			log.WithFields(log.Fields{"create": ruser.Fullname, "timeout": ruser.Timeout}).Error(e)
			continue
		}
		user.Timeout = ruser.Timeout

		// Check role
		roleForDefaultAdmin := api.UserRoleAdmin
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
			roleForDefaultAdmin = api.UserRoleFedAdmin // default admin is always federate administrator on master cluster
		}
		if ruser.Fullname == common.DefaultAdminUser && ruser.Role != "" && ruser.Role != roleForDefaultAdmin {
			e := "Default admin user's role cannot be changed"
			log.WithFields(log.Fields{"user": ruser.Fullname, "role": ruser.Role}).Error(e)
			continue
		}

		user.Role = ruser.Role

		if ruser.Locale == "" {
			ruser.Locale = common.OEMDefaultUserLocale
		}
		user.Locale = ruser.Locale

		normalizeUserRoles(user)

		if newuser {
			if err := clusHelper.CreateUser(user); err != nil {
				e := "Failed to write to the cluster"
				log.WithFields(log.Fields{"error": err}).Error(e)
				continue
			}
		} else {
			if err := clusHelper.PutUserRev(user, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
				continue
			}
		}
	}
	return nil
}

func HandleAdminUserUpdate() {
	if _, err := os.Stat(authconfigmap); err == nil {
		if useryaml_data, err := ioutil.ReadFile(authconfigmap); err == nil {
			json_data, err1 := yaml.YAMLToJSON(useryaml_data)
			if err1 != nil {
				log.WithFields(log.Fields{"error": err1}).Error("user config to json convert error")
				return
			}

			var rconf api.RESTUsersData
			err := json.Unmarshal(json_data, &rconf)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Unmarshall error")
				return

			}

			accAdmin := access.NewAdminAccessControl()
			for _, ruser := range rconf.Users {
				if ruser == nil || ruser.Fullname != common.DefaultAdminUser {
					continue
				}
				updateAdminPass(ruser, accAdmin)
				break
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("user config file read error")
		}
	}
}

func k8sResourceLog(ev share.TLogEvent, msg string, detail []string) {
	clog := share.CLUSEventLog{
		Event:      ev,
		ReportedAt: time.Now().UTC(),
	}
	clog.Msg = fmt.Sprintf("%s :\n %s", msg, strings.Join(detail[:], "\n."))
	evqueue.Append(&clog)
}

func LoadInitCfg(load bool) {
	log.WithFields(log.Fields{"load": load}).Info()
	var loaded, failed []string
	var skip bool
	// After that if configmap have license it will overwrite the consol and eventually write back to .lc
	type configMap struct {
		FileName    string
		Type        string
		HandlerFunc func([]byte, bool, *bool, *configMapHandlerContext) error
	}

	configMaps := []configMap{
		configMap{FileName: eulaconfigmap, Type: "eula", HandlerFunc: handleeulacfg},
		configMap{FileName: roleconfigmap, Type: "role", HandlerFunc: handlecustomrolecfg},                   // must be before user/ldap/saml/oidc
		configMap{FileName: pwdprofileconfigmap, Type: "password profile", HandlerFunc: handlepwdprofilecfg}, // must be before user
		configMap{FileName: ldapconfigmap, Type: "ldap", HandlerFunc: handleldapcfg},
		configMap{FileName: samlconfigmap, Type: "saml", HandlerFunc: handlesamlcfg},
		configMap{FileName: oidcconfigmap, Type: "oidc", HandlerFunc: handleoidccfg},
		configMap{FileName: syscfgconfigmap, Type: "system", HandlerFunc: handlesystemcfg},
		configMap{FileName: authconfigmap, Type: "auth", HandlerFunc: handleusercfg},
	}

	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}

	var context configMapHandlerContext

	for _, configMap := range configMaps {
		if _, err := os.Stat(configMap.FileName); err == nil {
			if yaml_data, err := ioutil.ReadFile(configMap.FileName); err == nil {
				skip = false
				err = configMap.HandlerFunc(yaml_data, load, &skip, &context)
				log.WithFields(log.Fields{"cfg": configMap.Type, "skip": skip, "error": err}).Debug()
				if err == nil {
					e := fmt.Sprintf("    %s init configmap loaded", configMap.Type)
					loaded = append(loaded, e)
				} else {
					e := fmt.Sprintf("    %s init configmap failed: %s ", configMap.Type, err.Error())
					log.Error(e)
					failed = append(loaded, e)
				}
			} else {
				e := fmt.Sprintf("    %s init configmap read error: %s ", configMap.Type, err.Error())
				log.Error(e)
				failed = append(loaded, e)
			}
		}
	}

	if len(loaded) > 0 {
		e := "Following k8s configmap loaded as neuvector init config "
		k8sResourceLog(share.CLUSEvInitCfgMapDone, e, loaded)
	}

	if len(failed) > 0 {
		e := "Following k8s configmap as neuvector init config failed to load "
		k8sResourceLog(share.CLUSEvInitCfgMapError, e, failed)
	}

}
