package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
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
	platform          string
	pwdProfile        *share.CLUSPwdProfile
	subDetail         string
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
		remoteAuther = auth.NewRemoteAuther(nil)
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

	rconf := api.RESTSystemConfigConfigData{
		Config: &api.RESTSystemConfigConfig{
			NewServicePolicyMode:      rc.NewServicePolicyMode,
			NewServiceProfileBaseline: rc.NewServiceProfileBaseline,
			UnusedGroupAging:          rc.UnusedGroupAging,
			SyslogServer:              rc.SyslogServer,
			SyslogIPProto:             rc.SyslogIPProto,
			SyslogPort:                rc.SyslogPort,
			SyslogLevel:               rc.SyslogLevel,
			SyslogEnable:              rc.SyslogEnable,
			SyslogCategories:          rc.SyslogCategories,
			SyslogInJSON:              rc.SyslogInJSON,
			SingleCVEPerSyslog:        rc.SingleCVEPerSyslog,
			SyslogCVEInLayers:         rc.SyslogCVEInLayers,
			SyslogServerCert:          rc.SyslogServerCert,
			OutputEventToLogs:         rc.OutputEventToLogs,
			AuthOrder:                 rc.AuthOrder,
			AuthByPlatform:            rc.AuthByPlatform,
			RancherEP:                 rc.RancherEP,
			WebhookEnable:             rc.WebhookEnable,
			WebhookUrl:                rc.WebhookUrl,
			Webhooks:                  rc.Webhooks,
			ClusterName:               rc.ClusterName,
			ControllerDebug:           rc.ControllerDebug,
			MonitorServiceMesh:        rc.MonitorServiceMesh,
			RegistryHttpProxyEnable:   rc.RegistryHttpProxyEnable,
			RegistryHttpsProxyEnable:  rc.RegistryHttpsProxyEnable,
			RegistryHttpProxy:         rc.RegistryHttpProxy,
			RegistryHttpsProxy:        rc.RegistryHttpsProxy,
			IBMSAEpEnabled:            rc.IBMSAEpEnabled,
			IBMSAEpDashboardURL:       rc.IBMSAEpDashboardURL,
			XffEnabled:                rc.XffEnabled,
			ScannerAutoscale:          rc.ScannerAutoscale,
			NoTelemetryReport:         rc.NoTelemetryReport,
			RemoteRepositories:        rc.RemoteRepositories,
		},
		NetConfig: &api.RESTSysNetConfigConfig{
			NetServiceStatus:     rc.NetServiceStatus,
			NetServicePolicyMode: rc.NetServicePolicyMode,
			DisableNetPolicy:     rc.DisableNetPolicy,
			DetectUnmanagedWl:    rc.DetectUnmanagedWl,
		},
		AtmoConfig: &api.RESTSysAtmoConfigConfig{
			ModeAutoD2M:         rc.ModeAutoD2M,
			ModeAutoD2MDuration: rc.ModeAutoD2MDuration,
			ModeAutoM2P:         rc.ModeAutoM2P,
			ModeAutoM2PDuration: rc.ModeAutoM2PDuration,
		},
	}

	acc := access.NewAdminAccessControl()
	_, err = configSystemConfig(nil, acc, nil, "configmap", share.ScopeLocal, context.platform, &rconf)
	if err == nil && rc.ScanConfig != nil && rc.ScanConfig.AutoScan != nil {
		cconf := &share.CLUSScanConfig{AutoScan: *rc.ScanConfig.AutoScan}
		value, _ := json.Marshal(cconf)
		err = cluster.Put(share.CLUSConfigScanKey, value)
	}

	return err
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
		log.WithFields(log.Fields{"error": err}).Error("Admin user data not find")
		return
	}

	if user.PasswordHash != utils.HashPassword(common.DefaultAdminPass) {
		e := "already updated"
		log.WithFields(log.Fields{"Password of": common.DefaultAdminUser}).Error(e)
		return
	}

	var profile share.CLUSPwdProfile
	if _, err := os.Stat(pwdprofileconfigmap); err == nil {
		if profileyaml_data, err := ioutil.ReadFile(pwdprofileconfigmap); err == nil {
			if json_data, err := yaml.YAMLToJSON(profileyaml_data); err == nil {
				var rconf api.RESTPwdProfilesDataCfgMap
				if err := json.Unmarshal(json_data, &rconf); err == nil {
					for _, rprofile := range rconf.PwdProfiles {
						if rprofile != nil && rprofile.Name == share.CLUSDefPwdProfileName {
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
							if rprofile.SessionTimeout == 0 {
								profile.SessionTimeout = common.DefIdleTimeoutInternal
							} else {
								profile.SessionTimeout = rprofile.SessionTimeout
							}
							if profile.MinLen <= 0 || profile.MinUpperCount < 0 || profile.MinLowerCount < 0 || profile.MinDigitCount < 0 || profile.MinSpecialCount < 0 ||
								(profile.EnablePwdExpiration && profile.PwdExpireAfterDays <= 0) ||
								(profile.EnablePwdHistory && profile.PwdHistoryCount <= 0) ||
								(profile.EnableBlockAfterFailedLogin && (profile.BlockAfterFailedCount <= 0 || profile.BlockMinutes <= 0)) ||
								(profile.MinLen < (profile.MinUpperCount + profile.MinLowerCount + profile.MinDigitCount + profile.MinSpecialCount)) ||
								(profile.SessionTimeout > api.UserIdleTimeoutMax || profile.SessionTimeout < api.UserIdleTimeoutMin) {
								log.WithFields(log.Fields{"profile": profile}).Error("invalid value")
								profile = share.CLUSPwdProfile{}
							}
							break
						}
					}
				}
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("password profile config file read error")
		}
	}
	empty := share.CLUSPwdProfile{}
	if profile == empty {
		if pprofile, _, _ := clusHelper.GetPwdProfileRev(share.CLUSDefPwdProfileName, acc); pprofile != nil {
			profile = *pprofile
		}
	}

	if profile.EnablePwdHistory && profile.PwdHistoryCount > 0 {
		if weak, pwdHistoryToKeep, _, e := isWeakPassword(ruser.Password, utils.HashPassword(common.DefaultAdminPass), nil, &profile); weak {
			log.WithFields(log.Fields{"update password of": common.DefaultAdminUser}).Error(e)
			return
		} else {
			foundInHistory := false
			newPwdHash := utils.HashPassword(ruser.Password)
			if newPwdHash == user.PasswordHash {
				foundInHistory = true
			} else {
				for _, oldHash := range user.PwdHashHistory {
					if newPwdHash == oldHash {
						foundInHistory = true
						break
					}
				}
			}
			if !foundInHistory {
				if pwdHistoryToKeep <= 1 { // because user.PasswordHash remembers one password hash
					user.PwdHashHistory = nil
				} else {
					user.PwdHashHistory = append(user.PwdHashHistory, user.PasswordHash)
					if i := len(user.PwdHashHistory) - pwdHistoryToKeep; i >= 0 { // len(user.PwdHashHistory) + 1(current password hash) should be <= pwdHistoryToKeep
						user.PwdHashHistory = user.PwdHashHistory[i+1:]
					}
				}
			}
		}
	}
	user.PasswordHash = utils.HashPassword(ruser.Password)
	user.PwdResetTime = time.Now().UTC()

	if ruser.Timeout == 0 {
		if profile.SessionTimeout == 0 {
			ruser.Timeout = common.DefIdleTimeoutInternal
		} else {
			ruser.Timeout = profile.SessionTimeout
		}
	} else if ruser.Timeout > api.UserIdleTimeoutMax || ruser.Timeout < api.UserIdleTimeoutMin {
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
		if rprofile.SessionTimeout == 0 {
			profile.SessionTimeout = common.DefIdleTimeoutInternal
		} else {
			profile.SessionTimeout = rprofile.SessionTimeout
		}
		if profile.MinLen <= 0 || profile.MinUpperCount < 0 || profile.MinLowerCount < 0 || profile.MinDigitCount < 0 || profile.MinSpecialCount < 0 ||
			(profile.EnablePwdExpiration && profile.PwdExpireAfterDays <= 0) ||
			(profile.EnablePwdHistory && profile.PwdHistoryCount <= 0) ||
			(profile.EnableBlockAfterFailedLogin && (profile.BlockAfterFailedCount <= 0 || profile.BlockMinutes <= 0)) ||
			(profile.MinLen < (profile.MinUpperCount + profile.MinLowerCount + profile.MinDigitCount + profile.MinSpecialCount)) ||
			(profile.SessionTimeout > api.UserIdleTimeoutMax || profile.SessionTimeout < api.UserIdleTimeoutMin) {
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

	// occasionally the timing for kv callback to update cache about kv changes is just not right during start-up period.
	// so we simply read password profile from kv & pass it to isWeakPassword() later
	var activePwdProfileName string
	if context != nil && context.pwdProfile != nil {
		activePwdProfileName = context.pwdProfile.Name
	} else {
		activePwdProfileName = clusHelper.GetActivePwdProfileName()
	}
	profile, _, err := clusHelper.GetPwdProfileRev(activePwdProfileName, accAdmin)
	if err != nil {
		log.WithFields(log.Fields{"profile": activePwdProfileName, "error": err}).Error("Failed to get password profile")
		return err
	}

	var badPwdUsers []string
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

		// Check role
		if ruser.Fullname == common.DefaultAdminUser {
			fedRole := cacher.GetFedMembershipRoleNoAuth()
			roleForDefaultAdmin := api.UserRoleAdmin
			if fedRole == api.FedRoleMaster {
				roleForDefaultAdmin = api.UserRoleFedAdmin // default admin is always federate administrator on master cluster
			}
			if ruser.Role == "" || ruser.Role == api.UserRoleAdmin || ruser.Role == api.UserRoleFedAdmin {
				ruser.Role = roleForDefaultAdmin
			} else if ruser.Role != roleForDefaultAdmin {
				e := "Default admin user's role cannot be changed"
				log.WithFields(log.Fields{"user": ruser.Fullname, "fedRole": fedRole, "role": ruser.Role}).Error(e)
				continue
			}
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

		if weak, pwdHistoryToKeep, _, e := isWeakPassword(ruser.Password, user.PasswordHash, user.PwdHashHistory, profile); weak {
			log.WithFields(log.Fields{"create": ruser.Fullname}).Error(e)
			badPwdUsers = append(badPwdUsers, username)
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
			ruser.Timeout = profile.SessionTimeout
			if ruser.Timeout == 0 {
				ruser.Timeout = common.DefIdleTimeoutInternal
			}
		} else if ruser.Timeout > api.UserIdleTimeoutMax || ruser.Timeout < api.UserIdleTimeoutMin {
			e := "Invalid idle timeout value"
			log.WithFields(log.Fields{"create": ruser.Fullname, "timeout": ruser.Timeout}).Error(e)
			continue
		}
		user.Timeout = ruser.Timeout

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
	if len(badPwdUsers) == 1 {
		context.subDetail = fmt.Sprintf("password for user %s does not meet password profile requirements", badPwdUsers[0])
	} else if len(badPwdUsers) > 1 {
		context.subDetail = fmt.Sprintf("passwords for users %s do not meet password profile requirements", strings.Join(badPwdUsers, ", "))
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
	if len(detail) > 0 {
		clog.Msg = fmt.Sprintf("%s :\n.  %s", msg, strings.Join(detail[:], "\n.  "))
	} else {
		clog.Msg = msg
	}
	evqueue.Append(&clog)
}

func LoadInitCfg(load bool, platform string) {
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

	context.platform = platform
	for _, configMap := range configMaps {
		var errMsg string
		context.subDetail = ""
		if _, err := os.Stat(configMap.FileName); err == nil {
			if yaml_data, err := ioutil.ReadFile(configMap.FileName); err == nil {
				skip = false
				err = configMap.HandlerFunc(yaml_data, load, &skip, &context)
				log.WithFields(log.Fields{"cfg": configMap.Type, "skip": skip, "error": err}).Debug()
				if err == nil {
					msg := fmt.Sprintf("%s init configmap loaded", configMap.Type)
					if context.subDetail != "" {
						msg = fmt.Sprintf("%s partially:\n   %s", msg, context.subDetail)
					}
					loaded = append(loaded, msg)
				} else {
					errMsg = fmt.Sprintf("%s init configmap failed: %s ", configMap.Type, err.Error())
				}
			} else {
				errMsg = fmt.Sprintf("%s init configmap read error: %s ", configMap.Type, err.Error())
			}
		}
		if errMsg != "" {
			log.Error(errMsg)
			failed = append(failed, errMsg)
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
	log.WithFields(log.Fields{"load": load}).Info("done")

}
