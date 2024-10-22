package rest

import (
	"encoding/json"
	"errors"
	"fmt"
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
const authconfigmap string = "/etc/config/userinitcfg.yaml"
const roleconfigmap string = "/etc/config/roleinitcfg.yaml"
const syscfgconfigmap string = "/etc/config/sysinitcfg.yaml"
const pwdprofileconfigmap string = "/etc/config/passwordprofileinitcfg.yaml"
const fedconfigmap string = "/etc/config/fedinitcfg.yaml"

const maxNameLength = 1024

type configMapHandlerContext struct {
	gotAllCustomRoles bool
	platform          string
	pwdProfile        *share.CLUSPwdProfile
	subDetail         string
	alwaysReload      bool // set by each HandlerFunc
	defAdminLoaded    bool // set only when default admin user is loaded from userinitcfg.yaml
}

var cfgmapRetryTimer *time.Timer
var cfgmapTried map[string]int = make(map[string]int) // cfg type -> tried times(<0 means no need to retry)

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
	context.alwaysReload = rconf.AlwaysReload

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
	context.alwaysReload = rconf.AlwaysReload

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
	context.alwaysReload = rconf.AlwaysReload

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
	context.alwaysReload = rc.AlwaysReload

	rconf := api.RESTSystemConfigConfigData{
		Config: &api.RESTSystemConfigConfig{
			NewServicePolicyMode:      rc.NewServicePolicyMode,
			NewServiceProfileMode:     rc.NewServiceProfileMode,
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
			EnableTLSVerification:     rc.EnableTLSVerification,
			GlobalCaCerts:             rc.GlobalCaCerts,
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
	context.alwaysReload = rconf.AlwaysReload

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
		if profileyaml_data, err := os.ReadFile(pwdprofileconfigmap); err == nil {
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
	context.alwaysReload = rconf.AlwaysReload

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
	context.alwaysReload = rconf.AlwaysReload

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
		if e := isValidRoleDomains(ruser.Fullname, ruser.Role, ruser.RoleDomains, nil, nil, false); e != nil {
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

		if ruser.Fullname == common.DefaultAdminUser && ruser.Server == "" {
			context.defAdminLoaded = true
		}

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
		if useryaml_data, err := os.ReadFile(authconfigmap); err == nil {
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

func LoadInitCfg(load bool, platform string) bool {
	log.WithFields(log.Fields{"load": load, "cfgmapTried": cfgmapTried}).Info()
	var loaded, failed []string
	var defAdminLoaded bool
	var skip bool
	// After that if configmap have license it will overwrite the consol and eventually write back to .lc
	type configMap struct {
		FileName    string
		Type        string
		HandlerFunc func([]byte, bool, *bool, *configMapHandlerContext) error
	}

	configMaps := []configMap{
		{FileName: roleconfigmap, Type: "role", HandlerFunc: handlecustomrolecfg},                   // must be before user/ldap/saml/oidc
		{FileName: pwdprofileconfigmap, Type: "password profile", HandlerFunc: handlepwdprofilecfg}, // must be before user
		{FileName: ldapconfigmap, Type: "ldap", HandlerFunc: handleldapcfg},
		{FileName: samlconfigmap, Type: "saml", HandlerFunc: handlesamlcfg},
		{FileName: oidcconfigmap, Type: "oidc", HandlerFunc: handleoidccfg},
		{FileName: syscfgconfigmap, Type: "system", HandlerFunc: handlesystemcfg},
		{FileName: authconfigmap, Type: "auth", HandlerFunc: handleusercfg},
	}

	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}

	var context configMapHandlerContext

	context.platform = platform
	for _, configMap := range configMaps {
		// check whether we need to retry loading configmap when it failed in the last loading
		if tried := cfgmapTried[configMap.Type]; tried >= 6 {
			cfgmapTried[configMap.Type] = -2 // no need to retry loading this config
		}
		tried := cfgmapTried[configMap.Type]
		if tried < 0 {
			continue
		}

		var errMsg string
		context.subDetail = ""
		context.alwaysReload = false
		context.defAdminLoaded = false
		if _, err := os.Stat(configMap.FileName); err == nil {
			if yaml_data, err := os.ReadFile(configMap.FileName); err == nil {
				skip = false
				err = configMap.HandlerFunc(yaml_data, load, &skip, &context)
				log.WithFields(log.Fields{"cfg": configMap.Type, "skip": skip, "error": err}).Debug()
				if err == nil {
					cfgmapTried[configMap.Type] = -1 // no need to retry loading this config
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
			if context.alwaysReload {
				cfgmapTried[configMap.Type] = tried + 1
			}
			log.Error(errMsg)
			failed = append(failed, errMsg)
		} else if configMap.Type == "auth" {
			defAdminLoaded = context.defAdminLoaded
		}
		context.alwaysReload = false
	}

	if len(loaded) > 0 {
		e := "Following k8s configmap loaded as neuvector init config "
		k8sResourceLog(share.CLUSEvInitCfgMapDone, e, loaded)
	}

	if len(failed) > 0 {
		e := "Following k8s configmap as neuvector init config failed to load "
		k8sResourceLog(share.CLUSEvInitCfgMapError, e, failed)

		cfgmapRetryTimer = time.AfterFunc(time.Duration(time.Minute), func() { LoadInitCfg(load, platform) })
	} else {
		if cfgmapRetryTimer != nil {
			cfgmapRetryTimer.Stop()
			cfgmapRetryTimer = nil
		}
		cfgmapTried = nil
	}
	log.WithFields(log.Fields{"load": load, "cfgmapTried": cfgmapTried, "defAdminLoaded": defAdminLoaded}).Info("done")

	return defAdminLoaded
}

func waitForFedRoleChange(roleExpected string) {
	for i := 0; i < 30; i++ {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == roleExpected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
}

func handlefedcfg(yaml_data []byte) (string, error) {
	json_data, err1 := yaml.YAMLToJSON(yaml_data)
	if err1 != nil {
		log.WithFields(log.Fields{"error": err1}).Error("fed config to json convert error")
		return "", err1
	}

	var rconf api.RESTFedDataCfgMap
	var err error

	if err := json.Unmarshal(json_data, &rconf); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return "", err
	} else if !rconf.PrimaryRestInfo.IsValid() {
		return "", fmt.Errorf("no primary rest server info")
	}

	var msg string
	var fedOp string
	acc := access.NewAdminAccessControl()
	login := loginSession{
		fullname:    common.ReservedNvSystemUser,
		remote:      "configmap",
		domainRoles: map[string]string{access.AccessDomainGlobal: api.UserRoleAdmin},
	}

	membership := clusHelper.GetFedMembership()
	fedSettings := clusHelper.GetFedSettings()

	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockFedKey); err != nil {
		return msg, err
	}
	defer clusHelper.ReleaseLock(lock)

	// configmap has higher priority over backup settings.
	if rconf.ManagedRestInfo == nil {
		// to be a master cluster
		fedOp = "promote"
		promote := true
		if membership.FedRole == api.FedRoleMaster {
			if membership.UseProxy != rconf.UseProxy {
				membership.UseProxy = rconf.UseProxy
				clusHelper.PutFedMembership(membership)
			}
			if rconf.DeployRepoScanData != nil && fedSettings.DeployRepoScanData != *rconf.DeployRepoScanData {
				var cfg share.CLUSFedSettings = share.CLUSFedSettings{DeployRepoScanData: *rconf.DeployRepoScanData}
				clusHelper.PutFedSettings(nil, cfg)
			}
			// check whether any published fed server info is different
			if membership.MasterCluster.RestInfo != rconf.PrimaryRestInfo {
				// it's already a master cluster but with different fed rest host/port. restart fed rest server
				StartStopFedPingPoll(share.StopFedRestServer, 0, nil)
				membership.LocalRestInfo = rconf.PrimaryRestInfo
				membership.MasterCluster.User = common.ReservedNvSystemUser
				membership.MasterCluster.RestInfo = rconf.PrimaryRestInfo
				clusHelper.PutFedMembership(membership)
				clusHelper.PutFedJointClusterList(&share.CLUSFedJoinedClusterList{})
				go StartStopFedPingPoll(share.StartFedRestServer, 0, nil)
			}
			promote = false
			if rconf.ClusterName != "" {
				oldName := cacher.GetSystemConfigClusterName(acc)
				if rconf.ClusterName != oldName {
					if list := clusHelper.GetFedJointClusterList(); list == nil || len(list.IDs) == 0 {
						updateSystemClusterName(rconf.ClusterName, acc)
					} else {
						log.WithFields(log.Fields{"name": rconf.ClusterName}).Info("cluster name cannot be changed when there is managed cluster in fedetation")
					}
				}
			}
			_fixedJoinToken = rconf.JoinToken
		} else if membership.FedRole == api.FedRoleJoint {
			// change from joint role to master role. leave original fed and then promote as master cluster
			reqData := api.RESTFedLeaveReq{Force: true}
			masterCluster := api.RESTFedMasterClusterInfo{
				Name:     membership.MasterCluster.Name,
				ID:       membership.MasterCluster.ID,
				Secret:   membership.MasterCluster.Secret,
				RestInfo: membership.MasterCluster.RestInfo,
			}
			jointCluster := api.RESTFedJointClusterInfo{
				ID:            membership.JointCluster.ID,
				Secret:        membership.JointCluster.Secret,
				RestInfo:      membership.JointCluster.RestInfo,
				ProxyRequired: membership.JointCluster.ProxyRequired,
			}
			if _, _, _, err = leaveFed(nil, acc, &login, reqData, masterCluster, jointCluster); err == nil {
				waitForFedRoleChange(api.FedRoleNone)
			}
		}
		if promote {
			if m := clusHelper.GetFedMembership(); m.FedRole != api.FedRoleNone {
				err = fmt.Errorf("it's not a standalone cluster(current cluster role: %s) before promotion", m.FedRole)
			} else {
				_fixedJoinToken = rconf.JoinToken
				reqData := api.RESTFedPromoteReqData{
					Name:               rconf.ClusterName,
					MasterRestInfo:     &rconf.PrimaryRestInfo,
					UseProxy:           &rconf.UseProxy,
					DeployRepoScanData: rconf.DeployRepoScanData,
				}
				if _, _, _, err = promoteToMaster(nil, acc, &login, reqData); err == nil {
					if m := clusHelper.GetFedMembership(); m.FedRole == api.FedRoleMaster {
						msg = fmt.Sprintf("Successfully set up primary cluster for federation(%s:%d)",
							rconf.PrimaryRestInfo.Server, rconf.PrimaryRestInfo.Port)
					}
				} else {
					log.WithFields(log.Fields{"err": err}).Debug("promote")
				}
			}
		}
	} else {
		// to be a managed cluster
		fedOp = "join"
		join := true
		if membership.FedRole == api.FedRoleMaster {
			// change from master role to joint role. demote from master cluster and then join another fed
			login.domainRoles[access.AccessDomainGlobal] = api.UserRoleFedAdmin
			if _, _, _, err = demoteFromMaster(nil, access.NewFedAdminAccessControl(), &login); err == nil {
				waitForFedRoleChange(api.FedRoleNone)
			}
		} else if membership.FedRole == api.FedRoleJoint {
			if membership.MasterCluster.RestInfo != rconf.PrimaryRestInfo || membership.JointCluster.RestInfo != *rconf.ManagedRestInfo {
				reqData := api.RESTFedLeaveReq{Force: true}
				masterCluster := api.RESTFedMasterClusterInfo{
					Name:     membership.MasterCluster.Name,
					ID:       membership.MasterCluster.ID,
					Secret:   membership.MasterCluster.Secret,
					RestInfo: membership.MasterCluster.RestInfo,
				}
				jointCluster := api.RESTFedJointClusterInfo{
					ID:            membership.JointCluster.ID,
					Secret:        membership.JointCluster.Secret,
					RestInfo:      membership.JointCluster.RestInfo,
					ProxyRequired: membership.JointCluster.ProxyRequired,
				}
				if _, _, _, err = leaveFed(nil, acc, &login, reqData, masterCluster, jointCluster); err == nil {
					waitForFedRoleChange(api.FedRoleNone)
				}
			}
		}
		if join {
			if m := clusHelper.GetFedMembership(); m.FedRole != api.FedRoleNone {
				err = fmt.Errorf("it's not a standalone cluster(current cluster role: %s) before joining federation", m.FedRole)
			} else {
				reqData := api.RESTFedJoinReq{
					Name:      rconf.ClusterName,
					Server:    rconf.PrimaryRestInfo.Server,
					Port:      rconf.PrimaryRestInfo.Port,
					JoinToken: rconf.JoinToken,
					JointRestInfo: &share.CLUSRestServerInfo{
						Server: rconf.ManagedRestInfo.Server,
						Port:   rconf.ManagedRestInfo.Port,
					},
					UseProxy: &rconf.UseProxy,
				}
				for i := 0; i < 3; i++ {
					if _, _, _, err = joinFed(nil, acc, &login, reqData); err == nil {
						if m := clusHelper.GetFedMembership(); m.FedRole == api.FedRoleJoint {
							msg = fmt.Sprintf("Successfully set up managed cluster(%s:%d) to join federation(primary cluster: %s:%d)",
								rconf.ManagedRestInfo.Server, rconf.ManagedRestInfo.Port, rconf.PrimaryRestInfo.Server, rconf.PrimaryRestInfo.Port)
							break
						}
					} else {
						log.WithFields(log.Fields{"err": err}).Debug("join")
					}
					time.Sleep(10 * time.Second)
				}
			}
		}
	}
	log.WithFields(log.Fields{"msg": msg, "err": err}).Info()

	if fedOp != "" && err != nil {
		err = fmt.Errorf("Failed to %s for federation setup(%s)", fedOp, err.Error())
	}

	return msg, err
}

func loadFedInitCfg() {
	log.Info()

	var errMsg string
	if _, err := os.Stat(fedconfigmap); err == nil {
		configMapType := "fed"
		if yaml_data, err := os.ReadFile(fedconfigmap); err == nil {
			msg, err := handlefedcfg(yaml_data)
			if err == nil {
				k8sResourceLog(share.CLUSEvInitCfgMapDone, msg, nil)
			} else {
				errMsg = fmt.Sprintf("%s init configmap failed: %s ", configMapType, err.Error())
			}
		} else {
			errMsg = fmt.Sprintf("%s init configmap read error: %s ", configMapType, err.Error())
		}
	}
	if errMsg != "" {
		log.Error(errMsg)
		k8sResourceLog(share.CLUSEvInitCfgMapError, errMsg, nil)
	}
	log.Info("done")
}
