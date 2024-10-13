package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var TESTApikeySpecifiedCretionTime bool

// return (isWeak, pwdHistoryToKeep, profileBasic, message)
func isWeakPassword(newPwd, pwdHash string, pwdHashHistory []string, useProfile *share.CLUSPwdProfile) (bool, int, api.RESTPwdProfileBasic, string) {
	var upperCount, lowerCount, digitCount, specialCount int
	var profileBasic api.RESTPwdProfileBasic
	var profile share.CLUSPwdProfile
	var err error

	if useProfile == nil {
		profile, err = cacher.GetPwdProfile(share.CLUSSysPwdProfileName)
	} else {
		profile = *useProfile
	}
	if err == nil {
		profileBasic = api.RESTPwdProfileBasic{
			MinLen:          profile.MinLen,
			MinUpperCount:   profile.MinUpperCount,
			MinLowerCount:   profile.MinLowerCount,
			MinDigitCount:   profile.MinDigitCount,
			MinSpecialCount: profile.MinSpecialCount,
		}
		pwdHistoryCount := profile.PwdHistoryCount
		if !profile.EnablePwdHistory {
			pwdHistoryCount = 0
		}
		for _, char := range newPwd {
			if unicode.IsUpper(char) {
				upperCount++
			} else if unicode.IsLower(char) {
				lowerCount++
			} else if unicode.IsNumber(char) {
				digitCount++
			} else if unicode.IsSymbol(char) || unicode.IsPunct(char) {
				specialCount++
			}
		}
		if len(newPwd) < profile.MinLen || upperCount < profile.MinUpperCount || lowerCount < profile.MinLowerCount ||
			digitCount < profile.MinDigitCount || specialCount < profile.MinSpecialCount {
			return true, pwdHistoryCount, profileBasic, "Weak password"
		}

		if pwdHistoryCount > 0 {
			newPwdHash := utils.HashPassword(newPwd)
			if pwdHash != "" && newPwdHash == pwdHash {
				return true, pwdHistoryCount, profileBasic, "Password has been used before"
			} else if len(pwdHashHistory) > 0 {
				idx := 0
				if i := len(pwdHashHistory) - profile.PwdHistoryCount; i >= 0 {
					idx = i + 1 // because user.PasswordHash remembers one password hash
				}
				for i := idx; i < len(pwdHashHistory); i++ {
					if newPwdHash == pwdHashHistory[i] {
						return true, pwdHistoryCount, profileBasic, "Password has been used before"
					}
				}
			}
		}
	}

	return false, profile.PwdHistoryCount, profileBasic, ""
}

func handlerUserCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTUserData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.User == nil {
		e := "Request error"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	ruser := rconf.User
	username := ruser.Fullname
	if len(username) == 0 || username[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	// User's own domain does't matter, only domains they can manage matters.

	if !isUserNameValid(username) {
		e := "Invalid characters in username"
		log.WithFields(log.Fields{"login": login.fullname, "create": ruser.Fullname}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if e := isValidRoleDomains(ruser.Fullname, ruser.Role, ruser.RoleDomains, nil, nil, true); e != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
		return
	}

	// 1. Only fedAdmin can create users with fedAdmin/fedReader role (on master cluster)
	// 2. For every domain that a namespace user is in, the creater must have PERM_AUTHORIZATION(modify) permission in the domain
	user := share.CLUSUser{
		Fullname:    utils.MakeUserFullname("", username),
		Username:    username,
		EMail:       ruser.EMail,
		Role:        ruser.Role,
		Locale:      ruser.Locale,
		RoleDomains: ruser.RoleDomains,
	}
	if !acc.AuthorizeOwn(&user, nil) {
		log.WithFields(log.Fields{"login": login.fullname, "user": ruser.Fullname}).Error(common.ErrObjectAccessDenied.Error())
		restRespAccessDenied(w, login)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if user already exists
	if userExisting, _, _ := clusHelper.GetUserRev(ruser.Fullname, acc); userExisting != nil {
		e := "User already exists"
		log.WithFields(log.Fields{"login": login.fullname, "create": ruser.Fullname}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		return
	}

	// Check weak password
	if weak, _, profileBasic, e := isWeakPassword(ruser.Password, "", nil, nil); weak {
		log.WithFields(log.Fields{"login": login.fullname, "create": ruser.Fullname}).Error(e)
		restRespErrorMessageEx(w, http.StatusBadRequest, api.RESTErrWeakPassword, e, profileBasic)
		return
	} else {
		user.PasswordHash = utils.HashPassword(ruser.Password)
		user.FailedLoginCount = 0
		user.BlockLoginSince = time.Time{}
		user.PwdResetTime = time.Now().UTC()
	}

	if ruser.Timeout == 0 {
		ruser.Timeout = common.DefaultIdleTimeout
	} else if ruser.Timeout > api.UserIdleTimeoutMax || ruser.Timeout < api.UserIdleTimeoutMin {
		e := "Invalid idle timeout value"
		log.WithFields(log.Fields{"login": login.fullname, "create": ruser.Fullname, "timeout": ruser.Timeout}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	user.Timeout = ruser.Timeout

	if user.Locale == "" {
		user.Locale = common.OEMDefaultUserLocale
	}

	if e := normalizeUserRoles(&user); e != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
		return
	}
	if username == common.DefaultAdminUser {
		fedRole := cacher.GetFedMembershipRoleNoAuth()
		roleForDefaultAdmin := api.UserRoleAdmin
		if fedRole == api.FedRoleMaster {
			roleForDefaultAdmin = api.UserRoleFedAdmin
		}
		if user.Role != roleForDefaultAdmin {
			e := fmt.Sprintf("User \"admin\" must be %s role", roleForDefaultAdmin)
			log.WithFields(log.Fields{"fedRole": fedRole, "error": err}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}
	if err := clusHelper.CreateUser(&user); err != nil {
		e := "Failed to write to the cluster"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Create user")
}

func user2REST(user *share.CLUSUser, acc *access.AccessControl) *api.RESTUser {
	var defaultPW bool
	if user.Fullname == common.DefaultAdminUser && user.PasswordHash == utils.HashPassword(common.DefaultAdminPass) {
		defaultPW = true
	}

	userRest := &api.RESTUser{
		Fullname:           user.Fullname,
		Server:             user.Server,
		Username:           user.Username,
		Role:               user.Role,
		EMail:              user.EMail,
		Timeout:            user.Timeout,
		Locale:             user.Locale,
		DefaultPWD:         defaultPW,
		RoleDomains:        user.RoleDomains,
		LastLoginTimeStamp: user.LastLoginAt.Unix(),
		LastLoginAt:        api.RESTTimeString(user.LastLoginAt),
		LoginCount:         user.LoginCount,
	}

	if strings.HasPrefix(user.Server, share.FlavorRancher) {
		userRest.ExtraPermits = access.GetTopLevelPermitsList(access.CONST_PERM_SUPPORT_GLOBAL, user.ExtraPermits)
		if len(user.ExtraPermitsDomains) > 0 {
			extraPermitsDomains := make([]api.RESTPermitsAssigned, len(user.ExtraPermitsDomains))
			for i, permitsDomains := range user.ExtraPermitsDomains {
				extraPermitsDomains[i] = api.RESTPermitsAssigned{
					Permits: access.GetTopLevelPermitsList(access.CONST_PERM_SUPPORT_DOMAIN, permitsDomains.Permits),
					Domains: permitsDomains.Domains,
				}
			}
			userRest.ExtraPermitsDomains = extraPermitsDomains
		}

		if user.RemoteRolePermits != nil {
			var remoteRolePermits api.RESTRemoteRolePermits
			if len(user.RemoteRolePermits.DomainRole) > 0 {
				remoteRoleDomains := make(map[string][]string, 3)
				for d, r := range user.RemoteRolePermits.DomainRole {
					if d == access.AccessDomainGlobal {
						remoteRolePermits.Role = r
					} else {
						domains := remoteRoleDomains[r]
						remoteRoleDomains[r] = append(domains, d)
					}
				}
				remoteRolePermits.RoleDomains = remoteRoleDomains
			}
			if len(user.RemoteRolePermits.ExtraPermits) > 0 {
				remoteExtraPermitsDomains := make(map[share.NvPermissions][]string, len(user.ExtraPermitsDomains))
				for d, p := range user.RemoteRolePermits.ExtraPermits {
					if d == access.AccessDomainGlobal {
						remoteRolePermits.ExtraPermits = access.GetTopLevelPermitsList(access.CONST_PERM_SUPPORT_GLOBAL, p)
					} else {
						domains := remoteExtraPermitsDomains[p]
						remoteExtraPermitsDomains[p] = append(domains, d)
					}
				}
				if len(remoteExtraPermitsDomains) > 0 {
					extraPermitsDomains := make([]api.RESTPermitsAssigned, 0, len(remoteExtraPermitsDomains))
					for p, domains := range remoteExtraPermitsDomains {
						assigned := api.RESTPermitsAssigned{
							Permits: access.GetTopLevelPermitsList(access.CONST_PERM_SUPPORT_DOMAIN, p),
							Domains: domains,
						}
						extraPermitsDomains = append(extraPermitsDomains, assigned)
					}
					remoteRolePermits.ExtraPermitsDomains = extraPermitsDomains
				}
			}
			if remoteRolePermits.Role != "" || len(remoteRolePermits.RoleDomains) > 0 ||
				len(remoteRolePermits.ExtraPermits) > 0 || len(remoteRolePermits.ExtraPermitsDomains) > 0 {
				userRest.RemoteRolePermits = &remoteRolePermits
			}
		}
	}

	if acc != nil && acc.HasGlobalPermissions(0, share.PERM_AUTHORIZATION) && userRest.Server == "" {
		if acc.IsFedAdmin() || (acc.CanWriteCluster() && user.Role != api.UserRoleFedAdmin && user.Role != api.UserRoleFedReader) {
			userRest.PwdResettable = true
		}
	}

	return userRest
}

func handlerUserShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	fullname := ps.ByName("fullname")
	fullname, _ = url.PathUnescape(fullname)
	if len(fullname) == 0 || fullname[0] == '~' {
		handlerNotFound(w, r)
		return
	}

	// Retrieve user from the cluster
	user, _, err := clusHelper.GetUserRev(fullname, acc)
	if user == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTUserData{User: user2REST(user, acc)}
	if user.Server == "" {
		if pwdProfile, err := cacher.GetPwdProfile(share.CLUSSysPwdProfileName); err == nil {
			now := time.Now().UTC()
			if pwdProfile.EnablePwdExpiration && pwdProfile.PwdExpireAfterDays > 0 {
				pwdValidUnit := _pwdValidUnit
				if user.Fullname == common.DefaultAdminUser {
					pwdValidUnit = _pwdValidPerDayUnit
				}
				pwdExpireTime := user.PwdResetTime.Add(time.Duration(time.Minute * pwdValidUnit * time.Duration(pwdProfile.PwdExpireAfterDays)))
				if now.After(pwdExpireTime) {
					resp.User.BlockedForPwdExpired = true
				}
			}
			if pwdProfile.EnableBlockAfterFailedLogin && !user.BlockLoginSince.IsZero() {
				if now.Before(user.BlockLoginSince.Add(time.Minute * time.Duration(pwdProfile.BlockMinutes))) {
					resp.User.BlockedForFailedLogin = true
				}
			}
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get user detail")
}

// API used to get the user from token.
func handlerSelfUserShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if login.fullname == "" {
		restRespAccessDenied(w, login)
		return
	} else if login.loginType == loginTypeApikey {
		restRespAccessDenied(w, login)
		return
	}

	// Retrieve user from the cluster
	user, _, err := clusHelper.GetUserRev(login.fullname, access.NewReaderAccessControl())
	if user == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTSelfUserData{User: user2REST(user, acc)}
	if user.Server == "" {
		pwdDaysUntilExpire, pwdHoursUntilExpire, _ := isPasswordExpired(true, user.Fullname, user.PwdResetTime)
		resp.PwdDaysUntilExpire = pwdDaysUntilExpire
		resp.PwdHoursUntilExpire = pwdHoursUntilExpire
	} else {
		resp.PwdDaysUntilExpire = -1
		resp.PwdHoursUntilExpire = 0
	}
	resp.GlobalPermits, resp.DomainPermits, _ = access.GetUserPermissions(user.Role, user.RoleDomains, user.ExtraPermits, user.ExtraPermitsDomains)

	// collect all top-level permissions from role/extraPermits for global domain on remote managed clsuters
	if user.RemoteRolePermits != nil {
		role := api.UserRoleNone
		extraPermits := share.NvPermissions{}
		if user.RemoteRolePermits.DomainRole != nil {
			role = user.RemoteRolePermits.DomainRole[access.AccessDomainGlobal]
		}
		if user.RemoteRolePermits.ExtraPermits != nil {
			extraPermits = user.RemoteRolePermits.ExtraPermits[access.AccessDomainGlobal]
		}
		resp.RemoteGlobalPermits, _, _ = access.GetUserPermissions(role, nil, extraPermits, nil)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get self user detail")
}

func handlerUserList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Retrieve all users
	var resp api.RESTUsersData
	resp.Users = make([]*api.RESTUser, 0)

	now := time.Now().UTC()
	pwdProfile, _ := cacher.GetPwdProfile(share.CLUSSysPwdProfileName)
	users := clusHelper.GetAllUsersNoAuth()
	for _, user := range users {
		if login.fullname != user.Fullname || login.loginType == loginTypeApikey { // a user can always see himself/herself
			if !acc.Authorize(user, nil) {
				continue
			}
		}

		// skip hidden user
		if len(user.Fullname) == 0 || user.Fullname[0] == '~' {
			continue
		}

		// Domain user can only list user of its domain
		if login.domain != "" && login.domain != user.Domain {
			continue
		}

		userRest := user2REST(user, acc)
		if user.Server == "" && pwdProfile.Name != "" {
			if pwdProfile.EnablePwdExpiration && pwdProfile.PwdExpireAfterDays > 0 {
				pwdValidUnit := _pwdValidUnit
				if user.Fullname == common.DefaultAdminUser {
					pwdValidUnit = _pwdValidPerDayUnit
				}
				pwdExpireTime := user.PwdResetTime.Add(time.Duration(time.Minute * pwdValidUnit * time.Duration(pwdProfile.PwdExpireAfterDays)))
				if now.After(pwdExpireTime) {
					userRest.BlockedForPwdExpired = true
				}
			}
			if pwdProfile.EnableBlockAfterFailedLogin && !user.BlockLoginSince.IsZero() {
				if now.Before(user.BlockLoginSince.Add(time.Minute * time.Duration(pwdProfile.BlockMinutes))) {
					userRest.BlockedForFailedLogin = true
				}
			}
		}
		resp.Users = append(resp.Users, userRest)
	}

	resp.GlobalRoles = access.GetValidRoles(access.CONST_VISIBLE_USER_ROLE)
	resp.DomainRoles = access.GetValidRoles(access.CONST_VISIBLE_DOMAIN_ROLE)
	sort.Slice(resp.Users, func(i, j int) bool { return resp.Users[i].Fullname < resp.Users[j].Fullname })

	restRespSuccess(w, r, &resp, acc, login, nil, "Get user list")
}

func applyRoleChange(old *share.CLUSUser, new *api.RESTUserConfig) (*share.CLUSUser, bool) {
	var roleMod bool = false
	// A dummy user for role change authz. If the role in a domain is change, we set the _reader_ role to
	// the dummy user, then authorize this dummy user.
	roleModUser := share.CLUSUser{RoleDomains: make(map[string][]string)}

	// UI sends all fields when modifying a user, so we have to compare to see if value indeed changed.
	if new.Role != nil && *new.Role != old.Role {
		old.Role = *new.Role
		roleModUser.Role = roleModDummyRole
		roleMod = true
	}

	if new.RoleDomains != nil {
		diff := utils.NewSet()

		for _, role := range access.GetValidRoles(access.CONST_VISIBLE_DOMAIN_ROLE) {
			oldSet := utils.NewSetFromSliceKind(old.RoleDomains[role])
			newSet := utils.NewSetFromSliceKind((*new.RoleDomains)[role])
			diff = diff.Union(oldSet.SymmetricDifference(newSet))
		}

		// 'diff' accumulates domains where role is changed.
		if diff.Cardinality() > 0 {
			old.RoleDomains = *new.RoleDomains
			roleModUser.RoleDomains[roleModDummyRole] = diff.ToStringSlice()
			roleMod = true
		}
	}

	return &roleModUser, roleMod
}

func normalizeUserRoles(user *share.CLUSUser) error {
	if user.Role == api.UserRoleFedAdmin || user.Role == api.UserRoleAdmin || user.RoleDomains == nil {
		// If the user is fed admin or cluster admin, then it is the admin of all namespaces
		user.RoleDomains = make(map[string][]string)
	} else {
		// With a user's global role, it doesn't need to have the same role in its RoleDomains
		delete(user.RoleDomains, user.Role)

		domainRole := make(map[string]string, 0)
		for role, domains := range user.RoleDomains {
			domainsFound := utils.NewSet()
			for _, d := range domains {
				if r, ok := domainRole[d]; ok {
					if r == role { // same domain shows up multiple times for a role. avoid duplicate domain entry
						continue
					}
					return fmt.Errorf("Multiple roles(%s, %s) for a domain(%s) is not allowed", role, r, d)
				} else {
					domainRole[d] = role
					domainsFound.Add(d)
				}
			}
			user.RoleDomains[role] = domainsFound.ToStringSlice()
		}
	}

	return nil
}

func handlerUserConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	fullname := ps.ByName("fullname")
	fullname, _ = url.PathUnescape(fullname)

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTUserConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		e := "Request error"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if fullname != rconf.Config.Fullname {
		e := "Username not match"
		log.WithFields(log.Fields{"name": fullname, "config": rconf.Config.Fullname}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	} else if len(fullname) == 0 || fullname[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		var myself, kick bool

		// Retrieve user from the cluster
		user, rev, err := clusHelper.GetUserRev(fullname, access.NewReaderAccessControl())
		if user == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		myself = compareUserWithLogin(user, login)

		// First check if the login user can modify the user. Allow the login user to modify its own user.
		// We will check at the end if the modification is valid.
		if !myself {
			if !acc.AuthorizeOwn(user, nil) {
				restRespAccessDenied(w, login)
				return
			}
		}

		/*
			if readonly && !myself {
				e := "Non-admin user can only configure self"
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}
		*/

		// Domain admin can only modify user of its domain
		if login.domain != "" && login.domain != user.Domain {
			e := "Cannot modify user in different domain"
			log.WithFields(log.Fields{"user": fullname}).Error(e)
			restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
			return
		}

		ruser := rconf.Config

		if strings.HasPrefix(user.Server, share.FlavorRancher) {
			if ruser.Role != nil || ruser.RoleDomains != nil {
				//e := "Cannot change Rancher SSO user's role/permissions in NeuVector"
				//log.WithFields(log.Fields{"user": fullname}).Error(e)
				ruser.Role = nil
				ruser.RoleDomains = nil
			}
		}

		// To modify password, existing password must be given
		if ruser.NewPassword != nil {
			if !myself {
				e := "Cannot modify other user's password"
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}

			if user.Server != "" {
				e := "Cannot modify remote user's password"
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}

			if ruser.Password == nil {
				e := "Need current password to modify password."
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}

			if user.PasswordHash != utils.HashPassword(*ruser.Password) {
				e := "Current password doesn't match."
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}

			if weak, pwdHistoryToKeep, profileBasic, e := isWeakPassword(*ruser.NewPassword, user.PasswordHash, user.PwdHashHistory, nil); weak {
				log.WithFields(log.Fields{"create": ruser.Fullname}).Error(e)
				restRespErrorMessageEx(w, http.StatusBadRequest, api.RESTErrWeakPassword, e, profileBasic)
				return
			} else {
				if pwdHistoryToKeep <= 1 { // because user.PasswordHash remembers one password hash
					user.PwdHashHistory = nil
				} else {
					user.PwdHashHistory = append(user.PwdHashHistory, user.PasswordHash)
					if i := len(user.PwdHashHistory) - pwdHistoryToKeep; i >= 0 { // len(user.PwdHashHistory) + 1(current password hash) should be <= pwdHistoryToKeep
						user.PwdHashHistory = user.PwdHashHistory[i+1:]
					}
				}
				user.PasswordHash = utils.HashPassword(*ruser.NewPassword)
				user.PwdResetTime = time.Now().UTC()
			}
			kick = true
		}

		fedRole := cacher.GetFedMembershipRoleNoAuth()
		if fullname == common.DefaultAdminUser && ruser.Role != nil {
			if (fedRole == api.FedRoleMaster && *ruser.Role != api.UserRoleFedAdmin) || (fedRole != api.FedRoleMaster && *ruser.Role != api.UserRoleAdmin) {
				e := "Default admin user's role cannot be changed"
				log.WithFields(log.Fields{"user": fullname, "role": *ruser.Role, "fedRole": fedRole}).Error(e)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
				return
			}
		}

		if !strings.HasPrefix(user.Server, share.FlavorRancher) {
			// Check if global role & domain roles are valid
			newRole := user.Role
			newRoleDomains := user.RoleDomains
			if ruser.Role != nil {
				newRole = *ruser.Role
			}
			if ruser.RoleDomains != nil {
				newRoleDomains = *ruser.RoleDomains
			}
			if e := isValidRoleDomains(ruser.Fullname, newRole, newRoleDomains, nil, nil, false); e != nil {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
				return
			}

			err = nil
			if (user.Role == api.UserRoleIBMSA) || (user.Role == api.UserRoleImportStatus) {
				err = common.ErrObjectAccessDenied
			} else {
				fedRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)
				if fedRole == api.FedRoleMaster {
					if newRole != user.Role {
						// On master cluster, only users with fedAdmin role can:
						// 1. assign/remove fedAdmin/fedReader role to/from users
						// 2. delete users who have fedAdmin/fedReader role
						if (login.domainRoles[access.AccessDomainGlobal] != api.UserRoleFedAdmin) && (fedRoles.Contains(newRole) || fedRoles.Contains(user.Role)) {
							err = common.ErrObjectAccessDenied
						}
					}
				} else if fedRoles.Contains(newRole) {
					// On non-master cluster, fedAdmin/fedReader roles cannot be be assigned to user
					err = common.ErrObjectAccessDenied
				}
			}
			if err == common.ErrObjectAccessDenied {
				restRespAccessDenied(w, login)
				return
			}

			// With a user's global role, it doesn't need to have the same role in its RoleDomains
			delete(newRoleDomains, newRole)

			// If configuring myself, no authz needed if role not changed; if not myself, authz has been done.
			// For every domain that a user is in, the creater must have PERM_AUTHORIZATION(modify) permission in the domain
			if roleModUser, roleModified := applyRoleChange(user, ruser); roleModified {
				log.WithFields(log.Fields{
					"acc":        acc,
					"mod-role":   roleModUser.Role == roleModDummyRole,
					"mod-domain": roleModUser.RoleDomains[roleModDummyRole],
				}).Debug("Role modified")

				if !acc.AuthorizeOwn(roleModUser, nil) {
					restRespAccessDenied(w, login)
					return
				}

				user.RoleOverride = true
				kick = true
			}
		}

		if ruser.EMail != nil {
			user.EMail = *ruser.EMail
		}
		if ruser.Timeout != nil {
			if *ruser.Timeout == 0 {
				*ruser.Timeout = common.DefaultIdleTimeout
			} else if *ruser.Timeout > api.UserIdleTimeoutMax || *ruser.Timeout < api.UserIdleTimeoutMin {
				e := fmt.Sprintf("Invalid idle timeout value. (%v, %v)", api.UserIdleTimeoutMin, api.UserIdleTimeoutMax)
				log.WithFields(log.Fields{"user": fullname, "timeout": *ruser.Timeout}).Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return
			}

			user.Timeout = *ruser.Timeout
		}
		if ruser.Locale != nil {
			if *ruser.Locale == "" {
				*ruser.Locale = common.OEMDefaultUserLocale
			}

			user.Locale = *ruser.Locale
		}

		if e := normalizeUserRoles(user); e != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
			return
		}
		if err := clusHelper.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
			retry++
		} else {
			if kick {
				kickLoginSessions(user)
			}
			if ruser.Timeout != nil {
				changeTimeoutLoginSessions(user)
			}

			break
		}
	}

	if retry >= retryClusterMax {
		e := "Failed to write to the cluster"
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure user")
}

func handlerUserPwdConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	fullname := ps.ByName("fullname")
	fullname, _ = url.PathUnescape(fullname)
	if len(fullname) == 0 || fullname[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var errMsg string
	var rconf api.RESTUserPwdConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		errMsg = "Request error"
	} else if fullname != rconf.Config.Fullname {
		errMsg = "Username not match"
	} else if rconf.Config.ForceResetPwd && rconf.Config.NewPassword == nil {
		errMsg = "No password provided"
	}
	if errMsg != "" {
		log.WithFields(log.Fields{"error": err, "fullname": fullname}).Error(errMsg)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, errMsg)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	var unblockUser, resetPassword bool
	retry := 0
	for retry < retryClusterMax {
		pwdProfile, _ := cacher.GetPwdProfile(share.CLUSSysPwdProfileName)
		// Retrieve user from the cluster
		user, rev, err := clusHelper.GetUserRev(fullname, acc)
		if user == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		ruser := rconf.Config
		if ruser.ClearFailedLogin != nil && *ruser.ClearFailedLogin {
			zeroTime := time.Time{}
			if user.BlockLoginSince != zeroTime {
				unblockUser = true
			}
			user.FailedLoginCount = 0
			user.BlockLoginSince = time.Time{}
		}

		if ruser.NewPassword != nil {
			errMsg = ""
			if user.Server != "" {
				errMsg = "Cannot modify remote user's password"
			} else if !ruser.ForceResetPwd && pwdProfile.EnablePwdExpiration && pwdProfile.PwdExpireAfterDays > 0 {
				pwdValidUnit := _pwdValidUnit
				if user.Fullname == common.DefaultAdminUser {
					pwdValidUnit = _pwdValidPerDayUnit
				}
				pwdExpireTime := user.PwdResetTime.Add(time.Duration(time.Minute * pwdValidUnit * time.Duration(pwdProfile.PwdExpireAfterDays)))
				if time.Now().UTC().Before(pwdExpireTime) {
					errMsg = "user's password is not expired yet"
				}
			}
			if errMsg != "" {
				log.WithFields(log.Fields{"user": fullname}).Error(errMsg)
				restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, errMsg)
				return
			}

			// only fedAdmin-role user can force reset other fedAdmin/fedReader-role user's password
			// only admin-role user can force reset other admin-role user's password
			if ((user.Role == api.UserRoleFedAdmin || user.Role == api.UserRoleFedReader) && !acc.IsFedAdmin()) ||
				(user.Role == api.UserRoleAdmin && !acc.CanWriteCluster()) {
				restRespAccessDenied(w, login)
				return
			}

			if weak, pwdHistoryToKeep, profileBasic, e := isWeakPassword(*ruser.NewPassword, user.PasswordHash, user.PwdHashHistory, nil); weak {
				log.WithFields(log.Fields{"user": fullname}).Error(e)
				restRespErrorMessageEx(w, http.StatusBadRequest, api.RESTErrWeakPassword, e, profileBasic)
				return
			} else {
				if pwdHistoryToKeep <= 1 { // because user.PasswordHash remembers one password hash
					user.PwdHashHistory = nil
				} else {
					user.PwdHashHistory = append(user.PwdHashHistory, user.PasswordHash)
					if i := len(user.PwdHashHistory) - pwdHistoryToKeep; i >= 0 { // len(user.PwdHashHistory) + 1(current password hash) should be <= pwdHistoryToKeep
						user.PwdHashHistory = user.PwdHashHistory[i+1:]
					}
				}
				user.PasswordHash = utils.HashPassword(*ruser.NewPassword)
				user.PwdResetTime = time.Now().UTC()
				if ruser.ForceResetPwd {
					user.FailedLoginCount = 0
					user.BlockLoginSince = time.Time{}
					user.ResetPwdInNextLogin = ruser.ResetPwdInNextLogin
				}
				resetPassword = true
			}
		}

		if err := clusHelper.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			if resetPassword {
				kickLoginSessions(user)
			}
			break
		}
	}

	if retry >= retryClusterMax {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, "Failed to write to the cluster")
		return
	} else {
		remote := r.RemoteAddr
		if i := strings.Index(remote, ":"); i > 0 {
			remote = remote[:i]
		}
		if unblockUser {
			msg := fmt.Sprintf("User %s is unblocked from login by %s", fullname, login.fullname)
			authLog(share.CLUSEvAuthLoginUnblocked, fullname, remote, "", nil, msg)
		}
		if resetPassword {
			msg := fmt.Sprintf("User %s's password is reset by %s", fullname, login.fullname)
			authLog(share.CLUSEvAuthUserPwdResetByAdmin, fullname, remote, "", nil, msg)
		}
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure user login")
}

func handlerUserRoleDomainsConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	fullname := ps.ByName("fullname")
	fullname, _ = url.PathUnescape(fullname)
	role := ps.ByName("role")
	if len(fullname) == 0 || fullname[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTUserRoleDomainsConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config
	if rc.Fullname != fullname {
		e := "Name mismatch"
		log.WithFields(log.Fields{"user": rc.Fullname}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if rc.Role != role {
		e := "Role mismatch"
		log.WithFields(log.Fields{"user": rc.Fullname, "role": rc.Role}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		var kick bool

		user, rev, err := clusHelper.GetUserRev(fullname, acc)
		if user == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		var roleMod bool = false
		// A dummy user for role change authz. If the role in a domain is change, we set the _reader_ role to
		// the dummy user, then authorize this dummy user.
		roleModUser := share.CLUSUser{RoleDomains: make(map[string][]string)}
		if rc.Domains == nil {
			if domains, ok := user.RoleDomains[role]; ok && len(domains) > 0 {
				delete(user.RoleDomains, role)
				roleModUser.RoleDomains[roleModDummyRole] = domains
				roleMod = true
			}
		} else {
			var oldSet utils.Set
			if domains, ok := user.RoleDomains[role]; ok && len(domains) > 0 {
				oldSet = utils.NewSetFromSliceKind(domains)
			} else {
				oldSet = utils.NewSet()
			}
			newSet := utils.NewSetFromSliceKind(rc.Domains)
			diff := oldSet.SymmetricDifference(newSet)
			if diff.Cardinality() > 0 {
				user.RoleDomains[role] = rc.Domains
				roleModUser.RoleDomains[roleModDummyRole] = diff.ToStringSlice()
				roleMod = true
			}
		}

		if roleMod {
			log.WithFields(log.Fields{
				"acc":        acc,
				"mod-role":   roleModUser.Role == roleModDummyRole,
				"mod-domain": roleModUser.RoleDomains[roleModDummyRole],
			}).Debug("Role modified")

			if !acc.AuthorizeOwn(&roleModUser, nil) {
				restRespAccessDenied(w, login)
				return
			}

			kick = true
		}

		if e := isValidRoleDomains(user.Fullname, user.Role, user.RoleDomains, nil, nil, false); e != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
			return
		}

		if e := normalizeUserRoles(user); e != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
			return
		}
		if err := clusHelper.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
			retry++
		} else {
			if kick {
				kickLoginSessions(user)
			}

			break
		}
	}

	if retry >= retryClusterMax {
		e := "Failed to write to the cluster"
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure user '%v' role domains", fullname))
}

func handlerUserDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	fullname := ps.ByName("fullname")
	fullname, _ = url.PathUnescape(fullname)
	if len(fullname) == 0 || fullname[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	// Retrieve user from the cluster
	user, _, err := clusHelper.GetUserRev(fullname, acc)
	if user == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// 1. Users with fedAdmin/fedReader role can only be deleted by fedAdmins (on master cluster)
	// 2. For every domain that a namespace user is in, the deleter must have PERM_AUTHORIZATION(modify) permission in the domain
	if !acc.AuthorizeOwn(user, nil) {
		log.WithFields(log.Fields{"login": login.fullname, "user": user.Fullname}).Error(common.ErrObjectAccessDenied.Error())
		restRespAccessDenied(w, login)
		return
	}

	// Domain admin can only delete user of its domain
	if login.domain != "" && login.domain != user.Domain {
		e := "Cannot delete user in different domain"
		log.WithFields(log.Fields{"user": fullname}).Error(e)
		restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
		return
	}

	if fullname == common.DefaultAdminUser {
		e := "Cannot delete default admin user"
		log.WithFields(log.Fields{"user": fullname}).Error(e)
		restRespErrorMessage(w, http.StatusForbidden, api.RESTErrOpNotAllowed, e)
		return
	}

	if err := clusHelper.DeleteUser(fullname); err != nil {
		e := "Failed to write to delete the user"
		log.WithFields(log.Fields{"error": err, "user": fullname}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	kickLoginSessions(user)

	restRespSuccess(w, r, nil, acc, login, nil, "Delete user")
}

func isValidRoleDomains(user, globalRole string, roleDomains map[string][]string,
	globalPermits *share.NvPermissions, extraPermitsDomains []share.CLUSPermitsAssigned, allowNoPermission bool) error {

	var err error
	if !access.IsValidRole(globalRole, access.CONST_VISIBLE_USER_ROLE) {
		err = fmt.Errorf("User %s  Unknown global role %s ", user, globalRole)
	}
	domainRole := make(map[string]string)
out:
	for role, domains := range roleDomains {
		if len(domains) == 0 {
			// no domain for this domain role effectively!
			delete(roleDomains, role)
			continue
		}
		for _, domain := range domains {
			if !isDomainNameValid(domain) {
				err = fmt.Errorf("User %s  Invalid characters in namespace %s ", user, domain)
				break out
			}
		}
		if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) {
			err = fmt.Errorf("User %s  Unknown domain role %s ", user, role)
			break out
		}

		domainsNew := make([]string, 0, len(domains))
		for _, d := range domains {
			if d == access.AccessDomainGlobal {
				log.WithFields(log.Fields{"user": user, "role": globalRole}).Info("Ignore invalid global domain")
				continue
			}
			if r, ok := domainRole[d]; !ok {
				domainRole[d] = role
				domainsNew = append(domainsNew, d)
			} else {
				if role != r {
					err = fmt.Errorf("User %s  Assigned multiple domain roles(%s, %s) for domain %s", user, r, role, d)
					break out
				}
			}
		}
		if len(domainsNew) == 0 {
			delete(roleDomains, role)
			log.WithFields(log.Fields{"user": user, "role": role}).Info("Ignore domain role without domain")
		} else if len(domainsNew) != len(domains) {
			roleDomains[role] = domainsNew
		}
	}
	if globalRole == api.UserRoleNone && len(roleDomains) == 0 && !allowNoPermission {
		foundPermits := false
		if globalPermits != nil && globalPermits.IsEmpty() {
			for _, permitsDomains := range extraPermitsDomains {
				if !permitsDomains.Permits.IsEmpty() && len(permitsDomains.Domains) > 0 {
					foundPermits = true
					break
				}
			}
		} else {
			foundPermits = true
		}
		if !foundPermits {
			err = fmt.Errorf("User %s  Not assigned any role/permission for any domain", user)
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	return err
}

func normalizeApikeyRoles(user *share.CLUSApikey) error {
	if user.Role == api.UserRoleFedAdmin || user.Role == api.UserRoleAdmin || user.RoleDomains == nil {
		// If the user is fed admin or cluster admin, then it is the admin of all namespaces
		user.RoleDomains = make(map[string][]string)
	} else {
		// With a user's global role, it doesn't need to have the same role in its RoleDomains
		delete(user.RoleDomains, user.Role)

		domainRole := make(map[string]string, 0)
		for role, domains := range user.RoleDomains {
			domainsFound := utils.NewSet()
			for _, d := range domains {
				if r, ok := domainRole[d]; ok {
					if r == role { // same domain shows up multiple times for a role. avoid duplicate domain entry
						continue
					}
					return fmt.Errorf("Multiple roles(%s, %s) for a domain(%s) is not allowed", role, r, d)
				} else {
					domainRole[d] = role
					domainsFound.Add(d)
				}
			}
			user.RoleDomains[role] = domainsFound.ToStringSlice()
		}
	}

	return nil
}

func handlerApikeyList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Retrieve all apikeys
	var resp api.RESTApikeysData
	resp.Apikeys = make([]*api.RESTApikey, 0)

	apikeys := clusHelper.GetAllApikeysNoAuth()
	for _, apikey := range apikeys {
		if login.fullname != apikey.Name { // a user can always see himself/herself
			if !acc.Authorize(apikey, nil) {
				continue
			}
		}

		apikeyRest := apikey2REST(apikey)
		resp.Apikeys = append(resp.Apikeys, apikeyRest)
	}

	resp.GlobalRoles = access.GetValidRoles(access.CONST_VISIBLE_USER_ROLE)
	resp.DomainRoles = access.GetValidRoles(access.CONST_VISIBLE_DOMAIN_ROLE)
	sort.Slice(resp.Apikeys, func(i, j int) bool { return resp.Apikeys[i].Name < resp.Apikeys[j].Name })

	restRespSuccess(w, r, &resp, acc, login, nil, "Get apikey list")
}

func handlerApikeyShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	name, _ = url.PathUnescape(name)

	// Retrieve apikey from the cluster
	apikey, _, err := clusHelper.GetApikeyRev(name, acc)
	if apikey == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTApikeyData{Apikey: apikey2REST(apikey)}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get apikey detail")
}

func handlerApikeyCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTApikeyCreationData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Apikey == nil {
		e := "Request error"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	rapikey := rconf.Apikey
	name := rapikey.Name
	if len(name) == 0 || name[0] == '~' {
		restRespAccessDenied(w, login)
		return
	}

	// only english characters, numbers and -,_ allowed
	if !isApiAccessKeyFormatValid(name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"login": login.fullname, "create": rapikey.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if len(name) > 32 {
		e := "Exceed maximum name length limitation (32 characters)"
		log.WithFields(log.Fields{"login": login.fullname, "create": rapikey.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if e := isValidRoleDomains(rapikey.Name, rapikey.Role, rapikey.RoleDomains, nil, nil, true); e != nil {
		msg := e.Error()
		if strings.HasPrefix(msg, "User") {
			msg = fmt.Sprintf("API key %s", msg[5:])
		}
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	if access.ContainsNonSupportRole(rapikey.Role) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "API key cannot bind to nonsupport roles")
		return
	}

	// 1. Only fedAdmin can create users with fedAdmin/fedReader role (on master cluster)
	// 2. For every domain that a namespace user is in, the creater must have PERM_AUTHORIZATION(modify) permission in the domain

	// Generate secret key
	tmpGuid, _ := utils.GetGuid()
	secretKey := utils.EncryptPassword(tmpGuid)

	apikey := share.CLUSApikey{
		ExpirationType:   rapikey.ExpirationType,
		ExpirationHours:  rapikey.ExpirationHours,
		Name:             rapikey.Name,
		Description:      rapikey.Description,
		Role:             rapikey.Role,
		RoleDomains:      rapikey.RoleDomains,
		Locale:           common.OEMDefaultUserLocale,
		CreatedTimestamp: time.Now().UTC().Unix(),
		CreatedByEntity:  login.fullname,
		SecretKeyHash:    utils.HashPassword(secretKey),
	}
	if !acc.AuthorizeOwn(&apikey, nil) {
		log.WithFields(log.Fields{"login": login.fullname, "apikey": rapikey.Name}).Error(common.ErrObjectAccessDenied.Error())
		restRespAccessDenied(w, login)
		return
	}

	// calculate expiration time
	now := time.Now()
	if TESTApikeySpecifiedCretionTime {
		creation_timestamp := r.URL.Query().Get("creation_timestamp")
		epochTimestamp, err := strconv.ParseInt(creation_timestamp, 10, 64)
		if err != nil {
			log.WithFields(log.Fields{"creation_timestamp": creation_timestamp, "err": err}).Debug("TESTApikeySpecifiedCretionTime failed")
		} else {
			apikey.CreatedTimestamp = epochTimestamp
			now = time.Unix(epochTimestamp, 0)
		}
	}

	switch rapikey.ExpirationType {
	case api.ApikeyExpireNever:
		apikey.ExpirationTimestamp = math.MaxInt64
	case api.ApikeyExpireOneHour:
		apikey.ExpirationTimestamp = now.Add(time.Duration(1) * time.Hour).UTC().Unix()
	case api.ApikeyExpireOneDay:
		apikey.ExpirationTimestamp = now.AddDate(0, 0, 1).UTC().Unix()
	case api.ApikeyExpireOneMonth:
		apikey.ExpirationTimestamp = now.AddDate(0, 1, 0).UTC().Unix()
	case api.ApikeyExpireOneYear:
		apikey.ExpirationTimestamp = now.AddDate(1, 0, 0).UTC().Unix()
	case api.ApikeyExpireCustomHour:
		if rapikey.ExpirationHours == 0 || rapikey.ExpirationHours > 8760 {
			e := "invalid expiration hour value (1 ~ 8760)"
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
		apikey.ExpirationTimestamp = now.Add(time.Duration(rapikey.ExpirationHours) * time.Hour).UTC().Unix()
	default:
		e := "invalid expiration type"
		log.WithFields(log.Fields{"Name": rapikey.Name, "ExpirationType": rapikey.ExpirationType}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockApikeyKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if apikey already exists
	if apikeyExisting, _, _ := clusHelper.GetApikeyRev(rapikey.Name, acc); apikeyExisting != nil {
		e := "apikey name already exists"
		log.WithFields(log.Fields{"Name": login.fullname, "create": rapikey.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		return
	}

	if e := normalizeApikeyRoles(&apikey); e != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
		return
	}

	if err := clusHelper.CreateApikey(&apikey); err != nil {
		e := "Failed to write to the cluster"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	var resp api.RESTApikeyGeneratedData
	resp.Apikey = &api.RESTApikeyGenerated{
		Name:      apikey.Name,
		SecretKey: secretKey,
	}

	restRespSuccess(w, r, &resp, acc, login, &rconf, "Create apikey")
}

func handlerApikeyDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	name, _ = url.PathUnescape(name)

	// Retrieve user from the cluster
	apikey, _, err := clusHelper.GetApikeyRev(name, acc)
	if apikey == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// 1. Users with fedAdmin/fedReader role can only be deleted by fedAdmins (on master cluster)
	// 2. For every domain that a namespace user is in, the deleter must have PERM_AUTHORIZATION(modify) permission in the domain
	if !acc.AuthorizeOwn(apikey, nil) {
		log.WithFields(log.Fields{"login": login.fullname, "apikey.Name": apikey.Name}).Error(common.ErrObjectAccessDenied.Error())
		restRespAccessDenied(w, login)
		return
	}

	if err := clusHelper.DeleteApikey(name); err != nil {
		e := "Failed to write to delete the apikey"
		log.WithFields(log.Fields{"error": err, "apikey.Name": name}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete apikey")
}

// API used to get the apikey from token.
func handlerSelfApikeyShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if login.fullname == "" {
		restRespAccessDenied(w, login)
		return
	}

	// Retrieve apikey from the cluster
	apikey, _, err := clusHelper.GetApikeyRev(login.fullname, access.NewReaderAccessControl())
	if apikey == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTSelfApikeyData{Apikey: apikey2REST(apikey)}

	resp.GlobalPermits, resp.DomainPermits, _ = access.GetUserPermissions(apikey.Role, apikey.RoleDomains, share.NvPermissions{}, nil)

	restRespSuccess(w, r, &resp, acc, login, nil, "Get self apikey detail")
}

func apikey2REST(apikey *share.CLUSApikey) *api.RESTApikey {
	return &api.RESTApikey{
		ExpirationType:      apikey.ExpirationType,
		ExpirationHours:     apikey.ExpirationHours,
		Name:                apikey.Name,
		Description:         apikey.Description,
		Role:                apikey.Role,
		RoleDomains:         apikey.RoleDomains,
		ExpirationTimestamp: apikey.ExpirationTimestamp,
		CreatedTimestamp:    apikey.CreatedTimestamp,
		CreatedByEntity:     apikey.CreatedByEntity,
	}
}

func isApiAccessKeyFormatValid(name string) bool {
	if !isObjectNameWithSpaceValid(name) {
		return false
	}

	valid, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", name)
	return valid
}
