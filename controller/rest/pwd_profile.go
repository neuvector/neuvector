package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

const _maxPwdHistoryCount = 32
const _pwdValidPerDayUnit = 1440

var _pwdValidUnit time.Duration = _pwdValidPerDayUnit // default: per day

func handlerPwdProfileShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	getFullInfo := true
	name := ps.ByName("name")
	if name != share.CLUSSysPwdProfileName {
		if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
			restRespAccessDenied(w, login)
			return
		}
	} else {
		getFullInfo = false
	}
	profile, _ := cacher.GetPwdProfile(name)
	if profile.Name == "" {
		log.WithFields(log.Fields{"name": name}).Error("Request error")
		restRespNotFoundLogAccessDenied(w, login, common.ErrObjectNotFound)
		return
	} else if profile.SessionTimeout == 0 {
		profile.SessionTimeout = common.DefIdleTimeoutInternal
	}

	var resp api.RESTPwdProfileDataConditional
	if getFullInfo {
		resp.PwdProfile = &api.RESTPwdProfileConditional{
			Name:                        &profile.Name,
			Comment:                     &profile.Comment,
			MinLen:                      profile.MinLen,
			MinUpperCount:               profile.MinUpperCount,
			MinLowerCount:               profile.MinLowerCount,
			MinDigitCount:               profile.MinDigitCount,
			MinSpecialCount:             profile.MinSpecialCount,
			EnablePwdExpiration:         &profile.EnablePwdExpiration,
			PwdExpireAfterDays:          &profile.PwdExpireAfterDays,
			EnablePwdHistory:            &profile.EnablePwdHistory,
			PwdHistoryCount:             &profile.PwdHistoryCount,
			EnableBlockAfterFailedLogin: &profile.EnableBlockAfterFailedLogin,
			BlockAfterFailedCount:       &profile.BlockAfterFailedCount,
			BlockMinutes:                &profile.BlockMinutes,
			SessionTimeout:              &profile.SessionTimeout,
		}
	} else {
		resp.PwdProfile = &api.RESTPwdProfileConditional{
			MinLen:          profile.MinLen,
			MinUpperCount:   profile.MinUpperCount,
			MinLowerCount:   profile.MinLowerCount,
			MinDigitCount:   profile.MinDigitCount,
			MinSpecialCount: profile.MinSpecialCount,
		}
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get password profile")
}

func handlerPwdProfileList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	// Retrieve all profiles
	var resp api.RESTPwdProfilesData
	activeProfileName, profiles := cacher.GetAllPwdProfiles()
	resp.ActiveProfileName = activeProfileName
	resp.PwdProfiles = make([]*api.RESTPwdProfile, 0, len(profiles))
	for _, profile := range profiles {
		if profile.SessionTimeout == 0 {
			profile.SessionTimeout = common.DefIdleTimeoutInternal
		}
		resp.PwdProfiles = append(resp.PwdProfiles, &api.RESTPwdProfile{
			Name:                        profile.Name,
			Comment:                     profile.Comment,
			MinLen:                      profile.MinLen,
			MinUpperCount:               profile.MinUpperCount,
			MinLowerCount:               profile.MinLowerCount,
			MinDigitCount:               profile.MinDigitCount,
			MinSpecialCount:             profile.MinSpecialCount,
			EnablePwdExpiration:         profile.EnablePwdExpiration,
			PwdExpireAfterDays:          profile.PwdExpireAfterDays,
			EnablePwdHistory:            profile.EnablePwdHistory,
			PwdHistoryCount:             profile.PwdHistoryCount,
			EnableBlockAfterFailedLogin: profile.EnableBlockAfterFailedLogin,
			BlockAfterFailedCount:       profile.BlockAfterFailedCount,
			BlockMinutes:                profile.BlockMinutes,
			SessionTimeout:              profile.SessionTimeout,
		})
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get password profile list")
}

func handlerPwdProfileConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var errMsg string
	var rconf api.RESTPwdProfileConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil || rconf.Config.Name == share.CLUSSysPwdProfileName {
		errMsg = "Request error"
	} else if name != rconf.Config.Name {
		errMsg = "password profile not match"
	}
	if errMsg != "" {
		log.WithFields(log.Fields{"error": err, "name": name}).Error("Request error")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, errMsg)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		// Retrieve profile from the cluster
		profile, rev, err := clusHelper.GetPwdProfileRev(name, acc)
		if profile != nil && err == nil {
			rprofile := rconf.Config
			oldProfile := *profile
			if rprofile.Comment != nil {
				profile.Comment = *rprofile.Comment
			}
			if rprofile.MinLen != nil {
				profile.MinLen = *rprofile.MinLen
			}
			if rprofile.MinUpperCount != nil {
				profile.MinUpperCount = *rprofile.MinUpperCount
			}
			if rprofile.MinLowerCount != nil {
				profile.MinLowerCount = *rprofile.MinLowerCount
			}
			if rprofile.MinDigitCount != nil {
				profile.MinDigitCount = *rprofile.MinDigitCount
			}
			if rprofile.MinSpecialCount != nil {
				profile.MinSpecialCount = *rprofile.MinSpecialCount
			}
			if rprofile.EnablePwdExpiration != nil {
				profile.EnablePwdExpiration = *rprofile.EnablePwdExpiration
			}
			if rprofile.PwdExpireAfterDays != nil {
				profile.PwdExpireAfterDays = *rprofile.PwdExpireAfterDays
			}
			if rprofile.EnablePwdHistory != nil {
				profile.EnablePwdHistory = *rprofile.EnablePwdHistory
			}
			if rprofile.PwdHistoryCount != nil {
				profile.PwdHistoryCount = *rprofile.PwdHistoryCount
			}
			if rprofile.EnableBlockAfterFailedLogin != nil {
				profile.EnableBlockAfterFailedLogin = *rprofile.EnableBlockAfterFailedLogin
			}
			if rprofile.BlockAfterFailedCount != nil {
				profile.BlockAfterFailedCount = *rprofile.BlockAfterFailedCount
			}
			if rprofile.BlockMinutes != nil {
				profile.BlockMinutes = *rprofile.BlockMinutes
			}
			if rprofile.SessionTimeout != nil {
				profile.SessionTimeout = *rprofile.SessionTimeout
			} else if profile.SessionTimeout == 0 {
				profile.SessionTimeout = common.DefIdleTimeoutInternal
			}
			if profile.PwdHistoryCount > _maxPwdHistoryCount {
				profile.PwdHistoryCount = _maxPwdHistoryCount
			}
			if profile.MinLen <= 0 || profile.MinUpperCount < 0 || profile.MinLowerCount < 0 || profile.MinDigitCount < 0 || profile.MinSpecialCount < 0 ||
				(profile.EnablePwdExpiration && profile.PwdExpireAfterDays <= 0) ||
				(profile.EnablePwdHistory && profile.PwdHistoryCount <= 0) ||
				(profile.EnableBlockAfterFailedLogin && (profile.BlockAfterFailedCount <= 0 || profile.BlockMinutes <= 0)) ||
				(profile.MinLen < (profile.MinUpperCount + profile.MinLowerCount + profile.MinDigitCount + profile.MinSpecialCount)) ||
				(profile.SessionTimeout > api.UserIdleTimeoutMax || profile.SessionTimeout < api.UserIdleTimeoutMin) {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "invalid value")
				return
			}

			resetAllUsers := false
			kvProfileUpdateOK, kvActiveProfileNameUpdateOK := true, true
			oldActivePwdProfileName := clusHelper.GetActivePwdProfileName()
			newActivePwdProfileName := oldActivePwdProfileName
			/*if (rprofile.Active != nil) && (*rprofile.Active) && (oldActivePwdProfileName != rprofile.Name) { //-> stage 4
				// active profile switches from profile A to profile B
				if err := clusHelper.PutActivePwdProfileName(profile.Name); err != nil {
					kvActiveProfileNameUpdateOK = false
				} else {
					newActivePwdProfileName = rprofile.Name
					oldActivePwdProfile, _, _ := clusHelper.GetPwdProfileRev(oldActivePwdProfileName, acc)
					if (oldActivePwdProfile == nil || !oldActivePwdProfile.EnablePwdExpiration) && profile.EnablePwdExpiration {
						// profile A's EnablePwdExpiration is false, but profile B's EnablePwdExpiration is true
						resetAllUsers = true
					}
				}
			}*/
			if oldProfile != *profile {
				if err := clusHelper.PutPwdProfileRev(profile, rev); err != nil {
					kvProfileUpdateOK = false
				} else if (newActivePwdProfileName == oldActivePwdProfileName) && (oldActivePwdProfileName == rprofile.Name) {
					// active profile doesn't switch but its profile setting is changed
					if !oldProfile.EnablePwdExpiration && profile.EnablePwdExpiration {
						// profile's EnablePwdExpiration changes from false to true
						resetAllUsers = true
					}
				}
			}
			if resetAllUsers {
				// when EnablePwdExpiration changes from false to true, reset all users' PwdResetTime to now to avoid all users' passwords get expired immediately
				now := time.Now().UTC()
				users := clusHelper.GetAllUsers(acc)
				for _, user := range users {
					user.PwdResetTime = now
					if err := clusHelper.PutUser(user); err != nil {
						log.WithFields(log.Fields{"error": err}).Error("PutUser")
					}
				}
			}
			if kvProfileUpdateOK && kvActiveProfileNameUpdateOK {
				break
			} else {
				retry++
			}
		} else {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}
	}

	if retry >= retryClusterMax {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, "Failed to write to the cluster")
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure passport profile")
}
