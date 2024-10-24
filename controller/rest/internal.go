package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerInternalSystem(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// any user can call this API to get system summary, but only users with global 'config' permission can see non-zero host/controller/agent/scanner counters
	accSysConfig := acc.BoostPermissions(share.PERM_SYSTEM_CONFIG)
	resp := cacher.GetRiskScoreMetrics(accSysConfig, acc)

	restRespSuccess(w, r, resp, acc, login, nil, "Get internal system data")
}

func handlerAcceptAlert(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if login.fullname == "" || login.loginType == loginTypeApikey {
		restRespAccessDenied(w, login)
		return
	}

	var rconf api.RESTAcceptedAlerts
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	supportedUserAlerts := utils.NewSet(share.AlertPwdExpiring, share.AlertAdminHasDefPwd)
	supportedManagerAlerts := utils.NewSet(share.AlertNvNewVerAvailable, share.AlertNvInMultiVersions, share.AlertCveDbTooOld)
	confAccepted := map[string][]string{
		"manager":    rconf.ManagerAlerts,
		"controller": rconf.ControllerAlerts,
		"user":       rconf.UserAlerts,
	}
	for alertSrc, newAccepted := range confAccepted {
		if len(newAccepted) == 0 {
			continue
		}

		var userName string
		if alertSrc != "user" {
			if !acc.CanWriteCluster() && !acc.IsFedAdmin() {
				continue
			}
			userName = common.ReservedNvSystemUser
		} else {
			if login.mainSessionUser != "" {
				// for login session from master cluster, do not allow accepting user alerts
				continue
			}
			userName = login.fullname
		}

		retry := 0
		for retry < retryClusterMax {
			user, rev, _ := clusHelper.GetUserRev(userName, access.NewReaderAccessControl())
			if user == nil && userName == common.ReservedNvSystemUser {
				secret, _ := utils.GetGuid()
				u := share.CLUSUser{
					Fullname:     common.ReservedNvSystemUser,
					Username:     common.ReservedNvSystemUser,
					PasswordHash: utils.HashPassword(secret),
					Domain:       "",
					Role:         api.UserRoleNone,
					Timeout:      common.DefIdleTimeoutInternal,
					RoleDomains:  make(map[string][]string),
					Locale:       common.OEMDefaultUserLocale,
					PwdResetTime: time.Now().UTC(),
				}
				value, _ := json.Marshal(u)
				key := share.CLUSUserKey(common.ReservedNvSystemUser)
				if err := cluster.PutIfNotExist(key, value, false); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("PutIfNotExist")
				}
				user, rev, _ = clusHelper.GetUserRev(common.ReservedNvSystemUser, acc)
			}
			if user == nil {
				restRespAccessDenied(w, login)
				return
			}

			acceptedAlerts := utils.NewSetFromStringSlice(user.AcceptedAlerts)
			for _, alert := range newAccepted {
				switch alertSrc {
				case "manager":
					if !supportedManagerAlerts.Contains(alert) {
						continue
					}
				case "controller":
					if len(alert) != 32 {
						continue
					}
				case "user":
					if !supportedUserAlerts.Contains(alert) {
						continue
					}
				}
				acceptedAlerts.Add(alert)
			}
			user.AcceptedAlerts = acceptedAlerts.ToStringSlice()
			if err = clusHelper.PutUserRev(user, rev); err != nil {
				log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
				retry++
			} else {
				break
			}
		}
		if retry >= retryClusterMax {
			e := "Failed to write to the cluster"
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
			return
		}
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Accept alerts")
}
