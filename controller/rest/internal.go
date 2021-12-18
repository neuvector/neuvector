package rest

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
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
