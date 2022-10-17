package rest

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	log "github.com/sirupsen/logrus"
)

func handlerEULAShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	var resp api.RESTEULAData

	key := share.CLUSConfigEULAKey
	value, _ := cluster.Get(key)
	if value != nil {
		var eula share.CLUSEULA
		json.Unmarshal(value, &eula)

		resp.EULA = &api.RESTEULA{Accepted: eula.Accepted}
	} else {
		resp.EULA = &api.RESTEULA{Accepted: false}
	}

	restRespSuccess(w, r, &resp, nil, nil, nil, "Get EULA")
}

func handlerEULAConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTEULAData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.EULA == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var cconf share.CLUSEULA
	cconf.Accepted = rconf.EULA.Accepted

	key := share.CLUSConfigEULAKey
	value, _ := json.Marshal(&cconf)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		// cache.AuthLog(cache.LOGEV_USER_CONFIG_FAILED,
		// 	auth.Password.Username, auth.Password.Domain)
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure EULA")
}
