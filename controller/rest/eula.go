package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/resource"
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
		if err := json.Unmarshal(value, &eula); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unmarshal")
		}

		resp.EULA = &api.RESTEULA{Accepted: eula.Accepted}
	} else {
		resp.EULA = &api.RESTEULA{Accepted: false}
	}
	if k8sPlatform && !resp.EULA.Accepted {
		var errs []string
		k8sRequiredRoles := []string{resource.NvRbacRole, resource.NvSecretRole}
		if errs, _ = resource.VerifyNvRbacRoles(k8sRequiredRoles, false); len(errs) == 0 {
			errs, _ = resource.VerifyNvRbacRoleBindings(k8sRequiredRoles, false, true)
		}
		if len(errs) > 0 {
			resp.K8sRbacAlertMsg = strings.Join(errs, "<p>")
		} else {
			accReadAll := access.NewReaderAccessControl()
			user, _, _ := clusHelper.GetUserRev(common.DefaultAdminUser, accReadAll)
			if user != nil && user.ResetPwdInNextLogin && user.UseBootstrapPwd {
				strK8sCmdFormat := `kubectl get secret --namespace %s neuvector-bootstrap-secret -o go-template='{{ .data.bootstrapPassword|base64decode}}{{ "\n" }}'`
				resp.BootstrapPwdCmd = fmt.Sprintf(strK8sCmdFormat, resource.NvAdmSvcNamespace)
			}
		}
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

	body, _ := io.ReadAll(r.Body)

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
