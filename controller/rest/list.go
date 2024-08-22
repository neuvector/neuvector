package rest

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

func handlerApplicationList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSApplicationListDummy{}, nil) {
		if login.hasFedPermission() {
			resp := api.RESTListData{
				List: &api.RESTList{},
			}
			restRespSuccess(w, r, &resp, acc, login, nil, "")
		} else {
			restRespAccessDenied(w, login)
		}
		return
	}

	var resp api.RESTListData
	resp.List = &api.RESTList{Application: make([]string, len(common.AppNameMap))}

	i := 0
	for _, app := range common.AppNameMap {
		resp.List.Application[i] = app
		i++
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get application list")
}
