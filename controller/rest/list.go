package rest

// #include "../../defs.h"
import "C"

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerApplicationList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSApplicationListDummy{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var resp api.RESTListData
	resp.List = &api.RESTList{Application: make([]string, len(utils.AppNameMap))}

	i := 0
	for _, app := range utils.AppNameMap {
		resp.List.Application[i] = app
		i++
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get application list")
}
