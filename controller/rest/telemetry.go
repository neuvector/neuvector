package rest

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

var lastTeleErrorDay int = -1

type tTelemetryReqData struct {
	AppVersion string            `json:"appVersion"`
	ExtraInfo  map[string]string `json:"extraInfo"` // from TelemetryDataRaw
}

func reportTelemetryData(rawData common.TelemetryData) {
	extraInfo := make(map[string]string, 8)
	extraInfo["hosts"] = strconv.Itoa(rawData.Hosts)
	extraInfo["groups"] = strconv.Itoa(rawData.Groups)
	extraInfo["policyRules"] = strconv.Itoa(rawData.PolicyRules)
	extraInfo["clusters"] = strconv.Itoa(rawData.Clusters)
	extraInfo["primaryClusters"] = strconv.Itoa(rawData.PrimaryCluster)

	reqPayload := tTelemetryReqData{
		AppVersion: cctx.NvSemanticVersion, // in the format v{major}.{minor}.{patch}
		ExtraInfo:  extraInfo,
	}

	today := time.Now().UTC().Day()
	if _teleNeuvectorURL == "" {
		return
	}
	if ss := strings.Split(reqPayload.AppVersion, "."); len(ss) < 2 || ss[0][0] != 'v' {
		return
	}

	logError := lastTeleErrorDay != today

	bodyTo, err := json.Marshal(&reqPayload)
	if err != nil {
		log.WithError(err).Warn("failed to marshal telemetry payload")
		return
	}
	if _, _, _, err := sendRestRequest("telemetry", http.MethodPost, _teleNeuvectorURL, "", "", "", "", nil, bodyTo, logError, nil, nil); err == nil {
		lastTeleErrorDay = -1
		upgradeInfo := share.CLUSCheckUpgradeInfo{
			LastUploadTime: time.Now().UTC(),
		}
		key := share.CLUSTelemetryStore + "controller"
		value, err := json.Marshal(&upgradeInfo)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Marshal")
			return
		}
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("cluster.Put")
		}
	} else if logError {
		lastTeleErrorDay = today
	}
}
