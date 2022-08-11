package rest

import "C"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var nvAppFullVersion string  // in the format  {major}.{minor}.{patch}[-s{#}]
var nvSemanticVersion string // in the format v{major}.{minor}.{patch}

var lastTeleErrorDay int = -1

type tTelemetryReqData struct {
	AppVersion string            `json:"appVersion"`
	ExtraInfo  map[string]string `json:"extraInfo"` // from TelemetryDataRaw
}

type tCheckUpgradeVersion struct {
	Name                 string // must be in semantic versioning, like v5.0.0
	ReleaseDate          string
	MinUpgradableVersion string // can be empty or semantic versioning
	Tags                 []string
	ExtraInfo            map[string]string
}

type tTelemetryResponse struct {
	Versions                 []tCheckUpgradeVersion `json:"versions"`
	RequestIntervalInMinutes int                    `json:"requestIntervalInMinutes"`
}

func reportTelemetryData(rawData common.TelemetryData) {
	extraInfo := make(map[string]string, 8)
	extraInfo["hosts"] = strconv.Itoa(rawData.Hosts)
	extraInfo["groups"] = strconv.Itoa(rawData.Groups)
	extraInfo["policyRules"] = strconv.Itoa(rawData.PolicyRules)
	extraInfo["clusters"] = strconv.Itoa(rawData.Clusters)
	extraInfo["primaryClusters"] = strconv.Itoa(rawData.PrimaryCluster)

	var nvMajorMinor string                                       // in the format {major}.{minor}
	if ss := strings.Split(nvAppFullVersion, "."); len(ss) >= 2 { // in the format {major}.{minor}[.{patch}][-s{#}]
		nvMajorMinor = fmt.Sprintf("%s.%s", ss[0], ss[1])
	}
	var useProxy string
	reqPayload := tTelemetryReqData{
		AppVersion: nvSemanticVersion, // in the format v{major}.{minor}.{patch}
		ExtraInfo:  extraInfo,
	}

	if rawData.UseProxy == const_https_proxy {
		useProxy = "https"
	} else if rawData.UseProxy == const_http_proxy {
		useProxy = "http"
	}

	today := time.Now().UTC().Day()
	if _teleNeuvectorURL == "" {
		return
	}
	if ss := strings.Split(reqPayload.AppVersion, "."); len(ss) < 2 || ss[0][0] != 'v' {
		return
	}

	appVer, err := utils.NewVersion(reqPayload.AppVersion[1:]) // {major}.{minor}[.{patch}]
	if err != nil {
		log.WithFields(log.Fields{"appVersion": reqPayload.AppVersion}).Error("invalid version")
		return
	}

	logError := false
	if lastTeleErrorDay != today {
		logError = true
	}

	bodyTo, _ := json.Marshal(&reqPayload)
	if data, _, _, err := sendRestRequest("telemetry", http.MethodPost, _teleNeuvectorURL, "", nil, bodyTo, logError, &useProxy, nil); err == nil {
		uploadTime := time.Now().UTC()
		lastTeleErrorDay = -1
		var resp tTelemetryResponse
		if err := json.Unmarshal(data, &resp); err == nil {
			var idx int
			var upgradeInfo share.CLUSCheckUpgradeInfo // for the latest versions from upgrade-responder response

			sort.Slice(resp.Versions[:], func(i, j int) bool {
				iVer, iErr := utils.NewVersion(resp.Versions[i].Name)
				jVer, jErr := utils.NewVersion(resp.Versions[j].Name)
				if iErr != nil || jErr != nil {
					log.WithFields(log.Fields{"i": resp.Versions[i].Name, "j": resp.Versions[j].Name}).Error("invalid version")
				} else {
					if iVer.Compare(jVer) > 0 {
						return true
					}
				}
				return false
			})
			for _, v := range resp.Versions {
				if idx >= 3 || len(v.Name) <= 1 || v.Name[0] != 'v' || len(v.Tags) == 0 { // check 3 {major}.{minor} versions only
					continue
				}
				var verMajorMinor string
				if ssName := strings.Split(v.Name, "."); len(ssName) < 2 {
					continue
				} else {
					verMajorMinor = fmt.Sprintf("%s.%s", ssName[0][1:], ssName[1]) // {major}.{minor}
				}

				if entryVer, err := utils.NewVersion(v.Name[1:]); err != nil {
					log.WithFields(log.Fields{"version": v.Name}).Error("invalid version")
					continue
				} else {
					// skip this version entry if its version is older than local version
					if entryVer.Compare(appVer) < 0 {
						continue
					}
				}

				var verImageTag string
				sort.Strings(v.Tags)
				for i := len(v.Tags) - 1; i >= 0; i-- {
					if v.Tags[i] == "latest" {
						if len(v.Tags) == 1 {
							// NV doesn't release an official image with "latest" tag
							// If we do get a Version entry that has only 'latest' tag, deduce the real tag from version
							verImageTag = v.Name[1:]
						}
					} else {
						verImageTag = v.Tags[i]
						break
					}
				}
				// skip this version entry if it is the same version but with older tag than local version
				if v.Name == reqPayload.AppVersion {
					verSecNum := 0
					localSecNum := 0
					if ss := strings.Split(verImageTag, "-"); len(ss) >= 2 && ss[1][0] == 's' {
						verSecNum, _ = strconv.Atoi(ss[1][1:])
					}
					if ss := strings.Split(nvAppFullVersion, "-"); len(ss) >= 2 && ss[1][0] == 's' {
						localSecNum, _ = strconv.Atoi(ss[1][1:])
					}
					if verSecNum <= localSecNum {
						continue
					}
				}

				if verImageTag != "" && verImageTag != nvAppFullVersion && (idx == 0 || verMajorMinor == nvMajorMinor) {
					upgradeVersion := share.CLUSCheckUpgradeVersion{
						Version:     v.Name,
						ReleaseDate: v.ReleaseDate,
						Tag:         verImageTag,
					}
					if idx == 0 {
						upgradeInfo.MaxUpgradeVersion = upgradeVersion
					} else {
						upgradeInfo.MinUpgradeVersion = upgradeVersion
					}
				}
				idx++
			}
			upgradeInfo.LastUploadTime = uploadTime
			key := share.CLUSTelemetryStore + "controller"
			value, _ := json.Marshal(&upgradeInfo)
			cluster.Put(key, value)
		}
	} else if logError {
		lastTeleErrorDay = today
	}
}
