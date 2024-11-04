package rest

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

	var nvMajorMinor string                                            // in the format {major}.{minor}
	if ss := strings.Split(cctx.NvAppFullVersion, "."); len(ss) >= 2 { // in the format {major}.{minor}[.{patch}][-s{#}]
		nvMajorMinor = fmt.Sprintf("%s.%s", ss[0], ss[1])
	}
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
	if data, _, _, err := sendRestRequest("telemetry", http.MethodPost, _teleNeuvectorURL, "", "", "", "", nil, bodyTo, logError, nil, nil); err == nil {
		uploadTime := time.Now().UTC()
		lastTeleErrorDay = -1
		var nvVerMajor int
		var nvVerMinor int
		var resp tTelemetryResponse
		if vers := strings.Split(nvMajorMinor, "."); len(vers) >= 2 {
			intVar0, err0 := strconv.Atoi(vers[0])
			intVar1, err1 := strconv.Atoi(vers[1])
			if err0 == nil && err1 == nil {
				nvVerMajor = intVar0
				nvVerMinor = intVar1
			}
		}
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
					if ss := strings.Split(cctx.NvAppFullVersion, "-"); len(ss) >= 2 && ss[1][0] == 's' {
						localSecNum, _ = strconv.Atoi(ss[1][1:])
					}
					if verSecNum <= localSecNum {
						continue
					}
				}

				var verMajor int
				var verMinor int
				if vers := strings.Split(verMajorMinor, "."); len(vers) >= 2 {
					intVar0, err0 := strconv.Atoi(vers[0])
					intVar1, err1 := strconv.Atoi(vers[1])
					if err0 == nil && err1 == nil {
						verMajor = intVar0
						verMinor = intVar1
					}
				}
				if verImageTag != "" && verImageTag != cctx.NvAppFullVersion &&
					(idx == 0 || verMajorMinor == nvMajorMinor || (verMajor > nvVerMajor || (verMajor == nvVerMajor && verMinor > nvVerMinor))) {
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
			value, err := json.Marshal(&upgradeInfo)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Marshal")
				return
			}
			if err := cluster.Put(key, value); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("cluster.Put")
			}
		}
	} else if logError {
		lastTeleErrorDay = today
	}
}
