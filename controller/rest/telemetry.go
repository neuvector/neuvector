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
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

var nvAppFullVersion string  // in the format  {major}.{minor}.{patch}[-s{#}]
var nvSemanticVersion string // in the format v{major}.{minor}.{patch}

var lastTeleErrorDay map[string]int = map[string]int{"controller": -1, "scanner": -1}

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

type tTelemetryInfo struct {
	app              string
	urlStr           string
	localFullVersion string // {major}.{minor}[.{patch}][-s{#}]
	localMajorMinor  string // {major}.{minor}
	reqPayload       tTelemetryReqData
	versionsToCheck  int // 3 for neuvector, 1 for scanner in upgrade-responder servers
}

func reportTelemetryData(rawData common.TelemetryData) {
	extraInfo := make(map[string]string, 8)
	extraInfo["hosts"] = strconv.Itoa(rawData.Hosts)
	extraInfo["groups"] = strconv.Itoa(rawData.Groups)
	extraInfo["policyRules"] = strconv.Itoa(rawData.PolicyRules)
	extraInfo["clusters"] = strconv.Itoa(rawData.Clusters)
	extraInfo["admCtrlEnabled"] = strconv.FormatBool(rawData.AdmCtrlEnabled)
	extraInfo["inFederate"] = strconv.FormatBool(rawData.InFederate)
	extraInfo["primaryCluster"] = strconv.FormatBool(rawData.PrimaryCluster)

	var nvMajorMinor string             //  {major}.{minor}
	var scannerAppFullVersion string    //  {major}.{minor}
	var scannerMajorMinorVersion string // v{major}.{minor}
	if ss := strings.Split(nvAppFullVersion, "."); len(ss) >= 2 {
		nvMajorMinor = fmt.Sprintf("%s.%s", ss[0], ss[1])
	}
	if sdb := scanUtils.GetScannerDB(); sdb != nil && sdb.CVEDBVersion != "" {
		scannerAppFullVersion = sdb.CVEDBVersion
		scannerMajorMinorVersion = fmt.Sprintf("v%s", scannerAppFullVersion)
	}
	var useProxy string
	var appsInfo []tTelemetryInfo = []tTelemetryInfo{
		tTelemetryInfo{
			app:              "controller",
			urlStr:           _teleNeuvectorURL,
			localFullVersion: nvAppFullVersion,
			localMajorMinor:  nvMajorMinor,
			reqPayload: tTelemetryReqData{
				AppVersion: nvSemanticVersion,
				ExtraInfo:  extraInfo,
			},
			versionsToCheck: 3,
		},
	}
	if scannerAppFullVersion != "" {
		appsInfo = append(appsInfo, tTelemetryInfo{
			app:              "scanner",
			urlStr:           _teleScannerURL,
			localFullVersion: scannerAppFullVersion,
			localMajorMinor:  scannerAppFullVersion,
			reqPayload: tTelemetryReqData{
				AppVersion: scannerMajorMinorVersion,
				ExtraInfo:  make(map[string]string),
			},
			versionsToCheck: 1,
		})
	}

	if rawData.UseProxy == const_https_proxy {
		useProxy = "https"
	} else if rawData.UseProxy == const_http_proxy {
		useProxy = "http"
	}

	today := time.Now().UTC().Day()
	for _, appInfo := range appsInfo {
		if appInfo.urlStr == "" {
			continue
		}
		if ss := strings.Split(appInfo.reqPayload.AppVersion, "."); len(ss) < 2 || ss[0][0] != 'v' {
			continue
		}

		appVer, err := utils.NewVersion(appInfo.reqPayload.AppVersion[1:]) // {major}.{minor}[.{patch}]
		if err != nil {
			log.WithFields(log.Fields{"app": appInfo.app, "appVersion": appInfo.reqPayload.AppVersion}).Error("invalid version")
			continue
		}

		logError := false
		if lastDay, ok := lastTeleErrorDay[appInfo.app]; ok && lastDay != today {
			logError = true
		}

		var noUpgradeInfo share.CLUSCheckUpgradeInfo
		bodyTo, _ := json.Marshal(&appInfo.reqPayload)
		if data, _, _, err := sendRestRequest("telemetry", http.MethodPost, appInfo.urlStr, "", nil, bodyTo, logError, &useProxy, nil); err == nil {
			lastTeleErrorDay[appInfo.app] = -1
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
					if idx >= appInfo.versionsToCheck || len(v.Name) <= 1 || v.Name[0] != 'v' || len(v.Tags) == 0 {
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
					if v.Name == appInfo.reqPayload.AppVersion {
						verSecNum := 0
						localSecNum := 0
						if ss := strings.Split(verImageTag, "-"); len(ss) >= 2 && ss[1][0] == 's' {
							verSecNum, _ = strconv.Atoi(ss[1][1:])
						}
						if ss := strings.Split(appInfo.localFullVersion, "-"); len(ss) >= 2 && ss[1][0] == 's' {
							localSecNum, _ = strconv.Atoi(ss[1][1:])
						}
						if verSecNum <= localSecNum {
							continue
						}
					}

					if verImageTag != "" && verImageTag != appInfo.localFullVersion && (idx == 0 || verMajorMinor == appInfo.localMajorMinor) {
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
				if upgradeInfo != noUpgradeInfo {
					key := share.CLUSUpgradeInfoStore + appInfo.app
					value, _ := json.Marshal(&upgradeInfo)
					cluster.Put(key, value)
					log.WithFields(log.Fields{"upgradeInfo": upgradeInfo}).Info()
				}
			}
		} else if logError {
			lastTeleErrorDay[appInfo.app] = today
		}
	}
}
