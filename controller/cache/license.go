package cache

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var licenseCode string
var installationID string

var licenseInfo api.RESTLicenseInfo = api.RESTLicenseInfo{
	Name:  "",
	Email: "",
	Phone: "",
}

func (m CacheMethod) GetCurrentLicense(acc *access.AccessControl) api.RESTLicenseInfo {
	lic := licenseInfo

	if !acc.Authorize(&lic, nil) {
		return api.RESTLicenseInfo{InstallationID: installationID}
	} else {
		return lic
	}
}

func logLicenseEvent(ev share.TLogEvent, msg string) {
	if !isLeader() {
		return
	}
	clog := share.CLUSEventLog{
		Event:          ev,
		ReportedAt:     time.Now().UTC(),
		HostID:         localDev.Host.ID,
		HostName:       localDev.Host.Name,
		ControllerID:   localDev.Ctrler.ID,
		ControllerName: localDev.Ctrler.Name,
		EnforcerLimit:  99999,
		Msg:            msg,
	}

	_ = cctx.EvQueue.Append(&clog)
}

func licenseConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	var license string
	var info api.RESTLicenseInfo

	if installationID == "" {
		installationID, _ = clusHelper.GetInstallationID()
	}
	license = string(value)
	if licenseCode != "" && licenseCode == license {
		log.Debug("license code already applied")
		return
	}

	if string(value) == "" {
		if licenseCode != "" {
			logLicenseEvent(share.CLUSEvLicenseRemove, "Delete license")
		}
	} else {
		logLicenseEvent(share.CLUSEvLicenseUpdate, "Update license")
	}

	val, err := utils.GetLicenseInfo(license)
	if err == nil {
		err = json.Unmarshal([]byte(val), &info)
	}
	if err != nil {
		info = api.RESTLicenseInfo{
			Name:  "",
			Email: "",
			Phone: "",
		}
	}
	info.InstallationID = installationID
	licenseInfo = info
	licenseCode = license
}

func licenseInit() {
	log.Info()

	cur, _ := cluster.Get(share.CLUSConfigLicenseKey)
	licenseConfigUpdate(cluster.ClusterNotifyAdd, share.CLUSConfigLicenseKey, cur)
	scanLicenseUpdate("", nil)
}
