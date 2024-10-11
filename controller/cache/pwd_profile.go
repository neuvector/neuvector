package cache

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

var activePwdProfileName string = share.CLUSDefPwdProfileName
var pwdProfiles map[string]*share.CLUSPwdProfile = make(map[string]*share.CLUSPwdProfile, 1)

func pwdProfileConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug()
	name := share.CLUSGroupKey2Name(key)
	if name == "" {
		if key == share.CLUSConfigPwdProfileStore && len(value) > 0 {
			var cfg share.CLUSActivePwdProfileConfig
			if json.Unmarshal(value, &cfg) == nil {
				cacheMutexLock()
				defer cacheMutexUnlock()
				if _, ok := pwdProfiles[cfg.Name]; ok {
					activePwdProfileName = cfg.Name
				} else {
					activePwdProfileName = share.CLUSDefPwdProfileName
				}
				if p, ok := pwdProfiles[activePwdProfileName]; ok && p.SessionTimeout != 0 {
					common.DefaultIdleTimeout = p.SessionTimeout
				}
			}
			return
		}
	}

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var profile share.CLUSPwdProfile
		_ = json.Unmarshal(value, &profile)
		cacheMutexLock()
		pwdProfiles[name] = &profile
		if name == activePwdProfileName && profile.SessionTimeout != 0 {
			common.DefaultIdleTimeout = profile.SessionTimeout
		}
		cacheMutexUnlock()
	case cluster.ClusterNotifyDelete:
		cacheMutexLock()
		delete(pwdProfiles, name)
		cacheMutexUnlock()
	}
}

func (m CacheMethod) GetPwdProfile(name string) (share.CLUSPwdProfile, error) {
	var pName string

	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if name == share.CLUSSysPwdProfileName {
		pName = activePwdProfileName
	} else {
		pName = name
	}
	if profile, ok := pwdProfiles[pName]; ok {
		return *profile, nil
	}
	return share.CLUSPwdProfile{}, common.ErrObjectNotFound
}

func (m CacheMethod) GetAllPwdProfiles() (string, map[string]share.CLUSPwdProfile) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	profiles := make(map[string]share.CLUSPwdProfile, len(pwdProfiles))
	for name, pwdProfile := range pwdProfiles {
		profiles[name] = *pwdProfile
	}

	return activePwdProfileName, profiles
}
