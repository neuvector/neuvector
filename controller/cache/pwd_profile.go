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
			}
			return
		}
	}

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var profile share.CLUSPwdProfile
		json.Unmarshal(value, &profile)
		cacheMutexLock()
		pwdProfiles[name] = &profile
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

func (m CacheMethod) PutPwdProfiles(activeName string, profiles map[string]*share.CLUSPwdProfile) {
	for _, profile := range profiles {
		key := share.CLUSPwdProfileKey(profile.Name)
		value, _ := json.Marshal(profile)
		pwdProfileConfigUpdate(cluster.ClusterNotifyAdd, key, value)
	}
	cfg := share.CLUSActivePwdProfileConfig{Name: activeName}
	value, _ := json.Marshal(&cfg)
	pwdProfileConfigUpdate(cluster.ClusterNotifyAdd, share.CLUSConfigPwdProfileStore, value)
}
