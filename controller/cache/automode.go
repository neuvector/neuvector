package cache

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/atmo"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

var atmoHelper atmo.AutoModeHelper

func automode_init(ctx *Context) {
	atmo.Init(ctx.TimerWheel, automode_test_func, automode_decision_func)
	atmoHelper = atmo.GetAutoModeHelper()
}

func automode_d2m_test_func(group string) (bool, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := groupCacheMap[group]; ok {
		// member count > 0
		return (cache.members.Cardinality() > 0), nil
	}
	return false, common.ErrObjectNotFound
}

func automode_m2p_test_func(group string, probeDuration int64) (bool, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if cache, ok := groupCacheMap[group]; ok {
		if cache.members.Cardinality() == 0 {
			return false, nil // TBD
		}

		var count int
		var incd_last *api.Incident
		var vio_last *api.Violation
		var thrt_last *api.Threat

		// trace back to last probe duration - 10 seconds
		traceback := time.Now().Unix() - probeDuration - 10

		// process incidents
		syncRLock(syncCatgIncidentIdx)
		for i := 0; i < curIncidentIndex; i++ {
			incd := incidentCache[curIncidentIndex-i-1]
			if incd == nil || incd.AggregationFrom < traceback {
				continue
			}

			if incd.Group == group {
				count++
				incd_last = incd
			}
		}
		syncRUnlock(syncCatgIncidentIdx)

		// suspicious threats
		syncRLock(syncCatgThreatIdx)
		for i := 0; i < curThrtIndex; i++ {
			thrt := thrtCache[curThrtIndex-i-1]
			if thrt == nil || thrt.ReportedTimeStamp < traceback {
				continue
			}

			if thrt.Group == group {
				count++
				thrt_last = thrt
			}
		}
		syncRUnlock(syncCatgThreatIdx)

		// network violations
		syncRLock(syncCatgViolationIdx)
		service := strings.TrimPrefix(group, "nv.")
		for i := 0; i < curVioIndex; i++ {
			vio := vioCache[curVioIndex-i-1]
			if vio == nil || vio.ReportedTimeStamp < traceback {
				continue
			}

			if vio.ServerService == service || vio.ClientService == service {
				count++
				vio_last = vio
			}
		}
		syncRUnlock(syncCatgViolationIdx)

		if count > 0 {
			log.WithFields(log.Fields{"incident": count, "group": group, "incd_last": incd_last, "thrt_last": thrt_last, "vio_last": vio_last}).Debug("ATMO:")
		}
		return (count == 0), nil
	}
	return false, common.ErrObjectNotFound
}

func automode_test_func(mover int, group string, probeDuration time.Duration) (bool, error) {
	switch mover {
	case atmo.Discover2Monitor:
		return automode_d2m_test_func(group)
	case atmo.Monitor2Protect:
		return automode_m2p_test_func(group, int64(probeDuration.Seconds()))
	}
	return false, common.ErrUnsupported
}

func automode_log_event(group, mode string) {
	clog := share.CLUSEventLog{
		Event:      share.CLUSEvGroupAutoPromote,
		GroupName:  group,
		ReportedAt: time.Now().UTC(),
	}
	clog.Msg = fmt.Sprintf("Promote the policy mode of group %s to %s.\n", group, mode)
	cctx.EvQueue.Append(&clog)
}

func automode_promote_mode(group, mode string) error {
	if strings.HasPrefix(group, api.LearnedSvcGroupPrefix) {
		return common.ErrUnsupported
	}

	grp, _, _ := clusHelper.GetGroup(group, access.NewAdminAccessControl())
	if grp == nil {
		log.WithFields(log.Fields{"group": group, "promote": mode}).Info("ATMO: no exist")
		return common.ErrObjectNotFound
	}

	if grp.CfgType != share.Learned {
		log.WithFields(log.Fields{"group": group, "type": grp.CfgType, "promote": mode}).Info("ATMO: ignored")
		return common.ErrUnsupported
	}

	log.WithFields(log.Fields{"group": group, "mode": mode}).Debug("ATMO:")
	// sync both policy and profile modes together
	switch mode {
	case share.PolicyModeEvaluate:
		if grp.ProfileMode != share.PolicyModeLearn {
			return nil
		}
	case share.PolicyModeEnforce:
		if grp.PolicyMode != share.PolicyModeEvaluate {
			return nil
		}
	default:
		return common.ErrUnsupported
	}

	// promote
	grp.ProfileMode = mode
	grp.PolicyMode = mode
	if pp := clusHelper.GetProcessProfile(group); pp != nil {
		pp.Mode = mode
		clusHelper.PutProcessProfile(group, pp)
	}
	if pp, rev := clusHelper.GetFileMonitorProfile(group); pp != nil {
		pp.Mode = grp.ProfileMode
		clusHelper.PutFileMonitorProfile(group, pp, rev)
	}
	log.WithFields(log.Fields{"group": group, "mode": mode}).Info("ATMO: upgraded")
	clusHelper.PutGroup(grp, false)

	automode_log_event(group, mode)
	return nil
}

func automode_decision_func(mover int, group string, err error) error {
	if err != nil {
		log.WithFields(log.Fields{"mover": mover, "error": err}).Debug("ATMO: member left")
		return nil
	}

	var targetMode string
	switch mover {
	case atmo.Discover2Monitor:
		targetMode = share.PolicyModeEvaluate
	case atmo.Monitor2Protect:
		targetMode = share.PolicyModeEnforce
	default:
		return common.ErrUnsupported
	}

	if isLeader() {
		automode_promote_mode(group, targetMode)
	} else {
		go func() {
			r1 := rand.New(rand.NewSource(time.Now().UnixNano()))
			wait_sec := 3*60 + r1.Intn(100) // separating controller actions. no promoting when it has been already promoted
			time.Sleep(time.Second * time.Duration(wait_sec))
			lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, time.Duration(time.Second*60))
			if err != nil {
				log.WithFields(log.Fields{"group": group, "mode": targetMode}).Error("failed: delay changed")
				return
			}
			defer clusHelper.ReleaseLock(lock)
			automode_promote_mode(group, targetMode)
		}()
	}

	return common.ErrUnsupported
}

func automode_configure_d2m(enabled bool, dur int64) {
	var dComplete time.Duration = 0
	if enabled {
		dComplete = time.Duration(dur) * time.Second
	}
	atmoHelper.ConfigureCompleteDuration(atmo.Discover2Monitor, dComplete)
}

func automode_configure_m2p(enabled bool, dur int64) {
	var dComplete time.Duration = 0
	if enabled {
		dComplete = time.Duration(dur) * time.Second
	}
	atmoHelper.ConfigureCompleteDuration(atmo.Monitor2Protect, dComplete)
}

func automode_init_trigger(mover int) {
	var mode string
	switch mover {
	case atmo.Discover2Monitor:
		mode = share.PolicyModeLearn
	case atmo.Monitor2Protect:
		mode = share.PolicyModeEvaluate
	default:
		return
	}

	now := time.Now().Unix()
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	for name, cache := range groupCacheMap {
		if !utils.DoesGroupHavePolicyMode(name) || name == api.AllHostGroup || cache.group == nil {
			continue
		}

		// log.WithFields(log.Fields{"group": name, "mode": mode}).Debug("ATMO:")
		if cache.group.ProfileMode == mode {
			atmoHelper.AddGroup(mover, name)
			switch mover {
			case atmo.Discover2Monitor:
				cache.atmo_d2m = now
			case atmo.Monitor2Protect:
				cache.atmo_m2p = now
			}
		}
	}
}

func automode_trigger_d2m() {
	//log.Debug("ATMO:")
	automode_init_trigger(atmo.Discover2Monitor)
}

func automode_trigger_m2p() {
	//log.Debug("ATMO:")
	automode_init_trigger(atmo.Monitor2Protect)
}

var firstUpdated bool

func automodeConfigUpdate(cfg, cache share.CLUSSystemConfig) {
	// log.WithFields(log.Fields{"cfg": cfg, "cache": cache}).Debug("ATMO:")
	if firstUpdated {
		if cfg.ModeAutoD2M != cache.ModeAutoD2M ||
			cfg.ModeAutoD2MDuration != cache.ModeAutoD2MDuration {
			automode_configure_d2m(cfg.ModeAutoD2M, cfg.ModeAutoD2MDuration)
			if cfg.ModeAutoD2M && !cache.ModeAutoD2M {
				automode_trigger_d2m()
			}
		}
		if cfg.ModeAutoM2P != cache.ModeAutoM2P ||
			cfg.ModeAutoM2PDuration != cache.ModeAutoM2PDuration {
			automode_configure_m2p(cfg.ModeAutoM2P, cfg.ModeAutoM2PDuration)
			if cfg.ModeAutoM2P && !cache.ModeAutoM2P {
				automode_trigger_m2p()
			}
		}
	} else {
		firstUpdated = true
		if cfg.ModeAutoD2M {
			automode_configure_d2m(cfg.ModeAutoD2M, cfg.ModeAutoD2MDuration)
			automode_trigger_d2m()
		}
		if cfg.ModeAutoM2P {
			automode_configure_m2p(cfg.ModeAutoM2P, cfg.ModeAutoM2PDuration)
			automode_trigger_m2p()
		}
	}
}

// ////////////////////
func automodeGroupDelete(name string, param interface{}) {
	log.WithFields(log.Fields{"group": name}).Debug("ATMO:")
	if bD2M, bM2P := atmoHelper.Enabled(); bD2M || bM2P {
		atmoHelper.RemoveGroup(name)
	}
}

func automodeGroupAdd(name string, param interface{}) {
	cache := param.(*groupCache)
	if bD2M, bM2P := atmoHelper.Enabled(); bD2M || bM2P {
		var mover int
		if !utils.DoesGroupHavePolicyMode(name) || name == api.AllHostGroup || cache.group == nil {
			return
		}

		// log.WithFields(log.Fields{"name": name, "cache": cache, "group": cache.group}).Debug("ATMO:")
		now := time.Now().Unix()
		switch cache.group.ProfileMode {
		case share.PolicyModeLearn:
			mover = atmo.Discover2Monitor
			if cache.atmo_d2m > 0 {
				return
			}
			cache.atmo_d2m = now
			cache.atmo_m2p = 0
		case share.PolicyModeEvaluate:
			mover = atmo.Monitor2Protect
			if cache.atmo_m2p > 0 {
				return
			}
			cache.atmo_m2p = now
			cache.atmo_d2m = 0
		default:
			return
		}
		atmoHelper.AddGroup(mover, name)
	} else {
		cache.atmo_m2p = 0 // reset all
		cache.atmo_d2m = 0
	}
}
