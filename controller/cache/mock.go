package cache

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func MockCacheInit() {
	connLog := log.New()
	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	scanLog := log.New()
	scanLog.Out = os.Stdout
	scanLog.Level = log.InfoLevel
	scanLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	mutexLog := log.New()
	mutexLog.Out = os.Stdout
	mutexLog.Level = log.InfoLevel
	mutexLog.Formatter = &utils.LogFormatter{Module: "CTL"}

	cctx = &Context{
		ConnLog:                  connLog,
		MutexLog:                 mutexLog,
		ScanLog:                  scanLog,
		StartFedRestServerFunc:   dummyStartFedRestServer,
		StopFedRestServerFunc:    dummyStopFedRestServer,
		StartStopFedPingPollFunc: dummyStartStopFedPingPoll,
	}
}

func MockSystemConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	systemConfigUpdate(nType, key, value)
}
func MockUserRoleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	userRoleConfigUpdate(nType, key, value)
}

func dummyStartFedRestServer(fedPingInterval uint32)                           {}
func dummyStopFedRestServer()                                                  {}
func dummyStartStopFedPingPoll(cmd, interval uint32, param1 interface{}) error { return nil }
