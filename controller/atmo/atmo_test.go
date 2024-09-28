package atmo

import (
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share/utils"
)

func my_test_func(mover int, group string, probeDuration time.Duration) (bool, error) {
	// log.WithFields(log.Fields{"group": group, "mover": mover}).Debug("ATMO:")
	switch mover {
	case Discover2Monitor:
		return true, nil
	case Monitor2Protect:
		return true, nil
	}
	return false, common.ErrUnsupported
}

func my_decision_func(mover int, group string, err error) error {
	log.WithFields(log.Fields{"group": group, "mover": mover, "error": err}).Debug("ATMO:")
	if err != nil {
		log.WithFields(log.Fields{"mover": mover, "error": err}).Debug("ATMO: member left")
		return nil
	}

	switch mover {
	case Discover2Monitor:
		return nil
	case Monitor2Protect:
		return nil
	}
	return common.ErrUnsupported
}

func my_completed(mover int, group string, err error) bool {
	log.WithFields(log.Fields{"group": group, "mover": mover, "error": err}).Debug("ATMO:")
	switch mover {
	case Discover2Monitor:
		return true		// promote Discover to Monitor
	case Monitor2Protect:
		return true		// promote Monitor to Protect
	}
	return false
}

func initEnv() *automode_ctx {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel) // change it later: log.InfoLevel
	log.SetFormatter(&utils.LogFormatter{Module: "ATMO"})
	timerWheel := utils.NewTimerWheel()
	timerWheel.Start()
	ctx := Init(timerWheel, my_test_func, my_decision_func)
	// testing purpose
	ctx.ConfigProbeTime(Discover2Monitor, time.Second*5)
	ctx.ConfigProbeTime(Monitor2Protect, time.Second*5)
	return ctx
}

func testAddGroups(t *testing.T) {
	ctx := initEnv()
	ctx.ConfigureCompleteDuration(Discover2Monitor, time.Second * 30)
	ctx.ConfigureCompleteDuration(Monitor2Protect, time.Second * 60)

	for i := 0; i < 2; i++ {
		name := fmt.Sprintf("m2d%d", i)
		if ok := ctx.AddGroup(Monitor2Protect, name, ProfileMode); !ok {
			t.Errorf("Error: failed to add %s\n", name)
			break
		}
		time.Sleep(time.Second * 10)
	}

	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("d2m%d", i)
		if ok := ctx.AddGroup(Discover2Monitor, name, ProfileMode); !ok {
			t.Errorf("Error: failed to add %s\n", name)
			break
		}
		time.Sleep(time.Second * 10)
	}

	cnt := 12
	for {
		time.Sleep(time.Second * 10)
		if ctx.Counts(Discover2Monitor) == 0 && ctx.Counts(Monitor2Protect) == 0 {
			break
		}
		cnt--
		if cnt == 0 {
			t.Errorf("Error: failed to stop\n")
			break
		}
	}
}