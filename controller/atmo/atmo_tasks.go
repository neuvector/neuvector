package atmo

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

// //////////////////
type probeFunc func(mover int, id string, probeDuration time.Duration) (bool, error)
type lifeCntFunc func(mover int) int
type completeFunc func(mover int, group string, err error) error
type task struct {
	mover      int
	id         string // group name
	timer      string
	timerWheel *utils.TimerWheel
	runs       int           // good counter
	interval   time.Duration // probe interval
	testFunc   probeFunc
	lifeFunc   lifeCntFunc
	cmplFunc   completeFunc
}

// /////////////////////////////////////////////////////////////////
func (t *task) StartTimer() {
	t.timer, _ = t.timerWheel.AddTask(t, t.interval)
}

func (t *task) CancelTimer() {
	if t.timer != "" {
		t.timerWheel.RemoveTask(t.timer)
		t.timer = ""
	}
}

func (t *task) Expire() {
	ok, err := t.testFunc(t.mover, t.id, t.interval)
	if err != nil {
		// remove the task
		t.CancelTimer()
		go t.cmplFunc(t.mover, t.id, err)
		return
	}

	if ok {
		// accumlated amount
		t.runs++
		// log.WithFields(log.Fields{"group": t.id, "runs": t.runs}).Debug("ATMO:")
	} else {
		//log.WithFields(log.Fields{"group": t.id}).Debug("ATMO:")
		if t.mover == Monitor2Protect {
			t.runs = 0 // reset counters
		}
	}

	if t.runs >= t.lifeFunc(t.mover) {
		// completed
		t.CancelTimer()
		go t.cmplFunc(t.mover, t.id, nil)
	} else {
		// re-queued
		t.StartTimer()
	}
}

// /////////////////////////////////////////////////////////////////
func (ctx *automode_ctx) prober(mover int, group string, dur time.Duration) (bool, error) {
	return ctx.testfn(mover, group, dur)
}

func (ctx *automode_ctx) life(mover int) int {
	switch mover {
	case Discover2Monitor:
		return ctx.d2m_life
	case Monitor2Protect:
		return ctx.m2p_life
	}
	return 0 // kick-out unknown
}

func (ctx *automode_ctx) finisher(mover int, group string, err error) error {
	ctx.lock()
	switch mover {
	case Discover2Monitor:
		delete(ctx.d2m_members, group)
	case Monitor2Protect:
		delete(ctx.m2p_members, group)
	}
	ctx.unlock()
	return ctx.decidefn(mover, group, err)
}

func (ctx *automode_ctx) addMember(mover int, group string) bool {
	var members map[string]*task
	var interval time.Duration

	ctx.lock()
	defer ctx.unlock()
	switch mover {
	case Discover2Monitor:
		members = ctx.d2m_members
		interval = ctx.d2m_itl
	case Monitor2Protect:
		members = ctx.m2p_members
		interval = ctx.m2p_itl
	default:
		return false
	}

	if _, ok := members[group]; !ok {
		log.WithFields(log.Fields{"group": group, "mover": mover}).Debug("ATMO:")
		t := &task{
			id:         group,
			mover:      mover,
			interval:   interval,
			timerWheel: ctx.timerWheel,
			testFunc:   ctx.prober,
			lifeFunc:   ctx.life,
			cmplFunc:   ctx.finisher,
		}
		members[group] = t
		t.StartTimer()
		return true
	}
	return false
}

func (ctx *automode_ctx) removeMember(mover int, group string) {
	var members map[string]*task

	ctx.lock()
	defer ctx.unlock()
	switch mover {
	case Discover2Monitor:
		members = ctx.d2m_members
	case Monitor2Protect:
		members = ctx.m2p_members
	default:
		return
	}

	if task, ok := members[group]; ok {
		log.WithFields(log.Fields{"group": group, "mover": mover}).Debug("ATMO:")
		task.CancelTimer()
		delete(members, group)
	}
}

func (ctx *automode_ctx) pruneMembers(mover int) {
	var members map[string]*task

	ctx.lock()
	defer ctx.unlock()
	switch mover {
	case Discover2Monitor:
		members = ctx.d2m_members
	case Monitor2Protect:
		members = ctx.m2p_members
	default:
		return
	}

	for group, task := range members {
		task.CancelTimer()
		delete(members, group)
	}
	log.WithFields(log.Fields{"mover": mover, "d2m_members": len(ctx.d2m_members), "m2p_members": len(ctx.m2p_members)}).Debug("ATMO:")
}
