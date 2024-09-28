package atmo

import (
	"time"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

const (
	Discover2Monitor = 0
	Monitor2Protect  = 1
)

const (
	AllMode     = 0		// not used
	ProfileMode = 1
	PolicyMode  = 2
)

const (
	allModeType = "@all"		// not used
	profileType = "@profile"
	policyType  = "@policy"
)

type AutoModeHelper interface {
	ConfigureCompleteDuration(mover int, dComplete time.Duration)
	AddGroup(mover int, group string, modeType int) bool
	RemoveGroup(group string)
	Counts(mover int) int
	Enabled() (bool, bool)
	List(mover int) []string
	GetTheGroupType(group string) (int, string)
}

//////
type testFunc	  func(mover int, group string, probeDuration time.Duration) (bool, error)
type decisionFunc func(mover int, group string, err error) error
type automode_ctx struct {
	bD2M		bool
	bM2P		bool

	// controls
	mutex		sync.Mutex
	timerWheel  *utils.TimerWheel

	// data
	d2m_members	map[string]*task
	m2p_members map[string]*task

	// parameters
	d2m_cmpl    time.Duration	// complete period
	m2p_cmpl    time.Duration
	d2m_itl     time.Duration	// probe interval
	m2p_itl     time.Duration
	d2m_life    int			// maximum probe counts
	m2p_life    int

	// callbacks
	probefn  	probeFunc

	// test functions
	testfn		testFunc
	decidefn	decisionFunc
}

//
var atmo_ctx 	*automode_ctx

const discover_probe = time.Second * 60		// interval: 1 minute
const discover_complete = time.Hour * 6		// convert into counters
const monitor_probe = time.Minute * 5       // interval: 5
const monitor_complete = time.Hour * 12		// convert into counters

///
func Init(timerWheel *utils.TimerWheel, test_cb testFunc, decision_cb decisionFunc) (*automode_ctx) {
	log.Debug("ATMO:")
	atmo_ctx = &automode_ctx {
		d2m_members: make(map[string]*task),
		m2p_members: make(map[string]*task),
		timerWheel:  timerWheel,
		d2m_cmpl:    discover_complete,		// complete period
		m2p_cmpl:    monitor_complete,
		d2m_itl:     discover_probe,		// probe interval
		m2p_itl:     monitor_probe,
		testfn:	  	 test_cb,
		decidefn:    decision_cb,
	}

	// prepare counters
	atmo_ctx.d2m_life = (int)(atmo_ctx.d2m_cmpl/atmo_ctx.d2m_itl)
	atmo_ctx.m2p_life = (int)(int64(atmo_ctx.m2p_cmpl/atmo_ctx.m2p_itl))
	return atmo_ctx
}

func GetAutoModeHelper() AutoModeHelper {
	return atmo_ctx
}

///////////////////////////////////////////////////////
func (ctx *automode_ctx) lock() {
	ctx.mutex.Lock()
}

func (ctx *automode_ctx) unlock() {
	ctx.mutex.Unlock()
}

////////////////////////////////////////////////////////////////////////////
// internal testing purpose: do before the first Configure() function
func (ctx *automode_ctx) ConfigProbeTime(mover int, probe time.Duration) {
	log.WithFields(log.Fields{"probe": probe, "mover": mover}).Info("ATMO:")
	switch mover {
	case Discover2Monitor:
		ctx.d2m_itl = probe
		ctx.d2m_life =  (int)(ctx.d2m_cmpl/ctx.d2m_itl)
	case Monitor2Protect:
		ctx.m2p_itl = probe
		ctx.m2p_life =  (int)(int64(ctx.m2p_cmpl/ctx.m2p_itl))
	default:
		log.WithFields(log.Fields{"probe": probe, "mover": mover}).Error("ATMO:")
	}
}

func (ctx *automode_ctx) GetTheGroupType(group string) (int, string) {
	if strings.HasSuffix(group, profileType) {
		return ProfileMode, strings.TrimSuffix(group, profileType)	// profile
	}
	return PolicyMode, strings.TrimSuffix(group, policyType) // policy
}

//////////////////////////////////////////////////////////////////////////
func (ctx *automode_ctx) ConfigureCompleteDuration(mover int, dComplete time.Duration) {
	log.WithFields(log.Fields{"complete": dComplete, "mover": mover}).Debug("ATMO:")
	switch mover {
	case Discover2Monitor:
		if dComplete == 0 {	// disabled
			ctx.pruneMembers(Discover2Monitor)
			ctx.bD2M = false
		} else {
			if ctx.d2m_cmpl != dComplete {
				ctx.d2m_cmpl = dComplete
				ctx.d2m_life = (int)(ctx.d2m_cmpl/ctx.d2m_itl)
			}
			ctx.bD2M = true
		}
	case Monitor2Protect:
		if dComplete == 0 {	// disabled
			ctx.pruneMembers(Monitor2Protect)
			ctx.bM2P = false
		} else {
			if ctx.m2p_cmpl != dComplete {
				ctx.m2p_cmpl = dComplete
				ctx.m2p_life = (int)(int64(ctx.m2p_cmpl/ctx.m2p_itl))
			}
			ctx.bM2P = true
		}
	}
}

func (ctx *automode_ctx) AddGroup(mover int, theGroup string, modeType int) bool {
	var group string
	switch modeType {
	case ProfileMode:
		group = theGroup + profileType
	case PolicyMode:
		group = theGroup + policyType
	default:
		return false
	}

	switch mover {
		case Discover2Monitor:
			ctx.removeMember(Monitor2Protect, group)
			if !ctx.bD2M {
				return false
			}
		case Monitor2Protect:
			ctx.removeMember(Discover2Monitor, group)
			if !ctx.bM2P {
				return false
			}
		default:
			return false
	}
	return ctx.addMember(mover, group)
}

func (ctx *automode_ctx) RemoveGroup(group string) {
	// log.WithFields(log.Fields{"group": group}).Debug("ATMO:")

	// where is it?
	ctx.removeMember(Discover2Monitor, group + profileType)
	ctx.removeMember(Monitor2Protect, group  + profileType)
	ctx.removeMember(Discover2Monitor, group + policyType)
	ctx.removeMember(Monitor2Protect, group  + policyType)
}

func (ctx *automode_ctx) Counts(mover int) int {
	ctx.lock()
	defer ctx.unlock()
	switch mover {
	case Discover2Monitor:
		return len(ctx.d2m_members)
	case Monitor2Protect:
		return len(ctx.m2p_members)
	}
	return 0
}

func (ctx *automode_ctx) List(mover int) []string {
	var list []string
	var members map[string]*task

	ctx.lock()
	defer ctx.unlock()
	switch mover {
	case Discover2Monitor:
		members = ctx.d2m_members
	case Monitor2Protect:
		members = ctx.m2p_members
	default:
		return list
	}

	for n, _ := range members {
		list = append(list, n)
	}
	return list
}

func (ctx *automode_ctx) Enabled() (bool, bool) {
	// log.WithFields(log.Fields{"d2m": ctx.bD2M, "m2p": ctx.bM2P}).Debug("ATMO:")
	return ctx.bD2M, ctx.bM2P
}
