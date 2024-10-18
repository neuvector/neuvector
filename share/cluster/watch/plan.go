package watch

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	consulapi "github.com/neuvector/neuvector/share/cluster/api"
	log "github.com/sirupsen/logrus"
)

const (
	// retryInterval is the base retry value
	//retryInterval = 5 * time.Second

	// maximum back off time, this is to prevent
	// exponential runaway
	maxBackoffTime = 180 * time.Second
	queryWaitTime  = 300 * time.Second

	// congestion controls
	// (1) congestion detection
	congestTimeWindow  = 2 * time.Second // detection on possible surges
	congestIndexWindow = 8
	congestQualCount   = 2 // qualification

	// (2) adaptive congestion avoidance
	fastForwardBaseline = 64   // minimum fast-forward count
	fastForwardTopline  = 2048 // maximum fast-forward count
	rampDownBaseline    = 128  // least ramp-down count
	waitStepBaseline    = 2    // minimum wait steps
	waitStepRampDown    = 4    // ramp-down wait steps
	waitStepTopline     = 6    // maximum wait steps
	waitStepBaseUnit    = 5    // 5 sec per wait step
	queryWaitTimeStep   = waitStepBaseUnit * time.Second
)

var reportFail bool

// Run is used to run a watch plan
func (p *WatchPlan) Run(address string) error {
	// Setup the client
	p.address = address
	conf := consulapi.DefaultConfig()
	conf.Address = address
	conf.Datacenter = p.Datacenter
	conf.Token = p.Token
	client, err := consulapi.NewClient(conf)
	if err != nil {
		return fmt.Errorf("Failed to connect to agent: %v", err)
	}
	p.client = client

	// Create the logger
	/*
		output := p.LogOutput
		if output == nil {
			output = os.Stderr
		}
		logger := log.New(output, "", log.LstdFlags)
	*/
	// Loop until we are canceled
	failures := 0
	reportFail = true
	fastForwardMode := false
	var fastForwardCnt, vDiff uint64
	var waitSteps, cNum uint
	p.waitTime = queryWaitTime
	// log.WithFields(log.Fields{"type": p.Type, "congestCtl": p.CongestCtl, "Key": p.Key}).Info("WATCH")
OUTER:
	for !p.shouldStop() {
		if fastForwardMode && !p.CongestCtl {
			// the rate-ctl is disabled by external command, back to normal query
			fastForwardMode = false
			cNum = 0
			p.waitTime = queryWaitTime
			p.lastIndex = 0 // get the latest
		}

		// Invoke the handler
		now := time.Now()
		index, result, err := p.Func(p)
		if p.CongestCtl {
			vDiff = index + fastForwardCnt - p.lastIndex // eliminate the wrap-around case
			// log.WithFields(log.Fields{"index": index, "request": p.lastIndex, "diff": vDiff, "empty": result == nil}).Info("WATCH")
		}
		if err != nil {
			fastForwardMode = false
			cNum = 0
			p.waitTime = queryWaitTime
			// log.WithFields(log.Fields{"err": err}).Info("WATCH : normal mode")
		} else if fastForwardMode {
			if vDiff < fastForwardCnt {
				// ramp down
				if (vDiff * 2) > fastForwardCnt {
					// step down a level but keep the same wait time
					fastForwardCnt /= 2
				} else if vDiff > rampDownBaseline { // wait a little bit longer
					waitSteps = waitStepRampDown
					fastForwardCnt = rampDownBaseline
				} else {
					fastForwardCnt = fastForwardBaseline
				}

				if fastForwardCnt <= fastForwardBaseline {
					// log.Info("WATCH: normal")
					fastForwardMode = false
					cNum = 0
					fastForwardCnt = 0
					p.waitTime = queryWaitTime
					if result == nil { // should not happen
						index = 0 // recovery: do the must-proceed query
					}
				} /* else {
					// log.WithFields(log.Fields{"forward": fastForwardCnt, "waitSteps": waitSteps}).Info("WATCH: rampD")
				} */

			} else {
				// ramp up
				fastForwardCnt *= 2
				if fastForwardCnt > fastForwardTopline { // capped by predefined maximum number, 2048
					fastForwardCnt = fastForwardTopline
				}
				waitSteps++
				if waitSteps > waitStepTopline { // capped by predefined maximum time, 30 sec
					waitSteps = waitStepTopline
				}
				p.waitTime = time.Duration(waitSteps) * queryWaitTimeStep
				// log.WithFields(log.Fields{"forward": fastForwardCnt, "waitSteps": waitSteps}).Info("WATCH: busyF")
			}
		} else if p.CongestCtl {
			if p.lastIndex != 0 && result != nil {
				if time.Since(now) < congestTimeWindow && vDiff > congestIndexWindow {
					// a quick response: it could have a lot of ongoing data updates
					//   ==> slow down the blocking query by increasing expecting incoming index with a shorter waiting period
					//   ==> if there is less expected revision updates with the shorter period. Resume the long-pulling policy
					cNum++
					if cNum == congestQualCount && !fastForwardMode {
						fastForwardMode = true
						fastForwardCnt = fastForwardBaseline
						waitSteps = waitStepBaseline
						p.waitTime = time.Duration(waitSteps) * queryWaitTimeStep
						// log.WithFields(log.Fields{"forward": fastForwardCnt, "waitSteps": waitSteps}).Info("WATCH: fastF")
					}
				} else {
					cNum = 0 // reset
				}
			}
		}

		// Check if we should terminate since the function
		// could have blocked for a while
		if p.shouldStop() {
			break
		}

		// Handle an error in the watch function
		if err != nil {
			// Perform an exponential backoff
			failures++
			/*
				retry := retryInterval * time.Duration(failures*failures)
				if retry > maxBackoffTime {
					retry = maxBackoffTime
				}
			*/
			if reportFail && p.Fail != nil {
				if p.Fail() {
					// report is accepted
					reportFail = false
				}
			}
			retry := 3 * time.Second
			if strings.Contains(err.Error(), "Unexpected response code: 500") { // timeouted
				failures = 0
			} else {
				log.WithFields(log.Fields{"type": p.Type, "error": err, "retry": retry, "fails": failures, "report": reportFail}).Error("consul watch")
			}

			select {
			case <-time.After(retry):
				// reset
				p.waitTime = queryWaitTime
				continue OUTER
			case <-p.stopCh:
				return nil
			}
		}

		if failures > 0 && p.Recover != nil {
			p.Recover()
		}

		// Clear the failures
		failures = 0
		reportFail = true

		// If the index is unchanged do nothing
		if !fastForwardMode && index == p.lastIndex {
			continue
		}

		// Update the index, look for change
		oldIndex := p.lastIndex
		// set next query index
		if fastForwardMode {
			p.lastIndex = index + fastForwardCnt
		} else {
			p.lastIndex = index
		}
		if oldIndex != 0 && reflect.DeepEqual(p.lastResult, result) {
			continue
		}

		// Handle the updated result
		p.lastResult = result
		if p.Handler != nil {
			p.Handler(index, result)
		}
	}
	return nil
}

// Stop is used to stop running the watch plan
func (p *WatchPlan) Stop() {
	p.stopLock.Lock()
	defer p.stopLock.Unlock()
	if p.stop {
		return
	}
	p.stop = true
	p.pause = false
	close(p.stopCh)
}

func (p *WatchPlan) shouldStop() bool {
	/*
		select {
		case <-p.stopCh:
			return true
		default:
			return false
		}
	*/
	if p.stop {
		return true
	}
	for p.pause && !p.stop {
		time.Sleep(time.Second)
	}
	return p.stop
}

func (p *WatchPlan) Pause() {
	p.stopLock.Lock()
	defer p.stopLock.Unlock()
	if p.stop || p.pause {
		return
	}
	p.pause = true
}

func (p *WatchPlan) Resume() {
	p.stopLock.Lock()
	defer p.stopLock.Unlock()
	if p.stop || !p.pause {
		return
	}
	reportFail = true
	p.pause = false
}
