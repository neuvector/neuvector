package system

import (
	"fmt"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// ///////////////////////////////////////////////////////////
// Record and trace the namespace processes in the system
// Kill them during process exiting stages
// ///////////////////////////////////////////////////////////
type toolProcessMonitor struct {
	mutex sync.Mutex
	pMap  map[int]string
}

var toolProc toolProcessMonitor = toolProcessMonitor{
	pMap: make(map[int]string),
}

func (s *SystemTools) AddToolProcess(pgid, pid int, exec, cmds string) {
	toolProc.mutex.Lock()
	defer toolProc.mutex.Unlock()
	if info, ok := toolProc.pMap[pgid]; ok {
		log.WithFields(log.Fields{"pgid": pgid, "info": info, "exec": exec, "cmds": cmds}).Debug("TOOLP: duplicate entry")
		return
	}

	// refernce only
	info := fmt.Sprintf("%d[%d]: %s, %s", pgid, pid, exec, cmds)
	toolProc.pMap[pgid] = info
	//	log.WithFields(log.Fields{"pgid": pgid, "info": info}).Debug("TOOLP: add")
}

func (s *SystemTools) RemoveToolProcess(pgid int, bKill bool) {
	toolProc.mutex.Lock()
	defer toolProc.mutex.Unlock()
	info, ok := toolProc.pMap[pgid]
	if ok {
		// log.WithFields(log.Fields{"pgid": pgid, "info": info}).Debug("TOOLP: removing")
		go func() {
			time.Sleep(time.Second * 5) // keep a temporary record for the probe reference
			toolProc.mutex.Lock()
			delete(toolProc.pMap, pgid)
			toolProc.mutex.Unlock()
			// log.WithFields(log.Fields{"pgid": pgid}).Debug("TOOLP: removed")
		}()
	}

	if bKill {
		s.KillCommandSubtree(pgid, info)
	}
}

func (s *SystemTools) ShowToolProcesses() {
	toolProc.mutex.Lock()
	defer toolProc.mutex.Unlock()
	for pgid, info := range toolProc.pMap {
		log.WithFields(log.Fields{"pgid": pgid, "info": info}).Debug("TOOLP:")
	}
}

func (s *SystemTools) StopToolProcesses() {
	s.bEnable = false
	toolProc.mutex.Lock()
	defer toolProc.mutex.Unlock()
	for pgid, info := range toolProc.pMap {
		// log.WithFields(log.Fields{"pgid": pgid, "info": info}).Debug("TOOLP: kill")
		s.KillCommandSubtree(pgid, info)
	}

	// clear the map with no entry
	toolProc.pMap = make(map[int]string)
}

func (s *SystemTools) IsToolProcess(sid, pgid int) bool {
	toolProc.mutex.Lock()
	defer toolProc.mutex.Unlock()
	if _, ok := toolProc.pMap[pgid]; ok {
		return true
	}

	_, ok := toolProc.pMap[sid]
	return ok
}

func (s *SystemTools) KillCommandSubtree(pgid int, info string) {
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		log.WithFields(log.Fields{"pid": pgid, "error": err}).Error("can not signal")
	}
}
