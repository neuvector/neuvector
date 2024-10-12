package workerlet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/system"
)

// ///
type Tasker struct {
	bEnable     bool
	bShowDebug  bool
	mutex       sync.Mutex
	taskPath    string
	workingPath string
	sys         *system.SystemTools
}

// ///
func NewWalkerTask(showDebug bool, sys *system.SystemTools) *Tasker {
	log.WithFields(log.Fields{"showDebug": showDebug}).Info()
	if dbgError := os.MkdirAll(WalkerBasePath, os.ModePerm); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	ts := &Tasker{
		bEnable:     true,
		taskPath:    WalkerApp,
		workingPath: WalkerBasePath, // working path
		bShowDebug:  showDebug,
		sys:         sys,
	}
	return ts
}

// ////
func (ts *Tasker) putInputFile(request interface{}) (string, []string, error) {
	var workingPath string
	var args []string
	var data []byte

	switch req := request.(type) {
	case WalkPathRequest:
		args = append(args, "-t", "path")
		data, _ = json.Marshal(req)
	case WalkGetPackageRequest:
		args = append(args, "-t", "pkg")
		data, _ = json.Marshal(req)
	case WalkSecretRequest:
		args = append(args, "-t", "scrt")
		data, _ = json.Marshal(req)
	default:
		return "", args, errors.New("Invalid type")
	}

	if ts.bShowDebug {
		args = append(args, "-d=true")
	}

	/// lock the allocation
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	for i := 0; i < 256; i++ {
		uid := uuid.New().String()
		workingPath = filepath.Join(ts.workingPath, uid)
		if _, err := os.Stat(workingPath); err != nil { // not existed
			args = append(args, "-u", uid)
			if dbgError := os.MkdirAll(workingPath, os.ModePerm); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if err = os.WriteFile(filepath.Join(workingPath, RequestJson), data, 0644); err == nil {
				return workingPath, args, nil
			}
		}
	}
	return "", nil, errors.New("Failed to allocate")
}

func (ts *Tasker) openResult(workingFolder, file string) ([]byte, error) {
	jsonFile, err := os.Open(filepath.Join(workingFolder, file))
	if err == nil {
		byteValue, _ := io.ReadAll(jsonFile)
		jsonFile.Close()
		return byteValue, nil
	}
	return nil, err
}

// ///
func (ts *Tasker) getResultFile(request interface{}, workingFolder string) ([]byte, []byte, error) {
	// primary result
	byteValue, err := ts.openResult(workingFolder, ResultJson)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open result")
		return nil, nil, err
	}

	switch request.(type) {
	case WalkPathRequest, WalkGetPackageRequest:
		return byteValue, nil, nil
	case WalkSecretRequest:
		byteValue2, err := ts.openResult(workingFolder, ResultJson2)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to open result2")
			return nil, nil, err
		}
		return byteValue, byteValue2, nil
	}
	return nil, nil, errors.New("Invalid type")
}

// ////
func (ts *Tasker) Run(request interface{}, cid string) ([]byte, []byte, error) {
	if !ts.bEnable {
		return nil, nil, fmt.Errorf("session ended")
	}

	workingFolder, args, err := ts.putInputFile(request)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil, nil, err
	}
	args = append(args, "-cid", cid) // reference only

	// remove working folder
	defer os.RemoveAll(workingFolder)

	// log.WithFields(log.Fields{"cmd": ts.taskPath, "wpath": workingFolder, "args": args}).Debug()
	//////
	cmd := exec.Command(ts.taskPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ts.bShowDebug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Start")
		return nil, nil, err
	}

	pgid := cmd.Process.Pid
	// log.WithFields(log.Fields{"pid": pgid}).Debug()
	ts.sys.AddToolProcess(pgid, 0, ts.taskPath, workingFolder)
	err = cmd.Wait()
	ts.sys.RemoveToolProcess(pgid, false)

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Done")
		return nil, nil, err
	}
	return ts.getResultFile(request, workingFolder)
}

// ////
func (ts *Tasker) RunWithTimeout(request interface{}, cid string, timeout time.Duration) ([]byte, []byte, error) {
	if !ts.bEnable {
		return nil, nil, fmt.Errorf("session ended")
	}

	workingFolder, args, err := ts.putInputFile(request)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil, nil, err
	}
	args = append(args, "-cid", cid) // reference only

	// remove working folder
	defer os.RemoveAll(workingFolder)

	// log.WithFields(log.Fields{"cmd": ts.taskPath, "wpath": workingFolder, "args": args}).Debug()
	cmd := exec.Command(ts.taskPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ts.bShowDebug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Start")
		return nil, nil, err
	}

	pgid := cmd.Process.Pid
	ts.sys.AddToolProcess(pgid, 0, ts.taskPath, workingFolder)

	var msg string
	result := make(chan error, 1)
	go func() {
		result <- cmd.Wait()
	}()

	select {
	case err := <-result:
		ts.sys.RemoveToolProcess(pgid, false)
		if err == nil {
			return ts.getResultFile(request, workingFolder)
		} else {
			msg = fmt.Sprintf("pathwalker: error=%s", err.Error())
			if ee, ok := err.(*exec.ExitError); ok {
				if status := ts.sys.GetExitStatus(ee); status != 0 {
					msg += fmt.Sprintf(", status=%d", status)
				}
			}
		}
	case <-time.After(timeout + time.Duration(10*time.Second)): // Set a hard limit + 10 seconds
		ts.sys.RemoveToolProcess(pgid, true)
		return nil, nil, fmt.Errorf("pathwalker: timeout")
	}
	return nil, nil, errors.New(msg)
}

// ///
func (ts *Tasker) Close() {
	log.Info()

	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.bEnable = false
	// ts.sys.ShowToolProcesses()
	ts.sys.StopToolProcesses()
}
