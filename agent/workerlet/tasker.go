package workerlet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/system"
)

/////
type Tasker struct {
	bEnable     bool
	bShowDebug  bool
	mutex       sync.Mutex
	taskPath    string
	workingPath string
	sys         *system.SystemTools
}

/////
func NewWalkerTask(showDebug bool, sys *system.SystemTools) *Tasker {
	log.WithFields(log.Fields{"showDebug": showDebug}).Info()
	os.MkdirAll(WalkerBasePath, os.ModePerm)
	ts := &Tasker{
		bEnable:     true,
		taskPath:    WalkerApp,
		workingPath: WalkerBasePath, // working path
		bShowDebug:  showDebug,
		sys:         sys,
	}
	return ts
}

//////
func (ts *Tasker) putInputFile(request interface{}) (string, []string, error) {
	var workingPath string
	var args []string
	var data []byte

	switch request.(type) {
	case WalkPathRequest:
		args = append(args, "-t", "path")
		data, _ = json.Marshal(request.(WalkPathRequest))
	case WalkGetPackageRequest:
		args = append(args, "-t", "pkg")
		data, _ = json.Marshal(request.(WalkGetPackageRequest))
	case WalkSecretRequest:
		args = append(args, "-t", "scrt")
		data, _ = json.Marshal(request.(WalkSecretRequest))
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
			os.MkdirAll(workingPath, os.ModePerm)
			if err = ioutil.WriteFile(filepath.Join(workingPath, RequestJson), data, 0644); err == nil {
				return workingPath, args, nil
			}
		}
	}
	return "", nil, errors.New("Failed to allocate")
}

func (ts *Tasker) openResult(workingFolder, file string) ([]byte, error) {
	jsonFile, err := os.Open(filepath.Join(workingFolder, file))
	if err == nil {
		byteValue, _ := ioutil.ReadAll(jsonFile)
		jsonFile.Close()
		return byteValue, nil
	}
	return nil, err
}

/////
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

//////
func (ts *Tasker) Run(request interface{}) ([]byte, []byte, error) {
	if !ts.bEnable {
		return nil, nil, fmt.Errorf("session ended")
	}

	workingFolder, args, err := ts.putInputFile(request)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil, nil, err
	}

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

/////
func (ts *Tasker) Close() {
	log.Info()

	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.bEnable = false
	// ts.sys.ShowToolProcesses()
	ts.sys.StopToolProcesses()
}
