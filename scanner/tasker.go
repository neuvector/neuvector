package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
)

const reqTemplate = "/tmp/%s_i.json"
const resTemplate = "/tmp/%s_o.json"

/////
type Tasker struct {
	bEnable    bool
	bShowDebug bool
	mutex      sync.Mutex
	taskPath   string
	rtSock     string // Container socket URL
	sys        *system.SystemTools
}

/////
func newTasker(taskPath, rtSock string, showDebug bool, sys *system.SystemTools) *Tasker {
	log.WithFields(log.Fields{"showDebug": showDebug}).Info()
	if _, err := os.Stat(taskPath); err != nil {
		return nil
	}

	ts := &Tasker{
		bEnable:    true,
		taskPath:   taskPath, // sannnerTask path
		rtSock:     rtSock,   // Container socket URL
		bShowDebug: showDebug,
		sys:        sys,
	}
	return ts
}

//////
func (ts *Tasker) putInputFile(request interface{}) (string, []string, error) {
	var args []string
	var uid string
	var data []byte

	switch request.(type) {
	case share.ScanImageRequest:
		req := request.(share.ScanImageRequest)
		data, _ = json.Marshal(req)
		args = append(args, "-t", "reg")
		args = append(args, "-u", ts.rtSock)
	case share.ScanAppRequest:
		req := request.(share.ScanAppRequest)
		data, _ = json.Marshal(req)
		args = append(args, "-t", "pkg")
	case share.ScanData:
		req := request.(share.ScanData)
		data, _ = json.Marshal(req)
		args = append(args, "-t", "dat")
	case share.ScanAwsLambdaRequest:
		req := request.(share.ScanAwsLambdaRequest)
		data, _ = json.Marshal(req)
		args = append(args, "-t", "awl")
	default:
		return "", args, errors.New("Invalid type")
	}

	/// lock the allocation
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	for i := 0; i < 256; i++ {
		uid = uuid.New().String()
		input := fmt.Sprintf(reqTemplate, uid)
		if _, err := os.Stat(input); err != nil { // not existed
			if err = ioutil.WriteFile(input, data, 0644); err == nil {
				args = append(args, "-i", input)
				args = append(args, "-o", fmt.Sprintf(resTemplate, uid))
				return uid, args, nil
			}
		}
	}
	return uid, args, errors.New("Failed to allocate")
}

/////
func (ts *Tasker) getResultFile(uid string) (*share.ScanResult, error) {
	jsonFile, err := os.Open(fmt.Sprintf(resTemplate, uid))
	if err != nil {
		log.WithFields(log.Fields{"error": err, "uid": uid}).Error("Failed to open result")
		return nil, err
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
	jsonFile.Close()

	var res share.ScanResult
	if err = json.Unmarshal(byteValue, &res); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to parse result")
		return nil, err
	}
	log.Debug("Completed")
	return &res, nil
}

//////
func (ts *Tasker) Run(ctx context.Context, request interface{}) (*share.ScanResult, error) {
	if !ts.bEnable {
		return nil, fmt.Errorf("session ended")
	}

	log.Debug()
	uid, args, err := ts.putInputFile(request)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil, err
	}

	// remove files
	defer os.Remove(fmt.Sprintf(reqTemplate, uid))
	defer os.Remove(fmt.Sprintf(resTemplate, uid))

	// image working folder
	workingFolder := scan.CreateImagePath(uid)
	defer os.RemoveAll(workingFolder)

	log.WithFields(log.Fields{"cmd": ts.taskPath, "wpath": workingFolder, "args": args}).Debug()
	//////
	cmd := exec.Command(ts.taskPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if ts.bShowDebug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Start")
		return nil, err
	}

	pgid := cmd.Process.Pid
	// log.WithFields(log.Fields{"pid": pgid}).Debug()
	ts.sys.AddToolProcess(pgid, 0, "Run", uid)

	ctxError := false
	bRunning := true
	go func() {
		for bRunning {
			if ctx.Err() != nil { // context.Canceled: remote cancelled
				ctxError = true
				// log.WithFields(log.Fields{"error": ctx.Err()}).Error("gRpc")
				ts.sys.RemoveToolProcess(pgid, true) // kill it
				return
			}
			time.Sleep(time.Millisecond * 250)
		}
	}()

	err = cmd.Wait()
	bRunning = false
	if ctxError {
		err = ctx.Err()
	} else {
		ts.sys.RemoveToolProcess(pgid, false)
	}

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Done")
		return nil, err
	}
	return ts.getResultFile(uid)
}

/////
func (ts *Tasker) Close() {
	log.Info()

	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	ts.bEnable = false

	//
	ts.sys.ShowToolProcesses()
	ts.sys.StopToolProcesses()
}
