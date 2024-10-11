package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/scan/secrets"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const procRootMountPoint = "/proc/%d/root"

func usage() {
	fmt.Fprintf(os.Stderr, "usage: pathWalker [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

// global control data
type taskMain struct {
	ctx      context.Context
	sys      *system.SystemTools
	workPath string
	done     chan error
}

func isPidValid(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// ///////////
func InitTaskMain(workPath string, done chan error, sys *system.SystemTools) *taskMain {
	tm := &taskMain{
		ctx:      context.Background(),
		sys:      sys,
		workPath: workPath,
		done:     done,
	}
	return tm
}

// //////////////////////
func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "WLK"})

	walkType := flag.String("t", "", "walk type: path, pkg, or scrt (Required)")
	uuid := flag.String("u", "uuid", "result uuid name")
	debugTrace := flag.Bool("d", false, "enable debug trace")
	cid := flag.String("cid", "", "container identifier")
	flag.Usage = usage
	flag.Parse()

	if *debugTrace {
		log.SetLevel(log.DebugLevel)
	}

	// acquire tool
	sys := system.NewSystemTools()

	// create a working path from the input file
	workPath := filepath.Join(workerlet.WalkerBasePath, *uuid)
	if dbgError := os.MkdirAll(workPath, os.ModePerm); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	log.WithFields(log.Fields{"workPath": workPath, "cid": *cid}).Debug()

	pass := false
	if sys.IsRunningInContainer() {
		// restricted only to scanner
		var exe string
		ppid := os.Getppid()
		ppath := fmt.Sprintf("/proc/%d/exe", ppid)
		if _, err := os.Stat(ppath); err == nil {
			exe, err = os.Readlink(ppath)
			if err == nil && strings.HasPrefix(exe, "/usr/local/bin/agent") {
				pass = true
			}
		}
	} else {
		log.Info("Not running in container.")
		pass = true // TODO: add some restriction
	}

	if !pass {
		fmt.Fprintf(os.Stderr, "---")
		usage() // exited as 2
	}

	log.Info("Running ... ")
	start := time.Now()
	done := make(chan error, 1)

	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c_sig
		done <- nil
	}()

	tm := InitTaskMain(workPath, done, sys)
	if err := tm.ProcessRequest(*walkType); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		os.Exit(-1)
	}

	err := <-done
	log.WithFields(log.Fields{"workPath": workPath, "used": time.Since(start).Seconds(), "error": err}).Info("Exit")
}

// ///////////////////////////////////////////////////////////////////////////////////////////////////
func (tm *taskMain) ProcessRequest(walkType string) error {
	jsonFile, err := os.Open(filepath.Join(tm.workPath, workerlet.RequestJson))
	if err != nil {
		return err
	}
	byteValue, _ := io.ReadAll(jsonFile)
	jsonFile.Close()

	// selector
	switch walkType {
	case "path": // paths
		var req workerlet.WalkPathRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			if req.Pid == 0 {
				return fmt.Errorf("%s: Invalid request Pid[%d]", walkType, req.Pid)
			}
			go tm.WalkPathTask(req)
			return nil
		}
	case "pkg": // app package search
		var req workerlet.WalkGetPackageRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			if req.Pid == 0 {
				return fmt.Errorf("%s: Invalid request Pid[%d]", walkType, req.Pid)
			}
			go tm.WalkPackageTask(req)
			return nil
		}
	case "scrt": // secret scan
		var req workerlet.WalkSecretRequest
		if err = json.Unmarshal(byteValue, &req); err == nil {
			if req.Pid == 0 {
				return fmt.Errorf("%s: Invalid request Pid[%d]", walkType, req.Pid)
			}
			go tm.ScanSecretTask(req)
			return nil
		}
	default:
		return errors.New("Invalid type")
	}
	return fmt.Errorf("Invalid request: %s", string(byteValue))
}

// ///////////////////////////////////////////////////////////////////////////////////////////////////
func (tm *taskMain) WalkPathTask(req workerlet.WalkPathRequest) {
	var errorCnt int
	var res = &workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	log.WithFields(log.Fields{"req": req}).Debug()
	rootPath := filepath.Join(fmt.Sprintf(procRootMountPoint, req.Pid), req.Path)
	rootPathLen := len(rootPath)
	rootPath += "/"

	bTimeoutFlag := false
	if req.Timeout > 0 {
		go func() {
			time.Sleep(req.Timeout)
			bTimeoutFlag = true
		}()
	}

	log.WithFields(log.Fields{"path": rootPath}).Debug("start")
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if bTimeoutFlag {
			return errors.New("Timeout")
		}

		if err != nil {
			if isPidValid(req.Pid) { // abort
				// fmt.Errorf("Invalid pid: %d", req.Pid)
				return nil
			}

			// log.WithFields(log.Fields{"path": rootPath, "error": err.Error()}).Error()
			if strings.Contains(err.Error(), "no such file") {
				errorCnt++
				if errorCnt < 100 {
					return nil
				}
			}
			log.WithFields(log.Fields{"path": rootPath, "error": err}).Error("prevent panic")
			return err
		}

		if info.IsDir() {
			// avoid the huge file systems on the hosts: /dev, /sys and /proc
			if path != rootPath {
				if utils.IsMountPoint(path) {
					log.WithFields(log.Fields{"path": path}).Debug("skip dir")
					return filepath.SkipDir
				}
			}

			ddata := &workerlet.DirData{
				Dir: path[rootPathLen:],
				Info: workerlet.FInfo{
					Name:    info.Name(),
					Size:    info.Size(),
					Mode:    info.Mode(),
					ModTime: info.ModTime(),
					IsDir:   info.IsDir(),
				},
			}
			res.Dirs = append(res.Dirs, ddata)
			// log.WithFields(log.Fields{"dir": ddata.Dir}).Debug()
		} else {
			bExec := false
			if info.Mode().IsRegular() {
				bExec = utils.IsExecutable(info, path)
			}

			fdata := &workerlet.FileData{
				File:   path[rootPathLen:],
				IsExec: bExec,
				Info: workerlet.FInfo{
					Name:    info.Name(),
					Size:    info.Size(),
					Mode:    info.Mode(),
					ModTime: info.ModTime(),
					IsDir:   info.IsDir(),
				},
			}

			if req.ExecOnly {
				if fdata.IsExec {
					res.Files = append(res.Files, fdata)
					//log.WithFields(log.Fields{"file": fdata.File}).Debug()
				}
			} else {
				if info.Mode().IsRegular() {
					// add hash data
					fdata.Hash = utils.FileHashCrc32(path, info.Size())
				}
				res.Files = append(res.Files, fdata)
				// log.WithFields(log.Fields{"file": fdata.File}).Debug()
			}
		}
		return nil
	})

	log.WithFields(log.Fields{"path": rootPath}).Debug("done")

	// outputs
	if data, err := json.Marshal(res); err == nil {
		if dbgError := os.WriteFile(filepath.Join(tm.workPath, workerlet.ResultJson), data, 0644); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	tm.done <- err
}

func (tm *taskMain) WalkPackageTask(req workerlet.WalkGetPackageRequest) {
	var data share.ScanData
	scanUtil := scan.NewScanUtil(tm.sys)
	data.Buffer, data.Error = scanUtil.GetRunningPackages(req.Id, req.ObjType, req.Pid, req.Kernel, req.PidHost)

	// outputs:
	output, err := json.Marshal(data)
	if err == nil {
		err = os.WriteFile(filepath.Join(tm.workPath, workerlet.ResultJson), output, 0644)
	}
	tm.done <- err
}

func (tm *taskMain) ScanSecretTask(req workerlet.WalkSecretRequest) {
	log.WithFields(log.Fields{"req": req}).Debug()

	config := secrets.Config{ // default
		MaxFileSize: req.MaxFileSize, // as 4 kB
		MiniWeight:  req.MiniWeight,
		TimeoutSec:  req.TimeoutSec,
	}

	var envVars []byte
	if content, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", req.Pid)); err == nil {
		envVars = bytes.Join(bytes.Split(content, []byte{0}), []byte{'\n'})
	} else {
		log.WithFields(log.Fields{"pid": req.Pid}).Error("failed to read environment variables")
	}

	rootPath := fmt.Sprintf(procRootMountPoint, req.Pid)
	logs, perms, err := secrets.FindSecretsByRootpath(rootPath, envVars, config)

	// outputs: perm
	if output, err := json.Marshal(perms); err == nil {
		if dbgError := os.WriteFile(filepath.Join(tm.workPath, workerlet.ResultJson), output, 0644); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	// outputs: secret
	if output, err := json.Marshal(logs); err == nil {
		if dbgError := os.WriteFile(filepath.Join(tm.workPath, workerlet.ResultJson2), output, 0644); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error()
	}

	tm.done <- err
}
