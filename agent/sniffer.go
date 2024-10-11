package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/system"
)

const (
	defaultPcapDir = "/var/nv_debug/pcap/"
	pcapHeaderLen  = 24
)

const (
	snifferRunning = iota
	snifferStopped
)

type procInfo struct {
	cmd        *exec.Cmd
	fileName   string
	fileNumber uint
	duration   uint
	workload   string
	args       []string
	status     int
	startTime  int64
	stopTime   int64
	errb       bytes.Buffer
}

var snifferPidMap map[string]*procInfo = make(map[string]*procInfo, 0)
var snifferIndex uint32
var snifferMutex sync.RWMutex

func releaseAllSniffer() {
	for key, proc := range snifferPidMap {
		if proc.status == snifferRunning {
			if dbgError := stopSniffer(key); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		if dbgError := removePcapFiles(proc.fileNumber, proc.fileName); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
}

func releaseSniffer(id string) {
	for key, proc := range snifferPidMap {
		if proc.workload == id && proc.status == snifferRunning {
			if dbgError := stopSniffer(key); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
	}
}

// sniffer ID: (index+rand)(8)+agentID
func generateSnifferID() string {
	randBytes := make([]byte, share.SnifferIdAgentField/2)
	if _, dbgError := rand.Read(randBytes); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	rstr := hex.EncodeToString(randBytes)
	str := fmt.Sprintf("%d", snifferIndex)
	snifferIndex++
	id := str + rstr[len(str):] + Agent.ID
	return id
}

func removePcapFiles(max uint, path string) error {
	//only one file
	if max <= 1 {
		if _, err := os.Stat(path); err == nil {
			if err = os.Remove(path); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("rm file error")
				return err
			}
		}
		return nil
	} else {
		//more than one file
		var i uint
		for i = 0; i < max; i++ {
			pa := getFilePath(max, i, path)
			if _, err := os.Stat(pa); os.IsNotExist(err) {
				break
			}
			if err := os.Remove(pa); err != nil {
				log.WithFields(log.Fields{"error": err, "file": pa}).Error("rm file error")
				return err
			}
		}
	}
	return nil
}

func getFilePath(max, i uint, path string) string {
	var pa string
	if max <= 10 {
		pa = fmt.Sprintf("%s%01d", path, i)
	} else if max <= 100 {
		pa = fmt.Sprintf("%s%02d", path, i)
	} else {
		//max is 1000 number files, if more than that, it will exit by not exist
		pa = fmt.Sprintf("%s%03d", path, i)
	}
	return pa
}

func getFileSizeNumber(max uint, path string) (int64, uint) {
	var size int64
	var number uint

	if max <= 1 {
		fi, err := os.Stat(path)
		if err != nil {
			return size, number
		}
		size = fi.Size()
		number = 1
	} else {
		var i uint
		for i = 0; i < max; i++ {
			pa := getFilePath(max, i, path)
			fi, err := os.Stat(pa)
			if err != nil {
				return size, number
			}
			size += fi.Size()
			number++
		}
	}
	return size, number
}

func readTimestamp(f *os.File) (uint64, error) {
	b := make([]byte, pcapHeaderLen+8)
	n, err := f.Read(b)
	//if the file exist, but the content has no pcap header, this file should be the latest one
	if err == io.EOF || n < (pcapHeaderLen+8) {
		return math.MaxInt64, nil
	}

	if err != nil {
		return 0, err
	}
	var swapped bool
	if b[0] == 0xd4 && b[1] == 0xc3 && b[2] == 0xb2 && b[3] == 0xa1 {
		swapped = true
	} else if b[0] == 0xa1 && b[1] == 0xb2 && b[2] == 0xc3 && b[3] == 0xd4 {
		swapped = false
	} else {
		return 0, fmt.Errorf("Wrong pcap file header")
	}
	//time stamp is right after pcap header
	var second, microSecond uint64
	if swapped {
		second = uint64(b[pcapHeaderLen+3])<<24 +
			uint64(b[pcapHeaderLen+2])<<16 +
			uint64(b[pcapHeaderLen+1])<<8 +
			uint64(b[pcapHeaderLen+0])
	} else {
		second = uint64(b[pcapHeaderLen+0])<<24 +
			uint64(b[pcapHeaderLen+1])<<16 +
			uint64(b[pcapHeaderLen+2])<<8 +
			uint64(b[pcapHeaderLen+3])
	}
	if swapped {
		microSecond = uint64(b[pcapHeaderLen+7])<<24 +
			uint64(b[pcapHeaderLen+6])<<16 +
			uint64(b[pcapHeaderLen+5])<<8 +
			uint64(b[pcapHeaderLen+4])
	} else {
		microSecond = uint64(b[pcapHeaderLen+4])<<24 +
			uint64(b[pcapHeaderLen+5])<<16 +
			uint64(b[pcapHeaderLen+6])<<8 +
			uint64(b[pcapHeaderLen+7])
	}

	return (second<<32 + microSecond), nil
}

// get all the pcap files name in time seqence
func getFileList(max uint, path string) []string {
	//split the list to two half, first half and second half
	//for example: t3,t4,t0,t1,t2
	//t3,t4 are first half
	//t0,t1,t2 are second half
	var firstHalf, secondHalf []string
	firstHalf = make([]string, 0)

	//only one file case
	if max <= 1 {
		_, err := os.Stat(path)
		if err == nil {
			firstHalf = append(firstHalf, path)
		}
		return firstHalf
	}

	//more than one file
	var lastTimestamp uint64
	var i uint
	for i = 0; i < max; i++ {
		pa := getFilePath(max, i, path)
		f, err := os.Open(pa)
		if err != nil {
			break
		}

		//read the time stamp from the file
		timestamp, err := readTimestamp(f)
		f.Close()
		if err != nil {
			break
		}

		if lastTimestamp == 0 || timestamp > lastTimestamp {
			lastTimestamp = timestamp
		}
		if timestamp < lastTimestamp {
			secondHalf = append(secondHalf, pa)
		} else {
			firstHalf = append(firstHalf, pa)
		}
	}
	//merge the two halves
	if len(secondHalf) > 0 {
		return append(secondHalf, firstHalf...)
	} else {
		return firstHalf
	}
}

func proc2Sniffer(proc *procInfo, id string) *share.CLUSSniffer {
	args := strings.Join(proc.args[2:], " ")
	size, number := getFileSizeNumber(proc.fileNumber, proc.fileName)
	s := &share.CLUSSniffer{
		ID:         id,
		AgentID:    Agent.ID,
		WorkloadID: proc.workload,
		Args:       args,
		FileNumber: uint32(number),
		Size:       size,
		StartTime:  proc.startTime,
		StopTime:   proc.stopTime,
	}
	if proc.status == snifferStopped {
		s.Status = share.SnifferStatus_Stopped
	} else {
		status := global.SYS.GetLocalProcessStatus(proc.cmd.Process.Pid)
		msg := proc.errb.String()
		if status == "R" || status == "S" || status == "D" {
			s.Status = share.SnifferStatus_Running
		} else if status == "Z" && strings.Contains(msg, "packets captured") {
			s.Status = share.SnifferStatus_Stopped
		} else {
			log.WithFields(log.Fields{"message": msg}).Debug("Sniffer error")
			s.Status = share.SnifferStatus_Failed
		}
	}
	return s
}

func showSniffer(id string) []*share.CLUSSniffer {
	log.WithFields(log.Fields{"id": id}).Debug("")

	list := make([]*share.CLUSSniffer, 0)
	snifferMutex.RLock()
	proc, ok := snifferPidMap[id]
	snifferMutex.RUnlock()
	if ok {
		list = append(list, proc2Sniffer(proc, id))
	}
	return list
}

func listSniffer(cid string) []*share.CLUSSniffer {
	log.WithFields(log.Fields{"container": cid}).Debug("")

	list := make([]*share.CLUSSniffer, 0)

	snifferMutex.RLock()
	defer snifferMutex.RUnlock()
	for id, proc := range snifferPidMap {
		if cid != "" && proc.workload != cid {
			continue
		}
		list = append(list, proc2Sniffer(proc, id))
	}
	return list
}

func waitOnSniffer(key string, proc *procInfo) {
	if _, err := proc.cmd.Process.Wait(); err != nil {
		log.WithFields(log.Fields{"id": proc.workload, "key": key, "error": err}).Error("Failed to wait the sniffer finish")
		return
	}

	proc.status = snifferStopped
	proc.stopTime = time.Now().UTC().Unix()
	log.WithFields(log.Fields{"id": proc.workload, "key": key}).Debug("Sniffer stopped")
}

func startSniffer(info *share.CLUSSnifferRequest) (string, error) {
	var pid int

	if c, ok := gInfoReadActiveContainer(info.WorkloadID); ok {
		if c.hostMode {
			return "", status.Errorf(codes.InvalidArgument, "Container packet capture not supported")
		}

		pid = c.pid
		//NVSHAS-6635 and NVSHAS-6682,ep is parent whose pid could be zero
		if pid == 0 {
			for podID := range c.pods.Iter() {
				if pod, ok := gInfoReadActiveContainer(podID.(string)); ok {
					if pod.pid != 0 && pod.hasDatapath {
						pid = pod.pid
						break
					}
				}
			}
		}
		if pid == 0 {
			err := fmt.Errorf("Container pid zero")
			return "", status.Errorf(codes.InvalidArgument, "%s", err.Error())

		}
	} else {
		err := fmt.Errorf("Container cannot be found or not running")
		return "", status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	proc := &procInfo{
		workload:   info.WorkloadID,
		fileNumber: uint(info.FileNumber),
		duration:   uint(info.DurationInSecond),
	}

	key := generateSnifferID()

	proc.fileName, proc.args = parseArgs(info, key[:share.SnifferIdAgentField])
	_, err := startSnifferProc(key, proc, pid)
	if err != nil {
		return "", status.Errorf(codes.Internal, "%s", err.Error())
	} else {
		return key, nil
	}
}

func startSnifferProc(key string, proc *procInfo, pid int) (string, error) {
	log.WithFields(log.Fields{"key": key}).Debug()

	if _, err := os.Stat(defaultPcapDir); os.IsNotExist(err) {
		if err = os.MkdirAll(defaultPcapDir, 0775); err != nil {
			e := fmt.Errorf("Failed to make directory for sniffer")
			log.WithFields(log.Fields{"error": err, "dir": defaultPcapDir}).Error(e)
			return "", e
		}
	}

	snifferMutex.Lock()
	if p, ok := snifferPidMap[key]; ok {
		if p.status == snifferRunning {
			snifferMutex.Unlock()
			return "", fmt.Errorf("Duplicated sniffer key")
		}
		delete(snifferPidMap, key)
	}
	snifferMutex.Unlock()

	err := removePcapFiles(proc.fileNumber, proc.fileName)
	if err != nil {
		return "", err
	}

	var script string
	if proc.duration > 0 {
		script = fmt.Sprintf("timeout %d ", proc.duration)
	}
	script += "tcpdump " + strings.Join(proc.args, " ")
	log.WithFields(log.Fields{"key": key, "cmd": script}).Debug()

	proc.cmd = exec.Command(system.ExecNSTool, system.NSActRun, "-i", "-n", global.SYS.GetNetNamespacePath(pid))
	proc.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	proc.cmd.Stderr = &proc.errb
	stdin, err := proc.cmd.StdinPipe()
	if err != nil {
		e := fmt.Errorf("Open nsrun stdin error")
		log.WithFields(log.Fields{"error": err}).Error(e)
		return "", e
	}

	err = proc.cmd.Start()
	if err != nil {
		e := fmt.Errorf("Failed to start sniffer")
		log.WithFields(log.Fields{"error": err}).Error(e)
		return "", e
	}

	pgid := proc.cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, pid, "sniffer", script)
	if _, dbgError := io.WriteString(stdin, script); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	stdin.Close()

	time.Sleep(time.Millisecond * 300)
	var status string
	retry := 0
	for retry < 10 {
		status = global.SYS.GetLocalProcessStatus(proc.cmd.Process.Pid)
		if status == "R" || status == "S" {
			e := proc.errb.String()
			successStr := "listening on "
			if strings.Contains(e, successStr) {
				log.WithFields(log.Fields{"pid": proc.cmd.Process.Pid, "status": status}).Info("Start sniffer successfully")

				proc.status = snifferRunning
				proc.startTime = time.Now().UTC().Unix()

				snifferMutex.Lock()
				snifferPidMap[key] = proc
				snifferMutex.Unlock()

				go waitOnSniffer(key, proc)
				return status, nil
			}
		} else if status == "T" || status == "Z" {
			break
		}
		retry++
		time.Sleep(time.Millisecond * 100)
	}

	e := proc.errb.String()
	log.WithFields(log.Fields{"pid": proc.cmd.Process.Pid, "status": status}).Error(e)

	// in some cases, the error pipe message is out of order, we don't find the "listening on" in it's output.
	// but if the status are running or sleep, we still think it is success.
	if status == "R" || status == "S" {
		proc.status = snifferRunning
		proc.startTime = time.Now().UTC().Unix()

		snifferMutex.Lock()
		snifferPidMap[key] = proc
		snifferMutex.Unlock()

		go waitOnSniffer(key, proc)
		return status, nil
	}

	_, err = proc.cmd.Process.Wait()
	global.SYS.RemoveToolProcess(pgid, false)
	if err != nil {
		log.WithFields(log.Fields{"pid": proc.cmd.Process.Pid, "err": err}).Error("Failed to wait sniffer exit")
		return status, fmt.Errorf("Failed to wait sniffer exit")
	}
	failStr := ": No such device exists"
	if strings.Contains(e, failStr) {
		err = fmt.Errorf("Enforcer's interface is not ready")
	} else {
		err = fmt.Errorf("Failed to create sniffer")
	}
	return status, err
}

func stopSniffer(id string) error {
	log.WithFields(log.Fields{"id": id}).Debug("")

	snifferMutex.RLock()
	proc, ok := snifferPidMap[id]
	snifferMutex.RUnlock()
	if !ok {
		log.WithFields(log.Fields{"id": id}).Error("Sniffer not found")
		return status.Errorf(codes.NotFound, "Sniffer not found")
	}

	if proc.status == snifferStopped {
		return nil
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		log.WithFields(log.Fields{"id": id, "err": err}).Error("Failed to kill sniffer")
		return status.Errorf(codes.Internal, "%s", err.Error())
	}

	// waitOnSniffer will set the status
	return nil
}

func parseArgs(info *share.CLUSSnifferRequest, keyname string) (string, []string) {
	var cmdStr []string
	var filename, filenumber, filesize string
	var filter []string

	filename = defaultPcapDir + keyname + "_"
	filenumber = fmt.Sprintf("%d", info.FileNumber)
	filesize = fmt.Sprintf("%d", info.FileSizeInMB)

	if info.Filter != "" {
		filter = strings.Split(info.Filter, " ")
	}

	tcpdumpCmd := []string{"-i", "any", "-Z", "root", "-U", "-C"}
	cmdStr = append(tcpdumpCmd, filesize, "-w", filename, "-W", filenumber)
	if filter != nil {
		cmdStr = append(cmdStr, filter...)
	}
	return filename, cmdStr
}

func removeSniffer(id string) error {
	log.WithFields(log.Fields{"id": id}).Debug("")
	var err error

	snifferMutex.RLock()
	proc, ok := snifferPidMap[id]
	snifferMutex.RUnlock()
	if ok {
		if proc.status == snifferRunning {
			if dbgError := stopSniffer(id); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		if err = removePcapFiles(proc.fileNumber, proc.fileName); err != nil {
			return status.Errorf(codes.Internal, "%s", err.Error())
		}

		snifferMutex.Lock()
		delete(snifferPidMap, id)
		snifferMutex.Unlock()

		return nil
	} else {
		log.WithFields(log.Fields{"id": id}).Error("Sniffer not found")
		return status.Errorf(codes.NotFound, "Sniffer not found")
	}
}
