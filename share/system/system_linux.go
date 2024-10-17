package system

// #include <unistd.h>
import "C"

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"

	namespace "github.com/neuvector/neuvector/share/system/ns"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultHostProc string = "/proc/"
const mappedHostProc string = "/host/proc/"
const defaultHostCgroup string = "/sys/fs/cgroup/"
const mappedHostCgroup string = "/host/cgroup/"
const maxStatCmdLen = 15
const (
	ExecNSTool string = "/usr/local/bin/nstools"
	NSActGet   string = "get"
	NSActRun   string = "run"
	NSActExist string = "exist"
)

const nanoSecondsPerSecond = 1e9

var ErrFileTooBig = errors.New("File Size over limit")
var reSharedNetNS = regexp.MustCompile(`^/proc/\d+/ns/net$`)

type NSCallback func(params interface{})

type SystemTools struct {
	bEnable             bool
	info                sysinfo.SysInfo
	procDir             string
	cgroupDir           string
	clockTicksPerSecond uint64
	cgroupVersion       int
	cgroupMemoryDir     string
}

func getClockTicks() int {
	return int(C.sysconf(C._SC_CLK_TCK))
}

func getMountDirs() (string, string) {
	var err error
	var mountProcDir, mountCgroupDir string
	if _, err = os.Stat(mappedHostProc); err == nil {
		mountProcDir = mappedHostProc
	} else {
		mountProcDir = defaultHostProc
	}
	if _, err = os.Stat(mappedHostCgroup); err == nil {
		mountCgroupDir = mappedHostCgroup
	} else {
		mountCgroupDir = defaultHostCgroup
	}
	return mountProcDir, mountCgroupDir
}

func NewSystemTools() *SystemTools {
	procDir, cgroupDir := getMountDirs()

	s := &SystemTools{
		bEnable: true,
		procDir: procDir, cgroupDir: cgroupDir,
		clockTicksPerSecond: uint64(getClockTicks()),
	}

	s.info.SetRootPathPrefix(fmt.Sprintf("%s1/root/", procDir))
	s.info.GetSysInfo()

	// fill cgroup info
	// https://github.com/opencontainers/runc/blob/master/docs/cgroup-v2.md
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		s.cgroupVersion = cgroup_v2
		// update cgroup v2 path
		if path, err := getCgroupPath_cgroup_v2(0); err == nil {
			s.cgroupMemoryDir = path
		} else {
			s.cgroupMemoryDir = "/sys/fs/cgroup" // last resort
		}
	} else {
		s.cgroupVersion = cgroup_v1
		s.cgroupMemoryDir = "/sys/fs/cgroup/memory"
	}
	return s
}

func (s *SystemTools) GetCgroupsVersion() int {
	return s.cgroupVersion
}

func (s *SystemTools) GetSystemInfo() *sysinfo.SysInfo {
	return &s.info
}

func (s *SystemTools) GetProcDir() string {
	return s.procDir
}

func (s *SystemTools) CallNetNamespaceFunc(pid int, cb NSCallback, params interface{}) error {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	return s.CallNetNamespaceFuncWithoutLock(pid, cb, params)
}

func (s *SystemTools) CallNetNamespaceFuncWithoutLock(pid int, cb NSCallback, params interface{}) error {
	// Remember current NS
	cur_ns, err := netns.Get()
	if err != nil {
		log.WithFields(log.Fields{"pid": pid, "err": err}).Error("fail to get namespace handle")
		return err
	}
	defer cur_ns.Close()

	// Get namespace
	var ns netns.NsHandle
	netns_path := filepath.Join(s.procDir, strconv.Itoa(pid), "ns/net")
	if ns, err = netns.GetFromPath(netns_path); err != nil {
		log.WithFields(log.Fields{"pid": pid, "err": err}).Error("fail to get namespace")
		return err
	}
	defer ns.Close()

	// Switch to namespace
	log.WithFields(log.Fields{"ns": ns, "pid": pid}).Debug("Switch net ns")
	if err = netns.Set(ns); err != nil {
		log.WithFields(log.Fields{"pid": pid, "ns": ns, "err": err}).Error("fail to set namespace")
		return err
	}

	cb(params)

	log.WithFields(log.Fields{"cur_ns": cur_ns}).Debug("Restore net ns")
	if err = netns.Set(cur_ns); err != nil {
		log.WithFields(log.Fields{"pid": pid, "ns": ns, "err": err}).Error("fail to set namespace back")
	}

	return err
}

func (s *SystemTools) CallNamespaceFunc(nsid int, nstypes []string, cb NSCallback, params interface{}) error {
	var err error

	cur_ns := make([]*namespace.NsHandle, len(nstypes))
	new_ns := make([]*namespace.NsHandle, len(nstypes))

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	for i, ns := range nstypes {
		cur_ns[i], err = namespace.CurNsHandle(ns)
		if err != nil {
			log.WithFields(log.Fields{"namespace": ns, "error": err}).Error("Failed to store")
			return err
		}
		defer cur_ns[i].Close()
	}

	// Get new namespace
	for i, ns := range nstypes {
		new_ns[i], err = namespace.NewNsHandle(ns, s.procDir, nsid)
		if err != nil {
			log.WithFields(log.Fields{"namespace": ns, "error": err}).Error("Failed to open")
			return err
		}
		defer new_ns[i].Close()
	}

	// Switch to namespace
	for i, ns := range nstypes {
		if err = namespace.Set(new_ns[i]); err != nil {
			log.WithFields(log.Fields{"namespace": ns, "error": err}).Error("Failed to switch to")
			return err
		}
		defer func() {
			if err := namespace.Set(cur_ns[i]); err != nil {
				log.WithFields(log.Fields{"namespace": ns, "error": err}).Error("Failed to switch back")
			}
		}()

		log.WithFields(log.Fields{"namespace": ns, "pid": nsid}).Error("Switch to")
	}

	cb(params)

	return nil
}

func (s *SystemTools) GetHostname(pid int) string {
	var hostname string

	if err2 := s.CallNamespaceFunc(pid, []string{namespace.NSUTS}, func(params interface{}) {
		if data, err := os.ReadFile("/proc/sys/kernel/hostname"); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to read hostname")
		} else {
			hostname = strings.TrimSpace(string(data))
		}
	}, nil); err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("CallNamespaceFunc failed")
	}

	return hostname
}

func (s *SystemTools) GetHostRouteIfaceAddr(addr net.IP) (net.IP, error) {
	var ipnet *net.IPNet
	var err error

	err2 := s.CallNetNamespaceFunc(1, func(params interface{}) {
		_, ipnet, err = sk.GetRouteIfaceAddr(addr)
	}, nil)

	if err2 != nil {
		return nil, err2
	} else {
		if err != nil {
			return nil, err
		} else {
			return ipnet.IP, nil
		}
	}
}

func (s *SystemTools) GetBindAddr(addr net.IP) (string, *net.IPNet) {
	if addr == nil {
		return "", nil
	}

	// Use local routes to get bind address
	port, bind, err := sk.GetRouteIfaceAddr(addr)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get bind address")
		return "", nil
	}

	log.WithFields(log.Fields{"bind": bind}).Debug("")
	return port, bind
}

func (s *SystemTools) GetAdvertiseAddr(addr net.IP) net.IP {
	if addr == nil {
		return nil
	}

	routeAddr, routeErr := s.GetHostRouteIfaceAddr(addr)
	if routeErr != nil {
		log.WithFields(log.Fields{"error": routeErr}).Error("Failed to get advertise address")
		return nil
	}

	log.WithFields(log.Fields{"advertise": routeAddr}).Debug("")
	return routeAddr
}

func (s *SystemTools) GetGlobalAddrs(device_only bool) map[string][]net.IPNet {
	ifaces := sk.GetGlobalAddrs()

	log.WithFields(log.Fields{"device_only": device_only}).Debug("")

	ipnets := make(map[string][]net.IPNet)
	for name, iface := range ifaces {
		log.WithFields(log.Fields{"link": name, "type": iface.Type}).Debug("")

		if device_only && iface.Type != "device" {
			continue
		}

		for _, addr := range iface.Addrs {
			ipnets[name] = append(ipnets[name], addr.IPNet)
			log.WithFields(log.Fields{"link": name, "ipnet": addr.IPNet}).Debug("Add")
		}
	}

	return ipnets
}

func (s *SystemTools) GetLocalProcessStatus(pid int) string {
	filename := fmt.Sprintf("/proc/%v/stat", pid)
	dat, err := os.ReadFile(filename)
	if err != nil {
		return ""
	}
	sa := strings.Split(string(dat), " ")

	if len(sa) < 4 {
		return ""
	}
	return sa[2]
}

func (s *SystemTools) ReadCmdLine(pid int) ([]string, error) {
	var cmds []string

	file, err := os.Open(fmt.Sprintf("%s/%v/cmdline", s.procDir, pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// first line only
		cmds = strings.Split(string(scanner.Text()), "\x00")
		for i, t := range cmds { // it guarantees the tokens aren't pinning memory.
			cmds[i] = string([]byte(t))
		}
	}
	return cmds, nil
}

func (s *SystemTools) ParseNetNamespacePath(path string) int {
	if reSharedNetNS.MatchString(path) {
		slash := strings.Index(path[6:], "/")
		pid, err := strconv.Atoi(path[6 : 6+slash])
		if err == nil {
			return pid
		}
	}
	return 0
}

func (s *SystemTools) GetNetNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSNET, s.procDir, pid)
}

func (s *SystemTools) GetMountNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSMNT, s.procDir, pid)
}

func (s *SystemTools) GetUtsNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSUTS, s.procDir, pid)
}

func (s *SystemTools) GetIpcNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSIPC, s.procDir, pid)
}

func (s *SystemTools) GetUserNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSUSER, s.procDir, pid)
}

func (s *SystemTools) GetPidNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSPID, s.procDir, pid)
}

func (s *SystemTools) GetCgroupNamespacePath(pid int) string {
	return namespace.GetPathFromPid(namespace.NSCGROUP, s.procDir, pid)
}

func (s *SystemTools) GetMntNamespaceId(pid int) uint64 {
	if link, err := os.Readlink(namespace.GetPathFromPid(namespace.NSMNT, s.procDir, pid)); err == nil {
		a := strings.Index(link, "[")
		b := strings.LastIndex(link, "]")
		if a > 0 && b > 0 {
			if mntNs, err := strconv.ParseUint(link[a+1:b], 10, 64); err == nil {
				return mntNs
			}
		}
	}
	return 0
}

func (s *SystemTools) CheckHostProgram(prog string, pid int) ([]byte, error) {
	if !s.bEnable {
		return nil, fmt.Errorf("session ended")
	}

	args := []string{
		NSActExist,
		"-m", namespace.GetPathFromPid(namespace.NSMNT, s.procDir, pid),
		"-f", prog,
	}

	var errb, outb bytes.Buffer
	cmd := exec.Command(ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	s.AddToolProcess(pgid, pid, "check-host", prog)
	err = cmd.Wait()
	s.RemoveToolProcess(pgid, false)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Done")
		return nil, err
	}
	return outb.Bytes(), nil
}

func (s *SystemTools) GetHostCPUUsage() (uint64, error) {
	f, err := os.Open(filepath.Join(s.procDir, "stat"))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		switch parts[0] {
		case "cpu":
			if len(parts) < 8 {
				return 0, fmt.Errorf("Invalid number of cpu fields")
			}

			var totalClockTicks uint64
			for _, i := range parts[1:8] {
				v, err := strconv.ParseUint(i, 10, 64)
				if err != nil {
					return 0, fmt.Errorf("Unable to convert value %s to int: %s", i, err)
				}
				totalClockTicks += v
			}
			return (totalClockTicks * nanoSecondsPerSecond) / s.clockTicksPerSecond, nil
		}
	}

	return 0, fmt.Errorf("Invalid stat format")
}

// --

func (s *SystemTools) GetExitStatus(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok {
		return status.ExitStatus()
	}
	return 0
}

func (s *SystemTools) CheckProcExist(pid int) bool {
	procDir := fmt.Sprintf("%s/%v", s.procDir, pid)
	if _, err := os.Stat(procDir); err == nil {
		return true
	} else {
		return false
	}
}

// Only can change network namespace
func (s *SystemTools) NsRunBinary(pid int, path string) ([]byte, error) {
	if !s.bEnable {
		return nil, fmt.Errorf("session ended")
	}

	args := []string{NSActRun, "-f", "\"" + path + "\"", "-n", s.GetNetNamespacePath(pid), "-b"}
	var errb, outb bytes.Buffer

	log.WithFields(log.Fields{"args": args}).Debug("Call nsrun")
	cmd := exec.Command(ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	s.AddToolProcess(pgid, pid, "ns-run-binary", path)
	err = cmd.Wait()
	s.RemoveToolProcess(pgid, false)
	out := outb.Bytes()

	if err != nil || len(out) == 0 {
		if err == nil {
			err = fmt.Errorf("Error executing nsrun")
		}
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("")
		return nil, err
	}
	return out, nil
}

func (s *SystemTools) NsRunScript(pid int, scripts string) ([]byte, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		log.WithFields(log.Fields{"error": err, "pid": pid}).Error()
	}
	filename := filepath.Join(os.TempDir(), hex.EncodeToString(randBytes))
	if err := os.WriteFile(filename, []byte(scripts), 0644); err != nil {
		return nil, err
	}
	defer os.Remove(filename)

	return s.NsRunScriptFile(pid, filename)
}

func (s *SystemTools) NsRunScriptFile(pid int, path string) ([]byte, error) {
	if !s.bEnable {
		return nil, fmt.Errorf("session ended")
	}

	args := []string{NSActRun, "-f", path, "-m", s.GetMountNamespacePath(pid)}
	var errb, outb bytes.Buffer

	log.WithFields(log.Fields{"args": args}).Debug("Call nsrun")
	cmd := exec.Command(ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	s.AddToolProcess(pgid, pid, "ns-run-script", path)
	err = cmd.Wait()
	s.RemoveToolProcess(pgid, false)
	out := outb.Bytes()
	if err != nil || len(out) == 0 {
		if err == nil {
			err = fmt.Errorf("Error executing nsrun")
		}
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error()
		return nil, err
	}
	return out, nil
}

func (s *SystemTools) GetFilePath(pid int) (string, error) {
	filename := s.ContainerProcFilePath(pid, "/exe")
	path, err := os.Readlink(filename)
	if err != nil {
		//log.WithFields(log.Fields{"error": err}).Error("Open file link fail")
		return "", err
	} else {
		// Sometime we see a path like "/bin/busybox (deleted)"
		// need to return the path part in order to detect the fast process like echo
		path = strings.TrimSuffix(path, " (deleted)")
		return path, nil
	}
}

func (s *SystemTools) GetProcessName(pid int) (string, int, error) {
	var name string
	var ppid int
	filename := s.ContainerProcFilePath(pid, "/status")
	dat, err := os.ReadFile(filename)
	if err != nil {
		return "", 0, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:\t") {
			name = line[6:]
			if i := strings.IndexAny(name, "/: ;,"); i > 0 {
				name = name[:i]
			}
			//the max len of cmd name in /stat is 16(include \r). if it's 15, it's maybe a short cut name
			//if it is exe, it's a symlink, not a real one.
			if name == "exe" || len(name) == maxStatCmdLen {
				if cmds, err := s.ReadCmdLine(pid); err == nil && len(cmds) > 0 && cmds[0] != "" {
					name = filepath.Base(cmds[0])
				}
			}
		} else if strings.HasPrefix(line, "PPid:\t") {
			ppid, _ = strconv.Atoi(line[6:])
			return name, ppid, nil
		}
	}
	return "", 0, fmt.Errorf("Process name not found in status")
}

func (s *SystemTools) GetFileHash(pid int, path string) ([]byte, error) {
	data, err := s.ReadContainerFile(path, pid, 0, 0)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Get file hash fail")
		return nil, err
	} else {
		sha := sha256.Sum256(data)
		return sha[:], nil
	}
}

func (s *SystemTools) GetProcRootDir() string {
	return s.procDir
}

func (s *SystemTools) ContainerProcFilePath(pid int, path string) string {
	return fmt.Sprintf("%s%d%s", s.procDir, pid, path)
}

func (s *SystemTools) ParseContainerFilePath(path string) (int, string) {
	a := strings.Index(path, s.procDir)
	b := strings.Index(path, "/root/")
	if a < 0 || b < 0 {
		log.Error("Parse path fail")
		return 0, ""
	}
	str := path[a+len(s.procDir) : b]
	pid, _ := strconv.Atoi(str)
	return pid, path[b+5:]
}

func (s *SystemTools) ContainerFilePath(pid int, path string) string {
	return fmt.Sprintf("%s%d/root%s", s.procDir, pid, path)
}

func (s *SystemTools) IsNotContainerFile(pid int, path string) (bool, bool) {
	rpath := s.ContainerFilePath(pid, path)
	_, err := os.Stat(rpath)
	os.IsNotExist(err)
	return os.IsNotExist(err), utils.IsMountPoint(filepath.Dir(rpath))
}

func (s *SystemTools) ReadContainerFile(filePath string, pid, start, length int) ([]byte, error) {
	wholePath := s.ContainerFilePath(pid, filePath)

	if start == 0 && length == 0 {
		return os.ReadFile(wholePath)
	}

	f, err := os.Open(wholePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var n int
	// length cannot be 0, if start is not 0
	dat := make([]byte, length)
	if start >= 0 {
		_, err = f.Seek(int64(start), 0)
		if err != nil {
			return nil, err
		}
		n, err = f.Read(dat)
		if err != nil && err != io.EOF {
			return nil, err
		}
	} else {
		//start < 0, index from the end
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if fi.Size() > int64(len(dat)) {
			n, err = f.ReadAt(dat, fi.Size()-int64(len(dat)))
			if err != nil && err != io.EOF {
				return nil, err
			}
		} else {
			_, err = f.Seek(0, 0)
			if err != nil {
				return nil, err
			}
			n, err = f.Read(dat)
			if err != nil && err != io.EOF {
				return nil, err
			}
		}
	}
	return dat[:n], nil
}

func (s *SystemTools) IsOpenshift() (bool, error) {
	fd, err := os.Open(s.procDir)
	if err != nil {
		log.Error("Read process directory fail")
		return false, err
	}
	defer fd.Close()

	files, err := fd.Readdir(-1)
	if err != nil {
		return false, err
	}

	for _, file := range files {
		if file.IsDir() {
			pid, err := strconv.Atoi(file.Name())
			if err != nil {
				continue
			}

			// openshift 3.x
			if cmds, err := s.ReadCmdLine(pid); err == nil && len(cmds) > 3 {
				if filepath.Base(cmds[0]) == "openshift" && cmds[1] == "start" {
					return true, nil
				}
			}

			// openshift 4.x
			if exepath, err := s.GetFilePath(pid); err == nil && strings.HasSuffix(exepath, "/openshift-sdn") {
				log.Info("oc 4.x")
				return true, nil
			}
		}
	}

	return false, nil
}

// return true if file size over limit
func (s *SystemTools) NsGetFile(filePath string, pid int, binary bool, start, len int) ([]byte, error) {
	var errb bytes.Buffer
	args := []string{
		NSActGet,
		"-m", namespace.GetPathFromPid(namespace.NSMNT, s.procDir, pid),
		"-f", filePath,
	}
	if binary {
		args = append(args, "-b")
	}
	if start != 0 {
		args = append(args, "-s", fmt.Sprintf("%d", start))
	}
	if len > 0 {
		args = append(args, "-l", fmt.Sprintf("%d", len))
	}
	cmd := exec.Command(ExecNSTool, args...)
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("nsget return error")
		if ee, ok := err.(*exec.ExitError); ok {
			status := s.GetExitStatus(ee)
			if status == 2 {
				return nil, ErrFileTooBig
			}
		}
		return nil, err
	}
	if errb.Len() != 0 {
		log.WithFields(log.Fields{"err": errb.String()}).Error("nsget return error")
		return nil, errors.New(errb.String())
	}
	if binary {
		out, err = base64.StdEncoding.DecodeString(string(out))
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("base64 DecodeString fail")
			return nil, err
		}
	}
	return out, nil
}

func (s *SystemTools) DefaultShellCmd(pid int, shellCmd string) (bool, string, string) {
	if f, err := os.Open(s.ContainerFilePath(pid, "/etc/shells")); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if shellCmd == filepath.Base(line) {
				if fi, err := os.Lstat(s.ContainerFilePath(pid, line)); err == nil {
					if fi.Mode()&os.ModeSymlink != 0 {
						if originFile, err := os.Readlink(s.ContainerFilePath(pid, line)); err == nil {
							path := filepath.Clean(filepath.Join(filepath.Dir(line), originFile))
							//log.WithFields(log.Fields{"line": line, "path": path}).Debug()
							return true, filepath.Base(originFile), path
						}
					}
				}
				break
			}
		}
	}
	return false, "", ""
}
