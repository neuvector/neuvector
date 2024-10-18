package osutil

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
	"golang.org/x/sys/unix"
)

const maxStatCmdLen = 15

type Connection struct {
	LocIP    net.IP
	RemIP    net.IP
	LocPort  uint16
	RemPort  uint16
	Ether    uint16
	Protocol uint8
}

var procStatusMap map[string]string = map[string]string{
	"R": "Running",
	"S": "Sleeping",
	"D": "Waiting",
	"Z": "Zombie",
	"T": "Stopped",
	"t": "Tracing",
	"X": "Dead",
	"x": "Dead",
	"K": "Wakekill",
	"W": "Waking",
	"P": "Parked",
}

type SocketInfo struct {
	IPProto uint8
	Port    uint16
	INode   uint32
}

// Get ppid, group and session id from /proc/<pid>/stat
// Error if ppid is -1
func GetProcessPIDs(pid int) (ppid, gid, sid int, status, cmd string) {
	ppid = -1
	filename := global.SYS.ContainerProcFilePath(pid, "/stat")
	dat, err := os.ReadFile(filename)
	if err != nil {
		// log.WithFields(log.Fields{"error": err, "file": filename}).Error("")
		return
	}
	sa := strings.Split(string(dat), " ")

	if len(sa) < 4 {
		return
	}

	cmd = strings.Trim(sa[1], "()")
	if i := strings.IndexAny(cmd, "/: ;,"); i > 0 {
		cmd = cmd[:i]
	}
	// second field is the command
	size := len(sa[1])
	if sa[1] == "" || sa[1][0] != '(' || sa[1][size-1] != ')' {
		return
	}

	status = procStatusMap[sa[2]]
	ppid, _ = strconv.Atoi(sa[3])

	if len(sa) < 5 {
		return
	}

	gid, _ = strconv.Atoi(sa[4])
	sid, _ = strconv.Atoi(sa[5])
	return
}

func GetAllProcesses() utils.Set {
	pids := utils.NewSet()

	d, err := os.Open(global.SYS.GetProcRootDir())
	if err != nil {
		return pids
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return pids
	}

	// get all the process
	for _, file := range files {
		if file.IsDir() {
			pid, err := strconv.Atoi(file.Name())
			if err != nil {
				continue
			}
			pids.Add(pid)
		}
	}

	return pids
}

func GetProcessSocketInodes(pid int) (utils.Set, error) {
	fdDir := global.SYS.ContainerProcFilePath(pid, "/fd")

	d, err := os.Open(fdDir)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return nil, err
	}

	inodes := utils.NewSet()

	for _, file := range files {
		mode := uint32((file.Mode() & os.ModeSymlink))
		if mode == uint32(os.ModeSymlink) {
			fl, err := os.Readlink(fdDir + "/" + file.Name())
			if err != nil {
				continue
			}

			if strings.HasPrefix(fl, "socket:[") {
				if inode, err := getSocketInode(fl); err == nil {
					inodes.Add(uint32(inode))
				}
			}
		}
	}

	return inodes, nil
}

/*
func getListenPortsByFile(listens utils.Set, fileName string, inodes utils.Set, tcp bool) {
	f, err := os.Open(fileName)
	if err != nil {
		//log.WithFields(log.Fields{"error": err}).Error("open net/tcp,udp")
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// skip the first line
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()

		splits := strings.Split(strings.TrimSpace(line), " ")

		// remove empty tokens
		var tokens []string
		for _, s := range splits {
			if s != "" {
				tokens = append(tokens, s)
			}
		}

		if tokens == nil || len(tokens) < 9 {
			continue
		}

		// State is Listen
		if (tcp && tokens[3] == "0A") || (!tcp && tokens[3] == "07") {
			inode, _ := strconv.ParseUint(tokens[9], 10, 32)
			if inodes.Contains(uint32(inode)) {
				ip_port := strings.Split(tokens[1], ":")
				port, _ := strconv.ParseUint(ip_port[1], 16, 16)
				if tcp {
					listens.Add(share.CLUSProtoPort{
						Port: uint16(port), IPProto: syscall.IPPROTO_TCP,
					})
				} else {
					listens.Add(share.CLUSProtoPort{
						Port: uint16(port), IPProto: syscall.IPPROTO_UDP,
					})
				}
			}
		}
	}
}
*/

func getCGroupSocketTable(rootPid int, tbl map[uint32]SocketInfo, file string, tcp bool) {
	fileName := filepath.Join("/proc", strconv.Itoa(rootPid), "root/proc/1/net", file)
	// log.WithFields(log.Fields{"filename": fileName}).Debug()
	f, err := os.Open(fileName)
	if err != nil {
		// Suppresss the log message
		// log.WithFields(log.Fields{"error": err, "filename": filename}).Error()
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// skip the first line
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()

		splits := strings.Split(strings.TrimSpace(line), " ")

		// remove empty tokens
		var tokens []string
		for _, s := range splits {
			if s != "" {
				tokens = append(tokens, s)
			}
		}

		if tokens == nil || len(tokens) < 9 {
			continue
		}

		// TCP: TCP_LISTEN, UDP: TCP_CLOSE (idle)
		if (tcp && tokens[3] == "0A") || (!tcp && tokens[3] == "07") {
			fd, _ := strconv.ParseUint(tokens[9], 10, 32)
			inode := uint32(fd)
			ip_port := strings.Split(tokens[1], ":")
			port, _ := strconv.ParseUint(ip_port[1], 16, 16)
			if tcp {
				tbl[inode] = SocketInfo{Port: uint16(port), IPProto: syscall.IPPROTO_TCP, INode: inode}
			} else {
				tbl[inode] = SocketInfo{Port: uint16(port), IPProto: syscall.IPPROTO_UDP, INode: inode}
			}
		}
	}
}

// Container's socket tables are located at /proc/[rootPid]/root/proc/1/net/
// inode is unique and handle either only one service
func GetContainerSocketTable(rootPid int) map[uint32]SocketInfo {
	tbl := make(map[uint32]SocketInfo, 0)
	getCGroupSocketTable(rootPid, tbl, "tcp", true)
	getCGroupSocketTable(rootPid, tbl, "tcp6", true)
	getCGroupSocketTable(rootPid, tbl, "udp", false)
	getCGroupSocketTable(rootPid, tbl, "udp6", false)

	//	log.WithFields(log.Fields{"rootPid": rootPid, "tbl": len(tbl)}).Debug()
	//	for inode, pport := range tbl {
	//		log.WithFields(log.Fields{"inode": inode, "pport": pport}).Debug()
	//	}
	return tbl
}

func getConnectionByFile(fileName string, inodes utils.Set, tcp bool, sport uint16) *Connection {
	f, err := os.Open(fileName)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("open net/tcp,udp")
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// skip the first line
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()

		splits := strings.Split(strings.TrimSpace(line), " ")

		// remove empty tokens
		var tokens []string
		for _, s := range splits {
			if s != "" {
				tokens = append(tokens, s)
			}
		}

		if tokens == nil || len(tokens) < 9 {
			continue
		}

		// State is Established
		//not to check the state of connection, report no matter any state
		//exclude listen state
		inode, _ := strconv.ParseUint(tokens[9], 10, 32)
		if inodes.Contains(uint32(inode)) {
			var locIp, remIp []byte
			var locPort, remPort uint64
			var err error
			//local ip and port
			ip_port := strings.Split(tokens[1], ":")
			if len(ip_port) < 2 {
				continue
			}
			if locIp, err = hex.DecodeString(ip_port[0]); err != nil {
				continue
			}
			if locPort, err = strconv.ParseUint(ip_port[1], 16, 16); err != nil {
				continue
			}

			//remote ip and port
			if ip_port = strings.Split(tokens[2], ":"); len(ip_port) < 2 {
				continue
			}
			if remIp, err = hex.DecodeString(ip_port[0]); err != nil {
				continue
			}
			if remPort, err = strconv.ParseUint(ip_port[1], 16, 16); err != nil {
				continue
			}
			if sport != 0 && uint16(locPort) != sport {
				continue
			}

			conn := &Connection{
				// TODO: maybe it's related to byte order
				LocIP:   net.IP(utils.ReverseBytesInPlace(locIp)),
				RemIP:   net.IP(utils.ReverseBytesInPlace(remIp)),
				LocPort: uint16(locPort),
				RemPort: uint16(remPort),
			}
			if tcp {
				//skip local loopback and listened connection
				listened := (tcp && tokens[3] == "0A")
				if conn.RemIP.IsLoopback() || listened {
					continue
				}
				conn.Protocol = syscall.IPPROTO_TCP
			} else {
				conn.Protocol = syscall.IPPROTO_UDP
			}
			if utils.IsIPv4(conn.LocIP) {
				conn.Ether = syscall.ETH_P_IP
			} else {
				conn.Ether = syscall.ETH_P_IPV6
			}
			return conn
		}
	}
	return nil
}

func GetProcessConnection(pid int, clientPort *share.CLUSProtoPort, inodes utils.Set) *Connection {
	var err error
	if inodes == nil {
		inodes, err = GetProcessSocketInodes(pid)
		if err != nil {
			return nil
		}
	}
	if inodes.Cardinality() == 0 {
		return nil
	}
	var sport uint16
	if clientPort != nil {
		sport = clientPort.Port
	}
	pidDir := global.SYS.ContainerProcFilePath(pid, "/")
	if clientPort == nil || clientPort.IPProto == syscall.IPPROTO_TCP {
		if conn := getConnectionByFile(pidDir+"net/tcp", inodes, true, sport); conn != nil {
			return conn
		}
		if conn := getConnectionByFile(pidDir+"net/tcp6", inodes, true, sport); conn != nil {
			return conn
		}
	}
	if clientPort == nil || clientPort.IPProto == syscall.IPPROTO_UDP {
		if conn := getConnectionByFile(pidDir+"net/udp", inodes, false, sport); conn != nil {
			return conn
		}
		if conn := getConnectionByFile(pidDir+"net/udp6", inodes, false, sport); conn != nil {
			return conn
		}
	}
	return nil
}

// Get the process parent id and uid from /proc/<pid>/status
// Error if ppid is -1
func GetProcessUIDs(pid int) (name string, ppid, ruid, euid int) {
	ppid = -1
	filename := global.SYS.ContainerProcFilePath(pid, "/status")
	dat, err := os.ReadFile(filename)
	if err != nil {
		// No log here, too many error when called by escalation eval.
		// log.WithFields(log.Fields{"error": err, "file": filename}).Error("")
		return
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
				if cmds, err := global.SYS.ReadCmdLine(pid); err == nil && len(cmds) > 0 && cmds[0] != "" {
					name = filepath.Base(cmds[0])
				}
			}

			name = filepath.Base(name)
			if i := strings.IndexAny(name, "/: ;,"); i > 0 {
				name = name[:i]
			}
			if name == "exe" {
				//make sure the process name not be "exe". it's a temparary one
				name = ""
			}
		} else if strings.HasPrefix(line, "PPid:\t") {
			ppid, _ = strconv.Atoi(line[6:])
		} else if strings.HasPrefix(line, "Uid:\t") {
			uids := strings.Split(line[5:], "\t")
			if len(uids) == 4 {
				ruid, _ = strconv.Atoi(uids[0])
				euid, _ = strconv.Atoi(uids[1])
			}
			break
		}
	}
	return
}

func CheckProcessOpenDevTun(pid int) (bool, string) {
	fdDir := global.SYS.ContainerProcFilePath(pid, "/fd")

	d, err := os.Open(fdDir)
	if err != nil {
		return false, ""
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return false, ""
	}

	for _, file := range files {
		mode := uint32((file.Mode() & os.ModeSymlink))
		if mode == uint32(os.ModeSymlink) {
			fl, err := os.Readlink(fdDir + "/" + file.Name())
			if err != nil {
				continue
			}

			if strings.HasPrefix(fl, "/dev/net/tun") ||
				strings.HasPrefix(fl, "/dev/net/tap") {
				return true, fl
			}
		}
	}

	return false, ""
}

func getSocketInode(name string) (uint32, error) {
	a := strings.Index(name, "[")
	b := strings.LastIndex(name, "]")
	if inode, err := strconv.ParseUint(name[a+1:b], 10, 32); err != nil {
		return 0, err
	} else {
		return uint32(inode), nil
	}
}

func GetFDSocketInode(pid int, fd int) (uint32, error) {
	fdDir := global.SYS.ContainerProcFilePath(pid, "/fd")

	f, err := os.Readlink(fmt.Sprintf("%s/%d", fdDir, fd))
	if err != nil {
		return 0, err
	}

	if !strings.HasPrefix(f, "socket") {
		return 0, nil
	}

	if inode, err := getSocketInode(f); err != nil {
		return 0, err
	} else {
		return inode, nil
	}
}

func GetContainerDaemonArgs() ([]string, error) {
	fd, err := os.Open(global.SYS.GetProcRootDir())
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	files, err := fd.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			pid, err := strconv.Atoi(file.Name())
			if err != nil {
				continue
			}
			if cmds, err := global.SYS.ReadCmdLine(pid); err == nil && len(cmds) > 0 {
				if global.RT.IsDaemonProcess(filepath.Base(cmds[0]), cmds) {
					return cmds[1:], nil
				}
			}
		}
	}

	return nil, fmt.Errorf("Docker Daemon not found")
}

func GetProcessName(pid int) string {
	var name string
	if path, err := GetExePathFromLink(pid); err == nil {
		name = filepath.Base(path)
	} else {
		name, _, _, _ = GetProcessUIDs(pid)
	}
	return name
}

func GetSessionId(pid int) int {
	sid, err := unix.Getsid(pid)
	if err != nil {
		//	log.WithFields(log.Fields{"error": err, "pid": pid}).Error("PROC:")  // process might be gone already: no such process
		sid = 0 //
	}
	return sid
}

func IsPidValid(pid int) bool {
	_, err := os.Stat(global.SYS.ContainerProcFilePath(pid, ""))
	return err == nil
}

func GetProcessGroupId(pid int) int {
	pgid, err := unix.Getpgid(pid)
	if err != nil {
		//	log.WithFields(log.Fields{"error": err, "pid": pid}).Error("PROC:")  // process might be gone already: no such process
		pgid = 0 //
	}
	return pgid
}
