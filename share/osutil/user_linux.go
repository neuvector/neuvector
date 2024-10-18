package osutil

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const UserUidMin int = 1000

func CheckUidAuthority(user string, pid int) (bool, error) {
	sudoGrp := utils.NewSet("adm", "sudo", "root")

	//dat, err := s.GetHostFile("/etc/sudoers", pid)
	//if err != nil {
	//	return false, err
	//}

	//scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	//for scanner.Scan() {
	//	line := scanner.Text()
	//	s := strings.TrimLeft(line, " ")
	//	s = strings.TrimRight(s, " ")
	//	if strings.HasPrefix(s, user) && strings.HasSuffix(s, "ALL") {
	//		return true, nil
	//	} else if strings.HasPrefix(s, "%") && strings.HasSuffix(s, "ALL") {
	//		if i := strings.IndexAny(s, " \t"); i > 2 {
	//			g := s[1:i]
	//			sudoGrp.Add(g)
	//		}
	//	}
	//}

	dat, err := global.SYS.ReadContainerFile("/etc/group", pid, 0, 0)
	if err != nil {
		return false, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, ":"); i > 1 {
			g := line[:i]
			if sudoGrp.Contains(g) {
				if i = strings.LastIndex(line, ":"); i > 0 {
					users := strings.Split(line[i+1:], ",")
					for _, u := range users {
						if u == user {
							return true, nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

// get the non-privileged user uid start value
func getUserStartUid(pid int) int {
	var uidStart int = UserUidMin
	dat, err := global.SYS.ReadContainerFile("/etc/login.defs", pid, 0, 0)
	if err != nil {
		//log.WithFields(log.Fields{"err": err, "pid": pid}).Debug("Get login.defs fail")
		return uidStart
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Replace(line, "\t", " ", -1)
		fields := strings.Split(line, " ")
		if len(fields) > 1 && strings.HasPrefix(fields[0], "UID_MIN") {
			for _, field := range fields[1:] {
				if uid, err := strconv.Atoi(field); err == nil {
					return uid
				}
			}
		}
	}
	return uidStart
}

// This is to enter process' mount namespace and get the passwd file.
func GetAllUsers(pid int, users map[int]string) (int, int, error) {
	uidStart := getUserStartUid(pid)

	dat, err := global.SYS.ReadContainerFile("/etc/passwd", pid, 0, 0)
	if err != nil {
		// log.WithFields(log.Fields{"err": err, "pid": pid}).Debug("Get /etc/passwd fail")
		return 0, uidStart, err
	}
	uidMap, err := getUserNsUid(pid)
	if err != nil {
		return 0, uidStart, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) > 5 {
			if id, err := strconv.Atoi(fields[2]); err == nil {
				users[id+uidMap] = fields[0]
			}
		}
	}
	return uidMap, uidStart, nil
}

func getUserNsUid(pid int) (int, error) {
	filename := global.SYS.ContainerProcFilePath(pid, "/uid_map")
	dat, err := os.ReadFile(filename)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "pid": pid}).Debug("Get uid_map fail")
		return -1, err
	}
	var base, uid int
	str := strings.TrimLeft(string(dat), " ")
	i := strings.Index(str, " ")
	if i <= 0 {
		log.WithFields(log.Fields{"err": err, "dat": string(dat)}).Debug("Get uid_map base fail")
		return -1, fmt.Errorf("Index uid_map base error")
	}
	if base, err = strconv.Atoi(str[:i]); err != nil {
		log.WithFields(log.Fields{"err": err, "dat": string(dat)}).Debug("Get strconv base fail")
		return -1, err
	}
	str = strings.TrimLeft(str[i+1:], " ")
	i = strings.Index(str, " ")
	if i <= 0 {
		log.WithFields(log.Fields{"err": err, "dat": string(dat)}).Debug("Get uid_map uid fail")
		return -1, fmt.Errorf("Index uid_map uid error")
	}
	if uid, err = strconv.Atoi(str[:i]); err != nil {
		log.WithFields(log.Fields{"err": err, "dat": string(dat)}).Debug("Get strconv uid fail")
		return -1, err
	}

	return (uid - base), nil
}

// This is to enter process' mount namespace and get the passwd file.
/*
func GetLinuxUserName(ruid, euid int, pid int) (string, string, error) {
	var ruser, euser string

	dat, err := global.SYS.ReadContainerFile("/etc/passwd", pid, 0, 0)
	if err != nil {
		return "", "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) > 5 {
			id, _ := strconv.Atoi(fields[2])
			if id == ruid {
				ruser = fields[0]
			}
			if id == euid {
				euser = fields[0]
			}
			if ruser != "" && euser != "" {
				break
			}
		}
	}
	return ruser, euser, nil
}
*/
