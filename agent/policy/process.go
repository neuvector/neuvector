package policy

// #include "../../defs.h"
import "C"

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type ProcProfileBrief struct {
	name string
	path string
}

type procGrpRef struct {
	name    string
	path    string
	service string
	id      string
	ppid    int
}

// allowed parent scripts
var permitProcessGrp map[int]*procGrpRef = make(map[int]*procGrpRef)
var k8sGrpProbe utils.Set = utils.NewSet()

func (e *Engine) UpdateProcessPolicy(name string, profile *share.CLUSProcessProfile) (bool, *share.CLUSProcessProfile) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	exist, ok := e.ProcessPolicy[name]
	if !ok || !reflect.DeepEqual(exist, profile) {
		e.ProcessPolicy[name] = profile
		for _, p := range profile.Process {
			if len(p.ProbeCmds) > 0 {
				k8sGrpProbe.Add(name) // set the flag
				break
			}
		}
		return true, exist
	} else {
		return false, exist
	}
}

func (e *Engine) ObtainProcessPolicy(name, id string) (*share.CLUSProcessProfile, bool) {
	e.Mutex.Lock()
	profile, _ := e.ProcessPolicy[name]
	e.Mutex.Unlock()
	if profile != nil { // the process policy per group has been fetched
		if grp_profile, ok := e.getGroupRule(id); ok {
			if grp_profile == nil { // neuvector pods only
				return profile, true
			}
			grp_profile.Baseline = profile.Baseline // following original profile
			if grp_profile.Mode == "" {
				grp_profile.Mode = profile.Mode // update
			} else if grp_profile.Mode != profile.Mode {
				// Detected: incomplete profile calculation, conflicts by timing
				// The new profile has not been calculated (it could be 5 seconds later) yet.
				// Just following the old group profile. it will be updated eventually.
				log.WithFields(log.Fields{"name": name, "latest-mode": profile.Mode, "group-mode": grp_profile.Mode}).Debug("GRP: ")
			}
			return grp_profile, true
		}
	}

	// log.WithFields(log.Fields{"name": name}).Debug("GRP: process profile not ready")
	return nil, false
}

func (e *Engine) IsK8sGroupWithProbe(name string) bool {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	return k8sGrpProbe.Contains(name)
}

func (e *Engine) DeleteProcessPolicy(name string) {
	e.Mutex.Lock()
	delete(e.ProcessPolicy, name)
	k8sGrpProbe.Remove(name)
	log.WithFields(log.Fields{"name": name}).Debug("PROC: ")
	e.Mutex.Unlock()
}

func defaultProcessAction(mode string) string {
	switch mode {
	case share.PolicyModeLearn:
		return share.PolicyActionLearn
	case share.PolicyModeEvaluate:
		return share.PolicyActionViolate
	case share.PolicyModeEnforce:
		return share.PolicyActionDeny
	}
	return share.PolicyActionViolate
}

func MatchProfileProcess(entry *share.CLUSProcessProfileEntry, proc *share.CLUSProcessProfileEntry) bool {
	// matching the major criteria: executable path
	// all accepted:
	if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {
		return true
	}

	// application matching
	i := strings.LastIndex(proc.Path, "/")
	if i < 0 {
		log.WithFields(log.Fields{"exepath": proc.Path}).Debug("PROC: invalid path")
		return false
	}

	//
	dir := proc.Path[0:i]
	bin := proc.Path[i+1:]
	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "exepath": proc.Path, "exebin": bin, "exedir": dir}).Debug("PROC: ")
	if bin == entry.Name {
		if entry.Path == "*" || entry.Path == "" || entry.Path == "/*" {
			return true // match all
		} else if strings.HasSuffix(entry.Path, "/*") && entry.Name != "*" { // recursive match
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		}
	}

	// wildcard name
	if entry.Name == "*" {
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		} else if len(entry.ProbeCmds) > 0 { // probe shell commands
			return bin == entry.Path
		} else { // on a spefific file
			return proc.Path == entry.Path
		}
	} else { // recursive directory ( *, /bin/*, and /usr/*/nginx)
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			return strings.HasPrefix(dir, path) && (entry.Name == proc.Name)
		} else if index := strings.Index(entry.Path, "/*/"); index > -1 {
			return strings.HasPrefix(dir, entry.Path[:index]) && (entry.Name == proc.Name) && (bin == filepath.Base(entry.Path))
		}
	}

	// regular cases
	if entry.Path != "" && entry.Path != "*" && entry.Path != "/*" {
		if proc.Path != entry.Path {
			return false
		}
	}

	// cases for busybox and others
	if proc.Name != entry.Name {
		return false
	}

	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "execPath": proc.Path, "execnName": proc.Name}).Debug("PROC: matched")
	return true
}

func (e *Engine) ProcessPolicyLookup(name, id string, proc *share.CLUSProcessProfileEntry, pid int) (string, string, string, error) {
	group := name // service group
	profile, ok := e.ObtainProcessPolicy(name, id)
	if ok {
		var matchedEntry *share.CLUSProcessProfileEntry
		for _, p := range profile.Process {
			if profile.Mode == share.PolicyModeLearn && len(p.ProbeCmds) > 0 {
				//	if p.Name == "sh" && p.Path == "*" {		// replace
				//		if ok, app, _ := global.SYS.DefaultShellCmd(pid, "sh"); ok {
				//			p.Name = "*"
				//			p.Path = app
				//		}
				//	}
				continue // trigger a learning event
			}

			if MatchProfileProcess(p, proc) {
				matchedEntry = p
				proc.Action = p.Action
				proc.AllowFileUpdate = p.AllowFileUpdate
				proc.ProbeCmds = p.ProbeCmds
				proc.CfgType = p.CfgType
				break
			}
		}

		if matchedEntry != nil {
			proc.Uuid = matchedEntry.Uuid
			if matchedEntry.DerivedGroup != "" { // "" : internal reference for service group
				group = matchedEntry.DerivedGroup
			}
			if proc.Action == share.PolicyActionAllow {
				if profile.HashEnable {
					hash, _ := global.SYS.GetFileHash(pid, proc.Path)
					if hash != nil {
						if len(matchedEntry.Hash) == 0 {
							log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: update hash")
							matchedEntry.Hash = hash
							proc.Action = share.PolicyActionLearn
						} else if string(matchedEntry.Hash) != string(hash) {
							log.WithFields(log.Fields{"group": name, "path": proc.Path, "rec": matchedEntry.Hash, "hash": hash}).Debug("PROC: mismatched hash")
							proc.Action = share.PolicyActionViolate
						}
					} else {
						log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: hash failed")
					}
				}

				// discovery mode and from a group rule
				// after re-calculated at group_profile, the service rules(updated at last) will become its derived_group ""
				// log.WithFields(log.Fields{"mode": profile.Mode, "name": name, "proc": proc, "group": group}).Debug("PROC: ")
				if profile.Mode == share.PolicyModeLearn && group != name {
					e.Mutex.Lock()
					prf, _ := e.ProcessPolicy[name]
					e.Mutex.Unlock()
					found := false
					for _, p := range prf.Process {
						if MatchProfileProcess(p, proc) {
							found = true
							break
						}
					}

					if !found {
						//	log.WithFields(log.Fields{"name": name, "proc": proc}).Debug("PROC: learnt")
						proc.Action = share.PolicyActionLearn
					}
				}
			} else { // deny decision
				// update deny decision in two other modes
				if profile.Mode != share.PolicyModeEnforce {
					proc.Action = share.PolicyActionViolate
				}
			}
		} else {
			if profile.Baseline == share.ProfileBasic || !e.IsK8sGroupWithProbe(name) {
				//not found in profile
				act := defaultProcessAction(profile.Mode)
				proc.Action = act
				proc.Uuid = share.CLUSReservedUuidNotAlllowed
			}
		}
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("")
	} else {
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("Profile not found")
		return "", "", "", errors.New("Profile not found")
	}
	return profile.Mode, profile.Baseline, group, nil
}

// matching the process name: suspicious process is defined by name only
func (e *Engine) IsAllowedSuspiciousApp(service, id, name string) bool {
	profile, ok := e.ObtainProcessPolicy(service, id)
	if ok {
		for _, entry := range profile.Process {
			// all accepted:
			if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {
				return true
			}

			if name == entry.Name {
				return true
			}
		}
	}
	return false
}

// allowed by parent process name
// The program logic is located at faccess_linux.go: isAllowedByParentApp()
func (e *Engine) IsAllowedByParentApp(service, id, name, pname, ppath string, pgid int) bool {
	var allowed bool

	profile, ok := e.ObtainProcessPolicy(service, id)
	if ok {
		if procGrp, ok := permitProcessGrp[pgid]; ok {
			ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
			// log.WithFields(log.Fields{"pgid": pgid, "ppid": ppid, "procGrp": procGrp}).Debug("exist")
			if procGrp.id != id || ppid != procGrp.ppid {
				// invalid match, reset record
				delete(permitProcessGrp, pgid)
				procGrp = nil
			} else {
				return true
			}
		}

		for _, entry := range profile.Process {
			if entry.Action == share.PolicyActionAllow && strings.HasSuffix(entry.Name, "/*") {
				n := strings.TrimSuffix(entry.Name, "/*")
				if pname == n || name == n { // allowed parent name (including itself)
					if entry.Path == "" || entry.Path == "*" || entry.Path == "/*" {
						allowed = true
					}

					if !allowed && strings.HasSuffix(entry.Path, "/*") {
						p := strings.TrimSuffix(entry.Path, "/*")
						allowed = strings.HasPrefix(ppath, p)
					}

					if !allowed {
						allowed = entry.Path == ppath
					}
				}

				if allowed {
					ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
					tagRef := &procGrpRef{name: n, path: entry.Path, service: service, id: id, ppid: ppid}
					permitProcessGrp[pgid] = tagRef
					log.WithFields(log.Fields{"pgid": pgid, "ppath": ppath, "tagRef": tagRef}).Debug()
					break
				}
			}
		}
	}
	return allowed
}

/////////////////////////////////////////////////////////////////////
func buildCustomizedProfile(serviceGroup, mode string, whtLst, blackLst []ProcProfileBrief) *share.CLUSProcessProfile {
	profile := &share.CLUSProcessProfile{
		Group:        serviceGroup,
		Baseline:     share.ProfileZeroDrift,
		AlertDisable: false,
		HashEnable:   false,
		Mode:         mode,
	}

	// white list
	for _, ppw := range whtLst {
		wht := &share.CLUSProcessProfileEntry{
			Name:      ppw.name,
			Path:      ppw.path,
			Action:    share.PolicyActionAllow, // white list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, wht)
	}

	// black list
	for _, ppb := range blackLst {
		blk := &share.CLUSProcessProfileEntry{
			Name:      ppb.name,
			Path:      ppb.path,
			Action:    share.PolicyActionDeny, // black list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, blk)
	}
	return profile
}

/////////////////////////////////////////////////////////////////////
func buildAllowAllProfile(serviceGroup string) *share.CLUSProcessProfile {
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		{"*", "*"},
	}
	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildNotAllowedProfile(serviceGroup string) *share.CLUSProcessProfile {
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		{"abcdefg", "ab556677"}, // unexpected item
	}
	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildManagerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: manager")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// python
		{"support", "*"},          // support
		{"cli", "*"},              // cli
		{"python", "/usr/bin/*"},  // cli
		{"*", "/usr/lib64/jvm/*"}, // JVM

		// tools
		{"ps", "*"},
		{"bash", "/usr/bin/bash"},
		{"uname", "/usr/bin/uname"}, // cli
		{"echo", "/usr/bin"},

		// below entries for debug purpose
		{"ip", "/sbin/ip"},
		{"tee", "/usr/bin/tee"},
		{"stty", "/usr/bin/stty"}, // python

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildScannerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: scanner")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		{"monitor", "/usr/local/bin/monitor"},
		{"scanner", "/usr/local/bin/scanner"},
		{"scannerTask", "/usr/local/bin/scannerTask"},
		{"sigstore-interface", "/usr/local/bin/sigstore-interface"},

		// tools
		{"ps", "*"},
		{"bash", "/usr/bin/bash"},

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

func buildCspProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: csp")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		{"csp-billing-ada", "*"},
		{"ldconfig", "/sbin/ldconfig"},
		{"python3", "/usr/bin/*"},
		{"uname", "/usr/bin/uname"},

		// tools
		{"ps", "*"},
		{"bash", "/usr/bin/bash"},

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

func buildRegistryAdapterProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: registry adapter")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		{"adapter", "/usr/local/bin/adapter"},

		// tools
		{"ps", "*"},
		{"bash", "/usr/bin/bash"},

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildControllerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: controller")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// /usr/local/bin
		{"consul", "*"}, // monitor also calls it through a shell command
		{"controller", "/usr/local/bin/controller"},
		{"monitor", "/usr/local/bin/monitor"},
		{"opa", "/usr/local/bin/opa"},

		// tools
		{"tcpdump", "/usr/sbin/tcpdump"},
		{"getconf", "/usr/bin/getconf"}, // get configuration values
		{"getent", "/usr/bin/getent"},   // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},     // convert encoding of given files from one encoding to another
		{"ps", "*"},
		{"cat", "*"}, // k8s readiness
		{"busybox", "/bin/busybox"}, // k8s readiness: backward compatible

		// bash
		{"bash", "/usr/bin/bash"},
		{"mv", "/usr/bin/mv"},
		{"ss", "/usr/sbin/ss"},
		{"nproc", "/usr/bin/nproc"}, // dp
		{"touch", "/usr/bin/touch"}, // detect container layer on the AUFS
		{"uname", "/usr/bin/uname"},
		{"grep", "/usr/bin/grep"},
		{"awk", "/usr/bin/gawk"},
		{"stty", "/usr/bin/stty"}, // python

		{"configure.sh", "*"}, // monitor tool
		{"teardown.sh", "*"},  // monitor tool
		{"netstat", "*"},      // monitor   <====== NOT
		{"kill", "*"},

		// below entries for debug purpose:
		{"ip", "/usr/sbin/ip"},

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildEnforcerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: enforcer")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// /usr/local/bin
		{"agent", "/usr/local/bin/agent"},
		{"consul", "*"}, // monitor also calls it through a shell command
		{"dp", "/usr/local/bin/dp"},
		{"monitor", "/usr/local/bin/monitor"},
		{"nstools", "/usr/local/bin/nstools"},
		{"pathWalker", "/usr/local/bin/pathWalker"},

		// tools
		{"tcpdump", "/usr/sbin/tcpdump"},
		{"ethtool", "/usr/sbin/ethtool"},        // network hardware setting
		{"tc", "/sbin/tc"},                      // traffic control
		{"modinfo", "/sbin/modinfo"},            // monitor tool: configure.sh
		{"getconf", "/usr/lib/getconf/getconf"}, // get configuration values
		{"getent", "/usr/bin/getent"},           // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},             // convert encoding of given files from one encoding to another
		{"curl", "/usr/bin/curl"},               // cis benchmark
		{"jq", "/usr/bin/jq"},                   // cis benchmark
		{"timeout", "/usr/bin/timeout"},         // could be used by tcpdump
		{"ps", "*"},

		// bash
		{"bash", "/usr/bin/bash"}, // below busybox and its symbolic links
		{"mv", "/usr/bin/mv"},
		{"ss", "/usr/sbin/ss"},
		{"nproc", "/usr/bin/nproc"}, // dp
		{"touch", "/usr/bin/touch"}, // detect container layer on the AUFS
		{"uname", "/usr/bin/uname"},
		{"grep", "/usr/bin/grep"},
		{"awk", "/usr/bin/gawk"},
		{"find", "/usr/bin/find"},
		{"sed", "/usr/bin/sed"},
		{"stty", "/usr/bin/stty"}, // python

		{"configure.sh", "*"}, // monitor tool
		{"teardown.sh", "*"},  // monitor tool
		{"kill", "*"},

		// below entries for debug purpose
		{"ip", "/usr/sbin/ip"},
		{"iptables", "/usr/sbin/xtables-legacy-multi"},      // dp
		{"iptables-save", "/usr/sbin/xtables-legacy-multi"}, // dp

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildAllinOneProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: allInOne")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// python: python2.7 or python3.8
		{"python", "/usr/bin/*"},      // runtime-gdb.py
		{"supervisord", "/usr/bin/*"}, // start-up
		{"support", "*"},              // support
		{"cli", "*"},                  // cli: python312

		// manager cores :  wildcard
		{"*", "/usr/lib64/jvm/*"}, // JVM

		// /usr/local/bin
		{"agent", "/usr/local/bin/agent"},
		{"consul", "*"}, // monitor also calls it through a shell command
		{"controller", "/usr/local/bin/controller"},
		{"dp", "/usr/local/bin/dp"},
		{"monitor", "/usr/local/bin/monitor"},
		{"nstools", "/usr/local/bin/nstools"},
		{"opa", "/usr/local/bin/opa"},
		{"pathWalker", "/usr/local/bin/pathWalker"},

		// tools
		{"tcpdump", "/usr/sbin/tcpdump"},
		{"ethtool", "/usr/sbin/ethtool"},        // network hardware setting
		{"tc", "/sbin/tc"},                      // traffic control
		{"modinfo", "/sbin/modinfo"},            // monitor tool: configure.sh
		{"getconf", "/usr/lib/getconf/getconf"}, // get configuration values
		{"getent", "/usr/bin/getent"},           // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},             // convert encoding of given files from one encoding to another
		{"curl", "/usr/bin/curl"},               // cis benchmark
		{"jq", "/usr/bin/jq"},                   // cis benchmark
		{"timeout", "/usr/bin/timeout"},         // could be used by tcpdump
		{"ps", "*"},
		{"cat", "*"}, // k8s readiness
		{"busybox", "/bin/busybox"}, // k8s readiness: backward compatible

		// bash
		{"bash", "/usr/bin/bash"}, // below busybox and its symbolic links
		{"mv", "/usr/bin/mv"},
		{"ss", "/usr/sbin/ss"},
		{"nproc", "/usr/bin/nproc"}, // dp
		{"touch", "/usr/bin/touch"}, // detect container layer on the AUFS
		{"uname", "/usr/bin/uname"},
		{"grep", "/usr/bin/grep"},
		{"awk", "/usr/bin/gawk"},
		{"find", "/usr/bin/find"},
		{"sed", "/usr/bin/sed"},
		{"stty", "/usr/bin/stty"}, // python

		{"configure.sh", "*"}, // monitor tool
		{"teardown.sh", "*"},  // monitor tool
		{"kill", "*"},

		// below entries for debug purpose
		{"ip", "/usr/sbin/ip"},
		{"iptables", "/usr/sbin/xtables-legacy-multi"},      // dp
		{"iptables-save", "/usr/sbin/xtables-legacy-multi"}, // dp

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

///
func (e *Engine) InsertNeuvectorProcessProfilePolicy(group, role string) {
	log.WithFields(log.Fields{"group": group, "role": role}).Debug("PROC:")
	var profile *share.CLUSProcessProfile
	switch role {
	case "enforcer":
		profile = buildEnforcerProfileList(group)
	case "controller":
		profile = buildControllerProfileList(group)
	case "manager":
		profile = buildManagerProfileList(group)
	case "controller+enforcer+manager", "controller+enforcer", "allinone":
		profile = buildAllinOneProfileList(group)
	case "scanner":
		profile = buildScannerProfileList(group)
	case "updater", "fetcher": // should not have protection, phase-out soon
		profile = buildAllowAllProfile(group)
	case "csp":
		profile = buildCspProfileList(group)
	case "registry-adapter":
		profile = buildRegistryAdapterProfileList(group)
	}

	// now, we use minimum policy for other neuvector containers
	if profile == nil {
		profile = buildAllinOneProfileList(group)
		// profile = buildNotAllowedProfile(group)		// TODO: enforce it to prevent hackers
	}

	e.UpdateProcessPolicy(group, profile)
}
