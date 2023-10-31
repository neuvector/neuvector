package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/nvbench"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	srcSh               = "/usr/local/bin/"
	dstSh               = "/tmp/"
	srcHostBenchSh      = srcSh + "host.tmpl"
	dstHostBenchSh      = dstSh + "host.sh"
	srcContainerBenchSh = srcSh + "container.tmpl"
	dstContainerBenchSh = dstSh + "container.sh"
	kube100MasterTmpl   = srcSh + "kube_master_1_0_0.tmpl"
	kube100WorkerTmpl   = srcSh + "kube_worker_1_0_0.tmpl"
	kube100Remediation  = srcSh + "kubecis_1_0_0.rem"
	kube120MasterTmpl   = srcSh + "kube_master_1_2_0.tmpl"
	kube120WorkerTmpl   = srcSh + "kube_worker_1_2_0.tmpl"
	kube120Remediation  = srcSh + "kubecis_1_2_0.rem"
	kube141MasterTmpl   = srcSh + "kube_master_1_4_1.tmpl"
	kube141WorkerTmpl   = srcSh + "kube_worker_1_4_1.tmpl"
	kube141Remediation  = srcSh + "kubecis_1_4_1.rem"
	kube151MasterTmpl   = srcSh + "kube_master_1_5_1.tmpl"
	kube151WorkerTmpl   = srcSh + "kube_worker_1_5_1.tmpl"
	kube151Remediation  = srcSh + "kubecis_1_5_1.rem"
	kube160MasterTmpl   = srcSh + "kube_master_1_6_0.tmpl"
	kube160WorkerTmpl   = srcSh + "kube_worker_1_6_0.tmpl"
	kube160Remediation  = srcSh + "kubecis_1_6_0.rem"
	kubeGKEMasterTmpl   = srcSh + "kube_master_gke_1_0_0.tmpl"
	kubeGKEWorkerTmpl   = srcSh + "kube_worker_gke_1_0_0.tmpl"
	kubeGKERemediation  = srcSh + "kubecis_gke_1_0_0.rem"
	kubeOC43MasterTmpl  = srcSh + "kube_master_ocp_4_3.tmpl"
	kubeOC43WorkerTmpl  = srcSh + "kube_worker_ocp_4_3.tmpl"
	kubeOC43Remediation = srcSh + "kubecis_ocp_4_3.rem"
	kubeOC45MasterTmpl  = srcSh + "kube_master_ocp_4_5.tmpl"
	kubeOC45WorkerTmpl  = srcSh + "kube_worker_ocp_4_5.tmpl"
	kubeOC45Remediation = srcSh + "kubecis_ocp_4_5.rem"
	masterScriptSh      = dstSh + "kube_master.sh"
	workerScriptSh      = dstSh + "kube_worker.sh"
	checkKubeVersion    = srcSh + "check_kube_version.sh"
	hostTimerStart      = time.Second * 10
	containerTimerStart = time.Second * 10
	kubeTimerStart      = time.Second * 10
	scriptTimerStart    = time.Second * 1
	cmdKubeApiServer    = "kube-apiserver"
	cmdKubeManager      = "kube-controller-manager"
	cmdKubeScheduler    = "kube-scheduler"
	cmdKubeEtcd         = "etcd"
	cmdKubelet          = "kubelet"
	cmdKubeProxy        = "kube-proxy"
	scriptTimeout       = 1 * time.Minute
)

type benchPlatform string

const (
	benchPlatDocker = "docker"
	benchPlatKube   = "kube"
)

type benchItem struct {
	level       string
	testNum     string
	group       string
	header      string
	profile     string // level 1, 2
	scored      bool
	automated   bool
	message     []string
	remediation string
}

type Bench struct {
	bEnable         bool
	mux             sync.Mutex
	platform        string
	flavor          string
	allContainers   utils.Set
	newContainers   map[string]string
	remediations    map[string]string
	hostTimer       *time.Timer
	conTimer        *time.Timer
	kubeTimer       *time.Timer
	customHostTimer *time.Timer
	customConTimer  *time.Timer
	daemonOpts      []string
	kubeCisCmds     map[string]string
	isKubeMaster    bool
	isKubeWorker    bool
	childCmd        *exec.Cmd
	hostScript      *share.CLUSCustomCheckGroup
	hostWarnItems   map[string]share.CLUSAuditBenchItem
	kubeHostDone    bool
	dockerHostDone  bool
	kubeCISVer      string
	dockerCISVer    string
	taskScanner     *TaskScanner
}

type DockerReplaceOpts struct {
	Replace_docker_daemon_opts string
	Replace_container_list     string
}

type KubeCisReplaceOpts struct {
	Replace_apiserver_cmd string
	Replace_manager_cmd   string
	Replace_scheduler_cmd string
	Replace_etcd_cmd      string
	Replace_kubelet_cmd   string
	Replace_proxy_cmd     string
}

func newBench(platform, flavor string) *Bench {
	b := &Bench{
		bEnable:         true,
		platform:        platform,
		flavor:          flavor,
		allContainers:   utils.NewSet(),
		newContainers:   make(map[string]string),
		remediations:    make(map[string]string),
		hostTimer:       time.NewTimer(hostTimerStart),
		conTimer:        time.NewTimer(containerTimerStart),
		kubeTimer:       time.NewTimer(kubeTimerStart),
		customHostTimer: time.NewTimer(scriptTimerStart),
		customConTimer:  time.NewTimer(scriptTimerStart),
		kubeCisCmds:     make(map[string]string),
		hostScript:      &share.CLUSCustomCheckGroup{},
		hostWarnItems:   make(map[string]share.CLUSAuditBenchItem),
		dockerCISVer:    "1.2.0",
	}

	// Let main program to start bench
	b.hostTimer.Stop()
	b.conTimer.Stop()
	b.kubeTimer.Stop()
	b.customHostTimer.Stop()
	b.customConTimer.Stop()

	// the master and worker's process will be set by probe
	//b.kubeCisCmds[cmdKubeApiServer] = cmdKubeApiServer
	//b.kubeCisCmds[cmdKubelet] = cmdKubelet
	b.kubeCisCmds[cmdKubeManager] = cmdKubeManager
	b.kubeCisCmds[cmdKubeScheduler] = cmdKubeScheduler
	b.kubeCisCmds[cmdKubeEtcd] = cmdKubeEtcd
	b.kubeCisCmds[cmdKubeProxy] = cmdKubeProxy
	return b
}

func (b *Bench) logBenchFailure(benchPlat benchPlatform, status share.BenchStatus) {
	var event share.TLogEvent
	if benchPlat == benchPlatKube {
		event = share.CLUSEvBenchKubeFail
	} else {
		event = share.CLUSEvBenchDockerFail
	}
	clog := share.CLUSEventLog{
		Event:      event,
		HostID:     Host.ID,
		HostName:   Host.Name,
		AgentID:    Agent.ID,
		AgentName:  Agent.Name,
		ReportedAt: time.Now().UTC(),
		Msg:        utils.BenchStatusToStr(status),
	}

	evqueue.Append(&clog)
}

func (b *Bench) BenchLoop() {
	var masterScript, workerScript, remediation string
	b.taskScanner = newTaskScanner(b, scanWorkerMax)
	//after the host bench, it will schedule a container bench automaticly even if no container
	for {
		select {
		case <-b.hostTimer.C:
			if agentEnv.autoBenchmark {
				b.doDockerHostBench()
			}
		case <-b.kubeTimer.C:
			if !agentEnv.autoBenchmark {
				continue
			}
			// Check version whenever the benchmark is rerun
			k8sVer, ocVer := global.ORCH.GetVersion(false, false)
			if masterScript == "" {
				// 1.11- : 1.3.0
				// 1.13- : 1.4.1
				// 1.15- : 1.5.1
				// 1.16- : 1.6.0
				// GKE: GKE 1.0.0
				if b.platform == share.PlatformKubernetes && b.flavor == share.FlavorGKE {
					b.kubeCISVer = "GKE-1.0.0"
					masterScript = kubeGKEMasterTmpl
					workerScript = kubeGKEWorkerTmpl
					remediation = kubeGKERemediation
				} else if b.platform == share.PlatformKubernetes && b.flavor == share.FlavorOpenShift {
					ocVer, err := version.NewVersion(ocVer)
					if err != nil {
						b.kubeCISVer = "OpenShift-1.1.0"
						masterScript = kubeOC45MasterTmpl
						workerScript = kubeOC45WorkerTmpl
						remediation = kubeOC45Remediation
					} else if ocVer.Compare(version.Must(version.NewVersion("4.4"))) >= 0 {
						b.kubeCISVer = "OpenShift-1.1.0"
						masterScript = kubeOC45MasterTmpl
						workerScript = kubeOC45WorkerTmpl
						remediation = kubeOC45Remediation
					} else {
						b.kubeCISVer = "OpenShift-1.1.0"
						masterScript = kubeOC43MasterTmpl
						workerScript = kubeOC43WorkerTmpl
						remediation = kubeOC43Remediation
					}
				} else {
					kVer, err := version.NewVersion(k8sVer)
					if err != nil {
						b.kubeCISVer = "1.6.0"
						masterScript = kube160MasterTmpl
						workerScript = kube160WorkerTmpl
						remediation = kube160Remediation
					} else if kVer.Compare(version.Must(version.NewVersion("1.16"))) >= 0 {
						b.kubeCISVer = "1.6.0"
						masterScript = kube160MasterTmpl
						workerScript = kube160WorkerTmpl
						remediation = kube160Remediation
					} else if kVer.Compare(version.Must(version.NewVersion("1.15"))) >= 0 {
						b.kubeCISVer = "1.5.1"
						masterScript = kube151MasterTmpl
						workerScript = kube151WorkerTmpl
						remediation = kube151Remediation
					} else if kVer.Compare(version.Must(version.NewVersion("1.11"))) >= 0 {
						b.kubeCISVer = "1.4.1"
						masterScript = kube141MasterTmpl
						workerScript = kube141WorkerTmpl
						remediation = kube141Remediation
					} else if kVer.Compare(version.Must(version.NewVersion("1.8"))) >= 0 {
						b.kubeCISVer = "1.2.0"
						masterScript = kube120MasterTmpl
						workerScript = kube120WorkerTmpl
						remediation = kube120Remediation
					} else {
						b.kubeCISVer = "1.0.0"
						masterScript = kube100MasterTmpl
						workerScript = kube100WorkerTmpl
						remediation = kube100Remediation
					}
				}
				b.remediations = b.loadRemediation(remediation)
			}

			b.doKubeBench(masterScript, workerScript, remediation)
		case <-b.conTimer.C:
			containers := b.cloneAllNewContainers()
			if agentEnv.autoBenchmark {
				if Host.CapDockerBench {
					b.doDockerContainerBench(containers)
				} else {
					b.putBenchReport(Host.ID, share.BenchDockerContainer, nil, share.BenchStatusFinished)
				}
			}

			// Run custom checks
			wls := make([]*share.CLUSWorkload, 0)
			for id, name := range containers {
				if c, ok := gInfoReadActiveContainer(id); ok {
					if Host.Platform == share.PlatformKubernetes && c.parentNS == "" {
						continue // skip kubernetes pod
					}

					// the service name has not the namespace extension
					wls = append(wls, createWorkload(c.info, &c.service, &c.domain))
					if agentEnv.scanSecrets {
						group := makeLearnedGroupName(utils.NormalizeForURL(c.service))
						b.taskScanner.addScanTask(c.pid, name, id, group)
					}
				}
			}

			if agentEnv.customBenchmark {
				b.doContainerCustomCheck(wls)
			}
		case <-b.customConTimer.C:
			if !agentEnv.customBenchmark {
				break
			}

			wls := make([]*share.CLUSWorkload, 0)
			gInfoRLock()
			for _, c := range gInfo.activeContainers {
				if Host.Platform == share.PlatformKubernetes && c.parentNS == "" {
					continue // skip kubernetes pod
				}
				wls = append(wls, createWorkload(c.info, &c.service, &c.domain))
			}
			gInfoRUnlock()

			b.doContainerCustomCheck(wls)
		case <-b.customHostTimer.C:
			b.doHostCustomCheck()
		}
	}
}

func (b *Bench) doKubeBench(masterScript, workerScript, remediation string) (error, error) {
	log.WithFields(log.Fields{"master": b.isKubeMaster, "worker": b.isKubeWorker}).Info()

	b.replaceKubeCisCmd(masterScript, masterScriptSh)
	b.replaceKubeCisCmd(workerScript, workerScriptSh)

	var errMaster, errWorker error
	var out []byte

	// run master bench
	if b.isKubeMaster {
		b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusRunning)

		out, errMaster = b.runKubeBench(share.BenchKubeMaster, masterScriptSh)
		if errMaster != nil {
			log.WithFields(log.Fields{
				"error": errMaster, "script": masterScriptSh,
			}).Error("Failed to run kubernetes master benchmark checks")

			b.logBenchFailure(benchPlatKube, share.BenchStatusKubeMasterFail)
			b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusKubeMasterFail)
		} else {
			list := b.getBenchMsg(out)
			b.assignKubeBenchMeta(list)
			b.kubeHostDone = true
			b.logHostResult(list)
			b.putBenchReport(Host.ID, share.BenchKubeMaster, list, share.BenchStatusFinished)
		}
	}

	// run worker bench
	if b.isKubeWorker {
		b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusRunning)

		out, errWorker = b.runKubeBench(share.BenchKubeWorker, workerScriptSh)
		if errWorker != nil {
			log.WithFields(log.Fields{
				"error": errWorker, "script": workerScriptSh,
			}).Error("Failed to run kubernetes worker benchmark checks")

			b.logBenchFailure(benchPlatKube, share.BenchStatusKubeWorkerFail)
			b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusKubeWorkerFail)
		} else {
			list := b.getBenchMsg(out)
			b.assignKubeBenchMeta(list)
			b.kubeHostDone = true
			b.logHostResult(list)
			b.putBenchReport(Host.ID, share.BenchKubeWorker, list, share.BenchStatusFinished)
		}
	}

	return errMaster, errWorker
}

func (b *Bench) AddContainer(id, name string) {
	b.mux.Lock()
	defer b.mux.Unlock()

	b.allContainers.Add(id)
	b.newContainers[id] = name
	b.conTimer.Reset(containerTimerStart)
}

func (b *Bench) RemoveContainer(id string) {
	b.mux.Lock()
	defer b.mux.Unlock()

	b.allContainers.Remove(id)
	delete(b.newContainers, id)
	b.conTimer.Reset(containerTimerStart)

	// TODO: delete existing keys
}

func (b *Bench) triggerContainerCustomCheck() {
	b.customConTimer.Reset(scriptTimerStart)
}

func (b *Bench) triggerHostCustomCheck(script *share.CLUSCustomCheckGroup) {
	b.hostScript = script
	b.customHostTimer.Reset(scriptTimerStart)
}

func (b *Bench) RerunDocker(forced bool) {
	if agentEnv.autoBenchmark == false && forced == false {
		log.Info("ignored")
		return
	}

	log.Info("")

	if err := b.dockerCheckPrerequisites(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot run Docker CIS benchmark")
		b.logBenchFailure(benchPlatDocker, share.BenchStatusNotSupport)
		b.putBenchReport(Host.ID, share.BenchDockerHost, nil, share.BenchStatusNotSupport)
	} else {
		b.hostTimer.Reset(hostTimerStart)
		b.conTimer.Reset(containerTimerStart)
		b.putBenchReport(Host.ID, share.BenchDockerHost, nil, share.BenchStatusScheduled)
	}
}

func (b *Bench) RerunKube(cmd, cmdRemap string, forced bool) {
	if agentEnv.autoBenchmark == false && forced == false {
		log.Info("ignored")
		return
	}

	log.Info("")

	if cmd != "" && cmdRemap != "" {
		b.kubeCisCmds[cmd] = cmdRemap
	}

	masterErr, workerErr := b.kubeCheckPrerequisites()
	_, b.isKubeMaster = b.kubeCisCmds[cmdKubeApiServer]
	_, b.isKubeWorker = b.kubeCisCmds[cmdKubelet]

	var sched bool

	if masterErr != nil {
		log.WithFields(log.Fields{"error": masterErr}).Error("Cannot run master node CIS benchmark")
		b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusNotSupport)
	} else if !b.isKubeMaster {
		log.Info("Not a kubernetes master node")
		b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusIdle)
	} else {
		b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusScheduled)
		sched = true
	}

	if workerErr != nil {
		log.WithFields(log.Fields{"error": workerErr}).Error("Cannot run worker node CIS benchmark")
		b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusNotSupport)
	} else if !b.isKubeWorker {
		log.Info("Not a kubernetes worker node")
		b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusIdle)
	} else {
		b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusScheduled)
		sched = true
	}

	if sched {
		b.kubeTimer.Reset(kubeTimerStart)
	}
}

func (b *Bench) ResetDockerStatus() {
	if agentEnv.autoBenchmark {
		b.putBenchReport(Host.ID, share.BenchDockerHost, nil, share.BenchStatusIdle)
	}
}

func (b *Bench) ResetKubeStatus() {
	if agentEnv.autoBenchmark {
		b.putBenchReport(Host.ID, share.BenchKubeMaster, nil, share.BenchStatusIdle)
		b.putBenchReport(Host.ID, share.BenchKubeWorker, nil, share.BenchStatusIdle)
	}
}

func (b *Bench) cloneAllNewContainers() map[string]string {
	b.mux.Lock()
	defer b.mux.Unlock()

	adds := make(map[string]string, len(b.newContainers))
	for id, name := range b.newContainers {
		adds[id] = name
	}
	b.newContainers = make(map[string]string, 0)
	return adds
}

func (b *Bench) parseBenchMsg(line string) (*benchItem, bool) {
	var level, id, msg, profile string
	var scored, automated bool

	if strings.Contains(line, "[INFO]") {
		level = share.BenchLevelInfo
	} else if strings.Contains(line, "[PASS]") {
		level = share.BenchLevelPass
	} else if strings.Contains(line, "[WARN]") {
		level = share.BenchLevelWarn
	} else if strings.Contains(line, "[NOTE]") {
		level = share.BenchLevelNote
	} else {
		return nil, false
	}

	a := strings.Index(line, "0m ")
	if a == -1 {
		return nil, false
	}
	c := strings.Index(line, " - ")
	if c != -1 {
		// Item headline
		id = strings.TrimSpace(line[a+3 : c])

		// Ignore the section title
		if strings.Index(id, ".") == -1 {
			return nil, false
		}

		if x := strings.Index(line, "[Scored]"); x != -1 {
			scored = true
		}
		if x := strings.Index(line, "[Automated]"); x != -1 {
			automated = true
		}
		if x := strings.Index(line, "[Level 1]"); x != -1 {
			profile = share.BenchProfileL1
		} else if x = strings.Index(line, "[Level 2]"); x != -1 {
			profile = share.BenchProfileL2
		}
	} else {
		// Item's following line
		c = strings.Index(line, " * ")
		if c == -1 {
			return nil, false
		}
	}

	msg = line[c+3:]
	msg = strings.ReplaceAll(msg, "(Scored)", "")
	msg = strings.ReplaceAll(msg, "(Not Scored)", "")
	msg = strings.ReplaceAll(msg, "(Automated)", "")
	msg = strings.ReplaceAll(msg, "(Manual)", "")
	msg = strings.TrimSpace(msg)

	return &benchItem{
		level: level, testNum: id, header: msg,
		scored: scored, automated: automated, profile: profile,
	}, true
}

//replace the docker daemon config line, so that can run the script without pid=host
func (b *Bench) replaceDockerDaemonCmdline(srcPath, dstPath string, containers []string) error {
	dat, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}
	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer f.Close()

	//containers only apply to container.sh, no effect to host.sh, because no <<<Containers>>> in it
	var containerLines string
	if len(containers) > 0 {
		containerLines = "containers=\"\n" + strings.Join(containers, "\n") + "\"\n"
	} else {
		containerLines = "containers=\"\"\n"
	}
	r := DockerReplaceOpts{
		Replace_docker_daemon_opts: strings.Join(b.daemonOpts, " "),
		Replace_container_list:     containerLines,
	}
	t := template.New("bench")
	t.Delims("<<<", ">>>")
	t.Parse(string(dat))

	if err = t.Execute(f, r); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Executing template error")
		return err
	}
	return nil
}

//if enforcer not running in pid host mode, change the audit warn to info
//because auditctl can not run without the pid host mode
/*
func (b *Bench) filterResult(list []*benchItem) {
	for _, l := range list {
		// TODO: skip all nv container
		newMsg := make([]string, 0)
		for _, m := range l.message {
			name := b.getContainerName(m)
			if name != Agent.Name {
				newMsg = append(newMsg, m)
			}
		}
		if len(l.message) > 0 && len(newMsg) == 0 && l.level == levelWarn {
			l.level = levelPass
		}
		l.message = newMsg
		if strings.HasPrefix(l.header, "Audit") &&
			strings.HasPrefix(l.testNum, "1.") &&
			Agent.PidMode != "host" &&
			l.level == levelWarn {
			l.level = levelInfo
		}
	}
}
*/

func (b *Bench) assignKubeBenchMeta(list []*benchItem) {
	for _, l := range list {
		if r, ok := b.remediations[l.testNum]; ok {
			l.remediation = r
		}
		l.testNum = fmt.Sprintf("K.%s", l.testNum)
	}
}

func (b *Bench) assignDockerBenchMeta(list []*benchItem) {
	for _, l := range list {
		if !nvbench.DockerNotScored.Contains(l.testNum) {
			l.scored = true
		}
		if !nvbench.DockerLevel2.Contains(l.testNum) {
			l.profile = share.BenchProfileL1
		} else {
			l.profile = share.BenchProfileL2
		}
		l.testNum = fmt.Sprintf("D.%s", l.testNum)
	}
}

func (b *Bench) getContainerName(msg string) string {
	if i := strings.Index(msg, ": "); i > 0 {
		return msg[i+2:]
	} else {
		return ""
	}
}

// check if last item should be accepted or ignored
func (b *Bench) acceptBenchItem(last, item *benchItem) bool {
	if last == nil {
		return false
	}
	// 1.2 should be ignored if the next line has 1.2. prefix
	if item != nil && strings.HasPrefix(item.testNum, fmt.Sprintf("%s.", last.testNum)) {
		return false
	}
	// Ignore NOTE and INFO entries
	if last.level == share.BenchLevelNote || last.level == share.BenchLevelInfo {
		return false
	}
	return true
}

func (b *Bench) getBenchMsg(out []byte) []*benchItem {
	list := make([]*benchItem, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var last, item *benchItem
	for scanner.Scan() {
		// Read output line-by-line. Every check forms a item,
		// the first line is the header and the rest form the message
		line := scanner.Text()
		if c, ok := b.parseBenchMsg(line); ok {
			if c.testNum == "" && item != nil {
				item.message = append(item.message, c.header)
			} else {
				if item != nil {
					// add the last item to the result
					if b.acceptBenchItem(last, item) {
						list = append(list, last)
					}
					last = item
				}
				item = c
			}
		}
	}
	if item != nil {
		// add the last item to the result
		if b.acceptBenchItem(last, item) {
			list = append(list, last)
		}
		if b.acceptBenchItem(item, nil) {
			list = append(list, item)
		}
	}
	return list
}

func (b *Bench) kubeCheckPrerequisites() (error, error) {
	kmasterProgs := []string{"grep", "pgrep", "sed", "kubectl"}
	masterError := b.checkRequiredHostProgs(kmasterProgs)
	kworkerProgs := []string{"grep", "pgrep", "sed"}
	workerError := b.checkRequiredHostProgs(kworkerProgs)
	return masterError, workerError
}

func (b *Bench) dockerCheckPrerequisites() error {
	if _, err := os.Stat(srcHostBenchSh); os.IsNotExist(err) {
		return fmt.Errorf("Docker bench host template not exist")
	}
	if _, err := os.Stat(srcContainerBenchSh); os.IsNotExist(err) {
		return fmt.Errorf("Docker bench container template not exist")
	}

	progs := []string{"grep", "stat", "docker"}
	if err := b.checkRequiredHostProgs(progs); err != nil {
		return err
	}

	// If failed to get docker daemon arguments, the bench can still do other items check,
	// but the item about the docker daemon is not correct
	opts, err := osutil.GetContainerDaemonArgs()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Get Docker daemon arguments fail")
		return fmt.Errorf("Get Docker daemon arguments fail")
	} else {
		b.daemonOpts = opts
	}
	return nil
}

func (b *Bench) runDockerHostBench() ([]byte, error) {
	if !b.bEnable {
		return nil, fmt.Errorf("Session ended")
	}

	if err := b.replaceDockerDaemonCmdline(srcHostBenchSh, dstHostBenchSh, nil); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Replace host docker daemon cmdline error")
		return nil, err
	}

	args := []string{system.NSActRun, "-f", dstHostBenchSh,
		"-m", global.SYS.GetMountNamespacePath(1), "-n", global.SYS.GetNetNamespacePath(1)}
	var errb, outb bytes.Buffer

	log.WithFields(log.Fields{"args": args}).Debug("Running bench script")
	cmd := exec.Command(system.ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	b.childCmd = cmd

	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, 1, "host-bench", dstHostBenchSh)
	err = cmd.Wait()
	global.SYS.RemoveToolProcess(pgid, false)
	out := outb.Bytes()

	b.childCmd = nil
	if err != nil || len(out) == 0 {
		if err == nil {
			err = fmt.Errorf("Error executing docker bench")
		}
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Done")
		return nil, err
	}

	return out, nil
}

func (b *Bench) doDockerHostBench() error {
	log.Debug()

	b.putBenchReport(Host.ID, share.BenchDockerHost, nil, share.BenchStatusRunning)

	out, err := b.runDockerHostBench()
	b.dockerHostDone = true

	if err != nil {
		b.logBenchFailure(benchPlatDocker, share.BenchStatusDockerHostFail)
		b.putBenchReport(Host.ID, share.BenchDockerHost, nil, share.BenchStatusDockerHostFail)
		return err
	}

	log.Info("Running benchmark checks done")

	list := b.getBenchMsg(out)
	b.assignDockerBenchMeta(list)

	b.logHostResult(list)
	b.putBenchReport(Host.ID, share.BenchDockerHost, list, share.BenchStatusFinished)
	return nil
}

func (b *Bench) doDockerContainerBench(containers map[string]string) error {
	b.putBenchReport(Host.ID, share.BenchDockerContainer, nil, share.BenchStatusRunning)
	if out, err := b.runDockerContainerBench(containers); err != nil {
		b.logBenchFailure(benchPlatDocker, share.BenchStatusDockerContainerFail)
		b.putBenchReport(Host.ID, share.BenchDockerContainer, nil, share.BenchStatusDockerContainerFail)
		return err
	} else {
		log.Info("Running benchmark checks done")

		list := b.getBenchMsg(out)
		b.assignDockerBenchMeta(list)

		b.putBenchReport(Host.ID, share.BenchDockerContainer, list, share.BenchStatusFinished)

		// Going through each container, write report and log
		for id, name := range containers {
			items, warns := b.getContainerItems(name, list)
			log.WithFields(log.Fields{"id": id, "items": len(items), "fails": len(warns)}).Debug()

			b.mux.Lock()
			if b.allContainers.Contains(id) {
				b.putBenchReport(id, share.BenchContainer, items, share.BenchStatusFinished)
			}
			b.mux.Unlock()

			if len(warns) > 0 {
				b.logContainerResult(name, id, warns, share.CLUSAuditComplianceContainerBenchViolation)
			}
		}

		return nil
	}
}

// This function returns per-container checks. The first value returned is all checks related to the container,
// the second is those failed checks.
func (b *Bench) getContainerItems(cname string, list []*benchItem) ([]*benchItem, []*benchItem) {
	items := make([]*benchItem, 0)
	warns := make([]*benchItem, 0)
	for _, l := range list {
		item := *l
		item.message = make([]string, 0)

		fail := false
		for _, msg := range l.message {
			// remove the container name and only keep the beginning as the messages
			tail := fmt.Sprintf(" %s", cname)
			if strings.HasSuffix(msg, tail) {
				nmsg := strings.TrimRight(msg, tail)
				nmsg = strings.TrimRight(nmsg, ":")
				item.message = append(item.message, nmsg)
				fail = true
				break
			}
		}
		if fail {
			warns = append(warns, &item)
		} else {
			item.level = share.BenchLevelPass
		}
		items = append(items, &item)
	}
	return items, warns
}

func (b *Bench) doContainerCustomCheck(wls []*share.CLUSWorkload) {
	log.Debug("")

	for _, wl := range wls {
		if items := b.runCustomScript(wl); len(items) > 0 {
			b.mux.Lock()
			if b.allContainers.Contains(wl.ID) {
				b.putBenchReport(wl.ID, share.BenchCustomContainer, items, share.BenchStatusFinished)
			}
			b.mux.Unlock()

			warns := make([]*benchItem, 0)
			for _, l := range items {
				if l.level == share.BenchLevelWarn || l.level == share.BenchLevelError {
					warns = append(warns, l)
				}
			}
			if len(warns) > 0 {
				b.logContainerResult(wl.Name, wl.ID, warns, share.CLUSAuditComplianceContainerCustomCheckViolation)
			}
		}
	}

	log.Debug("Running benchmark checks done")
}

func (b *Bench) doHostCustomCheck() {
	log.Debug("")

	b.mux.Lock()
	scripts := b.hostScript.Scripts
	b.mux.Unlock()

	items := make([]*benchItem, 0)
	for _, s := range scripts {
		ret, msg, err := b.runScript(s.Script, 1)
		log.WithFields(log.Fields{"Script": s.Name, "msg": msg}).Debug("run host script")

		item := &benchItem{
			testNum: s.Name,
			group:   "nodes",
			header:  msg,
		}

		if err == nil {
			if ret {
				item.level = share.BenchLevelPass
			} else {
				item.level = share.BenchLevelWarn
			}
		} else {
			item.level = share.BenchLevelError
		}
		items = append(items, item)
	}

	// Write to the cluster
	b.putBenchReport(Host.ID, share.BenchCustomHost, items, share.BenchStatusFinished)

	b.logHostCustomCheckResult(items)

	log.Info("Finish host custom check script")
}

func (b *Bench) runDockerContainerBench(containers map[string]string) ([]byte, error) {
	if !b.bEnable {
		return nil, fmt.Errorf("Session ended")
	}

	cs := make([]string, len(containers))
	i := 0
	for _, name := range containers {
		cs[i] = name
		i++
	}
	if err := b.replaceDockerDaemonCmdline(srcContainerBenchSh, dstContainerBenchSh, cs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Replace container docker daemon cmdline error")
		return nil, fmt.Errorf("Replace container docker daemon cmdline error, error=%v", err)
	}

	args := []string{system.NSActRun, "-f", dstContainerBenchSh, "-m", global.SYS.GetMountNamespacePath(1)}
	var errb, outb bytes.Buffer

	log.WithFields(log.Fields{"args": args}).Debug("Running bench script")
	cmd := exec.Command(system.ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	b.childCmd = cmd
	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, 1, "container-docker-bench", dstContainerBenchSh)
	err = cmd.Wait()
	global.SYS.RemoveToolProcess(pgid, false)
	out := outb.Bytes()

	b.childCmd = nil
	if err != nil || len(out) == 0 {
		if err == nil {
			err = fmt.Errorf("Error executing docker bench")
		}
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Done")
		return nil, err
	}
	return out, nil
}

func (b *Bench) runCustomScript(wl *share.CLUSWorkload) []*benchItem {
	items := make([]*benchItem, 0)
	grpScripts := make(map[string]*share.CLUSCustomCheckGroup, 0)
	groupMux.Lock()
	for _, grp := range groups {
		if grp.script != nil && share.IsGroupMember(grp.group, wl, getDomainData(wl.Domain)) {
			grpScripts[grp.group.Name] = grp.script
		}
	}
	groupMux.Unlock()

	for grpName, script := range grpScripts {
		log.WithFields(log.Fields{"name": wl.Name, "group": grpName, "script": script}).Debug("selected")

		for _, s := range script.Scripts {
			ret, msg, err := b.runScript(s.Script, wl.Pid)
			msg = strings.TrimRight(msg, "\r\n")
			log.WithFields(log.Fields{"Script": s.Name, "name": wl.Name, "msg": msg, "err": err}).Debug("run script")

			item := &benchItem{
				testNum: s.Name,
				group:   grpName,
				header:  msg,
			}
			if err == nil {
				if ret {
					item.level = share.BenchLevelPass
				} else {
					item.level = share.BenchLevelWarn
				}
			} else {
				item.level = share.BenchLevelError
			}
			items = append(items, item)
		}
	}

	return items
}

func (b *Bench) runScript(script string, pid int) (bool, string, error) {
	if !b.bEnable {
		return false, "Session ended", fmt.Errorf("Session ended")
	}

	file, err := ioutil.TempFile(os.TempDir(), "script")
	if err != nil {
		return false, "file system error", err
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(script); err != nil {
		return false, "file system error", err
	}
	if err = file.Close(); err != nil {
		return false, "file system error", err
	}
	args := []string{system.NSActRun, "-f", file.Name(),
		"-m", global.SYS.GetMountNamespacePath(pid),
		"-t", global.SYS.GetUtsNamespacePath(pid),
		"-c", global.SYS.GetIpcNamespacePath(pid),
		//"-u", global.SYS.GetUserNamespacePath(pid),
		"-p", global.SYS.GetPidNamespacePath(pid),
		"-n", global.SYS.GetNetNamespacePath(pid),
		"-g", global.SYS.GetCgroupNamespacePath(pid),
	}
	var errb, outb bytes.Buffer

	cmd := exec.Command(system.ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	var msg string
	result := make(chan error, 1)
	b.childCmd = cmd

	//
	err = cmd.Start()
	if err != nil {
		return false, fmt.Sprintf("%s: err=%s", share.CustomScriptFailedPrefix, err.Error()), nil
	}

	pgid := cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, pid, "run-script", file.Name())

	go func() {
		log.WithFields(log.Fields{"args": args, "pgid": pgid, "pid": pid}).Debug("Running custom check script")
		err := cmd.Wait()
		if errb.Len() > 0 {
			msg = errb.String()
		}
		msg += fmt.Sprintf("%s", outb.String())
		result <- err
	}()
	select {
	case err := <-result:
		b.childCmd = nil
		global.SYS.RemoveToolProcess(pgid, false)
		if err == nil {
			return true, msg, nil
		} else {
			if ee, ok := err.(*exec.ExitError); ok {
				if status := global.SYS.GetExitStatus(ee); status != 0 {
					if msg == "" {
						msg = fmt.Sprintf("%s: status=%d, error=%s", share.CustomScriptFailedPrefix, status, err.Error())
					}
					return false, msg, nil
				}
			}
		}
		return false, msg, err
	case <-time.After(scriptTimeout):
		global.SYS.RemoveToolProcess(pgid, true)
		b.childCmd = nil
		return false, "script timeout", fmt.Errorf("script timeout")
	}
}

func (b *Bench) putBenchReport(id string, bench share.BenchType, items []*benchItem, status share.BenchStatus) {
	key := share.CLUSBenchReportKey(id, bench)

	checks := make([]*share.CLUSBenchItem, len(items))
	if len(items) > 0 {
		for i, l := range items {
			checks[i] = b.bench2Report(l)
		}
	}

	now := time.Now().UTC()
	report := share.CLUSBenchReport{
		Status: status,
		RunAt:  now,
		Items:  checks,
	}

	switch bench {
	case share.BenchDockerHost, share.BenchDockerContainer, share.BenchContainer:
		if Host.CapDockerBench {
			report.Version = b.dockerCISVer
		}
	case share.BenchKubeMaster, share.BenchKubeWorker:
		if Host.CapKubeBench {
			report.Version = b.kubeCISVer
		}
	}

	value, _ := json.Marshal(&report)
	zb := utils.GzipBytes(value)
	if err := cluster.PutBinary(key, zb); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}

	// Notify bench scan changed.
	if len(checks) > 0 {
		switch bench {
		case share.BenchDockerHost, share.BenchCustomHost, share.BenchKubeMaster, share.BenchKubeWorker:
			key = share.CLUSBenchStateHostKey(id)
		default:
			key = share.CLUSBenchStateWorkloadKey(id)
		}
		value, _ = json.Marshal(&share.CLUSBenchState{RunAt: now})
		cluster.PutBinary(key, value)
	}
}

//the script may use several command like grep netstat, check whether they exist in host
func (b *Bench) checkRequiredHostProgs(progs []string) error {
	for _, p := range progs {
		dat, err := global.SYS.CheckHostProgram(p, 1)
		if err != nil || len(dat) == 0 {
			log.WithFields(log.Fields{"error": err, "program": p}).Error("")
			return fmt.Errorf("%s command not found.\n", p)
		}

	}
	return nil
}

func (b *Bench) runKubeBench(bench share.BenchType, script string) ([]byte, error) {
	if !b.bEnable {
		return nil, fmt.Errorf("Session ended")
	}

	var errb, outb bytes.Buffer
	args := []string{
		system.NSActRun, "-f", script,
		"-m", global.SYS.GetMountNamespacePath(1),
		"-n", global.SYS.GetNetNamespacePath(1),
	}
	log.WithFields(log.Fields{"type": bench}).Debug("Running Kubernetes CIS bench")
	cmd := exec.Command(system.ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	b.childCmd = cmd
	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return nil, err
	}
	pgid := cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, 1, "kube-bench", script)
	err = cmd.Wait()
	global.SYS.RemoveToolProcess(pgid, false)
	out := outb.Bytes()

	b.childCmd = nil
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			status := global.SYS.GetExitStatus(ee)
			if status == 2 {
				// Not a master or worker node, ignore the error
				log.WithFields(log.Fields{"msg": errb.String()}).Debug("Done")
				return nil, fmt.Errorf("Node type not recognized")
			}
		}

		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("")
		return nil, err
	}

	log.WithFields(log.Fields{"type": bench}).Debug("Finish Kubernetes CIS bench")
	return out, nil
}

func (b *Bench) getKubeVersion() string {
	if !b.bEnable {
		return ""
	}

	var errb, outb bytes.Buffer
	args := []string{
		system.NSActRun, "-f", checkKubeVersion, "-m", global.SYS.GetMountNamespacePath(1),
	}
	log.WithFields(log.Fields{"args": args}).Debug("Get Kubernetes version")
	cmd := exec.Command(system.ExecNSTool, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	b.childCmd = cmd

	err := cmd.Start()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("Start")
		return ""
	}
	pgid := cmd.Process.Pid
	global.SYS.AddToolProcess(pgid, 1, "kube-version", checkKubeVersion)
	err = cmd.Wait()
	global.SYS.RemoveToolProcess(pgid, false)
	out := outb.Bytes()

	b.childCmd = nil
	if err != nil {
		log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("")
		return ""
	}
	log.WithFields(log.Fields{"version": string(out)}).Info("Kubernetes version")
	return string(out)
}

func (b *Bench) loadRemediation(remediation string) map[string]string {
	r := make(map[string]string)

	dat, err := ioutil.ReadFile(remediation)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open remediation file fail")
		return r
	}

	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, ":"); i > 0 {
			r[strings.TrimSpace(line[:i-1])] = line[i+1:]
		}
	}
	return r
}

//replace the kubernetes cis command
func (b *Bench) replaceKubeCisCmd(srcPath, dstPath string) error {
	dat, err := ioutil.ReadFile(srcPath)
	if err != nil {
		log.WithFields(log.Fields{"src": srcPath, "error": err}).Error("Open template file error")
		return err
	}
	f, err := os.Create(dstPath)
	if err != nil {
		log.WithFields(log.Fields{"dst": dstPath, "error": err}).Error("Create script file error")
		return err
	}
	defer f.Close()

	r := KubeCisReplaceOpts{
		Replace_apiserver_cmd: b.kubeCisCmds[cmdKubeApiServer],
		Replace_manager_cmd:   b.kubeCisCmds[cmdKubeManager],
		Replace_scheduler_cmd: b.kubeCisCmds[cmdKubeScheduler],
		Replace_etcd_cmd:      b.kubeCisCmds[cmdKubeEtcd],
		Replace_kubelet_cmd:   b.kubeCisCmds[cmdKubelet],
		Replace_proxy_cmd:     b.kubeCisCmds[cmdKubeProxy],
	}
	t := template.New("kubecis")
	t.Delims("<<<", ">>>")
	t.Parse(string(dat))

	if err = t.Execute(f, r); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Executing template error")
		return err
	}
	return nil
}

func (b *Bench) bench2Report(l *benchItem) *share.CLUSBenchItem {
	return &share.CLUSBenchItem{
		Level:       l.level,
		TestNum:     l.testNum,
		Header:      l.header,
		Message:     l.message,
		Remediation: l.remediation,
		Group:       l.group,
		Scored:      l.scored,
		Automated:   l.automated,
		Profile:     l.profile,
	}
}

func (b *Bench) bench2Log(l *benchItem) *share.CLUSAuditBenchItem {
	a := &share.CLUSAuditBenchItem{
		Level:     l.level,
		TestNum:   l.testNum,
		Group:     l.group,
		Scored:    l.scored,
		Automated: l.automated,
		Profile:   l.profile,
		Msg:       l.header,
	}
	switch a.TestNum {
	case "D.4.8":
		a.Msg = fmt.Sprintf("%s - File %s has %s mode", l.header, l.message[2], l.message[0])
	case "D.4.10":
		a.Msg = fmt.Sprintf("%s - File %s contains %s", l.header, l.message[2], l.message[0])
	default:
		a.Msg = l.header
	}
	return a
}

func (b *Bench) logContainerResult(name, id string, items []*benchItem, lid share.TLogAudit) {
	logs := make([]share.CLUSAuditBenchItem, len(items))
	for i, l := range items {
		logs[i] = *b.bench2Log(l)
	}
	logContainerAudit(name, id, logs, lid)
}

func (b *Bench) logHostResult(list []*benchItem) {
	var update, kube, docker bool

	for _, l := range list {
		if l.level == share.BenchLevelWarn {
			logItem := b.bench2Log(l)
			if itm, ok := b.hostWarnItems[l.testNum]; !ok || *logItem != itm {
				b.hostWarnItems[l.testNum] = *logItem
				update = true
			}
		}
	}

	if Host.CapKubeBench {
		kube = b.kubeHostDone
	} else {
		kube = true
	}
	if Host.CapDockerBench {
		docker = b.dockerHostDone
	} else {
		docker = true
	}

	if update && kube && docker {
		logs := make([]share.CLUSAuditBenchItem, 0)
		for _, itm := range b.hostWarnItems {
			logs = append(logs, itm)
		}
		sort.Slice(logs, func(i, j int) bool { return logs[i].TestNum < logs[j].TestNum })
		logHostAudit(logs, share.CLUSAuditComplianceHostBenchViolation)
	}
}

func (b *Bench) logHostCustomCheckResult(list []*benchItem) {
	logs := make([]share.CLUSAuditBenchItem, 0)
	for _, l := range list {
		if l.level == share.BenchLevelWarn {
			logItem := b.bench2Log(l)
			logs = append(logs, *logItem)
		}
	}
	// sort.Slice(logs, func(i, j int) bool { return logs[i].TestNum < logs[j].TestNum })
	logHostAudit(logs, share.CLUSAuditComplianceHostCustomCheckViolation)
}

//////
func (b *Bench) runFindSecrets(rootPid int, name, id, group string) {
	if !osutil.IsPidValid(rootPid) {
		log.WithFields(log.Fields{"pid": rootPid}).Error("Exited")
		return
	}

	b.mux.Lock()
	if b.allContainers.Contains(id) {
		b.putBenchReport(id, share.BenchContainerSecret, nil, share.BenchStatusRunning)
	}
	b.mux.Unlock()

	logs := make([]share.CLUSSecretLog, 0)
	perms := make([]share.CLUSSetIdPermLog, 0)
	req := workerlet.WalkSecretRequest{
		Pid:        rootPid,
		MiniWeight: 0.1,
		TimeoutSec: 3 * 60,
	}

	permBytes, secretBytes, err := walkerTask.RunWithTimeout(req, id, time.Duration(req.TimeoutSec)*time.Second)
	if err != nil {
		log.WithFields(log.Fields{"pid": rootPid, "id": id, "error": err}).Error()
	} else {
		if err = json.Unmarshal(secretBytes, &logs); err != nil {
			log.WithFields(log.Fields{"data": string(secretBytes), "id": id, "error": err}).Error("logs")
		}

		if err = json.Unmarshal(permBytes, &perms); err != nil {
			log.WithFields(log.Fields{"data": string(permBytes), "id": id, "error": err}).Error("perm")
		}

		log.WithFields(log.Fields{"pid": rootPid, "logCnt": len(logs), "permCnt": len(perms)}).Debug()
	}

	items := make([]*benchItem, len(logs))
	for i, l := range logs {
		// cloak the secret a little bit by masking out some digits
		var subject string
		secretLength := len(l.Text)
		if secretLength > 32 {
			subject = l.Text[:30]
		} else if secretLength > 6 { // should be longer than 6
			subject = l.Text[:secretLength-3]
		}
		subject += "..."
		items[i] = &benchItem{
			level:   share.BenchLevelWarn,
			testNum: "D.4.10",
			group:   group,
			header:  "Ensure secrets are not stored in container images",
			profile: share.BenchProfileL1,
			message: []string{l.RuleDesc, subject, l.File}, // cloaked evidence
		}
	}

	setids := make([]*benchItem, len(perms))
	for i, p := range perms {
		// log.WithFields(log.Fields{"attributes": p.Evidence, "path": p.File}).Debug()
		setids[i] = &benchItem{
			level:   share.BenchLevelWarn,
			testNum: "D.4.8",
			group:   group,
			header:  "Ensure setuid and setgid permissions are removed",
			profile: share.BenchProfileL2,
			message: []string{p.Types, p.Evidence, p.File}, // evidence: like  "dgrwxr-xr-x"
		}
	}

	b.putBenchReport(id, share.BenchContainerSetID, setids, share.BenchStatusFinished)
	b.putBenchReport(id, share.BenchContainerSecret, items, share.BenchStatusFinished)
	b.mux.Lock()
	if b.allContainers.Contains(id) {
		items = append(items, setids...)
		if len(items) > 0 {
			// has auditMutex.lock inside
			b.logContainerResult(name, id, items, share.CLUSAuditComplianceContainerFileBenchViolation)
		}
	}
	b.mux.Unlock()
}

func (b *Bench) Close() {
	b.bEnable = false
	//	if b.childCmd != nil {
	//		if err := syscall.Kill(b.childCmd.Process.Pid, syscall.SIGKILL); err != nil {
	//			log.WithFields(log.Fields{"err": err}).Error("Failed to kill child script")
	//		}
	//	}
}

// a simple pipeline routine to trigger the goroutine of a scan task
type taskScanSecrets struct {
	rootPid int
	name    string
	id      string
	group   string
}

type TaskScanner struct {
	lock       sync.Mutex
	done       chan error
	queue      []*taskScanSecrets
	maxWorkers int
	curWorkers int
	bench      *Bench
	// reference:
	startTime time.Time
	caseDone  int
}

////
const scanWorkerMax int = 4 // 16
const scanTimerTick int = 2 // tick at 2 sec
const scanTimerSlow int = 5 // long period: 10 sec
const scanTimerFast int = 1 // shorter period: 2 sec

///
func newTaskScanner(b *Bench, maxWorkers int) *TaskScanner {
	scanTask := &TaskScanner{
		bench:      b,
		queue:      make([]*taskScanSecrets, 0),
		done:       make(chan error),
		maxWorkers: maxWorkers,
	}

	go scanTask.scanSecretLoop()
	return scanTask
}

///
func (t *TaskScanner) scanSecretLoop() {
	bFirstScan := true
	scanTicks := 0
	scanTimerSetting := scanTimerSlow
	scanTicker := time.Tick(time.Second * time.Duration(scanTimerTick))
	for {
		select {
		case <-scanTicker:
			scanTicks++
			if scanTicks >= scanTimerSetting {
				scanTicks = 0
				t.lock.Lock()
				bAdded := t.nextScanTasks()
				if bAdded {
					if scanTimerSetting == scanTimerSlow {
						log.Info("SCRT: in progress ...")
						t.startTime = time.Now()
						t.caseDone = 0 // reset
						scanTimerSetting = scanTimerFast
						if bFirstScan {
							global.SYS.ReCalculateMemoryMetrics(0) // clean up previous operations, like other bench tests
						}
					}
				} else {
					if scanTimerSetting == scanTimerFast && t.curWorkers == 0 {
						log.WithFields(log.Fields{"Finished": t.caseDone, "TimeUsed": time.Since(t.startTime)}).Info("SCRT: done")
						scanTimerSetting = scanTimerSlow
						if bFirstScan {
							bFirstScan = false
							global.SYS.ReCalculateMemoryMetrics(0) // clean up
						}
					}
				}
				t.lock.Unlock()
			}
		case <-t.done:
			t.lock.Lock()
			t.curWorkers--
			t.caseDone++
			t.lock.Unlock()
			global.SYS.ReCalculateMemoryMetrics(memStatsEnforcerResetMark)
		}
	}
}

///
func (t *TaskScanner) nextScanTasks() bool {
	// was locked at outside of the function
	// log.WithFields(log.Fields{"curWorkers": t.curWorkers, "len": len(t.queue)}).Debug("SCRT")
	// try a maximum loop based on maximum workers
	bAddWorker := false
	for i := 0; i < t.maxWorkers; i++ {
		if t.curWorkers >= t.maxWorkers || len(t.queue) == 0 {
			break
		}

		task := t.queue[0]
		if len(t.queue) > 1 {
			t.queue = t.queue[1:]
		} else {
			t.queue = make([]*taskScanSecrets, 0)
		}

		bAddWorker = true
		t.curWorkers++
		go func() {
			// log.WithFields(log.Fields{"task": task}).Info("SCRT")
			bench.runFindSecrets(task.rootPid, task.name, task.id, task.group)
			t.done <- nil
		}()
	}
	return bAddWorker
}

///
func (t *TaskScanner) addScanTask(rootPid int, name, id, group string) {
	// log.WithFields(log.Fields{"len": len(t.queue), "id": id, "group": group}).Debug("SCRT")
	task := &taskScanSecrets{
		rootPid: rootPid,
		name:    name,
		id:      id,
		group:   group,
	}

	t.lock.Lock()
	t.queue = append(t.queue, task)
	t.lock.Unlock()
}
