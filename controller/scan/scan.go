package scan

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/scheduler"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/httptrace"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

var clusHelper kv.ClusterHelper

type Context struct {
	AuditQueue cluster.ObjectQueueInterface
	ScanChan   chan *resource.Event
	TimerWheel *utils.TimerWheel
	ScanLog    *log.Logger
	MutexLog   *log.Logger
	FedRole    string
}

type scanMethod struct {
	isLeader   bool
	isScanner  bool
	db         share.CLUSScannerDB
	auditQueue cluster.ObjectQueueInterface
	timerWheel *utils.TimerWheel
	scanChan   chan *resource.Event
	scanLog    *log.Logger
	mutexLog   *log.Logger
	httpProxy  string
	httpsProxy string
	fedRole    string
}

var smd *scanMethod

func isScanner() bool {
	return smd.isScanner
}

// count vul. with the consideration of vul. profile (alives)
// requirement: entries in 'vts' are in the same order as in 'vuls'
func countVuln(vuls []*share.ScanVulnerability, vts []*scanUtils.VulTrait, alives utils.Set) (
	[]string, []string, []string, []string, int, int, float32, map[string]map[string]share.CLUSScannedVulInfo, []share.CLUSScannedVulInfoSimple) {

	criticals := make([]string, 0)
	highs := make([]string, 0)
	meds := make([]string, 0)
	lows := make([]string, 0)
	var criticalWithFix, highWithFix, others int
	var scoreTemp int

	for _, v := range vuls {
		if !alives.Contains(v.Name) {
			continue
		}

		if v.Severity == share.VulnSeverityCritical {
			criticals = append(criticals, v.Name)
			if v.FixedVersion != "" {
				criticalWithFix++
			}
		} else if v.Severity == share.VulnSeverityHigh {
			highs = append(highs, v.Name)
			if v.FixedVersion != "" {
				highWithFix++
			}
		} else if v.Severity == share.VulnSeverityMedium {
			meds = append(meds, v.Name)
		} else {
			others++
		}
		scoreTemp += int(10 * v.Score)

		if v.Severity == share.VulnSeverityLow {
			lows = append(lows, v.Name)
		}
	}

	criticalVulPublishDate := make(map[string]share.CLUSScannedVulInfo, len(criticals))
	highVulPublishDate := make(map[string]share.CLUSScannedVulInfo, len(highs))
	mediumVulPublishDate := make(map[string]share.CLUSScannedVulInfo, len(meds))
	otherVuls := make([]share.CLUSScannedVulInfoSimple, others)
	var targetMap map[string]share.CLUSScannedVulInfo
	var low bool
	var idxLow int
	var score float32
	// j is the current index in vts
	// entries in 'vts' are in the same order as in 'vuls'
	//	see RegistryImageStateUpdate()/ExtractVulnerability()
	j := 0
	for i, v := range vuls {
		foundInVts := false
		if len(vts) > i && vts[j].Name == v.Name {
			foundInVts = true
		}
		if !alives.Contains(v.Name) {
			// this vul is filtered by profile. so skip this entry by moving vuls index(i) & vts index(j) by 1
			if foundInVts {
				j += 1
			}
			i += 1
			continue
		}

		low = false
		targetMap = nil
		score = v.Score
		if v.ScoreV3 > v.Score {
			score = v.ScoreV3
		}
		if v.Severity == share.VulnSeverityCritical {
			targetMap = criticalVulPublishDate
		} else if v.Severity == share.VulnSeverityHigh {
			targetMap = highVulPublishDate
		} else if v.Severity == share.VulnSeverityMedium {
			targetMap = mediumVulPublishDate
		} else {
			low = true
		}
		if targetMap != nil {
			withFix := false
			if v.FixedVersion != "" {
				withFix = true
			}

			n, err := strconv.ParseInt(v.PublishedDate, 10, 64)
			if err != nil {
				// if vul's publish date is unavailable, treat it as 2 years ago
				n = time.Now().UTC().AddDate(-2, 0, 0).Unix()
			}
			if foundInVts && vts[j].Name == v.Name {
				// found a same-vul-name entry in vts but with different publishDate value.
				// vul info in vts(from scannerDB) is more accurate than in vuls(from scanResult)
				if vtPubTS := vts[j].GetPubTS(); vtPubTS != n {
					n = vtPubTS
				}
			}

			name := fmt.Sprintf("%s::%s", v.Name, v.PackageName)
			targetMap[name] = share.CLUSScannedVulInfo{
				PublishDate: n,
				WithFix:     withFix,
				Score:       score,
			}
		} else if low {
			otherVuls[idxLow] = share.CLUSScannedVulInfoSimple{Score: score}
			idxLow++
		}
		if foundInVts {
			j += 1
		}
		i += 1
	}
	vulPublishDate := map[string]map[string]share.CLUSScannedVulInfo{
		share.VulnSeverityCritical: criticalVulPublishDate,
		share.VulnSeverityHigh:     highVulPublishDate,
		share.VulnSeverityMedium:   mediumVulPublishDate,
	}

	s := fmt.Sprintf("%d.%s", scoreTemp/10, strconv.Itoa(scoreTemp%10))
	totalScore, _ := strconv.ParseFloat(s, 32)
	return criticals, highs, meds, lows, criticalWithFix, highWithFix, float32(totalScore), vulPublishDate, otherVuls
}

func imageWatcher() {
	for {
		select {
		case ev := <-smd.scanChan:
			smd.scanLog.WithFields(log.Fields{"event": ev.Event, "type": ev.ResourceType}).Debug("Event received")
			if ev.ResourceNew == nil && ev.ResourceOld == nil {
				break
			}
			switch ev.ResourceType {
			case resource.RscTypeImage:
				var n, o *resource.Image
				if ev.ResourceNew != nil {
					n = ev.ResourceNew.(*resource.Image)
				}
				if ev.ResourceOld != nil {
					o = ev.ResourceOld.(*resource.Image)
				}
				if n != nil {
					imageBankUpdate(n)
				} else if n == nil && o != nil {
					imageBankDelete(o)
				}
			}
		}
	}
}

func ScannerChangeNotify(isScanner bool) {
	log.WithFields(log.Fields{"scanner": isScanner}).Info()

	smd.isScanner = isScanner
	if isScanner {
		becomeScanner()
	}
}

func LeadChangeNotify(isLeader bool) {
	log.WithFields(log.Fields{"leader": isLeader}).Info()

	smd.isLeader = isLeader
}

func FedRoleChangeNotify(fedRole string) {
	log.WithFields(log.Fields{"fedRole": fedRole}).Info()

	smd.fedRole = fedRole
}

func AddScanner(id string) error {
	log.WithFields(log.Fields{"id": id}).Info()

	if regScher == nil {
		regScher = &scheduler.Schd{}
		regScher.Init()
	}

	if err := regScher.AddProcessor(id); err != nil {
		return fmt.Errorf("failed to add processor: %w", err)
	}
	return nil
}

func RemoveScanner(id string) error {
	log.WithFields(log.Fields{"id": id}).Info()

	if regScher == nil {
		return errors.New("registry scheduler is not initialized")
	}

	if _, err := regScher.DelProcessor(id); err != nil {
		return fmt.Errorf("failed to remove processor: %w", err)
	}

	return nil
}

// used internally, so access control
func GetRegistryCount() int {
	regReadLock()
	defer regReadUnlock()
	return len(regMap)
}

func ScannerDBChange(db *share.CLUSScannerDB) {
	log.WithFields(log.Fields{"old": smd.db.CVEDBVersion, "new": db.CVEDBVersion}).Debug("")

	oldVer := smd.db.CVEDBVersion
	smd.db = *db

	// rescan registries. Skip if this is first time scanner is registered, because it is
	// likely the controller just starts, we don't want to scan starts automatically.
	if oldVer != "" && oldVer != db.CVEDBVersion && isScanner() {
		var getFed bool
		// when scan db changes, do nothing for fed registry on non-master cluster
		if smd.fedRole == api.FedRoleMaster {
			getFed = true
		}
		regs := regMapToArray(true, getFed)
		for _, reg := range regs {
			if reg.config.RescanImage {
				reg.stateLock()
				state := clusHelper.GetRegistryState(reg.config.Name)
				if state != nil {
					if state.Status == api.RegistryStatusScanning {
						if reg.sctx != nil {
							reg.stopScan()
						}
						reg.startScan()
					} else {
						smd.scanLog.WithFields(log.Fields{"registry": reg.config.Name}).Debug("CVE Database updated. Start re-scan")
						state := &share.CLUSRegistryState{Status: api.RegistryStatusScanning, StartedAt: time.Now().Unix()}
						clusHelper.PutRegistryState(reg.config.Name, state)
					}
				}
				reg.stateUnlock()
			}
		}
	}
}

func InitContext(ctx *Context, leader bool) {
	if smd == nil {
		smd = &scanMethod{
			auditQueue: ctx.AuditQueue,
			scanChan:   ctx.ScanChan,
			scanLog:    ctx.ScanLog,
			mutexLog:   ctx.MutexLog,
			timerWheel: ctx.TimerWheel,
			isLeader:   leader,
			fedRole:    ctx.FedRole,
		}
	} else {
		smd.auditQueue = ctx.AuditQueue
		smd.scanChan = ctx.ScanChan
		smd.scanLog = ctx.ScanLog
		smd.mutexLog = ctx.MutexLog
		smd.timerWheel = ctx.TimerWheel
		smd.isLeader = leader
		smd.fedRole = ctx.FedRole
	}
}

func Init(ctx *Context, leader bool) ScanInterface {
	log.Info()

	InitContext(ctx, leader)

	clusHelper = kv.GetClusterHelper()

	registryInit()

	go imageWatcher()

	return smd
}

func UpdateProxy(httpProxy, httpsProxy *share.CLUSProxy) {
	log.WithFields(log.Fields{"http": httpProxy, "https": httpsProxy}).Debug()

	// This can be called before InitContext is called
	if smd == nil {
		smd = &scanMethod{
			httpProxy:  httpclient.ParseProxy(httpProxy),
			httpsProxy: httpclient.ParseProxy(httpsProxy),
		}

		// It is startup state if smd is nil, let registry init to handle proxy settings
	} else {
		smd.httpProxy = httpclient.ParseProxy(httpProxy)
		smd.httpsProxy = httpclient.ParseProxy(httpsProxy)

		var getFed bool
		// when proxy setting changes, do nothing for fed registry on non-master cluster
		if smd.fedRole == api.FedRoleMaster {
			getFed = true
		}

		regs := regMapToArray(true, getFed)
		for _, reg := range regs {
			reg.driver.SetProxy()
			reg.backupDrv.SetProxy()
			reg.driver.Logout(true)
			reg.backupDrv.Logout(true)
			reg.driver = newRegistryDriver(reg.config, reg.public, new(httptrace.NopTracer))
			if isScanner() {
				reg.stateLock()
				if reg.state.Status == api.RegistryStatusScanning {
					if reg.sctx != nil {
						reg.stopScan()
					}
					reg.startScan()
				}
				reg.stateUnlock()
			}
		}
	}
}

func GetProxy(registry string) string {
	u, err := url.Parse(registry)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error()
		return ""
	}

	// Check if proxy should be skipped for the registry URL
	var httpProxy, httpsProxy, noProxy string
	if global.RT != nil { // in case of unitest
		httpProxy, httpsProxy, noProxy = global.RT.GetProxy()
		noProxyHosts := strings.Split(noProxy, ",")
		for _, noProxyHost := range noProxyHosts {
			if noProxyHost != "" {
				noProxyHost = strings.Replace(noProxyHost, "*", ".*", -1)
				if regx, err := regexp.Compile(noProxyHost); err == nil && regx.MatchString(u.Hostname()) {
					smd.scanLog.WithFields(log.Fields{"hostname": u.Hostname(), "noProxyHost": noProxyHost}).Debug("No need proxy")
					return ""
				}
			}
		}
	}

	// Return configured proxy if enabled, otherwise return container runtime's settings
	if u.Scheme == "https" {
		if smd.httpsProxy != "" {
			return smd.httpsProxy
		} else {
			return httpsProxy
		}
	} else {
		if smd.httpProxy != "" {
			return smd.httpProxy
		} else {
			return httpProxy
		}
	}
}

func RegTaskCount() int {
	var count int

	if regScher != nil {
		count = regScher.TaskCount()
	}

	return count
}
