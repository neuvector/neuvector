package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/cvetools"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"

	"github.com/neuvector/neuvector/controller/api"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: scan [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

const taskerPath = "/usr/local/bin/scannerTask"
const registerWaitTime = time.Duration(time.Second * 10)
const licenseTimeFormat string = "2006-01-02"

var ntChan chan uint32 = make(chan uint32, 1)
var cveTools *cvetools.CveTools // available inside package
var scanTasker *Tasker          // available inside package
var selfID string

func dbRead(path string, maxRetry int, output bool) map[string]*share.ScanVulnerability {
	dbFile := path + share.DefaultCVEDBName

	var retry int
	var dbReady bool
	var dbData map[string]*share.ScanVulnerability

	for {
		if _, err := os.Stat(dbFile); err != nil {
			log.WithFields(log.Fields{"file": dbFile}).Error("cannot find scanner db")
		} else {
			cveTools.UpdateMux.Lock()
			if verNew, createTime, hasAlpineTb, hasAmazonTb, err := common.LoadCveDb(path, cveTools.TbPath); err == nil {
				cveTools.CveDBVersion = verNew
				cveTools.CveDBCreateTime = createTime
				cveTools.Update.Redhat = true
				cveTools.Update.Debian = true
				cveTools.Update.Ubuntu = true
				if hasAlpineTb {
					cveTools.Update.Alpine = true
					cveTools.SupportOs.Add("alpine")
				}
				if hasAmazonTb {
					cveTools.Update.Amazon = true
					cveTools.SupportOs.Add("amzn")
				}
				if dbData, err = common.ReadCveDbMeta(cveTools.TbPath, hasAlpineTb, hasAmazonTb, output); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Failed to load scanner db")
				} else {
					dbReady = true
				}
			}
			cveTools.UpdateMux.Unlock()
		}

		if !dbReady {
			retry++
			if maxRetry != 0 && retry == maxRetry {
				return nil
			}

			time.Sleep(time.Second * 4)
		} else {
			return dbData
		}
	}
}

func connectController(path, advIP, joinIP, selfID string, advPort uint32, joinPort uint16, output bool) {
	cb := &clientCallback{
		shutCh:         make(chan interface{}, 1),
		ignoreShutdown: true,
	}

	for {
		// forever retry
		dbData := dbRead(path, 0, output)
		scanner := share.ScannerRegisterData{
			CVEDBVersion:    cveTools.CveDBVersion,
			CVEDBCreateTime: cveTools.CveDBCreateTime,
			CVEDB:           dbData,
			RPCServer:       advIP,
			RPCServerPort:   advPort,
			ID:              selfID,
		}

		for scannerRegister(joinIP, joinPort, &scanner, cb) != nil {
			time.Sleep(registerWaitTime)
		}

		// tagging it as a released-memory
		scanner.CVEDB = nil
		dbData = make(map[string]*share.ScanVulnerability) // zero size

		// start responding shutdown notice
		cb.ignoreShutdown = false
		<-cb.shutCh
		cb.ignoreShutdown = true
	}
}

// TODO: sidecar implementation might have two app pods
func adjustContainerPod(selfID string, containers []*container.ContainerMeta) string {
	for _, c := range containers {
		if v, ok := c.Labels["io.kubernetes.sandbox.id"]; ok {
			if v == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Update")
				return c.ID
			}
		}

		if c.Sandbox != c.ID { // a child
			if c.Sandbox != "" && c.Sandbox == selfID {
				log.WithFields(log.Fields{"Pod": selfID, "ID": c.ID}).Debug("Updated")
				return c.ID
			}
		}
	}
	return selfID
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "SCN"})

	dbPath := flag.String("d", "./dbgen/", "cve database file directory")
	join := flag.String("j", "", "Controller join address")
	joinPort := flag.Uint("join_port", 0, "Controller join port")
	adv := flag.String("a", "", "Advertise address")
	advPort := flag.Uint("adv_port", 0, "Advertise port")
	rtSock := flag.String("u", "unix:///var/run/docker.sock", "Container socket URL") // used for scan local image
	showTaskDebug := flag.Bool("g", true, "Show task debug information")
	getVer := flag.Bool("v", false, "show cve database version")
	// for on demand ci/cd scan
	license := flag.String("license", "", "Scanner license") // it means on-demand stand-alone scanner
	registry := flag.String("registry", "", "Scan image registry")
	repository := flag.String("repository", "", "Scan image repository")
	tag := flag.String("tag", "latest", "Scan image tag")
	regUser := flag.String("registry_username", "", "Registry username")
	regPass := flag.String("registry_password", "", "Registry password")
	scanLayers := flag.Bool("scan_layers", false, "Scan image layers")
	baseImage := flag.String("base_image", "", "Base image")
	ctrlUser := flag.String("ctrl_username", "", "Controller REST API username")
	ctrlPass := flag.String("ctrl_password", "", "Controller REST API password")
	noWait := flag.Bool("no_wait", false, "No initial wait")
	output := flag.Bool("output", false, "Output CVEDB in json format")

	flag.Usage = usage
	flag.Parse()

	// acquire tool
	sys := system.NewSystemTools()
	cveTools = cvetools.NewCveTools(*rtSock, scan.NewScanUtil(sys))

	var onDemand bool

	// show cve database version
	if *getVer {
		if v, _, err := common.GetDbVersion(*dbPath); err == nil {
			fmt.Printf("CVE database version: %.3f\n", v)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(-2)
		}
		return
	}

	// If license parameter is given, this is an on-demand scanner, no register to the controller,
	// but if join address is given, the scan result are sent to the controller.
	if *license != "" {
		if *repository == "" || *tag == "" {
			log.Error("Missing the repository name and tag of the image to be scanned")
			os.Exit(-2)
		}

		onDemand = true
	}

	// recovered, clean up all possible previous image folders
	os.RemoveAll(scan.ImageWorkingPath)
	os.MkdirAll(scan.ImageWorkingPath, 0755)

	var err error
	if sys.IsRunningInContainer() {
		selfID, _, err = sys.GetSelfContainerID() // it is a POD ID in the k8s cgroup v2; otherwise, a real container ID
		if selfID == "" {
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
	} else {
		log.Info("Not running in container.")
	}

	if rtSock != nil {
		if platform, _, _, containers, err := global.SetGlobalObjects(*rtSock, nil); err == nil {
			if platform == share.PlatformKubernetes {
				selfID = adjustContainerPod(selfID, containers)
			}
		}
	}

	scanTasker = newTasker(taskerPath, *rtSock, *showTaskDebug, sys)
	if scanTasker != nil {
		log.Info("Use scannerTask")
		defer scanTasker.Close()
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c_sig
		done <- true
	}()

	if onDemand {
		req := &share.ScanImageRequest{
			Registry:    *registry,
			Repository:  *repository,
			Tag:         *tag,
			Username:    *regUser,
			Password:    *regPass,
			ScanLayers:  *scanLayers,
			ScanSecrets: true,
			BaseImage:   *baseImage,
		}

		// DB read error printed inside dbRead()
		dbData := dbRead(*dbPath, 3, false)
		if dbData != nil {
			result := scanOnDemand(req, dbData)

			// submit scan result if join address is given
			if result != nil && result.Error == share.ScanErrorCode_ScanErrNone &&
				*join != "" && *ctrlUser != "" && *ctrlPass != "" {
				if *adv == "" {
					_, addr, err := cluster.ResolveJoinAndBindAddr(*join, sys)
					if err != nil {
						log.WithFields(log.Fields{"error": err}).Error()
						os.Exit(-2)
					}

					adv = &addr
				}
				if *joinPort == 0 {
					port := (uint)(api.DefaultControllerRESTAPIPort)
					joinPort = &port
				}

				err := scanSubmitResult(*join, (uint16)(*joinPort), *adv, *ctrlUser, *ctrlPass, result)
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Failed to sumit scan result")
				} else {
					log.Info("Scan result submitted.")
				}
			}
		}

		return
	}

	// Block until server is up.
	grpcServer := startGRPCServer()
	defer grpcServer.Stop()

	if !(*noWait) {
		// Intentionally introduce some delay so scanner IP can be populated to all enforcers
		log.Info("Wait 15s ...")
		time.Sleep(time.Second * 15)
	}

	if *adv == "" {
		_, addr, err := cluster.ResolveJoinAndBindAddr(*join, sys)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			os.Exit(-2)
		}

		adv = &addr
	}
	if *advPort == 0 {
		port := (uint)(cluster.DefaultScannerGRPCPort)
		advPort = &port
	}
	if *joinPort == 0 {
		port := (uint)(cluster.DefaultControllerGRPCPort)
		joinPort = &port
	}

	if selfID == "" {
		// if not running in container
		selfID = *adv
	}

	// Use the original address, which is the service name, so when controller changes,
	// new IP can be resolved
	go connectController(*dbPath, *adv, *join, selfID, (uint32)(*advPort), (uint16)(*joinPort), *output)
	<-done

	log.Info("Exiting ...")
	scannerDeregister(*join, (uint16)(*joinPort), selfID)
}
