package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	rpmdb "github.com/neuvector/go-rpmdb/pkg"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

var RPMPkgFiles utils.Set = utils.NewSet(
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages",
	"var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages.db",
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
)

const (
	DpkgStatus    = "var/lib/dpkg/status"
	DpkgStatusDir = "var/lib/dpkg/status.d/" // used by distroless images
	apkPackages   = "lib/apk/db/installed"
)

var OSPkgFiles utils.Set = utils.NewSet(
	// rpm files are added as union
	DpkgStatus,
	DpkgStatusDir,
	apkPackages,
	"etc/lsb-release",
	"etc/os-release",
	"usr/lib/os-release",
	"etc/centos-release",
	"etc/redhat-release",
	"etc/system-release",
	"etc/fedora-release",
	"etc/apt/sources.list",
).Union(RPMPkgFiles)

var scanErrString = []string{
	share.ScanErrorCode_ScanErrNone:                "succeeded",
	share.ScanErrorCode_ScanErrNetwork:             "network error",
	share.ScanErrorCode_ScanErrNotSupport:          "unsupported OS",
	share.ScanErrorCode_ScanErrSizeOverLimit:       "file size over limit",
	share.ScanErrorCode_ScanErrPackage:             "package error",
	share.ScanErrorCode_ScanErrDatabase:            "database error",
	share.ScanErrorCode_ScanErrTimeout:             "timeout",
	share.ScanErrorCode_ScanErrInProgress:          "scan in progress",
	share.ScanErrorCode_ScanErrRegistryAPI:         "registry API error",
	share.ScanErrorCode_ScanErrFileSystem:          "access file system error",
	share.ScanErrorCode_ScanErrContainerAPI:        "container API call error",
	share.ScanErrorCode_ScanErrXrayAPI:             "Xray API call error",
	share.ScanErrorCode_ScanErrContainerExit:       "container exit",
	share.ScanErrorCode_ScanErrAuthentication:      "authentication error",
	share.ScanErrorCode_ScanErrCertificate:         "certificate error",
	share.ScanErrorCode_ScanErrCanceled:            "scan canceled",
	share.ScanErrorCode_ScanErrDriverAPINotSupport: "driver API not supported",
	share.ScanErrorCode_ScanErrImageNotFound:       "Image not found",
	share.ScanErrorCode_ScanErrAwsDownloadErr:      "Aws Resource download error",
	share.ScanErrorCode_ScanErrArgument:            "invalid input arguments",
}

type CacheRecord struct {
	Layer   string    `json:"layerID,omitempty"`
	Size    uint64    `json:"size,omitempty"`
	RefCnt  uint32    `json:"ref_cnt,omitempty"`
	RefLast time.Time `json:"ref_last,omitempty"`
}

type CacherData struct {
	CacheRecords  []CacheRecord `json:"cache_records,omitempty"`
	MissCnt       uint64        `json:"cache_misses,omitempty"`
	HitCnt        uint64        `json:"cache_hits,omitempty"`
	CurRecordSize uint64        `json:"current_record_size"`
}

func ScanErrorToStr(e share.ScanErrorCode) string {
	if e >= 0 && int(e) < len(scanErrString) {
		return scanErrString[e]
	} else {
		return fmt.Sprintf("unknown error: %v", e)
	}
}

type ScanUtil struct {
	sys *system.SystemTools
}

// Scan normally doesn't require contaiener runtime socket, except for local image scan
func NewScanUtil(sys *system.SystemTools) *ScanUtil {
	s := &ScanUtil{
		sys: sys,
	}
	return s
}

func (s *ScanUtil) readRunningPackages(id string, pid int, prefix, kernel string, pidHost bool) ([]utils.TarFileInfo, bool) {
	var files []utils.TarFileInfo
	var hasPackage bool
	for itr := range OSPkgFiles.Iter() {
		var data []byte
		var err error

		lib := itr.(string)
		path := s.sys.ContainerFilePath(pid, prefix+lib)

		// Extract necessary packages
		if RPMPkgFiles.Contains(lib) {
			data, err = GetRpmPackages(path, kernel)
			if err != nil {
				continue
			}
			hasPackage = true
		} else if lib == DpkgStatusDir {
			dpkgfiles, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range dpkgfiles {
				filepath := fmt.Sprintf("%s%s", path, file.Name())
				filedata, err := GetDpkgStatus(filepath, kernel)
				if err != nil {
					continue
				}
				name := fmt.Sprintf("%s%s", DpkgStatusDir, file.Name())
				files = append(files, utils.TarFileInfo{Name: name, Body: filedata})
			}
			hasPackage = true
			continue
		} else if lib == DpkgStatus {
			//get the dpkg status file
			data, err = GetDpkgStatus(path, kernel)
			if err != nil {
				continue
			}
			hasPackage = true
		} else {
			// NVSHAS-5589, on some containers, we somehow identify the base os as the host's os.
			// The container shares host mount and pid namespace, but it still shouldn't result in this.
			// The real cause is unknown, switching the namespace fixes the problem.

			if pid != 1 && !pidHost && strings.HasSuffix(lib, "release") {
				data, err = s.sys.NsGetFile(prefix+lib, pid, false, 0, 0)
			} else {
				data, err = s.sys.ReadContainerFile(prefix+lib, pid, 0, 0)
			}

			if err != nil {
				continue
			}
			if lib == apkPackages {
				hasPackage = true
			}
		}

		files = append(files, utils.TarFileInfo{Name: lib, Body: data})
	}
	return files, hasPackage
}

func (s *ScanUtil) GetRunningPackages(id string, objType share.ScanObjectType, pid int, kernel string, pidHost bool) ([]byte, share.ScanErrorCode) {
	files, hasPkgMgr := s.readRunningPackages(id, pid, "/", kernel, pidHost)
	if len(files) == 0 && !hasPkgMgr && objType == share.ScanObjectType_HOST {
		// In RancherOS, host os-release file is at /host/proc/1/root/usr/etc/os-release
		// but sometimes this file is not accessible.
		files, _ /*hasPkgMgr*/ = s.readRunningPackages(id, pid, "/usr/", kernel, pidHost)
	}

	if objType == share.ScanObjectType_CONTAINER {
		// We may still have data when there is an error, such as timeout
		data, err := s.getContainerAppPkg(pid)
		if err != nil {
			log.WithFields(log.Fields{"data": len(data), "error": err}).Error("Error when getting container app packages")
		}
		if len(data) > 0 {
			files = append(files, utils.TarFileInfo{Name: AppFileName, Body: data})
		}
	}

	if len(files) == 0 {
		log.WithFields(log.Fields{"id": id}).Debug("Empty libary files")
		return nil, share.ScanErrorCode_ScanErrNotSupport
	}
	buf, err := utils.MakeTar(files)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("make TAR error")
		return nil, share.ScanErrorCode_ScanErrFileSystem
	}

	return buf.Bytes(), share.ScanErrorCode_ScanErrNone
}

func (s *ScanUtil) GetAppPackages(path string) ([]AppPackage, []byte, share.ScanErrorCode) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, share.ScanErrorCode_ScanErrFileSystem
	} else if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, nil, share.ScanErrorCode_ScanErrNotSupport
	}

	apps := NewScanApps(true)
	apps.ExtractAppPkg(path, path)
	pkgs := apps.marshal()
	files := []utils.TarFileInfo{{Name: AppFileName, Body: pkgs}}
	buf, _ := utils.MakeTar(files)
	appPkgs := apps.Data()[path]
	return appPkgs, buf.Bytes(), share.ScanErrorCode_ScanErrNone
}

func (s *ScanUtil) getContainerAppPkg(pid int) ([]byte, error) {
	apps := NewScanApps(false) // no need to scan the same file twice
	exclDirs := utils.NewSet("boot", "dev", "proc", "run", "sys")
	rootPath := s.sys.ContainerFilePath(pid, "/")
	rootLen := len(rootPath)

	bTimeoutFlag := false
	go func() {
		time.Sleep(time.Duration(120) * time.Second)
		bTimeoutFlag = true
	}()

	// recursive the possible node/jar directories
	walkErr := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if bTimeoutFlag {
			return errors.New("Timeout")
		}

		if info.IsDir() {
			inpath := path[rootLen:]
			tokens := strings.Split(inpath, "/")
			if len(tokens) > 0 && exclDirs.Contains(tokens[0]) {
				return filepath.SkipDir
			}
			if utils.IsMountPoint(path) {
				return filepath.SkipDir
			}
		} else if info.Mode().IsRegular() && info.Size() > 0 {
			if utils.IsMountPoint(path) {
				return nil
			}
			inpath := path[rootLen:]
			apps.ExtractAppPkg(inpath, path)
		}
		return nil
	})

	return apps.marshal(), walkErr
}

type RPMPackage struct {
	Name    string `json:"n"`
	Epoch   int    `json:"e"`
	Version string `json:"v"`
	Release string `json:"r"`
}

func isRpmKernelPackage(p *rpmdb.PackageInfo) string {
	if p.Name == "kernel " ||
		p.Name == "kernel-tools-libs" ||
		p.Name == "kernel-default" ||
		p.Name == "kernel-tools" ||
		p.Name == "kernel-core" ||
		p.Name == "kernel-modules" ||
		p.Name == "kernel-headers" {
		return fmt.Sprintf("%s-%s", p.Version, p.Release)
	} else {
		return ""
	}
}

func GetRpmPackages(fullpath, kernel string) ([]byte, error) {
	if strings.HasPrefix(fullpath, "/proc/") || strings.HasPrefix(fullpath, "/host/proc/") {
		// container scans
		if rpmFile, err := os.Open(fullpath); err != nil {
			// log.WithFields(log.Fields{"file": fullpath, "error": err}).Error()
			return nil, err
		} else {
			tempDir, err := os.MkdirTemp("", "")
			if err == nil {
				defer os.RemoveAll(tempDir)
			}
			dstPath := filepath.Join(tempDir, filepath.Base(fullpath)) // retain the filename
			if dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666); err == nil {
				if _, err := io.Copy(dstFile, rpmFile); err == nil {
					fullpath = dstPath // updated
				}
				dstFile.Close()
			} else {
				log.WithFields(log.Fields{"file": dstPath, "error": err}).Error("failed: Copy")
			}
			rpmFile.Close()
		}
	}

	db, err := rpmdb.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"file": fullpath, "error": err}).Error("Failed to open rpm packages")
		return nil, err
	}
	defer db.Close()

	pkgs, err := db.ListPackages()
	if err != nil {
		log.WithFields(log.Fields{"file": fullpath, "error": err}).Error("Failed to read rpm packages")
		return nil, err
	}

	log.WithFields(log.Fields{"file": fullpath, "kernel": kernel, "packages": len(pkgs)}).Info()

	list := make([]RPMPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name != "gpg-pubkey" {
			var epoch int
			if p.Epoch != nil {
				epoch = *p.Epoch
			}

			if kernel == "" {
				list = append(list, RPMPackage{Name: p.Name, Epoch: epoch, Version: p.Version, Release: p.Release})
			} else {
				// filter kernels that are not running
				if k := isRpmKernelPackage(p); k == "" || strings.HasPrefix(kernel, k) {
					list = append(list, RPMPackage{Name: p.Name, Epoch: epoch, Version: p.Version, Release: p.Release})
				}
			}
		}
	}

	value, _ := json.Marshal(&list)
	return value, nil
}

func isDpkgKernelPackage(line string) string {
	pkg := strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
	if strings.HasSuffix(pkg, "-virtual") {
		// ignore kernel virtual package
		return ""
	} else if strings.HasPrefix(pkg, "linux-headers-") {
		return strings.TrimPrefix(pkg, "linux-headers-")
	} else if strings.HasPrefix(pkg, "linux-image-") {
		return strings.TrimPrefix(pkg, "linux-image-")
	} else if strings.HasPrefix(pkg, "linux-image-extra-") {
		return strings.TrimPrefix(pkg, "linux-image-extra-")
	} else {
		return ""
	}
}

func GetDpkgStatus(fullpath, kernel string) ([]byte, error) {
	inputFile, err := os.Open(fullpath)
	if err != nil {
		return nil, err
	}
	defer inputFile.Close()

	log.WithFields(log.Fields{"file": fullpath, "kernel": kernel}).Info()

	skipPackage := false

	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// filter kernels that are not running
		if strings.HasPrefix(line, "Package: ") && kernel != "" {
			kpkg := isDpkgKernelPackage(line)
			if kpkg == "" {
				skipPackage = false
			} else if kpkg == kernel {
				skipPackage = false
			} else {
				skipPackage = true
				continue
			}
		} else if skipPackage {
			continue
		}

		if strings.HasPrefix(line, "Package: ") ||
			strings.HasPrefix(line, "Status: ") ||
			strings.HasPrefix(line, "Source: ") ||
			strings.HasPrefix(line, "Version: ") ||
			line == "" {
			buf.WriteString(line)
			buf.WriteString("\n")

			/*
				if strings.Contains(line, "apt") {
					aptVersion = true
					log.WithFields(log.Fields{"package": line}).Error("======")
				}
				if strings.HasPrefix(line, "Version: ") && aptVersion {
					aptVersion = false
					log.WithFields(log.Fields{"version": line}).Error("======")
				}
			*/
		}
	}
	return buf.Bytes(), nil
}

func ParseRegistryURI(ur string) (string, error) {
	u, err := url.ParseRequestURI(ur)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "url": ur}).Error("Failed parse registry url")
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("Unsupport registry schema")
	}
	uf := u.String()
	if !strings.HasSuffix(uf, "/") {
		uf += "/"
	}
	return uf, nil
}

var dockerRegistries = utils.NewSet("https://docker.io/", "https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/")

// Not a strict parsing, if the input is wrong, we just cannot get the image.
func ParseImageName(image string) (string, string, string, error) {
	var reg, repo, tag string

	if strings.HasPrefix(image, "https://") {
		if slash := strings.Index(image[8:], "/"); slash != -1 {
			reg = image[:slash+8]
			image = image[slash+9:]

			var err error
			if reg, err = ParseRegistryURI(reg); err != nil {
				return image, "", "", err
			}
		} else {
			return image, "", "", errors.New("Invalid base image name")
		}
	} else if strings.HasPrefix(image, "http://") {
		if slash := strings.Index(image[7:], "/"); slash != -1 {
			reg = image[:slash+7]
			image = image[slash+8:]

			var err error
			if reg, err = ParseRegistryURI(reg); err != nil {
				return image, "", "", err
			}
		} else {
			return image, "", "", errors.New("Invalid base image name")
		}
	}

	if colon := strings.LastIndex(image, ":"); colon != -1 {
		repo = image[:colon]
		tag = image[colon+1:]
	} else {
		repo = image
		tag = "latest"
	}

	if dockerRegistries.Contains(reg) && !strings.Contains(repo, "/") {
		repo = fmt.Sprintf("library/%s", repo)
	}

	return reg, repo, tag, nil
}

func parseSocketFromRepo(repo string) (string, string) {
	if strings.HasPrefix(repo, "tcp://") {
		n := strings.Index(strings.TrimPrefix(repo, "tcp://"), "/")
		if n > 0 {
			return repo[:n+6], repo[n+6+1:]
		}
	}

	return "", repo
}

// --

var userRegexp = regexp.MustCompile(`USER ([a-zA-Z0-9_\-.]+)`)

func NormalizeImageCmd(cmd string) string {
	if s := strings.Index(cmd, "/bin/sh -c "); s != -1 {
		cmd = strings.TrimSpace(cmd[s+11:])
		if strings.HasPrefix(cmd, "#(nop) ") {
			cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "#(nop) "))
		} else {
			cmd = fmt.Sprintf("RUN %s", cmd)
		}
	}
	return cmd
}

func ParseImageCmds(cmds []string) (bool, bool, bool) {
	var runAsRoot, hasADD, hasHEALTHCHECK bool
	var hasUser bool

	runAsRoot = true
	for _, cmd := range cmds {
		if !hasUser {
			r := userRegexp.FindStringSubmatch(cmd)
			if len(r) == 2 {
				if r[1] == "root" || r[1] == "0" {
					runAsRoot = true
				} else {
					runAsRoot = false
				}
				hasUser = true
			}
		}
		if strings.HasPrefix(cmd, "ADD ") {
			line := strings.TrimSpace(strings.TrimPrefix(cmd, "ADD "))
			if !strings.HasPrefix(line, "file:") {
				hasADD = true
			}
		}
		if strings.HasPrefix(cmd, "HEALTHCHECK ") {
			hasHEALTHCHECK = true
		}
	}

	return runAsRoot, hasADD, hasHEALTHCHECK
}

// --
func DownloadFromUrl(url, fileName string) error {

	output, err := os.Create(fileName)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error creating file")
		return err
	}
	defer output.Close() // clean up

	response, err := http.Get(url)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error downloading file")
		return err
	}
	defer response.Body.Close()

	_, err = io.Copy(output, response.Body)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "filename": fileName}).Debug("Error copy file")
		return err
	}
	return nil
}

func GetAwsFuncPackages(fileName string) ([]*share.ScanAppPackage, error) {
	r, err := zip.OpenReader(fileName)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("open func name fail")
		return nil, err
	}
	defer r.Close()
	defer os.Remove(fileName) // clean up

	apps := NewScanApps(true)
	tmpDir, err := os.MkdirTemp(os.TempDir(), "scan_lambda")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Create temp directory fail")
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	for _, file := range r.File {
		if IsAppsPkgFile(file.Name, file.Name) {
			zFile, err := file.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Debug("open zipped file fail")
				continue
			}
			defer zFile.Close()

			tmpfile, err := os.CreateTemp(tmpDir, "extract")
			if err != nil {
				log.WithFields(log.Fields{"err": err, "filename": file.Name}).Error("write to temp file fail")
				continue
			}
			if nb, err := io.Copy(tmpfile, zFile); err != nil || nb == 0 {
				if err != nil {
					log.WithFields(log.Fields{"err": err, "filename": file.Name}).Error("copy file fail")
					continue
				}
			}
			defer os.Remove(tmpfile.Name()) // clean up
			apps.ExtractAppPkg(file.Name, tmpfile.Name())
		}
	}
	var appPkg []*share.ScanAppPackage
	for _, v := range apps.pkgs {
		for _, vt := range v {

			filename := strings.Replace(vt.FileName, "/package.json", "", -1)
			pckg := &share.ScanAppPackage{
				AppName:    vt.AppName,
				ModuleName: vt.ModuleName,
				Version:    vt.Version,
				FileName:   filename,
			}
			appPkg = append(appPkg, pckg)
		}
	}
	return appPkg, nil
}
