package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/container/dockerclient"
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
	dpkgStatus    = "var/lib/dpkg/status"
	dpkgStatusDir = "var/lib/dpkg/status.d/" // used by distroless images
	apkPackages   = "lib/apk/db/installed"
)

const (
	//max package file size
	maxFileSize     = 300 * 1024 * 1024
	manifestJson    = "manifest.json"
	layerJson       = "/json"
	contentManifest = "root/buildinfo/content_manifests"
	dockerfile      = "root/buildinfo/Dockerfile-"
)

var libsList utils.Set = utils.NewSet(
	// rpm files are added as union
	dpkgStatus,
	dpkgStatusDir,
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

type ImageManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type downloadLayerResult struct {
	layer   string
	Size    int64
	TarSize int64
	err     error
}

// Scan normally doesn't require contaiener runtime socket, except for local image scan
func NewScanUtil(sys *system.SystemTools) *ScanUtil {
	s := &ScanUtil{
		sys: sys,
	}
	return s
}

func (s *ScanUtil) readRunningPackages(id string, pid int, prefix, kernel string) ([]utils.TarFileInfo, bool) {
	var files []utils.TarFileInfo
	var hasPackage bool

	for itr := range libsList.Iter() {
		var data []byte
		var err error

		lib := itr.(string)
		path := s.sys.ContainerFilePath(pid, prefix+lib)

		// Extract necessary packages
		if RPMPkgFiles.Contains(lib) {
			data, err = getRpmPackages(path, kernel)
			if err != nil {
				continue
			}
			hasPackage = true
		} else if lib == dpkgStatusDir {
			dpkgfiles, err := ioutil.ReadDir(path)
			if err != nil {
				continue
			}
			for _, file := range dpkgfiles {
				filepath := fmt.Sprintf("%s%s", path, file.Name())
				filedata, err := getDpkgStatus(filepath, kernel)
				if err != nil {
					continue
				}
				name := fmt.Sprintf("%s%s", dpkgStatusDir, file.Name())
				files = append(files, utils.TarFileInfo{name, filedata})
			}
			hasPackage = true
			continue
		} else if lib == dpkgStatus {
			//get the dpkg status file
			data, err = getDpkgStatus(path, kernel)
			if err != nil {
				continue
			}
			hasPackage = true
		} else {
			// NVSHAS-5589, on some containers, we somehow identify the base os as the host's os.
			// The container shares host mount and pid namespace, but it still shouldn't result in this.
			// The real cause is unknown, switching the namespace fixes the problem.
			if pid != 1 && strings.HasSuffix(lib, "release") {
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

		files = append(files, utils.TarFileInfo{lib, data})
	}
	return files, hasPackage
}

func (s *ScanUtil) GetRunningPackages(id string, objType share.ScanObjectType, pid int, kernel string) ([]byte, share.ScanErrorCode) {
	files, hasPkgMgr := s.readRunningPackages(id, pid, "/", kernel)
	if len(files) == 0 && !hasPkgMgr && objType == share.ScanObjectType_HOST {
		// In RancherOS, host os-release file is at /host/proc/1/root/usr/etc/os-release
		// but sometimes this file is not accessible.
		files, hasPkgMgr = s.readRunningPackages(id, pid, "/usr/", kernel)
	}

	if objType == share.ScanObjectType_CONTAINER {
		// We may still have data when there is an error, such as timeout
		data, err := s.getContainerAppPkg(pid)
		if err != nil {
			log.WithFields(log.Fields{"data": len(data), "error": err}).Error("Error when getting container app packages")
		}
		if len(data) > 0 {
			files = append(files, utils.TarFileInfo{AppFileName, data})
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

func (s *ScanUtil) getContainerAppPkg(pid int) ([]byte, error) {
	apps := NewScanApps(true)
	exclDirs := utils.NewSet("bin", "boot", "dev", "proc", "run", "sys", "tmp")
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
			apps.extractAppPkg(inpath, path)
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

func getRpmPackages(fullpath, kernel string) ([]byte, error) {
	db, err := rpmdb.Open(fullpath)
	if err != nil {
		return nil, err
	}

	pkgs, err := db.ListPackages()
	if err != nil {
		log.WithFields(log.Fields{"file": fullpath, "kernel": kernel}).Error("Failed to read rpm packages")
		return nil, err
	}

	log.WithFields(log.Fields{"file": fullpath, "kernel": kernel, "packages": len(pkgs)}).Info()

	list := make([]RPMPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name != "gpg-pubkey" {
			if kernel == "" {
				list = append(list, RPMPackage{Name: p.Name, Epoch: p.Epoch, Version: p.Version, Release: p.Release})
			} else {
				// filter kernels that are not running
				if k := isRpmKernelPackage(p); k == "" || strings.HasPrefix(kernel, k) {
					list = append(list, RPMPackage{Name: p.Name, Epoch: p.Epoch, Version: p.Version, Release: p.Release})
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

func getDpkgStatus(fullpath, kernel string) ([]byte, error) {
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

func getApkPackages(fullpath string) ([]byte, error)  {
	inputFile, err := os.Open(fullpath)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "P:") ||
			strings.HasPrefix(line, "V:") ||
			strings.HasPrefix(line, "o:") ||
			line == "" {
			buf.WriteString(line)
			buf.WriteString("\n")
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

	if dockerRegistries.Contains(reg) && strings.Index(repo, "/") == -1 {
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

func (s *ScanUtil) GetLocalImageMeta(ctx context.Context, repository, tag, rtSock string) (*container.ImageMeta, share.ScanErrorCode) {
	sock, repo := parseSocketFromRepo(repository)
	if sock == "" {
		sock = rtSock
	}

	rt, err := container.ConnectDocker(sock, s.sys)
	if err != nil {
		log.WithFields(log.Fields{"repo": repository, "tag": tag, "error": err}).Error("Connect docker server fail")
		return nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	meta, err := rt.GetImage(fmt.Sprintf("%s:%s", repo, tag))
	if err != nil {
		log.WithFields(log.Fields{"repo": repository, "tag": tag, "error": err}).Error("Failed to get local image")
		if err == dockerclient.ErrImageNotFound {
			return nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	return meta, share.ScanErrorCode_ScanErrNone
}

func (s *ScanUtil) LoadLocalImage(ctx context.Context, repository, tag, rtSock, imgPath string) (*ImageInfo, map[string]*LayerFiles, []string, share.ScanErrorCode) {
	sock, repo := parseSocketFromRepo(repository)
	if sock == "" {
		sock = rtSock
	}

	rt, err := container.ConnectDocker(sock, s.sys)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Connect docker server fail")
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	imageName := fmt.Sprintf("%s:%s", repo, tag)

	meta, err := rt.GetImage(imageName)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get local image")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	histories, err := rt.GetImageHistory(imageName)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get local image history")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	file, err := rt.GetImageFile(meta.ID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to get image")
		if err == dockerclient.ErrImageNotFound {
			return nil, nil, nil, share.ScanErrorCode_ScanErrImageNotFound
		} else if err == container.ErrMethodNotSupported {
			return nil, nil, nil, share.ScanErrorCode_ScanErrDriverAPINotSupport
		}
		return nil, nil, nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	// create an image file and image layered folders
	repoFolder := filepath.Join(imgPath, "repo")
	os.MkdirAll(repoFolder, 0755)
	defer os.RemoveAll(repoFolder)

	// save the image
	imageFile := filepath.Join(repoFolder, "image.tar")
	out, err := os.OpenFile(imageFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err == nil {
		_, err = io.Copy(out, file)
		out.Close()
	}
	file.Close()
	if err != nil {
		log.Errorf("could not write to image: %s", err)
		return nil, nil, nil, share.ScanErrorCode_ScanErrFileSystem
	}

	// obtain layer information, then extract the layers into tar files
	layers, _, _, _, err := getImageLayers(repoFolder, imageFile)
	if err != nil {
		log.Errorf("could not extract image layers: %s", err)
		return nil, nil, nil, share.ScanErrorCode_ScanErrPackage
	}

	layerFiles, errCode := getImageLayerIterate(ctx, layers, nil, false, imgPath,
		func(ctx context.Context, layer string) (interface{}, int64, error) {
			layer += "_layer.tar" // restore file name
			layerTarPath := filepath.Join(repoFolder, layer)
			file, err := os.Open(layerTarPath)
			if err != nil {
				return nil, -1, err
			}
			stat, err := file.Stat()
			if err != nil {
				return nil, -1, err
			}
			var bytes int64
			bytes = stat.Size()
			return file, bytes, nil
		})

	// GetImage(sha256:xxxx) and getImageLayers (yyyy) return different sets of layer ID, make them consistent.
	// In the "inspect image" CLI command, users can only read the "sha256:xxxx" list.
	// however, "yyyy" is the real data storage and referrable.
	var tarLayers []string
	for i, l2 := range layers {
		tarLayers = append(tarLayers, l2)
		l1 := meta.Layers[i]
		if files, ok := layerFiles[l2]; ok {
			layerFiles[l1] = files
			delete(layerFiles, l2)
		}
	}

	// Use cmds from "docker history" API, add 0-sized layer back in.
	layers = make([]string, len(histories))
	cmds := make([]string, len(histories))
	ml := 0
	lenML := len(meta.Layers)
	for i, h := range histories {
		cmds[i] = NormalizeImageCmd(h.Cmd)
		if h.Size > 0 {
			// Some layer size is 0, remove them from layerFiles and layers, otherwise, layers won't match with history
			for ml < lenML {
				l := meta.Layers[ml]
				if files, ok := layerFiles[l]; ok {
					if files.Size > 0 {
						layers[i] = meta.Layers[ml]
						ml++
						break
					} else {
						delete(layerFiles, l)
						ml++
					}
				} else {
					// shouldn't happen, advance ml
					ml++
				}
			}
		} else {
			layers[i] = ""
		}
	}

	repoInfo := &ImageInfo{
		ID:       meta.ID,
		Digest:   meta.Digest,
		Layers:   layers,
		Cmds:     cmds,
		Envs:     meta.Env,
		Labels:   meta.Labels,
		RepoTags: meta.RepoTags,
	}

	return repoInfo, layerFiles, tarLayers, errCode
}

type LayerMetadata struct {
	ID              string    `json:"id"`
	Parent          string    `json:"parent"`
	Created         time.Time `json:"created"`
	Container       string    `json:"container"`
	ContainerConfig struct {
		Hostname   string            `json:"Hostname"`
		Domainname string            `json:"Domainname"`
		User       string            `json:"User"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"container_config"`
	Config struct {
		Hostname    string            `json:"Hostname"`
		Domainname  string            `json:"Domainname"`
		User        string            `json:"User"`
		Env         []string          `json:"Env"`
		Cmd         []string          `json:"Cmd"`
		ArgsEscaped bool              `json:"ArgsEscaped"`
		Image       string            `json:"Image"`
		WorkingDir  string            `json:"WorkingDir"`
		Labels      map[string]string `json:"Labels"`
	} `json:"config"`
	Architecture string `json:"architecture"`
	Os           string `json:"os"`
}

func getImageLayers(tmpDir string, imageTar string) ([]string, []string, []string, map[string]string, error) {
	var image []ImageManifest
	reader, err := os.Open(imageTar)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer reader.Close()

	//get the manifest from the image tar
	files, err := utils.SelectivelyExtractArchive(bufio.NewReader(reader), func(filename string) bool {
		if filename == manifestJson || strings.HasSuffix(filename, layerJson) {
			return true
		} else {
			return false
		}
	}, maxFileSize)
	dat, ok := files[manifestJson]
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("Can not locate the manifest.json in image")
	}
	if err = json.Unmarshal(dat, &image); err != nil {
		return nil, nil, nil, nil, err
	}
	if len(image) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("Can not extract layer from the image")
	}

	//extract all the layers to tar files
	reader.Seek(0, 0)
	fileMap, err := utils.SelectivelyExtractToFile(bufio.NewReader(reader), func(filename string) bool {
		for _, l := range image[0].Layers {
			if filename == l {
				return true
			}
		}
		return false
	}, tmpDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	layerCount := len(fileMap)
	list := make([]string, layerCount)
	cmds := make([]string, layerCount)
	envs := make([]string, 0)
	labels := make(map[string]string)
	for i, ftar := range image[0].Layers {
		fpath, ok := fileMap[ftar]
		if !ok {
			log.Errorf("could not find the image layer: %s", ftar)
			return nil, nil, nil, nil, err
		}
		jsonFile := strings.Replace(ftar, "layer.tar", "json", 1)
		jsonData, ok := files[jsonFile]
		if !ok {
			log.Errorf("could not find the layer json file %s", jsonFile)
			return nil, nil, nil, nil, err
		}
		var lmeta LayerMetadata
		if err = json.Unmarshal(jsonData, &lmeta); err != nil {
			return nil, nil, nil, nil, err
		}

		fname := filepath.Base(fpath)                                  // ignore parent path
		list[layerCount-i-1] = strings.TrimSuffix(fname, "_layer.tar") // remove unwanted suffix
		cmds[layerCount-i-1] = strings.Join(lmeta.Config.Cmd, " ")
		if lmeta.Config.Env != nil {
			envs = append(envs, lmeta.Config.Env...)
		}
		if lmeta.Config.Labels != nil {
			for k, v := range lmeta.Config.Labels {
				labels[k] = v
			}
		}
	}
	return list, cmds, envs, labels, nil
}

type LayerFiles struct {
	Size int64
	Pkgs map[string][]byte
	Apps map[string][]AppPackage
}

func getImageLayerIterate(ctx context.Context, layers []string, sizes map[string]int64, schemaV1 bool, imgPath string,
	layerReader func(ctx context.Context, layer string) (interface{}, int64, error)) (map[string]*LayerFiles, share.ScanErrorCode) { // layer -> filename -> file content
	layerFiles := make(map[string]*LayerFiles)

	// download layered images into image folder
	layerInfo, err := downloadLayers(ctx, layers, sizes, imgPath, layerReader)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open image layer fail")
		return nil, share.ScanErrorCode_ScanErrFileSystem
	}

	//for registry, download all the layers.
	//for read all the layers.
	for _, layer := range layers {
		var size int64
		layerPath := filepath.Join(imgPath, layer)
		if info, ok := layerInfo[layer]; ok {
			size = info.Size
		}

		pathMap, err := selectiveFilesFromPath(layerPath, maxFileSize, func(path, fullpath string) bool {
			if libsList.Contains(path) || isAppsPkgFile(path, fullpath) {
				return true
			}
			if strings.HasPrefix(path, dpkgStatusDir) {
				return true
			}
			if strings.HasPrefix(path, contentManifest) && strings.HasSuffix(path, ".json") {
				return true
			}
			if strings.HasPrefix(path, dockerfile) {
				return true
			}
			return false
		})

		if err != nil {
			return nil, share.ScanErrorCode_ScanErrPackage
		}

		// for file content
		curLayerFiles := make(map[string][]byte)
		curLayerApps := NewScanApps(true)
		for filename, fullpath := range pathMap {
			var data []byte
			if RPMPkgFiles.Contains(filename) {
				data, err = getRpmPackages(fullpath, "")
				if err != nil {
					continue
				}
			} else if filename == dpkgStatus || strings.HasPrefix(filename, dpkgStatusDir) {
				// get the dpkg status file
				data, err = getDpkgStatus(fullpath, "")
				if err != nil {
					continue
				}
			} else if filename == apkPackages {
				data, err = getApkPackages(fullpath)
				if err != nil {
					continue
				}
			} else if isAppsPkgFile(filename, fullpath) {
				curLayerApps.extractAppPkg(filename, fullpath)
				continue
			} else {
				// Files have been selectively picked above.
				data, err = ioutil.ReadFile(fullpath)
			}

			curLayerFiles[filename] = data
		}

		layerFiles[layer] = &LayerFiles{Size: size, Pkgs: curLayerFiles, Apps: curLayerApps.data()}
	}

	return layerFiles, share.ScanErrorCode_ScanErrNone
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
	tmpDir, err := ioutil.TempDir(os.TempDir(), "scan_lambda")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Create temp directory fail")
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	for _, file := range r.File {
		if isAppsPkgFile(file.Name, file.Name) {
			zFile, err := file.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Debug("open zipped file fail")
				continue
			}
			defer zFile.Close()

			tmpfile, err := ioutil.TempFile(tmpDir, "extract")
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
			apps.extractAppPkg(file.Name, tmpfile.Name())
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

////////
type layerSize struct {
	layer string
	size  int64
}

func sortLayersBySize(layerMap map[string]int64) []layerSize {
	if len(layerMap) == 0 {
		return nil
	}

	layers := make([]layerSize, 0, len(layerMap))
	for k, v := range layerMap {
		l := layerSize{layer: k, size: v}
		layers = append(layers, l)
	}

	sort.SliceStable(layers, func(i, j int) bool {
		return layers[i].size > layers[j].size
	})

	// log.WithFields(log.Fields{"layers": layers}).Debug()
	return layers
}

// Download layers in parallels
// Reducing memory by limiting its concurrent downloading tar size near to 400MB,
//    which size information is provided from the Image Manifest Version 2, Schema 2.
// The download layers are sorted by descending layer's tar sizes
// (1) if the tar size is greater than 500MB, it will be downloaded alone
// (2) if concurrent download (accumulate) is greater than 400MB, the next download item will wait until there are sufficient resources
// (3) the maximum accumulate is less 800MB (for example, 399.99MB + 399.98MB).
// Note: docker uses the "maxConcurrentDownloads" (3)
//       containerd uses the download altogether
//
const downloadThrottlingVolume = 400 * 1024 * 1024 // the average could be around this level, decompressed size could be 4x more
func downloadLayers(ctx context.Context, layers []string, sizes map[string]int64, imgPath string,
	layerReader func(ctx context.Context, layer string) (interface{}, int64, error)) (map[string]*downloadLayerResult, error) {

	bHasSizeInfo := (len(sizes) > 0) // sizes data is from schema v2
	results := make(map[string]*downloadLayerResult)

	// remove duplicate layers
	layerMap := make(map[string]int64)
	for _, layer := range layers {
		if _, ok := layerMap[layer]; !ok && layer != "" {
			layerMap[layer] = 0 // no decision
			if bHasSizeInfo {
				if size, ok := sizes[layer]; ok {
					layerMap[layer] = size
				}
			}
		}
	}

	layerBySizes := sortLayersBySize(layerMap)

	////
	var accumlates int64
	complete := make(chan error)
	done := make(chan *downloadLayerResult)
	go func() { // monitor
		var err error
		for i := 0; i < len(layerMap); i++ {
			res := <-done
			results[res.layer] = res
			accumlates -= res.TarSize
			log.WithFields(log.Fields{"res": res}).Debug()
			if res.err != nil {
				err = res.err // reporting just one error
			}
		}
		complete <- err
	}()

	for _, layerSize := range layerBySizes {
		ml := layerSize.layer
		sl := layerSize.size // from manifest
		accumlates += sl
		// log.WithFields(log.Fields{"layerSize": layerSize}).Debug()
		go func() { // workers
			var err error
			var size int64
			var rd interface{}
			var retry int

			layerPath := filepath.Join(imgPath, ml)
			if bHasSizeInfo && sl == 0 {
				log.WithFields(log.Fields{"layer": ml}).Debug("skip")
				os.MkdirAll(layerPath, 0755) // empty folder
				done <- &downloadLayerResult{layer: ml, err: nil, Size: 0, TarSize: 0}
				return
			}

			for retry < 3 {
				retry++
				rd, size, err = layerReader(ctx, ml)
				if err == nil {
					// unpack image data
					if _, err = os.Stat(layerPath); os.IsNotExist(err) { // ignored if it was untarred before
						err = os.MkdirAll(layerPath, 0755)
						if err != nil {
							log.WithFields(log.Fields{"error": err, "path": layerPath}).Error("Failed to make dir")
							// local file error, no retry
							break
						}

						size, err = utils.ExtractAllArchive(layerPath, rd.(io.ReadCloser), -1)
						if err != nil {
							log.WithFields(log.Fields{"error": err, "path": layerPath}).Error("Failed to unzip image")
							os.RemoveAll(layerPath)
							continue
						}
					}
					break
				}
			}
			done <- &downloadLayerResult{layer: ml, err: err, Size: size, TarSize: sl}
		}()

		for accumlates > downloadThrottlingVolume { // pause and wait for released resources
			// log.WithFields(log.Fields{"accumlates": accumlates}).Debug("Wait")
			time.Sleep(time.Second * 1)
		}
	}

	err := <-complete
	close(done)
	close(complete)
	return results, err
}

// selectiveFilesFromPath the specified files and folders
// store them in a map indexed by file paths
func selectiveFilesFromPath(rootPath string, maxFileSize int64, selected func(string, string) bool) (map[string]string, error) {
	rootLen := len(filepath.Clean(rootPath))
	data := make(map[string]string)

	// log.WithFields(log.Fields{"rootPath": rootPath}).Debug()
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithFields(log.Fields{"path": rootPath, "error": err.Error()}).Error()
			return err
		}

		if !info.IsDir() {
			if info.Mode().IsRegular() && (maxFileSize > 0 && info.Size() < maxFileSize) {
				inpath := path[(rootLen + 1):] // remove the root "/"
				if selected(inpath, path) {
					data[inpath] = path
				}
			}
		}
		return nil
	})

	return data, err
}
