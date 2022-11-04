package container

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	crioAPI "github.com/cri-o/cri-o/client"
	"github.com/cri-o/cri-o/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	// criRT "k8s.io/kubernetes/pkg/kubelet/apis/cri/runtime/v1alpha2"
	criRT "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultCriOSock = "/var/run/crio/crio.sock"

type crioDriver struct {
	sys          *system.SystemTools
	sysInfo      *sysinfo.SysInfo
	nodeHostname string
	criClient    *grpc.ClientConn
	version      *criRT.VersionResponse
	daemonInfo   types.CrioInfo

	/////
	podImgRepoDigest string
	podImgDigest     string
	podImgID         string
	pidHost          bool
}

type imageInfo struct {
	repoTag string
	digest  string
}

// --
const (
	// unixProtocol is the network protocol of unix socket.
	unixProtocol = "unix"
)

// GetAddressAndDialer returns the address parsed from the given endpoint and a dialer.
func GetAddressAndDialer(endpoint string) (string, func(addr string, timeout time.Duration) (net.Conn, error), error) {
	protocol, addr, err := parseEndpointWithFallbackProtocol(endpoint, unixProtocol)
	if err != nil {
		return "", nil, err
	}
	if protocol != unixProtocol {
		return "", nil, fmt.Errorf("only support unix socket endpoint")
	}

	return addr, dial, nil
}

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(unixProtocol, addr, timeout)
}

func parseEndpointWithFallbackProtocol(endpoint string, fallbackProtocol string) (protocol string, addr string, err error) {
	if protocol, addr, err = parseEndpoint(endpoint); err != nil && protocol == "" {
		fallbackEndpoint := fallbackProtocol + "://" + endpoint
		log.Warningf("Using %q as endpoint is deprecated, please consider using full url format %q.", endpoint, fallbackEndpoint)
		protocol, addr, err = parseEndpoint(fallbackEndpoint)
		if err == nil {
			log.Warningf("Using %q as endpoint is deprecated, please consider using full url format %q.", endpoint, fallbackEndpoint)
		}
	}
	log.Warningf("no error %v %v.", protocol, addr)
	return
}

func getPauseImageRepoDigests() (string, error) {
	config_files := []string {
		"/proc/1/root/etc/crio/crio.conf",
		"/proc/1/root/etc/crio/crio.conf.d/00-default.conf",
		"/proc/1/root/etc/crio/crio.conf.d/00-default",
	}

	for _, filename := range config_files {
		dat, err := ioutil.ReadFile(filename)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(dat)))
		for scanner.Scan() {
			// removing whitespaces, tabs and quote
			line := strings.Replace(scanner.Text(), " ", "", -1)
			line = strings.Replace(line, "\t", "", -1)
			// log.WithFields(log.Fields{"line": line}).Debug("CRIO:")
			if strings.HasPrefix(line, "pause_image=") {
				line = strings.Replace(line, "\"", "", -1)
				return line[len("pause_image="):], nil
			}
		}
	}
	return "", fmt.Errorf("no found")
}

func parseEndpoint(endpoint string) (string, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}

	switch u.Scheme {
	case "tcp":
		return "tcp", u.Host, nil

	case "unix":
		return "unix", u.Path, nil

	case "":
		return "", "", fmt.Errorf("Using %q as endpoint is deprecated, please consider using full url format", endpoint)

	default:
		return u.Scheme, "", fmt.Errorf("protocol %q not supported", u.Scheme)
	}
}

// LocalEndpoint returns the full path to a unix socket at the given endpoint
func LocalEndpoint(path, file string) string {
	u := url.URL{
		Scheme: unixProtocol,
		Path:   path,
	}
	return filepath.Join(u.String(), file+".sock")
}

// --
func newCriClient(sock string) (*grpc.ClientConn, error) {
	addr, dialer, err := GetAddressAndDialer("unix://" + sock)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"addr": addr}).Debug()

	conn, err := grpc.Dial(addr, grpc.WithInsecure() /*grpc.WithBlock(), */, grpc.WithTimeout(4*time.Second), grpc.WithDialer(dialer))
	if err != nil {
		return nil, fmt.Errorf("failed to connect, make sure you are running as root and the runtime has been started: %v", err)
	}
	return conn, nil
}

func crioConnect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Debug("Connecting to crio")

	crio, err := crioAPI.New(endpoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to create crio client")
		return nil, err
	}

	cri, err := newCriClient(endpoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to create cri client")
		return nil, err
	}

	daemon, err := crio.DaemonInfo()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to get daemon info")
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	crt := criRT.NewRuntimeServiceClient(cri)
	req := &criRT.VersionRequest{}
	ver, err := crt.Version(ctx, req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to get crio version")
		return nil, err
	}

	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("crio connected")

	driver := crioDriver{
		sys: sys, version: ver, criClient: cri, podImgRepoDigest: "pod",
		// Read /host/proc/sys/kernel/hostname doesn't give the correct node hostname. Change UTS namespace to read it
		sysInfo: sys.GetSystemInfo(), nodeHostname: sys.GetHostname(1), daemonInfo: daemon,
	}

	name, _ := os.Readlink("/proc/1/exe")
	if name == "/usr/local/bin/monitor" || strings.HasPrefix(name, "/usr/bin/python") { // when pid mode != host, 'pythohn' is for allinone
		driver.pidHost = false
	} else {
		driver.pidHost = true
		if repoDig, err := getPauseImageRepoDigests(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to get pause image info")
		} else {
			driver.podImgRepoDigest = repoDig
			driver.setPodImageInfo()
			log.WithFields(log.Fields{"repoDig": driver.podImgRepoDigest, "imgID": driver.podImgID, "imgDigest": driver.podImgDigest}).Debug("CRIO:")
		}
	}

	return &driver, nil
}

func imageRef2Digest(ref string) string {
	if tokens := strings.Split(ref, "@"); len(tokens) > 1 {
		return tokens[1]
	} else {
		return ref
	}
}

func (d *crioDriver) String() string {
	return RuntimeCriO
}

func (d *crioDriver) GetHost() (*share.CLUSHost, error) {
	var host share.CLUSHost

	host.Runtime = d.String()
	if d.version != nil {
		host.RuntimeVer = d.version.RuntimeVersion
		host.RuntimeAPIVer = d.version.RuntimeApiVersion
	}

	if d.sysInfo != nil {
		host.Name = d.nodeHostname
		host.ID = fmt.Sprintf("%s:%s", d.nodeHostname, d.sysInfo.Product.UUID)
		host.OS = d.sysInfo.OS.Name
		host.Kernel = d.sysInfo.Kernel.Release
		host.CPUs = int64(d.sysInfo.CPU.Threads)
		host.Memory = int64(d.sysInfo.Memory.Size) * 1024 * 1024
	}

	return &host, nil
}

func (d *crioDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	return getDevice(id, d, d.sys)
}

type criContainerInfo struct {
	Info struct {
		SandboxID  string `json:"sandboxID"`
		Pid        int    `json:"pid"`
		Image      string `json:"image"`
		Privileged bool   `json:"privileged"`
	} `json:"info"`
}

func (d *crioDriver) getContainerInfo(infoMap map[string]string) (*criContainerInfo, error) {
	// Info is extra information of the Runtime. The key could be arbitrary string, and
	// value should be in json format.
	var info criContainerInfo

	jsonInfo := buildJsonFromMap(infoMap) // from map[string]string
	if err := json.Unmarshal([]byte(jsonInfo), &info); err != nil {
		// log.WithFields(log.Fields{"error": err, "json": jsonInfo}).Error()
		return nil, err
	}
	// log.WithFields(log.Fields{"info": info}).Debug()
	return &info, nil
}

func (d *crioDriver) getPodMeta(id string, pod *criRT.PodSandboxStatusResponse, info *criContainerInfo) *ContainerMeta {
	name := "k8s_POD_" + pod.Status.Labels["io.kubernetes.pod.name"] + "_" +
		pod.Status.Labels["io.kubernetes.pod.namespace"] + "_" +
		pod.Status.Labels["io.kubernetes.pod.uid"] + "_" +
		fmt.Sprintf("%d", pod.Status.Metadata.Attempt) // cinfo.Name
	meta := &ContainerMeta{
		ID:       id,
		Name:     name,
		Pid:      info.Info.Pid,
		Image:    info.Info.Image,
		Labels:   pod.Status.Labels,
		Hostname: "",
		Envs:     make([]string, 0),
		Sandbox:  id,
		isChild:  false,
	}
	return meta
}

func (d *crioDriver) getContainerMeta(id string, cs *criRT.ContainerStatusResponse, pod *criRT.PodSandboxStatusResponse, info *criContainerInfo) *ContainerMeta {
	name := "k8s_" + cs.Status.Labels["io.kubernetes.container.name"] + "_" +
		cs.Status.Labels["io.kubernetes.pod.name"] + "_" +
		cs.Status.Labels["io.kubernetes.pod.namespace"] + "_" +
		cs.Status.Labels["io.kubernetes.pod.uid"] + "_" +
		fmt.Sprintf("%d", cs.Status.Metadata.Attempt)

	meta := &ContainerMeta{
		ID:         id,
		Name:       name,
		Pid:        info.Info.Pid,
		Sandbox:    info.Info.SandboxID,
		Labels:     cs.Status.Labels,
		Hostname:   "",
		Envs:       make([]string, 0),
		isChild:    true,
	}

	if cs.Status.Image != nil {
		meta.Image = cs.Status.Image.Image
	} else {
		meta.Image = cs.Status.ImageRef
	}
	return meta
}

func (d *crioDriver) isPrivileged(pod *criRT.PodSandboxStatus, cinfo *criContainerInfo) bool {
	if scc, ok := pod.Annotations["openshift.io/scc"]; ok {
		return scc == "privileged"
	}

	if cinfo != nil {
		return cinfo.Info.Privileged
	}
	return false
}

// Using cri runtime API to list containers doesn't give pod containers; however, with
// the crio API with specific container ID, we can retrieve the pod container info. The
// later is usually triggered by process monitoring
func (d *crioDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crt := criRT.NewRuntimeServiceClient(d.criClient)
	resp_container, err := crt.ListContainers(ctx, &criRT.ListContainersRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list containers")
		return nil, err
	}

	resp_sandboxes, err := crt.ListPodSandbox(ctx, &criRT.ListPodSandboxRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list sandboxes")
		return nil, err
	}

	metas := make([]*ContainerMeta, 0, len(resp_container.Containers)+len(resp_sandboxes.Items))
	for _, pod := range resp_sandboxes.Items {
		if runningOnly && pod.State != criRT.PodSandboxState_SANDBOX_READY {
			continue
		}

		m, err := d.GetContainer(pod.Id)
		if err != nil {
			log.WithFields(log.Fields{"sandbox": pod.Id, "error": err}).Error("Fail: sandbox")
			continue
		}
		if runningOnly && !m.Running {
			continue
		}
		metas = append(metas, &m.ContainerMeta)
	}

	for _, c := range resp_container.Containers {
		m, err := d.GetContainer(c.Id)
		if err != nil {
			log.WithFields(log.Fields{"container": c.Id, "error": err}).Error("Fail: container")
			continue
		}
		if runningOnly && !m.Running {
			continue
		}
		metas = append(metas, &m.ContainerMeta)
	}
	return metas, nil
}

func (d *crioDriver) GetContainer(id string) (*ContainerMetaExtra, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crt := criRT.NewRuntimeServiceClient(d.criClient) // GRPC
	var meta *ContainerMetaExtra
	pod, err := crt.PodSandboxStatus(ctx, &criRT.PodSandboxStatusRequest{PodSandboxId: id, Verbose: true})
	if err == nil && pod != nil {
		if pod.Status == nil || pod.Info == nil {
			log.WithFields(log.Fields{"id":id, "pod": pod}).Error("Fail to get pod")
			return nil, err
		}

		podInfo, err2 := d.getContainerInfo(pod.Info)
		if err2 != nil {
			log.WithFields(log.Fields{"id":id, "info": pod.Info}).Error("Fail to get pod info")
			return nil, err
		}

		// a POD
		meta = &ContainerMetaExtra{
			ContainerMeta: *d.getPodMeta(id, pod, podInfo),
			Privileged:    d.isPrivileged(pod.Status, nil),
			Running:       pod.Status.State == criRT.PodSandboxState_SANDBOX_READY,
			Networks:      utils.NewSet(),
		}

		if pod.Status.CreatedAt > 0 {
			meta.CreatedAt = time.Unix(0, pod.Status.CreatedAt)
			meta.StartedAt = meta.CreatedAt
		}

		// image ID
		if meta.Image == "" {
			// from host's crio information
			meta.Image = d.podImgRepoDigest
			meta.ImageID = d.podImgID
			meta.ImageDigest = d.podImgDigest
		} else {
			meta.ImageDigest = imageRef2Digest(meta.Image)
			if imageMeta, _ := d.GetImage(meta.Image); imageMeta != nil {
				meta.ImageID = imageMeta.ID
				meta.Author = imageMeta.Author
			}
		}
	} else {
		// an APP container
		cs, err2 := crt.ContainerStatus(ctx, &criRT.ContainerStatusRequest{ContainerId: id, Verbose: true})
		if err2 != nil || cs.Status == nil || cs.Info == nil {
			log.WithFields(log.Fields{"id": id, "error": err2, "cs": cs}).Error("Fail to get container")
			return nil, err
		}

		csInfo, err2 := d.getContainerInfo(cs.Info)
		if err2 != nil {
			log.WithFields(log.Fields{"id": id, "info": cs.Info}).Error("Fail to get cs info")
			return nil, err
		}

		pod, err = crt.PodSandboxStatus(ctx, &criRT.PodSandboxStatusRequest{PodSandboxId: csInfo.Info.SandboxID, Verbose: true})
		if err2 != nil {
			log.WithFields(log.Fields{"id": id, "csInfo": csInfo, "error": err}).Error("Fail to get its pod")
			return nil, err
		}

		meta = &ContainerMetaExtra{
			ContainerMeta: *d.getContainerMeta(id, cs, pod, csInfo),
			ImageDigest:   imageRef2Digest(cs.Status.ImageRef),
			Privileged:    d.isPrivileged(pod.Status, csInfo),
			ExitCode:      int(cs.Status.ExitCode),
			Running:       cs.Status.State == criRT.ContainerState_CONTAINER_RUNNING || cs.Status.State == criRT.ContainerState_CONTAINER_CREATED,
			Networks:      utils.NewSet(),
			LogPath:       cs.Status.LogPath,
		}

		if cs.Status.CreatedAt > 0 {
			meta.CreatedAt = time.Unix(0, cs.Status.CreatedAt)
		}

		if cs.Status.StartedAt > 0 {
			meta.StartedAt = time.Unix(0, cs.Status.StartedAt)
		} else {
			meta.StartedAt = meta.CreatedAt
		}

		if cs.Status.FinishedAt > 0 {
			meta.FinishedAt = time.Unix(0, cs.Status.FinishedAt)
		}

		// image ID
		if image, _ := d.GetImage(meta.Image); image != nil {
			meta.ImageID = image.ID
			meta.Author = image.Author
			for k, v := range image.Labels {
				// Not to overwrite container labels when merging
				if _, ok := meta.Labels[k]; !ok {
					meta.Labels[k] = v
				}
			}
		} else {
			// 2nd chance
			if meta.ImageID == "" && meta.ImageDigest != "" {
				if image, _ := d.GetImage(cs.Status.ImageRef); image != nil {
					meta.ImageID = image.ID
					meta.Author = image.Author
					for k, v := range image.Labels {
						// Not to overwrite container labels when merging
						if _, ok := meta.Labels[k]; !ok {
							meta.Labels[k] = v
						}
					}
				}
			}
		}

		if meta.ImageID == "" {
			log.WithFields(log.Fields{"cs": cs}).Debug("fail to obtain image id")
		}
	}

	// retrive its network/pid namespace from the POD
	if pod.Status.Linux == nil || pod.Status.Linux.Namespaces == nil || pod.Status.Linux.Namespaces.Options == nil {
		log.Error("Fail to get sandbox linux namespaces")
	} else {
		opts := pod.Status.Linux.Namespaces.Options
		switch opts.Network {
		case criRT.NamespaceMode_NODE:
			meta.NetMode = "host"
		case criRT.NamespaceMode_CONTAINER:
			meta.NetMode = "default"
		case criRT.NamespaceMode_POD:
			meta.NetMode = "default"
		}
		switch opts.Pid {
		case criRT.NamespaceMode_NODE:
			meta.PidMode = "host"
		case criRT.NamespaceMode_CONTAINER:
		case criRT.NamespaceMode_POD:
		}
	}

	// avoid false-positive event which is different from the process monitor
	if d.pidHost {
		if meta.Pid > 0 {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", meta.Pid)); err != nil {
				log.WithFields(log.Fields{"id": id, "pid": meta.Pid}).Debug("dead rootPid")
				meta.Running = false
			}
		}
	}
	return meta, nil
}

func (d *crioDriver) GetImageHistory(name string) ([]*ImageHistory, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) GetImage(name string) (*ImageMeta, error) {
	return getCriImageMeta(d.criClient, name)
}

func (d *crioDriver) GetImageFile(id string) (io.ReadCloser, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) ListContainerIDs() (utils.Set, utils.Set) {
	ids := utils.NewSet()
	stops := utils.NewSet()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crt := criRT.NewRuntimeServiceClient(d.criClient)
	resp_containers, err := crt.ListContainers(ctx, &criRT.ListContainersRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list containers")
		return ids, nil
	}

	resp_sandboxes, err := crt.ListPodSandbox(ctx, &criRT.ListPodSandboxRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list sandboxes")
		return ids, nil
	}

	// log.WithFields(log.Fields{"sandbox": resp_sandboxes, "containers": resp_containers}).Debug("")
	for _, c := range resp_containers.Containers {
		switch c.GetState() {
		case criRT.ContainerState_CONTAINER_EXITED:
			stops.Add(c.Id)
			ids.Add(c.Id)
		case criRT.ContainerState_CONTAINER_UNKNOWN:// do nothing
		default:	// criRT.ContainerState_CONTAINER_RUNNING, criRT.ContainerState_CONTAINER_CREATED
			ids.Add(c.Id)
		}
	}

	///
	for _, pod := range resp_sandboxes.Items {
		switch pod.GetState() {
		case criRT.PodSandboxState_SANDBOX_READY:
			ids.Add(pod.Id)
		case criRT.PodSandboxState_SANDBOX_NOTREADY:
			stops.Add(pod.Id)
			ids.Add(pod.Id)
		}
	}
	return ids, stops
}

func (d *crioDriver) GetNetworkEndpoint(netName, container, epName string) (*NetworkEndpoint, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) ListNetworks() (map[string]*Network, error) {
	return make(map[string]*Network), nil
}

func (d *crioDriver) GetService(id string) (*Service, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) ListServices() ([]*Service, error) {
	return make([]*Service, 0), nil
}

func (d *crioDriver) IsDaemonProcess(proc string, cmds []string) bool {
	return false
}

func (d *crioDriver) IsRuntimeProcess(proc string, cmds []string) bool {
	return proc == "runc" || proc == "crio" || proc == "conmon" // an OCI container runtime monitor
}

func (d *crioDriver) GetParent(info *ContainerMetaExtra, pidMap map[int]string) (bool, string) {
	if info.ID == info.Sandbox {
		return false, ""
	} else {
		return true, info.Sandbox
	}
}

func (d *crioDriver) StopMonitorEvent() {
}

func (d *crioDriver) MonitorEvent(cb EventCallback, cpath bool) error {
	// crio api doesn't support this
	return ErrMethodNotSupported
}

func (d *crioDriver) GetProxy() (string, string, string) {
	return "", "", ""
}

func (d *crioDriver) GetDefaultRegistries() []string {
	return nil
}

func (d *crioDriver) GetStorageDriver() string {
	return d.daemonInfo.StorageDriver
}

func (d *crioDriver) setPodImageInfo() error {
	// log.WithFields(log.Fields{"repoDigest": d.podImgRepoDigest}).Debug("CRIO")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cimg := criRT.NewImageServiceClient(d.criClient)
	if list, err := cimg.ListImages(ctx, &criRT.ListImagesRequest{}); err == nil {
		for _, img := range list.Images {
			// log.WithFields(log.Fields{"image": img}).Debug("CRIO")
			for _, repoDig := range img.RepoDigests {
				if strings.Compare(repoDig, d.podImgRepoDigest) == 0 {
					// matched
					d.podImgID = img.Id
					d.podImgDigest = imageRef2Digest(repoDig)
					return nil
				}
			}

			// second chance: it was a tag instead of an image digest
			for _, repoTag := range img.RepoTags {
				if strings.Compare(repoTag, d.podImgRepoDigest) == 0 {
					// matched
					d.podImgID = img.Id
					if len(img.RepoDigests) > 0 {
						d.podImgDigest = imageRef2Digest(img.RepoDigests[0])
					} else {
						log.WithFields(log.Fields{"pause": d.podImgRepoDigest}).Error("Fail to get image digest")
					}
					return nil
				}
			}
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Fail to get image list")
		return err
	}
	return nil
}
