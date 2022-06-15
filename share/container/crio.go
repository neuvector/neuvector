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
	crioClient   crioAPI.CrioClient
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

	crt := criRT.NewRuntimeServiceClient(cri)
	req := &criRT.VersionRequest{}
	ver, err := crt.Version(context.Background(), req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to get crio version")
		return nil, err
	}

	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("crio connected")

	driver := crioDriver{
		sys: sys, version: ver, criClient: cri, crioClient: crio,
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

func (d *crioDriver) getPodMeta(id string, pod *criRT.PodSandboxStatus, cinfo *types.ContainerInfo) *ContainerMeta {
	name := "k8s_POD_" + pod.Labels["io.kubernetes.pod.name"] + "_" +
		pod.Labels["io.kubernetes.pod.namespace"] + "_" +
		pod.Labels["io.kubernetes.pod.uid"] + "_" +
		fmt.Sprintf("%d", pod.Metadata.Attempt) // cinfo.Name
	image := cinfo.Image
	meta := &ContainerMeta{
		ID:       id,
		Name:     name,
		Image:    image,
		Labels:   pod.Labels, // cinfo.Labels,
		Hostname: "",
		Envs:     make([]string, 0),
		Pid:      cinfo.Pid,
		Sandbox:  cinfo.Sandbox,
		isChild:  cinfo.Sandbox != id,
	}

	if !meta.isChild && meta.Image == "" {
		meta.Image = d.podImgRepoDigest
		if meta.Image == "" {
			meta.Image = "pod" // last resort
		}
	}

	if pod.Linux == nil || pod.Linux.Namespaces == nil ||
		pod.Linux.Namespaces.Options == nil {
		log.Error("Fail to get sandbox linux namespaces")
	} else {
		opts := pod.Linux.Namespaces.Options
		switch opts.Network {
		case criRT.NamespaceMode_NODE:
			meta.NetMode = "host"
			meta.isChild = true
		case criRT.NamespaceMode_CONTAINER:
			meta.NetMode = "default"
		case criRT.NamespaceMode_POD:
			meta.NetMode = "default"
			meta.isChild = true
		}
		switch opts.Pid {
		case criRT.NamespaceMode_NODE:
			meta.PidMode = "host"
		case criRT.NamespaceMode_CONTAINER:
		case criRT.NamespaceMode_POD:
		}
	}

	return meta
}

func (d *crioDriver) getContainerMeta(id string, pod *criRT.PodSandboxStatus, cs *criRT.ContainerStatus, cinfo *types.ContainerInfo) *ContainerMeta {
	name := "k8s_" + cs.Labels["io.kubernetes.container.name"] + "_" +
		cs.Labels["io.kubernetes.pod.name"] + "_" +
		cs.Labels["io.kubernetes.pod.namespace"] + "_" +
		cs.Labels["io.kubernetes.pod.uid"] + "_" +
		fmt.Sprintf("%d", cs.Metadata.Attempt) // cinfo.Name
	image := cs.Image.Image // cinfo.Image
	meta := &ContainerMeta{
		ID:       id,
		Name:     name,
		Image:    image,
		Labels:   cs.Labels, // cinfo.Labels,
		Hostname: "",
		Envs:     make([]string, 0),
		Pid:      cinfo.Pid,
		Sandbox:  cinfo.Sandbox,
		isChild:  cinfo.Sandbox != id,
	}

	if pod.Linux == nil || pod.Linux.Namespaces == nil ||
		pod.Linux.Namespaces.Options == nil {
		log.Error("Fail to get sandbox linux namespaces")
	} else {
		opts := pod.Linux.Namespaces.Options
		switch opts.Network {
		case criRT.NamespaceMode_NODE:
			meta.NetMode = "host"
			meta.isChild = true
		case criRT.NamespaceMode_CONTAINER:
			meta.NetMode = "default"
		case criRT.NamespaceMode_POD:
			meta.NetMode = "default"
			meta.isChild = true
		}
		switch opts.Pid {
		case criRT.NamespaceMode_NODE:
			meta.PidMode = "host"
		case criRT.NamespaceMode_CONTAINER:
		case criRT.NamespaceMode_POD:
		}
	}

	return meta
}

type criContainerStatusExtension struct {
	SandboxID  string `json:"sandboxID"`
	Privileged bool   `json:"privileged"`
}

func (d *crioDriver) isPrivileged(pod *criRT.PodSandboxStatus, cs *criRT.ContainerStatusResponse) bool {
	if scc, ok := pod.Annotations["openshift.io/scc"]; ok && scc == "privileged" {
		return true
	}

	if cs != nil {
		// Info is extra information of the Runtime. The key could be arbitrary string, and
		// value should be in json format.
		var ext criContainerStatusExtension
		for _, v := range cs.Info { //
			if err := json.Unmarshal([]byte(v), &ext); err != nil {
				// log.WithFields(log.Fields{"err": err, "key": k, "value": v}).Debug()
				continue
			}

			if ext.Privileged {
				// log.WithFields(log.Fields{"Ext": ext}).Debug()
				return true
			}
		}
	}
	return false
}

// Using cri runtime API to list containers doesn't give pod containers; however, with
// the crio API with specific container ID, we can retrieve the pod container info. The
// later is usually triggered by process monitoring
func (d *crioDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) {
	crt := criRT.NewRuntimeServiceClient(d.criClient)

	resp_container, err := crt.ListContainers(context.Background(), &criRT.ListContainersRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list containers")
		return nil, err
	}

	resp_sandboxes, err := crt.ListPodSandbox(context.Background(), &criRT.ListPodSandboxRequest{})
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
	sandboxID := id                              // assumption
	cinfo, err := d.crioClient.ContainerInfo(id) // http
	if err != nil {
		log.WithFields(log.Fields{"container": id, "error": err}).Error("Fail to get container info")
	} else {
		sandboxID = cinfo.Sandbox // update the correct sandboxID
	}

	//////
	crt := criRT.NewRuntimeServiceClient(d.criClient) // GRPC
	pod, err := crt.PodSandboxStatus(
		context.Background(), &criRT.PodSandboxStatusRequest{PodSandboxId: sandboxID, Verbose: true})
	if err != nil || pod.Status == nil {
		log.WithFields(log.Fields{"container": id, "podID": sandboxID, "error": err}).Error("Fail to get sandbox status")
		return nil, err
	}

	// fault-tolerent on the failure of http channel
	if cinfo == nil {
		// build an info structure
		cinfo = &types.ContainerInfo{
			Pid:     0, //
			Sandbox: pod.Status.Id,
		}
	}

	cs, err := crt.ContainerStatus(context.Background(), &criRT.ContainerStatusRequest{ContainerId: id, Verbose: true})
	if err != nil {
		// This most likely be a pod
	} else if cs.Status == nil {
		log.WithFields(log.Fields{"container": id, "info": cinfo}).Error("Fail to get container status")
		return nil, err
	}

	//	if cs == nil {
	//		log.WithFields(log.Fields{"container": id, "info": cinfo, "pod": pod}).Info()
	//	} else {
	//		log.WithFields(log.Fields{"container": id, "info": cinfo, "pod": pod, "cs": cs}).Info()
	//	}

	var meta *ContainerMetaExtra
	if cs == nil { // POD as sandbox
		// POD
		meta = &ContainerMetaExtra{
			ContainerMeta: *d.getPodMeta(id, pod.Status, cinfo),
			ImageDigest:   imageRef2Digest(cinfo.ImageRef),
			Privileged:    d.isPrivileged(pod.Status, cs),
			CreatedAt:     time.Unix(0, pod.Status.CreatedAt),
			StartedAt:     time.Unix(0, pod.Status.CreatedAt),
			Running:       (cinfo.Pid != 0) || (pod.Status.State == criRT.PodSandboxState_SANDBOX_READY),
			Networks:      utils.NewSet(),
		}

		if cinfo.Image != "" {
			if image, _ := d.GetImage(cinfo.Image); image != nil {
				meta.ImageID = image.ID
			}
		}

		if meta.ImageID != "" && meta.ImageDigest != "" {
			if image, _ := d.GetImage(cinfo.ImageRef); image != nil {
				meta.ImageID = image.ID
			}
		}

		if meta.ImageID == "" {
			// log.WithFields(log.Fields{"cinfo": cinfo}).Debug("fail to obtain pod id")
			meta.ImageID = d.podImgID // from host's crio information
			meta.ImageDigest = d.podImgDigest
		}
	} else {
		// application Container
		meta = &ContainerMetaExtra{
			ContainerMeta: *d.getContainerMeta(id, pod.Status, cs.Status, cinfo),
			ImageDigest:   imageRef2Digest(cs.Status.ImageRef),
			Privileged:    d.isPrivileged(pod.Status, cs),
			CreatedAt:     time.Unix(0, cs.Status.CreatedAt),
			StartedAt:     time.Unix(0, cs.Status.StartedAt),
			ExitCode:      int(cs.Status.ExitCode),
			Running:       (cinfo.Pid != 0) || (cs.Status.State == criRT.ContainerState_CONTAINER_RUNNING),
			Networks:      utils.NewSet(),
			LogPath:       cs.Status.LogPath,
		}

		// otherwise, it is shown as "" in workload record
		if cs.Status.FinishedAt != 0 {
			meta.FinishedAt = time.Unix(0, cs.Status.FinishedAt)
		}

		// first try
		if cs.Status.Image != nil && len(cs.Status.Image.Image) > 0 {
			if image, _ := d.GetImage(cs.Status.Image.Image); image != nil {
				meta.ImageID = image.ID
			}
		}

		// 2nd chance
		if meta.ImageID == "" && meta.ImageDigest != "" {
			if image, _ := d.GetImage(cs.Status.ImageRef); image != nil {
				meta.ImageID = image.ID
			}
		}

		if meta.ImageID == "" {
			log.WithFields(log.Fields{"cs": cs}).Debug("fail to obtain image id")
		}
	}

	// avoid false-positive event which is different from the process monitor
	if d.pidHost {
		if cinfo.Pid > 0 {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", cinfo.Pid)); err != nil {
				log.WithFields(log.Fields{"id": id, "info": cinfo}).Debug("dead rootPid")
				meta.Running = false
			}
		}
	}

	// patch POD finsihed time
	if cs == nil && !meta.Running {
		meta.FinishedAt = time.Now()
	}
	return meta, nil
}

func (d *crioDriver) GetImageHistory(name string) ([]*ImageHistory, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) GetImage(name string) (*ImageMeta, error) {
	cimg := criRT.NewImageServiceClient(d.criClient)

	req := &criRT.ImageStatusRequest{Image: &criRT.ImageSpec{Image: name}}
	// Extra check for resp and resp.Image because of NVSHAS-4778
	if resp, err := cimg.ImageStatus(context.Background(), req); err == nil && resp != nil && resp.Image != nil {
		meta := &ImageMeta{
			ID:     resp.Image.Id,
			Size:   int64(resp.Image.Size_),
			Labels: make(map[string]string),
		}
		if len(resp.Image.RepoDigests) > 0 {
			meta.Digest = resp.Image.RepoDigests[0]
		}
		return meta, nil
	} else {
		log.WithFields(log.Fields{"error": err, "name": name}).Error("Fail to get image")
		return nil, err
	}
}

func (d *crioDriver) GetImageFile(id string) (io.ReadCloser, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) ListContainerIDs() (utils.Set, utils.Set) {
	ids := utils.NewSet()
	stops := utils.NewSet()

	crt := criRT.NewRuntimeServiceClient(d.criClient)
	resp_containers, err := crt.ListContainers(context.Background(), &criRT.ListContainersRequest{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list containers")
		return ids, nil
	}

	resp_sandboxes, err := crt.ListPodSandbox(context.Background(), &criRT.ListPodSandboxRequest{})
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
	cimg := criRT.NewImageServiceClient(d.criClient)
	if list, err := cimg.ListImages(context.Background(), &criRT.ListImagesRequest{}); err == nil {
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
