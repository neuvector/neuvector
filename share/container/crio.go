package container

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	criRT "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultCriOSock = "/var/run/crio/crio.sock"

// standard CRI runtime drivers
const defaultCriDockerSock = "/var/run/cri-dockerd.sock"

type crioDriver struct {
	sys          *system.SystemTools
	sysInfo      *sysinfo.SysInfo
	endpoint     string
	endpointHost string
	nodeHostname string
	selfID       string
	criClient    *grpc.ClientConn
	version      *criRT.VersionResponse

	/////
	storageDriver    string
	podImgRepoDigest string
	podImgDigest     string
	podImgID         string
	pidHost          bool
	failedQueryCnt   int
	eventCallback    EventCallback
}

func getPauseImageRepoDigests(sys *system.SystemTools) (string, error) {
	config_files := []string{
		"/proc/1/root/etc/crio/crio.conf",
		"/proc/1/root/etc/crio/crio.conf.d/00-default.conf",
		"/proc/1/root/etc/crio/crio.conf.d/00-default",
	}

	for _, filename := range config_files {
		dat, err := os.ReadFile(filename)
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

	// already pidHost
	if _, pause_img, ok := obtainRtEndpointFromKubelet(sys); ok && pause_img != "" {
		return pause_img, nil
	}
	return "", fmt.Errorf("no found")
}

func crioConnect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Debug("Connecting to crio")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cri, ver, err := newCriClient(endpoint, ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to create cri client")
		return nil, err
	}

	var sockPath string
	id, _, _ := sys.GetSelfContainerID() // not relaible, could be sandboxID
	id, _ = criGetSelfID(cri, ctx, id)
	sockPath, err = criGetContainerSocketPath(cri, ctx, id, endpoint) // update id
	if err == nil {
		log.WithFields(log.Fields{"selfID": id, "sockPath": sockPath}).Info()
	}

	storageDev, _ := criGetStorageDevice(cri, ctx)
	log.WithFields(log.Fields{"endpoint": endpoint, "sockPath": sockPath, "version": ver, "storageDriver": storageDev}).Info("cri connected")
	driver := crioDriver{
		sys: sys, version: ver, criClient: cri, podImgRepoDigest: "pod", endpoint: endpoint, endpointHost: sockPath,
		// Read /host/proc/sys/kernel/hostname doesn't give the correct node hostname. Change UTS namespace to read it
		sysInfo: sys.GetSystemInfo(), nodeHostname: sys.GetHostname(1), storageDriver: storageDev, selfID: id,
	}

	driver.pidHost = IsPidHost()
	if driver.pidHost {
		if repoDig, err := getPauseImageRepoDigests(sys); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to get pause image info")
		} else {
			driver.podImgRepoDigest = repoDig
			_ = driver.setPodImageInfo()
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

func (d *crioDriver) reConnect() error {
	if !d.pidHost {
		return errors.New("Not pidHost")
	}
	// the original socket has been recreated and its mounted path was also lost.
	endpoint := d.endpoint
	if d.endpointHost != "" { // use the host
		endpoint = filepath.Join("/proc/1/root", d.endpointHost)
		endpoint, _ = justifyRuntimeSocketFile(endpoint)
	}

	log.WithFields(log.Fields{"endpoint": endpoint}).Info("Reconnecting ...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cri, ver, err := newCriClient(endpoint, ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to create cri client")
		return err
	}

	d.storageDriver, _ = criGetStorageDevice(cri, ctx)

	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("cri-o connected")

	// update records
	d.criClient = cri
	d.version = ver
	return nil
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

func (d *crioDriver) GetSelfID() string {
	return d.selfID
}

func (d *crioDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	return getDevice(id, d, d.sys)
}

type criContainerInfo struct {
	Info struct {
		SandboxID   string `json:"sandboxID"`
		Pid         int    `json:"pid"`
		Image       string `json:"image"`
		Privileged  bool   `json:"privileged"`
		RuntimeSpec struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"runtimeSpec"`
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
		Labels:   pod.Status.Labels,
		Hostname: "",
		Envs:     make([]string, 0),
		Sandbox:  id,
		isChild:  false,
	}

	if info != nil {
		meta.Pid = info.Info.Pid
		meta.Image = info.Info.Image
		if img, ok := info.Info.RuntimeSpec.Annotations["io.kubernetes.cri-o.ImageName"]; ok {
			meta.Image = img
		}
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
		ID:       id,
		Name:     name,
		Pid:      info.Info.Pid,
		Sandbox:  info.Info.SandboxID,
		Labels:   cs.Status.Labels,
		Hostname: "",
		Envs:     make([]string, 0),
		isChild:  true,
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
	var metas []*ContainerMeta

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if resp_containers, err := criListContainers(d.criClient, ctx, true); err == nil && resp_containers != nil {
		for _, c := range resp_containers.Containers {
			m, err := d.getContainer(c.Id, ctx)
			if err != nil {
				log.WithFields(log.Fields{"container": c.Id, "error": err}).Error("Fail: container")
				continue
			}
			metas = append(metas, &m.ContainerMeta)
		}
	}

	if resp_sandboxes, err := criListPodSandboxes(d.criClient, ctx, true); err == nil && resp_sandboxes != nil {
		for _, pod := range resp_sandboxes.Items {
			m, err := d.getContainer(pod.Id, ctx)
			if err != nil {
				log.WithFields(log.Fields{"sandbox": pod.Id, "error": err}).Error("Fail: sandbox")
				continue
			}
			metas = append(metas, &m.ContainerMeta)
		}
	}

	if !runningOnly {
		if exited_containers, err := criListContainers(d.criClient, ctx, false); err == nil && exited_containers != nil {
			for _, c := range exited_containers.Containers {
				m, err := d.getContainer(c.Id, ctx)
				if err != nil {
					log.WithFields(log.Fields{"container": c.Id, "error": err}).Error("Fail: exited container")
					continue
				}
				metas = append(metas, &m.ContainerMeta)
			}
		}

		if exited_sandboxes, err := criListPodSandboxes(d.criClient, ctx, false); err == nil && exited_sandboxes != nil {
			for _, pod := range exited_sandboxes.Items {
				m, err := d.getContainer(pod.Id, ctx)
				if err != nil {
					log.WithFields(log.Fields{"sandbox": pod.Id, "error": err}).Error("Fail: exited sandbox")
					continue
				}
				metas = append(metas, &m.ContainerMeta)
			}
		}
	}
	return metas, nil
}

func (d *crioDriver) GetContainer(id string) (*ContainerMetaExtra, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return d.getContainer(id, ctx)
}

func (d *crioDriver) getContainer(id string, ctx context.Context) (*ContainerMetaExtra, error) {
	var pod *criRT.PodSandboxStatusResponse
	var meta *ContainerMetaExtra
	var cInfo *criContainerInfo

	// log.WithFields(log.Fields{"id": id}).Debug()
	if cs, err := criContainerStatus(d.criClient, ctx, id); err == nil && cs != nil {
		// log.WithFields(log.Fields{"cs": cs}).Debug("container")
		if cInfo, err = d.getContainerInfo(cs.Info); err != nil {
			log.WithFields(log.Fields{"id": id, "info": cs.Info}).Error("Fail to get cInfo")
			return nil, err
		}

		if cInfo.Info.SandboxID == "" { // a pod
			// a POD
			pod, err = criPodSandboxStatus(d.criClient, ctx, id)
			if err != nil {
				log.WithFields(log.Fields{"id": id, "cInfo": cInfo, "error": err}).Error("Fail to get its pod")
				return nil, err
			}

			meta = &ContainerMetaExtra{
				ContainerMeta: *d.getPodMeta(id, pod, cInfo),
				Privileged:    d.isPrivileged(pod.Status, nil),
				ExitCode:      int(cs.Status.ExitCode),
				Running:       pod.Status.State == criRT.PodSandboxState_SANDBOX_READY,
				Networks:      utils.NewSet(),
				ImageDigest:   imageRef2Digest(cs.Status.ImageRef),
			}

			if cs.Status.Image != nil {
				meta.Image = cs.Status.Image.Image
			} else {
				meta.Image = cs.Status.ImageRef
			}
		} else {
			pod, err = criPodSandboxStatus(d.criClient, ctx, cInfo.Info.SandboxID)
			if err != nil || pod == nil {
				log.WithFields(log.Fields{"id": id, "cInfo": cInfo, "error": err}).Error("Fail to get its pod")
				return nil, err
			}
			meta = &ContainerMetaExtra{
				ContainerMeta: *d.getContainerMeta(id, cs, pod, cInfo),
				ImageDigest:   imageRef2Digest(cs.Status.ImageRef),
				Privileged:    d.isPrivileged(pod.Status, cInfo),
				ExitCode:      int(cs.Status.ExitCode),
				Running:       cs.Status.State == criRT.ContainerState_CONTAINER_RUNNING || cs.Status.State == criRT.ContainerState_CONTAINER_CREATED,
				Networks:      utils.NewSet(),
				LogPath:       cs.Status.LogPath,
			}
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
			meta.ImgCreateAt = image.CreatedAt
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
					meta.ImgCreateAt = image.CreatedAt
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
	} else {
		if pod, err = criPodSandboxStatus(d.criClient, ctx, id); err != nil || pod == nil || pod.Status == nil {
			log.WithFields(log.Fields{"id": id, "pod": pod}).Error("Fail to get pod")
			return nil, err
		}
		// log.WithFields(log.Fields{"pod": pod}).Debug("pod")
		if pod.Info != nil {
			cInfo, err = d.getContainerInfo(pod.Info)
			if err != nil {
				log.WithFields(log.Fields{"id": id, "info": pod.Info}).Error("Fail to get pod info")
				return nil, err
			}
		}

		// a POD
		meta = &ContainerMetaExtra{
			ContainerMeta: *d.getPodMeta(id, pod, cInfo),
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
	}

	// retrive its network/pid namespace from the POD
	if pod.Status == nil || pod.Status.Linux == nil || pod.Status.Linux.Namespaces == nil || pod.Status.Linux.Namespaces.Options == nil {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return criGetImageMeta(d.criClient, ctx, name)
}

func (d *crioDriver) GetImageFile(id string) (io.ReadCloser, error) {
	return nil, ErrMethodNotSupported
}

func (d *crioDriver) ListContainerIDs() (utils.Set, utils.Set) {
	ids := utils.NewSet()
	stops := utils.NewSet()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp_containers, err := criListContainers(d.criClient, ctx, true)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to list containers")

		// lost connection, wait for 5 second try reconnect
		time.Sleep(time.Second * 5)
		if err := d.reConnect(); err != nil {
			log.WithFields(log.Fields{"err": err}).Error()
			d.failedQueryCnt++        // the query is coming every 20-seconds
			if d.failedQueryCnt > 5 { // 100 seconds
				// notify parent to exit container
				if d.eventCallback != nil {
					d.eventCallback(EventSocketError, "", 0)
				}
			}
			return ids, nil
		}
	} else if resp_containers != nil {
		for _, c := range resp_containers.Containers {
			ids.Add(c.Id)
		}
	}

	if exited_containers, err := criListContainers(d.criClient, ctx, false); err == nil && exited_containers != nil {
		for _, c := range exited_containers.Containers {
			stops.Add(c.Id)
			ids.Add(c.Id)
		}
	}

	d.failedQueryCnt = 0 // reset
	if resp_sandboxes, err := criListPodSandboxes(d.criClient, ctx, true); err == nil && resp_sandboxes != nil {
		for _, pod := range resp_sandboxes.Items {
			ids.Add(pod.Id)
		}
	}

	if exited_sandboxes, err := criListPodSandboxes(d.criClient, ctx, false); err == nil && exited_sandboxes != nil {
		for _, pod := range exited_sandboxes.Items {
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
	return proc == "runc" || proc == "crio" || proc == "conmon" || proc == "crio-conmon" // an OCI container runtime monitor
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
	d.eventCallback = cb
	return ErrMethodNotSupported
}

func (d *crioDriver) GetProxy() (string, string, string) {
	return "", "", ""
}

func (d *crioDriver) GetDefaultRegistries() []string {
	return nil
}

func (d *crioDriver) GetStorageDriver() string {
	return d.storageDriver
}

func (d *crioDriver) setPodImageInfo() error {
	// log.WithFields(log.Fields{"repoDigest": d.podImgRepoDigest}).Debug("CRIO")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if list, err := criListImages(d.criClient, ctx); err == nil {
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
