package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd"
	apiEvents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/typeurl"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	criRT "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultContainerdSock = "/run/containerd/containerd.sock"
const defaultK3sContainerdSock = "/run/k3s/containerd/containerd.sock"
const k8sContainerdNamespace = "k8s.io"

// const defaultContainerdNamespace = "default"

type containerdDriver struct {
	sys           *system.SystemTools
	sysInfo       *sysinfo.SysInfo
	endpoint      string
	endpointHost  string
	nodeHostname  string
	selfID        string
	client        *containerd.Client
	criClient     *grpc.ClientConn
	version       *containerd.Version
	cancelMonitor context.CancelFunc
	rtProcMap     utils.Set
	snapshotter   string
	pidHost       bool
}

// patch for the mismatched grpc versions
func wrapIntoErrorString(err error) error {
	return errors.New(err.Error())
}

func containerdConnect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Debug("Connecting to containerd")

	client, err := containerd.New(endpoint,
		containerd.WithDefaultNamespace(k8sContainerdNamespace),
		containerd.WithTimeout(clientConnectTimeout))
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("")
		return nil, wrapIntoErrorString(err)
	}

	sockPath := endpoint

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// optional
	snapshotter := ""
	id, _, _ := sys.GetSelfContainerID() // not relaible, could be sandboxID
	cri, criVer, err := newCriClient(endpoint, ctx)
	if err == nil {
		log.WithFields(log.Fields{"version": criVer}).Info("cri")
		if status, err := criGetStatus(cri, ctx); err == nil {
			snapshotter, err = decodeSnapshotter(status.Info)
			if err != nil { // reserved debug for newer versions
				log.WithFields(log.Fields{"info": status.Info, "error": err}).Error()
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("cri info")
		}

		id, _ = criGetSelfID(cri, ctx, id)
		sockPath, err = criGetContainerSocketPath(cri, ctx, id, endpoint)
		if err == nil {
			log.WithFields(log.Fields{"selfID": id, "sockPath": sockPath}).Info()
		}
	}

	ver, err := client.Version(ctx)
	if err != nil {
		return nil, wrapIntoErrorString(err)
	}

	log.WithFields(log.Fields{"endpoint": endpoint, "sockPath": sockPath, "version": ver}).Info("containerd connected")

	driver := containerdDriver{
		sys: sys, client: client, version: &ver, criClient: cri, endpoint: endpoint, endpointHost: sockPath,
		// Read /host/proc/sys/kernel/hostname doesn't give the correct node hostname. Change UTS namespace to read it
		sysInfo: sys.GetSystemInfo(), nodeHostname: sys.GetHostname(1), snapshotter: snapshotter, selfID: id,
	}

	driver.rtProcMap = utils.NewSet("runc", "containerd", "containerd-shim", "containerd-shim-runc-v1", "containerd-shim-runc-v2")
	driver.pidHost = IsPidHost()
	return &driver, nil
}

func (d *containerdDriver) reConnect() error {
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

	client, err := containerd.New(endpoint,
		containerd.WithDefaultNamespace(k8sContainerdNamespace),
		containerd.WithTimeout(clientConnectTimeout))
	if err != nil {
		return wrapIntoErrorString(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ver, err := client.Version(ctx)
	if err != nil {
		return wrapIntoErrorString(err)
	}
	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("containerd connected")

	// optional: cri connection
	cri, criVer, err := newCriClient(endpoint, ctx)
	if err == nil {
		log.WithFields(log.Fields{"version": criVer}).Info("cri")
	}

	// update records
	d.client = client
	d.criClient = cri
	d.version = &ver
	return nil
}

func (d *containerdDriver) String() string {
	return RuntimeContainerd
}

func (d *containerdDriver) GetHost() (*share.CLUSHost, error) {
	var host share.CLUSHost

	host.Runtime = d.String()
	if d.version != nil {
		host.RuntimeVer = d.version.Version
		host.RuntimeAPIVer = d.version.Version
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

func (d *containerdDriver) GetSelfID() string {
	return d.selfID
}

func (d *containerdDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	return getDevice(id, d, d.sys)
}

// When a container task is killed, 'task' can still be retrieved; but when it is deleted, task will be nil
func (d *containerdDriver) getSpecs(ctx context.Context, c containerd.Container) (*containers.Container, *oci.Spec, int, *containerd.Status, int, error) {
	info, err := c.Info(ctx)
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
		return nil, nil, 0, nil, 0, wrapIntoErrorString(err)
	}

	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}

	spec, err := c.Spec(ctx)
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container spec")
		return nil, nil, 0, nil, 0, wrapIntoErrorString(err)
	}

	// if image name is a digest identifier
	if strings.HasPrefix(info.Image, "sha256:") {
		if imageName := d.reverseImageNameFromDigestName(info.Image); imageName != "" {
			info.Image = imageName
		}
	}

	if meta, pid, attempt, err := d.GetContainerCriSupplement(c.ID()); err == nil {
		// log.WithFields(log.Fields{"meta": meta}).Info("CRI")
		state := containerd.Stopped
		if meta.Running {
			state = containerd.Running
		}
		status := &containerd.Status{
			Status:     state,
			ExitStatus: uint32(meta.ExitCode),
			ExitTime:   meta.FinishedAt,
		}
		return &info, spec, pid, status, int(attempt), nil
	}

	// 2nd try on the ctr task
	rootpid := 0
	attempts := 0
	if task, err := c.Task(ctx, nil); err == nil {
		rootpid = int(task.Pid())
		if ext, err := c.Extensions(ctx); err == nil {
			if pdata, ok := ext["io.cri-containerd.sandbox.metadata"]; ok {
				attempts, err = d.decodeExtension_attempt(pdata.GetValue())
				if err != nil {
					log.WithFields(log.Fields{"id": c.ID(), "rootpid": rootpid, "err": err}).Error("CTR: sandbox")
				}
				//	log.WithFields(log.Fields{"id": c.ID(), "attempt": attempt}).Debug("CTR: sandbox")
			} else if pdata, ok := ext["io.cri-containerd.container.metadata"]; ok {
				attempts, err = d.decodeExtension_attempt(pdata.GetValue())
				if err != nil {
					log.WithFields(log.Fields{"id": c.ID(), "rootpid": rootpid, "err": err}).Error("CTR: container")
				}
				//	log.WithFields(log.Fields{"id": c.ID(),"attempt": attempt}).Debug("CTR: container")
			}
		}

		if status, err := task.Status(ctx); err == nil {
			return &info, spec, rootpid, &status, attempts, nil
		}
	}

	status := &containerd.Status{ // unknown
		Status:     containerd.Stopped,
		ExitStatus: 0,
		ExitTime:   time.Time{},
	}
	return &info, spec, rootpid, status, attempts, nil
}

func (d *containerdDriver) getMeta(info *containers.Container, spec *oci.Spec, pid int, attempt int) (*ContainerMeta, string, time.Time) {
	var author string
	var imgCreateAt time.Time

	meta := &ContainerMeta{
		ID:       info.ID,
		Name:     info.ID,
		Image:    info.Image,
		Labels:   info.Labels,
		Hostname: spec.Hostname,
		Pid:      pid,
	}
	if image, err := d.GetImage(info.Image); err == nil {
		author = image.Author
		imgCreateAt = image.CreatedAt
		for k, v := range image.Labels {
			// Not to overwrite container labels when merging
			if _, ok := meta.Labels[k]; !ok {
				meta.Labels[k] = v
			}
		}
	}

	if spec.Process != nil {
		meta.Envs = spec.Process.Env
	}
	if spec.Linux != nil {
		// If a namespace path doesn't exist, it is host mode
		var hasPid, hasNet bool
		for _, ns := range spec.Linux.Namespaces {
			switch ns.Type {
			case specs.PIDNamespace:
				hasPid = true
				meta.PidMode = ns.Path
			case specs.NetworkNamespace:
				// Containerd use CNI to manage container network.
				hasNet = true
				meta.NetMode = ns.Path
				if ppid := d.sys.ParseNetNamespacePath(meta.NetMode); ppid > 0 {
					meta.isChild = true
				}
			}
		}

		// update the workload name only when below entry is existed
		if _, ok := info.Labels["io.kubernetes.pod.namespace"]; ok {
			if meta.isChild {
				// application
				meta.Name = "k8s_" + info.Labels["io.kubernetes.container.name"] + "_" +
					info.Labels["io.kubernetes.pod.name"] + "_" +
					info.Labels["io.kubernetes.pod.namespace"] + "_" +
					info.Labels["io.kubernetes.pod.uid"] + "_" +
					fmt.Sprintf("%d", attempt)
			} else {
				// pod
				meta.Name = "k8s_POD_" + info.Labels["io.kubernetes.pod.name"] + "_" +
					info.Labels["io.kubernetes.pod.namespace"] + "_" +
					info.Labels["io.kubernetes.pod.uid"] + "_" +
					fmt.Sprintf("%d", attempt)
			}
		} else {
			log.Debug("no k8s namespace label")
		}

		// [{Type:pid Path:} {Type:ipc Path:} {Type:uts Path:} {Type:mount Path:}]
		// [{Type:pid Path:} {Type:ipc Path:} {Type:uts Path:} {Type:mount Path:} {Type:network Path:/var/run/netns/cni-3018ce67-8056-7321-210a-e42a37a98f5a}]
		// [{Type:pid Path:} {Type:ipc Path:/proc/11217/ns/ipc} {Type:uts Path:/proc/11217/ns/uts} {Type:mount Path:} {Type:network Path:/proc/11217/ns/net}]
		if !hasPid {
			meta.PidMode = "host"
		}
		if !hasNet {
			meta.NetMode = "host"
		}
	}
	return meta, author, imgCreateAt
}

func (d *containerdDriver) isPrivileged(spec *oci.Spec, id string, bSandBox bool) bool {
	for _, m := range spec.Mounts {
		switch m.Type {
		case "sysfs":
			for _, o := range m.Options {
				switch o {
				case "rw":
					return true
				}
			}
		}
	}

	// 2nd chance from cri
	if bSandBox {
		return d.isPrivilegedPod_CRI(id)
	}
	return d.isPrivilegedContainer_CRI(id)
}

func (d *containerdDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) {
	ctx, cancel := context.WithCancel(context.Background())
	containers, err := d.client.Containers(ctx)
	defer cancel()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to list containers")
		return nil, wrapIntoErrorString(err)
	}

	metas := make([]*ContainerMeta, 0, len(containers))
	for _, c := range containers {
		info, spec, pid, status, attempt, err := d.getSpecs(ctx, c)
		if err != nil {
			log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
			continue
		}

		if runningOnly && (status == nil || status.Status != containerd.Running) {
			continue
		}

		meta, _, _ := d.getMeta(info, spec, pid, attempt)
		metas = append(metas, meta)
	}

	return metas, nil
}

func (d *containerdDriver) GetContainer(id string) (*ContainerMetaExtra, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to get container")
		return nil, wrapIntoErrorString(err)
	}

	info, spec, pid, status, attempt, err := d.getSpecs(ctx, c)
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
		return nil, wrapIntoErrorString(err)
	}

	bSandBox := false
	if kind, ok := info.Labels["io.cri-containerd.kind"]; ok && kind == "sandbox" {
		bSandBox = true
	}

	cmeta, author, imgCreatedAt := d.getMeta(info, spec, pid, attempt)
	meta := &ContainerMetaExtra{
		ContainerMeta: *cmeta,
		Author:        author,
		ImgCreateAt:   imgCreatedAt,
		Privileged:    d.isPrivileged(spec, c.ID(), bSandBox),
		Networks:      utils.NewSet(),
	}

	if !info.CreatedAt.IsZero() {
		meta.CreatedAt = info.CreatedAt
		meta.StartedAt = meta.CreatedAt
	}

	if status != nil {
		meta.Running = (status.Status == containerd.Running)
		meta.ExitCode = int(status.ExitStatus)
		if !status.ExitTime.IsZero() {
			meta.FinishedAt = status.ExitTime
		}
	}
	if spec.Linux != nil && spec.Linux.Resources != nil {
		r := spec.Linux.Resources
		if r.Memory != nil && r.Memory.Limit != nil {
			meta.MemoryLimit = *r.Memory.Limit
		}
		if r.CPU != nil {
			meta.CPUs = r.CPU.Cpus
		}
	}

	if img, err := c.Image(ctx); err == nil {
		meta.ImageDigest = img.Target().Digest.String()
		if imgCfg, err := img.Config(ctx); err == nil {
			meta.ImageID = TrimImageID(imgCfg.Digest.String())
		} else {
			log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container image config")
		}
	} else {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container image")
	}

	return meta, nil
}

func (d *containerdDriver) GetImageHistory(name string) ([]*ImageHistory, error) {
	return nil, ErrMethodNotSupported
}

func (d *containerdDriver) GetImage(name string) (*ImageMeta, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return criGetImageMeta(d.criClient, ctx, name)
}

func (d *containerdDriver) GetImageFile(id string) (io.ReadCloser, error) {
	return nil, ErrMethodNotSupported
}

func (d *containerdDriver) ListContainerIDs() (utils.Set, utils.Set) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ids := utils.NewSet()
	containers, err := d.client.Containers(ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to list containers")
		return ids, nil
	}

	for _, c := range containers {
		ids.Add(c.ID())
	}
	return ids, nil
}

func (d *containerdDriver) GetNetworkEndpoint(netName, container, epName string) (*NetworkEndpoint, error) {
	return nil, ErrMethodNotSupported
}

func (d *containerdDriver) ListNetworks() (map[string]*Network, error) {
	return make(map[string]*Network), nil
}

func (d *containerdDriver) GetService(id string) (*Service, error) {
	return nil, ErrMethodNotSupported
}

func (d *containerdDriver) ListServices() ([]*Service, error) {
	return make([]*Service, 0), nil
}

func (d *containerdDriver) IsDaemonProcess(proc string, cmds []string) bool {
	return false
}

func (d *containerdDriver) IsRuntimeProcess(proc string, cmds []string) bool {
	return d.rtProcMap.Contains(proc)
}

func (d *containerdDriver) GetParent(meta *ContainerMetaExtra, pidMap map[int]string) (bool, string) {
	// {Type:network Path:/proc/11217/ns/net}
	pid := d.sys.ParseNetNamespacePath(meta.NetMode)
	if pid == 0 {
		return false, ""
	}
	if pidMap == nil {
		return true, ""
	} else {
		if id, ok := pidMap[pid]; ok {
			return true, id
		} else {
			return true, ""
		}
	}
}

func (d *containerdDriver) StopMonitorEvent() {
	d.cancelMonitor()
}

func (d *containerdDriver) MonitorEvent(cb EventCallback, cpath bool) error {
	if cpath {
		return ErrMethodNotSupported
	}

	var connectErrorCnt int
	for {
		ctx, cancel := context.WithCancel(context.Background())
		d.cancelMonitor = cancel
		evCh, errCh := d.client.Subscribe(ctx,
			`topic~="/tasks/start"`,
			`topic~="/tasks/exit"`,
			`topic~="/containers/delete"`,
		)

	Loop:
		for {
			select {
			case ev := <-evCh:
				if ev.Event != nil {
					v, err := typeurl.UnmarshalAny(ev.Event)
					if err != nil {
						log.WithFields(log.Fields{"error": err.Error(), "event": v}).Error("Unmarshal containderd event error")
						break
					}
					switch event := v.(type) {
					case *apiEvents.TaskStart:
						// TaskStart{ContainerID:25d62dcf65...,Pid:10560,}
						log.WithFields(log.Fields{"event": v}).Debug("start")
						cb(EventContainerStart, event.ContainerID, int(event.Pid))
					case *apiEvents.TaskExit:
						// TaskExit{ContainerID:25d62dcf65...,ID:25d62dcf65...,Pid:10560,ExitStatus:0,ExitedAt:2018-11-01 07:40:22.252023597 +0000 UTC,}
						log.WithFields(log.Fields{"event": v}).Debug("stop")
						cb(EventContainerStop, event.ContainerID, int(event.Pid))
					case *apiEvents.ContainerDelete:
						// ContainerDelete{ID:25d62dcf65...,}
						log.WithFields(log.Fields{"event": v}).Debug("delete")
						cb(EventContainerDelete, event.ID, 0)
					default:
						log.WithFields(log.Fields{"event": v}).Debug("Unknown containderd event")
					}
					connectErrorCnt = 0 // reset
				}
			case err := <-errCh:
				if err != nil && err != io.EOF {
					log.WithFields(log.Fields{"error": err.Error()}).Error("Containderd event monitor error")
					if strings.Contains(err.Error(), "rpc error: code = Unavailable") {
						// lost connection, wait for 10 second try reconnect
						time.Sleep(time.Second * 10)
						if err := d.reConnect(); err != nil {
							log.WithFields(log.Fields{"err": err}).Error()
							break
						}
					}
					connectErrorCnt++
					if connectErrorCnt >= 12 { // restart enforcer
						cb(EventSocketError, "", 0)
					}
				}
				break Loop
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (d *containerdDriver) GetProxy() (string, string, string) {
	return "", "", ""
}

func (d *containerdDriver) GetDefaultRegistries() []string {
	return nil
}

func (d *containerdDriver) GetStorageDriver() string {
	return d.snapshotter
}

func (d *containerdDriver) reverseImageNameFromDigestName(digestName string) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if image, err := d.client.GetImage(ctx, digestName); err == nil {
		digest := image.Target().Digest.String()
		if images, err := d.client.ListImages(ctx, ""); err == nil {
			for _, img := range images {
				if img.Name() == digestName { // skip
					continue
				}

				if img.Target().Digest.String() == digest {
					log.WithFields(log.Fields{"Name": img.Name()}).Debug("Found")
					return img.Name()
				}
			}
		}
	}
	return ""
}

// / below structures are for decoding purpose only
type containerdConfigMeta struct {
	Name      string `json:"name"`
	Uid       string `json:"uid"`
	Namespace string `json:"namespace"`
	Attempt   int    `json:"attempt"`
}

type containerdConfigImage struct {
	Image string `json:"image"`
}

type containerdConfig struct {
	Meta  containerdConfigMeta  `json:"metadata"`
	Image containerdConfigImage `json:"image"`
}

type containerdMetadata struct {
	Id        string           `json:"ID"`
	Name      string           `json:"Name"`
	SandboxID string           `json:"SandboxID"` // only in application container
	Config    containerdConfig `json:"Config"`
}

type containerdExtension struct {
	Version  string             `json:"Version"`
	Metadata containerdMetadata `json:"Metadata"`
}

func (d *containerdDriver) decodeExtension_attempt(extData []byte) (int, error) {
	// log.WithFields(log.Fields{"ext": extDataStr}).Debug("CTR:")  // a json file
	var ext containerdExtension
	if err := json.Unmarshal(extData, &ext); err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("CTR:")
		return 0, err
	}

	attempt := ext.Metadata.Config.Meta.Attempt
	// log.WithFields(log.Fields{"ext": ext}).Debug("CTR:")  // a json file
	return attempt, nil
}

func (d *containerdDriver) GetContainerCriSupplement(id string) (*ContainerMetaExtra, int, uint32, error) {
	if d.criClient == nil {
		return nil, 0, 0, nil
	}

	var meta *ContainerMetaExtra
	var attempt uint32
	var pid int

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pod, err := criPodSandboxStatus(d.criClient, ctx, id)
	if err == nil && pod != nil {
		if pod.Status == nil || pod.Info == nil {
			log.WithFields(log.Fields{"id": id, "pod": pod}).Error("Fail to get pod")
			return nil, 0, 0, err
		}

		// a POD
		meta = &ContainerMetaExtra{
			CreatedAt: time.Unix(0, pod.Status.CreatedAt),
			Running:   pod.Status.State == criRT.PodSandboxState_SANDBOX_READY,
		}
		attempt = pod.Status.Metadata.Attempt
		pid, _ = d.getContainerPid_CRI(pod.GetInfo())
	} else {
		// an APP container
		cs, err2 := criContainerStatus(d.criClient, ctx, id)
		if err2 != nil || cs.Status == nil || cs.Info == nil {
			log.WithFields(log.Fields{"id": id, "error": err2, "cs": cs}).Error("Fail to get container")
			return nil, 0, 0, err2
		}

		meta = &ContainerMetaExtra{
			ExitCode: int(cs.Status.ExitCode),
			Running:  cs.Status.State == criRT.ContainerState_CONTAINER_RUNNING || cs.Status.State == criRT.ContainerState_CONTAINER_CREATED,
		}
		attempt = cs.Status.Metadata.Attempt
		pid, _ = d.getContainerPid_CRI(cs.GetInfo())
	}
	return meta, pid, attempt, nil
}

// /////
type criContainerInfoRes struct {
	Info struct {
		Pid    int `json:"pid"`
		Config struct {
			MetaData struct {
				Name string `json:"name"`
			} `json:"metadata"`

			Image struct {
				Name string `json:"image"`
			} `json:"image"`

			Linux struct {
				SecurityContext struct {
					Privileged bool `json:"privileged"`
				} `json:"security_context"`
			} `json:"linux"`
		} `json:"config"`
	} `json:"info"`
}

func (d *containerdDriver) isPrivilegedContainer_CRI(id string) bool {
	if d.criClient == nil {
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cs, err := criContainerStatus(d.criClient, ctx, id); err == nil {
		var res criContainerInfoRes
		jsonInfo := buildJsonFromMap(cs.GetInfo()) // from map[string]string
		if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
			// log.WithFields(log.Fields{"error": err, "json": jsonInfo}).Error()
			return false
		}

		// expandable structures
		// log.WithFields(log.Fields{"info": res.Info}).Debug()
		return res.Info.Config.Linux.SecurityContext.Privileged
	}
	return false
}

func (d *containerdDriver) isPrivilegedPod_CRI(id string) bool {
	if d.criClient == nil {
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if pod, err := criPodSandboxStatus(d.criClient, ctx, id); err == nil {
		var res criContainerInfoRes
		jsonInfo := buildJsonFromMap(pod.GetInfo()) // from map[string]string
		if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
			// log.WithFields(log.Fields{"error": err, "json": jsonInfo}).Error()
			return false
		}

		// expandable structures
		// log.WithFields(log.Fields{"info": res.Info}).Debug()
		return res.Info.Config.Linux.SecurityContext.Privileged
	}
	return false
}

func (d *containerdDriver) getContainerPid_CRI(infoMap map[string]string) (int, error) {
	// Info is extra information of the Runtime. The key could be arbitrary string, and
	// value should be in json format.
	var res criContainerInfoRes

	jsonInfo := buildJsonFromMap(infoMap) // from map[string]string
	if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
		return 0, err
	}
	return res.Info.Pid, nil
}

func decodeSnapshotter(info map[string]string) (string, error) {
	// use a partial structure
	type InfoConfig struct {
		Config struct {
			Containerd struct {
				Snapshotter string `json:"snapshotter"`
			} `json:"containerd"`
		} `json:"config"`
	}

	jsonInfo := buildJsonFromMap(info)

	var cfg InfoConfig
	if err := json.Unmarshal([]byte(jsonInfo), &cfg); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return "", err
	}

	// log.WithFields(log.Fields{"snapshotter": cfg.Config.Containerd.Snapshotter}).Debug()
	if cfg.Config.Containerd.Snapshotter != "" {
		return cfg.Config.Containerd.Snapshotter, nil
	}

	// Alternative method:
	// (1) Decode unstructure Json string
	// (2) A map[string]interface{} type, and its type is asserted from the interface{} type

	//  var res map[string]interface{}
	//  if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
	//	     log.WithFields(log.Fields{"error": err}).Error()
	//	     return "", err
	//  }

	//  config := res["config"].(map[string]interface{})
	//  if _, ok := config["containerd"]; ok {
	//	     cs := config["containerd"].(map[string]interface{})
	//	     if snapshotter, ok := cs["snapshotter"]; ok {
	//		    return fmt.Sprintf("%v", snapshotter), nil
	//	     }
	//  }

	return "", errors.New("not found")
}
