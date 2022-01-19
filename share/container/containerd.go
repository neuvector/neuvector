package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
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
	criRT "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

const defaultContainerdSock = "/run/containerd/containerd.sock"
const defaultContainerdNamespace = "default"
const k8sContainerdNamespace = "k8s.io"

type containerdDriver struct {
	sys           *system.SystemTools
	sysInfo       *sysinfo.SysInfo
	nodeHostname  string
	client        *containerd.Client
	criClient     *grpc.ClientConn
	version       *containerd.Version
	cancelMonitor context.CancelFunc
	rtProcMap     utils.Set
	snapshotter   string
}

func containerdConnect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Debug("Connecting to containerd")

	client, err := containerd.New(endpoint,
		containerd.WithDefaultNamespace(k8sContainerdNamespace),
		containerd.WithTimeout(clientConnectTimeout))
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return nil, err
	}

	// optional
	snapshotter := ""
	cri, err := newCriClient(endpoint)
	if err == nil {
		crt := criRT.NewRuntimeServiceClient(cri)
		req := &criRT.VersionRequest{}
		if criVer, err := crt.Version(context.Background(), req); err == nil {
			log.WithFields(log.Fields{"version": criVer}).Info("cri")
		}

		reqStatus := &criRT.StatusRequest{Verbose: true}
		if status, err := crt.Status(context.Background(), reqStatus); err == nil {
			snapshotter, err = decodeSnapshotter(status.Info)
			if err != nil { // reserved debug for newer versions
				log.WithFields(log.Fields{"info": status.Info, "error": err}).Error()
			}
		} else {
			log.WithFields(log.Fields{"error": err}).Error("cri info")
		}
	}

	ver, err := client.Version(context.Background())
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"endpoint": endpoint, "version": ver}).Info("containerd connected")

	driver := containerdDriver{
		sys: sys, client: client, version: &ver, criClient: cri,
		// Read /host/proc/sys/kernel/hostname doesn't give the correct node hostname. Change UTS namespace to read it
		sysInfo: sys.GetSystemInfo(), nodeHostname: sys.GetHostname(1), snapshotter: snapshotter,
	}

	driver.rtProcMap = utils.NewSet("runc", "containerd", "containerd-shim")
	return &driver, nil
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

func (d *containerdDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	return getDevice(id, d, d.sys)
}

// When a container task is killed, 'task' can still be retrieved; but when it is deleted, task will be nil
func (d *containerdDriver) getSpecs(c containerd.Container) (*containers.Container, *oci.Spec, containerd.Task, *containerd.Status, int, error) {
	info, err := c.Info(context.Background())
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
		return nil, nil, nil, nil, 0, err
	}
	spec, err := c.Spec(context.Background())
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container spec")
		return nil, nil, nil, nil, 0, err
	}
	task, err := c.Task(context.Background(), nil)
	if err != nil {
		meta, _ := d.GetContainerCriSupplement(c.ID())
		if meta != nil {
			// log.WithFields(log.Fields{"meta": meta}).Info("CRI")
			status := &containerd.Status{
				Status:     containerd.Stopped,
				ExitStatus: uint32(meta.ExitCode),
				ExitTime:   meta.FinishedAt,
			}
			return &info, spec, nil, status, 0, nil
		}
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Info("Failed to get container task")
		return &info, spec, nil, nil, 0, nil
	}
	status, err := task.Status(context.Background())
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Info("Failed to get container task status")
		return &info, spec, nil, nil, 0, nil
	}

	attempt := 0
	ext, err := c.Extensions(context.Background())
	if err == nil {
		if pdata, ok := ext["io.cri-containerd.sandbox.metadata"]; ok {
			attempt, err = d.decodeExtension_attempt(pdata.GetValue())
			//	log.WithFields(log.Fields{"id": c.ID(), "attempt": attempt}).Debug("CTR: sandbox")
		} else if pdata, ok := ext["io.cri-containerd.container.metadata"]; ok {
			attempt, err = d.decodeExtension_attempt(pdata.GetValue())
			//	log.WithFields(log.Fields{"id": c.ID(),"attempt": attempt}).Debug("CTR: container")
		}
	}

	// if image name is a digest identifier
	if strings.HasPrefix(info.Image, "sha256:") {
		if imageName := d.reverseImageNameFromDigestName(info.Image); imageName != "" {
			info.Image = imageName
		}
	}

	return &info, spec, task, &status, attempt, nil
}

func (d *containerdDriver) getMeta(info *containers.Container, spec *oci.Spec, task containerd.Task, attempt int) *ContainerMeta {
	meta := &ContainerMeta{
		ID:       info.ID,
		Name:     info.ID,
		Image:    info.Image,
		Labels:   info.Labels,
		Hostname: spec.Hostname,
	}
	if image, err := d.GetImage(info.Image); err == nil {
		for k, v := range image.Labels {
			// Not to overwrite container labels when merging
			if _, ok := meta.Labels[k]; !ok {
				meta.Labels[k] = v
			}
		}
	}

	if task != nil {
		meta.Pid = int(task.Pid())
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
	return meta
}

func (d *containerdDriver) isPrivileged(spec *oci.Spec, id string) bool {
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
	return d.isPrivilegedCri(id)
}

func (d *containerdDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) {
	containers, err := d.client.Containers(context.Background())
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to list containers")
		return nil, err
	}

	metas := make([]*ContainerMeta, 0, len(containers))
	for _, c := range containers {
		info, spec, task, status, attempt, err := d.getSpecs(c)
		if err != nil {
			log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
			continue
		}

		if runningOnly && (status == nil || status.Status != containerd.Running) {
			continue
		}

		metas = append(metas, d.getMeta(info, spec, task, attempt))
	}

	return metas, nil
}

func (d *containerdDriver) GetContainer(id string) (*ContainerMetaExtra, error) {
	c, err := d.client.LoadContainer(context.Background(), id)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to get container")
		return nil, err
	}

	info, spec, task, status, attempt, err := d.getSpecs(c)
	if err != nil {
		log.WithFields(log.Fields{"id": c.ID(), "error": err.Error()}).Error("Failed to get container info")
		return nil, err
	}

	meta := &ContainerMetaExtra{
		ContainerMeta: *d.getMeta(info, spec, task, attempt),
		Privileged:    d.isPrivileged(spec, c.ID()),
		CreatedAt:     info.CreatedAt,
		StartedAt:     info.CreatedAt,
		Networks:      utils.NewSet(),
	}
	if status != nil {
		meta.Running = (status.Status == containerd.Running)
		meta.ExitCode = int(status.ExitStatus)
		meta.FinishedAt = status.ExitTime
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

	if img, err := c.Image(context.Background()); err == nil {
		meta.ImageDigest = img.Target().Digest.String()
		if imgCfg, err := img.Config(context.Background()); err == nil {
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
	if image, err := d.client.GetImage(context.Background(), name); err == nil {
		target := image.Target()
		meta := &ImageMeta{
			ID:     target.Digest.String(),
			Digest: target.Digest.String(),
			Size:   target.Size,
			Labels: image.Labels(),
		}
		return meta, nil
	} else {
		return nil, err
	}
}

func (d *containerdDriver) GetImageFile(id string) (io.ReadCloser, error) {
	return nil, ErrMethodNotSupported
}

func (d *containerdDriver) ListContainerIDs() utils.Set {
	ids := utils.NewSet()

	containers, err := d.client.Containers(context.Background())
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to list containers")
		return ids
	}

	for _, c := range containers {
		ids.Add(c.ID())
	}
	return ids
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
						log.WithFields(log.Fields{"error": err, "event": v}).Error("Unmarshal containderd event error")
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
				}
			case err := <-errCh:
				if err != nil && err != io.EOF {
					log.WithFields(log.Fields{"error": err}).Error("Containderd event monitor error")
				}
				break Loop
			case <-ctx.Done():
				return nil
			}
		}
	}

	return nil
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
	if image, err := d.client.GetImage(context.Background(), digestName); err == nil {
		digest := image.Target().Digest.String()
		if images, err := d.client.ListImages(context.Background(), ""); err == nil {
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

/// below structures are for decoding purpose only
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

func (d *containerdDriver) GetContainerCriSupplement(id string) (*ContainerMetaExtra, error) {
	if d.criClient == nil {
		return nil, nil
	}

	crt := criRT.NewRuntimeServiceClient(d.criClient) // GRPC
	cs, err := crt.ContainerStatus(context.Background(), &criRT.ContainerStatusRequest{ContainerId: id, Verbose: true})
	if err != nil || cs.Status == nil {
		return nil, err
	}

	meta := &ContainerMetaExtra{
		FinishedAt: time.Unix(0, cs.Status.FinishedAt),
		ExitCode:   int(cs.Status.ExitCode),
	}
	return meta, nil
}

func (d *containerdDriver) isPrivilegedCri(id string) bool {
	if d.criClient == nil {
		return false
	}

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

	crt := criRT.NewRuntimeServiceClient(d.criClient) // GRPC
	if cs, err := crt.ContainerStatus(context.Background(), &criRT.ContainerStatusRequest{ContainerId: id, Verbose: true}); err == nil {
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

//// construct a json string from map[]
func buildJsonFromMap(info map[string]string) string {
	// sort all keys
	keys := []string{}
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	jsonInfo := "{"
	for _, k := range keys {
		var res interface{}
		// We attempt to convert key into JSON if possible else use it directly
		if err := json.Unmarshal([]byte(info[k]), &res); err != nil {
			jsonInfo += "\"" + k + "\"" + ":" + "\"" + info[k] + "\","
		} else {
			jsonInfo += "\"" + k + "\"" + ":" + info[k] + ","
		}
	}
	jsonInfo = jsonInfo[:len(jsonInfo)-1]
	jsonInfo += "}"
	// log.WithFields(log.Fields{"info": jsonInfo}).Debug()
	return jsonInfo
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
