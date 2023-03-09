package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	criRT "k8s.io/cri-api/pkg/apis/runtime/v1"     // major
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"  // backward-compatible
)

var bCriApiV1Alpha2 bool 	// V1Alpha2 for older crio

// --
const (
	// unixProtocol is the network protocol of unix socket.
	unixProtocol = "unix"
)

func dial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(unixProtocol, addr, timeout)
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

// getAddressAndDialer returns the address parsed from the given endpoint and a dialer.
func getAddressAndDialer(endpoint string) (string, func(addr string, timeout time.Duration) (net.Conn, error), error) {
	protocol, addr, err := parseEndpointWithFallbackProtocol(endpoint, unixProtocol)
	if err != nil {
		return "", nil, err
	}
	if protocol != unixProtocol {
		return "", nil, fmt.Errorf("only support unix socket endpoint")
	}

	return addr, dial, nil
}

// --
func newCriClient(sock string, ctx context.Context) (*grpc.ClientConn, *criRT.VersionResponse, error) {
	addr, dialer, err := getAddressAndDialer("unix://" + sock)
	if err != nil {
		return nil, nil, err
	}

	log.WithFields(log.Fields{"addr": addr}).Debug()
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithTimeout(4*time.Second), grpc.WithDialer(dialer))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect, make sure you are running as root and the runtime has been started: %v", err)
	}

	rtVersion, err := criRT.NewRuntimeServiceClient(conn).Version(ctx, &criRT.VersionRequest{})
	if err != nil {
		// try v1alpha2
		log.WithFields(log.Fields{"error": err}).Debug("try v1alpha2 ...")
		ver, err := pb.NewRuntimeServiceClient(conn).Version(ctx, &pb.VersionRequest{})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to get crio version")
			return nil, nil, err
		}
		bCriApiV1Alpha2 = true		// a global key selector
		rtVersion = (*criRT.VersionResponse)(unsafe.Pointer(ver))
	}
	return conn, rtVersion, err
}

func criGetStatus(conn *grpc.ClientConn, ctx context.Context) (*criRT.StatusResponse, error) {
	if bCriApiV1Alpha2 {
		status, err := pb.NewRuntimeServiceClient(conn).Status(ctx, &pb.StatusRequest{Verbose: true})
		return (*criRT.StatusResponse)(unsafe.Pointer(status)), err
	}
	return criRT.NewRuntimeServiceClient(conn).Status(ctx, &criRT.StatusRequest{Verbose: true})
}

func criListContainers(conn *grpc.ClientConn, ctx context.Context) (*criRT.ListContainersResponse, error) {
	if bCriApiV1Alpha2 {
		resp_containers, err := pb.NewRuntimeServiceClient(conn).ListContainers(ctx, &pb.ListContainersRequest{})
		return (*criRT.ListContainersResponse)(unsafe.Pointer(resp_containers)), err
	}
	return criRT.NewRuntimeServiceClient(conn).ListContainers(ctx, &criRT.ListContainersRequest{})
}

func criListPodSandboxes(conn *grpc.ClientConn, ctx context.Context) (*criRT.ListPodSandboxResponse, error) {
	if bCriApiV1Alpha2 {
		resp_sandboxes, err := pb.NewRuntimeServiceClient(conn).ListPodSandbox(ctx, &pb.ListPodSandboxRequest{})
		return (*criRT.ListPodSandboxResponse)(unsafe.Pointer(resp_sandboxes)), err
	}
	return criRT.NewRuntimeServiceClient(conn).ListPodSandbox(ctx, &criRT.ListPodSandboxRequest{})
}

func criPodSandboxStatus(conn *grpc.ClientConn, ctx context.Context, id string) (*criRT.PodSandboxStatusResponse, error) {
	if bCriApiV1Alpha2 {
		pod, err := pb.NewRuntimeServiceClient(conn).PodSandboxStatus(ctx, &pb.PodSandboxStatusRequest{PodSandboxId: id, Verbose: true})
		return (*criRT.PodSandboxStatusResponse)(unsafe.Pointer(pod)), err
	}
	return criRT.NewRuntimeServiceClient(conn).PodSandboxStatus(ctx, &criRT.PodSandboxStatusRequest{PodSandboxId: id, Verbose: true})
}

func criContainerStatus(conn *grpc.ClientConn, ctx context.Context, id string) (*criRT.ContainerStatusResponse, error) {
	if bCriApiV1Alpha2 {
		cs, err := pb.NewRuntimeServiceClient(conn).ContainerStatus(ctx, &pb.ContainerStatusRequest{ContainerId: id, Verbose: true})
		return (*criRT.ContainerStatusResponse)(unsafe.Pointer(cs)), err
	}
	return criRT.NewRuntimeServiceClient(conn).ContainerStatus(ctx, &criRT.ContainerStatusRequest{ContainerId: id, Verbose: true})
}

func criListImages(conn *grpc.ClientConn, ctx context.Context) (*criRT.ListImagesResponse, error) {
	if bCriApiV1Alpha2 {
		list, err := pb.NewImageServiceClient(conn).ListImages(ctx, &pb.ListImagesRequest{})
		return (*criRT.ListImagesResponse)(unsafe.Pointer(list)), err
	}
	return criRT.NewImageServiceClient(conn).ListImages(ctx, &criRT.ListImagesRequest{})
}

func criImageStatus(conn *grpc.ClientConn, ctx context.Context, name string) (*criRT.ImageStatusResponse, error) {
	if bCriApiV1Alpha2 {
		status, err := pb.NewImageServiceClient(conn).ImageStatus(ctx,
			&pb.ImageStatusRequest{Image: &pb.ImageSpec{Image: name}, Verbose: true})
		return (*criRT.ImageStatusResponse)(unsafe.Pointer(status)), err
	}
	return criRT.NewImageServiceClient(conn).ImageStatus(ctx,
			&criRT.ImageStatusRequest{Image: &criRT.ImageSpec{Image: name}, Verbose: true})
}

func criGetImageMeta(conn *grpc.ClientConn, ctx context.Context, name string) (*ImageMeta, error) {
	type criImageInfo struct {
		Info struct {
			ImageSpec struct {
				Author string `json:"author"`
				Config struct {
					Enrtrypoint []string          `json:"Entrypoint"`
					Labels      map[string]string `json:"Labels"`
				} `json:"config"`
			} `json:"imageSpec"`
		} `json:"info"`
	}

	resp, err := criImageStatus(conn, ctx, name)
	if err == nil && resp != nil && resp.Image != nil {
		meta := &ImageMeta{
			ID:     resp.Image.Id,
			Size:   int64(resp.Image.Size_),
			Labels: make(map[string]string),
		}

		for _, tag := range resp.Image.RepoTags {
			meta.RepoTags = append(meta.RepoTags, tag)
		}

		if len(resp.Image.RepoDigests) > 0 {
			meta.Digest = resp.Image.RepoDigests[0]
		}

		jsonInfo := buildJsonFromMap(resp.GetInfo())
		var res criImageInfo
		if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
			// log.WithFields(log.Fields{"error": err, "json": jsonInfo}).Error()
			return nil, err
		}

		meta.Author = res.Info.ImageSpec.Author
		if res.Info.ImageSpec.Config.Labels != nil {
			meta.Labels = res.Info.ImageSpec.Config.Labels
		}
		return meta, nil
	}

	log.WithFields(log.Fields{"error": err, "name": name}).Error("Failed to get image meta")
	return nil, errors.New("Failed to get image meta")
}
