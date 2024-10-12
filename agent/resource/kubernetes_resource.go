// [20220809] this is a simplified version of controller/resource/kubernetes_resource.go
package resource

import (
	"context"
	"fmt"
	"sync"

	"github.com/neuvector/k8s"
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type resourceMaker struct {
	apiVersion string
	//	newObject  func() metav1.Object
	//	newList    func() metav1.ListInterface
	//  xlate func(obj metav1.Object) (string, interface{})
}

type k8sResource struct {
	apiGroup string
	makers   []*resourceMaker
}

// ----------------------------------------------------------
var resourceMakers map[string]k8sResource = map[string]k8sResource{
	RscTypeImage: {apiGroup: "image.openshift.io", makers: []*resourceMaker{
		{
			"v1",
			//	func() metav1.Object { return new(ocImageStream) },
			//	func() metav1.ListInterface { return new(ocImageStreamList) },
			//  nil,
		},
	}},
}

type kubernetes struct {
	*noop

	lock      sync.RWMutex
	client    *k8s.Client
	discovery *k8s.Discovery
	version   *k8s.Version
}

func newKubernetesDriver(platform, flavor, network string) *kubernetes {
	d := &kubernetes{
		noop: newNoopDriver(platform, flavor, network),
	}
	return d
}

func (d *kubernetes) discoverResource(rt string) (*resourceMaker, error) {
	r, ok := resourceMakers[rt]
	if !ok {
		return nil, fmt.Errorf("Unknown resource name: %s", rt)
	}

	if d.discovery == nil {
		if err := d.newClient(); err != nil {
			return nil, err
		}
	}

	// Don't know how to discover core API group. 'v1' is always supported.
	if r.apiGroup == "" {
		return r.makers[0], nil
	}

	g, err := d.discovery.APIGroup(context.Background(), r.apiGroup)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover API group: %s(%s)", r.apiGroup, err.Error())
	}

	// First, try preferred version
	v := g.PreferredVersion.Version
	for _, maker := range r.makers {
		if v == maker.apiVersion {
			return maker, nil
		}
	}

	// Second, going through versions by our order
	vers := g.Versions
	supported := make([]string, len(vers))
	for _, maker := range r.makers {
		for i, ver := range vers {
			supported[i] = ver.Version
			if supported[i] == maker.apiVersion {
				return maker, nil
			}
		}
	}

	return nil, fmt.Errorf("Supported version not found")
}

func (d *kubernetes) RegisterResource(rt string) error {
	switch rt {
	case RscTypeImage:
		_, err := d.discoverResource(rt)
		if err == nil {
			d.lock.Lock()
			k8s.Register("image.openshift.io", "v1", "imagestreams", true, &ocImageStream{})
			k8s.RegisterList("image.openshift.io", "v1", "imagestreams", true, &ocImageStreamList{})
			d.lock.Unlock()
		}
		return err
	default:
		return ErrResourceNotSupported
	}
}

func (d *kubernetes) newClient() error {
	if client, err := k8s.NewInClusterClient(); err != nil {
		return err
	} else {
		d.client = client
		d.discovery = k8s.NewDiscoveryClient(client)

		d.version, _ = d.discovery.Version(context.Background())
	}
	return nil
}

func (d *kubernetes) SetFlavor(flavor string) error {
	if d.flavor == "" {
		d.flavor = flavor
	}

	return nil
}
