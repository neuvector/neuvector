package e2e_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	nvAPISvcName = "neuvector-svc-controller-api"
)

type nvAPIEndpointKey struct{}

func getAPIEndpoint(ctx context.Context) string {
	return ctx.Value(nvAPIEndpointKey{}).(string)
}

// discoverAPIEndpoint is an env.Func that resolves the NeuVector controller REST API
// endpoint (https://<nodeIP>:<nodePort>) and stores it in the context.
// It must run after installHelmCharts, since the NodePort service is created by Helm.
func discoverAPIEndpoint() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, fmt.Errorf("create k8s client for endpoint discovery: %w", err)
		}

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: nvAPISvcName, Namespace: nvNamespace},
		}
		if err = client.Resources(nvNamespace).Get(ctx, nvAPISvcName, nvNamespace, svc); err != nil {
			return ctx, fmt.Errorf("get service %s: %w", nvAPISvcName, err)
		}
		if len(svc.Spec.Ports) == 0 {
			return ctx, fmt.Errorf("service %s has no ports", nvAPISvcName)
		}
		nodePort := svc.Spec.Ports[0].NodePort

		nodes := &corev1.NodeList{}
		if err = client.Resources().List(ctx, nodes); err != nil {
			return ctx, fmt.Errorf("list nodes: %w", err)
		}
		if len(nodes.Items) == 0 {
			return ctx, fmt.Errorf("no nodes found in cluster")
		}
		nodeIP := ""
		for _, addr := range nodes.Items[0].Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nodeIP = addr.Address
				break
			}
		}
		if nodeIP == "" {
			return ctx, fmt.Errorf("no InternalIP found on node %s", nodes.Items[0].Name)
		}

		endpoint := fmt.Sprintf("https://%s:%d", nodeIP, nodePort)
		return context.WithValue(ctx, nvAPIEndpointKey{}, endpoint), nil
	}
}

func setupAPIEndpoint(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	newCtx, err := discoverAPIEndpoint()(ctx, cfg)
	require.NoError(t, err, "discover NeuVector API endpoint")
	return newCtx
}

// newNVHTTPClient returns an HTTP client that skips TLS verification, suitable for
// talking to the NeuVector controller which uses a self-signed certificate in test clusters.
func newNVHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed cert in test cluster
		},
		Timeout: 30 * time.Second,
	}
}
