package orchestration

import (
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCustomServiceNameLabelGate verifies that the io.neuvector.service.name label is
// honored only when the feature is enabled, and that all drivers fall through to their
// normal service-name heuristics when it is disabled (the default).
func TestCustomServiceNameLabelGate(t *testing.T) {
	k8s := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}
	baseDrv := &base{}
	ecsDrv := &ecs{}

	cases := []struct {
		name     string
		enabled  bool
		get      func() *Service
		expected string
	}{
		{
			name:    "k8s label honored when enabled",
			enabled: true,
			get: func() *Service {
				return k8s.GetServiceFromPodLabels("prod", "frontend-3823415956-853n5", "", map[string]string{
					container.NeuvectorSetServiceName: "MyApp",
					container.KubeKeyPodHash:          "3823415956",
				})
			},
			expected: "myapp",
		},
		{
			name:    "k8s label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return k8s.GetServiceFromPodLabels("prod", "frontend-3823415956-853n5", "", map[string]string{
					container.NeuvectorSetServiceName: "MyApp",
					container.KubeKeyPodHash:          "3823415956",
				})
			},
			expected: "frontend",
		},
		{
			name:    "docker label honored when enabled",
			enabled: true,
			get: func() *Service {
				return baseDrv.GetService(&container.ContainerMeta{
					Image:  "nginx:1.0",
					Labels: map[string]string{container.NeuvectorSetServiceName: "mydockersvc"},
				}, "")
			},
			expected: "mydockersvc",
		},
		{
			name:    "docker label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return baseDrv.GetService(&container.ContainerMeta{
					Image:  "nginx:1.0",
					Labels: map[string]string{container.NeuvectorSetServiceName: "mydockersvc"},
				}, "")
			},
			expected: "nginx",
		},
		{
			name:    "ecs label honored when enabled",
			enabled: true,
			get: func() *Service {
				return ecsDrv.GetService(&container.ContainerMeta{
					Labels: map[string]string{
						container.NeuvectorSetServiceName: "myecssvc",
						container.ECSCluster:              "cluster1",
						container.ECSTaskDefinition:       "task1",
						container.ECSContainerName:        "app",
					},
				}, "")
			},
			expected: "myecssvc",
		},
		{
			name:    "ecs label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return ecsDrv.GetService(&container.ContainerMeta{
					Labels: map[string]string{
						container.NeuvectorSetServiceName: "myecssvc",
						container.ECSCluster:              "cluster1",
						container.ECSTaskDefinition:       "task1",
						container.ECSContainerName:        "app",
					},
				}, "")
			},
			expected: "cluster1.task1.app",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := enableCustomSvcName
			enableCustomSvcName = c.enabled
			defer func() { enableCustomSvcName = old }()

			svc := c.get()
			require.NotNil(t, svc)
			assert.Equal(t, c.expected, svc.Name)
		})
	}
}
