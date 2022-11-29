package orchestration

import (
	"testing"

	"github.com/neuvector/neuvector/share/container"
)

func TestServiceName(t *testing.T) {
	var driver base

	meta := container.ContainerMeta{
		Labels: make(map[string]string),
	}

	meta.Labels[container.DockerComposeProjectKey] = "Docker Trusted Registry 2.2.5 - (Replica 112dbe66163e)"
	meta.Labels[container.DockerComposeServiceKey] = "notary-server"

	svc := driver.GetService(&meta, "")
	expect := "Docker.Trusted.Registry.notary-server"
	if svc.Name != expect {
		t.Errorf("Error: expect=%v actual=%v\n", expect, svc)
	}

	meta.Labels[container.DockerComposeProjectKey] = "Docker Universal Control Plane RN3B:GP34:KHVM:LLB6:5CRA:HRTW:SCPJ:3OHZ:3DXG:W2Z2:6S76:YBTI"
	meta.Labels[container.DockerComposeServiceKey] = "ucp-auth-api"

	svc = driver.GetService(&meta, "")
	expect = "Docker.UCP.ucp-auth-api"
	if svc.Name != expect {
		t.Errorf("Error: expect=%v actual=%v\n", expect, svc)
	}
}

func TestPlatformDTR(t *testing.T) {
	var driver base

	meta := container.ContainerMeta{
		Labels: make(map[string]string),
	}

	meta.Image = "docker/dtr-garant:2.4.1"
	meta.Labels[container.DockerComposeProjectKey] = "Docker Trusted Registry 2.4.1 - (Replica c4dfe9fd6d23)"
	meta.Labels[container.DockerComposeServiceKey] = "com.docker.compose.service garant-c4dfe9fd6d23"
	meta.Labels[container.DockerUCPCollectionKey] = "swarm"

	role, _ := driver.GetPlatformRole(&meta)
	if role != container.PlatformContainerDockerDTR {
		t.Errorf("Error: Unexpected platform role=%v\n", role)
	}
}
