package v1

import "github.com/neuvector/k8s"

func init() {
	k8s.Register("apps", "v1", "deployments", true, &Deployment{})
	k8s.RegisterList("apps", "v1", "deployments", true, &DeploymentList{})
}
