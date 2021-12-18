package resource

import (
	"fmt"
)

// for OperationType
const (
	OperationAll string = "*"
	Create       string = "CREATE"
	Update       string = "UPDATE"
	Delete       string = "DELETE"
	Connect      string = "CONNECT"
)

// for ServiceType
const (
	ServiceTypeClusterIP    string = "ClusterIP"
	ServiceTypeNodePort     string = "NodePort"
	ServiceTypeLoadBalancer string = "LoadBalancer"
	ServiceTypeExternalName string = "ExternalName"
)

// for FailurePolicyType
const (
	Ignore string = "Ignore"
	Fail   string = "Fail"
)

const (
	IgnoreLower string = "ignore"
	FailLower   string = "fail"
)

const DefTimeoutSeconds = 30

// for SideEffectClass
const (
	SideEffectNone         string = "None"
	SideEffectSome         string = "Some"
	SideEffectNoneOnDryRun string = "NoneOnDryRun"
)

func GetTlsKeyCertPath(svcName, ns string) (string, string) {
	keyPath := fmt.Sprintf("/etc/neuvector/certs/%s.%s.svc.key.pem", svcName, ns)
	certPath := fmt.Sprintf("/etc/neuvector/certs/%s.%s.svc.cert.pem", svcName, ns)
	return keyPath, certPath
}
