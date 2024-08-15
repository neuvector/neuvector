package rest

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"

	//	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/scan/secrets"
	"github.com/neuvector/neuvector/share/utils"
	//"github.com/neuvector/neuvector/vendor/github.com/neuvector/k8s"
)

const (
	tlsClientCA = "/var/neuvector/clientCA.cert.pem"
)

const (
	admissionWebhookAnnotationStatusKey = "neuvector-mutating-admission-webhook/status"
	admissionWebhookLabelKey            = "neuvector-mutating-admission-webhook/label"
)

const errFmtUnmarshall = "could not unmarshal raw %s object"

const (
	OPERATION_CREATE = iota
	OPERATION_UPDATE
	OPERATION_DELETE
)

const aggregateInterval = time.Minute * 8

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

// var emptyJSON = make(map[string]string)

type WebhookServer struct {
	dumpRequestObj bool
	server         *http.Server
	port           uint
	clientAuth     bool
	debug          bool
	running        bool
	reloadChan     chan int
}

type ContainerImage struct {
	registry  string
	imageRepo string
}

var admResCache = make(map[string]*nvsysadmission.AdmResObject) // key is the resource object id (object.metadata.uid)
var admResCacheMutex sync.RWMutex

var aggrLogsCache = make(map[string]*share.CLUSAuditLog) // key is "{owner uid}.{resource image}"
var aggrLogsCacheMutex sync.Mutex

var responseAllow = admissionv1beta1.AdmissionResponse{Allowed: true}

var whSvrsMutex sync.RWMutex
var whsvrs = make(map[string]*WebhookServer)

// ReplicaSet/pod's userinfo is always "system:serviceaccount:kube-system:deployment-controller"!

const (
	k8sKindCronJob               = "CronJob"
	k8sKindDaemonSet             = "DaemonSet"
	k8sKindDeployment            = "Deployment"
	k8sKindDeploymentConfig      = "DeploymentConfig"
	k8sKindJob                   = "Job"
	k8sKindPod                   = "Pod"
	K8sKindReplicationController = "ReplicationController"
	k8sKindReplicaSet            = "ReplicaSet"
	k8sKindService               = "Service"
	K8sKindStatefulSet           = "StatefulSet"
	K8sKindRole                  = "Role"
	K8sKindClusterRole           = "ClusterRole"
	K8sKindRoleBinding           = "RoleBinding"
	K8sKindClusterRoleBinding    = "ClusterRoleBinding"
	k8sKindPersistentVolumeClaim = "PersistentVolumeClaim"
)

var sidecarImages = []*ContainerImage{
	&ContainerImage{registry: "https://gcr.io/", imageRepo: "istio-release/proxyv2"},
	&ContainerImage{registry: "https://gcr.io/", imageRepo: "linkerd-io/proxy"},
	&ContainerImage{registry: "https://docker.io/", imageRepo: "istio/proxyv2"},
}

/*
	func init() {
		_ = corev1.AddToScheme(runtimeScheme)
		_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
		// defaulting with webhooks:
		// https://github.com/kubernetes/kubernetes/issues/57982
		_ = appsv1.AddToScheme(runtimeScheme)
		_ = batchv1beta1.AddToScheme(runtimeScheme)
	}
*/
func checkAggrLogsCache(alwaysFlush bool) {
	var err error
	aggrLogsCacheMutex.Lock()
	defer aggrLogsCacheMutex.Unlock()
	for key, alog := range aggrLogsCache { // key is {owner_uid}.{image}
		if alog != nil {
			if alwaysFlush || time.Now().Unix() > alog.ReportedAt.Unix() {
				delete(aggrLogsCache, key)
				if alog.Count > 0 {
					// use the last log's time as the aggregated log's ReportedAt
					alog.ReportedAt, err = time.Parse(api.RESTTimeFomat, alog.Props[nvsysadmission.AuditLogPropLastLogAt])
					if err != nil {
						alog.ReportedAt = time.Now().UTC()
					}
					delete(alog.Props, nvsysadmission.AuditLogPropLastLogAt)
					auditQueue.Append(alog)
				}
			}
		} else {
			delete(aggrLogsCache, key)
		}
	}
}

func CleanupSessCfgCache() {
	cSig := make(chan os.Signal, 1)
	signal.Notify(cSig, os.Interrupt, syscall.SIGTERM)
	ticker := time.Tick(time.Minute)
Loop:
	for {
		select {
		case <-ticker:
			admResCacheMutex.Lock()
			for uid, admResObject := range admResCache {
				if time.Now().Unix() > admResObject.ValidUntil {
					delete(admResCache, uid)
				}
			}
			admResCacheMutex.Unlock()
			checkAggrLogsCache(false)

			rancherCookieMutex.Lock()
			for rsessToken, validUntil := range rancherCookieCache {
				if time.Now().Unix() > validUntil {
					delete(rancherCookieCache, rsessToken)
				}
			}
			rancherCookieMutex.Unlock()
		case <-cSig:
			checkAggrLogsCache(true)
			auditQueue.Flush()
			break Loop
		}
	}
}

func parseReqImageName(admContainerInfo *nvsysadmission.AdmContainerInfo) error {
	protocol := "https://"
	imgName := admContainerInfo.Image
	idx := strings.Index(imgName, "://")
	if idx != -1 {
		protocol = imgName[0 : idx+len("://")]
		imgName = imgName[idx+len("://"):] // remove leading "https://" in case it's specified
	}

	var foundRegistry bool
	ss := strings.Split(imgName, "/")
	if len(ss) > 1 {
		// see splitDockerDomain() in https://github.com/docker/distribution/blob/release/2.7/reference/normalize.go
		if !strings.ContainsAny(ss[0], ".:") && ss[0] != "localhost" {
			// there is no registry info inimgName, like "nvlab/iperf"
		} else {
			// there is registry info in result.Repository, like "docker.io/nvlab/iperf" or "10.1.127.3:5000/......" or "localhost/........"
			foundRegistry = true
			imgName = strings.Join(ss[1:], "/")
		}
	}
	if !foundRegistry {
		admContainerInfo.ImageRegistry = defaultRegistries
		if len(ss) == 1 {
			imgName = fmt.Sprintf("library/%s", imgName)
		}
	} else {
		if ss[0] == "docker.io" {
			admContainerInfo.ImageRegistry = defaultRegistries
			if len(ss) == 2 {
				imgName = fmt.Sprintf("library/%s", imgName)
			} else {
				imgName = strings.Join(ss[1:], "/")
			}
		} else {
			admContainerInfo.ImageRegistry = utils.NewSet(fmt.Sprintf("%s%s/", protocol, strings.ToLower(ss[0])))
			if len(ss) == 2 {
				for registry := range defaultRegistries.Iter() {
					if admContainerInfo.ImageRegistry.Any() == registry {
						imgName = fmt.Sprintf("library/%s", imgName)
						break
					}
				}
			} else {
				imgName = strings.Join(ss[1:], "/")
			}
		}
	}
	// Here imgName does not contain registry

	parsed := false
	indexAt := strings.Index(imgName, "@")
	indexColon := strings.Index(imgName, ":")
	if indexAt != -1 && indexAt < indexColon {
		strHash := imgName[indexAt+1 : indexColon]
		if strings.Index(strHash, "sha") == 0 {
			admContainerInfo.ImageRepo = imgName[:indexAt]
			admContainerInfo.ImageTag = imgName[indexAt+1:]
			parsed = true
		}
	}
	if !parsed {
		if indexColon != -1 {
			ss := strings.Split(imgName, ":")
			admContainerInfo.ImageRepo = ss[0]
			admContainerInfo.ImageTag = ss[1]
		} else {
			admContainerInfo.ImageRepo = imgName
			admContainerInfo.ImageTag = "latest"
		}
	}

	return nil
}

const appArmorAnnotation = "container.apparmor.security.beta.kubernetes.io"

func getAppArmorProfilesByContainer(specAnnotations map[string]string) map[string]string {
	profilesByContainer := make(map[string]string)
	if specAnnotations == nil {
		return profilesByContainer
	}
	for key, value := range specAnnotations {
		keySeparatorIndex := strings.Index(key, "/")
		if keySeparatorIndex == -1 {
			continue
		}
		annotationType := key[:keySeparatorIndex]
		if annotationType == appArmorAnnotation {
			target := key[keySeparatorIndex+1:]
			profilesByContainer[target] = value
		}
	}
	return profilesByContainer
}

func parsePodSpec(objectMeta *metav1.ObjectMeta, spec *corev1.PodSpec) ([3][]*nvsysadmission.AdmContainerInfo, error) {
	var allContainers [3][]*nvsysadmission.AdmContainerInfo
	vols := make(map[string]string, len(spec.Volumes))
	appArmorProfilesByContainer := getAppArmorProfilesByContainer(objectMeta.Annotations)
	ephemeralContainers := make([]corev1.Container, len(spec.EphemeralContainers))
	for i, ephemeralContainer := range spec.EphemeralContainers {
		ephemeralContainers[i] = corev1.Container(ephemeralContainer.EphemeralContainerCommon)
	}

	for _, vol := range spec.Volumes {
		if vol.VolumeSource.HostPath != nil {
			vols[vol.Name] = vol.VolumeSource.HostPath.Path
		}
	}

	for i, containers := range [3][]corev1.Container{spec.InitContainers, spec.Containers, ephemeralContainers} {
		allContainers[i] = make([]*nvsysadmission.AdmContainerInfo, 0, len(containers))
		for _, c := range containers {
			volMounts := utils.NewSet()
			for _, volMnt := range c.VolumeMounts {
				if path, exist := vols[volMnt.Name]; exist {
					volMounts.Add(path)
				}
			}

			envVars := make(map[string]string)
			regualrEnvVars := make(map[string]string) // reducing false-positive cases from "ValueFrom" types
			for _, env := range c.Env {
				if env.Value == "" {
					if env.ValueFrom != nil {
						/*[2019/Apr.] do not enable ConfigMap support for env vars yet
						if env.ValueFrom.ConfigMapKeyRef != nil {
							if cfgMap, err := admission.GetK8sConfigMap(env.ValueFrom.ConfigMapKeyRef.Name, objectMeta.Namespace); err == nil {
								if cfgMap != nil && cfgMap.Data != nil {
									if value, exist := cfgMap.Data[env.ValueFrom.ConfigMapKeyRef.Key]; exist {
										envVars[env.Name] = value
									}
								}
							}
						}*/
						if env.ValueFrom.FieldRef != nil {
							switch env.ValueFrom.FieldRef.FieldPath {
							case "metadata.name":
								envVars[env.Name] = objectMeta.Name
							case "metadata.namespace":
								envVars[env.Name] = objectMeta.Namespace
							case "metadata.labels":
								if value, exist := objectMeta.Labels[env.Name]; exist {
									envVars[env.Name] = value
								}
							case "metadata.annotations":
								if value, exist := objectMeta.Annotations[env.Name]; exist {
									envVars[env.Name] = value
								}
							case "spec.nodeName":
								envVars[env.Name] = spec.NodeName
							case "spec.serviceAccountName":
								envVars[env.Name] = spec.ServiceAccountName
							case "status.hostIP", "status.podIP":
								envVars[env.Name] = ""
							}
						} /*else if env.ValueFrom.ResourceFieldRef != nil || env.ValueFrom.SecretKeyRef != nil {
							// For env var from ResourceFieldRef and SecretKeyRef, we don't resolve its value
							envVars[env.Name] = ""
						}*/
					} else {
						envVars[env.Name] = ""
					}
				} else {
					envVars[env.Name] = env.Value
					regualrEnvVars[env.Name] = env.Value
				}
			}
			/*[2019/Apr.] do not enable ConfigMap support for env vars yet
			for _, envFrom := range c.EnvFrom {
				// do not handle SecretRef(*SecretEnvSource)
				if envFrom.ConfigMapRef != nil {
					if cfgMap, err := admission.GetK8sConfigMap(envFrom.ConfigMapRef.Name, objectMeta.Namespace); err == nil {
						if cfgMap != nil && cfgMap.Data != nil {
							for k, v := range cfgMap.Data {
								if envFrom.Prefix == "" {
									envVars[k] = v
								} else {
									k2 := fmt.Sprintf("%s%s", envFrom.Prefix, k)
									envVars[k2] = v
								}
							}
						}
					}
				}
			}*/

			admContainerInfo := &nvsysadmission.AdmContainerInfo{
				RunAsUser:   -1,
				VolMounts:   volMounts,
				EnvVars:     envVars,
				HostNetwork: spec.HostNetwork,
				HostPID:     spec.HostPID,
				HostIPC:     spec.HostIPC,
				Volumes:     spec.Volumes,
				Capabilities: nvsysadmission.LinuxCapabilities{
					Add:  []string{},
					Drop: []string{},
				},
				HostPorts:      []int32{},
				SELinuxOptions: nvsysadmission.SELinuxOptions{},
				Sysctls:        []string{},
			}

			if c.Ports != nil {
				for _, port := range c.Ports {
					if port.HostPort != 0 {
						admContainerInfo.HostPorts = append(admContainerInfo.HostPorts, port.HostPort)
					}
				}
			}

			if appArmorProfile, hasProfile := appArmorProfilesByContainer[c.Name]; hasProfile {
				admContainerInfo.AppArmorProfile = &appArmorProfile
			}

			cpuRequestSpecified := false
			memoryRequestSpecified := false
			if len(c.Resources.Requests) > 0 {
				if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
					if v := q.Value(); v < 9223372036854775 {
						admContainerInfo.CpuRequests = float64(q.MilliValue()) / 1000
					} else {
						admContainerInfo.CpuRequests = float64(v)
					}
					cpuRequestSpecified = true
				}
				if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
					admContainerInfo.MemoryRequests = q.Value()
					memoryRequestSpecified = true
				}
			}

			if len(c.Resources.Limits) > 0 {
				if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
					if v := q.Value(); v < 9223372036854775 {
						admContainerInfo.CpuLimits = float64(q.MilliValue()) / 1000
					} else {
						admContainerInfo.CpuLimits = float64(v)
					}
					if !cpuRequestSpecified {
						admContainerInfo.CpuRequests = admContainerInfo.CpuLimits
					}
				}
				if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
					admContainerInfo.MemoryLimits = q.Value()
					if !memoryRequestSpecified {
						admContainerInfo.MemoryRequests = admContainerInfo.MemoryLimits
					}
				}
			}

			admContainerInfo.EnvSecrets = scanEnvVarSecrets(regualrEnvVars)

			if spec.SecurityContext != nil {
				// pod selinux options
				if spec.SecurityContext.SELinuxOptions != nil {
					admContainerInfo.SELinuxOptions.Type = spec.SecurityContext.SELinuxOptions.Type
					admContainerInfo.SELinuxOptions.User = spec.SecurityContext.SELinuxOptions.User
					admContainerInfo.SELinuxOptions.Role = spec.SecurityContext.SELinuxOptions.Role
				}

				// sysctls
				if spec.SecurityContext.Sysctls != nil {
					for _, sysctl := range spec.SecurityContext.Sysctls {
						admContainerInfo.Sysctls = append(admContainerInfo.Sysctls, sysctl.Name)
					}
				}

				// pod seccomp profile type
				if spec.SecurityContext.SeccompProfile != nil {
					admContainerInfo.SeccompProfileType = &spec.SecurityContext.SeccompProfile.Type
				}

				// run as non root
				if spec.SecurityContext.RunAsNonRoot != nil {
					admContainerInfo.RunAsNonRoot = *spec.SecurityContext.RunAsNonRoot
				} else {
					admContainerInfo.RunAsNonRoot = false
				}
			}

			if spec.SecurityContext != nil && spec.SecurityContext.RunAsUser != nil {
				admContainerInfo.RunAsUser = *spec.SecurityContext.RunAsUser
			}

			if c.SecurityContext != nil { // c.SecurityContext is type SecurityContext
				if c.SecurityContext.Privileged != nil {
					admContainerInfo.Privileged = *c.SecurityContext.Privileged
					if *c.SecurityContext.Privileged {
						admContainerInfo.AllowPrivilegeEscalation = true
					}
				}
				if c.SecurityContext.RunAsUser != nil {
					// If set in both SecurityContext and PodSecurityContext, the value specified in SecurityContext takes precedence.
					admContainerInfo.RunAsUser = *c.SecurityContext.RunAsUser
				} else if spec.SecurityContext != nil && spec.SecurityContext.RunAsUser != nil {
					admContainerInfo.RunAsUser = *spec.SecurityContext.RunAsUser
				}
				if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
					admContainerInfo.AllowPrivilegeEscalation = true
				}

				// linux capabilities
				if c.SecurityContext.Capabilities != nil {
					if c.SecurityContext.Capabilities.Add != nil {

						for _, addedCapability := range c.SecurityContext.Capabilities.Add {
							if addedCapability == "SYS_ADMIN" {
								admContainerInfo.AllowPrivilegeEscalation = true
							}
							admContainerInfo.Capabilities.Add = append(admContainerInfo.Capabilities.Add, string(addedCapability))
						}
					}
					if c.SecurityContext.Capabilities.Drop != nil {
						for _, droppedCapability := range c.SecurityContext.Capabilities.Drop {
							admContainerInfo.Capabilities.Drop = append(admContainerInfo.Capabilities.Drop, string(droppedCapability))
						}
					}
				}

				// container selinux options
				if c.SecurityContext.SELinuxOptions != nil {
					admContainerInfo.SELinuxOptions.Type = c.SecurityContext.SELinuxOptions.Type
					admContainerInfo.SELinuxOptions.User = c.SecurityContext.SELinuxOptions.User
					admContainerInfo.SELinuxOptions.Role = c.SecurityContext.SELinuxOptions.Role
				}

				// proc masks
				if c.SecurityContext.ProcMount != nil {
					admContainerInfo.ProcMount = string(*c.SecurityContext.ProcMount)
				} else {
					admContainerInfo.ProcMount = ""
				}

				// container seccomp profile type
				if c.SecurityContext.SeccompProfile != nil {
					admContainerInfo.SeccompProfileType = &c.SecurityContext.SeccompProfile.Type
				}

				// container run as non root
				if c.SecurityContext.RunAsNonRoot != nil {
					admContainerInfo.RunAsNonRoot = *c.SecurityContext.RunAsNonRoot
				} else {
					admContainerInfo.RunAsNonRoot = false
				}
			}
			admContainerInfo.Name = c.Name
			admContainerInfo.Image = c.Image
			parseReqImageName(admContainerInfo)
			isSidecar := false
			for imageRegistry := range admContainerInfo.ImageRegistry.Iter() {
				for _, sidecar := range sidecarImages {
					if sidecar.registry == imageRegistry && sidecar.imageRepo == admContainerInfo.ImageRepo {
						isSidecar = true
						break
					}
				}
				if isSidecar {
					break
				}
			}
			if !isSidecar {
				allContainers[i] = append(allContainers[i], admContainerInfo)
			}
		}
	}

	return allContainers, nil
}

func mergeMaps(labels1, labels2 map[string]string) map[string]string {
	labels := make(map[string]string, len(labels1)+len(labels2))
	for k, v := range labels1 {
		labels[k] = v
	}
	for k, v := range labels2 {
		labels[k] = v
	}
	return labels
}

// kind, name, ns are owner's attributes
func getOwnerUserGroupMetadataFromK8s(kind, name, ns string) (string, utils.Set, map[string]string, map[string]string, bool) {
	if obj, err := global.ORCH.GetResource(kind, ns, name); err == nil {
		var ownerReferences []metav1.OwnerReference
		switch kind {
		case resource.RscTypeStatefulSet:
			// support pod -> statefulset
			if ssObj, ok := obj.(*appsv1.StatefulSet); ok {
				if len(ssObj.OwnerReferences) == 0 {
					return "", utils.NewSet(), mergeMaps(ssObj.Labels, ssObj.Spec.Template.Labels), mergeMaps(ssObj.Annotations, ssObj.Spec.Template.Annotations), true
				}
			}
		case resource.RscTypeReplicaSet:
			// support pod -> replicaset -> deployment for now
			if rsObj, ok := obj.(*appsv1.ReplicaSet); ok {
				ownerReferences = rsObj.OwnerReferences
			}
		case resource.RscTypeDeployment:
			if deployObj, ok := obj.(*appsv1.Deployment); ok {
				if len(deployObj.OwnerReferences) == 0 {
					return "", utils.NewSet(), mergeMaps(deployObj.Labels, deployObj.Spec.Template.Labels), mergeMaps(deployObj.Annotations, deployObj.Spec.Template.Annotations), true
				}
			}
		}
		for _, ownerRef := range ownerReferences {
			admResCacheMutex.RLock()
			ownerObject, exist := admResCache[string(ownerRef.UID)]
			admResCacheMutex.RUnlock()
			if exist {
				if len(ownerObject.OwnerUIDs) == 0 {
					// owner is root resource (most likely deployment)
					return ownerObject.UserName, ownerObject.Groups, ownerObject.Labels, ownerObject.Annotations, true
				} else {
					log.WithFields(log.Fields{"kind": kind, "name": name, "ns": ns}).Info("unsupported owner resource type yet")
				}
			} else {
				// trace up one layer in the owner chain
				if userName, groups, labels, annotations, found := getOwnerUserGroupMetadataFromK8s(strings.ToLower(ownerRef.Kind), ownerRef.Name, ns); found {
					return userName, groups, labels, annotations, true
				}
			}
		}
	} else {
		log.WithFields(log.Fields{"kind": kind, "name": name, "ns": ns, "error": err}).Error()
	}

	return "", utils.NewSet(), nil, nil, false
}

func getOwnerUserGroupMetadata(ownerUIDs []string, ownerReferences []metav1.OwnerReference, ns string) (string, utils.Set, map[string]string, map[string]string) {
	for _, uid := range ownerUIDs {
		admResCacheMutex.RLock()
		ownerObject, exist := admResCache[uid]
		admResCacheMutex.RUnlock()
		if exist {
			ownerObject.ValidUntil = time.Now().Add(time.Minute * 5).Unix()
			userName, groups, labels, annotations := getOwnerUserGroupMetadata(ownerObject.OwnerUIDs, nil, ns)
			if userName == "" && groups.Cardinality() == 0 {
				userName = ownerObject.UserName
				groups = ownerObject.Groups
			}
			if len(labels) == 0 {
				labels = ownerObject.Labels
			}
			if len(annotations) == 0 {
				annotations = ownerObject.Annotations
			}
			return userName, groups, labels, annotations
		} else {
			// owner resource is not in cache anymore. query k8s instead
			for _, ownerRef := range ownerReferences {
				kind := strings.ToLower(ownerRef.Kind)
				if userName, groups, labels, annotations, found := getOwnerUserGroupMetadataFromK8s(kind, ownerRef.Name, ns); found {
					return userName, groups, labels, annotations
				}
			}
		}
	}

	return "", utils.NewSet(), nil, nil
}

func isRootOwnerCacheAvailable(ownerUIDs []string) bool {
	// returns true if root owner resource's cache is available or there is no owner resource(i.e. itself is the root)
	if len(ownerUIDs) == 0 { // no owner
		return true
	}
	for _, uid := range ownerUIDs {
		admResCacheMutex.RLock()
		ownerObject, exist := admResCache[uid]
		admResCacheMutex.RUnlock()
		if exist {
			isOwnerCacheAvailable := isRootOwnerCacheAvailable(ownerObject.OwnerUIDs)
			if isOwnerCacheAvailable {
				return true
			}
		}
	}

	return false // has owner but all their caches in admResCache are gone
}

func parseAdmRequest(req *admissionv1beta1.AdmissionRequest, objectMeta *metav1.ObjectMeta, podSpec interface{}) (*nvsysadmission.AdmResObject, error) {
	var specLabels map[string]string
	var specAnnotations map[string]string
	var allContainers [3][]*nvsysadmission.AdmContainerInfo
	var saName string
	if podSpec != nil {
		switch podSpec.(type) {
		case *corev1.PodTemplateSpec:
			podTemplateSpec, _ := podSpec.(*corev1.PodTemplateSpec)
			allContainers, _ = parsePodSpec(objectMeta, &podTemplateSpec.Spec)
			specLabels = podTemplateSpec.ObjectMeta.Labels
			specAnnotations = podTemplateSpec.ObjectMeta.Annotations
			saName = podTemplateSpec.Spec.ServiceAccountName
		case *corev1.PodSpec:
			podSpec, _ := podSpec.(*corev1.PodSpec)
			allContainers, _ = parsePodSpec(objectMeta, podSpec)
			saName = podSpec.ServiceAccountName
		default:
			return nil, errors.New("unsupported podSpec type")
		}

	}
	ownerUIDs := make([]string, 0, len(objectMeta.OwnerReferences))
	for _, ref := range objectMeta.OwnerReferences {
		ownerUIDs = append(ownerUIDs, string(ref.UID))
	}
	userName, groups, labels, annotations := getOwnerUserGroupMetadata(ownerUIDs, objectMeta.OwnerReferences, objectMeta.Namespace)
	if userName == "" && groups.Cardinality() == 0 && len(ownerUIDs) == 0 { // only root resource's user/group is used
		userName = req.UserInfo.Username
		if len(req.UserInfo.Groups) > 0 {
			for _, group := range req.UserInfo.Groups {
				groups.Add(group)
			}
		}
	}
	if labels == nil && len(ownerUIDs) == 0 {
		labels = mergeMaps(objectMeta.Labels, specLabels)
	}
	if annotations == nil && len(ownerUIDs) == 0 {
		annotations = mergeMaps(objectMeta.Annotations, specAnnotations)
	}

	resObject := &nvsysadmission.AdmResObject{
		ValidUntil:         time.Now().Add(time.Minute * 5).Unix(),
		Kind:               req.Kind.Kind,
		Name:               objectMeta.Name,
		Namespace:          objectMeta.Namespace,
		UserName:           userName,
		Groups:             groups,
		OwnerUIDs:          ownerUIDs,
		Labels:             labels,
		Annotations:        annotations,
		AllContainers:      allContainers,
		ServiceAccountName: saName,
	}
	admResCacheMutex.Lock()
	admResCache[string(objectMeta.UID)] = resObject
	admResCacheMutex.Unlock()
	//log.WithFields(log.Fields{"user": resObject.UserName, "uid": string(objectMeta.UID), "name": resObject.Name, "nameSpace": resObject.Namespace}).Debug("resObject") //->

	return resObject, nil
}

func walkThruContainers(admResObject *nvsysadmission.AdmResObject, stamps *api.AdmCtlTimeStamps, ar *admissionv1beta1.AdmissionReview,
	evalContext *nvsysadmission.AdmCtrlEvalContext, reqEvalResult *nvsysadmission.AdmCtrlReqEvalResult) {

	if len(admResObject.OwnerUIDs) > 0 {
		// If there is owner for this resource, check if the root owner's cache is still available.
		// If not, do not compare user/user group
		evalContext.RootAvail = isRootOwnerCacheAvailable(admResObject.OwnerUIDs)

		//----------------------------------------------------------------------------------------------------
		// Do not re-use the matching result of owners. i.e. call EvaluateK8sAdmissionRules() for every resource CREATE request
		//----------------------------------------------------------------------------------------------------
		/*var allowedImageName string
		var allowedResult *nvsysadmission.AdmResult
		// if there is owner for this resource, check if any owner resource is already denied
		for _, uid := range admResObject.OwnerUIDs {
			admResCacheMutex.RLock()
			ownerObject, exist := admResCache[uid]
			admResCacheMutex.RUnlock()
			if exist {
				for imageName, ownerResult := range ownerObject.AdmResults {
					if ownerResult.MatchDenyRule {
						admResObject.AdmResults[imageName] = ownerResult
						return ownerResult
					} else if ownerResult.RuleID != 0 {
						allowedImageName = imageName
						allowedResult = ownerResult
					}
				}
			}
		}
		if allowedResult != nil && len(allowedImageName) > 0 {
			// If it reaches here, it means the resource's owner(s) match allow rule but not deny rule.
			admResObject.AdmResults[allowedImageName] = allowedResult
			return allowedResult
		}*/
		// If it reaches here, it means we cannot find owner's matching result info in the session cache
	} else {
		// this resource has no owner. So it's a root resource by itself
		evalContext.RootAvail = true
	}
	// if it's Create operation or no owner for this resource or no owner's matching result info for this resource, use the container info for rule matching
	var unscannedImages = make([]string, 0, evalContext.ContainersInReq)
	var allImages = make([]string, 0, evalContext.ContainersInReq)
	var assessResults = make([]*nvsysadmission.AdmCtrlAssessResult, 0, evalContext.ContainersInReq)

	containerTypes := []string{share.AdmCtrlRuleInitContainers, share.AdmCtrlRuleContainers, share.AdmCtrlRuleEphemeralContainers}
	for i, containers := range admResObject.AllContainers { // range (initContainers, Containers, ephemeralContainers)
		for _, c := range containers {
			var thisStamp api.AdmCtlTimeStamps
			result, _ := cacher.MatchK8sAdmissionRules(admResObject, c, evalContext, &thisStamp, ar, containerTypes[i])
			// result is per-container-image's matching result, in type nvsysadmission.AdmCtrlAssessResult
			if thisStamp.Fetched.Sub(thisStamp.GonnaFetch).Seconds() > stamps.Fetched.Sub(stamps.GonnaFetch).Seconds() {
				stamps.GonnaFetch = thisStamp.GonnaFetch
				stamps.Fetched = thisStamp.Fetched
			}
			if !result.ContainerImageInfo.ImageScanned {
				unscannedImages = append(unscannedImages, c.Image)
			}
			allImages = append(allImages, c.Image)

			reqEvalResult.AllCriticalVulsCnt += result.ContainerImageInfo.CriticalVulsCnt
			reqEvalResult.AllHighVulsCnt += result.ContainerImageInfo.HighVulsCnt
			reqEvalResult.AllMedVulsCnt += result.ContainerImageInfo.MedVulsCnt
			if (result.AssessAction == share.AdmCtrlActionAllow && reqEvalResult.ReqAction == "") ||
				(result.AssessAction == share.AdmCtrlActionDeny && reqEvalResult.ReqAction != share.AdmCtrlActionDeny) {
				reqEvalResult.ReqAction = result.AssessAction
				reqEvalResult.CriticalAssessment = result
				evalContext.ReqActionSoFar = result.AssessAction
			}
			assessResults = append(assessResults, result)
			// admResObject.AdmResults[c.ImageRepo] = result // comment out because we do not re-use the matching result of owners anymore.
		}
	}

	reqEvalResult.AllContainerImages = strings.Join(allImages, ", ")
	if len(unscannedImages) > 0 {
		reqEvalResult.UnscannedImages = strings.Join(unscannedImages, ", ")
	}
	reqEvalResult.AssessResults = assessResults
}

func composeResponse(err *error) *admissionv1beta1.AdmissionResponse {
	if err == nil {
		return &responseAllow
	}
	return &admissionv1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: (*err).Error(),
		},
	}
}

func logUnmarshallError(kind *string, uid *types.UID, err *error) *admissionv1beta1.AdmissionResponse {
	msg := fmt.Sprintf(errFmtUnmarshall, *kind)
	log.WithFields(log.Fields{"uid": *uid}).Error(msg)
	return composeResponse(err)
}

// returns (alog aggregated, alog to be added to auditQueue)
//  1. The first occurrence of a 'denied' audit for a key({owner_uid}.{image}} is always added to auditQueue without aggregation
//     Then a {key, dummy log} entry is added to aggrLogsCache so we start aggregation for the following 'denied' audits of same key({owner_uid}.{image})
//  2. For the next 'denied' audit of the same key in 8 minutes, {key, real alog} is updated in aggrLogsCache
//  3. For the following 'denied' audits of the same key in 8 minutes, occurrences for the same key's alog is increased(1 for each log) in aggrLogsCache
//  4. In CleanupSessCfgCache(), it periodically checks if there are audit logs that have been aggregated for 8(+) minutes.
//     If yes, add them to auditQueue and delete their entries from aggrLogsCache
//     If it's the dummy log entry sitting in aggrLogsCache for 8(+) minutes, delete it as well.
//  5. The next 'denied' audit for the same key starts over from step 1
func aggregateDenyLogs(reqResult *nvsysadmission.AdmCtrlReqEvalResult, ownerUID string, alog *share.CLUSAuditLog) (bool, *share.CLUSAuditLog) {

	if reqResult == nil || reqResult.CriticalAssessment == nil || reqResult.CriticalAssessment.ContainerImageInfo.Image == "" || ownerUID == "" {
		return false, alog
	}
	criticalAssessment := reqResult.CriticalAssessment

	// aggregation is for image with the same owner resource
	key := fmt.Sprintf("%s.%s", ownerUID, criticalAssessment.ContainerImageInfo.Image)
	aggrLogsCacheMutex.Lock()
	defer aggrLogsCacheMutex.Unlock()
	if alog == nil {
		// alog being nil means checking if it's still aggregating for the same image/owner so that caller may not need to compose a new log
		if cachedLog, exist := aggrLogsCache[key]; exist && cachedLog.Count > 0 {
			// it's still aggregating for the same image/owner. increase occurrences in the log by 1
			cachedLog.Count++
			cachedLog.Props[nvsysadmission.AuditLogPropLastLogAt] = api.RESTTimeString(time.Now().UTC())
			return true, nil
		}
		// it's not aggregation for this image/owner yet.
		return false, alog
	} else {
		if cachedLog, exist := aggrLogsCache[key]; exist {
			if cachedLog.Count == 0 {
				// cachedLog is a dummy entry meaning we starts aggregating audits for this image/owner now
				alog.Props[nvsysadmission.AuditLogPropLastLogAt] = alog.Props[nvsysadmission.AuditLogPropFirstLogAt]
				alog.ReportedAt = alog.ReportedAt.Add(aggregateInterval) // so that CleanupSessCfgCache() doesn't need to calculate the time in each loop
				aggrLogsCache[key] = alog
			} else {
				// it's still aggregating for the same image/owner. increase occurrences in the log by 1
				cachedLog.Count++
				cachedLog.Props[nvsysadmission.AuditLogPropLastLogAt] = api.RESTTimeString(time.Now().UTC())
			}
			return true, nil
		} else {
			// it's the first non-aggregated log of a 'denied' audit for this image/owner.
			// inform caller to add it to auditQueue & add a dummy aggregated log entry(Count: 0) so the next audit for the same image/owner will start aggregation
			aggrLogsCache[key] = &share.CLUSAuditLog{Count: 0, ReportedAt: time.Now().Add(aggregateInterval).UTC()}
			return false, alog
		}
	}
}

func cacheAdmCtrlAudit(auditId share.TLogAudit, reqResult *nvsysadmission.AdmCtrlReqEvalResult, criticalAssessment *nvsysadmission.AdmCtrlAssessResult,
	matchedImageInfo *nvsysadmission.AdmCtrlMatchedImageInfo, admResObject *nvsysadmission.AdmResObject) error {

	// assessResult is the container that triggers this audit event.
	// it's possible that assessResult/matchedImageInfo is nil when no container matches any rule.
	// any controller that handles admission control request could save result to queue
	if auditId >= share.CLUSAuditAdmCtrlK8sReqAllowed && auditId <= share.CLUSAuditAdmCtrlK8sReqDenied {
		if auditId == share.CLUSAuditAdmCtrlK8sReqDenied && len(admResObject.OwnerUIDs) > 0 {
			if aggregated, _ := aggregateDenyLogs(reqResult, admResObject.OwnerUIDs[0], nil); aggregated {
				// we increased the occurrences field in the aggregated log by 1 so we don't need to keep processing for this audit
				return nil
			}
		}
		alog := &share.CLUSAuditLog{
			ID:         auditId,
			Count:      1,
			ReportedAt: time.Now().UTC(),
		}

		props := make(map[string]string, 10)
		if reqResult.AllContainerImages != "" {
			props[nvsysadmission.AuditLogPropImage] = reqResult.AllContainerImages
			props[nvsysadmission.AuditLogPropCriticalVulsCnt] = strconv.Itoa(reqResult.AllCriticalVulsCnt)
			props[nvsysadmission.AuditLogPropHighVulsCnt] = strconv.Itoa(reqResult.AllHighVulsCnt)
			props[nvsysadmission.AuditLogPropMedVulsCnt] = strconv.Itoa(reqResult.AllMedVulsCnt)
			if criticalAssessment != nil {
				props[nvsysadmission.AuditLogPropImage] = criticalAssessment.ContainerImageInfo.Image
				props[nvsysadmission.AuditLogPropRepository] = criticalAssessment.ContainerImageInfo.Repository
				props[nvsysadmission.AuditLogPropTag] = criticalAssessment.ContainerImageInfo.Tag
			}
			if matchedImageInfo != nil {
				props[nvsysadmission.AuditLogPropImageID] = matchedImageInfo.ImageID
				props[nvsysadmission.AuditLogPropRegistry] = matchedImageInfo.Registry
				props[nvsysadmission.AuditLogPropBaseOS] = matchedImageInfo.BaseOS
				props[nvsysadmission.AuditLogPropCriticalVulsCnt] = strconv.Itoa(matchedImageInfo.CriticalVulsCnt)
				props[nvsysadmission.AuditLogPropHighVulsCnt] = strconv.Itoa(matchedImageInfo.HighVulsCnt)
				props[nvsysadmission.AuditLogPropMedVulsCnt] = strconv.Itoa(matchedImageInfo.MedVulsCnt)
			}
		} else {
			props[nvsysadmission.AuditLogPropPVCName] = reqResult.PVCName
			props[nvsysadmission.AuditLogPVCStorageClassName] = reqResult.PVCStorageClassName
		}
		props[nvsysadmission.AuditLogPropNamespace] = admResObject.Namespace
		props[nvsysadmission.AuditLogPropMessage] = reqResult.Msg
		props[nvsysadmission.AuditLogPropUser] = reqResult.User
		props[nvsysadmission.AuditLogPropFirstLogAt] = api.RESTTimeString(alog.ReportedAt)
		alog.Props = props

		if auditId == share.CLUSAuditAdmCtrlK8sReqDenied && len(admResObject.OwnerUIDs) > 0 {
			_, alog = aggregateDenyLogs(reqResult, admResObject.OwnerUIDs[0], alog)
		}
		if alog != nil {
			auditQueue.Append(alog)
		}
	}

	return nil
}

func (whsvr *WebhookServer) validate(ar *admissionv1beta1.AdmissionReview, globalMode string, defaultAction int, stamps *api.AdmCtlTimeStamps,
	forTesting bool) (*admissionv1beta1.AdmissionResponse, []*nvsysadmission.AdmCtrlMatchedResult, bool) {

	req := ar.Request
	var objectMeta *metav1.ObjectMeta
	var podTemplateSpec *corev1.PodTemplateSpec
	var admResObject *nvsysadmission.AdmResObject
	var opDisplay string
	var msgHeader string
	var scName string // pvc.Spec.StorageClassName
	var op int
	var reqIgnored bool

	switch req.Operation {
	case admissionv1beta1.Create:
		opDisplay = "Creation"
		op = OPERATION_CREATE
	case admissionv1beta1.Update:
		opDisplay = "Update"
		op = OPERATION_UPDATE
	case admissionv1beta1.Delete:
		op = OPERATION_DELETE
	default:
		return composeResponse(nil), nil, reqIgnored
	}

	if req.DryRun != nil && *req.DryRun {
		msgHeader = "<Server Dry Run> "
	} else if forTesting {
		msgHeader = "<Assessment> "
	}

	switch req.Kind.Kind {
	case k8sKindCronJob:
		var cronJob batchv1beta1.CronJob // The batch/v1beta1 API version of CronJob will no longer be served in v1.25 !!
		if err := json.Unmarshal(req.Object.Raw, &cronJob); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &cronJob.ObjectMeta
		podTemplateSpec = &cronJob.Spec.JobTemplate.Spec.Template
	case k8sKindDaemonSet:
		if op == OPERATION_DELETE {
			if req.Name == resource.NvDaemonSetName && req.Namespace == resource.NvAdmSvcNamespace {
				log.WithFields(log.Fields{"Name": req.Name, "Namespace": req.Namespace}).Info("Critical daemonset deleted")
				cacher.SetNvDeployStatusInCluster(resource.NvDeploymentName, false) // leverage resource.NvDeploymentName to tell NV is being uninstalled
				time.Sleep(time.Second * 2)                                         // so that the leading controller should have enough time to unregister adm ctrl from K8s
			}
			return composeResponse(nil), nil, reqIgnored // always allow
		}

		var daemonSet appsv1.DaemonSet
		if err := json.Unmarshal(req.Object.Raw, &daemonSet); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &daemonSet.ObjectMeta
		podTemplateSpec = &daemonSet.Spec.Template
		if op == OPERATION_UPDATE {
			var oldDaemonSet appsv1.DaemonSet
			if err := json.Unmarshal(req.OldObject.Raw, &oldDaemonSet); err != nil {
				return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
			}
		}
	case k8sKindDeployment:
		if op == OPERATION_DELETE {
			if req.Name == resource.NvDeploymentName && req.Namespace == resource.NvAdmSvcNamespace {
				log.WithFields(log.Fields{"Name": req.Name, "Namespace": req.Namespace}).Info("Critical deployment deleted")
				cacher.SetNvDeployStatusInCluster(req.Name, false) // leverage resource.NvDeploymentName to tell NV is being uninstalled
				time.Sleep(time.Second * 2)                        // so that the leading controller should have enough time to unregister adm ctrl from K8s
			}
			return composeResponse(nil), nil, reqIgnored // always allow
		}

		var deployment appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &deployment); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		if op == OPERATION_UPDATE {
			var oldDeployment appsv1.Deployment
			if err := json.Unmarshal(req.OldObject.Raw, &oldDeployment); err != nil {
				return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
			}
		}
		objectMeta = &deployment.ObjectMeta
		podTemplateSpec = &deployment.Spec.Template
	case k8sKindDeploymentConfig:
		var deploymentConfig resource.DeploymentConfig
		if err := json.Unmarshal(req.Object.Raw, &deploymentConfig); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &deploymentConfig.ObjectMeta
		podTemplateSpec = deploymentConfig.Spec.Template
	case k8sKindJob:
		var job batchv1.Job
		if err := json.Unmarshal(req.Object.Raw, &job); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &job.ObjectMeta
		podTemplateSpec = &job.Spec.Template
	case K8sKindReplicationController:
		var controller corev1.ReplicationController
		if err := json.Unmarshal(req.Object.Raw, &controller); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &controller.ObjectMeta
		podTemplateSpec = controller.Spec.Template
	case k8sKindReplicaSet:
		var replicaSet appsv1.ReplicaSet
		if err := json.Unmarshal(req.Object.Raw, &replicaSet); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &replicaSet.ObjectMeta
		podTemplateSpec = &replicaSet.Spec.Template
	case k8sKindService:
		if req.Namespace == resource.NvAdmSvcNamespace && (req.Name == resource.NvAdmSvcName || req.Name == resource.NvCrdSvcName) {
			if op == OPERATION_CREATE {
				cacher.SetNvDeployStatusInCluster(req.Name, true)
			} else if op == OPERATION_UPDATE {
				var svc corev1.Service
				if err := json.Unmarshal(req.Object.Raw, &svc); err == nil && svc.ObjectMeta.Labels != nil {
					tagKey, echoKey := admission.GetSvcLabelKeysForTest(resource.NvAdmSvcName)
					if tag, ok := svc.ObjectMeta.Labels[tagKey]; ok && tag != "" {
						// if label 'echo-neuvector-svc-admission-webhook' has the same value as label 'tag-neuvector-svc-admission-webhook',
						// it means this UPDATE request is triggered by EchoAdmWebhookConnection(). Otherwise skip to avoid looping
						if _, exist := svc.ObjectMeta.Labels[echoKey]; !exist {
							go admission.EchoAdmWebhookConnection(tag, req.Name)
						}
					}
				}
			} else { // OPERATION_DELETE
				log.WithFields(log.Fields{"Name": req.Name, "Namespace": req.Namespace}).Info("Critical service deleted")
				cacher.SetNvDeployStatusInCluster(req.Name, false)
			}
		}
		return composeResponse(nil), nil, reqIgnored // always allow
	case K8sKindStatefulSet:
		if op == OPERATION_DELETE {
			if req.Namespace == resource.NvAdmSvcNamespace && (req.Name == resource.NvDeploymentName || req.Name == resource.NvDaemonSetName) {
				log.WithFields(log.Fields{"Name": req.Name, "Namespace": req.Namespace}).Info("Critical statefulset deleted")
				cacher.SetNvDeployStatusInCluster(resource.NvDeploymentName, false) // leverage resource.NvDeploymentName to tell NV is being uninstalled
				time.Sleep(time.Second * 2)                                         // so that the leading controller should have enough time to unregister adm ctrl from K8s
			}
			return composeResponse(nil), nil, reqIgnored // always allow
		}

		var statefulSet appsv1.StatefulSet
		if err := json.Unmarshal(req.Object.Raw, &statefulSet); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		objectMeta = &statefulSet.ObjectMeta
		podTemplateSpec = &statefulSet.Spec.Template
	case k8sKindPod:
		var pod corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		// if pod is middle resource(i.e. has owner) & it's already at running phase(i.e. this is an UPDATE pod request), skip handling this request
		if len(pod.ObjectMeta.OwnerReferences) != 0 && pod.Status.Phase == "Running" {
			return composeResponse(nil), nil, reqIgnored
		}
		admResObject, _ = parseAdmRequest(req, &pod.ObjectMeta, &pod.Spec)
	case k8sKindPersistentVolumeClaim:
		var pvc corev1.PersistentVolumeClaim
		if err := json.Unmarshal(req.Object.Raw, &pvc); err != nil {
			return logUnmarshallError(&req.Kind.Kind, &req.UID, &err), nil, reqIgnored
		}
		// not all pvc has StorageClassName
		if pvc.Spec.StorageClassName == nil {
			if forTesting {
				return &admissionv1beta1.AdmissionResponse{
					Allowed: true,
					Result:  &metav1.Status{Message: fmt.Sprintf("%s%s of Kubernetes %s is allowed.", msgHeader, opDisplay, req.Kind.Kind)},
				}, nil, false
			}
			return logUnmarshallError(&req.Kind.Kind, &req.UID, nil), nil, reqIgnored
		}
		objectMeta = &pvc.ObjectMeta
		scName = *pvc.Spec.StorageClassName
	default:
		return composeResponse(nil), nil, reqIgnored
	}

	// parse request meta object
	if objectMeta != nil {
		if req.Kind.Kind == k8sKindPersistentVolumeClaim {
			admResObject, _ = parseAdmRequest(req, objectMeta, nil)
		} else if podTemplateSpec != nil {
			admResObject, _ = parseAdmRequest(req, objectMeta, podTemplateSpec)
		}
	}
	stamps.Parsed = time.Now()

	totalContainers := 0
	{
		reqImages := make([]string, 0, len(admResObject.AllContainers))
		for _, containers := range admResObject.AllContainers {
			for _, c := range containers {
				reqImages = append(reqImages, c.Image)
			}
			totalContainers += len(containers)
		}
		stamps.Images = strings.Join(reqImages, ",")
	}

	var allowed = true
	var statusResult = &metav1.Status{}
	var matchedResults []*nvsysadmission.AdmCtrlMatchedResult
	var reqEvalResult nvsysadmission.AdmCtrlReqEvalResult

	if admResObject != nil {
		evalContext := nvsysadmission.AdmCtrlEvalContext{
			ForTesting:      forTesting,
			GlobalMode:      globalMode,
			ContainersInReq: totalContainers,
			AdmCtrlType:     admission.NvAdmValidateType,
		}
		reqEvalResult.ContainersInReq = totalContainers
		if req.Kind.Kind == k8sKindPersistentVolumeClaim {
			result, _ := cacher.MatchK8sAdmissionRulesForPVC(objectMeta.Namespace, objectMeta.Name, scName, &evalContext)
			// result is pvc's matching result, in type nvsysadmission.AdmCtrlAssessResult
			if forTesting || len(result.MatchedResults) > 0 {
				if result.AssessAction == share.AdmCtrlActionDeny && reqEvalResult.ReqAction != share.AdmCtrlActionDeny {
					reqEvalResult.ReqAction = share.AdmCtrlActionDeny
					reqEvalResult.CriticalAssessment = result
				}
				reqEvalResult.AssessResults = []*nvsysadmission.AdmCtrlAssessResult{result}
				reqEvalResult.User = admResObject.UserName
				reqEvalResult.PVCName = objectMeta.Name
				reqEvalResult.PVCStorageClassName = scName
			}
		} else if totalContainers > 0 {
			var requestedBy string
			if admResObject.UserName != "" {
				requestedBy = admResObject.UserName
			} else {
				for group := range admResObject.Groups.Iter() {
					if group != "system:authenticated" {
						requestedBy, _ = group.(string)
						break
					}
				}
			}
			reqEvalResult.User = requestedBy
			// check whether the containers are allowed.
			walkThruContainers(admResObject, stamps, ar, &evalContext, &reqEvalResult)
		}
	}
	stamps.Evaluated = time.Now()

	// if whsvr.dumpRequestObj {
	// 	const (
	// 		DDMMYYYYhhmmss = "2006-01-02-15-04-05"
	// 	)
	// 	now := time.Now().UTC()

	// 	jsonData, _ := json.Marshal(ar)
	// 	docKey := fmt.Sprintf("/v1/data/debug/ar/%s_%s_%s_MatchDeny_%v", now.Format(DDMMYYYYhhmmss), ar.Request.UID, req.Kind.Kind, admResult.MatchDenyRule)
	// 	opa.AddDocument(docKey, string(jsonData))
	// }

	unscannedImagesMsg := ""
	if reqEvalResult.UnscannedImages != "" {
		unscannedImagesMsg = fmt.Sprintf(" [Notice: the requested image(s) are not scanned: %s]", reqEvalResult.UnscannedImages)
	}

	if forTesting {
		var actioMsg string = "allowed"
		var ruleIdMsg string
		if reqEvalResult.ReqAction == share.AdmCtrlActionDeny {
			actioMsg = "denied"
			allowed = false

			ruleScope := ""
			criticalAssessment := reqEvalResult.CriticalAssessment
			criticalMatch := criticalAssessment.CriticalMatch
			if criticalMatch.IsFedRule {
				ruleScope = "federal "
			}
			ruleIdMsg = fmt.Sprintf(" because of %sdeny rule id %d", ruleScope, criticalMatch.RuleID)
		}

		matchedCount := 0
		for _, assessResult := range reqEvalResult.AssessResults {
			// assessResult is per-container-image's matching result, in type nvsysadmission.AdmCtrlAssessResult
			for _, matchedResult := range assessResult.MatchedResults {
				matchedResult.RuleDetails = fmt.Sprintf("It matches rule with criteria: %s.", matchedResult.RuleDetails)
				matchedCount++
			}
		}
		matchedResults = make([]*nvsysadmission.AdmCtrlMatchedResult, 0, matchedCount)
		for _, assessResult := range reqEvalResult.AssessResults {
			matchedResults = append(matchedResults, assessResult.MatchedResults...)
		}

		statusResult.Message = fmt.Sprintf("%s%s of Kubernetes %s is %s%s%s.", msgHeader, opDisplay, req.Kind.Kind, actioMsg, ruleIdMsg, unscannedImagesMsg)

	} else {
		violatedContainers := make([]string, 0, 4)
		for _, assessResult := range reqEvalResult.AssessResults {
			// assessResult is per-container-image's matching result, in type nvsysadmission.AdmCtrlAssessResult
			// when the request is denied, collect the matched deny/monitor rules before the deny/protect match
			violatedRules := make([]string, 0, 4) // for matched deny/monitor rules before the deny/protect match
			for _, matchedResult := range assessResult.MatchedResults {
				if matchedResult == assessResult.CriticalMatch {
					break
				}
				if matchedResult.IsDenyRuleType && matchedResult.IsMatchedMode(globalMode, share.AdmCtrlModeMonitor) {
					ruleScope := ""
					if matchedResult.IsFedRule {
						ruleScope = "federal "
					}
					msg := fmt.Sprintf("%sdeny rule id %d with criteria: %s", ruleScope, matchedResult.RuleID, matchedResult.RuleDetails)
					violatedRules = append(violatedRules, msg)
				}
			}
			if len(violatedRules) > 0 {
				msg := fmt.Sprintf("Container %s violates %s.", assessResult.ContainerImageInfo.Name, strings.Join(violatedRules, ", ")) // for only this container
				violatedContainers = append(violatedContainers, msg)
			}
			if reqEvalResult.ReqAction == share.AdmCtrlActionDeny && assessResult == reqEvalResult.CriticalAssessment {
				break
			}
		}

		if len(violatedContainers) > 0 {
			reqEvalResult.Msg = fmt.Sprintf("%s%s of Kubernetes %s resource (%s) violates Admission Control monitor-mode rule(s). %s%s",
				msgHeader, opDisplay, req.Kind.Kind, admResObject.Name, strings.Join(violatedContainers, " "), unscannedImagesMsg)
			cacheAdmCtrlAudit(share.CLUSAuditAdmCtrlK8sReqViolation, &reqEvalResult, nil, nil, admResObject)
		}

		if reqEvalResult.ReqAction != "" {
			criticalAssessment := reqEvalResult.CriticalAssessment
			criticalMatch := criticalAssessment.CriticalMatch
			if reqEvalResult.ReqAction == share.AdmCtrlActionDeny {
				statusResult.Message = fmt.Sprintf("%s%s of Kubernetes %s is denied.", msgHeader, opDisplay, req.Kind.Kind)
				allowed = false
				ruleScope := ""
				if criticalMatch.IsFedRule {
					ruleScope = "federal "
				}
				reqEvalResult.Msg = fmt.Sprintf("%s%s of Kubernetes %s resource (%s) is denied because of %sdeny rule id %d with criteria: %s.%s",
					msgHeader, opDisplay, req.Kind.Kind, admResObject.Name, ruleScope, criticalMatch.RuleID, criticalMatch.RuleDetails, unscannedImagesMsg)
				cacheAdmCtrlAudit(share.CLUSAuditAdmCtrlK8sReqDenied, &reqEvalResult, criticalAssessment, &criticalMatch.ImageInfo, admResObject)
			} else {
				allowedContainers := make([]string, 0, 4) // containers that explicitly match allow rule
				for _, assessResult := range reqEvalResult.AssessResults {
					// assessResult is per-container-image's matching result, in type nvsysadmission.AdmCtrlAssessResult
					if assessResult.CriticalMatch != nil && assessResult.AssessAction == share.AdmCtrlActionAllow {
						ruleScope := ""
						if assessResult.CriticalMatch.IsFedRule {
							ruleScope = "federal "
						}
						msg := fmt.Sprintf("conatiner %s matches %sallow rule id %d with criteria: %s",
							assessResult.ContainerImageInfo.Name, ruleScope, assessResult.CriticalMatch.RuleID, assessResult.CriticalMatch.RuleDetails)
						allowedContainers = append(allowedContainers, msg)
					}
				}
				reqEvalResult.Msg = fmt.Sprintf("%s%s of Kubernetes %s resource (%s) is allowed because %s.%s",
					msgHeader, opDisplay, req.Kind.Kind, admResObject.Name, strings.Join(allowedContainers, ", "), unscannedImagesMsg)
				matchedImageInfo := &criticalMatch.ImageInfo
				if reqEvalResult.ContainersInReq > 1 {
					criticalAssessment = nil
					matchedImageInfo = nil
				}
				cacheAdmCtrlAudit(share.CLUSAuditAdmCtrlK8sReqAllowed, &reqEvalResult, criticalAssessment, matchedImageInfo, admResObject)
			}
		} else {
			// doesn't match any rule
			reqEvalResult.Msg = fmt.Sprintf("%s%s of Kubernetes %s resource (%s) is allowed because it doesn't match any decisive rule.%s",
				msgHeader, opDisplay, req.Kind.Kind, admResObject.Name, unscannedImagesMsg)
			cacheAdmCtrlAudit(share.CLUSAuditAdmCtrlK8sReqAllowed, &reqEvalResult, nil, nil, admResObject)
		}
	}

	return &admissionv1beta1.AdmissionResponse{
		Allowed: allowed,
		Result:  statusResult,
	}, matchedResults, false
}

// Serve method for Kubernetes Admission Control
func (whsvr *WebhookServer) serveK8s(w http.ResponseWriter, r *http.Request, admType, category, globalMode string,
	defaultAction int, body []byte, stamps *api.AdmCtlTimeStamps, nvStatusReq bool) {
	var admissionResponse *admissionv1beta1.AdmissionResponse
	var ignoredReq bool
	ar := admissionv1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("can't decode body")
		http.Error(w, "invalid request", http.StatusBadRequest)
		if !nvStatusReq {
			cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
		}
		return
	} else {
		if ar.Request.Operation != admissionv1beta1.Delete {
			if b, err := json.Marshal(ar); err == nil {
				log.WithFields(log.Fields{"AdmissionReview": string(b)}).Debug()
			}
		}
		if (ar.Request == nil || len(ar.Request.Object.Raw) == 0) && (ar.Request.Operation != admissionv1beta1.Delete) {
			log.Warn("disallow because of no request/raw data")
			http.Error(w, "invalid request", http.StatusBadRequest)
			if !nvStatusReq {
				cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
			}
			return
		}

		if admType == admission.NvAdmValidateType {
			admissionResponse, _, ignoredReq = whsvr.validate(&ar, globalMode, defaultAction, stamps, false)
			admissionResponse.UID = ar.Request.UID
		} else {
			log.WithFields(log.Fields{"path": r.URL.Path}).Debug("unsupported path")
			http.Error(w, "unsupported", http.StatusNotImplemented)
			if !nvStatusReq {
				cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
			}
			return
		}
	}
	if admissionResponse == nil {
		http.Error(w, "could not get response", http.StatusInternalServerError)
		if !nvStatusReq {
			cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
		}
		return
	}

	var stats = nvsysadmission.ReqDenied
	if ignoredReq {
		stats = nvsysadmission.ReqIgnored
	} else if admissionResponse.Allowed {
		stats = nvsysadmission.ReqAllowed
	}

	admissionReview := admissionv1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       resource.K8sKindAdmissionReview,
			APIVersion: resource.AdmissionK8sIoV1Beta1, // [2021/09/21] currently our webhook server only support k8s.io/api/admission/v1beta1
		},
		Response: admissionResponse,
	}
	resp, err := json.Marshal(admissionReview)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("can't encode response")
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		stats = nvsysadmission.ReqErrored
	} else {
		if _, err := w.Write(resp); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("can't write response")
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
			stats = nvsysadmission.ReqErrored
		}
	}
	if !nvStatusReq {
		cacher.UpdateLocalAdmCtrlStats(category, stats)
	}
}

// Serve method for Admission Control webhook server
func (whsvr *WebhookServer) serveWithTimeStamps(w http.ResponseWriter, r *http.Request, stamps *api.AdmCtlTimeStamps) {
	var nvStatusReq bool

	uriMiddle := fmt.Sprintf("/%s/%s/", admission.UriAdmCtrlPrefix, admission.UriAdmCtrlNvStatus)
	if strings.Index(r.URL.String(), uriMiddle) > 0 {
		nvStatusReq = true
	}

	if !nvStatusReq {
		cacher.IncrementAdmCtrlProcessing()
	}
	enabled, globalMode, defaultAction, admType, category := cacher.IsAdmControlEnabled(&r.URL.Path)
	if !enabled {
		log.WithFields(log.Fields{"path": r.URL.Path, "admType": admType, "category": category}).Debug("disabled path")
		http.Error(w, "disabled", http.StatusNotImplemented)
		if !nvStatusReq {
			cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
		}
		return
	}

	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		log.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		if !nvStatusReq {
			cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
		}
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.WithFields(log.Fields{"contentType": contentType}).Error("unexpectd header")
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		if !nvStatusReq {
			cacher.UpdateLocalAdmCtrlStats(category, nvsysadmission.ReqErrored)
		}
		return
	}

	whsvr.serveK8s(w, r, admType, category, globalMode, defaultAction, body, stamps, nvStatusReq)
}

// Serve method for Admission Control webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var stamps api.AdmCtlTimeStamps

	stamps.Start = time.Now()
	whsvr.serveWithTimeStamps(w, r, &stamps)
	diff := time.Now().Sub(stamps.Start)
	if diff.Seconds() >= 28 {
		log.WithFields(log.Fields{"image": stamps.Images, "seconds": diff.Seconds(),
			"fetch": stamps.Fetched.Sub(stamps.GonnaFetch).Seconds()}).Warn("unexpected")
	}
}

/*
func (whsvr *WebhookServer) test(w http.ResponseWriter, r *http.Request) {
	log.Debug("test called")
	resp, _ := json.Marshal(emptyJSON)
	w.Write(resp)
	return
}
*/

func loadX509KeyPair(svcName string) (tls.Certificate, error) {
	var cert *share.CLUSX509Cert
	var err error

	cn := fmt.Sprintf("%s.%s.svc", svcName, resource.NvAdmSvcNamespace)
	for i := 0; i < 3; i++ {
		if cert, _, err = clusHelper.GetObjectCertRev(cn); !cert.IsEmpty() {
			keyPEMBlock := []byte(cert.Key)
			certPEMBlock := []byte(cert.Cert)
			b := md5.Sum(certPEMBlock)
			log.WithFields(log.Fields{"svcName": svcName, "cert": hex.EncodeToString(b[:])}).Info("md5")
			// admission.SetCABundle(svcName, certPEMBlock) //->

			return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		}
		time.Sleep(time.Second)
	}
	log.WithFields(log.Fields{"svcName": svcName, "error": err}).Error("Failed to load key pair for webhook server")

	return tls.Certificate{}, err
}

func restartWebhookServer(svcName string) error {
	log.WithFields(log.Fields{"svcName": svcName}).Info()

	k8sInfo := map[string]string{
		resource.NvAdmSvcName: resource.NvAdmValidatingName,
		resource.NvCrdSvcName: resource.NvCrdValidatingName,
	}
	if leader := atomic.LoadUint32(&_isLeader); leader == 1 {
		if nvAdmName, ok := k8sInfo[svcName]; ok {
			cacher.SyncAdmCtrlStateToK8s(svcName, nvAdmName, false)
		}
	}

	var whsvr *WebhookServer
	whSvrsMutex.RLock()
	whsvr = whsvrs[svcName]
	whSvrsMutex.RUnlock()

	if whsvr != nil {
		if whsvr.running {
			whsvr.reloadChan <- 1
			for i := 0; i < 15; i++ {
				if !whsvr.running {
					break
				}
				time.Sleep(time.Second)
			}
		}

		if svcName == resource.NvAdmSvcName {
			AdmissionRestServer(whsvr.port, whsvr.clientAuth, whsvr.debug)
		} else if svcName == resource.NvCrdSvcName {
			CrdValidateRestServer(whsvr.port, whsvr.clientAuth, whsvr.debug)
		}

		return nil
	} else {
		return fmt.Errorf("not supported(%s)", svcName)
	}
}

func k8sWebhookRestServer(svcName string, port uint, clientAuth, debug bool) {
	cacher.WaitUntilApiPathReady()

	state, _ := clusHelper.GetAdmissionStateRev(svcName)
	if state == nil {
		log.WithFields(log.Fields{"svcName": svcName}).Error("Failed to get control state from consul")
		return
	}

	listenPortTLS := fmt.Sprintf(":%d", port)

	pair, _ := loadX509KeyPair(svcName)

	whsvr := &WebhookServer{
		dumpRequestObj: debug,
		server: &http.Server{
			Addr: listenPortTLS,
			TLSConfig: &tls.Config{
				Certificates:             []tls.Certificate{pair},
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					// Best disabled, as they don't provide Forward Secrecy,
					// but might be necessary for some clients
					// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
		},
		port:       port,
		clientAuth: clientAuth,
		debug:      debug,
		reloadChan: make(chan int, 1),
	}
	whSvrsMutex.Lock()
	whsvrs[svcName] = whsvr
	whSvrsMutex.Unlock()
	whsvr.running = true // do not set to true until now

	if clientAuth {
		clientCACert := tlsClientCA
		caCert, err := os.ReadFile(clientCACert)
		if err != nil {
			log.WithFields(log.Fields{"svcName": svcName}).Info("Cannot load CA cert for client authentication")
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		whsvr.server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		whsvr.server.TLSConfig.ClientCAs = caCertPool
		whsvr.server.TLSConfig.MinVersion = tls.VersionTLS11
	}

	// define http server and server handler
	mux := http.NewServeMux()
	//mux.HandleFunc("/test", whsvr.test)
	for admType, ctrlState := range state.CtrlStates {
		log.WithFields(log.Fields{"admType": admType, "uri": ctrlState.Uri, "status_uri": ctrlState.NvStatusUri}).Debug("K8s webhook server")
		if ctrlState.Uri != "" {
			switch svcName {
			case resource.NvAdmSvcName:
				mux.HandleFunc(ctrlState.Uri, whsvr.serve)
			case resource.NvCrdSvcName:
				mux.HandleFunc(ctrlState.Uri, whsvr.crdserve)
			}

		}
		if ctrlState.NvStatusUri != "" {
			if svcName == resource.NvAdmSvcName {
				mux.HandleFunc(ctrlState.NvStatusUri, whsvr.serve)
			}
		}
	}
	whsvr.server.Handler = mux

	// start webhook server in new routine
	go func() {
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
			log.WithFields(log.Fields{"error": err, "svcName": svcName}).Error("Failed to listen and serve webhook server")
		}
	}()

	log.WithFields(log.Fields{"port": port, "svcName": svcName}).Info("Started Admission REST server")
	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// If server.ListenAndServe() cannot startup due to errors such as "port in use",
	// it will return error and get stuck waiting for osSignals.
	// This is not ideal because if a server doesn't start, we want to log the error and exit.
	// Unfortunately, we can't select on a waitgroup.
	// The done channel and select statement is used to handle the above case.
	var src string
	select {
	case <-whsvr.reloadChan:
		src = "reload"
	case <-signalChan:
		src = "OS"
	}
	log.WithFields(log.Fields{"svcName": svcName, "src": src}).Info("Got signal, shutting down webhook server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Attempt the graceful shutdown by closing the listener and completing all inflight requests.
	var sdErr error
	if err := whsvr.server.Shutdown(ctx); err != nil {
		sdErr = err
		// Looks like we timedout on the graceful shutdown. Kill it hard.
		if err := whsvr.server.Close(); err != nil {
			sdErr = err
		}
	}
	if sdErr != nil {
		log.WithFields(log.Fields{"err": sdErr, "svcName": svcName}).Error("shutdown error")
	}
	whsvr.running = false
}

func AdmissionRestServer(port uint, clientAuth, debug bool) {
	k8sWebhookRestServer(resource.NvAdmSvcName, port, clientAuth, debug)
}

func scanEnvVarSecrets(vars map[string]string) []share.ScanSecretLog {
	if len(vars) == 0 {
		return nil
	}

	var envVars string
	for k, v := range vars {
		pair := fmt.Sprintf("%v = %v\n", k, v)
		envVars = envVars + pair
		//	log.WithFields(log.Fields{"pair": pair}).Debug()
	}

	config := secrets.Config{} // default:
	logs, _, err := secrets.FindSecretsByRootpath("", []byte(envVars), config)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		return nil
	}

	// log.WithFields(log.Fields{"count": len(logs)}).Debug()
	slogs := make([]share.ScanSecretLog, len(logs))
	for i, l := range logs {
		// log.WithFields(log.Fields{"desc": l.RuleDesc, "path": l.File}).Debug()
		// cloak the secret a little bit by masking out some digits
		var subject string
		secretLength := len(l.Text)
		if secretLength > 32 {
			subject = l.Text[:30]
		} else if secretLength > 6 { // should be longer than 6
			subject = l.Text[:secretLength-3]
		}
		subject += "..."

		slogs[i] = share.ScanSecretLog{
			Type:       l.Type,
			Text:       subject, // description
			File:       l.File,
			RuleDesc:   l.RuleDesc,
			Suggestion: l.Suggestion,
		}
	}
	return slogs
}

func updateToOtherControllers(docKey string, jsonData string) {
	// call grpc
	info := share.CLUSKubernetesResInfo{
		DocKey: docKey,
		Data:   jsonData,
	}

	eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
	for _, ep := range eps {
		log.WithFields(log.Fields{"ep.ClusterIP": ep.ClusterIP, "ClusterIP": localDev.Ctrler.ClusterIP}).Debug("updateToOtherControllers(grpc-client)")

		if ep.ClusterIP != localDev.Ctrler.ClusterIP {
			go rpc.ReportK8SResToOPA(ep.ClusterIP, ep.RPCServerPort, info)
		}
	}
}

func ReportK8SResToOPA(info *share.CLUSKubernetesResInfo) {
	docKey := info.DocKey
	json_data := info.Data
	b := opa.AddDocument(docKey, string(json_data))

	log.WithFields(log.Fields{"docKey": info.DocKey, "AddDocument_Result": b}).Debug("ReportK8SResToOPA(grpc-server)")
}
