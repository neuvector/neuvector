package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/neuvector/neuvector/share/k8sutils"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
)

const (
	UPGRADER_JOB_NAME       = "neuvector-cert-upgrader-job"
	UPGRADER_CRONJOB_NAME   = "neuvector-cert-upgrader-pod"
	UPGRADER_UID_ANNOTATION = "cert-upgrader-uid"

	CONTROLLER_LEASE_NAME = "neuvector-controller"
)

// Check controller pods to see if they are all coming from the same owner (ReplicaSet)
// It's more complicated to check if we're doing an upgrade instead of creating a new pod.
// Luckily, we only need this information to speed up cert rotation during fresh install.
func IsFreshInstall(ctx context.Context, client dynamic.Interface, namespace string) (bool, error) {

	// Get all controller pods including those being initialized.
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: ControllerPodLabelSelector,
	})
	if err != nil {
		return false, fmt.Errorf("failed to find controller pods: %w", err)
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, fmt.Errorf("failed to read pod list: %w", err)
	}

	ownerID := ""
	// Examine all controller pods to see if their certificate expires or they're still using legacy certs.
	for _, pod := range pods.Items {
		uid := ""
		if len(pod.OwnerReferences) > 0 {
			uid = string(pod.OwnerReferences[0].UID)
		}

		log.WithFields(log.Fields{
			"pod":      pod.Status.PodIP,
			"ownerUID": uid,
		}).Debug("Getting pod's owner UID")

		if len(pod.OwnerReferences) != 1 {
			// Shouldn't be more than one owner reference...return error in this case.
			return false, errors.New("invalid owner reference are detected")
		}
		if ownerID == "" {
			ownerID = uid
			continue
		}
		if ownerID != uid {
			log.Info("Controller pods belonging to other replicaset is detected.  We're not in a fresh install.")
			return false, nil
		}
	}

	log.Info("All controllers coming from the same replicaset. It's a fresh install.")
	return true, nil
}

func GetCronJobDetail(ctx context.Context, client dynamic.Interface, namespace string) (item *unstructured.Unstructured, jobSpec *batchv1.JobSpec, labels map[string]string, annotations map[string]string, useBetav1 bool, err error) {
	item, err = client.Resource(
		schema.GroupVersionResource{
			Resource: "cronjobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Get(ctx, UPGRADER_CRONJOB_NAME, metav1.GetOptions{})

	if err != nil && k8sError.IsNotFound(err) {
		log.Info("batch/v1 is not found.  Fallback to batch/v1beta1")
		useBetav1 = false
		item, err = client.Resource(
			schema.GroupVersionResource{
				Resource: "cronjobs",
				Version:  "v1beta1",
				Group:    "batch",
			},
		).Namespace(namespace).Get(ctx, UPGRADER_CRONJOB_NAME, metav1.GetOptions{})
	}

	if err != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("failed to find cert upgrader cronjob: %w", err)
	}

	if useBetav1 {
		var cronjob batchv1.CronJob
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &cronjob)
		if err != nil {
			return nil, nil, nil, nil, false, fmt.Errorf("failed to convert to job: %w", err)
		}
		jobSpec = &cronjob.Spec.JobTemplate.Spec
		annotations = cronjob.Spec.JobTemplate.Annotations
		labels = cronjob.Spec.JobTemplate.Labels
	} else {
		var cronjob batchv1beta1.CronJob
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(item.UnstructuredContent(), &cronjob)
		if err != nil {
			return nil, nil, nil, nil, false, fmt.Errorf("failed to convert to job: %w", err)
		}
		jobSpec = &cronjob.Spec.JobTemplate.Spec
		annotations = cronjob.Spec.JobTemplate.Annotations
		labels = cronjob.Spec.JobTemplate.Labels
	}

	if annotations == nil {
		annotations = make(map[string]string)
	}

	if labels == nil {
		labels = make(map[string]string)
	}

	return item, jobSpec, labels, annotations, useBetav1, nil

}

// Create post-sync job and leave.
func CreatePostSyncJob(ctx context.Context, client dynamic.Interface, namespace string, certUpgraderUID string, withLock bool) (*batchv1.Job, error) {
	// Global cluster-level lock with 5 mins TTL
	if withLock {
		lock, err := CreateLocker(client, namespace, CONTROLLER_LEASE_NAME)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire cluster-wide lock: %w", err)
		}
		lock.Lock()
		defer lock.Unlock()
	}

	// Get cron job's template to create job.
	// Note: CronJob is moved to batch/v1 in 1.21.  We fallback to v1beta1 if it doesn't exist.
	cronjob, jobSpec, jobLabels, jobAnnotations, useBetav1, err := GetCronJobDetail(ctx, client, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get detail from cert upgrader cronjob: %w", err)
	}

	// Make sure jobs created by other init containers will not be deleted.
	annotations := cronjob.GetAnnotations()
	if annotations != nil && annotations[UPGRADER_UID_ANNOTATION] == certUpgraderUID {
		// This is created by the same deployment.
		log.Info("Upgrader job is already created.  Exit.")
		return nil, nil
	}

	background := metav1.DeletePropagationBackground
	err = client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Delete(ctx, UPGRADER_JOB_NAME, metav1.DeleteOptions{PropagationPolicy: &background})

	if err != nil {
		if !k8sError.IsNotFound(err) {
			return nil, fmt.Errorf("failed to find cert upgrader job: %w", err)
		}
	} else {
		log.Info("Job from the previous deployment/values is deleted.")
	}

	freshInstall, err := IsFreshInstall(ctx, client, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to check if it's a fresh install or not: %w", err)
	}

	jobAnnotations["cronjob.kubernetes.io/instantiate"] = "manual"
	jobAnnotations[UPGRADER_UID_ANNOTATION] = certUpgraderUID

	newjob := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Labels:            jobLabels,
			Annotations:       jobAnnotations,
			Name:              UPGRADER_JOB_NAME,
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: time.Now()},
			OwnerReferences: []metav1.OwnerReference{metav1.OwnerReference{
				APIVersion:         cronjob.GetAPIVersion(),
				Kind:               cronjob.GetKind(),
				Name:               cronjob.GetName(),
				UID:                cronjob.GetUID(),
				BlockOwnerDeletion: pointer.Bool(true),
				Controller:         pointer.Bool(true),
			}},
		},
		Spec: *jobSpec,
	}

	if freshInstall {
		newjob.Spec.Template.Spec.Containers[0].Command = append(newjob.Spec.Template.Spec.Containers[0].Command, "--fresh-install")
	}

	if os.Getenv("ENABLE_ROTATION") != "" {
		newjob.Spec.Template.Spec.Containers[0].Command = append(newjob.Spec.Template.Spec.Containers[0].Command, "--enable-rotation")
	}

	unstructedJob, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&newjob)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target job: %w", err)
	}

	retjob, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "jobs",
			Version:  "v1",
			Group:    "batch",
		},
	).Namespace(namespace).Create(ctx, &unstructured.Unstructured{Object: unstructedJob}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create upgrade job: %w", err)
	}

	// Patch cronjob, so it has the UPGRADER_UID_ANNOTATION annotation

	var ret batchv1.Job
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(retjob.UnstructuredContent(), &ret)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to job: %w", err)
	}

	// Update cronjob
	payload := []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}{{
		Op:    "replace",
		Path:  fmt.Sprintf("/metadata/annotations/%s", UPGRADER_UID_ANNOTATION),
		Value: certUpgraderUID,
	}}
	patchBytes, _ := json.Marshal(payload)

	if useBetav1 {
		_, err = client.Resource(
			schema.GroupVersionResource{
				Resource: "cronjobs",
				Version:  "v1beta1",
				Group:    "batch",
			},
		).Namespace(namespace).Patch(ctx, UPGRADER_CRONJOB_NAME, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
	} else {
		_, err = client.Resource(
			schema.GroupVersionResource{
				Resource: "cronjobs",
				Version:  "v1",
				Group:    "batch",
			},
		).Namespace(namespace).Patch(ctx, UPGRADER_CRONJOB_NAME, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update cron job labels: %w", err)
	}

	log.Info("Post upgrade job is created")
	return &ret, nil
}

func PreSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("pod-namespace")
	kubeconfig := ctx.String("kube-config")
	secretName := ctx.String("internal-secret-name")
	timeout := ctx.Duration("timeout")

	log.Info("Getting running namespace")

	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(data)
	} else {
		log.WithError(err).Warn("failed to open namespace file.")
	}

	log.WithFields(log.Fields{
		"namespace":  namespace,
		"kubeconfig": kubeconfig,
		"secretName": secretName,
	}).Info("init container starts")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	log.Info("Checking k8s permissions")

	// Check if required permissions are there.
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to read in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to get k8s config: %w", err)
	}

	for _, res := range k8sutils.UpgraderPresyncRequiredPermissions {
		capable, err := k8sutils.CanI(clientset, res, namespace)
		if err != nil {
			return err
		}
		if !capable {
			if os.Getenv("NO_FALLBACK") == "" {
				log.Warn("required permission is missing...skip the certificate generation/rotation")
				os.Exit(0)
			} else {
				log.Error("required permission is missing...ending now")
				os.Exit(-2)
			}
		}
	}

	log.Info("Getting helm values check sum")

	valuesChecksum := os.Getenv("OVERRIDE_CHECKSUM")

	timeoutCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	defer cancel()

	var secret *corev1.Secret
	if secret, err = GetK8sSecret(timeoutCtx, client, namespace, secretName); err != nil {
		// The secret is supposed to be created by helm.
		// If the secret is not created yet, it can be automatically retried by returning error.
		return fmt.Errorf("failed to find source secret: %w", err)
	}
	secretUID := string(secret.UID)

	log.WithField("checksum", valuesChecksum).Info("Retrieved values sha256 sum successfully")

	log.Info("Creating cert upgrade job")

	// Here we create a UID combined with neuvector-internal-certs's resource ID (created/deleted via helm)
	// If secret.UID is changed, that means this is a different deployment, so we have to delete the existing job.
	// If the deploymentUID, which is a sha256 sum of all helm values, changes, we do the same thing.
	// If this UID is the same, skip the job creation.
	if _, err := CreatePostSyncJob(timeoutCtx, client, namespace, secretUID+valuesChecksum, true); err != nil {
		return fmt.Errorf("failed to create post sync job: %w", err)
	}

	// At this point, we should have a job is running.
	// Let's wait until the job exits or this container gets restarted.  If we exit here, it would cause race condition.

	log.Info("Completed")
	return nil
}
