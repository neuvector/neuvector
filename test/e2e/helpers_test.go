package e2e_test

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type contextKey struct{}

var k8sClientKey contextKey

const (
	controllerDeploymentName = "neuvector-controller-pod"
	enforcerDaemonSetName    = "neuvector-enforcer-pod"
	managerDeploymentName    = "neuvector-manager-pod"
	scannerDeploymentName    = "neuvector-scanner-pod"

	assessTimeout = 5 * time.Minute
)

func getNeuVectorDeploymentFeature() types.Feature {
	return features.New("NeuVector Core Deployment").
		Setup(setupSharedK8sClient).
		Assess("controller deployment is available", assessControllerDeployment).
		Assess("enforcer daemonset is ready", assessEnforcerDaemonSet).
		Assess("manager deployment is available", assessManagerDeployment).
		Assess("scanner deployment is available", assessScannerDeployment).
		Feature()
}

func setupSharedK8sClient(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client, err := cfg.NewClient()
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}
	return context.WithValue(ctx, k8sClientKey, client)
}

func getK8sClient(ctx context.Context) klient.Client {
	return ctx.Value(k8sClientKey).(klient.Client)
}

func assessControllerDeployment(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: controllerDeploymentName, Namespace: nvNamespace},
	}
	if err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	); err != nil {
		t.Fatalf("controller deployment not available: %v", err)
	}
	return ctx
}

func assessEnforcerDaemonSet(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: enforcerDaemonSetName, Namespace: nvNamespace},
	}
	if err := wait.For(
		conditions.New(client.Resources()).ResourceMatch(ds, func(obj k8s.Object) bool {
			d := obj.(*appsv1.DaemonSet)
			return d.Status.DesiredNumberScheduled > 0 &&
				d.Status.DesiredNumberScheduled == d.Status.NumberReady
		}),
		wait.WithTimeout(assessTimeout),
	); err != nil {
		t.Fatalf("enforcer daemonset not ready: %v", err)
	}
	return ctx
}

func assessManagerDeployment(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: managerDeploymentName, Namespace: nvNamespace},
	}
	if err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	); err != nil {
		t.Fatalf("manager deployment not available: %v", err)
	}
	return ctx
}

func assessScannerDeployment(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: scannerDeploymentName, Namespace: nvNamespace},
	}
	if err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	); err != nil {
		t.Fatalf("scanner deployment not available: %v", err)
	}
	return ctx
}
