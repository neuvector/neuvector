package main

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Update kuberentes secret.
// This is a wrapper for dynamic client.
func UpdateSecret(ctx context.Context, client dynamic.Interface, namespace string, secret *corev1.Secret) (*corev1.Secret, error) {
	var err error
	var item *unstructured.Unstructured
	var ret corev1.Secret
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	secret.Labels["last-modified"] = time.Now().Format("2006-01-02-15-04-05")

	unstructedSecret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target secret: %w", err)
	}

	item, err = client.Resource(schema.GroupVersionResource{
		Resource: "secrets",
		Version:  "v1",
	}).Namespace(namespace).Update(ctx, &unstructured.Unstructured{Object: unstructedSecret}, metav1.UpdateOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to update resource: %w", err)
	}

	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &ret)
	return &ret, err
}

// Get kuberentes secret.
// This is a wrapper for dynamic client.
func GetK8sSecret(ctx context.Context, client dynamic.Interface, namespace string, name string) (*corev1.Secret, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "secrets",
			Version:  "v1",
		},
	).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})

	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	var targetSecret corev1.Secret
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &targetSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target secret: %w", err)
	}
	return &targetSecret, nil
}
