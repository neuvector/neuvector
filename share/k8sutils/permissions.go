package k8sutils

import (
	authorizationv1 "k8s.io/api/authorization/v1"
)

var UpgraderPresyncRequiredPermissions = []authorizationv1.ResourceAttributes{
	// jobs
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "create",
		Group:       "batch",
		Resource:    "jobs",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "batch",
		Resource:    "jobs",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "delete",
		Group:       "batch",
		Resource:    "jobs",
		Subresource: "",
		Name:        "",
	},
	// cronjobs
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "update",
		Group:       "batch",
		Resource:    "cronjobs",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "patch",
		Group:       "batch",
		Resource:    "cronjobs",
		Subresource: "",
		Name:        "",
	},
	// cronjobs/finalizers
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "update",
		Group:       "batch",
		Resource:    "cronjobs",
		Subresource: "finalizers",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "patch",
		Group:       "batch",
		Resource:    "cronjobs",
		Subresource: "finalizers",
		Name:        "",
	},
}

var UpgraderPostsyncRequiredPermissions = []authorizationv1.ResourceAttributes{
	// secrets
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "update",
		Group:       "",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "list",
		Group:       "",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "watch",
		Group:       "",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	// pods
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "",
		Resource:    "pods",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "list",
		Group:       "",
		Resource:    "pods",
		Subresource: "",
		Name:        "",
	},
	// deployments
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "apps",
		Resource:    "deployments",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "list",
		Group:       "apps",
		Resource:    "deployments",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "watch",
		Group:       "apps",
		Resource:    "deployments",
		Subresource: "",
		Name:        "",
	},
	// daemonsets
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "apps",
		Resource:    "daemonsets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "list",
		Group:       "apps",
		Resource:    "daemonsets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "watch",
		Group:       "apps",
		Resource:    "daemonsets",
		Subresource: "",
		Name:        "",
	},
	// cronjobs
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "update",
		Group:       "batch",
		Resource:    "cronjobs",
		Subresource: "",
		Name:        "",
	},
}

var SecretInformerRequiredPermissions = []authorizationv1.ResourceAttributes{
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "get",
		Group:       "",
		Version:     "v1",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "list",
		Group:       "",
		Version:     "v1",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
	{
		Namespace:   NV_NAMESPACE,
		Verb:        "watch",
		Group:       "",
		Version:     "v1",
		Resource:    "secrets",
		Subresource: "",
		Name:        "",
	},
}
