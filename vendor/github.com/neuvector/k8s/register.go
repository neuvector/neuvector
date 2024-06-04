package k8s

import (
	admregv1 "k8s.io/api/admissionregistration/v1"
	admregv1b1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1b1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1b1 "k8s.io/api/rbac/v1beta1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1b1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

func init() {
	Register("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", false, &admregv1.MutatingWebhookConfiguration{})
	Register("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", false, &admregv1.ValidatingWebhookConfiguration{})
	RegisterList("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", false, &admregv1.MutatingWebhookConfigurationList{})
	RegisterList("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", false, &admregv1.ValidatingWebhookConfigurationList{})

	Register("admissionregistration.k8s.io", "v1beta1", "mutatingwebhookconfigurations", false, &admregv1b1.MutatingWebhookConfiguration{})
	Register("admissionregistration.k8s.io", "v1beta1", "validatingwebhookconfigurations", false, &admregv1b1.ValidatingWebhookConfiguration{})
	RegisterList("admissionregistration.k8s.io", "v1beta1", "mutatingwebhookconfigurations", false, &admregv1b1.MutatingWebhookConfigurationList{})
	RegisterList("admissionregistration.k8s.io", "v1beta1", "validatingwebhookconfigurations", false, &admregv1b1.ValidatingWebhookConfigurationList{})

	Register("apiextensions.k8s.io", "v1", "customresourcedefinitions", false, &apiextv1.CustomResourceDefinition{})
	RegisterList("apiextensions.k8s.io", "v1", "customresourcedefinitions", false, &apiextv1.CustomResourceDefinitionList{})

	Register("apiextensions.k8s.io", "v1beta1", "customresourcedefinitions", false, &apiextv1b1.CustomResourceDefinition{})
	RegisterList("apiextensions.k8s.io", "v1beta1", "customresourcedefinitions", false, &apiextv1b1.CustomResourceDefinitionList{})

	Register("apps", "v1", "controllerrevisions", true, &appsv1.ControllerRevision{})
	Register("apps", "v1", "daemonsets", true, &appsv1.DaemonSet{})
	Register("apps", "v1", "deployments", true, &appsv1.Deployment{})
	Register("apps", "v1", "replicasets", true, &appsv1.ReplicaSet{})
	Register("apps", "v1", "statefulsets", true, &appsv1.StatefulSet{})
	RegisterList("apps", "v1", "controllerrevisions", true, &appsv1.ControllerRevisionList{})
	RegisterList("apps", "v1", "daemonsets", true, &appsv1.DaemonSetList{})
	RegisterList("apps", "v1", "deployments", true, &appsv1.DeploymentList{})
	RegisterList("apps", "v1", "replicasets", true, &appsv1.ReplicaSetList{})
	RegisterList("apps", "v1", "statefulsets", true, &appsv1.StatefulSetList{})

	Register("batch", "v1", "jobs", true, &batchv1.Job{})
	RegisterList("batch", "v1", "jobs", true, &batchv1.JobList{})

	Register("batch", "v1", "cronjobs", true, &batchv1.CronJob{})
	RegisterList("batch", "v1", "cronjobs", true, &batchv1.CronJobList{})
	Register("batch", "v1beta1", "cronjobs", true, &batchv1b1.CronJob{})
	RegisterList("batch", "v1beta1", "cronjobs", true, &batchv1b1.CronJobList{})

	Register("", "v1", "componentstatuses", false, &corev1.ComponentStatus{})
	Register("", "v1", "configmaps", true, &corev1.ConfigMap{})
	Register("", "v1", "endpoints", true, &corev1.Endpoints{})
	Register("", "v1", "limitranges", true, &corev1.LimitRange{})
	Register("", "v1", "namespaces", false, &corev1.Namespace{})
	Register("", "v1", "nodes", false, &corev1.Node{})
	Register("", "v1", "persistentvolumeclaims", true, &corev1.PersistentVolumeClaim{})
	Register("", "v1", "persistentvolumes", false, &corev1.PersistentVolume{})
	Register("", "v1", "pods", true, &corev1.Pod{})
	Register("", "v1", "replicationcontrollers", true, &corev1.ReplicationController{})
	Register("", "v1", "resourcequotas", true, &corev1.ResourceQuota{})
	Register("", "v1", "secrets", true, &corev1.Secret{})
	Register("", "v1", "services", true, &corev1.Service{})
	Register("", "v1", "serviceaccounts", true, &corev1.ServiceAccount{})
	RegisterList("", "v1", "componentstatuses", false, &corev1.ComponentStatusList{})
	RegisterList("", "v1", "configmaps", true, &corev1.ConfigMapList{})
	RegisterList("", "v1", "endpoints", true, &corev1.EndpointsList{})
	RegisterList("", "v1", "limitranges", true, &corev1.LimitRangeList{})
	RegisterList("", "v1", "namespaces", false, &corev1.NamespaceList{})
	RegisterList("", "v1", "nodes", false, &corev1.NodeList{})
	RegisterList("", "v1", "persistentvolumeclaims", true, &corev1.PersistentVolumeClaimList{})
	RegisterList("", "v1", "persistentvolumes", false, &corev1.PersistentVolumeList{})
	RegisterList("", "v1", "pods", true, &corev1.PodList{})
	RegisterList("", "v1", "replicationcontrollers", true, &corev1.ReplicationControllerList{})
	RegisterList("", "v1", "resourcequotas", true, &corev1.ResourceQuotaList{})
	RegisterList("", "v1", "secrets", true, &corev1.SecretList{})
	RegisterList("", "v1", "services", true, &corev1.ServiceList{})
	RegisterList("", "v1", "serviceaccounts", true, &corev1.ServiceAccountList{})

	Register("rbac.authorization.k8s.io", "v1", "clusterroles", false, &rbacv1.ClusterRole{})
	Register("rbac.authorization.k8s.io", "v1", "clusterrolebindings", false, &rbacv1.ClusterRoleBinding{})
	Register("rbac.authorization.k8s.io", "v1", "roles", true, &rbacv1.Role{})
	Register("rbac.authorization.k8s.io", "v1", "rolebindings", true, &rbacv1.RoleBinding{})
	RegisterList("rbac.authorization.k8s.io", "v1", "clusterroles", false, &rbacv1.ClusterRoleList{})
	RegisterList("rbac.authorization.k8s.io", "v1", "clusterrolebindings", false, &rbacv1.ClusterRoleBindingList{})
	RegisterList("rbac.authorization.k8s.io", "v1", "roles", true, &rbacv1.RoleList{})
	RegisterList("rbac.authorization.k8s.io", "v1", "rolebindings", true, &rbacv1.RoleBindingList{})

	Register("rbac.authorization.k8s.io", "v1beta1", "clusterroles", false, &rbacv1b1.ClusterRole{})
	Register("rbac.authorization.k8s.io", "v1beta1", "clusterrolebindings", false, &rbacv1b1.ClusterRoleBinding{})
	Register("rbac.authorization.k8s.io", "v1beta1", "roles", true, &rbacv1b1.Role{})
	Register("rbac.authorization.k8s.io", "v1beta1", "rolebindings", true, &rbacv1b1.RoleBinding{})
	RegisterList("rbac.authorization.k8s.io", "v1beta1", "clusterroles", false, &rbacv1b1.ClusterRoleList{})
	RegisterList("rbac.authorization.k8s.io", "v1beta1", "clusterrolebindings", false, &rbacv1b1.ClusterRoleBindingList{})
	RegisterList("rbac.authorization.k8s.io", "v1beta1", "roles", true, &rbacv1b1.RoleList{})
	RegisterList("rbac.authorization.k8s.io", "v1beta1", "rolebindings", true, &rbacv1b1.RoleBindingList{})
}
