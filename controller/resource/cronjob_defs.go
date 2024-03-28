// type CronJob(v1) is first available in k8s.io/api 1.21
// To upgrade k8s.io/api to 1.21, we also need to upgrade k8s.io/apiextensions-apiserver to 1.21 & k8s.io/apimachinery to 1.19
// However, CronJob(v1) in k8s.io/api 1.21(+) doesn't implement GetMetadata(), which is required for k8s.Resource, anymore
// So we declare type CronJobV1 which is a warpper of k8s.io/api's CronJob(v1) & implements 'GetMetadata() *metav1.ObjectMeta'
package resource

import (
	"github.com/neuvector/k8s"

	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	batchv1 "k8s.io/api/batch/v1"
)

type CronJobV1 struct {
	batchv1.CronJob
}

type CronJobListV1 struct {
	batchv1.CronJobList
}

func (m *CronJobV1) GetMetadata() *metav1.ObjectMeta {
	if m != nil {
		uid := string(m.UID)
		return &metav1.ObjectMeta{
			Name:                       &m.Name,
			GenerateName:               &m.GenerateName,
			Namespace:                  &m.Namespace,
			SelfLink:                   &m.SelfLink,
			Uid:                        &uid,
			ResourceVersion:            &m.ResourceVersion,
			Generation:                 &m.Generation,
			DeletionGracePeriodSeconds: m.DeletionGracePeriodSeconds,
			Labels:                     m.Labels,
			Annotations:                m.Annotations,
			Finalizers:                 m.Finalizers,
			//ClusterName:                &m.ClusterName,
			//CreationTimestamp:          m.CreationTimestamp,
			//DeletionTimestamp:          m.DeletionTimestamp,
			//OwnerReferences:            &m.OwnerReferences,
			//ManagedFields:              &m.ManagedFields,
		}
	}
	return nil
}

func (m *CronJobListV1) GetMetadata() *metav1.ListMeta {
	if m != nil {
		return &metav1.ListMeta{
			SelfLink:        &m.SelfLink,
			ResourceVersion: &m.ResourceVersion,
			Continue:        &m.Continue,
		}
	}
	return nil
}

func init() {
	k8s.Register("batch", "v1", "cronjobs", true, &CronJobV1{})

	k8s.RegisterList("batch", "v1", "cronjobs", true, &CronJobListV1{})
}
