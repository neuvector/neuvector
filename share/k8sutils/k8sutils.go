package k8sutils

import (
	"context"

	log "github.com/sirupsen/logrus"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const NV_NAMESPACE = "{nv_namespace}"
const ALL_NAMESPACE = "{all_namespace}"

func CanI(clientset *kubernetes.Clientset, ra authorizationv1.ResourceAttributes, namespace string) (bool, error) {

	if ra.Namespace == NV_NAMESPACE {
		ra.Namespace = namespace
	} else if ra.Namespace == ALL_NAMESPACE {
		ra.Namespace = ""
	}

	client := clientset.AuthorizationV1()

	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &ra,
		},
	}

	response, err := client.SelfSubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	if response.Status.Allowed {
		return true, nil
	} else {
		log.WithFields(log.Fields{
			"resource":         ra,
			"reason":           response.Status.Reason,
			"evaluation_error": response.Status.EvaluationError,
		}).Info("the action is not allowed")
		return false, nil
	}
}
