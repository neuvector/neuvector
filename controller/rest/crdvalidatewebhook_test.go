package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
)

func TestCrdServeK8sAllowsDryRunWithoutQueue(t *testing.T) {
	preTest()
	defer postTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}

	oldCrdReqMgr := crdReqMgr
	crdReqMgr = nil
	defer func() {
		crdReqMgr = oldCrdReqMgr
	}()

	policyMode := share.PolicyModeEnforce
	secRule := resource.NvSecurityRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "neuvector.com/v1",
			Kind:       resource.NvSecurityRuleKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ubuntu",
			Namespace: "default",
		},
		Spec: resource.NvSecurityRuleSpec{
			Target: resource.NvSecurityTarget{
				PolicyMode: &policyMode,
				Selector: api.RESTCrdGroupConfig{
					Name: "nv.ubuntu.default",
					Criteria: []api.RESTCriteriaEntry{
						{Key: share.CriteriaKeyService, Value: "ubuntu.default", Op: share.CriteriaOpEqual},
						{Key: share.CriteriaKeyDomain, Value: "default", Op: share.CriteriaOpEqual},
					},
				},
			},
		},
	}
	rawSecRule, err := json.Marshal(secRule)
	if err != nil {
		t.Fatalf("marshal security rule: %v", err)
	}

	dryRun := true
	ar := admissionv1beta1.AdmissionReview{
		Request: &admissionv1beta1.AdmissionRequest{
			UID: types.UID("dry-run-test"),
			Kind: metav1.GroupVersionKind{
				Group:   "neuvector.com",
				Version: "v1",
				Kind:    resource.NvSecurityRuleKind,
			},
			Resource: metav1.GroupVersionResource{
				Group:    "neuvector.com",
				Version:  "v1",
				Resource: resource.NvSecurityRulePlural,
			},
			Operation: admissionv1beta1.Create,
			Name:      secRule.Name,
			Namespace: secRule.Namespace,
			Object:    runtime.RawExtension{Raw: rawSecRule},
			DryRun:    &dryRun,
		},
	}
	body, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal admission review: %v", err)
	}

	w := new(mockResponseWriter)
	r := httptest.NewRequest(http.MethodPost, "/validate", nil)
	(&WebhookServer{}).crdserveK8s(w, r, body)

	if w.status != 0 && w.status != http.StatusOK {
		t.Fatalf("dry-run request status=%v, want %v: %s", w.status, http.StatusOK, string(w.body))
	}

	var resp admissionv1beta1.AdmissionReview
	if err := json.Unmarshal(w.body, &resp); err != nil {
		t.Fatalf("unmarshal admission response: %v", err)
	}
	if resp.Response == nil {
		t.Fatalf("missing admission response")
	}
	if !resp.Response.Allowed {
		message := ""
		if resp.Response.Result != nil {
			message = resp.Response.Result.Message
		}
		t.Fatalf("dry-run request was denied: %s", message)
	}
	if resp.Response.Result == nil || !strings.Contains(resp.Response.Result.Message, "done in dry-run") {
		t.Fatalf("unexpected dry-run response message: %#v", resp.Response.Result)
	}
}
