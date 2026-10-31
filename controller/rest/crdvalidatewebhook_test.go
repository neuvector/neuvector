package rest

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/resource"
)

func serveCrdRequest(t *testing.T, req *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse {
	t.Helper()

	ar := admissionv1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1beta1",
		},
		Request: req,
	}
	body, err := json.Marshal(&ar)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	whsvr := &WebhookServer{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	whsvr.crdserveK8s(w, r, body)

	var resp admissionv1beta1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (body: %q)", err, w.Body.String())
	}
	if resp.Response == nil {
		t.Fatalf("no response in AdmissionReview (body: %q)", w.Body.String())
	}
	return resp.Response
}

func TestCrdValidateDryRunAllowed(t *testing.T) {
	preTest()

	dryRun := true
	raw := []byte(`{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"nv.test.default","namespace":"default"}}`)

	for _, op := range []admissionv1beta1.Operation{admissionv1beta1.Create, admissionv1beta1.Update, admissionv1beta1.Delete} {
		req := &admissionv1beta1.AdmissionRequest{
			UID:       types.UID("dry-run-test"),
			Kind:      metav1.GroupVersionKind{Group: "neuvector.com", Version: "v1", Kind: resource.NvSecurityRuleKind},
			Name:      "nv.test.default",
			Namespace: "default",
			Operation: op,
			DryRun:    &dryRun,
		}
		if op == admissionv1beta1.Delete {
			req.OldObject = runtime.RawExtension{Raw: raw}
		} else {
			req.Object = runtime.RawExtension{Raw: raw}
		}

		resp := serveCrdRequest(t, req)
		if !resp.Allowed {
			t.Errorf("dry-run %s denied: %+v", op, resp.Result)
		}
		// kubectl shows Result.Message only on a denial, so an allowed
		// dry-run has to say what happened through a warning.
		if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "dry-run") {
			t.Errorf("dry-run %s: expected one warning naming dry-run, got %v", op, resp.Warnings)
		}
	}

	postTest()
}

func TestCrdValidateDryRunKeepsNameCheck(t *testing.T) {
	preTest()

	// A CREATE with a metadata name outside the allowed set for this kind is
	// denied synchronously, and dry-run must give the same answer.
	dryRun := true
	raw := []byte(`{"apiVersion":"neuvector.com/v1","kind":"NvAdmissionControlSecurityRule","metadata":{"name":"bogus"}}`)

	req := &admissionv1beta1.AdmissionRequest{
		UID:       types.UID("dry-run-test"),
		Kind:      metav1.GroupVersionKind{Group: "neuvector.com", Version: "v1", Kind: resource.NvAdmCtrlSecurityRuleKind},
		Name:      "bogus",
		Operation: admissionv1beta1.Create,
		Object:    runtime.RawExtension{Raw: raw},
		DryRun:    &dryRun,
	}

	resp := serveCrdRequest(t, req)
	if resp.Allowed {
		t.Errorf("dry-run CREATE with disallowed metadata name was allowed")
	}
	// The denial already carries the message; no warning on top of it.
	if len(resp.Warnings) != 0 {
		t.Errorf("denied dry-run carried warnings: %v", resp.Warnings)
	}

	postTest()
}

func TestCrdValidateDryRunKeepsFedCheck(t *testing.T) {
	preTest()

	// Importing a federated rule through CRD is denied synchronously, and
	// dry-run must give the same answer.
	dryRun := true
	name := api.FederalGroupPrefix + "test"
	raw := []byte(`{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"` + name + `","namespace":"default"}}`)

	req := &admissionv1beta1.AdmissionRequest{
		UID:       types.UID("dry-run-test"),
		Kind:      metav1.GroupVersionKind{Group: "neuvector.com", Version: "v1", Kind: resource.NvSecurityRuleKind},
		Name:      name,
		Namespace: "default",
		Operation: admissionv1beta1.Create,
		Object:    runtime.RawExtension{Raw: raw},
		DryRun:    &dryRun,
	}

	resp := serveCrdRequest(t, req)
	if resp.Allowed {
		t.Errorf("dry-run CREATE of federated rule %q was allowed", name)
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "federated") {
		t.Errorf("expected the federated-import denial, got %+v", resp.Result)
	}

	postTest()
}
