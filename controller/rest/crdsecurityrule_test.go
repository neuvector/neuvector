package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
	"sigs.k8s.io/yaml"
)

func TestParseCrdSecurityRule(t *testing.T) {
	preTest()
	var raw_string, err string
	var raw []byte
	var errCount int
	var gfwrule api.NvSecurityRule

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey, importCallerRest)

	// all correct
	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount > 0 {
		t.Errorf("0 parse error\n %v", err)
	}
	// get service name different than criteria service value "ubuntu1"
	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu1.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	//	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu1.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// operation should only be =

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"!=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// key value can't be empty or anything other than service/domain

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must be service or domain for nv

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"namespace\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must match domain value with name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default1\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}
	// criteria self dumplicate for ubuntu_egress_rule

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu\",\"op\":\"=\"},{\"key\":\"lable\",\"value\":\"alpine\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"alpine\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	// same group with different criteria

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// policy name duplicate

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't use nv.ip.exc.defult the ip based learned group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ip.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Host:  as group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"Host:1.2.3.4\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Workload:  as group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"Workload:1.2.3.4\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// PolicyMode need bu Protect/Moinitor/Discover

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect3\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	//
	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default1\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	{
		//---
		errCountExpected := []int{1, 1, 1, 1, 1, 1, 1, 1, 0, 0}
		raw_strings := []string{
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: test\n    criteria:\n    - name: pspCompliance\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: test\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      op: test\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      op: =\n      value: true\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    test:\n    - name: pspCompliance\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - test: pspCompliance\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      test: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      op: =\n      test: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  rules:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  ruled:\n  - action: deny\n    criteria:\n    - name: pspCompliance\n      op: =\n      value: \"true\"\n  - action: allow\n    criteria:\n    - name: namespace\n      op: containsAny\n      value: ns-1\n",
		}
		for idx, raw_string := range raw_strings {
			json_data, err := yaml.YAMLToJSON([]byte(raw_string))
			if err != nil {
				if idx != 4 {
					t.Errorf("[admission rules: %d] yaml error\n %v", idx, err)
				}
			} else {
				var admCtrlSecRule api.NvAdmCtrlSecurityRule
				if err = json.Unmarshal(json_data, &admCtrlSecRule); err != nil {
					if errCountExpected[idx] == 0 {
						t.Errorf("[admission rules: %d] unmarshal error\n %v", idx, err)
					}
				} else {
					crdHandler.mdName = admCtrlSecRule.GetName()
					_, errCount, err, _ := crdHandler.parseCurCrdAdmCtrlContent(&admCtrlSecRule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
					if errCount != errCountExpected[idx] {
						t.Errorf("[admission rules: %d] %d parse error, %d parse error expected\n %v", idx, errCount, errCountExpected[idx], err)
					}
				}
			}
		}
	}

	//---
	{
		errCountExpected := []int{0, 0, 0, 0, 1, 1, 1, 1, 1, 1}
		raw_strings := []string{
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  test:\n    client_mode: service\n    enable: true\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: test\nspec:\n  config:\n    client_mode: service\n    enable: true\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: service\n    enable: true\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: test\n    enable: true\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: service\n    enable: test\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: service\n    enable: true\n    mode: test\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    enable: true\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: service\n    mode: protect\n",
			"apiVersion: neuvector.com/v1\nkind: NvAdmissionControlSecurityRule\nmetadata:\n  name: local\nspec:\n  config:\n    client_mode: service\n    enable: true\n",
		}
		for idx, raw_string := range raw_strings {
			json_data, err := yaml.YAMLToJSON([]byte(raw_string))
			if err != nil {
				t.Errorf("[admission config: %d] yaml error\n %v", idx, err)
			} else {
				var admCtrlSecRule api.NvAdmCtrlSecurityRule
				if err = json.Unmarshal(json_data, &admCtrlSecRule); err != nil {
					if errCountExpected[idx] == 0 {
						t.Errorf("[admission config: %d] unmarshal error\n %v", idx, err)
					}
				} else {
					crdHandler.mdName = admCtrlSecRule.GetName()
					_, errCount, err, _ := crdHandler.parseCurCrdAdmCtrlContent(&admCtrlSecRule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
					if errCount != errCountExpected[idx] {
						t.Errorf("[admission config: %d] %d parse error, %d parse error expected\n %v", idx, errCount, errCountExpected[idx], err)
					}
				}
			}
		}
	}

	postTest()
}

func TestParseCrdSecurityRuleGroupReferral(t *testing.T) {
	preTest()
	var raw_string, err string
	var raw []byte
	var errCount int
	var gfwrule api.NvSecurityRule

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey, importCallerRest)

	// all correct
	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount > 0 {
		t.Errorf("0 parse error\n %v", err)
	}
	// get service name different than criteria service value "ubuntu1"
	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu1.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// operation should only be =

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"!="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// key value can't be empty or anything other than service/domain

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must be service or domain for nv

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"namespace","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must match domain value with name

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default1","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}
	// criteria self dumplicate for ubuntu_egress_rule

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu","op":"="},{"key":"lable","value":"alpine","op":"="},{"key":"domain","value":"alpine","op":"="},{"key":"domain","value":"default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	// same group with different criteria

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// policy name duplicate

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't use nv.ip.exc.defult the ip based learned group name

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ip.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Host:  as group name

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"Host:1.2.3.4","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Workload:  as group name

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"Workload:1.2.3.4","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// PolicyMode need bu Protect/Moinitor/Discover

	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default"},"spec":{"version":"v1","target":{"policymode":"Protect3","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	//
	raw_string = `{"apiVersion":"neuvector.com/v1","kind":"NvSecurityRule","metadata":{"name":"ubuntu","namespace":"default1"},"spec":{"version":"v1","target":{"policymode":"Protect","selector":{"name":"nv.ubuntu.default","criteria":[{"key":"service","value":"ubuntu.default","op":"="},{"key":"domain","value":"default","op":"="}]}},"ingress":[{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/2222","applications":["Apache","etcd"],"action":"deny","name":"nv.ubuntu.neuvector1"},{"selector":{"name":"nv.ubuntu.neuvector","criteria":[{"key":"service","value":"ubuntu.neuvector","op":"="},{"key":"domain","value":"neuvector","op":"="}]},"ports":"tcp/22","applications":["Apache"],"action":"allow","name":"nv.ubuntu.neuvector2"},{"selector":{"name":"nv.alpine.default","criteria":[{"key":"service","value":"alpine.default","op":"="},{"key":"domain","value":"default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu.neuvector3"}],"egress":[{"selector":{"name":"ubuntu_egress_rule","criteria":[{"key":"service","value":"ubuntu.default","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress1"},{"selector":{"name":"alpine_egress_rule","criteria":[{"key":"service","value":"alpine","op":"="}]},"ports":"tcp/22","action":"allow","name":"nv.ubuntu-egress2"}]}}`

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGfwContent(&gfwrule, nil, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	postTest()
}

type mockK8s struct {
	*resource.MockK8s
	crCache map[string]map[string]map[string]interface{} // rt -> ns -> name -> obj
}

func (d *mockK8s) GetResource(rt, namespace, name string) (interface{}, error) {
	switch rt {
	case resource.RscTypeCrdGroupDefinition:
		if nsToNameToObjs := d.crCache[rt]; nsToNameToObjs != nil {
			if nameToObjs := nsToNameToObjs[namespace]; nameToObjs != nil {
				if res := nameToObjs[name]; res != nil {
					return res, nil
				}
			}
		}
		return nil, common.ErrObjectNotFound
	}
	return nil, resource.ErrResourceNotSupported
}

func (d *mockK8s) AddResource(rt string, res interface{}) error {
	switch rt {
	case resource.RscTypeCrdGroupDefinition:
		if obj := res.(*api.NvGroupDefinition); obj != nil {
			if nsToNameToObjs := d.crCache[rt]; nsToNameToObjs != nil {
				if nameToObjs := nsToNameToObjs[obj.Namespace]; nameToObjs != nil {
					nameToObjs[obj.Name] = res
					return nil
				}
			}
		}
	}
	return resource.ErrResourceNotSupported
}

func (d *mockK8s) UpdateResource(rt string, res interface{}) error {
	switch rt {
	case resource.RscTypeCrdGroupDefinition:
		if obj := res.(*api.NvGroupDefinition); obj != nil {
			if nsToNameToObjs := d.crCache[rt]; nsToNameToObjs != nil {
				if nameToObjs := nsToNameToObjs[obj.Namespace]; nameToObjs != nil {
					nameToObjs[obj.Name] = res
					return nil
				}
			}
		}
		return common.ErrObjectNotFound
	}
	return resource.ErrResourceNotSupported
}

func (d *mockK8s) DeleteResource(rt string, res interface{}) error {
	switch rt {
	case resource.RscTypeCrdGroupDefinition:
		if obj := res.(*api.NvGroupDefinition); obj != nil {
			if nsToNameToObjs := d.crCache[rt]; nsToNameToObjs != nil {
				if nameToObjs := nsToNameToObjs[obj.Namespace]; nameToObjs != nil {
					if _, ok := nameToObjs[obj.Name]; ok {
						delete(nameToObjs, obj.Name)
						return nil
					}
				}
			}
		}
		return common.ErrObjectNotFound
	}
	return resource.ErrResourceNotSupported
}

func registerK8sForUT(platform, flavor, network string) orchAPI.ResourceDriver {
	k8sPlatform = true

	nameToObj := make(map[string]interface{})
	nsToNameToObj := make(map[string]map[string]interface{})
	nsToNameToObj[resource.NvAdmSvcNamespace] = nameToObj
	rtToNsToNameToObj := make(map[string]map[string]map[string]interface{})
	rtToNsToNameToObj[resource.RscTypeCrdGroupDefinition] = nsToNameToObj

	mock := &mockK8s{
		MockK8s: resource.NewMockKK8sDriver(platform, flavor, network),
		crCache: rtToNsToNameToObj,
	}

	return mock
}

func TestDoGroupReferral(t *testing.T) {
	preTest()

	global.SetPseudoOrchHub_UnitTest("pseudo_k8s", "", "1.24", "", registerK8sForUT)

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	group12 := share.CLUSGroup{
		Name:     "g-12",
		Criteria: []share.CLUSCriteriaEntry{{Key: "container", Op: "=", Value: "myServer12"}},
	}
	if err := clusHelper.PutGroup(&group12, true); err != nil {
		t.Logf("PutGroup(%s) failed: %s\n", group12.Name, err)
	}

	group13 := share.CLUSGroup{
		Name:     "g-13",
		Comment:  "original",
		Criteria: []share.CLUSCriteriaEntry{{Key: "container", Op: "=", Value: "myServer13"}},
	}
	if err := clusHelper.PutGroup(&group13, true); err != nil {
		t.Logf("PutGroup(%s) failed: %s\n", group12.Name, err)
	}

	var crdHandler nvCrdHandler
	crdHandler.Init("", importCallerK8s)

	{
		// 4 NvGroupDefinition items but only 1 is valid
		raw_string := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-1
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer12
      name: g-10
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-12
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer2002
      name: g-12
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-13
    namespace: neuvector
  spec:
    selector:
      comment: "comment-new-13"
      criteria:
      - key: container
        op: =
        value: myServer13
      name: g-13
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: nv.ip.kubernetes.default
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
        - key: address
          op: =
          value: 10.43.0.10
        - key: domain
          op: =
          value: default2
      name: nv.ip.kubernetes.default
kind: List
metadata: {}
`)

		if _, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[1] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 4 {
				t.Errorf("[1] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 4 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			} else {
				expectedErrCount := []int{1, 1, 0, 1}
				expectedErrMsg := []string{
					"CRD file format error:  mismatched name in selector and metadata g-1",
					"CRD Rule format error: Group g-12(in definition) has different criteria from existing group",
					"",
					"CRD Rule format error: Group nv.ip.kubernetes.default(in definition) validate error. Details: Learned group domain does not match between name and criteria(key: domain, value: default2)",
				}
				for i := range nvGrpDefs {
					_, errCount, errMsg, _ := crdHandler.parseCrdContent(api.NvGroupDefKind, &nvGrpDefs[i], nil)
					if errCount != expectedErrCount[i] || errMsg != expectedErrMsg[i] {
						t.Errorf("[1-%d] parseCrdContent(NvGroupDefKind): Incorrect parsing result", i)
						t.Logf("  Expect %d errors, msg: %s\n", expectedErrCount[i], expectedErrMsg[i])
						t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
					} else if errCount == 0 {
						// if no parsing error, simulating adding CR to k8s
						if err := global.ORCH.AddResource(resource.RscTypeCrdGroupDefinition, &nvGrpDefs[i]); err != nil {
							t.Logf("AddResource(%v) failed: %s\n", nvGrpDefs[i], err)
						}
					}
				}
			}
		}
	}

	{
		// all correct: contains NvGroupDefinition, NvSecurityRule/NvClusterSecurityRule(no referral) for CRD import
		raw_string := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-1
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer12
      name: g-1
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-2
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer2
      name: g-2
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-3
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer3
      name: g-3
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-14
    namespace: neuvector
  spec:
    selector:
      comment: "comment-new-14"
      criteria:
      - key: container
        op: =
        value: myServer14
      name: g-14
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: nv.ip.kubernetes.default
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
        - key: address
          op: =
          value: 10.43.0.10
        - key: domain
          op: =
          value: default
      name: nv.ip.kubernetes.default
kind: List
metadata: {}
	
---
	
apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvSecurityRule
  metadata:
    name: nv.ip.kubernetes.default
    namespace: default
  spec:
    egress: []
    file: []
    ingress:
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-0
      ports: any
      priority: 0
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer
        name: g-1
        original_name: ""
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-1
      ports: any
      priority: 0
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer2
        name: g-1-192398063-2
        original_name: ""
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: address
          op: =
          value: 10.43.0.1
        - key: domain
          op: =
          value: default
        name: nv.ip.kubernetes.default
        original_name: ""
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    dlp:
      settings: []
      status: true
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer2
        name: g-1
        original_name: ""
    waf:
      settings: []
      status: true
kind: List
metadata: {}
`)

		if secRules, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[2] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 5 {
				t.Errorf("[2] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 5 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			} else {
				for i := range nvGrpDefs {
					_, errCount, errMsg, _ := crdHandler.parseCrdContent(api.NvGroupDefKind, &nvGrpDefs[i], nil)
					if errCount > 0 && !strings.HasSuffix(errMsg, " is not found") {
						t.Errorf("[2-%d] parseCrdContent(NvGroupDefKind) error\n %v", i, errMsg)
					} else {
						// if no parsing error, simulating adding CR to k8s
						if err := global.ORCH.AddResource(resource.RscTypeCrdGroupDefinition, &nvGrpDefs[i]); err != nil {
							t.Logf("AddResource(%v) failed: %s\n", nvGrpDefs[i], err)
						}
					}
				}
			}

			if len(secRules) != 2 {
				t.Errorf("[2] parseGroupYamlFile: Incorrect number of valid NvSecurityRule/NvClusterSecurityRule yaml docs.")
				t.Logf("  Expect 2 items\n")
				t.Logf("  Actual %d items\n", len(secRules))
			} else {
				nvSecurityRules := 0
				nvClusterSecurityRules := 0
				expectedGroupCfgsNumber := []int{3, 1}
				for _, r := range secRules {
					if r.Kind == "NvSecurityRule" {
						nvSecurityRules++
					} else if r.Kind == "NvClusterSecurityRule" {
						nvClusterSecurityRules++
					}
				}
				if nvSecurityRules != 1 {
					t.Errorf("[2] parseGroupYamlFile: Incorrect number of valid NvSecurityRule yaml docs.")
					t.Logf("  Expect 1 items\n")
					t.Logf("  Actual %d items\n", nvSecurityRules)
				}
				if nvClusterSecurityRules != 1 {
					t.Errorf("[2] parseGroupYamlFile: Incorrect number of valid NvClusterSecurityRule yaml docs.")
					t.Logf("  Expect 1 items\n")
					t.Logf("  Actual %d items\n", nvClusterSecurityRules)
				}

				for i := range secRules {
					crdCfgRet, errCount, errMsg, _ := crdHandler.parseCrdContent(api.NvSecurityRuleKind, &secRules[i], nil)
					if errCount > 0 {
						t.Errorf("[2-%d] parseCrdContent(NvSecurityRuleKind) error\n %v", i, errMsg)
					} else {
						if len(crdCfgRet.GroupCfgs) != expectedGroupCfgsNumber[i] {
							t.Errorf("[2] parseCrdContent(NvSecurityRuleKind): Incorrect number of GroupCfgs.")
							t.Logf("  Expect %d groups\n", expectedGroupCfgsNumber[i])
							t.Logf("  Actual %d groups\n", len(crdCfgRet.GroupCfgs))
						}
					}
				}
			}
		}

		{
			// contains NvSecurityRule/NvClusterSecurityRule(with referral) for CRD import
			// however, referred NvGroupDefinition CR g-1-192398063-2 is not found in mock-k8s &
			//	refered NvGroupDefinition CR g-2 has different criteria from group g-2 in kv
			raw_string := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvSecurityRule
  metadata:
    name: nv.ip.kubernetes.default
    namespace: default
  spec:
    egress: []
    file: []
    ingress:
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-0
      ports: any
      priority: 0
      selector:
        name_referral: true
        name: g-1
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-1
      ports: any
      priority: 0
      selector:
        name_referral: true
        name: g-1-192398063-2
    process: []
    target:
      policymode: N/A
      selector:
        name_referral: true
        name: nv.ip.kubernetes.default
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-2
  spec:
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        name_referral: true
        name: g-2
kind: List
metadata: {}
`)

			// let CR NvGroupDefKind g-2 has different criteria from group g-2 in kv
			group2 := share.CLUSGroup{
				Name:     "g-2",
				Criteria: []share.CLUSCriteriaEntry{{Key: "container", Op: "=", Value: "myServer2-unexpected"}},
			}
			if err := clusHelper.PutGroup(&group2, true); err != nil {
				t.Logf("PutGroup(%s) failed: %s\n", group2.Name, err)
			}

			if secRules, _, err := parseGroupYamlFile(raw_string); err != nil {
				t.Errorf("[3] parseGroupYamlFile failed: %s. Expect success", err)
			} else {
				expectedErrorCount := []int{1, 1}
				expectedErrorMsg := []string{
					"CRD Rule format error: NvGroupDefinition of referred group g-1-192398063-2 is not found",
					"CRD Rule format error: Group g-2(in nvgroupdefinitions CR) has different criteria from existing group",
				}
				for i := range secRules {
					_, errCount, errMsg, _ := crdHandler.parseCrdContent(api.NvSecurityRuleKind, &secRules[i], nil)
					if errCount != expectedErrorCount[i] || errMsg != expectedErrorMsg[i] {
						t.Errorf("[3-%d] parseCrdContent(NvSecurityRuleKind): Incorrect parsing result", i)
						t.Logf("  Expect %d errors, msg: %s\n", expectedErrorCount[i], expectedErrorMsg[i])
						t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
					}
				}
			}
		}
	}

	{
		// should fail when try to create a group that the same-name NvGroupDefKind CR exists but has different criteria
		conf := api.RESTGroupConfig{Name: "g-14", Criteria: &[]api.RESTCriteriaEntry{{Key: "label/key", Value: "label/value", Op: "="}}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)
		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("[4-1] Create group: Status %v is not expected.", w.status)
		}

		// should succeed when try to create a group that the same-name NvGroupDefKind CR exists and has same criteria
		conf = api.RESTGroupConfig{Name: "g-14", Criteria: &[]api.RESTCriteriaEntry{{Key: "container", Value: "myServer14", Op: "="}}}
		data = api.RESTGroupConfigData{Config: &conf}
		body, _ = json.Marshal(data)
		w = restCall("POST", "/v1/group", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("[4-2] Create group: Status %v is not expected.", w.status)
		}

		// should fail when try to update an existing group to different criteria from the same-name NvGroupDefKind CR's criteria
		conf = api.RESTGroupConfig{Name: "g-43", Criteria: &[]api.RESTCriteriaEntry{{Key: "container", Value: "myServer-14001", Op: "="}}}
		data = api.RESTGroupConfigData{Config: &conf}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/group/g-13", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("[4-3] Update group: Status %v is not expected.", w.status)
		}
	}

	{
		// NvGroupDefinition g-1 in the yaml is invalid
		raw_string := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-1
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer101
      name: g-2
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: nv.ip.kubernetes.default
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
        - key: address
          op: =
          value: 10.43.0.10
        - key: domain
          op: =
          value: default
      name: nv.ip.kubernetes.default
kind: List
metadata: {}
	
---
	
apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer1
        name: g-1
        original_name: ""
kind: List
metadata: {}
`)

		var crdHandler2 nvCrdHandler
		crdHandler2.Init("", importCallerRest)

		if _, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[5] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 2 {
				t.Errorf("[5] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 2 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			} else {
				for i := range nvGrpDefs {
					expectedErrCount := []int{1, 0}
					expectedErrMsg := []string{"CRD file format error:  mismatched name in selector and metadata g-1", ""}
					_, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvGroupDefKind, &nvGrpDefs[i], nil)
					if errCount != expectedErrCount[i] || errMsg != expectedErrMsg[i] {
						t.Errorf("[5-%d] parseCrdContent(NvGroupDefKind): Incorrect parsing result", i)
						t.Logf("  Expect %d errors, msg: %s\n", expectedErrCount[i], expectedErrMsg[i])
						t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
					}
				}
			}
		}

		// NvGroupDefinition g-1 in the yaml has different criteria from the same-name NvGroupDefKind CR's criteria
		raw_string = []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-1
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer101
      name: g-1
kind: List
metadata: {}
	
---
	
apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer1
        name: g-1
        original_name: ""
kind: List
metadata: {}
`)

		if _, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[6] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 1 {
				t.Errorf("[6] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 1 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			} else {
				for i := range nvGrpDefs {
					expectedErrCount := []int{1}
					expectedErrMsg := []string{"CRD Rule format error: NvGroupDefinition CR g-1 with different criteria exists in k8s"}
					_, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvGroupDefKind, &nvGrpDefs[i], nil)
					if errCount != expectedErrCount[i] || errMsg != expectedErrMsg[i] {
						t.Errorf("[6-%d] parseCrdContent(NvGroupDefKind): Incorrect parsing result", i)
						t.Logf("  Expect %d errors, msg: %s\n", expectedErrCount[i], expectedErrMsg[i])
						t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
					}
				}
			}
		}

		// the referred NvGroupDefinition g-1 is found in k8s(CR)
		raw_string = []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        name_referral: true
        name: g-1
kind: List
metadata: {}
`)

		if secRules, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[7] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 0 {
				t.Errorf("[7] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 0 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			}
			if len(secRules) != 1 {
				t.Errorf("[7] parseGroupYamlFile: Incorrect number of valid NvClusterSecurityRule yaml docs.")
				t.Logf("  Expect 1 items\n")
				t.Logf("  Actual %d items\n", len(secRules))
			} else {
				crdCfgRet, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvSecurityRuleKind, &secRules[0], nil)
				if errCount > 0 {
					t.Errorf("[7] parseCrdContent(NvSecurityRuleKind): Incorrect parsing result")
					t.Logf("  Expect 0 errors\n")
					t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
				} else if len(crdCfgRet.GroupCfgs) != 1 {
					t.Errorf("[7] parseCrdContent(NvSecurityRuleKind): Incorrect number of GroupCfgs.")
					t.Logf("  Expect 1 groups\n")
					t.Logf("  Actual %d groups\n", len(crdCfgRet.GroupCfgs))
				} else {
					// if no parsing error, simulating reading CR from k8s
					if obj, err := global.ORCH.GetResource(resource.RscTypeCrdGroupDefinition, resource.NvAdmSvcNamespace, "g-1"); err == nil {
						if o, ok := obj.(*api.NvGroupDefinition); ok {
							// expectedCriteria := api.RESTCriteriaEntry{Key: "container", Op: "=", Value: "myServer12"}
							if crdCfgRet.GroupCfgs[0].Comment != o.Spec.Selector.Comment ||
								!common.SameGroupCriteria(crdCfgRet.GroupCfgs[0].Criteria, o.Spec.Selector.Criteria, false) ||
								len(crdCfgRet.GroupCfgs[0].Criteria) == 0 {
								t.Errorf("[7] parseCrdContent(NvSecurityRuleKind): unexpected refered group result")
								t.Logf("  Expect criteria: %v, comment: %s\n", o.Spec.Selector.Criteria, o.Spec.Selector.Comment)
								t.Logf("  Actual criteria: %v, comment: %s\n", crdCfgRet.GroupCfgs[0].Criteria, crdCfgRet.GroupCfgs[0].Comment)
							}
						} else {
							t.Errorf("[7] parseCrdContent(NvSecurityRuleKind): unexpected referral processing result: %s", err)
						}
					} else {
						t.Errorf("[7] parseCrdContent(NvSecurityRuleKind): unexpected referral result")
						t.Logf("  Expect a failed referral\n")
						t.Logf("  Actual target group g-1 is referred to %s\n", crdCfgRet.GroupCfgs[0].Name)
					}
				}
			}
		}
	}

	{
		var crdHandler2 nvCrdHandler
		crdHandler2.Init("", importCallerRest)

		// the referred NvGroupDefinition g-1 is found in k8s(CR) but CR has different criteria from existing group in kv
		raw_string := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        name_referral: true
        name: g-1
kind: List
metadata: {}
`)

		group1 := share.CLUSGroup{
			Name:     "g-1",
			Criteria: []share.CLUSCriteriaEntry{{Key: "container", Op: "=", Value: "myServer1999"}},
		}
		if err := clusHelper.PutGroup(&group1, false); err != nil {
			t.Logf("PutGroup(%s) failed: %s\n", group1.Name, err)
		}

		if secRules, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[8] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			if len(nvGrpDefs) != 0 {
				t.Errorf("[8] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 0 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			}
			if len(secRules) != 1 {
				t.Errorf("[8] parseGroupYamlFile: Incorrect number of valid NvClusterSecurityRule yaml docs.")
				t.Logf("  Expect 1 items\n")
				t.Logf("  Actual %d items\n", len(secRules))
			} else {
				_, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvSecurityRuleKind, &secRules[0], nil)
				if errCount == 0 {
					t.Errorf("[8] parseCrdContent(NvSecurityRuleKind): Incorrect parsing result")
					t.Logf("  Expect 1 errors\n")
					t.Logf("  Actual 0 errors\n")
				} else {
					expectedMsg := "CRD Rule format error: Group g-1(in nvgroupdefinitions CR) has different criteria from existing group"
					if errMsg != expectedMsg {
						t.Errorf("[8] parseCrdContent(NvSecurityRuleKind): Incorrect refered result")
						t.Logf("  Expect %s error\n", expectedMsg)
						t.Logf("  Actual %s error\n", errMsg)
					}
				}
			}
		}
	}

	{
		var crdHandler2 nvCrdHandler
		crdHandler2.Init("", importCallerRest)

		// the referred group g-1 is found in the same yaml but it has different criteria from existing group in kv
		raw_string := []byte(`apiVersion: neuvector.com/v1
kind: NvGroupDefinition
metadata:
  name: g-1
  namespace: neuvector
spec:
  selector:
    comment: "10101"
    criteria:
    - key: container
      op: =
      value: myServer10101
    name: g-1

---

apiVersion: neuvector.com/v1
kind: NvClusterSecurityRule
metadata:
  name: g-1
spec:
  egress: []
  file: []
  ingress: []
  process: []
  target:
    policymode: N/A
    selector:
      name_referral: true
      name: g-1
`)

		{
			apiversion := fmt.Sprintf("%s/%s", common.OEMClusterSecurityRuleGroup, api.NvGroupDefVersion)
			nvGrpDefItem := api.NvGroupDefinition{
				TypeMeta: metav1.TypeMeta{
					Kind:       api.NvGroupDefKind,
					APIVersion: apiversion,
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: resource.NvAdmSvcNamespace,
					Name:      "g-1",
				},
			}
			if err := global.ORCH.DeleteResource(resource.RscTypeCrdGroupDefinition, &nvGrpDefItem); err != nil {
				t.Logf("  global.ORCH.DeleteResource(%v) failed(%s)\n", nvGrpDefItem, err)
			}
		}

		// group g-1 criteria in kv = api.RESTCriteriaEntry{Key: "container", Op: "=", Value: "myServer1999"}
		if secRules, nvGrpDefs, err := parseGroupYamlFile(raw_string); err != nil {
			t.Errorf("[9] parseGroupYamlFile failed: %s. Expect success", err)
		} else {
			parsedGrpDefs := make(map[string]*api.NvSecurityParse)
			if len(nvGrpDefs) != 1 {
				t.Errorf("[9] parseGroupYamlFile: Incorrect number of valid NvGroupDefinition yaml docs.")
				t.Logf("  Expect 1 items\n")
				t.Logf("  Actual %d items\n", len(nvGrpDefs))
			} else {
				for i := range nvGrpDefs {
					//_, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvGroupDefKind, &nvGrpDefs[i], nil)
					grpDefRet, errCount, errMsg := crdHandler2.parseCurCrdGrpDefContent(&nvGrpDefs[i], share.ReviewTypeImportGroup, share.ReviewTypeDisplayGroup)
					expectedErrCount := 1
					expectedMsg := "Group Policy Rule format error: Group g-1(in definition) has different criteria from existing group"
					if errCount != expectedErrCount || errMsg != expectedMsg {
						t.Errorf("[1-%d] parseCrdContent(NvGroupDefKind): Incorrect parsing result", i)
						t.Logf("  Expect %d errors, msg: %s\n", expectedErrCount, expectedMsg)
						t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
					} else if grpDefRet != nil {
						parsedGrpDefs[grpDefRet.TargetName] = grpDefRet
					}
				}
				crdHandler2.grpDefsInSameYaml = parsedGrpDefs
			}

			if len(secRules) != 1 {
				t.Errorf("[9] parseGroupYamlFile: Incorrect number of valid NvClusterSecurityRule yaml docs.")
				t.Logf("  Expect 1 items\n")
				t.Logf("  Actual %d items\n", len(secRules))
			} else {
				_, errCount, errMsg, _ := crdHandler2.parseCrdContent(api.NvSecurityRuleKind, &secRules[0], nil)
				if errCount == 0 {
					expectedErrCount := 1
					expectedMsg := "CRD Rule format error: NvGroupDefinition of referred group g-1 is not found"
					t.Errorf("[9] parseCrdContent(NvSecurityRuleKind): Incorrect parsing result")
					t.Logf("  Expect %d errors, msg: %s\n", expectedErrCount, expectedMsg)
					t.Logf("  Actual %d errors, msg: %s\n", errCount, errMsg)
				}
			}
		}
	}

	postTest()
}
