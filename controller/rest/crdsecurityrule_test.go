package rest

import (
	"encoding/json"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"testing"
    "sigs.k8s.io/yaml"
)

func TestParseCrdSecurityRule(t *testing.T) {
	preTest()
	var raw_string, err string
	var raw []byte
	var errCount int
	var gfwrule resource.NvSecurityRule

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey)

	// all correct
	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
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
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// operation should only be =

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"!=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// key value can't be empty or anything other than service/domain

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must be service or domain for nv

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"namespace\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}

	// must match domain value with name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default1\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("1 parse error\n %v", err)
	}
	// criteria self dumplicate for ubuntu_egress_rule

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu\",\"op\":\"=\"},{\"key\":\"lable\",\"value\":\"alpine\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"alpine\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	// same group with different criteria

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// policy name duplicate

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't use nv.ip.exc.defult the ip based learned group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ip.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Host:  as group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"Host:1.2.3.4\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// can't user Workload:  as group name

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"Workload:1.2.3.4\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"
	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}

	// PolicyMode need bu Protect/Moinitor/Discover

	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect3\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
	if errCount != 1 {
		t.Errorf("0 parse error\n %v", err)
	}
	//
	raw_string = "{\"apiVersion\":\"neuvector.com/v1\",\"kind\":\"NvSecurityRule\",\"metadata\":{\"name\":\"ubuntu\",\"namespace\":\"default1\"},\"spec\":{\"version\":\"v1\",\"target\":{\"policymode\":\"Protect\",\"selector\":{\"name\":\"nv.ubuntu.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]}},\"ingress\":[{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/2222\",\"applications\":[\"Apache\",\"etcd\"],\"action\":\"deny\",\"name\":\"nv.ubuntu.neuvector1\"},{\"selector\":{\"name\":\"nv.ubuntu.neuvector\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.neuvector\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"neuvector\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"applications\":[\"Apache\"],\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector2\"},{\"selector\":{\"name\":\"nv.alpine.default\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine.default\",\"op\":\"=\"},{\"key\":\"domain\",\"value\":\"default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu.neuvector3\"}],\"egress\":[{\"selector\":{\"name\":\"ubuntu_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"ubuntu.default\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress1\"},{\"selector\":{\"name\":\"alpine_egress_rule\",\"criteria\":[{\"key\":\"service\",\"value\":\"alpine\",\"op\":\"=\"}]},\"ports\":\"tcp/22\",\"action\":\"allow\",\"name\":\"nv.ubuntu-egress2\"}]}}"

	raw = []byte(raw_string)
	if err := json.Unmarshal(raw, &gfwrule); err != nil {
		t.Errorf("0 parse error\n %v", err)

	}
	_, errCount, err, _ = crdHandler.parseCurCrdGroupContent(&gfwrule, share.ReviewTypeCRD, share.ReviewTypeDisplayCRD)
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
				var admCtrlSecRule resource.NvAdmCtrlSecurityRule
				if err = json.Unmarshal(json_data, &admCtrlSecRule); err != nil {
					if errCountExpected[idx] == 0 {
						t.Errorf("[admission rules: %d] unmarshal error\n %v", idx, err)
					}
				} else {
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
				var admCtrlSecRule resource.NvAdmCtrlSecurityRule
				if err = json.Unmarshal(json_data, &admCtrlSecRule); err != nil {
					if errCountExpected[idx] == 0 {
						t.Errorf("[admission config: %d] unmarshal error\n %v", idx, err)
					}
				} else {
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
