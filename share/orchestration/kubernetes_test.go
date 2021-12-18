package orchestration

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

func TestKubeProxy(t *testing.T) {
	var driver kubernetes

	wl := share.CLUSWorkload{
		Labels: map[string]string{
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.pod.name":       "kube-proxy-xmk89",
			"io.kubernetes.pod.namespace":  "kube-system",
			"k8s-app":                      "kube-proxy",
		},
	}

	if !driver.isKubeProxy(&wl) {
		t.Errorf("Unable to ignore kube-proxy pod\n")
	}

	wl = share.CLUSWorkload{
		Labels: map[string]string{
			"io.kubernetes.container.name": "kube-proxy",
			"io.kubernetes.pod.name":       "kube-proxy-xmk89",
			"io.kubernetes.pod.namespace":  "kube-system",
		},
	}

	if !driver.isKubeProxy(&wl) {
		t.Errorf("Unable to ignore kube-proxy container\n")
	}
}

func TestKubeRancherImportService(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes, flavor: share.FlavorRancher}}

	meta := container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-06T15:23:48.20639067-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"DaemonSet\",\"namespace\":\"cattle-system\",\"name\":\"rancher-agent\",\"uid\":\"05d4b5df-aae5-11e7-8f44-0050568f0af6\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"8691739\"}}\n",
			"app": "rancher",
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.docker.type":    "podsandbox",
			"io.kubernetes.pod.name":       "rancher-agent-hsn6q",
			"io.kubernetes.pod.namespace":  "cattle-system",
			"io.kubernetes.pod.uid":        "05dda62e-aae5-11e7-8f44-0050568f0af6",
			"pod-template-generation":      "1",
			"type": "agent",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "cattle-system" || svc.Name != "rancher-agent" {
		t.Errorf("Invalid service for Rancher agent container: %+v\n", svc)
	}

	meta = container.ContainerMeta{
		Labels: map[string]string{
			"08cd1981": "15815710",
			"095e01a0": "4b702ddb",
			"49fc8029": "6b9950b2",
			"4fd2623f": "829e433d",
			"767a3995": "d3f8e337",
			"9a730256": "b76e98af",
			"a4476fd9": "b326b506",
			"annotation.io.rancher.container.agent_service.metadata": "true",
			"annotation.io.rancher.container.create_agent":           "true",
			"annotation.io.rancher.container.name":                   "core-services-metadata-1",
			"annotation.io.rancher.container.orchestration":          "kubernetes",
			"annotation.io.rancher.container.uuid":                   "0655f435-2ebb-49c9-aba2-d0d67cf9c9cd",
			"annotation.io.rancher.scheduler.global":                 "true",
			"annotation.io.rancher.service.deployment.unit":          "d5263c8e-fa6d-4654-8c56-df3ee6dbc3f5",
			"annotation.io.rancher.service.launch.config":            "io.rancher.service.primary.launch.config",
			"annotation.io.rancher.stack.name":                       "core-services",
			"annotation.io.rancher.stack_service.name":               "core-services/metadata",
			"annotation.kubernetes.io/config.seen":                   "2017-10-06T15:28:34.474367231-07:00",
			"annotation.kubernetes.io/config.source":                 "api",
			"b8cdf14a":                     "b326b506",
			"e91f139c":                     "16c0853b",
			"ee9e0a9c":                     "b326b506",
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.docker.type":    "podsandbox",
			"io.kubernetes.pod.name":       "core-services-metadata-1-d5263c8e",
			"io.kubernetes.pod.namespace":  "cattle-system",
			"io.kubernetes.pod.uid":        "b0922ee8-aae5-11e7-8f44-0050568f0af6",
			"io.rancher.container.primary": "core-services-metadata-1-0655f435-2ebb-49c9-aba2-d0d67cf9c9cd",
			"io.rancher.deployment.uuid":   "d5263c8e-fa6d-4654-8c56-df3ee6dbc3f5",
			"io.rancher.revision":          "de7cf8b570d98c6fc1c3b51befcaa25c",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "cattle-system" || svc.Name != "core-services-metadata" {
		t.Errorf("Invalid service for Rancher metadata container: %+v\n", svc)
	}
}

func TestKubeService(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes, flavor: share.FlavorRancher}}

	meta := container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-13T16:10:23.185985906-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"default\",\"name\":\"httpserver-pod-20-69c86db9fb\",\"uid\":\"b09164ac-b06b-11e7-b2c8-0050568f6596\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"28356\"}}\n",
			"io.kubernetes.container.name":           "POD",
			"io.kubernetes.docker.type":              "podsandbox",
			"io.kubernetes.pod.name":                 "httpserver-pod-20-69c86db9fb-vnjbl", // 10-digit hash
			"io.kubernetes.pod.namespace":            "default",
			"io.kubernetes.pod.uid":                  "b0ba11d0-b06b-11e7-b2c8-0050568f6596",
			"name":                                   "httpserver-pod-20",
			"pod-template-hash":                      "69c86db9fb",
		},
	}

	if svc := driver.GetService(&meta); svc.Name != "httpserver-pod-20" {
		t.Errorf("Invalid service name with matching hash: %+v\n", svc.Name)
	}

	meta = container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-13T16:10:23.185985906-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"default\",\"name\":\"httpserver-pod-20-69c86db9fb\",\"uid\":\"b09164ac-b06b-11e7-b2c8-0050568f6596\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"28356\"}}\n",
			"io.kubernetes.container.name":           "POD",
			"io.kubernetes.docker.type":              "podsandbox",
			"io.kubernetes.pod.name":                 "httpserver-pod-20-9c86db9fb-vnjbl", // 9-digit hash
			"io.kubernetes.pod.namespace":            "default",
			"io.kubernetes.pod.uid":                  "b0ba11d0-b06b-11e7-b2c8-0050568f6596",
			"name":                                   "httpserver-pod-20",
			"pod-template-hash":                      "69c86db9fb",
		},
	}

	if svc := driver.GetService(&meta); svc.Name != "httpserver-pod-20" {
		t.Errorf("Invalid service name with matching hash: %+v\n", svc.Name)
	}

	meta = container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-13T16:10:23.185985906-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"default\",\"name\":\"httpserver-pod-20-69c86db9fb\",\"uid\":\"b09164ac-b06b-11e7-b2c8-0050568f6596\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"28356\"}}\n",
			"io.kubernetes.container.name":           "POD",
			"io.kubernetes.docker.type":              "podsandbox",
			"io.kubernetes.pod.name":                 "httpserver-pod-20-69c86db9fb-vnjbl",
			"io.kubernetes.pod.namespace":            "default",
			"io.kubernetes.pod.uid":                  "b0ba11d0-b06b-11e7-b2c8-0050568f6596",
			"name":                                   "httpserver-pod-20",
			"pod-template-hash":                      "2574286596",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "default" || svc.Name != "httpserver-pod-20" {
		t.Errorf("Invalid service name without matching hash: %+v\n", svc)
	}

	meta = container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-13T16:10:23.185985906-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"default\",\"name\":\"httpserver-pod-20-69c86db9fb\",\"uid\":\"b09164ac-b06b-11e7-b2c8-0050568f6596\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"28356\"}}\n",
			"io.kubernetes.container.name":           "POD",
			"io.kubernetes.docker.type":              "podsandbox",
			"io.kubernetes.pod.name":                 "calico-node-m308t",
			"io.kubernetes.pod.namespace":            "default",
			"io.kubernetes.pod.uid":                  "b0ba11d0-b06b-11e7-b2c8-0050568f6596",
			"name":                                   "httpserver-pod-20",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "default" || svc.Name != "calico-node" {
		t.Errorf("Invalid service name: %+v\n", svc)
	}

	meta = container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":                     "2018-08-14T08:25:04.351035995-07:00",
			"annotation.kubernetes.io/config.source":                   "api",
			"annotation.kubernetes.io/created-by":                      "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicationController\",\"namespace\":\"connectservices\",\"name\":\"update-traveler-service-89\",\"uid\":\"33631d5c-9fd6-11e8-84af-005056bc268b\",\"apiVersion\":\"v1\",\"resourceVersion\":\"134359560\"}}\n",
			"annotation.openshift.io/deployment-config.latest-version": "89",
			"annotation.openshift.io/deployment-config.name":           "update-traveler-service",
			"annotation.openshift.io/deployment.name":                  "update-traveler-service-89",
			"annotation.openshift.io/scc":                              "anyuid",
			"architecture":                                             "x86_64",
			"authoritative-source-url":                                 "registry.access.redhat.com",
			"build-date":                                               "2017-10-14T11:17:23.457439",
			"com.redhat.build-host":                                    "rcm-img-docker02.build.eng.bos.redhat.com",
			"com.redhat.component":                                     "openshift-enterprise-pod-docker",
			"deployment":                                               "update-traveler-service-89",
			"deploymentconfig":                                         "update-traveler-service",
			"io.kubernetes.container.name":                             "POD",
			"io.kubernetes.docker.type":                                "podsandbox",
			"io.kubernetes.pod.name":                                   "update-traveler-service-89-48w0g",
			"io.kubernetes.pod.namespace":                              "connectservices",
			"io.kubernetes.pod.uid":                                    "386905b7-9fd6-11e8-84af-005056bc268b",
			"io.openshift.tags":                                        "openshift,pod",
			"name":                                                     "openshift3/ose-pod",
			"release":                                                  "4",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "connectservices" || svc.Name != "update-traveler-service" {
		t.Errorf("Invalid service name: %+v\n", svc)
	}

	// IBM
	meta = container.ContainerMeta{
		Labels: map[string]string{
			"app": "ibm-kube-fluentd",
			"controller-revision-hash":    "3537260262",
			"io.cri-containerd.kind":      "sandbox",
			"io.kubernetes.pod.name":      "ibm-kube-fluentd-zq9dk",
			"io.kubernetes.pod.namespace": "kube-system",
			"io.kubernetes.pod.uid":       "636a2bbe-e835-11e8-993c-3e0defd6115f",
			"pod-template-generation":     "2",
		},
	}

	if svc := driver.GetService(&meta); svc.Domain != "kube-system" || svc.Name != "ibm-kube-fluentd" {
		t.Errorf("Invalid service name: %+v\n", svc)
	}
}

func TestScriptTemplate(t *testing.T) {
	var driver kubernetes
	var script bytes.Buffer

	test := map[string][]share.CLUSIPAddr{
		"veth1234": []share.CLUSIPAddr{
			share.CLUSIPAddr{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
		},
	}
	ret := `
#!/bin/sh

ovs-vsctl get port veth1234 name
if [ $? -eq 0 ]; then
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src=1.2.3.4
    ovs-vsctl --if-exists del-port veth1234
fi
`
	script.Reset()
	driver.createCleanupScript(&script, test)
	e := strings.TrimSpace(ret)
	r := strings.TrimSpace(script.String())
	if e != r {
		t.Errorf("Error: \nexpect=\n%v\nactual=\n%v\n", e, r)
	}

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": []share.CLUSIPAddr{
			share.CLUSIPAddr{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
			share.CLUSIPAddr{IPNet: net.IPNet{IP: net.IPv4(4, 3, 2, 1)}},
		},
	}
	ret = `
#!/bin/sh

ovs-vsctl get port veth1234 name
if [ $? -eq 0 ]; then
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src=4.3.2.1
    ovs-vsctl --if-exists del-port veth1234
fi
`
	script.Reset()
	driver.createCleanupScript(&script, test)
	e = strings.TrimSpace(ret)
	r = strings.TrimSpace(script.String())
	if e != r {
		t.Errorf("Error: \nexpect=\n%v\nactual=\n%v\n", e, r)
	}

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": []share.CLUSIPAddr{
			share.CLUSIPAddr{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
		},
		"veth4321": []share.CLUSIPAddr{
			share.CLUSIPAddr{IPNet: net.IPNet{IP: net.IPv4(4, 3, 2, 1)}},
		},
	}
	ret = `
#!/bin/sh

ovs-vsctl get port veth1234 name
if [ $? -eq 0 ]; then
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst=1.2.3.4
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src=1.2.3.4
    ovs-vsctl --if-exists del-port veth1234
fi

ovs-vsctl get port veth4321 name
if [ $? -eq 0 ]; then
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_dst=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 ip,nw_src=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_dst=4.3.2.1
    ovs-ofctl -O OpenFlow13 del-flows br0 arp,nw_src=4.3.2.1
    ovs-vsctl --if-exists del-port veth4321
fi
`
	script.Reset()
	driver.createCleanupScript(&script, test)
	e = strings.TrimSpace(ret)
	r = strings.TrimSpace(script.String())
	if e != r {
		t.Errorf("Error: \nexpect=\n%v\nactual=\n%v\n", e, r)
	}

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": []share.CLUSIPAddr{},
	}
	ret = `
#!/bin/sh

ovs-vsctl get port veth1234 name
if [ $? -eq 0 ]; then
    ovs-vsctl --if-exists del-port veth1234
fi
`
	script.Reset()
	driver.createCleanupScript(&script, test)
	e = strings.TrimSpace(ret)
	r = strings.TrimSpace(script.String())
	if e != r {
		t.Errorf("Error: \nexpect=\n%v\nactual=\n%v\n", e, r)
	}
}
