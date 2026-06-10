package orchestration

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.True(t, driver.isKubeProxy(&wl), "Unable to ignore kube-proxy pod")

	wl = share.CLUSWorkload{
		Labels: map[string]string{
			"io.kubernetes.container.name": "kube-proxy",
			"io.kubernetes.pod.name":       "kube-proxy-xmk89",
			"io.kubernetes.pod.namespace":  "kube-system",
		},
	}

	assert.True(t, driver.isKubeProxy(&wl), "Unable to ignore kube-proxy container")
}

func TestKubeRancherImportService(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes, flavor: share.FlavorRancher}}

	meta := container.ContainerMeta{
		Labels: map[string]string{
			"annotation.kubernetes.io/config.seen":   "2017-10-06T15:23:48.20639067-07:00",
			"annotation.kubernetes.io/config.source": "api",
			"annotation.kubernetes.io/created-by":    "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"DaemonSet\",\"namespace\":\"cattle-system\",\"name\":\"rancher-agent\",\"uid\":\"05d4b5df-aae5-11e7-8f44-0050568f0af6\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"8691739\"}}\n",
			"app":                                    "rancher",
			"io.kubernetes.container.name":           "POD",
			"io.kubernetes.docker.type":              "podsandbox",
			"io.kubernetes.pod.name":                 "rancher-agent-hsn6q",
			"io.kubernetes.pod.namespace":            "cattle-system",
			"io.kubernetes.pod.uid":                  "05dda62e-aae5-11e7-8f44-0050568f0af6",
			"pod-template-generation":                "1",
			"type":                                   "agent",
		},
	}

	svc := driver.GetService(&meta, "")
	assert.Equal(t, "cattle-system", svc.Domain, "Invalid service domain for Rancher agent container")
	assert.Equal(t, "rancher-agent", svc.Name, "Invalid service name for Rancher agent container")

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
			"b8cdf14a":                                               "b326b506",
			"e91f139c":                                               "16c0853b",
			"ee9e0a9c":                                               "b326b506",
			"io.kubernetes.container.name":                           "POD",
			"io.kubernetes.docker.type":                              "podsandbox",
			"io.kubernetes.pod.name":                                 "core-services-metadata-1-d5263c8e",
			"io.kubernetes.pod.namespace":                            "cattle-system",
			"io.kubernetes.pod.uid":                                  "b0922ee8-aae5-11e7-8f44-0050568f0af6",
			"io.rancher.container.primary":                           "core-services-metadata-1-0655f435-2ebb-49c9-aba2-d0d67cf9c9cd",
			"io.rancher.deployment.uuid":                             "d5263c8e-fa6d-4654-8c56-df3ee6dbc3f5",
			"io.rancher.revision":                                    "de7cf8b570d98c6fc1c3b51befcaa25c",
		},
	}

	svc = driver.GetService(&meta, "")
	assert.Equal(t, "cattle-system", svc.Domain, "Invalid service domain for Rancher metadata container")
	assert.Equal(t, "core-services-metadata", svc.Name, "Invalid service name for Rancher metadata container")
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

	assert.Equal(t, "httpserver-pod-20", driver.GetService(&meta, "").Name, "10-digit hash: service name")

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

	assert.Equal(t, "httpserver-pod-20", driver.GetService(&meta, "").Name, "9-digit hash: service name")

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

	svc := driver.GetService(&meta, "")
	assert.Equal(t, "default", svc.Domain, "non-matching hash: service domain")
	assert.Equal(t, "httpserver-pod-20", svc.Name, "non-matching hash: service name")

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

	svc = driver.GetService(&meta, "")
	assert.Equal(t, "default", svc.Domain, "calico-node: service domain")
	assert.Equal(t, "calico-node", svc.Name, "calico-node: service name")

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

	svc = driver.GetService(&meta, "")
	assert.Equal(t, "connectservices", svc.Domain, "OpenShift: service domain")
	assert.Equal(t, "update-traveler-service", svc.Name, "OpenShift: service name")

	// IBM
	meta = container.ContainerMeta{
		Labels: map[string]string{
			"app":                         "ibm-kube-fluentd",
			"controller-revision-hash":    "3537260262",
			"io.cri-containerd.kind":      "sandbox",
			"io.kubernetes.pod.name":      "ibm-kube-fluentd-zq9dk",
			"io.kubernetes.pod.namespace": "kube-system",
			"io.kubernetes.pod.uid":       "636a2bbe-e835-11e8-993c-3e0defd6115f",
			"pod-template-generation":     "2",
		},
	}

	svc = driver.GetService(&meta, "")
	assert.Equal(t, "kube-system", svc.Domain, "IBM: service domain")
	assert.Equal(t, "ibm-kube-fluentd", svc.Name, "IBM: service name")
}

func TestScriptTemplate(t *testing.T) {
	var driver kubernetes
	var script bytes.Buffer

	test := map[string][]share.CLUSIPAddr{
		"veth1234": {
			{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
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
	require.NoError(t, driver.createCleanupScript(&script, test))
	assert.Equal(t, strings.TrimSpace(ret), strings.TrimSpace(script.String()))

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": {
			{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
			{IPNet: net.IPNet{IP: net.IPv4(4, 3, 2, 1)}},
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
	require.NoError(t, driver.createCleanupScript(&script, test))
	assert.Equal(t, strings.TrimSpace(ret), strings.TrimSpace(script.String()))

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": {
			{IPNet: net.IPNet{IP: net.IPv4(1, 2, 3, 4)}},
		},
		"veth4321": {
			{IPNet: net.IPNet{IP: net.IPv4(4, 3, 2, 1)}},
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
	require.NoError(t, driver.createCleanupScript(&script, test))
	assert.Equal(t, strings.TrimSpace(ret), strings.TrimSpace(script.String()))

	// --
	test = map[string][]share.CLUSIPAddr{
		"veth1234": {},
	}
	ret = `
#!/bin/sh

ovs-vsctl get port veth1234 name
if [ $? -eq 0 ]; then
    ovs-vsctl --if-exists del-port veth1234
fi
`
	script.Reset()
	require.NoError(t, driver.createCleanupScript(&script, test))
	assert.Equal(t, strings.TrimSpace(ret), strings.TrimSpace(script.String()))
}

func TestKubeServiceName_nodename(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}

	// only review POD labels
	pod_meta := container.ContainerMeta{
		Labels: map[string]string{
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.pod.name":       "apiserver-watcher-qalongruncluster4oc4-kxq6x-master-2",
			"io.kubernetes.pod.namespace":  "kube-system",
			"io.kubernetes.pod.uid":        "64597f27342cf2be42d89a655c0999c6",
		},
	}

	assert.Equal(t, "apiserver-watcher", driver.GetService(&pod_meta, "qalongruncluster4oc4-kxq6x-master-2").Name)
}

func TestKubeServiceName_batchnumber_nodename(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}
	// only review POD labels
	pod_meta := container.ContainerMeta{
		Labels: map[string]string{
			"app":                          "installer",
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.pod.name":       "installer-5-qalongruncluster4oc4-kxq6x-master-2",
			"io.kubernetes.pod.namespace":  "openshift-kube-controller-manager",
			"io.kubernetes.pod.uid":        "fb1802db-5537-4a19-8dc4-ea0152d4c740",
		},
	}

	assert.Equal(t, "installer", driver.GetService(&pod_meta, "qalongruncluster4oc4-kxq6x-master-2").Name)
}

func TestIbmClusterID(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}

	// only review POD labels
	pod_meta := container.ContainerMeta{
		Labels: map[string]string{
			"razee.io/build-url":          "https://travis.ibm.com/alchemy-containers/armada-bom-component-source/builds/47666062",
			"io.cri-containerd.kind":      "sandbox",
			"io.kubernetes.pod.name":      "rbac-sync-operator-cdsi61j20equel7caka0-587b9d8b8f-rr6bw",
			"io.kubernetes.pod.uid":       "2acacc2a-d066-42bd-a414-12a81fead69e",
			"clusterID":                   "cdsi61j20equel7caka0",
			"io.cri-containerd.image":     "managed",
			"io.kubernetes.pod.namespace": "kubx-masters",
			"pod-template-hash":           "587b9d8b8f",
			"app":                         "rbac-sync-operator-cdsi61j20equel7caka0",
			"razee.io/source-url":         "https://github.ibm.com/alchemy-containers/armada-bom-component-source/commit/f986b086198c1f6810e54317d54a1d33376ef748",
		},
	}

	assert.Equal(t, "rbac-sync-operator", driver.GetService(&pod_meta, "").Name)
}

func TestUUIDSuffix(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}

	// only review POD labels
	pod_meta := container.ContainerMeta{
		Labels: map[string]string{
			"razee.io/build-url":          "https://travis.ibm.com/alchemy-containers/armada-bom-component-source/builds/47666062",
			"io.cri-containerd.kind":      "sandbox",
			"io.kubernetes.pod.name":      "kubx-deployer-d8d18cf7-5c9d-40ac-9489-271b13871ba7-xskjt",
			"io.kubernetes.pod.ui":        "daf74aaf9-06bc-40b7-9b74-12b19977830a",
			"image":                       "Tag1.24.8_1544",
			"clusterID":                   "cdubb8320c9l6joom9kg",
			"job-name":                    "kubx-deployer-d8d18cf7-5c9d-40ac-9489-271b13871ba7",
			"operation":                   "deploy",
			"controller-uid":              "a2189e25-8221-40c3-b85d-e848be5a74d8",
			"io.cri-containerd.image":     "managed",
			"io.kubernetes.pod.namespace": "kubx-deployer",
			"requestID":                   "d8d18cf7-5c9d-40ac-9489-271b13871ba7",
			"razee.io/source-url":         "https://github.ibm.com/alchemy-containers/armada-bom-component-source/commit/f986b086198c1f6810e54317d54a1d33376ef748",
		},
	}

	assert.Equal(t, "kubx-deployer", driver.GetService(&pod_meta, "").Name)
}

func TestKubxEtcdBackupApp(t *testing.T) {
	driver := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}

	// only review POD labels
	pod_meta := container.ContainerMeta{
		Labels: map[string]string{
			"app":                         "kubx-etcd-backup-update",
			"controller-uid":              "cc0f0c00-7ad7-4cac-b3f6-e5373ff0d4f1",
			"io.cri-containerd.image":     "managed",
			"io.cri-containerd.kind":      "sandbox",
			"io.kubernetes.pod.name":      "kubx-etcd-backup-cdsm1j9200g7nufcakcg-update-79444",
			"io.kubernetes.pod.namespace": "kubx-etcd-04",
			"io.kubernetes.pod.uid":       "e0302e7f-50e3-45bd-9707-1d39b041f3d4",
			"job-name":                    "kubx-etcd-backup-cdsm1j9200g7nufcakcg-update",
			"name":                        "kubx-etcd-backup-cdsm1j9200g7nufcakcg-update",
			"razee.io/build-url":          "https://travis.ibm.com/alchemy-containers/armada-bom-component-source/builds/47666062",
			"razee.io/source-url":         "https://github.ibm.com/alchemy-containers/armada-bom-component-source/commit/f986b086198c1f6810e54317d54a1d33376ef748",
		},
	}

	assert.Equal(t, "kubx-etcd-backup", driver.GetService(&pod_meta, "").Name)
}
