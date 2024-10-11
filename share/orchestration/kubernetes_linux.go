package orchestration

import (
	"strings"
)

func (d *kubernetes) isTunnelInterface(name, kind string) bool {
	// OpenShift: tun0; calico: tunl0
	// OpenShift: openvswitch; calico: ipip
	if (strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "ovn")) && (kind == "ipip" || kind == "openvswitch") {
		return true
	}
	//antreaCNI's antrea-gw0 i/f
	if strings.HasPrefix(name, "antrea") && kind == "openvswitch" {
		return true
	}
	// flannel.1
	if strings.HasPrefix(name, "flannel") && kind == "vxlan" {
		return true
	}
	// cilium_vxlan
	if strings.HasPrefix(name, "cilium") && kind == "vxlan" {
		return true
	}
	//vxlan.calico i/f is transparent to user so we won't see
	//workload:ingress as source although it is still act as
	//a tunnel i/f
	if strings.HasSuffix(name, "calico") && kind == "vxlan" {
		return true
	}
	if strings.HasPrefix(name, "cni") {
		return true
	}
	// weave: linux bridge port
	if name == "weave" {
		return true
	}
	// azure AKS
	if name == "cbr0" && kind == "bridge" {
		return true
	}
	//kube-router CNI
	if name == "kube-bridge" && kind == "bridge" {
		return true
	}
	//NVSHAS-5338, ubuntu with containerd in gke set up
	//has veth interface work as ingress, need to add
	//veth's ip as tunnel ip
	if kind == "veth" {
		return true
	}
	return false
}
