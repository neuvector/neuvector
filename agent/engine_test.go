package main

import (
	"testing"

	"github.com/neuvector/neuvector/share/utils"
)

// Runtime coverage of getPodDatapathChild:
//   - CRI-O 1.22+ with drop_infra_ctr=true (OpenShift 4.9+, Kubernetes 1.22+): the pod sandbox has
//     no infra container (pid 0), so the app children (hasDatapath) own the pod's interfaces.
//   - containerd 1.x/2.x and Docker (cri-dockerd), or CRI-O with drop_infra_ctr=false: the pause
//     container has a pid, so children never get hasDatapath and the callers never reach this path.
func TestGetPodDatapathChild(t *testing.T) {
	type child struct {
		id          string
		pid         int
		hasDatapath bool
		examIntface bool
		inactive    bool // stopped and already removed from activeContainers
	}

	cases := []struct {
		name     string
		children []child
		expect   string
	}{
		{
			name: "CRI-O 1.22+ (OpenShift 4.9+): owner is preferred over other app children",
			children: []child{
				{id: "app1", pid: 101, hasDatapath: true},
				{id: "app2", pid: 102, hasDatapath: true, examIntface: true},
				{id: "app3", pid: 103, hasDatapath: true},
			},
			expect: "app2",
		},
		{
			name: "CRI-O 1.22+ (OpenShift 4.9+): owner exited without handover target, fallback to running app child",
			children: []child{
				{id: "git-clone", pid: 0, hasDatapath: true, examIntface: true},
				{id: "docker-build", pid: 102, hasDatapath: true},
			},
			expect: "docker-build",
		},
		{
			name: "CRI-O 1.22+ (OpenShift 4.9+): owner already removed, fallback to running app child",
			children: []child{
				{id: "git-clone", pid: 101, hasDatapath: true, examIntface: true, inactive: true},
				{id: "docker-build", pid: 102, hasDatapath: true},
			},
			expect: "docker-build",
		},
		{
			name:     "CRI-O 1.22+ (OpenShift 4.9+): pod sandbox without any child",
			children: nil,
			expect:   "",
		},
		{
			name: "containerd 1.x/2.x, Docker, CRI-O drop_infra_ctr=false: children have no datapath",
			children: []child{
				{id: "app1", pid: 101, hasDatapath: false},
				{id: "app2", pid: 102, hasDatapath: false},
			},
			expect: "",
		},
	}

	saved := gInfo.activeContainers
	defer func() { gInfo.activeContainers = saved }()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gInfo.activeContainers = make(map[string]*containerData)
			pod := &containerData{id: "pod", pid: 0, pods: utils.NewSet()}
			gInfo.activeContainers[pod.id] = pod
			for _, ch := range tc.children {
				pod.pods.Add(ch.id)
				if ch.inactive {
					continue
				}
				gInfo.activeContainers[ch.id] = &containerData{
					id:          ch.id,
					pid:         ch.pid,
					parentNS:    pod.id,
					hasDatapath: ch.hasDatapath,
					examIntface: ch.examIntface,
					pods:        utils.NewSet(),
				}
			}

			got := ""
			if c := getPodDatapathChild(pod); c != nil {
				got = c.id
			}
			if got != tc.expect {
				t.Errorf("expect %q, got %q", tc.expect, got)
			}
		})
	}
}
