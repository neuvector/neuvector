package system

import (
	"io"
	"strings"
	"testing"
)

func TestDockerIDDebian(t *testing.T) {
	cgroup := `
10:net_prio:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
9:perf_event:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
8:blkio:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
7:net_cls:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
6:freezer:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
5:devices:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
4:memory:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
3:cpuacct:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
2:cpu:/4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970
`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "4f797c539e6c745de61a93ca3ff892358ecbcaccd8414d5db545c38428142970" {
		t.Errorf("Invalid Debian docker ID: %v\n", id)
	}
}

func TestDockerIDCentOS(t *testing.T) {
	cgroup := `
10:devices:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
9:blkio:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
8:memory:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
7:freezer:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
6:perf_event:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
5:hugetlb:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
4:net_cls:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
3:cpuset:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
2:cpuacct,cpu:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
1:name=systemd:/system.slice/docker-9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d.scope
`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "9ec39b91f3d70e1beff50a308f77067065ea6be0d91a3378375056cd4422cf3d" {
		t.Errorf("Invalid CentOS docker ID: %v\n", id)
	}
}

func TestDockerIDUbuntu(t *testing.T) {
	cgroup := `
12:name=systemd:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
11:hugetlb:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
10:net_prio:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
9:perf_event:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
8:blkio:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
7:net_cls:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
6:freezer:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
5:devices:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
4:memory:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
3:cpuacct:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
2:cpu:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
1:cpuset:/docker/31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30
`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "31cb02944da7a12196a193cf0e0f6c226d7c453a1db62e65ba98287593a2ee30" {
		t.Errorf("Invalid Ubuntu docker ID: %v\n", id)
	}
}

func TestDockerIDRancherOS(t *testing.T) {
	cgroup := `
9:name=systemd:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
8:memory:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
7:blkio:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
6:cpu,cpuacct:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
5:cpuset:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
4:perf_event:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
3:net_cls,net_prio:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
2:freezer:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
1:devices:/docker/a9a5ad238e59234193ee7ec3fcff5e735b3708ea1068826952255b69e3cfa413/docker/ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a
`
	r := strings.NewReader(cgroup)
	id, did, _, _ := getContainerIDByCgroupReader(r)
	if id != "ec08435e04266c5ba381fccbb829f626d11d8ddf5f8f547263c7a2d79ab4787a" {
		t.Errorf("Invalid RancherOS docker ID: %v\n", id)
	}
	if !did {
		t.Errorf("RancherOS docker-in-docker not recognized.\n")
	}
}

func TestDockerIDKubepods(t *testing.T) {
	cgroup := `
11:devices:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
10:memory:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
9:hugetlb:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
8:perf_event:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
7:freezer:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
6:pids:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
5:cpu,cpuacct:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
4:cpuset:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
3:blkio:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
2:net_cls,net_prio:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c
1:name=systemd:/kubepods/besteffort/pod74ba62da-1a3d-11e7-bb11-080027cb0e22/cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "cb1eadb7abe3a6545e9856411207073277838e1bdc003337c2f8685faeedc32c" {
		t.Errorf("Invalid Kubepods docker ID: %v\n", id)
	}
}

func TestDockerIDKubepods2(t *testing.T) {
	cgroup := `
11:cpuset:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
10:blkio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
9:devices:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
8:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
7:freezer:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
6:perf_event:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
5:net_prio,net_cls:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
4:hugetlb:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
3:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
2:cpuacct,cpu:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope
1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod045b1e35_7f13_11e7_ac42_0050568ffca0.slice/docker-b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70.scope`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "b5b6f2da8008be266864f896f93789762b2ce50792114a5c5f2cc3315af0bc70" {
		t.Errorf("Invalid Kubepods2 docker ID: %v\n", id)
	}
}

func TestDockerIDKubepods3(t *testing.T) {
	cgroup := `
8:pids:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
7:blkio:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
6:perf_event:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
5:devices:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
4:freezer:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
3:rdma:/
2:cpuset,cpu,cpuacct,memory,net_cls,net_prio,hugetlb:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d
1:name=systemd:/kubepods/besteffort/pod1fe19bf5-e8ef-11e8-900c-52daee5a874d/da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "da31e536c8d61304a6d5998d163d12400a7a9a1003e1d86369e8fadb022fc17d" {
		t.Errorf("Invalid Kubepods2 docker ID: %v\n", id)
	}
}

func TestHostProcess(t *testing.T) {
	cgroup := `
14:name=dsystemd:/
13:name=systemd:/
12:pids:/
11:hugetlb:/
10:net_prio:/
9:perf_event:/
8:net_cls:/
7:freezer:/
6:devices:/
5:memory:/
4:blkio:/
3:cpuacct:/
2:cpu:/
1:cpuset:/`
	r := strings.NewReader(cgroup)
	id, _, err, _ := getContainerIDByCgroupReader(r)
	if id != "" || err != nil {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestNsEnterProcess(t *testing.T) {
	cgroup := `
13:name=systemd:/user/1000.user/c2.session
12:pids:/
11:hugetlb:/user/1000.user/c2.session
10:net_prio:/user/1000.user/c2.session
9:perf_event:/user/1000.user/c2.session
8:net_cls:/user/1000.user/c2.session
7:freezer:/user/1000.user/c2.session
6:devices:/user/1000.user/c2.session
5:memory:/user/1000.user/c2.session
4:blkio:/user/1000.user/c2.session
3:cpuacct:/user/1000.user/c2.session
2:cpu:/user/1000.user/c2.session
1:cpuset:/`
	r := strings.NewReader(cgroup)
	id, _, err, _ := getContainerIDByCgroupReader(r)
	if id != "" || err != nil {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestK8sProxyProcess(t *testing.T) {
	cgroup := `
11:freezer:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
10:memory:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
9:pids:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
8:cpuset:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
7:cpu,cpuacct:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
6:devices:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
5:blkio:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
4:perf_event:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
3:hugetlb:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
2:net_cls,net_prio:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy
1:name=systemd:/kubepods/besteffort/podf8a694f2-7c08-11e9-98da-000c29077430/c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903/kube-proxy`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "c04e0a88a1de067f25bece337d4dbb897396e0b623c2a65330850fc9823f1903" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestK8sBottleRocket(t *testing.T) {
	cgroup := `
11:cpuset:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
10:blkio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
9:hugetlb:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
8:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
7:net_cls,net_prio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
6:freezer:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
5:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
4:cpu,cpuacct:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
3:devices:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
2:perf_event:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope
0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poddd1bf9d1_241d_47f5_8e25_12de83135812.slice/cri-containerd-f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830.scope`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "f45298cd514d1930c4fe3afc4412e59547f7e3148fddd22ca33cefce046eb830" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestK8sCrio_v1_19(t *testing.T) {
	// [root@worker0 2615]# crio -v
	// crio version 1.19.0-26.rhaos4.6.git8a05a29.el8
	// Version:    1.19.0-26.rhaos4.6.git8a05a29.el8
	// GoVersion:  go1.15.2
	// Compiler:   gc
	// Platform:   linux/amd64
	// Linkmode:   dynamic
	cgroup := `
	12:devices:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	11:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	10:freezer:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	9:cpuset:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	8:cpu,cpuacct:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	7:hugetlb:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	6:rdma:/
	5:perf_event:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	4:blkio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	3:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	2:net_cls,net_prio:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8ca306fa_3c03_47fa_97dd_19979c345572.slice/crio-d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607.scope
	`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "d6d725b909f37c3e232aadfbafa950a58bfe7baa579ba8c47a12be88bb921607" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestK8sCrio_v1_17(t *testing.T) {
	//	[root@master0 ~]# crio -v
	//  crio version 1.17.4-8.dev.rhaos4.4.git5f5c5e4.el8
	cgroup := `
	12:hugetlb:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	11:blkio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	10:freezer:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	9:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	8:devices:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	7:rdma:/
	6:perf_event:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	5:cpuset:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	4:cpu,cpuacct:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	3:memory:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	2:net_cls,net_prio:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope
	1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod487a0dc6dccaeefbcfedba7a7ce1ca18.slice/crio-7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e.scope`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "7a1fd6fe8cdfbd44dc78c4cc85dad7031eaab4365801684cad0aabdeaf863f9e" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestUpperDir_Overlay2(t *testing.T) {
	// docker Server Version: 18.06.3-ce
	// Storage Driver: overlay2
	mounts := `
		overlay / overlay rw,relatime,lowerdir=/var/lib/docker/overlay2/l/3QGUFQFUCYCBOH5EW4JWJTUKKQ:/var/lib/docker/overlay2/l/6PPV4WKAQLZBMFTSIUOZXV2NI2:/var/lib/docker/overlay2/l/5UBRXGS3E2F5N2DBELLIOGAHSI:/var/lib/docker/overlay2/l/RNASMLQOG7545OZSZFTV3J7S5J:/var/lib/docker/overlay2/l/EMSY5VUYPJCOUQ5U2L22RVOTOJ:/var/lib/docker/overlay2/l/BXQVDHGAYRMZEEMOFVUMKXTBE5:/var/lib/docker/overlay2/l/A4OAWYSWRTQJEPC5CKLLDQKTI4:/var/lib/docker/overlay2/l/HORWAPLLSDMCKOCHBWTHF6FINC:/var/lib/docker/overlay2/l/4DX2Z5ZJ6MJ2FMQAXTOIML3EJ2,upperdir=/var/lib/docker/overlay2/03a3f687e69707e7d9ed2864727a6b6f70a273980e7bed41ad5d98c5a7b29264/diff,workdir=/var/lib/docker/overlay2/03a3f687e69707e7d9ed2864727a6b6f70a273980e7bed41ad5d98c5a7b29264/work 0 0
		proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
		tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
		devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
		sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
		tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,relatime,mode=755 0 0
		cgroup /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0
		cgroup /sys/fs/cgroup/cpu cgroup ro,nosuid,nodev,noexec,relatime,cpu 0 0
		cgroup /sys/fs/cgroup/cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpuacct 0 0
		cgroup /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0
		cgroup /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0
		cgroup /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0
		cgroup /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0
		cgroup /sys/fs/cgroup/net_cls cgroup ro,nosuid,nodev,noexec,relatime,net_cls 0 0
		cgroup /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0
		cgroup /sys/fs/cgroup/net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_prio 0 0
		cgroup /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0
		cgroup /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0
		systemd /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,name=systemd 0 0
		cgroup /sys/fs/cgroup/dsystemd cgroup ro,nosuid,nodev,noexec,relatime,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=dsystemd 0 0
		mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
		/dev/sda1 /app ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
		/dev/sda1 /etc/resolv.conf ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
		/dev/sda1 /etc/hostname ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
		/dev/sda1 /etc/hosts ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
		shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
		devpts /dev/console devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
		proc /proc/asound proc ro,relatime 0 0
		proc /proc/bus proc ro,relatime 0 0
		proc /proc/fs proc ro,relatime 0 0
		proc /proc/irq proc ro,relatime 0 0
		proc /proc/sys proc ro,relatime 0 0
		proc /proc/sysrq-trigger proc ro,relatime 0 0
		tmpfs /proc/acpi tmpfs ro,relatime 0 0
		tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755 0 0
		tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755 0 0
		tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755 0 0
		tmpfs /proc/timer_stats tmpfs rw,nosuid,size=65536k,mode=755 0 0
		tmpfs /proc/sched_debug tmpfs rw,nosuid,size=65536k,mode=755 0 0
		tmpfs /proc/scsi tmpfs ro,relatime 0 0
		tmpfs /sys/firmware tmpfs ro,relatime 0 0`

	id := "00462ec62b1186a3962d7814fa02214011b7e99300cf30efa0a33bfe79555067"
	res_rootfs := "/"
	res_upper := "/var/lib/docker/overlay2/03a3f687e69707e7d9ed2864727a6b6f70a273980e7bed41ad5d98c5a7b29264/diff"

	r := strings.NewReader(mounts)
	upper, rootfs, _ := readUppperLayerPath(r, id)
	if rootfs != res_rootfs {
		t.Errorf("failed to obtain rootfs: %v\n", rootfs)
	}

	if upper != res_upper {
		t.Errorf("failed to obtain upperDir: %v\n", upper)
	}
}

func TestK8sContainerd_v1_2_13(t *testing.T) {
	//	[root@master0 ~]# ~# ctr -v
	//  ctr containerd.io 1.2.13
	cgroup := `11:pids:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	10:perf_event:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	9:memory:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	8:cpu,cpuacct:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	7:blkio:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	6:cpuset:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	5:hugetlb:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	4:devices:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	3:freezer:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	2:net_cls,net_prio:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61
	1:name=systemd:/kubepods/besteffort/poda36d0c1d-0b26-4451-8d80-9c195e004afa/5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "5dd96d5394ca930a854a390ea46f7515a8bc930123eb3251ba20f2708a38fc61" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestK8sContainerd_v1_4_4(t *testing.T) {
	//	[root@master0 ~]# ~# ctr -v
	//  ctr containerd.io 1.4.4
	cgroup := `11:pids:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
10:freezer:/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
9:perf_event:/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
8:cpu,cpuacct:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
7:cpuset:/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
6:devices:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
5:net_cls,net_prio:/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
4:memory:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
3:hugetlb:/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
2:blkio:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e
1:name=systemd:/system.slice/containerd.service/kubepods-besteffort-pod2105e389_7471_476e_a50f_6074cef29bbd.slice:cri-containerd:d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e`
	r := strings.NewReader(cgroup)
	id, _, _, _ := getContainerIDByCgroupReader(r)
	if id != "d3d8ccf5cca91931c6285c1d7472c413dd5a7700fddc0aa9f89a9ac7008b003e" {
		t.Errorf("detect wrong container ID: %v\n", id)
	}
}

func TestUpperDir_Overlay_MutipleMounts(t *testing.T) {
	// docker Server Version: 18.06.3-ce
	// Storage Driver: overlay2
	mounts := `
/dev/mapper/ubuntu--vg-ubuntu--lv /bin ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /cdrom ext4 rw,relatime 0 0
udev /dev devtmpfs rw,nosuid,noexec,relatime,size=2999468k,nr_inodes=749867,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,relatime,pagesize=2M 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /etc ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /home ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /lib ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /lib32 ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /lib64 ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /libx32 ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /lost+found ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /media ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /mnt ext4 rw,relatime 0 0
10.1.24.250:/nfs /nfs nfs4 rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.1.24.10,local_lock=none,addr=10.1.24.250 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /opt ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=608888k,mode=755 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
sunrpc /run/rpc_pipefs rpc_pipefs rw,relatime 0 0
tmpfs /run/snapd/ns tmpfs rw,nosuid,nodev,noexec,relatime,size=608888k,mode=755 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/591d8de2ed342e20b3b484e63f1b8c46ba807a7ab3d0a43e45f59678abefc298/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1638/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1638/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/3f9d9e34207ac96708327c4ae231df89bccd964aecb47159a7de5abb3d3dfadc/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1641/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1641/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/e29a3d40c4a15f33ae221bc9c2a942897f8f853bfc4576f203ff48582c8f6ee6/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1640/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1640/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/e6f0b6f6382bbefbc998d30991c993fa6c5e2d492152f78d79aef26dbd5cfbba/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1639/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1639/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/75fc506da0584ed2a3c8a62808013f3c2d80cf269ebcef4252cfce6c6ff7ff23/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/4/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1642/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1642/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/cc09735d67ae849fa0a568d382358ee8540b40cd439f055c922fc05b1474de4a/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/18/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/17/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/16/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/15/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/14/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1643/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1643/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/90d7219e8940870304c0aff926ac89a6d6f195a3ba51233f66e21d6661d2e1d1/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/5/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1644/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1644/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/30eaa85bed874566c49258329f38e56c9b2a4259cfac9039091f50b164917c18/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1645/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1645/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/bd93ca32392b5a770598408e34a27e443f173ab32b515a3e6bc1192b5d0cc2ab/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1646/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1646/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/d2dadd3607be52dad0725b07157af1c8d108b10025505cbb418d2beee4f3de84/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1647/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1647/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/8e1bb143c6e82b1d6585760a655227c510f8d6ce274653483f151a821925586d/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1648/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1648/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/1a1b6718490126611502123ef8373fbe5b87411f94de805cb2e86355ea4b43b2/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1650/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1650/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/91ed625f7b69daa28085471ee552699b7877f6aafeed331c47b97a347b45db15/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/59/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1649/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1649/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/1bddb56cd62acee6f60c73d9e77da01f10816c57e3f70e7203dc852fd2ccbd79/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/11/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/10/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/8/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/6/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1651/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1651/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1615/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1614/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1613/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1612/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/582/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/581/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1653/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1653/work,xino=off 0 0
overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1615/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1614/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1613/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1612/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/582/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/581/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1653/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1653/work,xino=off 0 0
proc /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
devpts /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
mqueue /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
sysfs /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/rdma cgroup rw,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs/sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /sbin ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /snap ext4 rw,relatime 0 0
/dev/loop0 /snap/core18/2074 squashfs ro,nodev,relatime 0 0
/dev/loop5 /snap/snapd/12398 squashfs ro,nodev,relatime 0 0
/dev/loop2 /snap/core18/2066 squashfs ro,nodev,relatime 0 0
/dev/loop3 /snap/lxd/20326 squashfs ro,nodev,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /srv ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /usr ext4 rw,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv /var ext4 rw,relatime 0 0
proc /proc proc rw,relatime 0 0
sys /sys sysfs rw,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/rdma cgroup rw,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
securityfs /sys/kernel/security securityfs rw,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
tracefs /sys/kernel/debug/tracing tracefs rw,relatime 0 0`

	id := "5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a"
	res_rootfs := "/run/containerd/io.containerd.runtime.v2.task/k8s.io/5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a/rootfs"
	res_upper := "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1653/fs"

	r := strings.NewReader(mounts)
	upper, rootfs, _ := readUppperLayerPath(r, id)
	if rootfs != res_rootfs {
		t.Errorf("failed to obtain rootfs: %v\n", rootfs)
	}

	if upper != res_upper {
		t.Errorf("failed to obtain upperDir: %v\n", upper)
	}
}

func Test_Aufs_SI_Mount(t *testing.T) {
	// docker Server Version: 19.03.5
	// Storage Driver: aufs
	// read only example:
	//  none / aufs ro,relatime,si=5bc22622cbf00f12,dio,dirperm1 0 0
	mounts := `
none / aufs rw,relatime,si=17a0558472d016ab,dio,dirperm1 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,relatime,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup ro,nosuid,nodev,noexec,relatime,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
cgroup /sys/fs/cgroup/memory cgroup ro,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/cpuset cgroup ro,nosuid,nodev,noexec,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup ro,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/devices cgroup ro,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/perf_event cgroup ro,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup ro,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/pids cgroup ro,nosuid,nodev,noexec,relatime,pids 0 0
cgroup /sys/fs/cgroup/blkio cgroup ro,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup ro,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/freezer cgroup ro,nosuid,nodev,noexec,relatime,freezer 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
/dev/mapper/ubuntu1604--vg-root /etc/resolv.conf ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/mapper/ubuntu1604--vg-root /etc/hostname ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
/dev/mapper/ubuntu1604--vg-root /etc/hosts ext4 rw,relatime,errors=remount-ro,data=ordered 0 0
devpts /dev/console devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
proc /proc/bus proc ro,relatime 0 0
proc /proc/fs proc ro,relatime 0 0
proc /proc/irq proc ro,relatime 0 0
proc /proc/sys proc ro,relatime 0 0
proc /proc/sysrq-trigger proc ro,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/sched_debug tmpfs rw,nosuid,size=65536k,mode=755 0 0
tmpfs /proc/scsi tmpfs ro,relatime 0 0
tmpfs /sys/firmware tmpfs ro,relatime 0 0`

	si := "17a0558472d016ab"
	id := "5e144353a977c7731eddef70bd57e5d8d09b3d09af46f00d0cc2fb9220bfff8a" // TODO
	r := strings.NewReader(mounts)
	res_si, _ := readAufsSI(r, id)
	if res_si != si {
		t.Errorf("failed to obtain si: %v\n", res_si)
	}
}

func TestDocker_Host_Proc1_Cgroupv2(t *testing.T) {
	// docker: 20.10.0 ce
	// OpenSuse tumbleweed (similair on the ubuntu 21.10)
	// host process: /proc/1
	cgroup := `
0::/../../init.scope
	`
	mountinfo := `
22 60 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:11 - proc proc rw
23 60 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
24 60 0:5 / /dev rw,nosuid shared:7 - devtmpfs devtmpfs rw,size=1994196k,nr_inodes=498549,mode=755,inode64
25 23 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:3 - securityfs securityfs rw
26 24 0:22 / /dev/shm rw,nosuid,nodev shared:8 - tmpfs tmpfs rw,inode64
27 24 0:23 / /dev/pts rw,nosuid,noexec,relatime shared:9 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 60 0:24 / /run rw,nosuid,nodev shared:10 - tmpfs tmpfs rw,size=802128k,nr_inodes=819200,mode=755,inode64
29 23 0:25 /../.. /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:4 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
30 23 0:26 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:5 - pstore pstore rw
31 23 0:27 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:6 - bpf none rw,mode=700
60 1 0:29 /@/.snapshots/1/snapshot / rw,relatime shared:1 - btrfs /dev/sda2 rw,space_cache,subvolid=267,subvol=/@/.snapshots/1/snapshot
32 22 0:34 / /proc/sys/fs/binfmt_misc rw,relatime shared:12 - autofs systemd-1 rw,fd=29,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=11773
33 24 0:19 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:13 - mqueue mqueue rw
34 23 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:14 - debugfs debugfs rw
35 24 0:35 / /dev/hugepages rw,relatime shared:15 - hugetlbfs hugetlbfs rw,pagesize=2M
36 23 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:16 - tracefs tracefs rw
38 60 0:29 /@/.snapshots /.snapshots rw,relatime shared:17 - btrfs /dev/sda2 rw,space_cache,subvolid=266,subvol=/@/.snapshots
87 60 0:29 /@/boot/grub2/i386-pc /boot/grub2/i386-pc rw,relatime shared:33 - btrfs /dev/sda2 rw,space_cache,subvolid=265,subvol=/@/boot/grub2/i386-pc
37 60 0:29 /@/boot/grub2/x86_64-efi /boot/grub2/x86_64-efi rw,relatime shared:40 - btrfs /dev/sda2 rw,space_cache,subvolid=264,subvol=/@/boot/grub2/x86_64-efi
39 60 0:29 /@/home /home rw,relatime shared:42 - btrfs /dev/sda2 rw,space_cache,subvolid=263,subvol=/@/home
40 60 0:29 /@/opt /opt rw,relatime shared:44 - btrfs /dev/sda2 rw,space_cache,subvolid=262,subvol=/@/opt
41 60 0:29 /@/root /root rw,relatime shared:46 - btrfs /dev/sda2 rw,space_cache,subvolid=261,subvol=/@/root
42 60 0:29 /@/srv /srv rw,relatime shared:48 - btrfs /dev/sda2 rw,space_cache,subvolid=260,subvol=/@/srv
43 60 0:29 /@/usr/local /usr/local rw,relatime shared:50 - btrfs /dev/sda2 rw,space_cache,subvolid=259,subvol=/@/usr/local
44 60 0:29 /@/var /var rw,relatime shared:52 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
83 60 0:44 / /tmp rw,nosuid,nodev shared:54 - tmpfs tmpfs rw,nr_inodes=409600,inode64
106 23 0:45 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:56 - configfs configfs rw
109 23 0:46 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:58 - fusectl fusectl rw
327 60 0:51 / /mnt/nfs rw,relatime shared:158 - cifs //10.1.5.5/share rw,vers=3.1.1,cache=strict,username=neuvector,uid=0,noforceuid,gid=0,noforcegid,addr=10.1.5.5,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1
354 34 0:12 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime shared:197 - tracefs tracefs rw
336 44 0:29 /@/var/lib/docker/btrfs /var/lib/docker/btrfs rw,relatime shared:52 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
452 28 0:4 net:[4026532664] /run/docker/netns/de54128c08f8 rw shared:202 - nsfs nsfs rw
345 28 0:69 / /run/user/1000 rw,nosuid,nodev,relatime shared:192 - tmpfs tmpfs rw,size=401060k,nr_inodes=100265,mode=700,uid=1000,gid=100,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "" || found {
		t.Errorf("detect wrong container ID, cgroup: %v\n", id)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "" || found {
		t.Errorf("detect wrong container ID, mountinfo: %v\n", id)
	}
}

func TestDocker_Host_ProcAny_Cgroupv2(t *testing.T) {
	// docker: 20.10.0 ce
	// OpenSuse tumbleweed (similair on the ubuntu 21.10)
	// host process: /proc/(other Pid)
	cgroup := `
0::/../..
	`
	mountinfo := `
22 60 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:11 - proc proc rw
23 60 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
24 60 0:5 / /dev rw,nosuid shared:7 - devtmpfs devtmpfs rw,size=1994196k,nr_inodes=498549,mode=755,inode64
25 23 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:3 - securityfs securityfs rw
26 24 0:22 / /dev/shm rw,nosuid,nodev shared:8 - tmpfs tmpfs rw,inode64
27 24 0:23 / /dev/pts rw,nosuid,noexec,relatime shared:9 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 60 0:24 / /run rw,nosuid,nodev shared:10 - tmpfs tmpfs rw,size=802128k,nr_inodes=819200,mode=755,inode64
29 23 0:25 /../.. /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:4 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
30 23 0:26 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:5 - pstore pstore rw
31 23 0:27 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:6 - bpf none rw,mode=700
60 1 0:29 /@/.snapshots/1/snapshot / rw,relatime shared:1 - btrfs /dev/sda2 rw,space_cache,subvolid=267,subvol=/@/.snapshots/1/snapshot
32 22 0:34 / /proc/sys/fs/binfmt_misc rw,relatime shared:12 - autofs systemd-1 rw,fd=29,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=11773
33 24 0:19 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:13 - mqueue mqueue rw
34 23 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:14 - debugfs debugfs rw
35 24 0:35 / /dev/hugepages rw,relatime shared:15 - hugetlbfs hugetlbfs rw,pagesize=2M
36 23 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:16 - tracefs tracefs rw
38 60 0:29 /@/.snapshots /.snapshots rw,relatime shared:17 - btrfs /dev/sda2 rw,space_cache,subvolid=266,subvol=/@/.snapshots
87 60 0:29 /@/boot/grub2/i386-pc /boot/grub2/i386-pc rw,relatime shared:33 - btrfs /dev/sda2 rw,space_cache,subvolid=265,subvol=/@/boot/grub2/i386-pc
37 60 0:29 /@/boot/grub2/x86_64-efi /boot/grub2/x86_64-efi rw,relatime shared:40 - btrfs /dev/sda2 rw,space_cache,subvolid=264,subvol=/@/boot/grub2/x86_64-efi
39 60 0:29 /@/home /home rw,relatime shared:42 - btrfs /dev/sda2 rw,space_cache,subvolid=263,subvol=/@/home
40 60 0:29 /@/opt /opt rw,relatime shared:44 - btrfs /dev/sda2 rw,space_cache,subvolid=262,subvol=/@/opt
41 60 0:29 /@/root /root rw,relatime shared:46 - btrfs /dev/sda2 rw,space_cache,subvolid=261,subvol=/@/root
42 60 0:29 /@/srv /srv rw,relatime shared:48 - btrfs /dev/sda2 rw,space_cache,subvolid=260,subvol=/@/srv
43 60 0:29 /@/usr/local /usr/local rw,relatime shared:50 - btrfs /dev/sda2 rw,space_cache,subvolid=259,subvol=/@/usr/local
44 60 0:29 /@/var /var rw,relatime shared:52 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
83 60 0:44 / /tmp rw,nosuid,nodev shared:54 - tmpfs tmpfs rw,nr_inodes=409600,inode64
106 23 0:45 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:56 - configfs configfs rw
109 23 0:46 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:58 - fusectl fusectl rw
327 60 0:51 / /mnt/nfs rw,relatime shared:158 - cifs //10.1.5.5/share rw,vers=3.1.1,cache=strict,username=neuvector,uid=0,noforceuid,gid=0,noforcegid,addr=10.1.5.5,file_mode=0755,dir_mode=0755,soft,nounix,serverino,mapposix,rsize=4194304,wsize=4194304,bsize=1048576,echo_interval=60,actimeo=1
354 34 0:12 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime shared:197 - tracefs tracefs rw
336 44 0:29 /@/var/lib/docker/btrfs /var/lib/docker/btrfs rw,relatime shared:52 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
452 28 0:4 net:[4026532664] /run/docker/netns/de54128c08f8 rw shared:202 - nsfs nsfs rw
345 28 0:69 / /run/user/1000 rw,nosuid,nodev,relatime shared:192 - tmpfs tmpfs rw,size=401060k,nr_inodes=100265,mode=700,uid=1000,gid=100,inode64
	`

	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "" || found {
		t.Errorf("detect wrong container ID, cgroup:: %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "" || found {
		t.Errorf("detect wrong container ID, mountinfo: %v, %v\n", id, found)
	}
}

func TestDockerNative_Container_Cgroupv2(t *testing.T) {
	// docker native: 20.10.0 ce
	// OpenSuse tumbleweed (similair on the ubuntu 21.10)
	// container process: /proc/<pid>
	cgroup := `
0::/../docker-1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7.scope
	`
	mountinfo := `
400 365 0:29 /@/var/lib/docker/btrfs/subvolumes/78c1b6ecbc5ed8f5d2a06d3ad4435791c101e5dc6534f1b17cfdcbff013a7892 / rw,relatime master:52 - btrfs /dev/sda2 rw,space_cache,subvolid=353,subvol=/@/var/lib/docker/btrfs/subvolumes/78c1b6ecbc5ed8f5d2a06d3ad4435791c101e5dc6534f1b17cfdcbff013a7892
401 400 0:95 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
402 400 0:96 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
403 402 0:97 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
404 400 0:98 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
405 404 0:25 /../docker-1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7.scope /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
406 402 0:94 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
407 402 0:99 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
408 400 0:29 /@/var/lib/docker/containers/1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7/resolv.conf /etc/resolv.conf rw,relatime - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
409 400 0:29 /@/var/lib/docker/containers/1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7/hostname /etc/hostname rw,relatime - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
410 400 0:29 /@/var/lib/docker/containers/1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7/hosts /etc/hosts rw,relatime - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/var
366 401 0:95 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
367 401 0:95 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
368 401 0:95 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
369 401 0:95 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
370 401 0:95 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
371 401 0:100 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
372 401 0:96 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
373 401 0:96 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
374 401 0:96 /null /proc/latency_stats rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
375 401 0:96 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
376 401 0:101 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
	`

	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7" || !found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	// Optional:
	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7" || !found {
		t.Errorf("detect wrong pod ID, mountinfo: %v, %v\n", id, found)
	}

	// Optional:
	_, _ = r.Seek(0, io.SeekStart)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_fscgroup)
	if id != "1f1d6e2d4940ddac13abd421a2617992bf89f0e0f9a902ed58278c5f843e9ae7" || !found {
		t.Errorf("detect wrong container ID, fscgroup: %v, %v\n", id, found)
	}
}

func TestDockerK8s_Ubuntu_Container_Cgroupv2(t *testing.T) {
	// docker : 20.10.7 ce
	// ubuntu 21.10
	// container process: /proc/<pid>
	cgroup := `
0::/../../kubepods-besteffort-podfd698699_eabf_4c23_92ef_cf0bbdb78261.slice/docker-2cc65c162ca1388b6b8d5ccfb701d22fc96675ccf8b2f1590c490c2c4039547f.scope
	`
	mountinfo := `
857 770 0:72 / / rw,relatime master:340 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/6FQCFGALN25TMA5XIQP25OXL4K:/var/lib/docker/overlay2/l/7GYLCN6XDFHF3F2CM75G54X3TO:/var/lib/docker/overlay2/l/E7CN62YLSWZ74TVVJLYSIMND2O:/var/lib/docker/overlay2/l/LTLRXQRTSXA52XBKXL2YAABMZC:/var/lib/docker/overlay2/l/KI4HYV4ITZCXSNKZEMYUZCATPB:/var/lib/docker/overlay2/l/WHCAYZWGUBE6BPSLIK33Y2BL2X,upperdir=/var/lib/docker/overlay2/f32bbcb5813406e768a2ec515ce7c923f0b44f3055bf9747e982a491bad5a1a6/diff,workdir=/var/lib/docker/overlay2/f32bbcb5813406e768a2ec515ce7c923f0b44f3055bf9747e982a491bad5a1a6/work
858 857 0:84 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
859 857 0:85 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
860 859 0:86 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
862 857 0:21 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
863 862 0:28 /../../kubepods-besteffort-podfd698699_eabf_4c23_92ef_cf0bbdb78261.slice/docker-2cc65c162ca1388b6b8d5ccfb701d22fc96675ccf8b2f1590c490c2c4039547f.scope /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
864 859 0:59 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
865 857 253:0 /var/lib/kubelet/pods/fd698699-eabf-4c23-92ef-cf0bbdb78261/volumes/kubernetes.io~configmap/typha-ca /typha-ca ro,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
866 857 0:44 / /typha-certs ro,relatime - tmpfs tmpfs rw,size=8039532k,inode64
867 859 253:0 /var/lib/kubelet/pods/fd698699-eabf-4c23-92ef-cf0bbdb78261/containers/calico-typha/fc4135aa /dev/termination-log rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
868 857 253:0 /var/lib/docker/containers/c0316cc3b633d0ba4167a2b8a9c0e56e374aa47e5da0954c7c007e0bf93e58b4/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
869 857 253:0 /var/lib/docker/containers/c0316cc3b633d0ba4167a2b8a9c0e56e374aa47e5da0954c7c007e0bf93e58b4/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
870 857 253:0 /var/lib/kubelet/pods/fd698699-eabf-4c23-92ef-cf0bbdb78261/etc-hosts /etc/hosts rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
871 859 0:52 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
872 857 0:45 / /var/run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=8039532k,inode64
771 858 0:84 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
772 858 0:84 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
783 858 0:84 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
784 858 0:84 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
785 858 0:84 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
786 858 0:87 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
787 858 0:85 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
788 858 0:85 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
789 858 0:85 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
790 858 0:88 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
791 862 0:89 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "2cc65c162ca1388b6b8d5ccfb701d22fc96675ccf8b2f1590c490c2c4039547f" || !found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	// Optional:
	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "c0316cc3b633d0ba4167a2b8a9c0e56e374aa47e5da0954c7c007e0bf93e58b4" || !found { // pod ID
		t.Errorf("detect wrong pod ID, mountinfo: %v, %v\n", id, found)
	}

	// Optional:
	_, _ = r.Seek(0, io.SeekStart)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_fscgroup)
	if id != "2cc65c162ca1388b6b8d5ccfb701d22fc96675ccf8b2f1590c490c2c4039547f" || !found {
		t.Errorf("detect wrong dcontainer ID, fscgroup: %v, %v\n", id, found)
	}
}

func TestDockerK8s_Container_SelfProbe_Cgroupv2(t *testing.T) {
	// docker : 20.10.7 ce
	// ubuntu 21.10
	// container process: /proc/self
	cgroup := `
	0::/
	`
	mountinfo := `
1039 961 0:102 / / rw,relatime master:401 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/ZSKEXZKXK5HUVNQMO73OQHZOWT:/var/lib/docker/overlay2/l/PFIYY4P6LDYTLPV2WABMDBILJX,upperdir=/var/lib/docker/overlay2/fe18fca8f66c1e0227ecd9565e5c758fb20ed7bdbf2e8b606ea5b4a7f6aaecb8/diff,workdir=/var/lib/docker/overlay2/fe18fca8f66c1e0227ecd9565e5c758fb20ed7bdbf2e8b606ea5b4a7f6aaecb8/work
1040 1039 0:104 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1041 1039 0:105 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
1042 1041 0:106 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
1043 1039 0:101 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
1044 1043 0:28 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
1045 1041 0:97 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
1046 1041 253:0 /var/lib/kubelet/pods/90f456dd-e019-48a5-b43b-f79c657d637b/containers/ubuntu/c46bde50 /dev/termination-log rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
1047 1039 253:0 /var/lib/docker/containers/3de9403cee30663f24308ed70211c07f82de65efa2d8dec576f356c3d40e410f/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
1048 1039 253:0 /var/lib/docker/containers/3de9403cee30663f24308ed70211c07f82de65efa2d8dec576f356c3d40e410f/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
1049 1039 253:0 /var/lib/kubelet/pods/90f456dd-e019-48a5-b43b-f79c657d637b/etc-hosts /etc/hosts rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
1050 1041 0:96 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
1051 1039 0:92 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=8039532k,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "" || found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	// real ID was "766cc41ad9dc3fcbc498ae2982834010d0d858cd8ce62eac5f0ca1d1b1247b6c"
	// but the alternate ID is also unqiue in the node system
	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "3de9403cee30663f24308ed70211c07f82de65efa2d8dec576f356c3d40e410f" || !found { // pod ID
		t.Errorf("detect wrong pod ID, cgroup: %v, %v\n", id, found)
	}
}

func TestCrio_Host_Proc1_Cgroupv2(t *testing.T) {
	// crictl version: 1.22
	// OpenSuse Kubic cluster: 1.22.1
	// host process: /proc/(other Pid)
	cgroup := `
0::/init.scope
	`
	mountinfo := `
22 60 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
23 60 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:5 - sysfs sysfs rw
24 60 0:5 / /dev rw,nosuid shared:10 - devtmpfs devtmpfs rw,size=1851604k,nr_inodes=462901,mode=755,inode64
25 23 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:6 - securityfs securityfs rw
26 24 0:22 / /dev/shm rw,nosuid,nodev shared:11 - tmpfs tmpfs rw,inode64
27 24 0:23 / /dev/pts rw,nosuid,noexec,relatime shared:12 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 60 0:24 / /run rw,nosuid,nodev shared:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
29 23 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw
30 23 0:26 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:8 - pstore pstore rw
31 23 0:27 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:9 - bpf none rw,mode=700
60 1 0:29 /@/.snapshots/1/snapshot / ro,relatime shared:1 - btrfs /dev/sda2 rw,space_cache,subvolid=267,subvol=/@/.snapshots/1/snapshot
63 60 0:29 /@/root /root rw,relatime shared:2 - btrfs /dev/sda2 rw,space_cache,subvolid=260,subvol=/@/root
66 60 0:35 / /var rw,relatime shared:3 - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
70 60 0:37 / /etc rw,relatime shared:4 - overlay overlay rw,lowerdir=/sysroot/etc,upperdir=/sysroot/var/lib/overlay/1/etc,workdir=/sysroot/var/lib/overlay/work-etc
32 22 0:40 / /proc/sys/fs/binfmt_misc rw,relatime shared:15 - autofs systemd-1 rw,fd=30,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=14666
33 23 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:16 - debugfs debugfs rw
34 60 0:41 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw,size=1862980k,nr_inodes=409600,inode64
35 24 0:42 / /dev/hugepages rw,relatime shared:18 - hugetlbfs hugetlbfs rw,pagesize=2M
36 23 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:19 - tracefs tracefs rw
37 24 0:19 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:20 - mqueue mqueue rw
39 60 0:29 /@/.snapshots /.snapshots rw,relatime shared:21 - btrfs /dev/sda2 rw,space_cache,subvolid=266,subvol=/@/.snapshots
42 60 0:29 /@/boot/writable /boot/writable rw,relatime shared:22 - btrfs /dev/sda2 rw,space_cache,subvolid=263,subvol=/@/boot/writable
41 60 0:29 /@/boot/grub2/x86_64-efi /boot/grub2/x86_64-efi rw,relatime shared:23 - btrfs /dev/sda2 rw,space_cache,subvolid=264,subvol=/@/boot/grub2/x86_64-efi
44 60 0:29 /@/home /home rw,relatime shared:24 - btrfs /dev/sda2 rw,space_cache,subvolid=262,subvol=/@/home
100 60 0:29 /@/srv /srv rw,relatime shared:25 - btrfs /dev/sda2 rw,space_cache,subvolid=259,subvol=/@/srv
108 60 0:29 /@/opt /opt rw,relatime shared:26 - btrfs /dev/sda2 rw,space_cache,subvolid=261,subvol=/@/opt
107 23 0:48 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:45 - configfs configfs rw
113 60 0:29 /@/usr/local /usr/local rw,relatime shared:58 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/usr/local
40 23 0:50 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:60 - fusectl fusectl rw
118 60 0:29 /@/boot/grub2/i386-pc /boot/grub2/i386-pc rw,relatime shared:62 - btrfs /dev/sda2 rw,space_cache,subvolid=265,subvol=/@/boot/grub2/i386-pc
503 66 0:35 /lib/containers/storage/btrfs /var/lib/containers/storage/btrfs rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
432 66 0:59 / /var/lib/kubelet/pods/b49b59c4-7721-4b1f-b6b2-304034aea38f/volumes/kubernetes.io~projected/kube-api-access-ljwtj rw,relatime shared:242 - tmpfs tmpfs rw,size=3623556k,inode64
443 66 0:60 / /var/lib/kubelet/pods/042efd86-1f3b-4f2f-8736-f31c58e95bbc/volumes/kubernetes.io~projected/kube-api-access-bzzml rw,relatime shared:248 - tmpfs tmpfs rw,size=51200k,inode64
454 28 0:63 / /run/containers/storage/btrfs-containers/66cb5145cc3f8f6491f698dd32b7af469519daff7a1dd009aacde12a00f68d34/userdata/shm rw,nosuid,nodev,noexec,relatime shared:254 - tmpfs shm rw,size=65536k,inode64
466 28 0:4 uts:[4026532576] /run/utsns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:260 - nsfs nsfs rw
477 28 0:4 ipc:[4026532577] /run/ipcns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:266 - nsfs nsfs rw
488 28 0:4 net:[4026531992] /run/netns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:272 - nsfs nsfs rw
499 28 0:69 / /run/containers/storage/btrfs-containers/a384237317c8537d2876f46e6b2902658396f5a64ee057db25e077f0b807c89d/userdata/shm rw,nosuid,nodev,noexec,relatime shared:278 - tmpfs shm rw,size=65536k,inode64
524 28 0:4 uts:[4026532589] /run/utsns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:284 - nsfs nsfs rw
535 28 0:4 ipc:[4026532590] /run/ipcns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:295 - nsfs nsfs rw
546 28 0:4 net:[4026531992] /run/netns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:301 - nsfs nsfs rw
421 66 0:88 / /var/lib/kubelet/pods/395f906e-7c77-4c83-9472-361ea8819cea/volumes/kubernetes.io~projected/kube-api-access-q2bcn rw,relatime shared:213 - tmpfs tmpfs rw,size=3623556k,inode64
581 28 0:90 / /run/containers/storage/btrfs-containers/7211d9dae7861aee9695d6775838ed026e0aa35adba06e077c58a9a6470e141d/userdata/shm rw,nosuid,nodev,noexec,relatime shared:307 - tmpfs shm rw,size=65536k,inode64
593 28 0:4 uts:[4026532605] /run/utsns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:313 - nsfs nsfs rw
644 28 0:4 ipc:[4026532606] /run/ipcns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:319 - nsfs nsfs rw
655 28 0:4 net:[4026532608] /run/netns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:325 - nsfs nsfs rw
666 28 0:101 / /run/user/1000 rw,nosuid,nodev,relatime shared:331 - tmpfs tmpfs rw,size=372592k,nr_inodes=93148,mode=700,uid=1000,gid=100,ino
	`

	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "" || found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "" || found {
		t.Errorf("detect wrong container ID, mountinfo: %v, %v\n", id, found)
	}
}

func TestCrio_Host_ProcAny_Cgroupv2(t *testing.T) {
	// crictl version: 1.22
	// OpenSuse Kubic cluster: 1.22.1
	// host process: /proc/(other Pid)
	cgroup := `
0::/
	`
	mountinfo := `
22 60 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
23 60 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:5 - sysfs sysfs rw
24 60 0:5 / /dev rw,nosuid shared:10 - devtmpfs devtmpfs rw,size=1851604k,nr_inodes=462901,mode=755,inode64
25 23 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:6 - securityfs securityfs rw
26 24 0:22 / /dev/shm rw,nosuid,nodev shared:11 - tmpfs tmpfs rw,inode64
27 24 0:23 / /dev/pts rw,nosuid,noexec,relatime shared:12 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 60 0:24 / /run rw,nosuid,nodev shared:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
29 23 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw
30 23 0:26 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:8 - pstore pstore rw
31 23 0:27 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:9 - bpf none rw,mode=700
60 1 0:29 /@/.snapshots/1/snapshot / ro,relatime shared:1 - btrfs /dev/sda2 rw,space_cache,subvolid=267,subvol=/@/.snapshots/1/snapshot
63 60 0:29 /@/root /root rw,relatime shared:2 - btrfs /dev/sda2 rw,space_cache,subvolid=260,subvol=/@/root
66 60 0:35 / /var rw,relatime shared:3 - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
70 60 0:37 / /etc rw,relatime shared:4 - overlay overlay rw,lowerdir=/sysroot/etc,upperdir=/sysroot/var/lib/overlay/1/etc,workdir=/sysroot/var/lib/overlay/work-etc
32 22 0:40 / /proc/sys/fs/binfmt_misc rw,relatime shared:15 - autofs systemd-1 rw,fd=30,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=14666
33 23 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:16 - debugfs debugfs rw
34 60 0:41 / /tmp rw,nosuid,nodev shared:17 - tmpfs tmpfs rw,size=1862980k,nr_inodes=409600,inode64
35 24 0:42 / /dev/hugepages rw,relatime shared:18 - hugetlbfs hugetlbfs rw,pagesize=2M
36 23 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:19 - tracefs tracefs rw
37 24 0:19 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:20 - mqueue mqueue rw
39 60 0:29 /@/.snapshots /.snapshots rw,relatime shared:21 - btrfs /dev/sda2 rw,space_cache,subvolid=266,subvol=/@/.snapshots
42 60 0:29 /@/boot/writable /boot/writable rw,relatime shared:22 - btrfs /dev/sda2 rw,space_cache,subvolid=263,subvol=/@/boot/writable
41 60 0:29 /@/boot/grub2/x86_64-efi /boot/grub2/x86_64-efi rw,relatime shared:23 - btrfs /dev/sda2 rw,space_cache,subvolid=264,subvol=/@/boot/grub2/x86_64-efi
44 60 0:29 /@/home /home rw,relatime shared:24 - btrfs /dev/sda2 rw,space_cache,subvolid=262,subvol=/@/home
100 60 0:29 /@/srv /srv rw,relatime shared:25 - btrfs /dev/sda2 rw,space_cache,subvolid=259,subvol=/@/srv
108 60 0:29 /@/opt /opt rw,relatime shared:26 - btrfs /dev/sda2 rw,space_cache,subvolid=261,subvol=/@/opt
107 23 0:48 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:45 - configfs configfs rw
113 60 0:29 /@/usr/local /usr/local rw,relatime shared:58 - btrfs /dev/sda2 rw,space_cache,subvolid=258,subvol=/@/usr/local
40 23 0:50 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:60 - fusectl fusectl rw
118 60 0:29 /@/boot/grub2/i386-pc /boot/grub2/i386-pc rw,relatime shared:62 - btrfs /dev/sda2 rw,space_cache,subvolid=265,subvol=/@/boot/grub2/i386-pc
503 66 0:35 /lib/containers/storage/btrfs /var/lib/containers/storage/btrfs rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
432 66 0:59 / /var/lib/kubelet/pods/b49b59c4-7721-4b1f-b6b2-304034aea38f/volumes/kubernetes.io~projected/kube-api-access-ljwtj rw,relatime shared:242 - tmpfs tmpfs rw,size=3623556k,inode64
443 66 0:60 / /var/lib/kubelet/pods/042efd86-1f3b-4f2f-8736-f31c58e95bbc/volumes/kubernetes.io~projected/kube-api-access-bzzml rw,relatime shared:248 - tmpfs tmpfs rw,size=51200k,inode64
454 28 0:63 / /run/containers/storage/btrfs-containers/66cb5145cc3f8f6491f698dd32b7af469519daff7a1dd009aacde12a00f68d34/userdata/shm rw,nosuid,nodev,noexec,relatime shared:254 - tmpfs shm rw,size=65536k,inode64
466 28 0:4 uts:[4026532576] /run/utsns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:260 - nsfs nsfs rw
477 28 0:4 ipc:[4026532577] /run/ipcns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:266 - nsfs nsfs rw
488 28 0:4 net:[4026531992] /run/netns/0234cef0-d2e2-451d-b26b-67b1c97d1fc2 rw shared:272 - nsfs nsfs rw
499 28 0:69 / /run/containers/storage/btrfs-containers/a384237317c8537d2876f46e6b2902658396f5a64ee057db25e077f0b807c89d/userdata/shm rw,nosuid,nodev,noexec,relatime shared:278 - tmpfs shm rw,size=65536k,inode64
524 28 0:4 uts:[4026532589] /run/utsns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:284 - nsfs nsfs rw
535 28 0:4 ipc:[4026532590] /run/ipcns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:295 - nsfs nsfs rw
546 28 0:4 net:[4026531992] /run/netns/16a002dd-f34b-4661-af9d-074af7d1566b rw shared:301 - nsfs nsfs rw
421 66 0:88 / /var/lib/kubelet/pods/395f906e-7c77-4c83-9472-361ea8819cea/volumes/kubernetes.io~projected/kube-api-access-q2bcn rw,relatime shared:213 - tmpfs tmpfs rw,size=3623556k,inode64
581 28 0:90 / /run/containers/storage/btrfs-containers/7211d9dae7861aee9695d6775838ed026e0aa35adba06e077c58a9a6470e141d/userdata/shm rw,nosuid,nodev,noexec,relatime shared:307 - tmpfs shm rw,size=65536k,inode64
593 28 0:4 uts:[4026532605] /run/utsns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:313 - nsfs nsfs rw
644 28 0:4 ipc:[4026532606] /run/ipcns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:319 - nsfs nsfs rw
655 28 0:4 net:[4026532608] /run/netns/0d5663f9-8bfb-4dad-b4b5-2ef74b898906 rw shared:325 - nsfs nsfs rw
666 28 0:101 / /run/user/1000 rw,nosuid,nodev,relatime shared:331 - tmpfs tmpfs rw,size=372592k,nr_inodes=93148,mode=700,uid=1000,gid=100,inode64
	`

	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "" || found {
		t.Errorf("detect wrong container ID, cgroup:  %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "" || found {
		t.Errorf("detect wrong pod ID, mountinfo: %v, %v\n", id, found)
	}
}

func TestCrio_Container_SelfProbe_Cgroupv2(t *testing.T) {
	// crictl version: 1.22
	// OpenSuse Kubic cluster: 1.22.1
	// container process: /proc/self
	cgroup := `
	0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod395f906e_7c77_4c83_9472_361ea8819cea.slice/crio-7b05b98b56047ad0e02e55f4e6bcffbcdc436340179a9c05908df1e5d4f0710d.scope
	`
	mountinfo := `
724 668 0:35 /lib/containers/storage/btrfs/subvolumes/c3d1155169e7e7e697dedf382a3915ccdc1337663d6c3368d96c679c34168294 / rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=269,subvol=/lib/containers/storage/btrfs/subvolumes/c3d1155169e7e7e697dedf382a3915ccdc1337663d6c3368d96c679c34168294
725 724 0:98 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
726 724 0:99 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
727 726 0:100 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
728 726 0:91 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
729 724 0:95 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs ro
730 729 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
731 726 0:90 / /dev/shm rw,nosuid,nodev,noexec,relatime master:307 - tmpfs shm rw,size=65536k,inode64
732 724 0:24 /containers/storage/btrfs-containers/7211d9dae7861aee9695d6775838ed026e0aa35adba06e077c58a9a6470e141d/userdata/resolv.conf /etc/resolv.conf rw,nosuid,nodev,noexec master:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
733 724 0:24 /containers/storage/btrfs-containers/7211d9dae7861aee9695d6775838ed026e0aa35adba06e077c58a9a6470e141d/userdata/hostname /etc/hostname rw,nosuid,nodev master:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
734 724 0:35 /lib/kubelet/pods/395f906e-7c77-4c83-9472-361ea8819cea/etc-hosts /etc/hosts rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
735 726 0:35 /lib/kubelet/pods/395f906e-7c77-4c83-9472-361ea8819cea/containers/ubuntu/673eb8df /dev/termination-log rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
736 724 0:88 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=3623556k,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "7b05b98b56047ad0e02e55f4e6bcffbcdc436340179a9c05908df1e5d4f0710d" || !found { // container ID
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "7211d9dae7861aee9695d6775838ed026e0aa35adba06e077c58a9a6470e141d" || !found { // pod ID
		t.Errorf("detect wrong pod ID, cgroup: %v, %v\n", id, found)
	}
}

func TestCrio_Container_Cgroupv2(t *testing.T) {
	// crictl version: 1.22
	// OpenSuse Kubic cluster: 1.22.1
	// container process: /proc/<pid>
	cgroup := `
0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod042efd86_1f3b_4f2f_8736_f31c58e95bbc.slice/crio-f33f47b0db740bb647cb3e7ac62d96c74966dbb99cbfaf4563bfd42d387e8b44.scope
	`
	mountinfo := `
600 422 0:35 /lib/containers/storage/btrfs/subvolumes/b4a1f22c8a21a2efdb6ab0a29154f8cd54d3cf26863806028148b0308bf5f0fd / rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=266,subvol=/lib/containers/storage/btrfs/subvolumes/b4a1f22c8a21a2efdb6ab0a29154f8cd54d3cf26863806028148b0308bf5f0fd
601 600 0:82 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
602 600 0:83 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
603 602 0:84 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
604 602 0:70 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
605 600 0:25 /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod042efd86_1f3b_4f2f_8736_f31c58e95bbc.slice/crio-f33f47b0db740bb647cb3e7ac62d96c74966dbb99cbfaf4563bfd42d387e8b44.scope /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
606 600 0:21 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
607 602 0:69 / /dev/shm rw,nosuid,nodev,noexec,relatime master:278 - tmpfs shm rw,size=65536k,inode64
608 600 0:24 /containers/storage/btrfs-containers/a384237317c8537d2876f46e6b2902658396f5a64ee057db25e077f0b807c89d/userdata/resolv.conf /etc/resolv.conf rw,nosuid,nodev,noexec master:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
609 600 0:24 /containers/storage/btrfs-containers/a384237317c8537d2876f46e6b2902658396f5a64ee057db25e077f0b807c89d/userdata/hostname /etc/hostname rw,nosuid,nodev master:13 - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
619 600 0:24 /flannel /run/flannel rw,nosuid,nodev - tmpfs tmpfs rw,size=745192k,nr_inodes=819200,mode=755,inode64
636 600 0:35 /lib/kubelet/pods/042efd86-1f3b-4f2f-8736-f31c58e95bbc/volumes/kubernetes.io~configmap/flannel-cfg /etc/kube-flannel ro,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
637 600 0:35 /lib/kubelet/pods/042efd86-1f3b-4f2f-8736-f31c58e95bbc/etc-hosts /etc/hosts rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
638 602 0:35 /lib/kubelet/pods/042efd86-1f3b-4f2f-8736-f31c58e95bbc/containers/kube-flannel/cef02de9 /dev/termination-log rw,relatime - btrfs /dev/sda3 rw,space_cache,subvolid=5,subvol=/
639 600 0:60 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=51200k,inode64
423 601 0:82 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
424 601 0:82 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
425 601 0:82 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
426 601 0:82 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
427 601 0:82 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
428 601 0:85 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
429 601 0:83 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
430 601 0:83 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
431 601 0:83 /null /proc/latency_stats rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
566 601 0:83 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
569 601 0:86 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
570 606 0:87 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "f33f47b0db740bb647cb3e7ac62d96c74966dbb99cbfaf4563bfd42d387e8b44" || !found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "a384237317c8537d2876f46e6b2902658396f5a64ee057db25e077f0b807c89d" || !found { // pod ID
		t.Errorf("detect wrong pod ID, cgroup:  %v, %v\n", id, found)
	}
}

func TestCrio_CPath_Cgroupv2(t *testing.T) {
	// crictl version: 1.22
	// OpenSuse Kubic cluster: 1.22.1
	// container process: /proc/<pid>
	cgroup := `
0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod042efd86_1f3b_4f2f_8736_f31c58e95bbc.slice/crio-f33f47b0db740bb647cb3e7ac62d96c74966dbb99cbfaf4563bfd42d387e8b44.scope
	`
	r := strings.NewReader(cgroup)
	path := getCgroupPathReaderV2(r)
	if path != "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod042efd86_1f3b_4f2f_8736_f31c58e95bbc.slice/crio-f33f47b0db740bb647cb3e7ac62d96c74966dbb99cbfaf4563bfd42d387e8b44.scope" {
		t.Errorf("incorrect cgroup path: %v\n", path)
	}
}

func TestDockerK8s_CPath_SelfProbe_Cgroupv2(t *testing.T) {
	// docker : 20.10.7 ce
	// ubuntu 21.10
	// container process: /proc/self
	cgroup := `
	0::/
	`
	r := strings.NewReader(cgroup)
	path := getCgroupPathReaderV2(r)
	if path != "" {
		t.Errorf("incorrect cgroup path: %v\n", path)
	}
}

func TestDockerK8s_CPath_Container_Cgroupv2(t *testing.T) {
	// docker : 20.10.7 ce
	// ubuntu 21.10
	// container process: /proc/<pid>
	cgroup := `
0::/../../kubepods-besteffort-podfd698699_eabf_4c23_92ef_cf0bbdb78261.slice/docker-2cc65c162ca1388b6b8d5ccfb701d22fc96675ccf8b2f1590c490c2c4039547f.scope
	`
	r := strings.NewReader(cgroup)
	path := getCgroupPathReaderV2(r) // it is not inside the container
	if path != "" {
		t.Errorf("incorrect cgroup path: %v\n", path)
	}
}

func TestWorkingDir_btrfs(t *testing.T) {
	// docker Server Version: 20.10-ce
	// Storage Driver: btrfs
	mounts := `
/dev/sda2 / btrfs rw,relatime,space_cache,subvolid=433,subvol=/@/var/lib/docker/btrfs/subvolumes/4d81d4a2b9bc85afc82a8bc202bc6f7ee011bb6c437b383541fb5702afd41d58 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k,inode64 0 0
/dev/sda2 /app btrfs rw,relatime,space_cache,subvolid=267,subvol=/@/.snapshots/1/snapshot 0 0
/dev/sda2 /etc/resolv.conf btrfs rw,relatime,space_cache,subvolid=258,subvol=/@/var 0 0
/dev/sda2 /etc/hostname btrfs rw,relatime,space_cache,subvolid=258,subvol=/@/var 0 0
/dev/sda2 /etc/hosts btrfs rw,relatime,space_cache,subvolid=258,subvol=/@/var 0 0
devpts /dev/console devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
proc /proc/bus proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/fs proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/irq proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0
proc /proc/sysrq-trigger proc ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /proc/acpi tmpfs ro,relatime,inode64 0 0
tmpfs /proc/kcore tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/latency_stats tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/scsi tmpfs ro,relatime,inode64 0 0
tmpfs /sys/firmware tmpfs ro,relatime,inode64 0 0
`

	id := "00" // not used now
	res_rootfs := ""
	res_workingDir := "/var/lib/docker/btrfs/subvolumes/4d81d4a2b9bc85afc82a8bc202bc6f7ee011bb6c437b383541fb5702afd41d58"

	r := strings.NewReader(mounts)
	workingDir, rootfs, _ := readBtrfsWorkingPath(r, id)
	if rootfs != res_rootfs {
		t.Errorf("failed to obtain rootfs: %v\n", rootfs)
	}

	if workingDir != res_workingDir {
		t.Errorf("failed to obtain workingDir: %v\n", workingDir)
	}
}

func TestUpperDir_Overlay_MutipleMounts2(t *testing.T) {
	// Crio: 1.21
	// Storage Driver: overlay
	// oc pod: machine-config-daemon
	mounts := `
	/dev/sda4 / xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /etc xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	overlay /etc/NetworkManager/systemConnectionsMerged overlay rw,seclabel,relatime,lowerdir=/etc/NetworkManager/system-connections,upperdir=/run/nm-system-connections,workdir=/run/nm-system-connections-work 0 0
	/dev/sda4 /usr xfs ro,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /sysroot xfs ro,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
	securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
	tmpfs /sys/fs/cgroup tmpfs ro,seclabel,nosuid,nodev,noexec,mode=755 0 0
	cgroup /sys/fs/cgroup/systemd cgroup rw,seclabel,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
	cgroup /sys/fs/cgroup/memory cgroup rw,seclabel,nosuid,nodev,noexec,relatime,memory 0 0
	cgroup /sys/fs/cgroup/pids cgroup rw,seclabel,nosuid,nodev,noexec,relatime,pids 0 0
	cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,seclabel,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
	cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
	cgroup /sys/fs/cgroup/blkio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,blkio 0 0
	cgroup /sys/fs/cgroup/freezer cgroup rw,seclabel,nosuid,nodev,noexec,relatime,freezer 0 0
	cgroup /sys/fs/cgroup/perf_event cgroup rw,seclabel,nosuid,nodev,noexec,relatime,perf_event 0 0
	cgroup /sys/fs/cgroup/rdma cgroup rw,seclabel,nosuid,nodev,noexec,relatime,rdma 0 0
	cgroup /sys/fs/cgroup/cpuset cgroup rw,seclabel,nosuid,nodev,noexec,relatime,cpuset 0 0
	cgroup /sys/fs/cgroup/hugetlb cgroup rw,seclabel,nosuid,nodev,noexec,relatime,hugetlb 0 0
	cgroup /sys/fs/cgroup/devices cgroup rw,seclabel,nosuid,nodev,noexec,relatime,devices 0 0
	pstore /sys/fs/pstore pstore rw,seclabel,nosuid,nodev,noexec,relatime 0 0
	bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
	none /sys/kernel/tracing tracefs rw,seclabel,relatime 0 0
	configfs /sys/kernel/config configfs rw,relatime 0 0
	selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
	debugfs /sys/kernel/debug debugfs rw,seclabel,relatime 0 0
	fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0
	devtmpfs /dev devtmpfs rw,seclabel,nosuid,size=8157216k,nr_inodes=2039304,mode=755 0 0
	tmpfs /dev/shm tmpfs rw,seclabel,nosuid,nodev 0 0
	devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
	hugetlbfs /dev/hugepages hugetlbfs rw,seclabel,relatime,pagesize=2M 0 0
	mqueue /dev/mqueue mqueue rw,seclabel,relatime 0 0
	tmpfs /run tmpfs rw,seclabel,nosuid,nodev,mode=755 0 0
	shm /run/containers/storage/overlay-containers/58688a516052081917948beb43d8d527f4ab87bdcc47469bd53ce3695505899a/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c366,c947",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/c3ede37946e111e8fc1167f221fd0e882f912e1b7d0a1c80a7e68fa9be8a514c/userdata/shm tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/861c598c-420c-4093-8983-7deae358511b nsfs rw,seclabel 0 0
	nsfs /run/ipcns/861c598c-420c-4093-8983-7deae358511b nsfs rw,seclabel 0 0
	nsfs /run/netns/861c598c-420c-4093-8983-7deae358511b nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/a3dd9b7e063b219357076104baccc1680b35f83403d767ed509a1ccd6e3bcb91/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c14,c24",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/06c21eaf482d88eee2d0f4342ea8d7a097cca69c7c4b8f8293a5ab9f54c72179/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c541,c851",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/fdaca0243d8d0227aa8da70717790e0276ab6c30867feb733fcd8e96ebadf5cf/userdata/shm tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/6b1b4bc553727d910f8d338ca94c521b3ad49f7e27c1ed69b4bcdf6a47068588/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c4,c17",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/aeb84afe1f6a2bc719b79b56ce60a47b91cd4981718fd53f0eb7bfdd55dd1dd9/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/2df0c9d9be7c32d0cc497d8a783f0b730f878b76f8dbcbdef5bd30da2b952980/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/539b2690-c9f7-4fd6-87a6-ae19c459f6c4 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/539b2690-c9f7-4fd6-87a6-ae19c459f6c4 nsfs rw,seclabel 0 0
	nsfs /run/netns/539b2690-c9f7-4fd6-87a6-ae19c459f6c4 nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/5243653e13484d15d94c867ada606fbd4afd469bac22067457a33a1d8a14496c/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/ebc74697603ded65e3362ad21ad40c196fd2e2d36302f5ffeab5e8a1a90c96e6/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c9,c22",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/4922166cef98257b393557d976dc4f2575af23c3eabb41a8151032da9688908b/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c9,c22",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/81f3b980-3ed2-497a-b275-ca6e12259f4b nsfs rw,seclabel 0 0
	nsfs /run/ipcns/81f3b980-3ed2-497a-b275-ca6e12259f4b nsfs rw,seclabel 0 0
	nsfs /run/netns/81f3b980-3ed2-497a-b275-ca6e12259f4b nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/a7ea32d56d053b37911dad0b6e54c8c957e015e22362b920b7e1c80ff7b904be/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c4,c17",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/03272afb58a50492e0bd4d356ae9e79540ab92c89f7080fd3d512c3d840ea288/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/23986cbb6318cefe0ba57b1102fdeece2c680b98e22628e17d890d1805f9f152/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c25",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/c5f2fe8e841cc01be3b93ffabe86bc1b919aa1086d48a10a88b1b63537a7b925/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c102,c210",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/15da992408daa6f78df2351dd82815b014a3a082af3d3748cda007ef79933355/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c441,c714",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/71e7a93f-ba9e-4c60-914c-eb3c78201669 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/71e7a93f-ba9e-4c60-914c-eb3c78201669 nsfs rw,seclabel 0 0
	nsfs /run/netns/71e7a93f-ba9e-4c60-914c-eb3c78201669 nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/c276b872fd9fe4bcc52c1b4a6b1932ac429f5403dd0ed08235297f1822c42b05/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/78809b99da6079b332d199a9f2d3ebb03d2af92e5c59b6c8444b251401b714c2/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/9b82da4b2c6f762c231b3e96a2119742dfeb0082ee60020756f359c3f7686370/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c12,c18",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/85a26e51-2bbf-424e-b616-6aed877f10eb nsfs rw,seclabel 0 0
	nsfs /run/ipcns/85a26e51-2bbf-424e-b616-6aed877f10eb nsfs rw,seclabel 0 0
	nsfs /run/netns/85a26e51-2bbf-424e-b616-6aed877f10eb nsfs rw,seclabel 0 0
	nsfs /run/utsns/08e1d80c-0db7-4f4e-b934-5f4ddd3666f1 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/08e1d80c-0db7-4f4e-b934-5f4ddd3666f1 nsfs rw,seclabel 0 0
	nsfs /run/netns/08e1d80c-0db7-4f4e-b934-5f4ddd3666f1 nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/8975e24d8d319f75e242c89927c4448c1e3425d2c38068af8ed4f64931ef0bf4/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c19,c24",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/78a27ee9-4c9b-46c5-a6c8-56281e01cf1c nsfs rw,seclabel 0 0
	nsfs /run/ipcns/78a27ee9-4c9b-46c5-a6c8-56281e01cf1c nsfs rw,seclabel 0 0
	nsfs /run/netns/78a27ee9-4c9b-46c5-a6c8-56281e01cf1c nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/9b2973c22c7094907ead4685b640fd8cbe389c97316eb90d8cb7b6830de1e665/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/63740e64cfef7a589f1a5e006406363beb0e827348d862438c211b2958b87e95/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c299,c751",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/77786189-e72b-4d3a-983b-d4f626acd3e1 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/77786189-e72b-4d3a-983b-d4f626acd3e1 nsfs rw,seclabel 0 0
	nsfs /run/netns/77786189-e72b-4d3a-983b-d4f626acd3e1 nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/460d7d0cd0068fdb5762f104406cc42e0af827059d2e8db69e8631c171c505a8/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/6bc37d24e98d2ebb766d4c379d51cfb0338f82bce1e62176d79204af737192c5/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c43,c716",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/adb9833544d982350468a1741d52734d96446466c625544b82cc974657ebd669/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c4,c17",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/14b229ea6d25d458b61f939161cdd749f904ea0eb050b6f03f9882ad2a34adff/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/84138f017e19c942a372f3d501eb7926adaa2ff39aed8d8b926697f66141980d/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/36f28c83-fd4c-4935-be73-c86561a5a5c5 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/36f28c83-fd4c-4935-be73-c86561a5a5c5 nsfs rw,seclabel 0 0
	nsfs /run/netns/36f28c83-fd4c-4935-be73-c86561a5a5c5 nsfs rw,seclabel 0 0
	nsfs /run/utsns/3d6a578c-1aff-46ba-a1ac-693b591492d4 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/3d6a578c-1aff-46ba-a1ac-693b591492d4 nsfs rw,seclabel 0 0
	nsfs /run/netns/3d6a578c-1aff-46ba-a1ac-693b591492d4 nsfs rw,seclabel 0 0
	shm /run/containers/storage/overlay-containers/16631fad07dfb384f4d944d25531a61791c8be832dc09992cd87273339b19dbb/userdata/shm tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/f7a2509907896b6fba343b63af68b51d2c9022a0e37522c533a9c4a2bf1e29d3/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c25",nosuid,nodev,noexec,relatime,size=65536k 0 0
	shm /run/containers/storage/overlay-containers/f16d43c77339407744808de7646f207bdeb7ed0504b5d6ff766a7871ca976432/userdata/shm tmpfs rw,context="system_u:object_r:container_file_t:s0:c0,c21",nosuid,nodev,noexec,relatime,size=65536k 0 0
	nsfs /run/utsns/383592d5-331b-4042-b68c-b3d37cb93909 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/383592d5-331b-4042-b68c-b3d37cb93909 nsfs rw,seclabel 0 0
	nsfs /run/netns/383592d5-331b-4042-b68c-b3d37cb93909 nsfs rw,seclabel 0 0
	nsfs /run/utsns/d68d98be-e9dd-4449-93f3-1f43c6843632 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/d68d98be-e9dd-4449-93f3-1f43c6843632 nsfs rw,seclabel 0 0
	nsfs /run/netns/d68d98be-e9dd-4449-93f3-1f43c6843632 nsfs rw,seclabel 0 0
	nsfs /run/utsns/be78a4c4-77d5-46fd-ada7-ee9da3a0189b nsfs rw,seclabel 0 0
	nsfs /run/ipcns/be78a4c4-77d5-46fd-ada7-ee9da3a0189b nsfs rw,seclabel 0 0
	nsfs /run/netns/be78a4c4-77d5-46fd-ada7-ee9da3a0189b nsfs rw,seclabel 0 0
	nsfs /run/utsns/1ddae25a-d7c4-477f-8ee3-e64711fe5a7b nsfs rw,seclabel 0 0
	nsfs /run/ipcns/1ddae25a-d7c4-477f-8ee3-e64711fe5a7b nsfs rw,seclabel 0 0
	nsfs /run/netns/1ddae25a-d7c4-477f-8ee3-e64711fe5a7b nsfs rw,seclabel 0 0
	nsfs /run/utsns/a6958c39-624b-4422-bd9f-ad3c5f15ffc1 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/a6958c39-624b-4422-bd9f-ad3c5f15ffc1 nsfs rw,seclabel 0 0
	nsfs /run/netns/a6958c39-624b-4422-bd9f-ad3c5f15ffc1 nsfs rw,seclabel 0 0
	nsfs /run/utsns/c25274d0-a526-49ff-b2a1-4a9938712d1a nsfs rw,seclabel 0 0
	nsfs /run/ipcns/c25274d0-a526-49ff-b2a1-4a9938712d1a nsfs rw,seclabel 0 0
	nsfs /run/netns/c25274d0-a526-49ff-b2a1-4a9938712d1a nsfs rw,seclabel 0 0
	nsfs /run/utsns/e83dfa33-b87f-4451-ba43-fe1fae138a13 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/e83dfa33-b87f-4451-ba43-fe1fae138a13 nsfs rw,seclabel 0 0
	nsfs /run/netns/e83dfa33-b87f-4451-ba43-fe1fae138a13 nsfs rw,seclabel 0 0
	nsfs /run/utsns/590d19be-0e2f-4283-9867-eeb245e6c6d8 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/590d19be-0e2f-4283-9867-eeb245e6c6d8 nsfs rw,seclabel 0 0
	nsfs /run/netns/590d19be-0e2f-4283-9867-eeb245e6c6d8 nsfs rw,seclabel 0 0
	nsfs /run/utsns/83f94f65-0353-4834-a526-fd2dc7e00d85 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/83f94f65-0353-4834-a526-fd2dc7e00d85 nsfs rw,seclabel 0 0
	nsfs /run/netns/83f94f65-0353-4834-a526-fd2dc7e00d85 nsfs rw,seclabel 0 0
	nsfs /run/utsns/29536f3a-066c-4732-b2fb-fa54b5648707 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/29536f3a-066c-4732-b2fb-fa54b5648707 nsfs rw,seclabel 0 0
	nsfs /run/netns/29536f3a-066c-4732-b2fb-fa54b5648707 nsfs rw,seclabel 0 0
	nsfs /run/utsns/6cbc847a-1d84-43dc-8953-a7604eeb54f3 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/6cbc847a-1d84-43dc-8953-a7604eeb54f3 nsfs rw,seclabel 0 0
	nsfs /run/netns/6cbc847a-1d84-43dc-8953-a7604eeb54f3 nsfs rw,seclabel 0 0
	nsfs /run/utsns/5b2876be-9c76-4701-bd91-2c839c36c06b nsfs rw,seclabel 0 0
	nsfs /run/ipcns/5b2876be-9c76-4701-bd91-2c839c36c06b nsfs rw,seclabel 0 0
	nsfs /run/netns/5b2876be-9c76-4701-bd91-2c839c36c06b nsfs rw,seclabel 0 0
	nsfs /run/utsns/bbddb21d-e6f1-4c9b-9073-2d59df49b3e1 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/bbddb21d-e6f1-4c9b-9073-2d59df49b3e1 nsfs rw,seclabel 0 0
	nsfs /run/netns/bbddb21d-e6f1-4c9b-9073-2d59df49b3e1 nsfs rw,seclabel 0 0
	nsfs /run/utsns/f381243e-c033-4005-8d82-6e10a34659b8 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/f381243e-c033-4005-8d82-6e10a34659b8 nsfs rw,seclabel 0 0
	nsfs /run/netns/f381243e-c033-4005-8d82-6e10a34659b8 nsfs rw,seclabel 0 0
	nsfs /run/utsns/3a61e9f9-9ea3-4983-a10a-36f9309c121f nsfs rw,seclabel 0 0
	nsfs /run/ipcns/3a61e9f9-9ea3-4983-a10a-36f9309c121f nsfs rw,seclabel 0 0
	nsfs /run/netns/3a61e9f9-9ea3-4983-a10a-36f9309c121f nsfs rw,seclabel 0 0
	nsfs /run/utsns/12ecac15-f5d2-4926-89ff-714d13a05920 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/12ecac15-f5d2-4926-89ff-714d13a05920 nsfs rw,seclabel 0 0
	nsfs /run/netns/12ecac15-f5d2-4926-89ff-714d13a05920 nsfs rw,seclabel 0 0
	nsfs /run/utsns/e057fcc7-13a6-4965-a229-ef42383889a5 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/e057fcc7-13a6-4965-a229-ef42383889a5 nsfs rw,seclabel 0 0
	nsfs /run/netns/e057fcc7-13a6-4965-a229-ef42383889a5 nsfs rw,seclabel 0 0
	nsfs /run/utsns/23f18542-03e9-4da4-895b-efc37ed616dd nsfs rw,seclabel 0 0
	nsfs /run/ipcns/23f18542-03e9-4da4-895b-efc37ed616dd nsfs rw,seclabel 0 0
	nsfs /run/netns/23f18542-03e9-4da4-895b-efc37ed616dd nsfs rw,seclabel 0 0
	nsfs /run/utsns/497c6fc6-afa5-4861-b373-94c27a0b67b2 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/497c6fc6-afa5-4861-b373-94c27a0b67b2 nsfs rw,seclabel 0 0
	nsfs /run/netns/497c6fc6-afa5-4861-b373-94c27a0b67b2 nsfs rw,seclabel 0 0
	nsfs /run/utsns/0d10d2e7-093e-476b-9d3b-12bcb6113c88 nsfs rw,seclabel 0 0
	nsfs /run/ipcns/0d10d2e7-093e-476b-9d3b-12bcb6113c88 nsfs rw,seclabel 0 0
	nsfs /run/netns/0d10d2e7-093e-476b-9d3b-12bcb6113c88 nsfs rw,seclabel 0 0
	nsfs /run/utsns/6a911b47-c76d-4538-972c-60a14f07206f nsfs rw,seclabel 0 0
	nsfs /run/ipcns/6a911b47-c76d-4538-972c-60a14f07206f nsfs rw,seclabel 0 0
	nsfs /run/netns/6a911b47-c76d-4538-972c-60a14f07206f nsfs rw,seclabel 0 0
	proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
	systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=41,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=15032 0 0
	tmpfs /tmp tmpfs rw,seclabel,nosuid,nodev 0 0
	/dev/sda4 /var xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /var/lib/containers/storage/overlay xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	overlay /var/lib/containers/storage/overlay/0fc2eea34bc55c02a3e734c754444226bc9f13063d3e22716a84b3d2451fbd80/merged overlay rw,context="system_u:object_r:container_file_t:s0:c366,c947",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/0fc2eea34bc55c02a3e734c754444226bc9f13063d3e22716a84b3d2451fbd80/diff,workdir=/var/lib/containers/storage/overlay/0fc2eea34bc55c02a3e734c754444226bc9f13063d3e22716a84b3d2451fbd80/work 0 0
	overlay /var/lib/containers/storage/overlay/e23820188334478ed88eb12907b1791031bf90ac11dcc98604f0f614fc8e4714/merged overlay rw,context="system_u:object_r:container_file_t:s0:c411,c459",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/e23820188334478ed88eb12907b1791031bf90ac11dcc98604f0f614fc8e4714/diff,workdir=/var/lib/containers/storage/overlay/e23820188334478ed88eb12907b1791031bf90ac11dcc98604f0f614fc8e4714/work 0 0
	overlay /var/lib/containers/storage/overlay/d0e9c86c7570e5d054aba8851273d87f9cbe43fcedbc110ea3f3834cb429e47a/merged overlay rw,context="system_u:object_r:container_file_t:s0:c0,c683",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/d0e9c86c7570e5d054aba8851273d87f9cbe43fcedbc110ea3f3834cb429e47a/diff,workdir=/var/lib/containers/storage/overlay/d0e9c86c7570e5d054aba8851273d87f9cbe43fcedbc110ea3f3834cb429e47a/work 0 0
	overlay /var/lib/containers/storage/overlay/540f83df881c52f7f65a08567c97af4bdcc6216cb3335701a48b6634bd556941/merged overlay rw,context="system_u:object_r:container_file_t:s0:c441,c714",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/540f83df881c52f7f65a08567c97af4bdcc6216cb3335701a48b6634bd556941/diff,workdir=/var/lib/containers/storage/overlay/540f83df881c52f7f65a08567c97af4bdcc6216cb3335701a48b6634bd556941/work 0 0
	overlay /var/lib/containers/storage/overlay/48ca0ef70f4a2d2f25b6eb97333e36c573a209cea2542983f8ad63b47013f261/merged overlay rw,context="system_u:object_r:container_file_t:s0:c162,c405",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/48ca0ef70f4a2d2f25b6eb97333e36c573a209cea2542983f8ad63b47013f261/diff,workdir=/var/lib/containers/storage/overlay/48ca0ef70f4a2d2f25b6eb97333e36c573a209cea2542983f8ad63b47013f261/work 0 0
	overlay /var/lib/containers/storage/overlay/da0f0b093db65716988753ead3e6ab07a407b6805ba90da5acc21efd214615bd/merged overlay rw,context="system_u:object_r:container_file_t:s0:c102,c210",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/da0f0b093db65716988753ead3e6ab07a407b6805ba90da5acc21efd214615bd/diff,workdir=/var/lib/containers/storage/overlay/da0f0b093db65716988753ead3e6ab07a407b6805ba90da5acc21efd214615bd/work 0 0
	overlay /var/lib/containers/storage/overlay/732a8c35039144f16154551e73dd9ba4d4ed0e0d006eb804dcf7fe91ebdafb2b/merged overlay rw,context="system_u:object_r:container_file_t:s0:c569,c597",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/732a8c35039144f16154551e73dd9ba4d4ed0e0d006eb804dcf7fe91ebdafb2b/diff,workdir=/var/lib/containers/storage/overlay/732a8c35039144f16154551e73dd9ba4d4ed0e0d006eb804dcf7fe91ebdafb2b/work 0 0
	overlay /var/lib/containers/storage/overlay/c0c4483a78974c99497cd7719d7e5ba7057d3f58b53a9b45ad51fee191ea9178/merged overlay rw,context="system_u:object_r:container_file_t:s0:c19,c24",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/c0c4483a78974c99497cd7719d7e5ba7057d3f58b53a9b45ad51fee191ea9178/diff,workdir=/var/lib/containers/storage/overlay/c0c4483a78974c99497cd7719d7e5ba7057d3f58b53a9b45ad51fee191ea9178/work 0 0
	overlay /var/lib/containers/storage/overlay/85cad40c7d2ffd609cc41a350882e4deadd2be14ff1828788f45035cd51e8cd4/merged overlay rw,context="system_u:object_r:container_file_t:s0:c299,c751",relatime,lowerdir=/var/lib/containers/storage/overlay/l/ZOHQFFP6DNUZZII73VISP43FWT:/var/lib/containers/storage/overlay/l/QKE7WAAAABZLZDRCZ4R7246GPQ:/var/lib/containers/storage/overlay/l/IRD3CQIVJWKESQL4OBGFYGFMSR:/var/lib/containers/storage/overlay/l/ABFHB2YHGJQE3447IUXLWYI2M2:/var/lib/containers/storage/overlay/l/EFDMX3BHBG2L34QPVYSJFCLXQ6,upperdir=/var/lib/containers/storage/overlay/85cad40c7d2ffd609cc41a350882e4deadd2be14ff1828788f45035cd51e8cd4/diff,workdir=/var/lib/containers/storage/overlay/85cad40c7d2ffd609cc41a350882e4deadd2be14ff1828788f45035cd51e8cd4/work 0 0
	overlay /var/lib/containers/storage/overlay/d07f6e0925432844c7d7c85698fb5794f7ad2ede4066225d785dec82a5d1b987/merged overlay rw,context="system_u:object_r:container_file_t:s0:c366,c947",relatime,lowerdir=/var/lib/containers/storage/overlay/l/VLFJVHO3GAX6ORSBCTX3RYZ6QQ:/var/lib/containers/storage/overlay/l/2ELF657Y5OLDK7FCHGH5D72H65:/var/lib/containers/storage/overlay/l/DXG73U4ANCX3BLNDFYUOZI3PWN:/var/lib/containers/storage/overlay/l/2MFE53W2KO5V3TLKQFB4E4SFTG:/var/lib/containers/storage/overlay/l/RCENOS2O7PSNINC7ZQZFU52NEY,upperdir=/var/lib/containers/storage/overlay/d07f6e0925432844c7d7c85698fb5794f7ad2ede4066225d785dec82a5d1b987/diff,workdir=/var/lib/containers/storage/overlay/d07f6e0925432844c7d7c85698fb5794f7ad2ede4066225d785dec82a5d1b987/work 0 0
	overlay /var/lib/containers/storage/overlay/b17600ec08515f4b18ead9fc4aa62572a1372777132da4f1c5d8c5cdae4760ef/merged overlay rw,context="system_u:object_r:container_file_t:s0:c102,c210",relatime,lowerdir=/var/lib/containers/storage/overlay/l/5KFDTI7GO3E3PA3DKUL4DETGYN:/var/lib/containers/storage/overlay/l/2ELF657Y5OLDK7FCHGH5D72H65:/var/lib/containers/storage/overlay/l/DXG73U4ANCX3BLNDFYUOZI3PWN:/var/lib/containers/storage/overlay/l/2MFE53W2KO5V3TLKQFB4E4SFTG:/var/lib/containers/storage/overlay/l/RCENOS2O7PSNINC7ZQZFU52NEY,upperdir=/var/lib/containers/storage/overlay/b17600ec08515f4b18ead9fc4aa62572a1372777132da4f1c5d8c5cdae4760ef/diff,workdir=/var/lib/containers/storage/overlay/b17600ec08515f4b18ead9fc4aa62572a1372777132da4f1c5d8c5cdae4760ef/work 0 0
	overlay /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged overlay rw,context="system_u:object_r:container_file_t:s0:c720,c843",relatime,lowerdir=/var/lib/containers/storage/overlay/l/YD3YYD6KP6B3WUB3PYBELGZPI6:/var/lib/containers/storage/overlay/l/2ELF657Y5OLDK7FCHGH5D72H65:/var/lib/containers/storage/overlay/l/DXG73U4ANCX3BLNDFYUOZI3PWN:/var/lib/containers/storage/overlay/l/2MFE53W2KO5V3TLKQFB4E4SFTG:/var/lib/containers/storage/overlay/l/RCENOS2O7PSNINC7ZQZFU52NEY,upperdir=/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/diff,workdir=/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/work 0 0
	overlay /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged overlay rw,context="system_u:object_r:container_file_t:s0:c720,c843",relatime,lowerdir=/var/lib/containers/storage/overlay/l/YD3YYD6KP6B3WUB3PYBELGZPI6:/var/lib/containers/storage/overlay/l/2ELF657Y5OLDK7FCHGH5D72H65:/var/lib/containers/storage/overlay/l/DXG73U4ANCX3BLNDFYUOZI3PWN:/var/lib/containers/storage/overlay/l/2MFE53W2KO5V3TLKQFB4E4SFTG:/var/lib/containers/storage/overlay/l/RCENOS2O7PSNINC7ZQZFU52NEY,upperdir=/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/diff,workdir=/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/work 0 0
	proc /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/proc proc rw,nosuid,nodev,noexec,relatime 0 0
	tmpfs /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/dev tmpfs rw,seclabel,nosuid,size=65536k,mode=755 0 0
	devpts /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/dev/pts devpts rw,seclabel,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
	mqueue /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/dev/mqueue mqueue rw,seclabel,nosuid,nodev,noexec,relatime 0 0
	shm /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/dev/shm tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,size=65536k 0 0
	sysfs /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
	tmpfs /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,mode=755 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/systemd cgroup rw,seclabel,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/memory cgroup rw,seclabel,nosuid,nodev,noexec,relatime,memory 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/pids cgroup rw,seclabel,nosuid,nodev,noexec,relatime,pids 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/cpu,cpuacct cgroup rw,seclabel,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/net_cls,net_prio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/blkio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,blkio 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/freezer cgroup rw,seclabel,nosuid,nodev,noexec,relatime,freezer 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/perf_event cgroup rw,seclabel,nosuid,nodev,noexec,relatime,perf_event 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/rdma cgroup rw,seclabel,nosuid,nodev,noexec,relatime,rdma 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/cpuset cgroup rw,seclabel,nosuid,nodev,noexec,relatime,cpuset 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/hugetlb cgroup rw,seclabel,nosuid,nodev,noexec,relatime,hugetlb 0 0
	cgroup /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/sys/fs/cgroup/devices cgroup rw,seclabel,nosuid,nodev,noexec,relatime,devices 0 0
	tmpfs /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/etc/resolv.conf tmpfs rw,seclabel,nosuid,nodev,noexec,mode=755 0 0
	tmpfs /var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged/etc/hostname tmpfs rw,seclabel,nosuid,nodev,mode=755 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-prometheus-k8s-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-prometheus-k8s-thanos-sidecar-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~secret/secret-alertmanager-main-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/c22e676f-7936-4443-ade1-b9c268c9023f/volumes/kubernetes.io~secret/sdn-metrics-certs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-prometheus-k8s-htpasswd tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-grpc-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/9afd7e74-54c8-48f2-aaac-5b6cc103ae11/volumes/kubernetes.io~secret/default-certificate tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-thanos-querier-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e4b8ef89-fabb-48a7-9ccb-7188ecbeea14/volumes/kubernetes.io~secret/secret-grafana-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e4b8ef89-fabb-48a7-9ccb-7188ecbeea14/volumes/kubernetes.io~secret/grafana-config tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/3e2959ae-df82-45c8-8de7-65f408a4103c/volumes/kubernetes.io~secret/telemeter-client-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/tls-assets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/be3e0125-4eaa-46f9-9b7d-1c7ea478bb0a/volumes/kubernetes.io~secret/tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/config tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/3e2959ae-df82-45c8-8de7-65f408a4103c/volumes/kubernetes.io~secret/secret-telemeter-client tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/40150fa2-ff0e-42a3-bfef-5c2fef149d60/volumes/kubernetes.io~secret/metrics-certs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/a7cdb713-99c6-4efd-91d3-55f314f4b5dc/volumes/kubernetes.io~projected/registry-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/9afd7e74-54c8-48f2-aaac-5b6cc103ae11/volumes/kubernetes.io~secret/metrics-certs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/a7cdb713-99c6-4efd-91d3-55f314f4b5dc/volumes/kubernetes.io~secret/installation-pull-secrets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-kube-etcd-client-certs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e4b8ef89-fabb-48a7-9ccb-7188ecbeea14/volumes/kubernetes.io~secret/grafana-datasources tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~secret/secret-prometheus-k8s-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e4b8ef89-fabb-48a7-9ccb-7188ecbeea14/volumes/kubernetes.io~secret/secret-grafana-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4bac76dc-eead-418c-b8af-96b3c3d4c6b0/volumes/kubernetes.io~secret/node-exporter-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-thanos-querier-kube-rbac-proxy-rules tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-thanos-querier-oauth-htpasswd tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~secret/tls-assets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~secret/secret-alertmanager-main-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~secret/secret-alertmanager-main-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/05a61a92-e860-41b1-ad1b-05352eda2912/volumes/kubernetes.io~secret/cookie-secret tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-grpc-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~secret/secret-alertmanager-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/6f82d33c-9897-46d1-a837-363454bb6717/volumes/kubernetes.io~projected/kube-api-access-kb2rh tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/9afd7e74-54c8-48f2-aaac-5b6cc103ae11/volumes/kubernetes.io~secret/stats-auth tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-thanos-querier-oauth-cookie tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~secret/secret-alertmanager-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~secret/secret-alertmanager-main-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~secret/secret-thanos-querier-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/05a61a92-e860-41b1-ad1b-05352eda2912/volumes/kubernetes.io~secret/proxy-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/21f81d1c-8b52-4f50-af0a-997884e284af/volumes/kubernetes.io~secret/metrics-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e0fb5b7d-d585-4b89-ad39-38eebdd48673/volumes/kubernetes.io~secret/kube-state-metrics-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~secret/config-volume tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~secret/tls-assets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~secret/config-volume tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~secret/secret-alertmanager-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/30d92a25-2a5d-4562-b888-2270f684b1eb/volumes/kubernetes.io~projected/kube-api-access-kgfbh tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~secret/secret-alertmanager-main-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/c22e676f-7936-4443-ade1-b9c268c9023f/volumes/kubernetes.io~projected/kube-api-access-qvzkm tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~secret/tls-assets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~secret/config-volume tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~secret/secret-alertmanager-main-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/32b3a7b1-b8c3-482d-8997-37505ecdd1bb/volumes/kubernetes.io~secret/openshift-state-metrics-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/62f251b9-0c8b-4168-83ca-e95bb94994de/volumes/kubernetes.io~projected/kube-api-access-q6xtn tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/d4bbaadd-4fbc-4a65-a198-65d43ac44883/volumes/kubernetes.io~projected/kube-api-access-jwq5t tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7cda2a27-d760-439d-a35a-cf48ad09f796/volumes/kubernetes.io~projected/kube-api-access-zbbld tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/af369854-92f6-4d95-b56f-37ade3c43000/volumes/kubernetes.io~projected/kube-api-access-r9mgf tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/77a724f7-48c8-468f-b6b0-50158f852b21/volumes/kubernetes.io~projected/kube-api-access-zl6ms tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/32b3a7b1-b8c3-482d-8997-37505ecdd1bb/volumes/kubernetes.io~projected/kube-api-access-5gkwf tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/0e6273fd-ae4f-4f55-b2ee-7a999b789c18/volumes/kubernetes.io~projected/kube-api-access-8fthd tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7c01a046-572f-42d9-9b4e-47c8eee4ac70/volumes/kubernetes.io~projected/kube-api-access-kt2xs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/be3e0125-4eaa-46f9-9b7d-1c7ea478bb0a/volumes/kubernetes.io~projected/kube-api-access-vmbch tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/21f81d1c-8b52-4f50-af0a-997884e284af/volumes/kubernetes.io~projected/kube-api-access-8g49j tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e0fb5b7d-d585-4b89-ad39-38eebdd48673/volumes/kubernetes.io~projected/kube-api-access-ccctg tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4bac76dc-eead-418c-b8af-96b3c3d4c6b0/volumes/kubernetes.io~projected/kube-api-access-6hgft tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/480072dd-1b4a-4d9d-a4af-944656ccc448/volumes/kubernetes.io~projected/kube-api-access-m6sk9 tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/a7cdb713-99c6-4efd-91d3-55f314f4b5dc/volumes/kubernetes.io~projected/kube-api-access-sgmnt tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/config tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-prometheus-k8s-htpasswd tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-prometheus-k8s-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-kube-rbac-proxy tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-grpc-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/tls-assets tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-prometheus-k8s-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-prometheus-k8s-thanos-sidecar-tls tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~secret/secret-kube-etcd-client-certs tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/9afd7e74-54c8-48f2-aaac-5b6cc103ae11/volumes/kubernetes.io~projected/kube-api-access-8rtsl tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/9d02c1b4-77bc-4336-bd6f-2dbaea5faf53/volumes/kubernetes.io~projected/kube-api-access-kqr7h tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/45885bf7-719f-4328-acc0-73bc8d92e538/volumes/kubernetes.io~projected/kube-api-access-4jg8k tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/e4b8ef89-fabb-48a7-9ccb-7188ecbeea14/volumes/kubernetes.io~projected/kube-api-access-8ldgp tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volumes/kubernetes.io~projected/kube-api-access-qt85n tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/ee83aade-fd9e-43dc-9e87-3bbb9b26d3df/volumes/kubernetes.io~projected/kube-api-access-p28jw tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/40150fa2-ff0e-42a3-bfef-5c2fef149d60/volumes/kubernetes.io~projected/kube-api-access-gm5gl tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/3e2959ae-df82-45c8-8de7-65f408a4103c/volumes/kubernetes.io~projected/kube-api-access-c47pn tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/b2c226d0-59a5-41c3-b591-77730ed475e6/volumes/kubernetes.io~projected/kube-api-access-f78cv tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/16c7ab89-a5cd-4781-adbe-15106fd41711/volumes/kubernetes.io~projected/kube-api-access-jkrf7 tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/4532be57-6b3a-48e1-8523-7662406558c8/volumes/kubernetes.io~projected/kube-api-access-jhx49 tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/a7cdb713-99c6-4efd-91d3-55f314f4b5dc/volumes/kubernetes.io~projected/bound-sa-token tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/721d242c-c339-4b8c-bec4-de0b3f2b75a9/volumes/kubernetes.io~projected/kube-api-access-8ff7m tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/05a61a92-e860-41b1-ad1b-05352eda2912/volumes/kubernetes.io~projected/kube-api-access-4hmbp tmpfs rw,seclabel,relatime 0 0
	tmpfs /var/lib/kubelet/pods/7ff970d6-f92a-42bf-b73b-4ea9f7d8455d/volumes/kubernetes.io~projected/kube-api-access-f4scf tmpfs rw,seclabel,relatime 0 0
	/dev/sda4 /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volume-subpaths/etc/tuned/1 xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volume-subpaths/etc/tuned/2 xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volume-subpaths/etc/tuned/3 xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volume-subpaths/etc/tuned/4 xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda4 /var/lib/kubelet/pods/5991b76b-73e4-4773-8244-a3f7ec543915/volume-subpaths/etc/tuned/5 xfs rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota 0 0
	/dev/sda3 /boot ext4 ro,seclabel,nosuid,nodev,relatime 0 0
	tmpfs /run/secrets tmpfs rw,seclabel,nosuid,nodev,mode=755 0 0
	tmpfs /run/secrets/kubernetes.io/serviceaccount tmpfs ro,seclabel,relatime 0 0
	`

	id := "e00681fefce07e31233d07bca0730681a0a30591b57e5e255a04eb6a11cddc10"
	res_rootfs := "/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/merged"
	res_upper := "/var/lib/containers/storage/overlay/bd71ec861fd7bb0e1fec8ba016a2e02935d17941e9d3aa012b92428e268ddcf2/diff"

	r := strings.NewReader(mounts)
	upper, rootfs, _ := readUppperLayerPath(r, id)
	if rootfs != res_rootfs {
		t.Errorf("failed to obtain rootfs: %v\n", rootfs)
	}

	if upper != res_upper {
		t.Errorf("failed to obtain upperDir: %v\n", upper)
	}
}

func TestContainerd_Container_Cgroupv2(t *testing.T) {
	// crictl version: 1.24.0
	// containerd: 1.6.4
	// k8s: 1.24
	// container process: /proc/<pid>
	cgroup := `
	0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod9493223b_520e_4a97_a45f_359dcf967006.slice/cri-containerd-25d057a4c6c9555f2a0eb106e8896968c28f1c44aca4754174851aca7f89ad26.scope
	`
	mountinfo := `
	1350 1279 0:155 / / rw,relatime master:461 - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/67/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/66/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/65/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/64/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/63/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/62/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/61/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/60/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/59/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/58/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/93/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/93/work
	1351 1350 0:157 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
	1352 1350 0:158 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
	1353 1352 0:159 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
	1354 1352 0:146 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
	1355 1350 0:151 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
	1356 1355 0:28 /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod9493223b_520e_4a97_a45f_359dcf967006.slice/cri-containerd-25d057a4c6c9555f2a0eb106e8896968c28f1c44aca4754174851aca7f89ad26.scope /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw
	1357 1350 253:0 /var/lib/kubelet/pods/9493223b-520e-4a97-a45f-359dcf967006/etc-hosts /etc/hosts rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
	1358 1352 253:0 /var/lib/kubelet/pods/9493223b-520e-4a97-a45f-359dcf967006/containers/iperfserver/401d6fe2 /dev/termination-log rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
	1359 1350 253:0 /var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/f34e6ab6ed679d809c8d4a385777c4f72441f1d3ec7b1334d35c10f4d25e6f40/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
	1360 1350 253:0 /var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/f34e6ab6ed679d809c8d4a385777c4f72441f1d3ec7b1334d35c10f4d25e6f40/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
	1361 1352 0:143 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
	1362 1350 0:142 / /var/run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=8039888k,inode64
	1281 1351 0:157 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
	1282 1351 0:157 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
	1283 1351 0:157 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
	1284 1351 0:157 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
	1285 1351 0:157 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
	1286 1351 0:160 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
	1287 1351 0:158 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
	1288 1351 0:158 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
	1289 1351 0:158 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
	1290 1351 0:161 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
	1291 1355 0:162 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64
	`
	r := strings.NewReader(cgroup)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_cgroup)
	if id != "25d057a4c6c9555f2a0eb106e8896968c28f1c44aca4754174851aca7f89ad26" || !found {
		t.Errorf("detect wrong container ID, cgroup: %v, %v\n", id, found)
	}

	r = strings.NewReader(mountinfo)
	id, _, found = getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "f34e6ab6ed679d809c8d4a385777c4f72441f1d3ec7b1334d35c10f4d25e6f40" || !found { // pod ID
		t.Errorf("detect wrong pod ID, cgroup:  %v, %v\n", id, found)
	}
}

func TestK8sContainerdInDocker_Cgroupv2(t *testing.T) {
	// docker version: 25.0.4
	// containerd: v1.7.1
	// k8s: 1.28
	// container process: /proc/<pid>

	mountinfo := `
2911 1227 0:354 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/113/fs:/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/45/fs:/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/44/fs:/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/22/fs:/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/16/fs,upperdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/117/fs,workdir=/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/117/work,index=off,uuid=on
2913 2911 0:364 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
2918 2911 0:367 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
2922 2918 0:372 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
2928 2918 0:217 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
2932 2911 0:229 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
2934 2932 0:25 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
2938 2911 0:191 / /etc/config ro,relatime - tmpfs tmpfs rw,size=131639468k,inode64
2940 2911 259:3 /var/lib/docker/volumes/b0ee1af6a79635bcba4a66e30fb5e9d1d42dd828f2f79ce193f19186bdcef187/_data/pods/3b4761bd-6088-4844-9b6a-2cfb38b5dff1/etc-hosts /etc/hosts rw,relatime - ext4 /dev/nvme1n1p2 rw
2941 2918 259:3 /var/lib/docker/volumes/b0ee1af6a79635bcba4a66e30fb5e9d1d42dd828f2f79ce193f19186bdcef187/_data/pods/3b4761bd-6088-4844-9b6a-2cfb38b5dff1/containers/neuvector-controller-pod/d78e0e4b /dev/termination-log rw,relatime - ext4 /dev/nvme1n1p2 rw
2942 2911 259:3 /var/lib/docker/volumes/afa40c74a6c0dd0d639769d5c164f642c6154e769cc05b8436ec85214b7e13af/_data/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/d6fd144634f3c538705128592681c533d2c1907d2b6a574f24e79ad5eaf3a68e/hostname /etc/hostname rw,relatime - ext4 /dev/nvme1n1p2 rw
2943 2911 259:3 /var/lib/docker/volumes/afa40c74a6c0dd0d639769d5c164f642c6154e769cc05b8436ec85214b7e13af/_data/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/d6fd144634f3c538705128592681c533d2c1907d2b6a574f24e79ad5eaf3a68e/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/nvme1n1p2 rw
2944 2918 0:203 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
2947 2911 0:188 /..2024_04_03_01_49_30.49536134/ssl-cert.key /etc/neuvector/certs/ssl-cert.key ro,relatime - tmpfs tmpfs rw,size=131639468k,inode64
2948 2911 0:188 /..2024_04_03_01_49_30.49536134/ssl-cert.pem /etc/neuvector/certs/ssl-cert.pem ro,relatime - tmpfs tmpfs rw,size=131639468k,inode64
2949 2911 0:197 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=131639468k,inode64
1228 2913 0:364 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
1233 2913 0:364 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
1254 2913 0:364 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
1255 2913 0:364 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
1257 2913 0:364 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
1259 2913 0:376 / /proc/asound ro,relatime - tmpfs tmpfs ro,inode64
1260 2913 0:620 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
1262 2913 0:367 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
1264 2913 0:367 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
1269 2913 0:367 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
1281 2913 0:828 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
1282 2932 0:829 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64
	`
	r := strings.NewReader(mountinfo)
	id, _, found := getContainerIDByCgroupReaderV2(r, from_hostname)
	if id != "d6fd144634f3c538705128592681c533d2c1907d2b6a574f24e79ad5eaf3a68e" || !found {
		t.Errorf("detect wrong pod ID, mountinfo: %v, %v\n", id, found)
	}
}
