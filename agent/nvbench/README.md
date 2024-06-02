# CIS Benchmark

![CIS Benchmark output](https://raw.githubusercontent.com/neuvector/kubernetes-cis-benchmark/master/bench.png "CIS Benchmark output")

This set of scripts can be used to check the Kubernetes installation against the best-practices.


## How it trigger
When the enforcer pod start, it read the environment then deicde which benchmark it run then generated report.

## Supported CIS Kubernetes Benchmark versions
| CIS Kubernetes Benchmark Version | Kubernetes versions |
|---|---|
| 1.0.0 | 1.6 |
| 1.2.0 | 1.8 |
| 1.5.1 | 1.15 |
| 1.6.0 | 1.16 - 1.18 |
| 1.23 | 1.19 - 1.23 |
| 1.24 | 1.24 |
| 1.8.0 | 1.27+ |

| CIS Kubernetes Benchmark Version on Cloud| Kubernetes versions |
|---|---|
| EKS-1.4.0 | Any |
| AKS-1.4.0 | Any |
| GKE-1.4.0 | 1.24+ |
| GKE-1.4.0 | 1.23 |

| CIS OpenShift Benchmark Version | OpenShift versions |
|---|---|
| 1.0.0 | 4.3 |
| 1.1.0 | 4.4 - 4.5 |
| 1.4.0 | 4.6+ |

## How it run?
1. enter to your enforcer pod ```/tmp```, you should see the following
   ``` shell
    /tmp # tree .

    ├── kube_master.sh
    ├── kube_worker.sh
    ├── cis-1.23
    │   ├── master
    │   │   ├── 1_control_plane_components.yaml
    │   │   ├── 2_etcd.yaml
    │   │   ├── 3_control_plane_configuration.yaml
    │   │   └── 5_policies.yaml
    │   └── worker
    │       └── 4_worker_nodes.yaml
    ├── cis-1.24
    │   ├── master
    │   │   ├── 1_control_plane_components.yaml
    │   │   ├── 2_etcd.yaml
    │   │   ├── 3_control_plane_configuration.yaml
    │   │   └── 5_policies.yaml
    │   └── worker
    │       └── 4_worker_nodes.yaml
    ├── cis-1.6.0
    │   ├── master
    │   │   ├── 1_control_plane_components.yaml
    │   │   ├── 2_etcd.yaml
    │   │   ├── 3_control_plane_configuration.yaml
    │   │   └── 5_policies.yaml
    │   └── worker
    │       └── 4_worker_nodes.yaml
    ├── cis-1.8.0
    │   ├── master
    │   │   ├── 1_control_plane_components.yaml
    │   │   ├── 2_etcd.yaml
    │   │   ├── 3_control_plane_configuration.yaml
    │   │   └── 5_policies.yaml
    │   └── worker
    │       └── 4_worker_nodes.yaml
    ├── rh-1.4.0
    │   ├── master
    │   │   ├── 1_control_plane_components.yaml
    │   │   ├── 2_etcd.yaml
    │   │   ├── 3_control_plane_configuration.yaml
    │   │   └── 5_policies.yaml
    │   └── worker
    │       └── 4_worker_nodes.yaml
    ├── utils
    │   ├── logger.sh
    │   ├── style.sh
    │   └── utils.sh
   ```
2. ```sh kube_master.sh / kube_worker.sh folder``` => the folder represents the cis version to the environment => e.g. ```sh kube_master.sh /tmp/cis-1.8.0/master/```
3. if you are using the older version, kubernetes < 1.16, then you are unable to run in this way, please contact us for help.

## Note
if modify Docker, Kubernetes benchmark before 1.5.1(include) or OpenShift benchmark before 1.1.0(include)
- After update bench submodule, run ```gen_bench.sh``` to re-generate container.tmpl and host.tmpl files.
