# CIS Kubernetes Benchmark

![CIS Kubernetes Benchmark output](https://raw.githubusercontent.com/neuvector/kubernetes-cis-benchmark/master/bench.png "CIS Kubernetes Benchmark output")

This set of scripts can be used to check the Kubernetes installation against the best-practices.

### Supported CIS Kubernetes versions

| CIS Kubernetes Benchmark Version | Kubernetes versions |
|---|---|
| 1.0.0 | 1.6 |
| 1.2.0 | 1.8 |
| 1.5.1 | 1.15 |
| 1.6.0 | 1.16 - 1.18 |

### Running the benchmark checks

On the Kubernetes master nodes,
```
$ ./master.sh <CIS_Version>
```

On the Kubernetes worker nodes,
```
$ ./worker.sh <CIS_Version>
```

On the Kubernetes federation nodes,
```
$ ./federation.sh <CIS_Version>

