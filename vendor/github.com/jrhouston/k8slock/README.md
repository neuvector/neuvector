# k8slock [![Godoc](https://godoc.org/github.com/jrhouston/k8slock?status.svg)](https://godoc.org/github.com/jrhouston/k8slock) [![Go Report Card](https://goreportcard.com/badge/github.com/jrhouston/k8slock)](https://goreportcard.com/report/github.com/jrhouston/k8slock)

k8slock is a Go module that enables distributed locking by implementing the [sync.Locker](https://golang.org/pkg/sync/#Locker) interface using the the [Lease](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#lease-v1-coordination-k8s-io) resource from the Kubernetes coordination API. 

If you want to use Kubernetes to create a simple distributed lock, this module is for you.


## Basic Usage

```go
package main

import "github.com/jrhouston/k8slock"

func main() {
    locker, err := k8slock.NewLocker("example-lock")
    if err != nil {
        panic(err)
    }

    locker.Lock()
    // do some work
    locker.Unlock()
}
```

# Locker Options

The locker can be configured using the following [functional options](https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis):

| Option | Details |
|---|---|
| `TTL(duration)` | The duration until the lock expires and can be forcibly claimed. By default the lock can be held infinitely. |
| `RetryWaitDuration(duration)` | The duration to wait before retrying after failing to acquired the lock. Default: 1 second. |
| `InClusterConfig()` | Get the kubernetes client config from inside a pod. Defaults to a clientset using the local kubeconfig. |
| `Clientset(*kubernetes.Clientset)` | Configure a custom Kubernetes Clientset. Defaults to a clientset using the local kubeconfig. |
| `Namespace(string)` | The kubernetes namespace to store the Lease resource. Defaults to "default". |
| `ClientID(string)` | A unique ID for the client that is trying to obtain the lock. Defaults to a random UUID. |

e.g:

```go
locker, err := k8slock.NewLocker("example-lock", k8slock.Namespace("locks"), k8slock.ClientID("client-0"))
```
