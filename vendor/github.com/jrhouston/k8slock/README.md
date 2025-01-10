# k8slock [![Godoc](https://godoc.org/github.com/jrhouston/k8slock?status.svg)](https://godoc.org/github.com/jrhouston/k8slock) [![Go Report Card](https://goreportcard.com/badge/github.com/jrhouston/k8slock)](https://goreportcard.com/report/github.com/jrhouston/k8slock)

k8slock is a Go module that makes it easy to do distributed locking using the [Lease](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/lease-v1/) resource from the Kubernetes coordination API. 

If you want to use Kubernetes to create a simple distributed lock, this module is for you.

This module implements the [sync.Locker](https://golang.org/pkg/sync/#Locker) interface using the `Lock()` and `Unlock()` functions.

This module also supports using contexts via the `LockContext()` and `UnlockContext()` functions. 


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

## Basic Usage – Context

```go
package main

import (
    "context"
    "github.com/jrhouston/k8slock"
)

func main() {
    locker, err := k8slock.NewLocker("example-lock")
    if err != nil {
        panic(err)
    }

    ctx := context.Background()
    if err := locker.LockContext(ctx); err != nil {
        fmt.Println("Error trying to lock", err)
    }

    // do some work
    
    if err := locker.Unlock(ctx); err != nil {
        fmt.Println("Error trying to unlock", err)
    }
}
```

# Locker Options

The locker can be configured using the following [functional options](https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis):

| Option | Details |
|---|---|
| `TTL(duration)` | The duration until the lock expires and can be forcibly claimed. By default the lock can be held infinitely. |
| `RetryWaitDuration(duration)` | The duration to wait before retrying after failing to acquired the lock. Default: 1 second. |
| `InClusterConfig()` | Get the kubernetes client config from inside a pod. Defaults to a clientset using the local kubeconfig. |
| `Clientset(kubernetes.Interface)` | Configure a custom Kubernetes Clientset. Defaults to a clientset using the local kubeconfig. |
| `Namespace(string)` | The kubernetes namespace to store the Lease resource. Defaults to "default". |
| `ClientID(string)` | A unique ID for the client that is trying to obtain the lock. Defaults to a random UUID. |
| `CreateLease(bool)` | Create a Lease resource if it does not already exist. Defaults to `true`. |

e.g:

```go
locker, err := k8slock.NewLocker("example-lock", k8slock.Namespace("locks"), k8slock.ClientID("client-0"))
```
