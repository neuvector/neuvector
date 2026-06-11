# Neuvector API

This package provides the NeuVector API definition to manipulate the custom resource in golang.  To use it,

```
import (
    nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
)

func main() {
    _ = nvv1.AddToScheme(scheme.Scheme)
}

```

## How to update generated files

```
controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
```
