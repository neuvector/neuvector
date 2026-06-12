# NeuVector E2E Tests

End-to-end tests for NeuVector using [`sigs.k8s.io/e2e-framework`](https://github.com/kubernetes-sigs/e2e-framework).

## Prerequisites

- Docker (to build images and run KIND)
- [`kind`](https://kind.sigs.k8s.io/)
- `kubectl` and `helm`

## Running the tests

The top-level `Makefile` provides the standard entry point:

```sh
make test-e2e
```

This will:
1. Build `neuvector/controller` and `neuvector/enforcer` Docker images from source
2. Create a temporary KIND cluster
3. Load the locally built images into the cluster
4. Add the NeuVector Helm repo and install the `core` chart
5. Run the tests
6. Export cluster logs to `./logs/`
7. Uninstall the Helm release and destroy the cluster

### Environment variables

| Variable | Default (Makefile) | Description |
|----------|--------------------|-------------|
| `E2E_USE_EXISTING_CLUSTER` | _(unset)_ | Not supported right now |
| `E2E_NO_REBUILD` | _(unset)_ | Set to any non-empty value to skip rebuilding Docker images before the test run |

### Skip image rebuild

If you have already built images and just want to re-run the tests:

```sh
E2E_NO_REBUILD=true make test-e2e
```
## Logs

When running in KIND mode (the default), cluster logs are exported to `./logs/` after the tests complete — whether they pass or fail. This includes:

- Pod logs for all NeuVector components
- Kubelet and containerd logs
- KIND node journal

