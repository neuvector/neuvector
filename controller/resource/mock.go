package resource

type MockK8s kubernetes

func NewMockKK8sDriver(platform, flavor, network string) *MockK8s {
	d := &MockK8s{
		noop: newNoopDriver(platform, flavor, network),
	}
	return d
}
