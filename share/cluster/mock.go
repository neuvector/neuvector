package cluster

// --

type MockEvQueue struct {
}

func (evq *MockEvQueue) Append(interface{}) error {
	return nil
}

func (evq *MockEvQueue) Flush() error {
	return nil
}

// --

type MockMessenger struct {
}

func (msgr *MockMessenger) Unicast(target string, subject string, data []byte,
	cb UnicastCallback, timeout int, args ...interface{}) error {
	return nil
}

func (msgr *MockMessenger) UnicastStore(target string) string {
	return ""
}

func (msgr *MockMessenger) UnicastKey2Subject(key string) string {
	return ""
}

func (msgr *MockMessenger) UniackStore() string {
	return ""
}

func (msgr *MockMessenger) UniackUpdateHandler(nType ClusterNotifyType, key string, value []byte, unused uint64) {
}
