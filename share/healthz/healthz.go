package healthz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

// A very simple healthz endpoint.
var data map[string]string
var lock sync.RWMutex

const healthzPort = 18500

func init() {
	data = make(map[string]string)
}

func UpdateStatus(key string, status string) {
	lock.Lock()
	defer lock.Unlock()
	data[key] = status
}

func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	lock.RLock()
	defer lock.RUnlock()
	buf, err := json.Marshal(data)
	if err != nil {
		// Write HTTP error
		log.WithError(err).Warn("failed to marshal healthz status")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

func StartHealthzServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", HealthzHandler)

	return http.ListenAndServe(fmt.Sprintf(":%d", healthzPort), mux)
}
