package healthz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/neuvector/neuvector/share/utils"
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
	if _, err := w.Write(buf); err != nil {
		log.WithError(err).Debug("failed to write healthz response")
	}
}

func StartHealthzServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", HealthzHandler)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		// This handles all errors in addition to the file not existing.
		if _, err := os.Stat(utils.ReadyFile); err != nil {
			log.WithError(err).Warn("ready file not accessible")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", healthzPort), mux)
}
