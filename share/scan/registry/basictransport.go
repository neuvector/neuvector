package registry

import (
	"net/http"
	"strings"
	// log "github.com/sirupsen/logrus"
)

type BasicTransport struct {
	Transport http.RoundTripper
	URL       string
	Username  string
	Password  string
}

func (t *BasicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// in the case of jfrog http redirect calls, basic auth is needed
	oPublic := strings.Contains(t.URL, "redhat.com") || strings.Contains(t.URL, "amazonaws.com") || strings.Contains(t.URL, "azurecr.io") ||
		strings.Contains(t.URL, "docker.io") || strings.Contains(t.URL, "docker.com") ||
		strings.Contains(t.URL, "icr.io") || strings.Contains(t.URL, "gitlab.com")
	nPublic := strings.Contains(req.URL.String(), "redhat.com") || strings.Contains(req.URL.String(), "amazonaws.com") || strings.Contains(req.URL.String(), "azurecr.io") ||
		strings.Contains(req.URL.String(), "docker.io") || strings.Contains(req.URL.String(), "docker.com") ||
		strings.Contains(req.URL.String(), "icr.io") || strings.Contains(req.URL.String(), "gitlab.com")

	// log.WithFields(log.Fields{"req": req.URL.String(), "url": t.URL, "oPublic": oPublic, "nPublic": nPublic}).Debug()

	// add auth header if redirect URL is same as the original; if not, re-auth unless neither original or redirecting URL is public
	if strings.HasPrefix(req.URL.String(), t.URL) || (!oPublic && !nPublic) {
		if t.Username != "" || t.Password != "" {
			req.SetBasicAuth(t.Username, t.Password)
		}
	}
	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}
