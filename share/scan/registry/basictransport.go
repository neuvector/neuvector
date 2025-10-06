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
	oPublic := false
	nPublic := false
	publicDomains := []string{"redhat.com", "amazonaws.com", "azurecr.io", "docker.io", "docker.com", "icr.io", "gitlab.com"}
	for _, domain := range publicDomains {
		if strings.Contains(t.URL, domain) {
			oPublic = true
			break
		}
	}
	for _, domain := range publicDomains {
		if strings.Contains(req.URL.String(), domain) {
			nPublic = true
			break
		}
	}

	// log.WithFields(log.Fields{"req": req.URL.String(), "url": t.URL, "oPublic": oPublic, "nPublic": nPublic}).Debug()

	basicAuthSet := false
	// add auth header if redirect URL is same as the original; if not, re-auth unless neither original or redirecting URL is public
	if strings.HasPrefix(req.URL.String(), t.URL) || (!oPublic && !nPublic) {
		if t.Username != "" || t.Password != "" {
			req.SetBasicAuth(t.Username, t.Password)
			basicAuthSet = true
		}
	}
	resp, err := t.Transport.RoundTrip(req)
	if resp != nil {
		if resp.StatusCode == http.StatusBadRequest && basicAuthSet {
			req.Header.Del("Authorization")
			resp, err = t.Transport.RoundTrip(req)
		}
	}

	return resp, err
}
