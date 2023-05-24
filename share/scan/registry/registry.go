package registry

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/httptrace"
)

const (
	ErrorNone uint = iota
	ErrorCertificate
	ErrorAuthentication
	ErrorUrl
	ErrorUnknown
)

type Registry struct {
	URL    string
	Client *httptrace.TraceClient
}

const nonDataTimeout = 20 * time.Second
const longTimeout = 300 * time.Second

func NewSecure(registryUrl, token, username, password, proxy string, trace httptrace.HTTPTrace) (*Registry, uint, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	if proxy != "" {
		pxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, ErrorUrl, err
		}
		transport.Proxy = http.ProxyURL(pxyUrl)
	}

	r := newFromTransport(registryUrl, token, username, password, transport, trace)
	return r, ErrorNone, nil
}

/*
 * Create a new Registry, as with New, using an http.Transport that disables
 * SSL certificate verification.
 */
func NewInsecure(registryUrl, token, username, password, proxy string, trace httptrace.HTTPTrace) (*Registry, uint, error) {
	// same as http.DefaultTransport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	if proxy != "" {
		pxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, ErrorUrl, err
		}
		transport.Proxy = http.ProxyURL(pxyUrl)
	}

	r := newFromTransport(registryUrl, token, username, password, transport, trace)
	return r, ErrorNone, nil
}

/*
 * Given an existing http.RoundTripper such as http.DefaultTransport, build the
 * transport stack necessary to authenticate to the Docker registry API. This
 * adds in support for OAuth bearer tokens and HTTP Basic auth, and sets up
 * error handling this library relies on.
 */
func wrapTransport(transport http.RoundTripper, url, token, username, password string) http.RoundTripper {
	tokenTransport := &TokenTransport{
		Transport: transport,
		Token:     token,
		Username:  username,
		Password:  password,
	}
	basicAuthTransport := &BasicTransport{
		Transport: tokenTransport,
		URL:       url,
		Username:  username,
		Password:  password,
	}
	errorTransport := &ErrorTransport{
		Transport: basicAuthTransport,
	}
	return errorTransport
}

// Let client handle POST redirect
func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	for _, v := range via {
		if req.Method == http.MethodGet && v.Method == http.MethodPost {
			return http.ErrUseLastResponse
		}
	}

	return nil
}

func newFromTransport(registryUrl, token, username, password string, transport http.RoundTripper, trace httptrace.HTTPTrace) *Registry {
	url := strings.TrimSuffix(registryUrl, "/")
	transport = wrapTransport(transport, url, token, username, password)

	return &Registry{
		URL: url,
		Client: &httptrace.TraceClient{
			Trace: trace,
			Client: &http.Client{
				Timeout:       nonDataTimeout,
				Transport:     transport,
				CheckRedirect: redirectPolicyFunc,
			},
		},
	}
}

func (r *Registry) url(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", r.URL, pathSuffix)
	return url
}

func (r *Registry) Ping() (uint, error) {
	url := r.url("/v2/")

	resp, err := r.Client.Get(url)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		return ErrorNone, nil
	} else if strings.Contains(err.Error(), "x509:") {
		// if it's x509 certificate error, return failed. so we will start insecure connection
		log.WithFields(log.Fields{"error": err}).Error()
		return ErrorCertificate, err
	} else if strings.Contains(err.Error(), "UNAUTHORIZED") {
		log.WithFields(log.Fields{"error": err}).Error()
		return ErrorAuthentication, err
	}
	return ErrorUnknown, err
}
