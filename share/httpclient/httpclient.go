package httpclient

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

type TLSClientSettings struct {
	TLSconfig *tls.Config
}

// To protect sharedTLSConfig, sharedTransport and sharedNoProxyTransport.
var lock sync.RWMutex

var httpProxyConfig string
var httpsProxyConfig string

var sharedTLSConfig = &tls.Config{}
var transportCache map[string]*http.Transport

// Create a http.Transport with the default setting.
func newTransport() *http.Transport {
	// http.DefaultTransport in golang 1.22.
	return &http.Transport{
		MaxIdleConnsPerHost: 10,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// Convert share.CLUSProxy to a proxy url with username and password.
func ParseProxy(proxy *share.CLUSProxy) string {
	if proxy != nil && proxy.URL != "" && proxy.Enable {
		url, err := url.Parse(proxy.URL)
		if err != nil {
			return ""
		}
		if proxy.Username != "" {
			return fmt.Sprintf("%s://%s:%s@%s:%s/",
				url.Scheme, proxy.Username, proxy.Password, url.Hostname(), url.Port())
		} else {
			return fmt.Sprintf("%s://%s:%s/",
				url.Scheme, url.Hostname(), url.Port())
		}
	}
	return ""
}

// Get the proxy url configured based on target URL.
func GetProxy(targetURL string) (string, error) {
	lock.RLock()
	defer lock.RUnlock()

	u, err := url.Parse(targetURL)
	if err != nil {
		log.WithError(err).Warn("failed to parse target url")
		return "", fmt.Errorf("failed to parse target url: %w", err)
	}

	// Return configured proxy if enabled, otherwise return container runtime's settings
	proxy := ""
	if u.Scheme == "https" {
		proxy = httpsProxyConfig
	} else {
		proxy = httpProxyConfig
	}
	return proxy, nil
}

// Change TLS config and update related connection pools (http.Transport).
//
// noProxy has no effect for now.
//
// Note: When this function is called, a new set of connection pools will be created
// to prevent issue in the existing clients.
func SetDefaultTLSClientConfig(config *TLSClientSettings, httpProxy string, httpsProxy string, noProxy string) (err error) {
	lock.Lock()
	defer lock.Unlock()

	var httpProxyURL, httpsProxyURL *url.URL
	if httpsProxy != "" {
		// Examine inputs
		httpsProxyURL, err = url.Parse(httpsProxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy: %w", err)
		}
	}

	if httpProxy != "" {
		httpProxyURL, err = url.Parse(httpProxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy: %w", err)
		}

	}

	// Cleanup the existing cache and create a new one.
	// This will make the cache and its content (http.Transport) be GCed if they're not referenced anymore.
	tCache := make(map[string]*http.Transport)

	// Initialize https proxy's transport

	t := newTransport()
	t.TLSClientConfig = config.TLSconfig
	if httpsProxyURL != nil {
		t.Proxy = http.ProxyURL(httpsProxyURL)
	}
	tCache[httpsProxy] = t

	// Initialize http proxy's transport
	t = newTransport()
	t.TLSClientConfig = config.TLSconfig
	if httpProxyURL != nil {
		t.Proxy = http.ProxyURL(httpProxyURL)
	}
	tCache[httpProxy] = t

	// Initialize no proxy's transport
	t = newTransport()
	t.TLSClientConfig = config.TLSconfig
	t.Proxy = nil
	tCache[""] = t

	// Cache related settings
	httpProxyConfig = httpProxy
	httpsProxyConfig = httpsProxy

	sharedTLSConfig = config.TLSconfig
	transportCache = tCache

	return nil
}

// Get the shared http.Transport with the proxy url.
//
// Note that proxy url must contain user name and password.
// If there is no transport available, this function creates a new transport for it
// using shared TLS config.
func GetTransport(proxy string) (*http.Transport, error) {
	lock.RLock()
	defer lock.RUnlock()
	t, ok := transportCache[proxy]
	if !ok {
		t = newTransport()
		t.TLSClientConfig = sharedTLSConfig

		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				return nil, fmt.Errorf("failed to parse proxy: %w", err)
			}
			t.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return t, nil
}

// Get the current TLS config
//
// This function doesn't support proxy, so it's not recommended in most cases.
// Use GetSharedTransport() or CreateHTTPClient()instead.
func GetTLSConfig() *tls.Config {
	lock.RLock()
	defer lock.RUnlock()

	return sharedTLSConfig
}

// This function creates a HTTP client using GetTransport().
//
// Basically a wrapper of GetTransport().
// If the proxy setting doesn't exist, GetTransport() will create a new Transport for it.
func CreateHTTPClient(proxy string) (*http.Client, error) {
	lock.RLock()
	defer lock.RUnlock()

	transport, err := GetTransport(proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to get transport: %w", err)
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// Get HTTP proxy setting.
//
// A convenient function to get the latest setting without implementing consul config notification.
func GetHttpProxy() string {
	lock.RLock()
	defer lock.RUnlock()

	return httpProxyConfig
}

// Get HTTPS proxy setting.
//
// A convenient function to get the latest setting without implementing consul config notification.
func GetHttpsProxy() string {
	lock.RLock()
	defer lock.RUnlock()

	return httpsProxyConfig
}
