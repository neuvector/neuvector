# HTTP client

This package provides common http.Transport(s)/connection pools to be used by NV. To use this package, follow below steps:

## Implement config update callback.

When proxy or TLS config is changed, SetDefaultTLSClientConfig() should be called.  For example, the below snippet parses config and set the default TLS config.

```
		var pool *x509.CertPool

		if cfg.GlobalCaCerts != "" {
			pool = x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(cfg.GlobalCaCerts))
		}

		httpProxy := httpclient.ParseProxy(&cfg.RegistryHttpProxy)
		httpsProxy := httpclient.ParseProxy(&cfg.RegistryHttpsProxy)
		var noProxy string

		httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				InsecureSkipVerify: !cfg.EnableTLSVerification,
				RootCAs:            pool,
			},
		}, httpProxy, httpsProxy, noProxy)
```

For some use case where no config is involved, e.g., standalone scanner, httpclient should still be initialized by using below snippet:

```
		// Default TLS config
		httpclient.SetDefaultTLSClientConfig(&httpclient.TLSClientSettings{
			TLSconfig: &tls.Config{
				// Your TLS config
			},
		}, "", "", "")
```

## http.Client implementation

Due to different implementations of http clients, this package provides a few methods to share http.Transport.

### GetTransport()

In NeuVector, proxy can be enabled/disabled in per-resource based.  For example, each registry can have different setting even when they connect to the same endpoints.  For these components that have their own http.Client, but would like to share a connection pool by using this package, use code similar to the snippet below:

```
	client := &http.Client{
		Timeout: requestTimeout,
	}

	proxyURL := httpclient.ParseProxy(proxy)
	t, err := httpclient.GetTransport(proxyURL)
	if err != nil {
        ...
	}
	client.Transport = t
```

This way, the shared http.Transport will be used depending on each function's proxy setting.

Similarly, you can use CreateHTTPClient() to create a HTTP client with the default setting.

### GetTLSConfig()

In some connections that are based on TLS but not HTTP, you can still utilize the shared TLSConfig by using GetTLSConfig().

Note that when with this method, proxy settings will not be honored. 

## Reference

https://pkg.go.dev/net/http#Transport

> Transports should be reused instead of created as needed. Transports are safe for concurrent use by multiple goroutines.

