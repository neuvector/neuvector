<img src="https://img.shields.io/badge/go%20version-min%201.21-green" alt="Go version"/>

# go-clientsyslog

Syslog client in Go

- Transport: UDP/TCP and TLS transport
- Formater: Unix, RFC3164, RFC5424
- Framing support: RFC5425

This package is a fork of the public archive [srslog](https://github.com/RackSec/srslog)

## Basic usage

Basic usage retains the same interface as the original `syslog` package. We
only added to the interface where required to support new functionality.

Switch from the standard library:

```golang
import(
    //"log/syslog"
    syslog "github.com/dmachard/go-clientsyslog"
)
```

You can still use it for local syslog:

```golang
w, err := syslog.Dial("", "", syslog.LOG_ERR, "testtag")
```

Or to unencrypted UDP:

```golang
w, err := syslog.Dial("udp", "192.168.0.50:514", syslog.LOG_ERR, "testtag")
```

Or to unencrypted TCP:

```golang
w, err := syslog.Dial("tcp", "192.168.0.51:514", syslog.LOG_ERR, "testtag")
```

## TLS encryption

But now you can also send messages via TLS-encrypted TCP:

```golang
w, err := syslog.DialWithTLSCertPath("tcp+tls", "192.168.0.52:514", syslog.LOG_ERR, "testtag", "/path/to/servercert.pem")
```

And if you need more control over your TLS configuration :

```golang
pool := x509.NewCertPool()
serverCert, err := os.ReadFile("/path/to/servercert.pem")
if err != nil {
    return nil, err
}
pool.AppendCertsFromPEM(serverCert)
config := tls.Config{
    RootCAs: pool,
}

w, err := DialWithTLSConfig(network, raddr, priority, tag, &config)
```


And then to write log messages, continue like so:

```golang
if err != nil {
    log.Fatal("failed to connect to syslog:", err)
}
defer w.Close()

w.Alert("this is an alert")
w.Crit("this is critical")
w.Err("this is an error")
w.Warning("this is a warning")
w.Notice("this is a notice")
w.Info("this is info")
w.Debug("this is debug")
w.Write([]byte("these are some bytes"))
```

If you need further control over connection attempts, you can use the DialWithCustomDialer
function. To continue with the DialWithTLSConfig example:

```golang
netDialer := &net.Dialer{Timeout: time.Second*5} // easy timeouts
realNetwork := "tcp" // real network, other vars your dail func can close over
dial := func(network, addr string) (net.Conn, error) {
    // cannot use "network" here as it'll simply be "custom" which will fail
    return tls.DialWithDialer(netDialer, realNetwork, addr, &config)
}

w, err := DialWithCustomDialer("custom", "192.168.0.52:514", syslog.LOG_ERR, "testtag", dial)
```

Your custom dial func can set timeouts, proxy connections, and do whatever else it needs before returning a net.Conn.

## Custom config

Set custom formatter

```golang
w, err := syslog.Dial("", "", syslog.LOG_ERR, "test")
w.SetFormatter(syslog.RFC3164Formatter)
```

Set custom framer

```golang
w, err := syslog.Dial("", "", syslog.LOG_ERR, "test")
w.SetFramer(syslog.RFC5425MessageLengthFramer)
```

Set custom hostname

```golang
w, err := syslog.Dial("", "", syslog.LOG_ERR, "test")
w.SetHostname("hostname")
```

Set custom program name

```golang
w, err := syslog.Dial("", "", syslog.LOG_ERR, "test")
w.SetProgram("program")
```

## Running Tests

Run the tests as usual:

```bash
go test
```
