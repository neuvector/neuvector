package rest

import (
	"log"
	"os"
	"strings"
)

type HttpServerErrorWriter struct{}

func (*HttpServerErrorWriter) Write(b []byte) (int, error) {
	msg := string(b)
	if strings.Contains(msg, "http: TLS handshake error") && strings.HasSuffix(msg, ": EOF\n") {
		return 0, nil
	}

	return os.Stderr.Write(b)
}

func newHttpServerErrorWriter() *log.Logger {
	return log.New(&HttpServerErrorWriter{}, "", log.LstdFlags)
}
