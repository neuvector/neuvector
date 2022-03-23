package httptrace

import (
	"io"
	"net/http"
	"time"
)

type HTTPTrace interface {
	SetPhase(message string)
	SendRequest(method, url string)
	// return a reader of the body content if the body is consumed; otherwise, return nil
	GotResponse(statusCode int, status string, header http.Header, body io.ReadCloser) io.Reader
	GotError(message string)
	AddComment(step, comment string)
}

type NopTracer struct {
}

func (t NopTracer) SetPhase(message string) {
}

func (t NopTracer) SendRequest(method, url string) {
}

func (t NopTracer) GotResponse(statusCode int, status string, header http.Header, body io.ReadCloser) io.Reader {
	return nil
}

func (t NopTracer) GotError(message string) {
}

func (t NopTracer) AddComment(step, message string) {
}

// --

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

func newNopCloser(r io.Reader) io.ReadCloser {
	return nopCloser{r}
}

type TraceClient struct {
	Trace  HTTPTrace
	Client *http.Client
}

func (tc TraceClient) response(resp *http.Response, err error) (*http.Response, error) {
	if err == nil {
		if r := tc.Trace.GotResponse(resp.StatusCode, resp.Status, resp.Header, resp.Body); r != nil {
			resp.Body = newNopCloser(r)
		}
	} else {
		tc.Trace.GotError(err.Error())
	}
	return resp, err
}

func (tc TraceClient) Get(url string) (*http.Response, error) {
	tc.Trace.SendRequest(http.MethodGet, url)
	resp, err := tc.Client.Get(url)
	return tc.response(resp, err)
}

func (tc TraceClient) Do(req *http.Request) (*http.Response, error) {
	tc.Trace.SendRequest(req.Method, req.URL.String())
	resp, err := tc.Client.Do(req)
	return tc.response(resp, err)
}

func (tc TraceClient) RoundTrip(req *http.Request) (*http.Response, error) {
	tc.Trace.SendRequest(req.Method, req.URL.String())
	resp, err := tc.Client.Transport.RoundTrip(req)
	return tc.response(resp, err)
}

func (tc TraceClient) Head(url string) (*http.Response, error) {
	tc.Trace.SendRequest(http.MethodHead, url)
	resp, err := tc.Client.Head(url)
	return tc.response(resp, err)
}

func (tc TraceClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	resp, err := tc.Client.Post(url, contentType, body)
	return tc.response(resp, err)
}

func (tc TraceClient) SetTimeout(timeout time.Duration) {
	tc.Client.Timeout = timeout
}
