package registry

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockData struct {
	responseCode int
	response     string
	err          error
}

type mockTransport struct {
	data  []mockData
	index int
}

func newMockTransport() *mockTransport {
	return &mockTransport{}
}

func (t *mockTransport) AddMockData(data mockData) error {
	t.data = append(t.data, data)
	return nil
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create mocked http.Response
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: t.data[t.index].responseCode,
	}
	response.Header.Set("Content-Type", "application/json")
	response.Header.Set("www-authenticate", "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/ubuntu:pull\"")

	if t.data[t.index].err != nil {
		reterr := t.data[t.index].err
		t.index++
		return nil, reterr
	}

	response.Body = io.NopCloser(strings.NewReader(t.data[t.index].response))
	t.index++
	return response, nil
}

func TestDockerHubAuth(t *testing.T) {

	transport := newMockTransport()
	tokenTransport := TokenTransport{
		Transport: transport,
		Username:  "",
		Password:  "",
		Token:     "",
	}

	// From the output of `curl -v https://registry.hub.docker.com/v2/library/ubuntu/manifests/23.04`
	authService := authService{
		Realm:     "https://auth.docker.io/token",
		Service:   "registry.docker.io",
		Scope:     "repository:library/ubuntu:pull",
		dockerApi: true,
	}

	tcs := []struct {
		token       string
		responseMsg string
		errMsg      string
		mockdata    []mockData
	}{
		{
			token:       "",
			responseMsg: "",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"respose\": \"ok\"}",
				},
			},
		},
		{
			token:       "",
			responseMsg: "",
			errMsg:      "failed to authenticate: 429: {\"respose\": \"too many requests\"}",
			mockdata: []mockData{
				{
					responseCode: 429,
					response:     "{\"respose\": \"too many requests\"}",
				},
			},
		},
		{
			token:       "asd",
			responseMsg: "",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
			},
		},
	}

	for _, tc := range tcs {
		for _, md := range tc.mockdata {
			_ = transport.AddMockData(md)
		}
	}

	for _, tc := range tcs {
		token, resp, err := tokenTransport.auth(&authService)

		if tc.errMsg == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, tc.errMsg, err.Error())
		}

		if tc.responseMsg != "" {
			respMsg, readErr := io.ReadAll(resp.Body)
			assert.Nil(t, readErr)
			assert.Equal(t, tc.responseMsg, string(respMsg))
		} else {
			assert.Nil(t, resp)
		}

		assert.Equal(t, tc.token, token)
	}
}

func TestDockerHubReauth(t *testing.T) {

	transport := newMockTransport()
	tokenTransport := TokenTransport{
		Transport: transport,
		Username:  "",
		Password:  "",
		Token:     "",
	}

	// From the output of `curl -v https://registry.hub.docker.com/v2/library/ubuntu/manifests/23.04`
	authService := authService{
		Realm:     "https://auth.docker.io/token",
		Service:   "registry.docker.io",
		Scope:     "repository:library/ubuntu:pull",
		dockerApi: true,
	}

	req, err := http.NewRequest(http.MethodGet, "https://registry.hub.docker.com/v2/library/ubuntu/manifests/23.04", nil)
	assert.Nil(t, err)

	tcs := []struct {
		name        string
		token       string
		responseMsg string
		errMsg      string
		mockdata    []mockData
	}{
		{
			name:        "Happy case",
			token:       "",
			responseMsg: "{\"respose\": \"ok\"}",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 200,
					response:     "{\"respose\": \"ok\"}",
				},
			},
		},
		{
			name:        "Error happens in the auth request.  Should fail with err != nil",
			token:       "",
			responseMsg: "",
			errMsg:      "failed to authenticate: 401: I don't know you",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "I don't know you",
				},
			},
		},
		{
			name:        "Error happens in the following request.  Should return the error to caller to handle",
			token:       "",
			responseMsg: "no permission",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 403,
					response:     "no permission",
				},
			},
		},
		{
			name:        "Communication error in auth",
			token:       "",
			responseMsg: "",
			errMsg:      "Get \"https://auth.docker.io/token?scope=repository%3Alibrary%2Fubuntu%3Apull&service=registry.docker.io\": communication error in auth",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "",
					err:          errors.New("communication error in auth"),
				},
			},
		},
		{
			name:        "Communication error in request",
			token:       "",
			responseMsg: "",
			errMsg:      "communication error in req",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 200,
					response:     "",
					err:          errors.New("communication error in req"),
				},
			},
		},
	}

	for _, tc := range tcs {
		for _, md := range tc.mockdata {
			_ = transport.AddMockData(md)
		}
	}

	for _, tc := range tcs {
		t.Log(tc.name)
		resp, err := tokenTransport.authAndRetry(&authService, req)
		if tc.errMsg == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, tc.errMsg, err.Error())
		}

		if tc.responseMsg != "" {
			respMsg, readErr := io.ReadAll(resp.Body)
			assert.Nil(t, readErr)
			assert.Equal(t, tc.responseMsg, string(respMsg))
		} else {
			assert.Nil(t, resp)
		}
	}
}

func TestDockerHubRoundTrip(t *testing.T) {

	transport := newMockTransport()
	tokenTransport := TokenTransport{
		Transport: transport,
		Username:  "",
		Password:  "",
		Token:     "",
	}

	req, err := http.NewRequest(http.MethodGet, "https://registry.hub.docker.com/v2/library/ubuntu/manifests/23.04", nil)
	assert.Nil(t, err)

	tcs := []struct {
		name        string
		token       string
		responseMsg string
		errMsg      string
		mockdata    []mockData
	}{

		{
			name:        "Happy case",
			token:       "",
			responseMsg: "{\"respose\": \"ok\"}",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 200,
					response:     "{\"respose\": \"ok\"}",
				},
			},
		},
		{
			name:        "Happy case#2",
			token:       "",
			responseMsg: "{\"respose\": \"ok\"}",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "",
				},
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 200,
					response:     "{\"respose\": \"ok\"}",
				},
			},
		},
		{
			name:        "Other error in 1st request",
			token:       "",
			responseMsg: "I don't know you",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 403,
					response:     "I don't know you",
				},
			},
		},
		{
			name:        "Fail to authenticate",
			token:       "",
			responseMsg: "",
			errMsg:      "failed to authenticate: 429: Too many requests",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "",
				},
				{
					responseCode: 429,
					response:     "Too many requests",
				},
			},
		},
		{
			name:        "Fail in the last request",
			token:       "",
			responseMsg: "I don't know you",
			errMsg:      "",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "",
				},
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 403,
					response:     "I don't know you",
				},
			},
		},
		{
			name:        "Communication error#1",
			token:       "",
			responseMsg: "",
			errMsg:      "communication error",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "",
					err:          errors.New("communication error"),
				},
			},
		},
		{
			name:        "Communication error#2",
			token:       "",
			responseMsg: "",
			errMsg:      "Get \"https://auth.docker.io/token?scope=repository%3Alibrary%2Fubuntu%3Apull&service=registry.docker.io\": communication error2",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "no authentication",
				},
				{
					responseCode: 401,
					response:     "",
					err:          errors.New("communication error2"),
				},
			},
		},

		{
			name:        "Communication error#3",
			token:       "",
			responseMsg: "",
			errMsg:      "communication error3",
			mockdata: []mockData{
				{
					responseCode: 401,
					response:     "no authentication",
				},
				{
					responseCode: 200,
					response:     "{\"token\": \"asd\"}",
				},
				{
					responseCode: 403,
					response:     "",
					err:          errors.New("communication error3"),
				},
			},
		},
	}

	for _, tc := range tcs {
		for _, md := range tc.mockdata {
			_ = transport.AddMockData(md)
		}
	}

	for _, tc := range tcs {
		t.Log(tc.name)
		resp, err := tokenTransport.RoundTrip(req)
		if tc.errMsg == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, tc.errMsg, err.Error())
		}

		if tc.responseMsg != "" {
			respMsg, readErr := io.ReadAll(resp.Body)
			assert.Nil(t, readErr)
			assert.Equal(t, tc.responseMsg, string(respMsg))
		} else {
			assert.Nil(t, resp)
		}
	}
}
