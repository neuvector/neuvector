package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

const dockerApiLogin = "https://hub.docker.com/v2/users/login/"

type TokenTransport struct {
	Transport http.RoundTripper
	Username  string
	Password  string
	Token     string
}

func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Token != "" {
		req.Header.Set("Authorization", t.Token)
	}

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if authService := isTokenDemand(resp); authService != nil {
		_, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			err = resp.Body.Close()
		}
		if err != nil {
			return nil, fmt.Errorf("http: failed to close token demand response (status=%v, err=%q)", resp.StatusCode, err)
		}
		resp, err = t.authAndRetry(authService, req)
	}
	return resp, err
}

type authToken struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func (t *TokenTransport) authAndRetry(authService *authService, req *http.Request) (*http.Response, error) {
	token, authResp, err := t.auth(authService)
	if err != nil {
		return authResp, err
	}

	retryResp, err := t.retry(req, token)
	return retryResp, err
}

func (t *TokenTransport) auth(authService *authService) (string, *http.Response, error) {
	authReq, err := authService.Request(t.Username, t.Password)
	if err != nil {
		return "", nil, err
	}

	client := http.Client{
		Transport: t.Transport,
	}

	response, err := client.Do(authReq)
	if err != nil {
		return "", nil, err
	}

	if response.StatusCode != http.StatusOK {
		return "", response, err
	}
	defer response.Body.Close()

	var authToken authToken
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&authToken)
	if err != nil {
		return "", nil, err
	}

	if authToken.Token != "" {
		return authToken.Token, nil, nil
	} else {
		return authToken.AccessToken, nil, nil
	}
}

func (t *TokenTransport) retry(req *http.Request, token string) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := t.Transport.RoundTrip(req)
	return resp, err
}

type authService struct {
	Realm     string
	Service   string
	Scope     string
	dockerApi bool
}

func (authService *authService) Request(username, password string) (*http.Request, error) {
	url, err := url.Parse(authService.Realm)
	if err != nil {
		return nil, err
	}

	q := url.Query()
	if authService.Service != "" {
		q.Set("service", authService.Service)
	}
	if authService.Scope != "" {
		q.Set("scope", authService.Scope)
	}
	url.RawQuery = q.Encode()

	var data []byte

	if authService.dockerApi {
		data = []byte(fmt.Sprintf("{\"username\": \"%s\", \"password\": \"%s\"}", username, password))
	}

	request, err := http.NewRequest("GET", url.String(), bytes.NewReader(data))

	if authService.dockerApi {
		request.Header.Set("Content-Type", "application/json")
	}

	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}

	return request, err
}

func isTokenDemand(resp *http.Response) *authService {
	if resp == nil {
		return nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	return parseOauthHeader(resp)
}

func parseOauthHeader(resp *http.Response) *authService {
	challenges := parseAuthHeader(resp.Header)
	for _, challenge := range challenges {
		if challenge.Scheme == "bearer" {
			return &authService{
				Realm:   challenge.Parameters["realm"],
				Service: challenge.Parameters["service"],
				Scope:   challenge.Parameters["scope"],
			}
		} else if challenge.Scheme == "jwt" && challenge.Parameters["realm"] == "api" {
			return &authService{
				Realm:     dockerApiLogin,
				dockerApi: true,
			}
		}
	}
	return nil
}
