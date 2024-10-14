package resource

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

const (
	// openshiftServer = "openshift"

	openshiftOAuthDiscoverURL    = "%s/.well-known/oauth-authorization-server"
	openshiftOAuthDefaultURL     = "%s/oauth/authorize"
	openshiftOAuthChallengeQuery = "response_type=token&client_id=openshift-challenging-client"
	openshiftOAuthLogoutURL      = "%s/apis/oauth.openshift.io/v1/oauthaccesstokens/%s"
)

// Location: https://xxxxxx:8443/oauth/token/implicit#access_token=f2NHwqzA1VsMlo88m_e1_qItJTpfQF6lwXAwubvV3Y0&expires_in=86400&scope=user%3Afull&token_type=Bearer
func parseOpenShiftAccessTokenHeader(resp *http.Response) (string, error) {
	log.WithFields(log.Fields{"status": resp.Status}).Debug()
	if resp.StatusCode != http.StatusFound {
		return "", errors.New("Unexpected response status")
	}

	loc, err := resp.Location()
	if err != nil {
		return "", err
	}

	s := loc.String()
	// log.WithFields(log.Fields{"location": s}).Debug()

	u, err := url.Parse(strings.Replace(s, "#", "?", 1))
	if err != nil {
		return "", err
	}

	q := u.Query()
	if values, ok := q["token_type"]; !ok || len(values) < 1 {
		return "", errors.New("Unable to parse token type")
	} else if values[0] != "Bearer" {
		return "", errors.New("Unexpected token type")
	}

	if values, ok := q["access_token"]; !ok || len(values) < 1 {
		return "", errors.New("Unable to parse access token")
	} else {
		return values[0], nil
	}
}

type discoverResp struct {
	Issuer  string `json:"issuer"`
	AuthzEP string `json:"authorization_endpoint"`
	TokenEP string `json:"token_endpoint"`
}

func discoverAuthzEndpoint(endpoint string) (string, error) {
	cfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{
		Transport: cfg,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf(openshiftOAuthDiscoverURL, endpoint)
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	r.Header.Set("X-CSRF-Token", "1")

	resp, err := c.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var disc discoverResp
	err = json.Unmarshal(body, &disc)
	if err != nil {
		return "", err
	}

	return disc.AuthzEP, nil
}

func loginOpenShift(endpoint, username, password string) (*http.Response, error) {
	url := fmt.Sprintf("%s?%s", endpoint, openshiftOAuthChallengeQuery)

	cfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{
		Transport: cfg,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	r, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}

	r.SetBasicAuth(username, password)
	r.Header.Set("X-CSRF-Token", "1")

	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func logoutOpenShift(endpoint, token string) error {
	url := fmt.Sprintf(openshiftOAuthLogoutURL, endpoint, token)

	cfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{
		Transport: cfg,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	r, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	r.Header.Del("Authorization")
	r.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("Unexpected response status")
	}

	return nil
}

func (d *kubernetes) Login(username, password string) (string, string, error) {
	if d.flavor != share.FlavorOpenShift {
		return "", "", ErrMethodNotSupported
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return "", "", err
		}
	}

	authzEP, err := discoverAuthzEndpoint(d.client.Endpoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to discover authz endpoint. Fallback!")
		authzEP = fmt.Sprintf(openshiftOAuthDefaultURL, d.client.Endpoint)
	} else if authzEP == "" {
		log.Error("Empty authz endpoint. Fallback!")
		authzEP = fmt.Sprintf(openshiftOAuthDefaultURL, d.client.Endpoint)
	}

	resp, err := loginOpenShift(authzEP, username, password)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	access_token, err := parseOpenShiftAccessTokenHeader(resp)
	if err != nil {
		return "", "", err
	}

	return username, access_token, nil
}

type OpenShiftUser struct {
	Kind       string   `json:"kind"`
	ApiVersion string   `json:"apiVersion"`
	Groups     []string `json:"groups"`
}

func (d *kubernetes) GetPlatformUserGroups(token string) ([]string, error) {
	groups := make([]string, 0)

	cfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{
		Transport: cfg,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("%s/apis/user.openshift.io/v1/users/~", d.client.Endpoint)
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return groups, err
	}

	r.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.Do(r)
	if err != nil {
		return groups, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return groups, err
	}

	var user OpenShiftUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.WithFields(log.Fields{"body": body, "err": err}).Error("Unable convert body to json")
		return groups, err
	}

	log.WithFields(log.Fields{"url": url, "user": user}).Debug("getPlatformUserGroups")
	groups = append(groups, user.Groups...)

	return groups, nil
}

func (d *kubernetes) Logout(username, token string) error {
	if d.flavor != share.FlavorOpenShift {
		return ErrMethodNotSupported
	}

	if d.client == nil {
		if err := d.newClient(); err != nil {
			return err
		}
	}

	err := logoutOpenShift(d.client.Endpoint, token)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to logout user")
		return err
	}

	return nil
}

func (d *kubernetes) GetAuthServerAlias() string {
	if d.flavor == share.FlavorOpenShift || d.flavor == share.FlavorRancher {
		return strings.ToLower(d.flavor)
	}

	return ""
}
