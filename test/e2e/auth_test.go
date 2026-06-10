package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type nvAuthRequest struct {
	Password nvPasswordAuth `json:"password"`
}

type nvPasswordAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type nvAuthResponse struct {
	Token struct {
		Token string `json:"token"`
	} `json:"token"`
}

func getNeuVectorLoginFeature() types.Feature {
	return features.New("NeuVector API Login").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Assess("admin login returns session token", assessAdminLogin).
		Feature()
}

func assessAdminLogin(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()

	endpoint := getAPIEndpoint(ctx)
	body, err := json.Marshal(nvAuthRequest{
		Password: nvPasswordAuth{Username: "admin", Password: nvAdminPassword},
	})
	require.NoError(t, err, "marshal auth request")

	client := newNVHTTPClient()
	url := endpoint + "/v1/auth"

	// The controller REST API may not accept logins immediately after the deployment
	// becomes available. Retry for up to 2 minutes.
	const (
		loginRetryInterval = 10 * time.Second
		loginTimeout       = 2 * time.Minute
	)
	deadline := time.Now().Add(loginTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = tryLogin(client, url, body)
		if lastErr == nil {
			return ctx
		}
		t.Logf("login attempt failed (%v), retrying in %s", lastErr, loginRetryInterval)
		time.Sleep(loginRetryInterval)
	}
	require.NoError(t, lastErr, "admin login to %s timed out after %s", url, loginTimeout)
	return ctx
}

func tryLogin(client *http.Client, url string, body []byte) error {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, raw)
	}

	var authResp nvAuthResponse
	if err = json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}
	if authResp.Token.Token == "" {
		return fmt.Errorf("auth response contained empty token")
	}
	return nil
}
