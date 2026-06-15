package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	api "github.com/neuvector/neuvector/controller/api"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getScannerCVEDBFeature() types.Feature {
	return features.New("NeuVector Scanner CVEDB Registration").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupAuthToken).
		Assess("scanner CVEDB version is populated in controller scan status", assessScannerCVEDBRegistered).
		Feature()
}

func assessScannerCVEDBRegistered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/scan/status", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTScanStatusData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false
		}
		return data.Status != nil && data.Status.CVEDBVersion != ""
	}, assessTimeout, retryInterval, "scanner CVEDB version not populated in /v1/scan/status after %s", assessTimeout)

	return ctx
}
