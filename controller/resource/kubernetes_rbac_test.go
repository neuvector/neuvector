package resource

import (
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tok
}

func TestGetSaFromJwtToken(t *testing.T) {
	cases := []struct {
		name      string
		token     string
		wantSA    string
		wantError bool
	}{
		{
			name:   "flat serviceaccount claim",
			token:  makeToken(t, jwt.MapClaims{"kubernetes.io/serviceaccount/service-account.name": "neuvector-controller"}),
			wantSA: "neuvector-controller",
		},
		{
			name:      "malformed token",
			token:     "not-a-jwt",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			wantError: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sa, err := GetSaFromJwtToken(c.token)
			if c.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, c.wantSA, sa)
		})
	}
}
