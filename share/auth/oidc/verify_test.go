package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubKeySet verifies a JWS with a fixed public key, standing in for the
// remoteKeySet used in production.
type stubKeySet struct {
	key *rsa.PublicKey
}

func (s *stubKeySet) verify(_ context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	return jws.Verify(s.key)
}

// signCompactToken builds and signs an ID token, returning it in JWS Compact
// Serialization (the format OIDC ID tokens always use).
func signCompactToken(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	obj, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := obj.CompactSerialize()
	require.NoError(t, err)
	return compact
}

func TestVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const (
		issuer   = "https://issuer.example.com"
		clientID = "test-client"
		subject  = "user-123"
	)

	validClaims := func() map[string]any {
		return map[string]any{
			"iss": issuer,
			"sub": subject,
			"aud": clientID,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
	}

	cases := []struct {
		name     string
		rawToken func() string
		wantErr  bool
		wantSub  string
		wantIss  string
	}{
		{
			name:     "valid compact token verifies",
			rawToken: func() string { return signCompactToken(t, priv, validClaims()) },
			wantErr:  false,
			wantSub:  subject,
			wantIss:  issuer,
		},
		{
			name:     "malformed token is rejected",
			rawToken: func() string { return "not-a-valid-jwt" },
			wantErr:  true,
		},
		{
			name: "wrong issuer is rejected",
			rawToken: func() string {
				c := validClaims()
				c["iss"] = "https://evil.example.com"
				return signCompactToken(t, priv, c)
			},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := NewVerifier(
				&stubKeySet{key: &priv.PublicKey},
				&Config{ClientID: clientID},
				issuer,
			)

			tok, err := v.Verify(context.Background(), c.rawToken())
			if c.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, tok)
			assert.Equal(t, c.wantSub, tok.Subject)
			assert.Equal(t, c.wantIss, tok.Issuer)
		})
	}
}
