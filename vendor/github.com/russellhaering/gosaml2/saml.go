// Copyright 2016 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml2

import (
	"crypto"
	"encoding/base64"
	"sync"
	"time"

	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	dsigtypes "github.com/russellhaering/goxmldsig/types"
)

type ErrSaml struct {
	Message string
	System  error
}

func (serr ErrSaml) Error() string {
	if serr.Message != "" {
		return serr.Message
	}
	return "SAML error"
}

type SAMLServiceProvider struct {
	IdentityProviderSSOURL     string
	IdentityProviderSSOBinding string
	IdentityProviderSLOURL     string
	IdentityProviderSLOBinding string
	IdentityProviderIssuer     string

	AssertionConsumerServiceURL string
	ServiceProviderSLOURL       string
	ServiceProviderIssuer       string

	SignAuthnRequests              bool
	SignAuthnRequestsAlgorithm     string
	SignAuthnRequestsCanonicalizer dsig.Canonicalizer

	// ForceAuthn attribute in authentication request forces the identity provider to
	// re-authenticate the presenter directly rather than rely on a previous security context.
	// NOTE: If both ForceAuthn and IsPassive are "true", the identity provider MUST NOT freshly
	// authenticate the presenter unless the constraints of IsPassive can be met.
	ForceAuthn bool
	// IsPassive attribute in authentication request requires that the identity provider and the
	// user agent itself MUST NOT visibly take control of the user interface from the requester
	// and interact with the presenter in a noticeable fashion.
	IsPassive bool
	// RequestedAuthnContext allows service providers to require that the identity
	// provider use specific authentication mechanisms. Leaving this unset will
	// permit the identity provider to choose the auth method. To maximize compatibility
	// with identity providers it is recommended to leave this unset.
	RequestedAuthnContext   *RequestedAuthnContext
	AudienceURI             string
	IDPCertificateStore     dsig.X509CertificateStore
	NameIdFormat            string
	ValidateEncryptionCert  bool
	SkipSignatureValidation bool
	AllowMissingAttributes  bool
	Clock                   *dsig.Clock

	// Required encryption key and default signing key.
	// Deprecated: Use SetSPKeyStore instead of setting or reading this field.
	SPKeyStore dsig.X509KeyStore

	// Optional signing key.
	// Deprecated: Use SetSPSigningKeyStore instead of setting or reading this field.
	SPSigningKeyStore dsig.X509KeyStore

	spKeyStoreOverride        *KeyStore // When set via SetSPKeyStore, this field is used instead of SPKeyStore
	spSigningKeyStoreOverride *KeyStore // When set via SetSPSigningKeyStore, this field is used instead of SPSigningKeyStore

	// MaximumDecompressedBodySize is the maximum size to which a compressed
	// SAML document will be decompressed. If a compresed document is exceeds
	// this size during decompression an error will be returned.
	MaximumDecompressedBodySize int64

	signingContextMu sync.RWMutex
	signingContext   *dsig.SigningContext
}

// SetSPKeyStore sets the encryption key to be used.
// It is required to either call this method (recommended) or
// set SPKeyStore directly (deprecated).
func (sp *SAMLServiceProvider) SetSPKeyStore(ks *KeyStore) error {
	if ks != nil && ks.Signer == nil {
		return ErrSaml{Message: "SP key store signer can't be nil"}
	}
	sp.spKeyStoreOverride = ks
	return nil
}

// SetSPSigningKeyStore sets the signing key to be used.
func (sp *SAMLServiceProvider) SetSPSigningKeyStore(ks *KeyStore) error {
	if ks != nil && ks.Signer == nil {
		return ErrSaml{Message: "SP signing key store signer can't be nil"}
	}
	sp.spSigningKeyStoreOverride = ks
	return nil
}

type KeyStore struct {
	Signer crypto.Signer
	Cert   []byte
}

// RequestedAuthnContext controls which authentication mechanisms are requested of
// the identity provider. It is generally sufficient to omit this and let the
// identity provider select an authentication mechansim.
type RequestedAuthnContext struct {
	// The RequestedAuthnContext comparison policy to use. See the section 3.3.2.2.1
	// of the SAML 2.0 specification for details. Constants named AuthnPolicyMatch*
	// contain standardized values.
	Comparison string

	// Contexts will be passed as AuthnContextClassRefs. For example, to force password
	// authentication on some identity providers, Contexts should have a value of
	// []string{AuthnContextPasswordProtectedTransport}, and Comparison should have a
	// value of AuthnPolicyMatchExact.
	Contexts []string
}

func (sp *SAMLServiceProvider) Metadata() (*types.EntityDescriptor, error) {
	keyDescriptors := make([]types.KeyDescriptor, 0, 2)
	if sp.GetSigningKey() != nil {
		signingCertBytes, err := sp.GetSigningCertBytes()
		if err != nil {
			return nil, err
		}
		keyDescriptors = append(keyDescriptors, types.KeyDescriptor{
			Use: "signing",
			KeyInfo: dsigtypes.KeyInfo{
				X509Data: dsigtypes.X509Data{
					X509Certificates: []dsigtypes.X509Certificate{dsigtypes.X509Certificate{
						Data: base64.StdEncoding.EncodeToString(signingCertBytes),
					}},
				},
			},
		})
	}

	encryptionCertBytes, err := sp.GetEncryptionCertBytes()
	if err != nil {
		return nil, err
	}
	if encryptionCertBytes != nil {
		keyDescriptors = append(keyDescriptors, types.KeyDescriptor{
			Use: "encryption",
			KeyInfo: dsigtypes.KeyInfo{
				X509Data: dsigtypes.X509Data{
					X509Certificates: []dsigtypes.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(encryptionCertBytes),
					}},
				},
			},
			EncryptionMethods: []types.EncryptionMethod{
				{Algorithm: types.MethodAES128GCM},
				{Algorithm: types.MethodAES192GCM},
				{Algorithm: types.MethodAES256GCM},
				{Algorithm: types.MethodAES128CBC},
				{Algorithm: types.MethodAES256CBC},
			},
		})
	}
	return &types.EntityDescriptor{
		ValidUntil: sp.Clock.Now().UTC().Add(time.Hour * 24 * 7), // 7 days
		EntityID:   sp.ServiceProviderIssuer,
		SPSSODescriptor: &types.SPSSODescriptor{
			AuthnRequestsSigned:        sp.SignAuthnRequests,
			WantAssertionsSigned:       !sp.SkipSignatureValidation,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors:             keyDescriptors,
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  BindingHttpPost,
				Location: sp.AssertionConsumerServiceURL,
				Index:    1,
			}},
		},
	}, nil
}

func (sp *SAMLServiceProvider) MetadataWithSLO(validityHours int64) (*types.EntityDescriptor, error) {
	signingCertBytes, err := sp.GetSigningCertBytes()
	if err != nil {
		return nil, err
	}
	encryptionCertBytes, err := sp.GetEncryptionCertBytes()
	if err != nil {
		return nil, err
	}

	if validityHours <= 0 {
		// By default let's keep it to 7 days.
		validityHours = int64(time.Hour * 24 * 7)
	}

	return &types.EntityDescriptor{
		ValidUntil: sp.Clock.Now().UTC().Add(time.Duration(validityHours)), // default 7 days
		EntityID:   sp.ServiceProviderIssuer,
		SPSSODescriptor: &types.SPSSODescriptor{
			AuthnRequestsSigned:        sp.SignAuthnRequests,
			WantAssertionsSigned:       !sp.SkipSignatureValidation,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors: []types.KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: dsigtypes.KeyInfo{
						X509Data: dsigtypes.X509Data{
							X509Certificates: []dsigtypes.X509Certificate{{
								Data: base64.StdEncoding.EncodeToString(signingCertBytes),
							}},
						},
					},
				},
				{
					Use: "encryption",
					KeyInfo: dsigtypes.KeyInfo{
						X509Data: dsigtypes.X509Data{
							X509Certificates: []dsigtypes.X509Certificate{{
								Data: base64.StdEncoding.EncodeToString(encryptionCertBytes),
							}},
						},
					},
					EncryptionMethods: []types.EncryptionMethod{
						{Algorithm: types.MethodAES128GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES192GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES256GCM, DigestMethod: nil},
						{Algorithm: types.MethodAES128CBC, DigestMethod: nil},
						{Algorithm: types.MethodAES256CBC, DigestMethod: nil},
					},
				},
			},
			AssertionConsumerServices: []types.IndexedEndpoint{{
				Binding:  BindingHttpPost,
				Location: sp.AssertionConsumerServiceURL,
				Index:    1,
			}},
			SingleLogoutServices: []types.Endpoint{{
				Binding:  BindingHttpPost,
				Location: sp.ServiceProviderSLOURL,
			}},
		},
	}, nil
}

// Deprecated: This method won't return the correct value if SetSPKeyStore is used.
func (sp *SAMLServiceProvider) GetEncryptionKey() dsig.X509KeyStore {
	return sp.SPKeyStore
}

// Deprecated: This method won't return the correct value if SetSPSigningKeyStore is used.
func (sp *SAMLServiceProvider) GetSigningKey() dsig.X509KeyStore {
	if sp.SPSigningKeyStore == nil {
		return sp.GetEncryptionKey() // Default is signing key is same as encryption key
	}
	return sp.SPSigningKeyStore
}

func (sp *SAMLServiceProvider) getEncryptionCert() ([]byte, error) {
	if sp.spKeyStoreOverride != nil {
		return sp.spKeyStoreOverride.Cert, nil
	}
	if sp.SPKeyStore != nil {
		_, cert, err := sp.SPKeyStore.GetKeyPair()
		return cert, err
	}
	return nil, nil
}

func (sp *SAMLServiceProvider) GetEncryptionCertBytes() ([]byte, error) {
	cert, err := sp.getEncryptionCert()
	if err != nil {
		return nil, err
	}
	if len(cert) < 1 {
		return nil, ErrSaml{Message: "empty SP encryption certificate"}
	}
	return cert, nil
}

func (sp *SAMLServiceProvider) getSigningCert() ([]byte, error) {
	if sp.spSigningKeyStoreOverride != nil {
		return sp.spSigningKeyStoreOverride.Cert, nil
	}
	if sp.SPSigningKeyStore != nil {
		_, cert, err := sp.SPSigningKeyStore.GetKeyPair()
		return cert, err
	}
	return sp.getEncryptionCert()
}

func (sp *SAMLServiceProvider) GetSigningCertBytes() ([]byte, error) {
	cert, err := sp.getSigningCert()
	if err != nil {
		return nil, err
	}
	if len(cert) < 1 {
		return nil, ErrSaml{Message: "empty SP signing certificate"}
	}
	return cert, nil
}

func (sp *SAMLServiceProvider) getSignerCert() (crypto.Signer, []byte, error) {
	if s := sp.spSigningKeyStoreOverride; s != nil {
		return s.Signer, s.Cert, nil
	}
	if s := sp.SPSigningKeyStore; s != nil {
		return s.GetKeyPair()
	}
	return nil, nil, nil
}

func (sp *SAMLServiceProvider) SigningContext() *dsig.SigningContext {
	sp.signingContextMu.RLock()
	signingContext := sp.signingContext
	sp.signingContextMu.RUnlock()

	if signingContext != nil {
		return signingContext
	}

	sp.signingContextMu.Lock()
	defer sp.signingContextMu.Unlock()

	signing := sp.spSigningKeyStoreOverride
	if signing == nil {
		signing = sp.spKeyStoreOverride
	}
	var err error
	if signing != nil {
		sp.signingContext, err = dsig.NewSigningContext(signing.Signer, [][]byte{signing.Cert})
		if err != nil {
			// Ideally this function should return the error, but updating the function signature would be backward incompatible.
			// In practice, this error should never happen because NewSigningContext only errors when passed a nil signer, and
			// sp.spSigningKeyStoreOverride only gets set after checking to ensure the signer is not nil.
			panic(err)
		}
	} else {
		sp.signingContext = dsig.NewDefaultSigningContext(sp.GetSigningKey())
	}
	sp.signingContext.SetSignatureMethod(sp.SignAuthnRequestsAlgorithm)
	if sp.SignAuthnRequestsCanonicalizer != nil {
		sp.signingContext.Canonicalizer = sp.SignAuthnRequestsCanonicalizer
	}

	return sp.signingContext
}

type ProxyRestriction struct {
	Count    int
	Audience []string
}

type WarningInfo struct {
	OneTimeUse       bool
	ProxyRestriction *ProxyRestriction
	NotInAudience    bool
	InvalidTime      bool
}

type AssertionInfo struct {
	NameID                     string
	Values                     Values
	WarningInfo                *WarningInfo
	SessionIndex               string
	AuthnInstant               *time.Time
	SessionNotOnOrAfter        *time.Time
	Assertions                 []types.Assertion
	ResponseSignatureValidated bool
}
