package saml

type ServiceProvider struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCert               string
	AssertionConsumerServiceURL string
	SPSignRequest               bool

	publicCert string
	privateKey string
}

// GetSignedAuthnRequest returns a singed XML document that represents a AuthnRequest SAML document
func (s *ServiceProvider) GetAuthnRequest() *AuthnRequest {
	r := newAuthnRequest()
	r.AssertionConsumerServiceURL = s.AssertionConsumerServiceURL
	r.Destination = s.IDPSSOURL
	r.Issuer.Url = s.IDPSSODescriptorURL
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = loadCertificate(s.IDPPublicCert)

	if !s.SPSignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}
