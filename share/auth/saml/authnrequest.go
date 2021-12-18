// Copyright 2014 Matthew Baird, Andrew Mussey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"time"
)

func newAuthnRequest() *AuthnRequest {
	id := getID()
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:                     "http://www.w3.org/2000/09/xmldsig#",
		ID:                          id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339), // 2018-12-28: Changed from RFC3339Nano, not supported by ADFS
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		/*
			RequestedAuthnContext: RequestedAuthnContext{
				XMLName: xml.Name{
					Local: "samlp:RequestedAuthnContext",
				},
				SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
				Comparison: "exact",
				AuthnContextClassRef: AuthnContextClassRef{
					XMLName: xml.Name{
						Local: "saml:AuthnContextClassRef",
					},
					SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
					Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		*/
		Signature: &Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: []Transform{Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						}},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
	}
}

func (r *AuthnRequest) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *AuthnRequest) EncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}

func (r *AuthnRequest) CompressedEncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	compressed := compress([]byte(saml))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func (r *AuthnRequest) GetAuthnRequestURL(state string) (string, error) {
	u, err := url.Parse(r.Destination)
	if err != nil {
		return "", err
	}

	b64XML, err := r.CompressedEncodedString()
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	//q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
