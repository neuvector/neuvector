package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
	log "github.com/sirupsen/logrus"
)

func ParseSAMLResponse(token string) (*Response, error) {
	q, err := url.ParseQuery(token)
	if err != nil {
		return nil, errors.New("Invalid URL query format")
	}
	resp := q.Get("SAMLResponse")
	if resp == "" {
		return nil, errors.New("SAMLResponse not present")
	}

	var response Response
	bytesXML, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		return nil, errors.New("SAMLResponse not base64 encoded")
	}
	if err = xml.Unmarshal(bytesXML, &response); err != nil {
		bytesXML = decompress(bytesXML)
		if err = xml.Unmarshal(bytesXML, &response); err != nil {
			return nil, errors.New("Unable to parse SAMLResponse into XML")
		}
	}

	response.bytesXML = bytesXML
	return &response, nil
}

func (r *Response) Validate(s *ServiceProvider, checkTime bool) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	if len(r.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}
	if len(r.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}
	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if r.Issuer.Url != s.IDPSSODescriptorURL {
		return errors.New("issuer mismatch")
	}

	// validate signature
	block, _ := pem.Decode([]byte(s.IDPPublicCert))
	if block == nil {
		return errors.New("decode certificate error")
	}
	certs, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("failed to parse certificate")
		return errors.New("parse certificate error")
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{certs},
	})

	doc := etree.NewDocument()
	doc.ReadFromBytes(r.bytesXML)

	if _, err = ctx.Validate(doc.Root()); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("failed to validate signature")
		return errors.New("validate signature error")
	}

	if checkTime {
		expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
		notOnOrAfter, e := time.Parse(time.RFC3339, expires)
		if e != nil {
			return e
		}
		if notOnOrAfter.Before(time.Now()) {
			return errors.New("assertion has expired on: " + expires)
		}
	}

	return nil
}

func (r *Response) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// GetAttribute by Name or by FriendlyName. Return blank string if not found
func (r *Response) GetAttribute(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}

func (r *Response) GetAttributes() map[string][]string {
	attrs := make(map[string][]string)
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		var values []string
		for _, v := range attr.AttributeValues {
			values = append(values, v.Value)
		}
		attrs[attr.Name] = values
	}
	return attrs
}
