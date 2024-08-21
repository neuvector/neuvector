package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/beevik/etree"
	"github.com/jonboulle/clockwork"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/ldap.v2"

	"errors"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth/oidc"
	"github.com/neuvector/neuvector/share/httpclient"

	"github.com/neuvector/neuvector/share/utils"
)

var DefaultOIDCScopes []string = []string{oidc.ScopeOpenID, "profile", "email"}
var MandateOIDCScopes []string = []string{oidc.ScopeOpenID}

const (
	ldapGroupFilter     = "(%s=%s)"
	adGroupFilter       = "(&(sAMAccountType=268435456)(%s=%s))"
	adNestedGroupFilter = "(&(member:1.2.840.113556.1.4.1941:=%s)(objectClass=group)(objectCategory=group))"
	ldapUserFilter      = "(%s=%s)"
	adUserFilter        = "(&(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(%s=%s))"

	stateTimeout = int64(20 * 60)
)

type RemoteAuthInterface interface {
	LDAPAuth(ldap *share.CLUSServerLDAP, username, password string) (map[string]string, []string, error)

	SAMLSPGetLogoutURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect, nameid string, sessionIndex string, overrides map[string]string) (string, error)
	SAMLSPGetRedirectURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect, overrides map[string]string) (string, error)
	// Return Name ID, session index, and attributes.
	SAMLSPAuth(csaml *share.CLUSServerSAML, tokenData *api.RESTAuthToken) (string, string, map[string][]string, error)
	OIDCDiscover(issuer string, proxy string) (string, string, string, string, error)
	OIDCGetRedirectURL(csaml *share.CLUSServerOIDC, redir *api.RESTTokenRedirect) (string, error)
	OIDCAuth(coidc *share.CLUSServerOIDC, tokenData *api.RESTAuthToken) (map[string]interface{}, error)
}

func NewRemoteAuther(fakeTime *time.Time) RemoteAuthInterface {
	return &remoteAuth{
		fakeTime: fakeTime,
	}
}

type remoteAuth struct {
	fakeTime *time.Time // For unit-tests
}

const defaultLDAPAuthTimeout = time.Second * 10
const oidcUserInfoTimeout = time.Duration(time.Second * 20)
const oidcGroupInfoTimeout = time.Duration(time.Second * 20)

// 1. Refer to https://github.com/grafana/grafana/issues/2441 about why we set UseSSL and SkipTLS this way
// 2. When running in a container, use --env LDAP_TLS_VERIFY_CLIENT=try to disable client certificate validation
func (a *remoteAuth) LDAPAuth(cldap *share.CLUSServerLDAP, username, password string) (map[string]string, []string, error) {
	client := &LDAPClient{
		BaseDN:       cldap.BaseDN,
		GroupDN:      cldap.GroupDN,
		Host:         cldap.Hostname,
		Port:         int(cldap.Port),
		UseSSL:       cldap.SSL,
		SkipTLS:      true,
		BindDN:       cldap.BindDN,
		BindPassword: cldap.BindPasswd,
		Attributes:   []string{"dn", "gidNumber"},
		Timeout:      defaultLDAPAuthTimeout,
	}

	if client.GroupDN == "" {
		client.GroupDN = cldap.BaseDN
	}

	defer client.Close()

	username = ldap.EscapeFilter(username)

	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.UserFilter = fmt.Sprintf(adUserFilter, cldap.UserNameAttr, username)
	} else {
		client.UserFilter = fmt.Sprintf(ldapUserFilter, cldap.UserNameAttr, username)
	}

	log.WithFields(log.Fields{"filter": client.UserFilter}).Debug("user query")
	dn, attrs, err := client.Authenticate(password)
	if err != nil {
		return nil, nil, err
	}
	if dn == "" {
		return nil, nil, errors.New("authentication failed")
	}

	dn = ldap.EscapeFilter(dn)

	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.GroupFilter = fmt.Sprintf(adGroupFilter, cldap.GroupMemberAttr, dn)
	} else {
		client.GroupFilter = fmt.Sprintf(ldapGroupFilter, cldap.GroupMemberAttr, username)
	}

	groups, _ := client.GetGroupsOfUser()
	log.WithFields(log.Fields{"filter": client.GroupFilter, "groups": groups}).Debug("group member query")

	// add nested group query for MSAD
	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.GroupFilter = fmt.Sprintf(adNestedGroupFilter, dn)

		groups2, _ := client.GetGroupsOfUser()
		log.WithFields(log.Fields{"filter": client.GroupFilter, "groups": groups2}).Debug("nested group member query")

		groups = append(groups, groups2...)
		groups = removeDuplicateValues(groups)
	}

	// There is a case (Ticket 1137), where group members are stored with their dn, so if groups are not found,
	// we try the other way again.
	if len(groups) == 0 {
		if cldap.Type == api.ServerLDAPTypeMSAD {
			client.GroupFilter = fmt.Sprintf(adGroupFilter, cldap.GroupMemberAttr, username)
		} else {
			client.GroupFilter = fmt.Sprintf(ldapGroupFilter, cldap.GroupMemberAttr, dn)
		}

		log.WithFields(log.Fields{"filter": client.GroupFilter}).Debug("group member query")
		groups, _ = client.GetGroupsOfUser()
	}

	return attrs, groups, nil
}

func GenerateSamlSP(csaml *share.CLUSServerSAML, spissuer string, redirurl string, timeOverride *time.Time) (*saml2.SAMLServiceProvider, error) {
	var keystore dsig.X509KeyStore

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	parseAndStoreCert := func(x509cert string) error {
		var err error
		block, _ := pem.Decode([]byte(x509cert))
		if block == nil {
			return errors.New("failed to decode pem block")
		}

		idpCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		certStore.Roots = append(certStore.Roots, idpCert)
		return nil
	}

	if err := parseAndStoreCert(csaml.X509Cert); err != nil {
		log.WithError(err).Error("failed to parse X509Cert.  Skip this cert.")
	}

	for _, cert := range csaml.X509CertExtra {
		if err := parseAndStoreCert(cert); err != nil {
			log.WithError(err).Error("failed to parse X509Cert.  Skip this cert.")
		}
	}

	if csaml.SigningCert != "" && csaml.SigningKey != "" {
		cert, err := tls.X509KeyPair([]byte(csaml.SigningCert), []byte(csaml.SigningKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse key pair: %w", err)
		}
		keystore = dsig.TLSCertKeyStore(cert)
	}

	// For unit-test
	var clockOverride *dsig.Clock
	if timeOverride != nil {
		clockOverride = dsig.NewFakeClock(clockwork.NewFakeClockAt(*timeOverride))
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: csaml.SSOURL,
		IdentityProviderSLOURL: csaml.SLOURL,

		ServiceProviderIssuer: spissuer,
		IDPCertificateStore:   &certStore,
		SPKeyStore:            keystore,

		// Use redirect URL as AudienceURI.
		IdentityProviderIssuer:      csaml.Issuer,
		AssertionConsumerServiceURL: redirurl,
		AudienceURI:                 redirurl,

		SignAuthnRequests: csaml.AuthnSigningEnabled,

		// Required by Okta. Otherwise you would get this error message:
		// Your request resulted in an error. NameIDPolicy '' is not the configured Name ID Format
		// 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified' for the app
		NameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		Clock:        clockOverride,
	}, nil
}

func (a *remoteAuth) SAMLSPGetRedirectURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect, overrides map[string]string) (string, error) {
	// For backward compatibility, use Authn response redirect url as SP issuer. (https://<NV>/token_auth_server)
	sp, err := GenerateSamlSP(csaml, redir.Redirect, redir.Redirect, a.fakeTime)
	if err != nil {
		return "", err
	}

	// This has to be no signature.
	doc, err := sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return "", err
	}

	// Allow unit-tests to override elements
	for k, v := range overrides {
		path, err := etree.CompilePath("./samlp:AuthnRequest")
		if err != nil {
			return "", fmt.Errorf("failed to parse xml path: %w", err)
		}
		for _, e := range doc.FindElementsPath(path) {
			attr := e.SelectAttr(k)
			attr.Value = v
		}
	}

	// In our previous version of https://github.com/RobotsAndPencils/go-saml, we don't send relay state.
	// Keep the same behavior for backward compatibility.
	return sp.BuildAuthURLRedirect("", doc)
}

func (a *remoteAuth) SAMLSPGetLogoutURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect, nameid string, sessionIndex string, overrides map[string]string) (string, error) {

	// In Azure AD, SSO and SLO must come from the same issuer.
	// Caller should specify issuer when it wants to have a different url for SLO response.
	issuer := redir.Issuer
	if issuer == "" {
		issuer = redir.Redirect
	}
	sp, err := GenerateSamlSP(csaml, issuer, redir.Redirect, a.fakeTime)
	if err != nil {
		return "", fmt.Errorf("failed to generate saml service provider: %w", err)
	}

	// Should be no sig in document.
	doc, err := sp.BuildLogoutRequestDocumentNoSig(nameid, sessionIndex)
	if err != nil {
		return "", fmt.Errorf("failed to build saml slo document: %w", err)
	}

	// Allow unit-tests to override elements
	for k, v := range overrides {
		path, err := etree.CompilePath("./samlp:LogoutRequest")
		if err != nil {
			return "", fmt.Errorf("failed to parse xml path: %w", err)
		}
		for _, e := range doc.FindElementsPath(path) {
			attr := e.SelectAttr(k)
			attr.Value = v
		}
	}

	return sp.BuildLogoutURLRedirect("", doc)
}

// Return Name ID, session index, and attributes.
func (a *remoteAuth) SAMLSPAuth(csaml *share.CLUSServerSAML, tokenData *api.RESTAuthToken) (string, string, map[string][]string, error) {
	// Authn response redirect url (AssertionConsumerServiceURL) as SP issuer. (https://<NV>/token_auth_server)
	sp, err := GenerateSamlSP(csaml, tokenData.Redirect, tokenData.Redirect, a.fakeTime)
	if err != nil {
		return "", "", map[string][]string{}, err
	}

	// Token is the whole query parameters.
	q, err := url.ParseQuery(tokenData.Token)
	if err != nil {
		return "", "", nil, errors.New("Invalid URL query format")
	}
	resp := q.Get("SAMLResponse")
	if resp == "" {
		return "", "", nil, errors.New("SAMLResponse not present")
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(resp)
	if err != nil {
		return "", "", map[string][]string{}, err
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return "", "", map[string][]string{}, errors.New("invalid time")
	}

	out := map[string][]string{}
	for k, v := range assertionInfo.Values {
		values := []string{}
		for _, attr := range v.Values {
			values = append(values, attr.Value)
		}
		out[k] = values
	}

	return assertionInfo.NameID, assertionInfo.SessionIndex, out, nil
}

func (a *remoteAuth) OIDCDiscover(issuer string, proxy string) (string, string, string, string, error) {
	var lastError error

	client, err := httpclient.CreateHTTPClient(proxy)
	if err != nil {
		log.WithError(err).Warn("failed to get transport")
		return "", "", "", "", nil
	}

	for i := 0; i < 3; i++ {
		ctx := oidc.ClientContext(context.Background(), client)

		if eps, err := oidc.Discover(ctx, issuer); err != nil {
			lastError = err
			log.WithFields(log.Fields{"error": err}).Debug("oidc discover failed")
		} else {
			return eps.AuthURL, eps.TokenURL, eps.JWKSURL, eps.UserInfoURL, nil
		}
		time.Sleep(1 * time.Second)
	}
	return "", "", "", "", lastError
}

func (a *remoteAuth) generateState() string {
	s := fmt.Sprintf("%d", time.Now().Unix())
	return utils.EncryptURLSafe(s)
}

func (a *remoteAuth) verifyState(state string) error {
	if tsStr := utils.DecryptURLSafe(state); tsStr == "" {
		return errors.New("Invalid state: wrong encryption")
	} else if ts, err := strconv.ParseInt(tsStr, 10, 64); err != nil {
		return errors.New("Invalid state: wrong format")
	} else if time.Now().Unix()-ts > stateTimeout {
		return errors.New("Invalid state: expired")
	}
	return nil
}

func (a *remoteAuth) OIDCGetRedirectURL(coidc *share.CLUSServerOIDC, redir *api.RESTTokenRedirect) (string, error) {
	cfg := oauth2.Config{
		ClientID:     coidc.ClientID,
		ClientSecret: coidc.ClientSecret,
		Endpoint:     oauth2.Endpoint{AuthURL: coidc.AuthURL, TokenURL: coidc.TokenURL},
		Scopes:       coidc.Scopes,
	}
	url := fmt.Sprintf("%s&redirect_uri=%s", cfg.AuthCodeURL(a.generateState()), redir.Redirect)
	return url, nil
}

func (a *remoteAuth) OIDCAuth(coidc *share.CLUSServerOIDC, tokenData *api.RESTAuthToken) (map[string]interface{}, error) {
	cfg := oauth2.Config{
		ClientID:     coidc.ClientID,
		ClientSecret: coidc.ClientSecret,
		RedirectURL:  tokenData.Redirect,
		Endpoint:     oauth2.Endpoint{AuthURL: coidc.AuthURL, TokenURL: coidc.TokenURL},
		Scopes:       coidc.Scopes,
	}

	if err := a.verifyState(tokenData.State); err != nil {
		return nil, err
	}

	if tokenData.Token == "" {
		return nil, errors.New("OpenID Connect code not present")
	}

	var client *http.Client
	var err error
	if coidc.UseProxy {
		proxy, err := httpclient.GetProxy(coidc.Issuer)
		if err != nil {
			log.WithError(err).Warn("failed to get proxy")
			// continue
		}
		client, err = httpclient.CreateHTTPClient(proxy)
		if err != nil {
			log.WithError(err).Warn("failed to create HTTP client")
		}
	} else {
		client, err = httpclient.CreateHTTPClient("")
		if err != nil {
			log.WithError(err).Warn("failed to create HTTP client")
		}
	}

	ctx := oidc.ClientContext(context.Background(), client)

	token, err := cfg.Exchange(ctx, tokenData.Token)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("OpenID Connect token not present")
	}

	keySet := oidc.NewRemoteKeySet(ctx, coidc.JWKSURL, nil)
	verifier := oidc.NewVerifier(keySet, &oidc.Config{ClientID: coidc.ClientID}, coidc.Issuer)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	claims, err := idToken.Claims()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to parse claims")
	}

	// Make UserInfo request
	timeout, cancel := context.WithTimeout(ctx, oidcUserInfoTimeout)
	defer cancel()

	userInfo, err2 := oidc.UserInfoReq(timeout, coidc.UserInfoURL, oauth2.StaticTokenSource(token))
	if err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("Failed on UserInfo request")
		return claims, err
	}

	// Check group info
	if claims["groups"] == nil {
		timeout, cancel := context.WithTimeout(ctx, oidcGroupInfoTimeout)
		defer cancel()
		if groups, err := oidc.GetAzureGroupInfo(timeout, claims, oauth2.StaticTokenSource(token)); err != nil {
			log.WithError(err).Debug("oidc: failed to fallback to distrubited group info")
		} else {
			claims["groups"] = groups
		}
	}

	// Merge claims from UserInfo call
	uiClaims := make(map[string]interface{})
	if err2 = userInfo.Claims(&uiClaims); err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("Failed to parse UserInfo claims")
		return claims, err
	}

	if claims == nil {
		claims = make(map[string]interface{})
	}
	for k, v := range uiClaims {
		claims[k] = v
	}

	return claims, nil
}

func removeDuplicateValues(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
