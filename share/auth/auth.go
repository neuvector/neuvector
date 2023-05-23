package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/ldap.v2"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth/oidc"
	"github.com/neuvector/neuvector/share/auth/saml"
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
	SAMLSPGetRedirectURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect) (string, error)
	SAMLSPAuth(csaml *share.CLUSServerSAML, tokenData *api.RESTAuthToken) (map[string][]string, error)
	OIDCDiscover(issuer string) (string, string, string, string, error)
	OIDCGetRedirectURL(csaml *share.CLUSServerOIDC, redir *api.RESTTokenRedirect) (string, error)
	OIDCAuth(coidc *share.CLUSServerOIDC, tokenData *api.RESTAuthToken) (map[string]interface{}, error)
}

func NewRemoteAuther() RemoteAuthInterface {
	return &remoteAuth{}
}

type remoteAuth struct {
}

const defaultLDAPAuthTimeout = time.Second * 10
const oidcUserInfoTimeout = time.Duration(time.Second * 20)

// 1. Refer to https://github.com/grafana/grafana/issues/2441 about why we set UseSSL and SkipTLS this way
// 2. When running in a container, use --env LDAP_TLS_VERIFY_CLIENT=try to disable client certificate validation
func (a *remoteAuth) LDAPAuth(cldap *share.CLUSServerLDAP, username, password string) (map[string]string, []string, error) {
	client := &LDAPClient{
		Base:               cldap.BaseDN,
		Host:               cldap.Hostname,
		Port:               int(cldap.Port),
		UseSSL:             cldap.SSL,
		SkipTLS:            true,
		InsecureSkipVerify: true,
		BindDN:             cldap.BindDN,
		BindPassword:       cldap.BindPasswd,
		Attributes:         []string{"dn", "gidNumber"},
		Timeout:            defaultLDAPAuthTimeout,
	}
	defer client.Close()

	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.UserFilter = fmt.Sprintf(adUserFilter, cldap.UserNameAttr, username)
	} else {
		client.UserFilter = fmt.Sprintf(ldapUserFilter, cldap.UserNameAttr, username)
	}

	log.WithFields(log.Fields{"filter": client.UserFilter}).Debug("user query")
	dn, attrs, err := client.Authenticate(username, password)
	if err != nil {
		return nil, nil, err
	}
	if dn == "" {
		return nil, nil, errors.New("Authentication failed")
	}

	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.GroupFilter = fmt.Sprintf(adGroupFilter, cldap.GroupMemberAttr, ldap.EscapeFilter(dn))
	} else {
		client.GroupFilter = fmt.Sprintf(ldapGroupFilter, cldap.GroupMemberAttr, ldap.EscapeFilter(username))
	}

	groups, _ := client.GetGroupsOfUser()
	log.WithFields(log.Fields{"filter": client.GroupFilter, "groups": groups}).Debug("group member query")

	// add nested group query for MSAD
	if cldap.Type == api.ServerLDAPTypeMSAD {
		client.GroupFilter = fmt.Sprintf(adNestedGroupFilter, ldap.EscapeFilter(dn))

		groups2, _ := client.GetGroupsOfUser()
		log.WithFields(log.Fields{"filter": client.GroupFilter, "groups": groups2}).Debug("nested group member query")

		groups = append(groups, groups2...)
		groups = removeDuplicateValues(groups)
	}

	// There is a case (Ticket 1137), where group members are stored with their dn, so if groups are not found,
	// we try the other way again.
	if len(groups) == 0 {
		if cldap.Type == api.ServerLDAPTypeMSAD {
			client.GroupFilter = fmt.Sprintf(adGroupFilter, cldap.GroupMemberAttr, ldap.EscapeFilter(username))
		} else {
			client.GroupFilter = fmt.Sprintf(ldapGroupFilter, cldap.GroupMemberAttr, ldap.EscapeFilter(dn))
		}

		log.WithFields(log.Fields{"filter": client.GroupFilter}).Debug("group member query")
		groups, _ = client.GetGroupsOfUser()
	}

	return attrs, groups, nil
}

func (a *remoteAuth) SAMLSPGetRedirectURL(csaml *share.CLUSServerSAML, redir *api.RESTTokenRedirect) (string, error) {
	// Use redirect URL as Entity ID
	sp := saml.ServiceProvider{
		IDPSSOURL:           csaml.SSOURL,
		IDPSSODescriptorURL: redir.Redirect,
		IDPPublicCert:       csaml.X509Cert,
	}

	r := sp.GetAuthnRequest()
	return r.GetAuthnRequestURL(a.generateState())
}

func (a *remoteAuth) SAMLSPAuth(csaml *share.CLUSServerSAML, tokenData *api.RESTAuthToken) (map[string][]string, error) {
	var certs []string
	certs = append(certs, csaml.X509Cert)
	certs = append(certs, csaml.X509CertExtra...)

	r, err := saml.ParseSAMLResponse(tokenData.Token)
	if err != nil {
		return nil, err
	}

	for i, c := range certs {
		sp := saml.ServiceProvider{
			IDPSSOURL:           csaml.SSOURL,
			IDPSSODescriptorURL: csaml.Issuer,
			IDPPublicCert:       c,
		}

		err = r.Validate(&sp, true)
		if err != nil{
			log.WithFields(log.Fields{"samlCertIndex": i, "error": err}).Debug("saml cert failed")
		} else {
			log.WithFields(log.Fields{"samlCertIndex": i}).Debug("saml cert succeed")
			return r.GetAttributes(), nil
		}
	}

	return nil, err		// err will be the last r.Validate() result
}

func (a *remoteAuth) OIDCDiscover(issuer string) (string, string, string, string, error) {
	var lastError error
	for i := 0; i < 3; i++ {
		if eps, err := oidc.Discover(context.Background(), issuer); err != nil {
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

	token, err := cfg.Exchange(context.Background(), tokenData.Token)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("OpenID Connect token not present")
	}

	keySet := oidc.NewRemoteKeySet(context.Background(), coidc.JWKSURL, nil)
	verifier := oidc.NewVerifier(keySet, &oidc.Config{ClientID: coidc.ClientID}, coidc.Issuer)
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return nil, err
	}

	claims, err := idToken.Claims()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to parse claims")
	}

	// Make UserInfo request
	ctx, cancel := context.WithTimeout(context.Background(), oidcUserInfoTimeout)
	defer cancel()

	userInfo, err2 := oidc.UserInfoReq(ctx, coidc.UserInfoURL, oauth2.StaticTokenSource(token))
	if err2 != nil {
		log.WithFields(log.Fields{"error": err2}).Error("Failed on UserInfo reqeuest")
		return claims, err
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
