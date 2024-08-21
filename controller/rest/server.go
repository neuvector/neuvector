package rest

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"errors"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/utils"
)

const DefaultLDAPServerPort uint16 = 389

func isReservedServerName(name string) bool {
	return name == api.AuthServerLocal || name == api.AuthServerPlatform
}

func allowedServerCat() utils.Set {
	return utils.NewSet(api.ServerCatAuth)
}

func allowedServerType() utils.Set {
	return utils.NewSet(api.ServerTypeLDAP, api.ServerTypeSAML, api.ServerTypeOIDC)
}

func isAuthServerInuse(name string) (bool, error) {
	// Check auth order
	sysconf, _ := clusHelper.GetSystemConfigRev(access.NewReaderAccessControl())
	for _, server := range sysconf.AuthOrder {
		if server == name {
			return true, errors.New("Server used by authentication order settings")
		}
	}

	return false, nil
}

func isPasswordAuthServer(s *share.CLUSServer) bool {
	return s.LDAP != nil
}

func isTokenAuthServer(s *share.CLUSServer) bool {
	return s.SAML != nil || s.OIDC != nil
}

func isAuthServer(s *share.CLUSServer) bool {
	return s.LDAP != nil || s.SAML != nil || s.OIDC != nil
}

func tokenAuthServer2REST(cs *share.CLUSServer) *api.RESTTokenAuthServer {
	rs := api.RESTTokenAuthServer{Name: cs.Name}
	if cs.SAML != nil {
		rs.Type = api.ServerTypeSAML
		return &rs
	} else if cs.OIDC != nil {
		rs.Type = api.ServerTypeOIDC
		return &rs
	}

	return nil
}

func server2REST(cs *share.CLUSServer) *api.RESTServer {
	rs := api.RESTServer{Name: cs.Name}
	if cs.LDAP != nil {
		rs.Type = api.ServerTypeLDAP
		rs.LDAP = &api.RESTServerLDAP{
			Type:             cs.LDAP.Type,
			Hostname:         cs.LDAP.Hostname,
			Port:             cs.LDAP.Port,
			SSL:              cs.LDAP.SSL,
			BaseDN:           cs.LDAP.BaseDN,
			GroupDN:          cs.LDAP.GroupDN,
			BindDN:           cs.LDAP.BindDN,
			BindPasswd:       cs.LDAP.BindPasswd,
			GroupMemberAttr:  cs.LDAP.GroupMemberAttr,
			UserNameAttr:     cs.LDAP.UserNameAttr,
			Enable:           cs.Enable,
			DefaultRole:      cs.LDAP.DefaultRole,
			GroupMappedRoles: cs.LDAP.GroupMappedRoles,
		}
		return &rs
	} else if cs.SAML != nil {
		rs.Type = api.ServerTypeSAML

		rs.SAML = &api.RESTServerSAML{
			SSOURL:              cs.SAML.SSOURL,
			Issuer:              cs.SAML.Issuer,
			X509Cert:            cs.SAML.X509Cert,
			GroupClaim:          cs.SAML.GroupClaim,
			Enable:              cs.Enable,
			DefaultRole:         cs.SAML.DefaultRole,
			GroupMappedRoles:    cs.SAML.GroupMappedRoles,
			AuthnSigningEnabled: cs.SAML.AuthnSigningEnabled,
			SigningCert:         cs.SAML.SigningCert,
			//SigningKey:          cs.SAML.SigningKey,
			SLOEnabled: cs.SAML.SLOEnabled,
			SLOURL:     cs.SAML.SLOURL,
		}
		rs.SAML.X509Certs = parseX509CertInfo(cs.SAML)

		return &rs
	} else if cs.OIDC != nil {
		rs.Type = api.ServerTypeOIDC
		rs.OIDC = &api.RESTServerOIDC{
			Issuer:           cs.OIDC.Issuer,
			ClientID:         cs.OIDC.ClientID,
			ClientSecret:     cs.OIDC.ClientSecret,
			AuthURL:          cs.OIDC.AuthURL,
			TokenURL:         cs.OIDC.TokenURL,
			UserInfoURL:      cs.OIDC.UserInfoURL,
			Scopes:           cs.OIDC.Scopes,
			GroupClaim:       cs.OIDC.GroupClaim,
			Enable:           cs.Enable,
			DefaultRole:      cs.OIDC.DefaultRole,
			GroupMappedRoles: cs.OIDC.GroupMappedRoles,
			UseProxy:         cs.OIDC.UseProxy,
		}
		return &rs
	}

	return nil
}

func parseX509CertInfo(csaml *share.CLUSServerSAML) []api.RESTX509CertInfo {
	certsInfo := make([]api.RESTX509CertInfo, 0)

	var certs []string
	certs = append(certs, csaml.X509Cert)
	certs = append(certs, csaml.X509CertExtra...)

	for _, c := range certs {
		block, _ := pem.Decode([]byte(c))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				oneCert := api.RESTX509CertInfo{
					X509Cert:          c,
					IssuerCommonName:  cert.Issuer.CommonName,
					SubjectCommonName: cert.Subject.CommonName,
					ValidityNotAfter:  uint64(cert.NotAfter.UTC().Unix()),
				}

				certsInfo = append(certsInfo, oneCert)
			}
		}
	}

	return certsInfo
}

// This api should be called for non-fedAdmin users only
// This function doesn't care the order of the groups.
// It's only for checking whether the caller tries to add/modify/delete the role mapping of a group whose mapped global role is fedAdmin/fedReader
func authCallerForFedRoleMapping(oldSettings, newSettings []*share.GroupRoleMapping) error {
	fedRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)
	oldRoleMappings := make(map[string]*share.GroupRoleMapping, len(oldSettings)) // key is group
	newRoleMappings := make(map[string]*share.GroupRoleMapping, len(newSettings)) // key is group
	oldMappedGroups := utils.NewSet()
	newMappedGroups := utils.NewSet()
	for _, mappedRoles := range oldSettings {
		if mappedRoles != nil && mappedRoles.Group != "" {
			oldRoleMappings[mappedRoles.Group] = mappedRoles
			oldMappedGroups.Add(mappedRoles.Group)
		}
	}
	for _, mappedRoles := range newSettings {
		if mappedRoles != nil && mappedRoles.Group != "" {
			newRoleMappings[mappedRoles.Group] = mappedRoles
			newMappedGroups.Add(mappedRoles.Group)
		}
	}

	grpMappingToDelete := oldMappedGroups.Difference(newMappedGroups)
	grpMappingToCreate := newMappedGroups.Difference(oldMappedGroups)
	grpMappingToUpdate := newMappedGroups.Intersect(oldMappedGroups)

	// 1. check whether someone(non-fedAdmin) tries to create/delete the role mapping of a group whose mapped global role is fedAdmin/fedReader
	for _, groupSet := range []utils.Set{grpMappingToCreate, grpMappingToDelete} {
		for grp := range groupSet.Iter() {
			if m, ok := oldRoleMappings[grp.(string)]; ok && fedRoles.Contains(m.GlobalRole) {
				return fmt.Errorf("Access denied for changing the mapped role(%s) of global domain in group(%s)'s role mapping", m.GlobalRole, grp.(string))
			}
			if m, ok := newRoleMappings[grp.(string)]; ok && fedRoles.Contains(m.GlobalRole) {
				return fmt.Errorf("Access denied for mapping role(%s) to global domain in group(%s)'s role mapping", m.GlobalRole, grp.(string))
			}
		}
	}

	// 2. check whether someone(non-fedAdmin) tries to assign/remove mapped fedAdmin/fedReader role for global domain to/from an existing groups role mapping
	for grp := range grpMappingToUpdate.Iter() {
		oldMappedRoles, _ := oldRoleMappings[grp.(string)]
		newMappedRoles, _ := newRoleMappings[grp.(string)]
		if fedRoles.Contains(oldMappedRoles.GlobalRole) || fedRoles.Contains(newMappedRoles.GlobalRole) {
			if oldMappedRoles.GlobalRole != newMappedRoles.GlobalRole { // group's mapped role for global domain is fedAdmin/fedReader-changed
				return fmt.Errorf("Access denied for roles(old: %s, new: %s) in the role mapping of group '%s'", oldMappedRoles.GlobalRole, newMappedRoles.GlobalRole, grp)
			}
			// A group's mapped domain roles cannot have fedAdmin/fedReader.
			// As long as the mapped global role is the same, changes on the mapped domain roles are allowed
		}
	}

	return nil
}

// 1. only fedAdmin user can assign/remove fedAdmin/fedReader role for global domain to/from groups' role mapping
// 2. groups that have fedAdmin/fedReader role mapping for global domain are always matched first (i.e. they stay at the front entries in []*share.GroupRoleMapping)
// 3. if a group's role mapping for global domain is admin/fedAdmin, it has no domain role(as it's unnecessary)
// 4. domain role cannot be be fedAdmin/fedReader
// 5. duplicate domains for a group/role in newSettings is also reduced to one domain
// 6. for any mapped domain role for a group, if it's the same as the group's mapped global role, that mapped domain role entry is removed from the mapping
//
// error is returned for any of the following cases:
// 1. non-fedAdmin tries to configure any group that have fedAdmin/fedReader mapped role for global domain
// 2. invalid role specified for the global role or any domain role of a group
// 3. duplicate entries of a group in new configuration
// 4. a namespace is mapped to multiple roles for a group
// 5. non-fedAdmin user tries to change the matching order of any group that have fedAdmin/fedReader-mapped role for global domain
func checkGroupRolesMapping(oldSettings, newSettings []*share.GroupRoleMapping, acc *access.AccessControl) ([]*share.GroupRoleMapping, error) {
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
		if !acc.IsFedAdmin() {
			if err := authCallerForFedRoleMapping(oldSettings, newSettings); err != nil {
				return nil, err
			}
		}
	}

	groups := utils.NewSet()
	for idx, mappedRoles := range newSettings {
		if mappedRoles != nil {
			if !access.IsValidRole(mappedRoles.GlobalRole, access.CONST_VISIBLE_USER_ROLE) {
				return nil, fmt.Errorf("Invalid mapped global role(%v) for group %s", mappedRoles.GlobalRole, mappedRoles.Group)
			} else if mappedRoles.GlobalRole == api.UserRoleFedAdmin || mappedRoles.GlobalRole == api.UserRoleAdmin {
				// if the mapped role for global domain is fedAdmin or admin, it is the admin of all local namespaces
				mappedRoles.RoleDomains = nil
			}

			if groups.Contains(mappedRoles.Group) {
				return nil, fmt.Errorf("Multiple mappings for group %s", mappedRoles.Group)
			} else {
				groups.Add(mappedRoles.Group)
			}

			// if a groups is mapped to a role for global domain, it's implicitly mapped to that same role for all domains. So remove unnecessary domain role mapping entry
			if mappedRoles.RoleDomains != nil {
				if _, ok := mappedRoles.RoleDomains[mappedRoles.GlobalRole]; ok {
					delete(mappedRoles.RoleDomains, mappedRoles.GlobalRole)
				}
			}

			mappedDomainRole := make(map[string]string, 0) // for each group, each domain can only be mapped to one role
			for role, domains := range mappedRoles.RoleDomains {
				if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) {
					return nil, fmt.Errorf("Invalid mapped domain role(%v) for group %s", role, mappedRoles.Group)
				}
				// remove duplicate domains in the domains list
				mappedDomains := utils.NewSet()
				for _, domain := range domains {
					if !mappedDomains.Contains(domain) {
						mappedDomains.Add(domain)
						if mappedRole, ok := mappedDomainRole[domain]; ok && (role != mappedRole) {
							// found this group already has a mapped role for a domain(namespace). Do not allow multiple roles being mapped to a domain!
							return nil, fmt.Errorf("Multiple roles(%s, %s) mapped to a namespace(%s) for group(%s) is not allowed", role, mappedRole, domain, mappedRoles.Group)
						} else {
							mappedDomainRole[domain] = role
						}
					}
				}
				if mappedDomains.Cardinality() != len(domains) {
					mappedRoles.RoleDomains[role] = mappedDomains.ToStringSlice()
				}
				sort.Strings(mappedRoles.RoleDomains[role])
			}

			if mappedRoles.Group == "" {
				newSettings[idx] = nil
			} else {
				// if a group's mapped role for global domain is None, it must have at least one non-None mapped domain role
				mappedDomains := 0
				for role, domains := range mappedRoles.RoleDomains {
					if mapped := len(domains); mapped == 0 {
						delete(mappedRoles.RoleDomains, role)
					} else {
						mappedDomains += mapped
					}
				}
				if mappedRoles.GlobalRole == api.UserRoleNone && mappedDomains == 0 {
					// this group's mapped role for glocal domain is None & has no mapped role for any domain. So remove this entry
					newSettings[idx] = nil
				}
			}
		}
	}

	// remove emtpy entries and still keep the order specified by caller
	emptySlotIdx := -1
	for idx, gmr := range newSettings {
		if gmr != nil {
			if emptySlotIdx >= 0 {
				newSettings[emptySlotIdx] = gmr
				emptySlotIdx++
			}
		} else {
			if emptySlotIdx == -1 {
				emptySlotIdx = idx
			}
		}
	}
	if emptySlotIdx > -1 {
		newSettings = newSettings[:emptySlotIdx]
	}

	for _, newSetting := range newSettings {
		for _, domains := range newSetting.RoleDomains {
			for _, domain := range domains {
				if !isDomainNameValid(domain) {
					return nil, fmt.Errorf("Invalid characters in namespace %s ", domain)
				}
			}
		}
	}

	return sortGroupRoleMappings(nil, newSettings, acc)
}

// for deprecated api(4.2-); it returns error if a group has multiple roles mapped or invalid role is specified
func checkRoleGroupsMapping(roleGroups map[string][]string) ([]*share.GroupRoleMapping, error) {
	groupRole := make(map[string]string, 0) // key is group, value is group's mapped role
	for role, groups := range roleGroups {
		if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) {
			return nil, fmt.Errorf("Invalid group role(%v)", role)
		}
		groupsFound := utils.NewSet()
		for _, g := range groups {
			if r, ok := groupRole[g]; ok {
				if r == role { // same group shows up multiple times for a role. avoid duplicate group entry
					continue
				}
				return nil, fmt.Errorf("Multiple roles(%s, %s) for a group(%s) is not allowed", role, r, g)
			} else {
				groupRole[g] = role
				groupsFound.Add(g)
			}
		}
		if groupsFound.Cardinality() == 0 {
			// no group for this mapped role effectively!
			delete(roleGroups, role)
		} else {
			roleGroups[role] = groupsFound.ToStringSlice()
		}
	}

	return kv.ConvertRoleGroupsToGroupRoleDomains(roleGroups)
}

func handlerTokenAuthServerRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	name := ps.ByName("server")

	cs, _, _ := clusHelper.GetServerRev(name, access.NewReaderAccessControl())
	if cs == nil {
		// Only return basic error, no more information
		log.WithFields(log.Fields{"server": name}).Error("Server not found")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var data api.RESTTokenRedirect
	err := json.Unmarshal(body, &data)
	if err != nil || data.Redirect == "" {
		e := "Get redirect URL request error"
		log.WithFields(log.Fields{"error": err, "redirect": data.Redirect}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if cs.SAML != nil && cs.Enable {
		// Redirect url is used to generate Issuer in AuthnRequest.
		// The string is generated by manager depending on how user connects to NeuVector, so we have to take this argument.
		log.WithFields(log.Fields{"redirect": data.Redirect}).Debug()

		if url, err := remoteAuther.SAMLSPGetRedirectURL(cs.SAML, &data, nil); err != nil {
			log.WithFields(log.Fields{"server": name, "error": err}).Error("Failed to get redirect URL")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		} else {
			var resp api.RESTTokenAuthServersRedirectData
			resp.Redirect = &api.RESTTokenAuthServerRedirect{Name: name, Type: api.ServerTypeSAML, RedirectURL: url}
			restRespSuccess(w, r, &resp, nil, nil, nil, "")
		}
	} else if cs.OIDC != nil && cs.Enable {
		log.WithFields(log.Fields{"redirect": data.Redirect}).Debug()

		if url, err := remoteAuther.OIDCGetRedirectURL(cs.OIDC, &data); err != nil {
			log.WithFields(log.Fields{"server": name, "error": err}).Error("Failed to get redirect URL")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		} else {
			var resp api.RESTTokenAuthServersRedirectData
			resp.Redirect = &api.RESTTokenAuthServerRedirect{Name: name, Type: api.ServerTypeOIDC, RedirectURL: url}
			restRespSuccess(w, r, &resp, nil, nil, nil, "")
		}
	} else {
		// Only return basic error, no more information
		log.WithFields(log.Fields{"server": name}).Error("Not a token auth server")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

func handlerGenerateSLORequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	var resp api.RESTTokenAuthServersRedirectData
	var url string
	var err error

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	var data api.RESTTokenRedirect
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		e := "Get redirect URL request error"
		log.WithFields(log.Fields{"error": err, "redirect": data.Redirect}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	// Handle SAML SLO
	if login.nameid == "" {
		log.Debug("This user has no nameid associated.  Do not generate SAML SLO request.")
		restRespSuccess(w, r, &resp, acc, login, nil, "")
		return
	}
	cs, _, err := clusHelper.GetServerRev(login.server, access.NewReaderAccessControl())
	if err != nil {
		log.WithError(err).Warn("failed to get saml server info")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if !cs.SAML.SLOEnabled {
		log.Debug("SAML SLO is not enabled.")
		restRespSuccess(w, r, &resp, acc, login, nil, "")
		return
	}

	remoteAuth := auth.NewRemoteAuther(nil)
	if url, err = remoteAuth.SAMLSPGetLogoutURL(cs.SAML, &data, login.nameid, login.sessionIndex, nil); err != nil {
		log.WithError(err).Warn("failed to generate saml logout url")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	log.WithField("url", url).Debug("SAML SLO request generated")
	resp.Redirect = &api.RESTTokenAuthServerRedirect{Name: login.server, Type: api.ServerTypeSAML, RedirectURL: url}
	restRespSuccess(w, r, &resp, nil, nil, nil, "")
	return
}

func handlerTokenAuthServerList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	// Can be called before user login !!! so UI can display authentication link of SAML/OAUTH

	var resp api.RESTTokenAuthServersData
	resp.Servers = make([]*api.RESTTokenAuthServer, 0)

	css := clusHelper.GetAllServers(access.NewReaderAccessControl())
	for _, cs := range css {
		if cs.SAML != nil && cs.Enable {
			resp.Servers = append(resp.Servers, tokenAuthServer2REST(cs))
		} else if cs.OIDC != nil && cs.Enable {
			resp.Servers = append(resp.Servers, tokenAuthServer2REST(cs))
		}
	}

	restRespSuccess(w, r, &resp, nil, nil, nil, "Get token auth server list")
}

func handlerServerList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var fcat, ftype string
	for _, f := range query.filters {
		if f.tag == api.FilterServerCategory {
			fcat = f.value
		} else if f.tag == api.FilterServerType {
			ftype = f.value
		}
	}

	if fcat != "" && !allowedServerCat().Contains(fcat) {
		e := "Invalid server category"
		log.WithFields(log.Fields{"category": fcat}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if ftype != "" && !allowedServerType().Contains(ftype) {
		e := "Invalid server type"
		log.WithFields(log.Fields{"type": ftype}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	resp := api.RESTServersData{
		Servers: make([]*api.RESTServer, 0),
		MappableRoles: &api.RESTMappableRoles{
			DefaultRoles:     access.GetValidRoles(access.CONST_MAPPABLE_SERVER_DEFAULT_ROLE),
			GroupRoles:       access.GetValidRoles(access.CONST_VISIBLE_USER_ROLE),
			GroupDomainRoles: access.GetValidRoles(access.CONST_VISIBLE_DOMAIN_ROLE),
		},
	}

	css := clusHelper.GetAllServers(acc)
	for _, cs := range css {
		if fcat == api.ServerCatAuth && !isAuthServer(cs) {
			continue
		}
		if ftype == api.ServerTypeLDAP && cs.LDAP == nil {
			continue
		}
		if ftype == api.ServerTypeSAML && cs.SAML == nil {
			continue
		}
		if ftype == api.ServerTypeOIDC && cs.OIDC == nil {
			continue
		}

		resp.Servers = append(resp.Servers, server2REST(cs))
	}

	log.WithFields(log.Fields{"entries": len(resp.Servers)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get server list")
}

func handlerServerShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	cs, _, err := clusHelper.GetServerRev(name, acc)
	if cs == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTServerData{Server: server2REST(cs)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get server detail")
}

func validateAuthServer(cas *share.CLUSServerAuth) error {
	// default role could be UserRoleNone, UserRoleReader or UserRoleAdmin or custom mappable global role
	if !access.IsValidRole(cas.DefaultRole, access.CONST_MAPPABLE_SERVER_DEFAULT_ROLE) {
		return errors.New("Invalid default role")
	}
	// roleGroups could be for UserRoleReader or UserRoleAdmin or custom mappable global roles
	for _, mappedRoles := range cas.GroupMappedRoles {
		if !access.IsValidRole(mappedRoles.GlobalRole, access.CONST_VISIBLE_USER_ROLE) {
			return fmt.Errorf("Invalid global role(%s) in group(%s) mapping", mappedRoles.GlobalRole, mappedRoles.Group)
		}
		for role := range mappedRoles.RoleDomains {
			if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) {
				return fmt.Errorf("Invalid domain role(%s) in group(%s) mapping", role, mappedRoles.Group)
			}
		}
	}
	return nil
}

func validateLDAPServer(cs *share.CLUSServer) error {
	cldap := cs.LDAP

	if cldap.Type != api.ServerLDAPTypeOpenLDAP && cldap.Type != api.ServerLDAPTypeMSAD {
		return errors.New("Unknown LDAP server type")
	}
	if len(cldap.Hostname) == 0 {
		return errors.New("LDAP settings must define hostname")
	}
	if len(cldap.BaseDN) == 0 {
		return errors.New("LDAP settings must define base DN")
	}
	if err := validateAuthServer(&cldap.CLUSServerAuth); err != nil {
		return err
	}
	return nil
}

func updateLDAPServer(cs *share.CLUSServer, ldap *api.RESTServerLDAPConfig, create bool, acc *access.AccessControl, login *loginSession) error {
	cldap := cs.LDAP

	// Do not support map to fedAdmin now
	// newRole := cldap.DefaultRole
	// if ldap.DefaultRole != nil {
	// 	newRole = *ldap.DefaultRole
	// }
	// if e := isAllowedGlobalRole(acc, login, "", cldap.DefaultRole, newRole); e != nil {
	// 	return e
	// }

	if ldap.Enable != nil {
		cs.Enable = *ldap.Enable
	}
	if ldap.Type != nil {
		cldap.Type = *ldap.Type
	}
	if ldap.Hostname != nil {
		cldap.Hostname = *ldap.Hostname
	}
	if ldap.Port != nil {
		if *ldap.Port != 0 {
			cldap.Port = *ldap.Port
		} else {
			cldap.Port = DefaultLDAPServerPort
		}
	}
	if ldap.SSL != nil {
		cldap.SSL = *ldap.SSL
	}
	if ldap.BaseDN != nil {
		cldap.BaseDN = *ldap.BaseDN
	}
	if ldap.GroupDN != nil {
		cldap.GroupDN = *ldap.GroupDN
	}
	if ldap.BindDN != nil {
		cldap.BindDN = *ldap.BindDN
	}
	if ldap.BindPasswd != nil {
		cldap.BindPasswd = *ldap.BindPasswd
	}
	if create {
		// Set default Group Member Attr if input is empty when creating a new server
		if ldap.GroupMemberAttr == nil || *ldap.GroupMemberAttr == "" {
			if cldap.Type == api.ServerLDAPTypeOpenLDAP {
				cldap.GroupMemberAttr = api.LDAPGroupMemberAttrOpenLDAP
			} else if cldap.Type == api.ServerLDAPTypeMSAD {
				cldap.GroupMemberAttr = api.LDAPGroupMemberAttrMSAD
			}
		} else {
			cldap.GroupMemberAttr = *ldap.GroupMemberAttr
		}
		// Set default User Name Attr if input is empty when creating a new server
		if ldap.UserNameAttr == nil || *ldap.UserNameAttr == "" {
			if cldap.Type == api.ServerLDAPTypeOpenLDAP {
				cldap.UserNameAttr = api.LDAPUserNameAttrOpenLDAP
			} else if cldap.Type == api.ServerLDAPTypeMSAD {
				cldap.UserNameAttr = api.LDAPUserNameAttrMSAD
			}
		} else {
			cldap.UserNameAttr = *ldap.UserNameAttr
		}
	} else {
		if ldap.GroupMemberAttr != nil {
			if *ldap.GroupMemberAttr == "" {
				if cldap.Type == api.ServerLDAPTypeOpenLDAP {
					cldap.GroupMemberAttr = api.LDAPGroupMemberAttrOpenLDAP
				} else if cldap.Type == api.ServerLDAPTypeMSAD {
					cldap.GroupMemberAttr = api.LDAPGroupMemberAttrMSAD
				}
			} else {
				cldap.GroupMemberAttr = *ldap.GroupMemberAttr
			}
		}
		if ldap.UserNameAttr != nil {
			if *ldap.UserNameAttr == "" {
				if cldap.Type == api.ServerLDAPTypeOpenLDAP {
					cldap.UserNameAttr = api.LDAPUserNameAttrOpenLDAP
				} else if cldap.Type == api.ServerLDAPTypeMSAD {
					cldap.UserNameAttr = api.LDAPUserNameAttrMSAD
				}
			} else {
				cldap.UserNameAttr = *ldap.UserNameAttr
			}
		}
	}
	if ldap.DefaultRole != nil {
		cldap.DefaultRole = *ldap.DefaultRole
	}
	var err error
	var groupRoleMappings []*share.GroupRoleMapping
	if ldap.GroupMappedRoles != nil {
		copiedMappings := make([]*share.GroupRoleMapping, len(*ldap.GroupMappedRoles))
		for idx, m := range *ldap.GroupMappedRoles {
			copiedMappings[idx] = m
		}
		if groupRoleMappings, err = checkGroupRolesMapping(cldap.GroupMappedRoles, copiedMappings, acc); err == nil {
			cldap.GroupMappedRoles = groupRoleMappings
		}
	} else if ldap.RoleGroups != nil {
		if groupRoleMappings, err = checkRoleGroupsMapping(*ldap.RoleGroups); err == nil {
			cldap.GroupMappedRoles = groupRoleMappings
			// no need to sort cldap.GroupMappedRoles because fed roles are not supported for RoleGroups ffield
		}
	}

	return err
}

func validateSAMLServer(cs *share.CLUSServer) error {
	csaml := cs.SAML

	if len(csaml.SSOURL) == 0 || len(csaml.Issuer) == 0 || len(csaml.X509Cert) == 0 {
		return errors.New("Parameters are missing in SAML settings")
	}
	if _, err := url.Parse(csaml.SSOURL); err != nil {
		return errors.New("Invalid SAML Single-sign-on URL format")
	}
	if csaml.SLOURL != "" {
		if _, err := url.Parse(csaml.SLOURL); err != nil {
			return errors.New("Invalid SAML Single-sign-on URL format")
		}
	}

	// When cert/key are empty, we only fail it when SLO is enabled.
	if csaml.SigningCert == "" || csaml.SigningKey == "" {
		if csaml.SLOEnabled || csaml.AuthnSigningEnabled {
			return errors.New("SAML SLO requires key cert pair")
		}
	} else {
		if _, err := tls.X509KeyPair([]byte(csaml.SigningCert), []byte(csaml.SigningKey)); err != nil {
			return fmt.Errorf("invalid key cert pair: %w", err)
		}
	}

	var certs []string
	certs = append(certs, csaml.X509Cert) // original one
	certs = append(certs, csaml.X509CertExtra...)

	for _, c := range certs {
		if len(c) > 0 {
			// certificate
			block, _ := pem.Decode([]byte(c))
			if block == nil {
				return errors.New("Invalid SAML X509 certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return errors.New("Invalid SAML X509 certificate")
			}
			if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
				return errors.New("SAML X509 certificate doesn't contain a public key")
			}

			if err := validateAuthServer(&csaml.CLUSServerAuth); err != nil {
				return err
			}
		}
	}

	return nil
}

func updateSAMLServer(cs *share.CLUSServer, saml *api.RESTServerSAMLConfig, acc *access.AccessControl, login *loginSession) error {
	csaml := cs.SAML

	// Do not support map to fedAdmin now
	// newRole := csaml.DefaultRole
	// if saml.DefaultRole != nil {
	// 	newRole = *saml.DefaultRole
	// }
	// if e := isAllowedGlobalRole(acc, login, "", csaml.DefaultRole, newRole); e != nil {
	// 	return e
	// }

	if saml.Enable != nil {
		cs.Enable = *saml.Enable
	}
	if saml.SSOURL != nil {
		csaml.SSOURL = *saml.SSOURL
	}
	if saml.Issuer != nil {
		csaml.Issuer = *saml.Issuer
	}
	if saml.X509Cert != nil {
		csaml.X509Cert = *saml.X509Cert
	}
	if saml.GroupClaim != nil {
		csaml.GroupClaim = *saml.GroupClaim
	}
	if saml.DefaultRole != nil {
		csaml.DefaultRole = *saml.DefaultRole
	}
	if saml.X509CertExtra != nil {
		csaml.X509CertExtra = nil
		for _, c := range *saml.X509CertExtra {
			csaml.X509CertExtra = append(csaml.X509CertExtra, c)
		}
	}
	if saml.AuthnSigningEnabled != nil {
		csaml.AuthnSigningEnabled = *saml.AuthnSigningEnabled
	}

	if saml.SigningCert != nil {
		csaml.SigningCert = *saml.SigningCert
	}
	if saml.SigningKey != nil {
		csaml.SigningKey = *saml.SigningKey
	}

	if saml.SLOEnabled != nil {
		csaml.SLOEnabled = *saml.SLOEnabled
	}
	if saml.SLOURL != nil {
		csaml.SLOURL = *saml.SLOURL
	}

	var err error
	var groupRoleMappings []*share.GroupRoleMapping
	if saml.GroupMappedRoles != nil {
		copiedMappings := make([]*share.GroupRoleMapping, len(*saml.GroupMappedRoles))
		for idx, m := range *saml.GroupMappedRoles {
			copiedMappings[idx] = m
		}
		if groupRoleMappings, err = checkGroupRolesMapping(csaml.GroupMappedRoles, copiedMappings, acc); err == nil {
			csaml.GroupMappedRoles = groupRoleMappings
		}
	} else if saml.RoleGroups != nil {
		if groupRoleMappings, err = checkRoleGroupsMapping(*saml.RoleGroups); err == nil {
			csaml.GroupMappedRoles = groupRoleMappings
			// no need to sort csaml.GroupMappedRoles because fed roles are not supported for RoleGroups ffield
		}
	}

	return err
}

func validateOIDCServer(cs *share.CLUSServer) error {
	coidc := cs.OIDC

	for _, s := range coidc.Scopes {
		// Customers want to use "https://mydomain.com/groups" as scope
		if !isNamePathValid(s) {
			return errors.New("Invalid OpenID Connect scope name")
		}
	}

	if len(coidc.Issuer) == 0 || len(coidc.ClientID) == 0 || len(coidc.ClientSecret) == 0 {
		return errors.New("Parameters are missing in OpenID Connect settings")
	}
	if _, err := url.Parse(coidc.Issuer); err != nil {
		return errors.New("Invalid OpenID Connect issuer format")
	}

	// discover
	var query string
	issuer := coidc.Issuer

	// NVSHAS-4739: remove query, https://test.iam.cloud.ibm.com/identity?account={ACCOUNTID}
	if q := strings.LastIndex(issuer, "?"); q != -1 {
		query = issuer[q+1:]
		issuer = issuer[:q]
	}

	accReadAll := access.NewReaderAccessControl()
	sc := cacher.GetSystemConfig(accReadAll)
	if sc == nil {
		return errors.New("Failed to read system config")
	}

	var proxy string
	var err error
	if coidc.UseProxy {
		proxy, err = httpclient.GetProxy(issuer)
		if err != nil {
			log.WithError(err).Warn("failed to get proxy.")
			// continue
		}
	}

	auth, token, jwks, userInfo, err := remoteAuther.OIDCDiscover(issuer, proxy)
	if err != nil {
		if strings.HasSuffix(issuer, "/") {
			issuer = issuer[:len(issuer)-1]
			auth, token, jwks, userInfo, err = remoteAuther.OIDCDiscover(issuer, proxy)
		}

		if err != nil {
			e := errors.New("Failed to discover OpenID Connect endpoints")
			log.WithFields(log.Fields{"error": err}).Error(e)
			return e
		}

		if query != "" {
			coidc.Issuer = fmt.Sprintf("%s?%s", issuer, query)
		} else {
			coidc.Issuer = issuer
		}
	}

	// Add query to token uri if there is one
	if query != "" {
		token = fmt.Sprintf("%s?%s", token, query)
	}

	if err := validateAuthServer(&coidc.CLUSServerAuth); err != nil {
		return err
	}

	coidc.AuthURL = auth
	coidc.TokenURL = token
	coidc.JWKSURL = jwks
	coidc.UserInfoURL = userInfo

	return nil
}

func updateOIDCServer(cs *share.CLUSServer, oidc *api.RESTServerOIDCConfig, acc *access.AccessControl, login *loginSession) error {
	coidc := cs.OIDC

	// Do not support map to fedAdmin now
	// newRole := coidc.DefaultRole
	// if oidc.DefaultRole != nil {
	// 	newRole = *oidc.DefaultRole
	// }
	// if e := isAllowedGlobalRole(acc, login, "", coidc.DefaultRole, newRole); e != nil {
	// 	return e
	// }

	if oidc.Enable != nil {
		cs.Enable = *oidc.Enable
	}
	if oidc.Issuer != nil {
		coidc.Issuer = *oidc.Issuer
	}
	if oidc.ClientID != nil {
		coidc.ClientID = *oidc.ClientID
	}
	if oidc.ClientSecret != nil {
		coidc.ClientSecret = *oidc.ClientSecret
	}
	if oidc.DefaultRole != nil {
		coidc.DefaultRole = *oidc.DefaultRole
	}
	var err error
	var groupRoleMappings []*share.GroupRoleMapping
	if oidc.GroupMappedRoles != nil {
		copiedMappings := make([]*share.GroupRoleMapping, len(*oidc.GroupMappedRoles))
		for idx, m := range *oidc.GroupMappedRoles {
			copiedMappings[idx] = m
		}
		if groupRoleMappings, err = checkGroupRolesMapping(coidc.GroupMappedRoles, copiedMappings, acc); err == nil {
			coidc.GroupMappedRoles = groupRoleMappings
		}
	} else if oidc.RoleGroups != nil {
		if groupRoleMappings, err = checkRoleGroupsMapping(*oidc.RoleGroups); err == nil {
			coidc.GroupMappedRoles = groupRoleMappings
			// no need to sort csaml.GroupMappedRoles because fed roles are not supported for RoleGroups ffield
		}
	}
	if err != nil {
		return err
	}

	if oidc.Scopes != nil {
		scopes := auth.MandateOIDCScopes
		set := utils.NewSetFromSliceKind(scopes)
		for _, s := range *oidc.Scopes {
			if !set.Contains(s) {
				scopes = append(scopes, s)
				set.Add(s)
			}
		}
		coidc.Scopes = scopes
	}
	if oidc.GroupClaim != nil {
		coidc.GroupClaim = *oidc.GroupClaim
	}

	if oidc.UseProxy != nil {
		coidc.UseProxy = *oidc.UseProxy
	}

	return nil
}

// if the group role mapping data is specified in the request payload, they are sorted (see sortGroupRoleMappings())
// controller adopts first-match when looking for a user's group role mapping data
func handlerServerCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rs := rconf.Config

	if !isObjectNameValid(rs.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}
	if isReservedServerName(rs.Name) {
		e := "Cannot use reserved name"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if cs, _, err := clusHelper.GetServerRev(rs.Name, acc); cs != nil {
		e := "Server already exists"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		return
	} else if err == common.ErrObjectAccessDenied {
		restRespAccessDenied(w, login)
		return
	}

	if rs.LDAP != nil {
		cldap := &share.CLUSServerLDAP{
			Port: DefaultLDAPServerPort,
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs := &share.CLUSServer{Name: rs.Name, LDAP: cldap}

		for ok := true; ok; ok = false {
			if err = updateLDAPServer(cs, rs.LDAP, true, acc, login); err == nil {
				if err = validateLDAPServer(cs); err == nil {
					break
				}
			}
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerIfNotExist(cs); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}

		restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Create LDAP server '%v'", rs.Name))
	} else if rs.SAML != nil {
		csaml := &share.CLUSServerSAML{
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs := &share.CLUSServer{Name: rs.Name, SAML: csaml}

		for ok := true; ok; ok = false {
			if err = updateSAMLServer(cs, rs.SAML, acc, login); err == nil {
				if err = validateSAMLServer(cs); err == nil {
					break
				}
			}
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerIfNotExist(cs); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}

		restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Create SMAL server '%v'", rs.Name))
	} else if rs.OIDC != nil {
		coidc := &share.CLUSServerOIDC{
			Scopes: auth.DefaultOIDCScopes,
			CLUSServerAuth: share.CLUSServerAuth{
				GroupMappedRoles: make([]*share.GroupRoleMapping, 0),
			},
		}
		cs := &share.CLUSServer{Name: rs.Name, OIDC: coidc}

		for ok := true; ok; ok = false {
			if err = updateOIDCServer(cs, rs.OIDC, acc, login); err == nil {
				if err = validateOIDCServer(cs); err == nil {
					break
				}
			}
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerIfNotExist(cs); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}

		restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Create OpenID Connect server '%v'", rs.Name))
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
}

func configLDAPServer(name string, ldap *api.RESTServerLDAPConfig, acc *access.AccessControl, login *loginSession) (int, int, error) {
	log.Debug()

	var err error
	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			return http.StatusNotFound, api.RESTErrObjectNotFound, errors.New("Server not found")
		}

		if cs.LDAP == nil {
			return http.StatusBadRequest, api.RESTErrInvalidRequest, errors.New("Server type cannot be modified")
		}

		for ok := true; ok; ok = false {
			if err = updateLDAPServer(cs, ldap, false, acc, login); err == nil {
				if err = validateLDAPServer(cs); err == nil {
					break
				}
			}
			return http.StatusBadRequest, api.RESTErrInvalidRequest, err
		}

		if !acc.Authorize(cs, nil) {
			return http.StatusForbidden, api.RESTErrObjectAccessDenied, common.ErrObjectAccessDenied
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		return http.StatusInternalServerError, api.RESTErrFailWriteCluster, errors.New("Failed to write cluster")
	}

	return http.StatusOK, 0, nil
}

func configSAMLServer(name string, saml *api.RESTServerSAMLConfig, acc *access.AccessControl, login *loginSession) (int, int, error) {
	log.Debug()

	var err error
	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			return http.StatusNotFound, api.RESTErrObjectNotFound, errors.New("Server not found")
		}

		if cs.SAML == nil {
			return http.StatusBadRequest, api.RESTErrInvalidRequest, errors.New("Server type cannot be modified")
		}

		for ok := true; ok; ok = false {
			if err = updateSAMLServer(cs, saml, acc, login); err == nil {
				if err = validateSAMLServer(cs); err == nil {
					break
				}
			}
			return http.StatusBadRequest, api.RESTErrInvalidRequest, err
		}

		if !acc.Authorize(cs, nil) {
			return http.StatusForbidden, api.RESTErrObjectAccessDenied, common.ErrObjectAccessDenied
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		return http.StatusInternalServerError, api.RESTErrFailWriteCluster, errors.New("Failed to write cluster")
	}

	return http.StatusOK, 0, nil
}

func configOIDCServer(name string, oidc *api.RESTServerOIDCConfig, acc *access.AccessControl, login *loginSession) (int, int, error) {
	log.Debug()

	var err error
	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			return http.StatusNotFound, api.RESTErrObjectNotFound, errors.New("Server not found")
		}

		if cs.OIDC == nil {
			return http.StatusBadRequest, api.RESTErrInvalidRequest, errors.New("Server type cannot be modified")
		}

		for ok := true; ok; ok = false {
			if err = updateOIDCServer(cs, oidc, acc, login); err == nil {
				if err = validateOIDCServer(cs); err == nil {
					break
				}
			}
			return http.StatusBadRequest, api.RESTErrInvalidRequest, err
		}

		if !acc.Authorize(cs, nil) {
			return http.StatusForbidden, api.RESTErrObjectAccessDenied, common.ErrObjectAccessDenied
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		return http.StatusInternalServerError, api.RESTErrFailWriteCluster, errors.New("Failed to write cluster")
	}

	return http.StatusOK, 0, nil
}

// the group roles mapping data in the request payload must follow:
// all groups that have fedAdmin/fedReader mapped to global domain must locate before those non-fedAdmin/fedReader global-domain-mapped entries in the payload
func handlerServerConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rs := rconf.Config

	if rs.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if isReservedServerName(name) {
		e := "Cannot configure reserved server"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if rs.LDAP != nil {
		status, code, err := configLDAPServer(rs.Name, rs.LDAP, acc, login)
		if err == nil {
			restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure LDAP server '%v'", rs.Name))
		} else {
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, status, code, err.Error())
		}
	} else if rs.SAML != nil {
		status, code, err := configSAMLServer(rs.Name, rs.SAML, acc, login)
		if err == nil {
			restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure SAML server '%v'", rs.Name))
		} else {
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, status, code, err.Error())
		}
	} else if rs.OIDC != nil {
		status, code, err := configOIDCServer(rs.Name, rs.OIDC, acc, login)
		if err == nil {
			restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure OpenID Connect server '%v'", rs.Name))
		} else {
			log.WithFields(log.Fields{"server": rs.Name}).Error(err)
			restRespErrorMessage(w, status, code, err.Error())
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
	}
}

func configGroupRoleDomainsFromRoleGroups(role string, groups []string, groupRoleMappings []*share.GroupRoleMapping,
	acc *access.AccessControl) ([]*share.GroupRoleMapping, error) {
	if len(groupRoleMappings) > 0 {
		fedRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)
		groupSet := utils.NewSet()
		for _, g := range groups {
			groupSet.Add(g)
		}
		groupsFound := utils.NewSet()
		for _, mappedRoles := range groupRoleMappings {
			if groupSet.Contains(mappedRoles.Group) {
				if fedRoles.Contains(mappedRoles.GlobalRole) && !acc.IsFedAdmin() {
					// The existing group role mapping has global domain mapped to fedAdmin/fedReader.
					// To change that global role mapping, the caller needs to be fedAdmin role
					return nil, fmt.Errorf("Access denied for global role %s in group %s mapping", mappedRoles.GlobalRole, mappedRoles.Group)
				}
				groupsFound.Add(mappedRoles.Group)
				// set this group's mapping
				mappedRoles.GlobalRole = role
				mappedRoles.RoleDomains = nil
			}
		}

		var newSettings []*share.GroupRoleMapping
		if newGroups := groupSet.Difference(groupsFound); newGroups.Cardinality() > 0 {
			new := make([]*share.GroupRoleMapping, 0, newGroups.Cardinality())
			for g := range newGroups.Iter() {
				mappedRoles := &share.GroupRoleMapping{
					Group:      g.(string),
					GlobalRole: role,
				}
				new = append(new, mappedRoles)
			}
			newSettings = append(groupRoleMappings, new...)
		} else {
			newSettings = groupRoleMappings
		}

		// will sort the group role mapping entries in checkGroupRolesMapping()
		return checkGroupRolesMapping(groupRoleMappings, newSettings, acc)
	} else {
		roleGroups := map[string][]string{
			role: groups,
		}
		// no need to sort the return of kv.ConvertRoleGroupsToGroupRoleDomains() because fed roles are not supported by handlerServerRoleGroupsConfig()
		return checkRoleGroupsMapping(roleGroups)
	}
}

// This api is deprecated since 4.2
func handlerServerRoleGroupsConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	role := ps.ByName("role")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerRoleGroupsConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rs := rconf.Config

	if rs.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	e := ""
	if rs.Role != role {
		e = "Role mismatch"
	} else if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) { // None role cannot be assigned for this api
		e = "Invalid role"
	}
	if e != "" {
		log.WithFields(log.Fields{"server": rs.Name, "role": rs.Role}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	// In 4.2(-), fedAdmin/fedReader roles are not supported for a group's role mapping, so we still do not allow it in 4.2(+) thru this api
	// To map a group's role to fedAdmin/fedReader for global domain on master cluster, please use handlerServerGroupRoleDomainsConfig() instead
	if !access.IsValidRole(role, access.CONST_VISIBLE_DOMAIN_ROLE) {
		e := "Invalid role"
		log.WithFields(log.Fields{"server": rs.Name, "role": rs.Role}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if isReservedServerName(name) {
		e := "Cannot configure reserved server"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			e := "Server not found"
			log.WithFields(log.Fields{"server": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}

		var err error
		var serverType string
		var groupRoleMappings []*share.GroupRoleMapping
		if cs.LDAP != nil {
			serverType = "LDAP"
			if groupRoleMappings, err = configGroupRoleDomainsFromRoleGroups(role, rs.Groups, cs.LDAP.GroupMappedRoles, acc); groupRoleMappings != nil {
				cs.LDAP.GroupMappedRoles = groupRoleMappings
			}
		} else if cs.SAML != nil {
			serverType = "SAML"
			if groupRoleMappings, err = configGroupRoleDomainsFromRoleGroups(role, rs.Groups, cs.SAML.GroupMappedRoles, acc); groupRoleMappings != nil {
				cs.SAML.GroupMappedRoles = groupRoleMappings
			}
		} else if cs.OIDC != nil {
			serverType = "OpenID Connect"
			if groupRoleMappings, err = configGroupRoleDomainsFromRoleGroups(role, rs.Groups, cs.OIDC.GroupMappedRoles, acc); groupRoleMappings != nil {
				cs.OIDC.GroupMappedRoles = groupRoleMappings
			}
		} else {
			err = fmt.Errorf("Not an authentication server")
		}
		if err != nil {
			log.WithFields(log.Fields{"server": name, "err": err}).Error()
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			if serverType != "" {
				restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure %s server '%v'", serverType, rs.Name))
			}
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
	}
}

func configOneGroupRolesMapping(groupRoleMapping *share.GroupRoleMapping, clusGroupMappedRoles []*share.GroupRoleMapping, acc *access.AccessControl) ([]*share.GroupRoleMapping, error) {
	newSettings := make([]*share.GroupRoleMapping, 0, len(clusGroupMappedRoles)+1)
	for _, m := range clusGroupMappedRoles {
		newSettings = append(newSettings, m)
	}

	foundIdx := -1
	for idx, m := range newSettings {
		if m.Group == groupRoleMapping.Group {
			foundIdx = idx
			break
		}
	}

	if foundIdx >= 0 {
		newSettings[foundIdx] = groupRoleMapping
	} else {
		newSettings = append(newSettings, groupRoleMapping)
	}

	// will sort the group role mapping entries in checkGroupRolesMapping()
	return checkGroupRolesMapping(clusGroupMappedRoles, newSettings, acc)
}

func handlerServerGroupRoleDomainsConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	group := ps.ByName("group")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerGroupRoleDomainsConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil || rconf.Config.GroupRoleMapping == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rs := rconf.Config

	if rs.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if rs.GroupRoleMapping.Group != group {
		e := "Group mismatch"
		log.WithFields(log.Fields{"server": rs.Name, "group": rs.GroupRoleMapping.Group}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if isReservedServerName(name) {
		e := "Cannot configure reserved server"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			e := "Server not found"
			log.WithFields(log.Fields{"server": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}

		var err error
		var serverType string
		var mappedRoles []*share.GroupRoleMapping
		if cs.LDAP != nil {
			serverType = "LDAP"
			if mappedRoles, err = configOneGroupRolesMapping(rs.GroupRoleMapping, cs.LDAP.GroupMappedRoles, acc); err == nil {
				cs.LDAP.GroupMappedRoles = mappedRoles
			}
		} else if cs.SAML != nil {
			serverType = "SAML"
			if mappedRoles, err = configOneGroupRolesMapping(rs.GroupRoleMapping, cs.SAML.GroupMappedRoles, acc); err == nil {
				cs.SAML.GroupMappedRoles = mappedRoles
			}
		} else if cs.OIDC != nil {
			serverType = "OpenID Connect"
			if mappedRoles, err = configOneGroupRolesMapping(rs.GroupRoleMapping, cs.OIDC.GroupMappedRoles, acc); err == nil {
				cs.OIDC.GroupMappedRoles = mappedRoles
			}
		} else {
			err = fmt.Errorf("Not an authentication server")
		}
		if err != nil {
			log.WithFields(log.Fields{"server": name, "err": err}).Error()
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			resp := &api.RESTServerGroupRoleConfigData{}
			if mappedRoles != nil {
				groups := make([]string, len(mappedRoles))
				for idx, m := range mappedRoles {
					groups[idx] = m.Group
				}
				resp.Groups = groups
			}
			if serverType != "" {
				restRespSuccess(w, r, resp, acc, login, &rconf, fmt.Sprintf("Configure %s server '%v'", serverType, rs.Name))
			}
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
	}
}

// parameter 'groupRoleMappings': the server's group role mapping data
// parameter 'groups': provided by caller for requesting which groups should be moved forward (with restrictions, see below)
//
//	[*] if any group in groupRoleMappings has fedAdmin/fedReader as the mapped role for global domain, it can be moved only if the caller is fedAdmin role!
//	    besides, the sorting must follow the following rules
//
// The priority of sorting rules: ("requested groups" means the 'groups' parameter from caller)
// 1. requested groups from 'groups' list(in order) that have fedAdmin/fedReader role mapped for global domain
// 2. unrequested groups from 'groupRoleMappings' list(in order) that have fedAdmin/fedReader role mapped for global domain
// 3. requested groups from 'groups' list(in order) that do not have fedAdmin/fedReader role mapped for global domain
// 4. unrequested groups from 'groupRoleMappings' list(in order) that do not have fedAdmin/fedReader role mapped for global domain
//
// error is returned for any of the following cases:
//  1. duplicate group in 'groups' parameter
//  2. a group in 'groups' parameter is not configured to have any role mapping yet
//  3. non-fedAdmin user tries to move any group that has fedAdmin/fedReader mapped role for global domain
//     Q: how to detect non-fedAdmin user tries to move any group that have fedAdmin/fedReader mapped role for global domain?
//     A: 1. we sort groupRoleMappings based on the above 4 rules and get a new 'sortedList'
//  2. we compare 'groupRoleMappings' with 'sortedList' to see whether any group that has fedAdmin/fedReader mapped role for global domain is moved
func sortGroupRoleMappings(groups []string, groupRoleMappings []*share.GroupRoleMapping, acc *access.AccessControl) ([]*share.GroupRoleMapping, error) {
	groupRoleMappingsMap := make(map[string]*share.GroupRoleMapping, len(groupRoleMappings))
	sortedList := make([]*share.GroupRoleMapping, 0, len(groupRoleMappings))
	specifiedNonFedMapped := make([]*share.GroupRoleMapping, 0, len(groupRoleMappings))
	requestedGroups := utils.NewSet()
	fedRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)

	for _, m := range groupRoleMappings {
		groupRoleMappingsMap[m.Group] = m
	}

	// 1. pick from 'groups' that        have fedAdmin/fedReader-mapped role for global domain -> sortedList
	// collect from 'groups' that do not have fedAdmin/fedReader-mapped role for global domain -> specifiedNonFedMapped
	for _, g := range groups {
		if requestedGroups.Contains(g) {
			return nil, fmt.Errorf("duplicate group %s in request", g)
		}
		requestedGroups.Add(g)
		if m, ok := groupRoleMappingsMap[g]; ok {
			if fedRoles.Contains(m.GlobalRole) {
				sortedList = append(sortedList, m)
			} else {
				specifiedNonFedMapped = append(specifiedNonFedMapped, m)
			}
			delete(groupRoleMappingsMap, g)
		} else {
			return nil, fmt.Errorf("group %s is not configured for role mapping", g)
		}
	}
	// Now groupRoleMappingsMap contains only unrequested groups' role mapping data

	// 2. collect unrequested groups from groupRoleMappingsMap that have fedAdmin/fedReader-mapped role for global domain -> append to sortedList
	for _, m := range groupRoleMappings { // still in correct order
		if _, ok := groupRoleMappingsMap[m.Group]; ok {
			if fedRoles.Contains(m.GlobalRole) {
				sortedList = append(sortedList, m)
				delete(groupRoleMappingsMap, m.Group)
			}
		}
	}
	// Now groupRoleMappingsMap contains only unrequested groups that do not have fedAdmin/fedReader-mapped role for global domain

	// 3. append requested groups that do not have fedAdmin/fedReader-mapped role for global domain to sortedList
	for _, m := range specifiedNonFedMapped {
		sortedList = append(sortedList, m)
	}

	// 4. append the unrequested groups that do not have fedAdmin/fedReader role mapping for global domain to sortedList
	for _, m := range groupRoleMappings {
		if _, ok := groupRoleMappingsMap[m.Group]; ok {
			sortedList = append(sortedList, m)
		}
	}

	// if any entry in groupRoleMappings has fedAdmin/fedReader-mapped role for global domain, it can be moved only if the caller is fedAdmin role!
	if !acc.IsFedAdmin() {
		groups := make([]string, 0, 2)
		for idx, newMapping := range sortedList {
			oldMapping := groupRoleMappings[idx]
			if oldMapping.Group != newMapping.Group {
				if fedRoles.Contains(oldMapping.GlobalRole) {
					groups = append(groups, oldMapping.Group)
				}
				if fedRoles.Contains(newMapping.GlobalRole) {
					groups = append(groups, newMapping.Group)
				}
				if len(groups) > 0 {
					return nil, fmt.Errorf("Access denied for moving group(s) %s", strings.Join(groups, ","))
				}
			}
		}
	}

	return sortedList, nil
}

func handlerServerGroupsOrderConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerGroupsOrderConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rs := rconf.Config

	if rs.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if isReservedServerName(name) {
		e := "Cannot configure reserved server"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		cs, rev, _ := clusHelper.GetServerRev(name, acc)
		if cs == nil {
			e := "Server not found"
			log.WithFields(log.Fields{"server": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}

		var err error
		var serverType string
		var mappedRoles []*share.GroupRoleMapping
		if cs.LDAP != nil {
			serverType = "LDAP"
			if mappedRoles, err = sortGroupRoleMappings(rs.Groups, cs.LDAP.GroupMappedRoles, acc); err == nil {
				cs.LDAP.GroupMappedRoles = mappedRoles
			}
		} else if cs.SAML != nil {
			serverType = "SAML"
			if mappedRoles, err = sortGroupRoleMappings(rs.Groups, cs.SAML.GroupMappedRoles, acc); err == nil {
				cs.SAML.GroupMappedRoles = mappedRoles
			}
		} else if cs.OIDC != nil {
			serverType = "OpenID Connect"
			if mappedRoles, err = sortGroupRoleMappings(rs.Groups, cs.OIDC.GroupMappedRoles, acc); err == nil {
				cs.OIDC.GroupMappedRoles = mappedRoles
			}
		} else {
			err = fmt.Errorf("Not an authentication server")
		}
		if err != nil {
			log.WithFields(log.Fields{"server": name, "err": err}).Error()
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutServerRev(cs, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			if serverType != "" {
				resp := &api.RESTServerGroupRoleConfigData{}
				if mappedRoles != nil {
					groups := make([]string, len(mappedRoles))
					for idx, m := range mappedRoles {
						groups[idx] = m.Group
					}
					resp.Groups = groups
				}
				restRespSuccess(w, r, resp, acc, login, &rconf, fmt.Sprintf("Reorder group role mapping for %s server '%v'", serverType, rs.Name))
			}
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
	}
}

func handlerServerDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	if isReservedServerName(name) {
		e := "Cannot delete reserved server"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	cs, _, _ := clusHelper.GetServerRev(name, acc)
	if cs == nil {
		e := "Server not found"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	if isAuthServer(cs) {
		// Acquire lock
		lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
		if err != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
			return
		}
		defer clusHelper.ReleaseLock(lock)

		// Check if server is in use
		if _, err := isAuthServerInuse(name); err != nil {
			log.WithFields(log.Fields{"server": name}).Error(err.Error())
			restRespErrorMessage(w, http.StatusConflict, api.RESTErrObjectInuse, err.Error())
			return
		}
	}

	if err := clusHelper.DeleteServer(name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, fmt.Sprintf("Delete server '%v'", name))

	kickAllLoginSessionsByServer(name)
	deleteShadowUsersByServer(name)
}

func handlerServerTest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServerTestData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Test == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var cs *share.CLUSServer

	rs := rconf.Test

	if isReservedServerName(rs.Name) {
		e := "Cannot test reserved server"
		log.WithFields(log.Fields{"server": rs.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if rs.LDAP != nil {
		cs, _, _ = clusHelper.GetServerRev(rs.Name, acc)
		if cs == nil {
			// This happens when creating a new server that has never been saved.
			cldap := &share.CLUSServerLDAP{Port: DefaultLDAPServerPort}
			cs = &share.CLUSServer{Name: rs.Name, LDAP: cldap}
		}

		if cs.LDAP == nil {
			e := "Server type not match"
			log.WithFields(log.Fields{"server": rs.Name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		// Consider as create so empty attributes can be filled
		for ok := true; ok; ok = false {
			if err = updateLDAPServer(cs, rs.LDAP, true, acc, login); err == nil {
				if err = validateLDAPServer(cs); err == nil {
					break
				}
			}
			log.Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}
	} else if rs.Name != "" {
		cs, _, _ = clusHelper.GetServerRev(rs.Name, acc)
		if cs == nil {
			e := "Server not found"
			log.WithFields(log.Fields{"server": rs.Name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}

		if !acc.Authorize(cs, nil) {
			restRespAccessDenied(w, login)
			return
		}
	} else {
		e := "Server name or configuration must be provided"
		log.Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	var resp api.RESTServerTestResultData

	if cs.LDAP != nil {
		if rs.TestLDAP == nil {
			e := "Server type mismatch"
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		_, groups, err := remoteAuther.LDAPAuth(cs.LDAP, rs.TestLDAP.Username, rs.TestLDAP.Password)
		if err != nil {
			log.WithFields(log.Fields{
				"username": rs.TestLDAP.Username, "error": err,
			}).Debug("Authentication test failed")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrUnauthorized, err.Error())
			return
		}

		log.WithFields(log.Fields{
			"username": rs.TestLDAP.Username, "groups": groups,
		}).Debug("Authentication test succeeded")

		resp.Result = &api.RESTServerTestResult{Groups: groups}
	} else {
		resp.Result = &api.RESTServerTestResult{Groups: make([]string, 0)}
	}

	restRespSuccess(w, r, &resp, acc, login, &rconf, "Test server")
}

func handlerServerUserList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSServer{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name := ps.ByName("name")

	if name != api.AuthServerPlatform {
		e := "Server not found"
		log.WithFields(log.Fields{"server": name}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	server := global.ORCH.GetAuthServerAlias()
	users := global.ORCH.ListUsers()

	var resp api.RESTUsersData
	resp.Users = make([]*api.RESTUser, 0, len(users))
	for _, user := range users {
		gRole, roleDomains, gExtraPermits, permitsDomains, _ := rbac2UserRole(user.RBAC, user.RBAC2)

		var extraPermitsDomains []api.RESTPermitsAssigned
		if len(permitsDomains) > 0 {
			extraPermitsDomains = make([]api.RESTPermitsAssigned, len(permitsDomains))
			for i, assignedPermits := range permitsDomains {
				var supportScope uint8 = access.CONST_PERM_SUPPORT_DOMAIN
				if len(assignedPermits.Domains) == 1 && assignedPermits.Domains[0] == "" {
					supportScope = access.CONST_PERM_SUPPORT_GLOBAL
				}
				extraPermitsDomains[i] = api.RESTPermitsAssigned{
					Permits: access.GetTopLevelPermitsList(supportScope, assignedPermits.Permits),
					Domains: assignedPermits.Domains,
				}
			}
		}

		if gRole != "" || len(roleDomains) > 0 || !gExtraPermits.IsEmpty() || len(permitsDomains) > 0 {
			u := &api.RESTUser{
				Fullname:            user.Name,
				Server:              server,
				Username:            user.Name,
				Role:                gRole,
				RoleDomains:         roleDomains,
				ExtraPermits:        access.GetTopLevelPermitsList(access.CONST_PERM_SUPPORT_GLOBAL, gExtraPermits),
				ExtraPermitsDomains: extraPermitsDomains,
			}
			resp.Users = append(resp.Users, u)
		}
	}

	sort.Slice(resp.Users, func(i, j int) bool { return resp.Users[i].Fullname < resp.Users[j].Fullname })

	restRespSuccess(w, r, &resp, acc, login, nil, "Get user list")
}
