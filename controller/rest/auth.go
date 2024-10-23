package rest

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mathRand "math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type loginSession struct {
	id                 string // For event log to correlate login and logout events. It's from token claim's id
	mainSessionID      string // (1) From master token claim, i.e. master cluster login's id. (2) "rancher:{R_SESS}" (3) Empty otherwise
	mainSessionUser    string // From master token claim, i.e. master cluster login's fullname. Empty otherwise
	token              string
	fullname           string
	nameid             string // Used by SAML Single Logout
	sessionIndex       string // Used by SAML Single Logout
	domain             string
	server             string
	timeout            uint32
	remote             string
	loginAt            time.Time
	lastAt             time.Time
	lastSyncTimerAt    time.Time // last time calling other controllers for syncing the timer for the token with this login session
	eolAt              time.Time // end of life
	timer              *time.Timer
	domainRoles        access.DomainRole        // map: domain -> role
	extraDomainPermits access.DomainPermissions // map: domain -> extra permissions(other than in 'domainRoles'), only for Rancher SSO
	loginType          int                      // 0=user (default), 1=apikey

	nvPage string // could change in every request even in the same login session
}

type tokenClaim struct {
	Remote          string                   `json:"remote"`
	Fullname        string                   `json:"fullname"`
	Username        string                   `json:"username"`
	Server          string                   `json:"server"`
	EMail           string                   `json:"email"`
	Locale          string                   `json:"locale"`
	MainSessionID   string                   `json:"main_session_id"`   // from id in master login token's claim. empty when the token is generated for local cluster login
	MainSessionUser string                   `json:"main_session_user"` // from fullname in master login token's claim. empty when the token is generated for local cluster login
	Timeout         uint32                   `json:"timeout"`
	Roles           access.DomainRole        `json:"roles"`                  // domain -> role
	ExtraPermits    access.DomainPermissions `json:"extra_permissions"`      // extra domain -> permissions(other than in 'Roles'). only for Rancher SSO
	NameID          string                   `json:"nameId,omitempty"`       // Used by SAML Single Logout
	SessionIndex    string                   `json:"sessionIndex,omitempty"` // Used by SAML Single Logout
	jwt.RegisteredClaims
}

type joinToken struct {
	MasterServer string `json:"s"`
	MasterPort   uint   `json:"p"`
	JoinTicket   string `json:"t"`
}

type joinTicket struct {
	Salt      int   `json:"s"`
	ExpiresAt int64 `json:"e"`
}

type tRancherUser struct {
	valid             bool
	userGone          bool
	id                string
	name              string
	provider          string                            // from Rancher's v3/principals?me=true
	token             string                            // rancher token from R_SESS cookie
	domainRoles       map[string]string                 // domain -> nv role
	domainPermissions map[string]share.NvFedPermissions // domain -> nv permissions
}

// Extra information of Single Sign-On session
type SsoSession struct {
	SAMLNameID       string
	SAMLSessionIndex string
}

var errTokenExpired error = errors.New("token expired")
var recordFedAuthSessions bool = false                                      // set to true for testing: handlerDumpAuthData
var loginFedSessions map[string]utils.Set = make(map[string]utils.Set)      // for testing: key is mainSessionID, value is a set of regular tokens
var loginSessions map[string]*loginSession = make(map[string]*loginSession) // key is the token
var loginUserAccounting map[string]int = make(map[string]int)
var userMutex sync.RWMutex

const idLength int = 6

const jwtTokenLife = time.Hour * 6
const jwtExpiredTokenSessionWindow = time.Minute * 5 // A heristic way to reduce session number
const jwtFedTokenLife = time.Minute * 60
const jwtFedJointTicketLife = time.Minute * 2 // for ticket used in requests from joint cluster to master cluster
const jwtIbmSaTokenLife = time.Minute * 30
const jwtImportStatusTokenLife = time.Minute * 10
const syncTokenTimerTimeout = time.Duration(120) * time.Second

// JWT token related
type JWTCertificateState struct {
	jwtPublicKey            *rsa.PublicKey
	jwtPublicKeyNotAfter    *time.Time
	jwtPrivateKey           *rsa.PrivateKey
	jwtOldPublicKey         *rsa.PublicKey // Only used in transition period
	jwtOldPublicKeyNotAfter *time.Time
}

var (
	jwtCertState JWTCertificateState
	jwtKeyMutex  sync.RWMutex
)

var jwtLastExpiredTokenSession cluster.SessionInterface
var jwtLastExpiredTokenSessionCreatedAt time.Time

var jointPublicKey *rsa.PublicKey                            // joint cluster's public key, used on joint clusters only
var jointClustersKeyCache = make(map[string]*rsa.PrivateKey) // joint cluster's private key, used on master cluster only. map key is joint cluster id
var fedAuthMutex sync.RWMutex

const MaxPerDomainLoginUsers int = 32

const roleModDummyRole string = api.UserRoleReader

const _interactiveSessionID = ""
const _rancherSessionPrefix = "rancher:"
const _halfHourBefore = time.Duration(-30) * time.Minute

const (
	userOK = iota
	userInvalidRequest
	userNotExist
	userTimeout
	userTooMany
	userKeyError
	userNoPlatformAuth
)

// const (
// 	jwtRegularTokenType = iota
// 	jwtFedMasterTokenType
// )

const loginTypeApikey int = 1

var rancherCookieCache = make(map[string]int64) // key is rancher cookie, value is seconds since the epoch(ValidUntil)
var rancherCookieMutex sync.RWMutex

// var installID *string

func GetJWTSigningKey() JWTCertificateState {
	jwtKeyMutex.RLock()
	defer jwtKeyMutex.RUnlock()
	return jwtCertState
}

// With userMutex locked when calling this because it does loginSession lookup first
func newLoginSessionFromToken(token string, claims *tokenClaim, now time.Time) (*loginSession, int) {
	s := &loginSession{
		id:                 claims.ID,
		mainSessionID:      claims.MainSessionID,
		mainSessionUser:    claims.MainSessionUser,
		token:              token,
		fullname:           claims.Fullname,
		server:             claims.Server,
		timeout:            claims.Timeout,
		remote:             claims.Remote,
		loginAt:            now,
		lastAt:             now,
		domainRoles:        claims.Roles,
		extraDomainPermits: claims.ExtraPermits,
		nameid:             claims.NameID,
		sessionIndex:       claims.SessionIndex,
	}
	if claims.ExpiresAt != nil {
		s.eolAt = claims.ExpiresAt.Time
	}
	if rc := _registerLoginSession(s); rc != userOK {
		updateFedLoginSession(s)
		return nil, rc
	} else {
		return s, rc
	}
}

func newLoginSessionFromUser(user *share.CLUSUser, domainRoles access.DomainRole, extraDomainPermits access.DomainPermissions,
	remote, mainSessionID, mainSessionUser string, sso *SsoSession) (*loginSession, int) {

	// Note: JWT keys should be loaded in initJWTSignKey() before calling this function.
	id, token, claims := jwtGenerateToken(user, domainRoles, extraDomainPermits, remote, mainSessionID, mainSessionUser, sso)
	now := user.LastLoginAt // Already updated
	s := &loginSession{
		id:                 id,
		mainSessionID:      mainSessionID,
		mainSessionUser:    mainSessionUser,
		token:              token,
		fullname:           user.Fullname,
		server:             user.Server,
		timeout:            user.Timeout,
		remote:             remote,
		loginAt:            now,
		lastAt:             now,
		domainRoles:        domainRoles,
		extraDomainPermits: extraDomainPermits,
	}
	// for federal login, give it longer timeout so it doesn't time out as easily as interactive login
	if mainSessionID != _interactiveSessionID && !strings.HasPrefix(mainSessionID, _rancherSessionPrefix) {
		s.timeout = s.timeout * 8
	}
	if sso != nil {
		s.nameid = sso.SAMLNameID
		s.sessionIndex = sso.SAMLSessionIndex
	}
	if claims.ExpiresAt != nil {
		s.eolAt = claims.ExpiresAt.Time
	}

	var rc int
	userMutex.Lock()
	rc = _registerLoginSession(s)
	userMutex.Unlock()

	if rc != userOK {
		return nil, rc
	} else {
		return s, rc
	}
}

// caller must own userMutex before calling this function
func _registerLoginSession(login *loginSession) int {
	if _, ok := loginUserAccounting[login.fullname]; ok {
		if loginUserAccounting[login.fullname] == MaxPerDomainLoginUsers {
			log.WithFields(log.Fields{"user": login.fullname}).Info("User login limit reached")
			return userTooMany
		}
		loginUserAccounting[login.fullname]++ //-> TODO: do we need it for federal login?
	} else {
		loginUserAccounting[login.fullname] = 1
	}

	ibmsaSetup := false
	importStatus := false
	var timeout time.Duration
	if r, ok := login.domainRoles[access.AccessDomainGlobal]; ok && (r == api.UserRoleIBMSA || r == api.UserRoleImportStatus) && len(login.domainRoles) == 1 {
		if r == api.UserRoleIBMSA {
			ibmsaSetup = true
			timeout = time.Duration(jwtIbmSaTokenLife) // IBM Security Advisor has 30 minutes for setting up endpoint
		} else {
			importStatus = true
			timeout = time.Duration(jwtImportStatusTokenLife)
		}
	} else {
		timeout = getUserTimeout(login.timeout)
	}
	login.timer = time.AfterFunc(timeout, func() { login.expire() })
	loginSessions[login.token] = login

	log.WithFields(log.Fields{"id": login.id, "user": login.fullname, "ibmsaSetup": ibmsaSetup, "importStatus": importStatus}).Debug()
	if !ibmsaSetup { // do not write auth log for ibmsa token
		var userName string
		var msg string
		domainRoles := login.domainRoles
		if login.mainSessionUser != "" {
			userName = fmt.Sprintf("%s (primary cluster)", login.mainSessionUser)
		} else {
			userName = login.fullname
		}
		if importStatus {
			msg = fmt.Sprintf("User %s login (for retrieving import result)", login.fullname)
			domainRoles = access.DomainRole{}
		}
		authLog(share.CLUSEvAuthLogin, userName, login.remote, login.id, domainRoles, msg)
	}

	return userOK
}

func (s *loginSession) getToken() string {
	return s.token
}

// caller must own userMutex before calling this function
func _deleteSessionToken(s *loginSession) {
	if s.timer != nil {
		s.timer.Stop()
	}
	if _, ok := loginSessions[s.token]; ok {
		delete(loginSessions, s.token)
		if n, ok := loginUserAccounting[s.fullname]; ok && n > 0 {
			loginUserAccounting[s.fullname]--
		}
	}

	now := time.Now()
	if now.After(s.eolAt) {
		return
	}

	// Add token to expired token blacklist
	if jwtLastExpiredTokenSession == nil || time.Since(jwtLastExpiredTokenSessionCreatedAt) > jwtExpiredTokenSessionWindow {
		if elts, err := cluster.NewSession("expired login token", s.eolAt.Sub(now)); err != nil {
			log.WithFields(log.Fields{"error": err, "user": s.fullname}).Error("failed to create expired login token session")
			return
		} else {
			jwtLastExpiredTokenSession = elts
			jwtLastExpiredTokenSessionCreatedAt = time.Now()
		}
	}

	key := share.CLUSExpiredTokenKey(s.token)
	err := jwtLastExpiredTokenSession.Associate(key)
	if err != nil {
		log.WithFields(log.Fields{"id": s.id, "err": err}).Error()
	}
}

// caller must own userMutex before calling this function
func (s *loginSession) _delete() {
	_deleteSessionToken(s)
}

// delete the calling fed login session/token from loginFedSessions cache
// caller must own userMutex before calling this function
func (s *loginSession) _testDelFedSessionToken() {
	if !recordFedAuthSessions {
		return
	}
	// this function is called when a fed login session token expires
	if s.mainSessionID != _interactiveSessionID && !strings.HasPrefix(s.mainSessionID, _rancherSessionPrefix) {
		if tokenSet, exist := loginFedSessions[s.mainSessionID]; exist && tokenSet.Contains(s.token) {
			tokenSet.Remove(s.token)
			if tokenSet.Cardinality() == 0 {
				delete(loginFedSessions, s.mainSessionID)
			}
		}
	}
}

// delete all fed login sessions/tokens(on joint cluster) that have the same mainSessionID as the caller's(i.e. master cluster) login session
// caller must own userMutex before calling this function
func (s *loginSession) _delJointFedSessions() {
	// this function is called on joint clusters by serving request from master cluster that is triggered by fed user logout on master cluster
	if s.mainSessionID != _interactiveSessionID && !strings.HasPrefix(s.mainSessionID, _rancherSessionPrefix) {
		if recordFedAuthSessions {
			if tokenSet, exist := loginFedSessions[s.mainSessionID]; exist && tokenSet.Cardinality() > 0 {
				for _, token := range tokenSet.ToStringSlice() {
					if s2, ok := loginSessions[token]; ok {
						s2._delete()
					}
				}
				delete(loginFedSessions, s.mainSessionID)
			}
		} else {
			for _, s2 := range loginSessions {
				if s2.mainSessionID == s.mainSessionID {
					s2._delete()
				}
			}
		}
	}
}

// caller must own userMutex before calling this function
func (s *loginSession) _logout() {
	log.WithFields(log.Fields{"id": s.id, "user": s.fullname}).Debug()
	var msg string
	var userName string
	domainRoles := s.domainRoles
	if s.mainSessionUser != "" {
		userName = fmt.Sprintf("%s (primary cluster)", s.mainSessionUser)
	} else {
		userName = s.fullname
	}
	if r, ok := s.domainRoles[access.AccessDomainGlobal]; ok && r == api.UserRoleImportStatus && len(s.domainRoles) == 1 {
		msg = fmt.Sprintf("User %s logout (for retrieving import result)", userName)
		domainRoles = access.DomainRole{}
	}
	authLog(share.CLUSEvAuthLogout, userName, s.remote, s.id, domainRoles, msg)
	s._delete()
}

// caller must own userMutex before calling this function
func (s *loginSession) _expire() {
	log.WithFields(log.Fields{"id": s.id, "user": s.fullname}).Debug()
	if r, ok := s.domainRoles[access.AccessDomainGlobal]; ok && (r == api.UserRoleIBMSA || r == api.UserRoleImportStatus) && len(s.domainRoles) == 1 {
		// do not write auth log for ibmsa/import_status token
	} else {
		var userName string
		if s.mainSessionUser != "" {
			userName = fmt.Sprintf("%s (primary cluster)", s.mainSessionUser)
		} else {
			userName = s.fullname
		}
		authLog(share.CLUSEvAuthTimeout, userName, s.remote, s.id, s.domainRoles, "")
	}
	s._testDelFedSessionToken()
	s._delete()
}

func (s *loginSession) expire() {
	if s.hasFedPermission() {
		clearTokensFromJointClusters(access.NewFedAdminAccessControl(), s)
	}

	userMutex.Lock()
	s._expire()
	userMutex.Unlock()
}

// caller must own userMutex before calling this function
func (s *loginSession) _updateTimeout(tmo uint32) {
	s.timeout = tmo
	elapsed := time.Since(s.lastAt)
	timeout := getUserTimeout(tmo)
	if elapsed >= timeout {
		// Timeout
		s._expire()
	} else {
		log.WithFields(log.Fields{
			"id": s.id, "user": s.fullname, "remain": timeout - elapsed,
		}).Debug("Timer adjusted")
		s.timer.Reset(timeout - elapsed)
	}
}

// SAML idp pass username and group info together with the authentication token.
// - User's group membership is expected to be passed in "NVRoleGroup". In the case of Okta,
// the group filter should be set in a way to return all groups that the user is in,
// for example, "regex=.*". User's role is derived from the group membership.
// - Username is expected to be in "Username" attribute, if it cannot be found, "Email"
// attribute will be used as the username.
// - If role and username cannot be located, authentication will fail.
const (
	samlNVGroupKey string = "NVRoleGroup"
	samlMSGroupKey string = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
	samlUserKey    string = "Username"
	samlEmailKey   string = "Email"
)

const (
	oidcNameKey          string = "name"
	oidcPreferredNameKey string = "preferred_username"
	oldcEmailKey         string = "email"
	oidcGroupKey         string = "groups"
	oidcNVGroupKey       string = "NVRoleGroup"
)

func checkRancherUserRole(cfg *api.RESTSystemConfig, rsessToken string, acc *access.AccessControl) (tRancherUser, error) {
	var data []byte
	var err error
	var statusCode int
	var proxyUsed bool
	var rancherUser tRancherUser = tRancherUser{
		domainRoles:       make(map[string]string),
		domainPermissions: make(map[string]share.NvFedPermissions),
	}

	cookie := &http.Cookie{
		Name:  "R_SESS",
		Value: rsessToken,
	}
	urlStr := fmt.Sprintf("%s/v3/users?me=true", cfg.RancherEP)
	data, statusCode, proxyUsed, err = sendRestRequest("rancher", http.MethodGet, urlStr, "", "", "", "", cookie, []byte{}, true, nil, acc)
	if err == nil {
		var domainPermissions map[string]share.NvFedPermissions = make(map[string]share.NvFedPermissions)
		var rancherUsers api.UserCollection
		if err = json.Unmarshal(data, &rancherUsers); err == nil {
			idx := -1
			for i, data := range rancherUsers.Data {
				if data.Me && data.Enabled != nil && *data.Enabled {
					if idx >= 0 {
						log.WithFields(log.Fields{"i": i, "id": data.ID, "name": data.Username}).Warn("multiple users")
					} else {
						idx = i
					}
				}
			}
			if idx >= 0 {
				principalIDs := utils.NewSetFromSliceKind(rancherUsers.Data[idx].PrincipalIDs)
				rancherUser.id = rancherUsers.Data[idx].ID
				rancherUser.name = rancherUsers.Data[idx].Username
				rancherUser.token = rsessToken
				urlStr = fmt.Sprintf("%s/v3/principals?me=true", cfg.RancherEP)
				data, statusCode, proxyUsed, err = sendRestRequest("rancher", http.MethodGet, urlStr, "", "", "", "", cookie, []byte{}, true, nil, acc)
				//-> if user-id changes, reset mapped roles
				//-> if mapped role changes, reset mapped roles in token
				if err == nil {
					var rancherPrincipals api.PrincipalCollection
					if err = json.Unmarshal(data, &rancherPrincipals); err == nil {
						rancherUser.valid = true
						fedRole := cacher.GetFedMembershipRoleNoAuth()
						allDomainRoles := make(map[string]share.NvReservedUserRole)
						reservedRoleMapping := map[string]share.NvReservedUserRole{
							api.UserRoleAdmin:     share.UserRoleAdmin,
							api.UserRoleReader:    share.UserRoleReader,
							api.UserRoleFedAdmin:  share.UserRoleFedAdmin,
							api.UserRoleFedReader: share.UserRoleFedReader,
						}
						for _, p := range rancherPrincipals.Data {
							var pid string
							var subType uint8 = resource.SUBJECT_USER
							if principalIDs.Contains(p.ID) {
								pid = rancherUsers.Data[idx].ID
								rancherUser.name = p.LoginName
								if p.Provider != "local" {
									rancherUser.provider = p.Provider
								}
							} else {
								pid = p.ID
								subType = resource.SUBJECT_GROUP
							}
							pripDomainRoles, pripDomainPermits, _ := global.ORCH.GetUserRoles(pid, subType)
							if len(pripDomainRoles) == 0 && len(pripDomainPermits) == 0 {
								log.WithFields(log.Fields{"pid": pid, "subType": subType}).Debug("no deduced role/permission")
							} else {
								// collect mapped roles for each domain
								for d, r := range pripDomainRoles {
									if fedRole != api.FedRoleMaster || d != access.AccessDomainGlobal {
										if r == api.UserRoleFedAdmin {
											r = api.UserRoleAdmin
										} else if r == api.UserRoleFedReader {
											r = api.UserRoleReader
										}
									} else if r == api.UserRoleAdmin && rancherUser.name == common.DefaultAdminUser {
										r = api.UserRoleFedAdmin
									}
									if r != api.UserRoleNone {
										allDomainRoles[d] = allDomainRoles[d] | reservedRoleMapping[r]
									}
								}

								// union mapped permissions for each domain
								if len(pripDomainPermits) > 0 {
									if len(domainPermissions) == 0 {
										domainPermissions = pripDomainPermits
									} else {
										for d, permits := range pripDomainPermits {
											if !permits.IsEmpty() {
												p := domainPermissions[d]
												p.Local.Union(permits.Local)
												p.Remote.Union(permits.Remote)
												domainPermissions[d] = p
											}
										}
									}
								}
							}
						}

						// We need to call RemoveRedundant() at last to delete redundant entries for namespace role/permissions (comparing to global role/permissions)
						// It's because a Rancher user could have multiple principal IDs but k8s watcher callback is not aware of this
						rancherUser.domainRoles, rancherUser.domainPermissions = resource.RemoveRedundant(allDomainRoles, domainPermissions, fedRole)
					}
				}
			} else {
				log.WithFields(log.Fields{"len": len(rancherUsers.Data)}).Error("no enabled user")
			}
		}
	}
	if err != nil {
		if statusCode == http.StatusGone {
			rancherUser.userGone = true
		}
		log.WithFields(log.Fields{"data": string(data), "url": urlStr, "err": err}).Error()
	}

	if !rancherUser.valid || (len(rancherUser.domainRoles) == 0 && len(rancherUser.domainPermissions) == 0) {
		err = fmt.Errorf("cannot find any role/permission")
		log.WithFields(log.Fields{"statusCode": statusCode, "user": rancherUser.name, "proxyUsed": proxyUsed}).Error()
	}

	return rancherUser, err
}

// caller must own userMutex before calling this function
func restReq2User(r *http.Request) (*loginSession, int, string) {
	// Note: JWT keys should be loaded in initJWTSignKey() before calling this function.

	var rsessToken string
	if localDev.Host.Platform == share.PlatformKubernetes && localDev.Host.Flavor == share.FlavorRancher {
		if header, ok := r.Header[api.RESTRancherTokenHeader]; ok && len(header) == 1 {
			rsessToken = header[0]
		}
	}

	token, ok := r.Header[api.RESTTokenHeader]
	if !ok || len(token) != 1 {
		// "X-Auth-Token" header not exist, check apikey "X-Auth-Apikey"
		apikey, ok2 := r.Header[api.RESTAPIKeyHeader]
		if !ok2 || len(apikey) != 1 {
			return nil, userInvalidRequest, rsessToken
		} else {
			parts := strings.Split(apikey[0], ":")
			if len(parts) == 2 {
				apikeyAccount, _, _ := clusHelper.GetApikeyRev(parts[0], access.NewReaderAccessControl())

				if apikeyAccount == nil {
					return nil, userInvalidRequest, rsessToken
				}

				// check password
				hash := utils.HashPassword(parts[1])
				if hash != apikeyAccount.SecretKeyHash {
					return nil, userInvalidRequest, rsessToken
				}

				// check timeout
				now := time.Now()
				if now.UTC().Unix() >= apikeyAccount.ExpirationTimestamp {
					return nil, userTimeout, rsessToken
				}

				roles := make(map[string]string)
				for role, domains := range apikeyAccount.RoleDomains {
					for _, d := range domains {
						roles[d] = role
					}
				}
				roles[access.AccessDomainGlobal] = apikeyAccount.Role

				_, _, err := access.GetUserPermissions(apikeyAccount.Role, apikeyAccount.RoleDomains, share.NvPermissions{}, nil)
				if err != nil {
					return nil, userInvalidRequest, rsessToken
				}

				s := &loginSession{
					id:          "apikey_" + apikeyAccount.Name,
					fullname:    apikeyAccount.Name,
					remote:      r.RemoteAddr,
					domainRoles: roles,
					loginType:   loginTypeApikey,
				}

				return s, userOK, rsessToken
			}
		}

		return nil, userInvalidRequest, rsessToken
	}

	// Validate token
	claims, err := jwtValidateToken(token[0], "", nil)
	if err != nil {
		return nil, userInvalidRequest, rsessToken
	}

	// Check token end-of-life
	if claims.ExpiresAt == nil {
		return nil, userInvalidRequest, rsessToken
	}
	now := time.Now()
	if now.After(claims.ExpiresAt.Time) {
		return nil, userTimeout, rsessToken
	}

	// Check whether the token has been kicked by another controller or expired
	key := share.CLUSExpiredTokenKey(token[0])
	if _, err := cluster.Get(key); err == nil {
		if s, ok := loginSessions[token[0]]; ok {
			if s != nil {
				if s.timer != nil {
					s.timer.Stop()
				}
				if n, ok := loginUserAccounting[s.fullname]; ok && n > 0 {
					loginUserAccounting[s.fullname]--
				}
			}
			delete(loginSessions, token[0])
		}
		log.Debug("Token already expired")
		return nil, userTimeout, rsessToken
	}

	cacheRancherCookie := false
	if strings.HasPrefix(claims.MainSessionID, _rancherSessionPrefix) {
		rc := userInvalidRequest
		if rsessToken != "" {
			expected := fmt.Sprintf("%s%s", _rancherSessionPrefix, rsessToken)
			if claims.MainSessionID != expected {
				log.WithFields(log.Fields{"expected": expected, "mainSessionID": claims.MainSessionID}).Error()
			} else {
				// Rancher SSO :
				// 1. (how often) should we call rancherEP to make sure the rancher cookie is still valid? 1 minute
				// 2. Even cookie is still valid, what if the uer's role is changed?
				accReadAll := access.NewReaderAccessControl()
				if cfg := cacher.GetSystemConfig(accReadAll); cfg.AuthByPlatform && cfg.RancherEP != "" {
					var ok bool
					rancherCookieMutex.RLock()
					_, ok = rancherCookieCache[rsessToken]
					rancherCookieMutex.RUnlock()
					if !ok {
						rc = userTimeout
						if _, err := checkRancherUserRole(cfg, rsessToken, accReadAll); err == nil {
							cacheRancherCookie = true
							rc = userOK
						}
					} else {
						rc = userOK
					}
				} else {
					rc = userNoPlatformAuth
				}
			}
		}
		// If rancher console logs out, R_SESS cookie is cleared in browser. The SSO NV console from that R_SESS cookie doesn't work as well.
		if rc != userOK {
			return nil, rc, rsessToken
		}
	}

	login, ok := loginSessions[token[0]]
	if !ok {
		if claims.MainSessionID == "" || strings.HasPrefix(claims.MainSessionID, _rancherSessionPrefix) { // meaning it's not a master token issued by master cluster
			// Check if the token is from the same "installation"
			installID, err := clusHelper.GetInstallationID()
			if err != nil {
				log.WithError(err).Error("failed to get installation ID")
				return nil, userTimeout, rsessToken
			}
			if installID != claims.Subject {
				log.Debug("Token from different installation")
				return nil, userTimeout, rsessToken
			}
		}

		// Create new login session
		var rc int
		login, rc = newLoginSessionFromToken(token[0], claims, now)
		if rc != userOK {
			return nil, rc, rsessToken
		}
	}

	// For auth token generated for IBM SA setup, it has a fixed 30 minutes time-out
	if role := login.domainRoles[access.AccessDomainGlobal]; role != api.UserRoleIBMSA && role != api.UserRoleImportStatus {
		login.timer.Reset(getUserTimeout(login.timeout))
		login.lastAt = now
		// on other controllers, if the token is already known, its login session timer is ticking based on the last request to other controllers.
		// simply reset the login session timer on this controller cannot prevent the timer on other controllers from calling expire().
		// so we need to notify other controllers who know this token to reset the timer for this token's login session.
		// however, to avoid lots of grpc calls among controllers for "reset token timer", we slow it down so that no more than one within 60 seconds.
		if login.lastSyncTimerAt.IsZero() {
			login.lastSyncTimerAt = now
		} else {
			if elapsed := time.Since(login.lastSyncTimerAt); elapsed > syncTokenTimerTimeout {
				tokenInfo := share.CLUSLoginTokenInfo{
					CtrlerID:     localDev.Ctrler.ID,
					LoginID:      login.id,
					UserFullname: login.fullname,
					LoginToken:   token[0],
				}
				go resetLoginTokenTimer(tokenInfo)
				login.lastSyncTimerAt = now
			}
		}
	}

	login.nvPage = ""
	if nvPage, ok := r.Header[api.RESTNvPageHeader]; ok && len(nvPage) == 1 {
		login.nvPage = nvPage[0]
	}
	if cacheRancherCookie {
		rancherCookieMutex.Lock()
		rancherCookieCache[rsessToken] = time.Now().Add(time.Minute).Unix()
		rancherCookieMutex.Unlock()
	}

	return login, userOK, rsessToken
}

// op is derived by HTTP request method, but the caller can overwrite it.
func getAccessControl(w http.ResponseWriter, r *http.Request, op access.AccessOP) (*access.AccessControl, *loginSession) {
	if op == "" {
		if r.Method == http.MethodGet {
			op = access.AccessOPRead
		} else {
			op = access.AccessOPWrite
		}
	}

	userMutex.Lock()
	defer userMutex.Unlock()

	login, rc, rsessToken := restReq2User(r)
	if rc != userOK {
		status := http.StatusUnauthorized
		code := api.RESTErrUnauthorized
		if rsessToken != "" {
			code = api.RESTErrRancherUnauthorized
			if rc == userNoPlatformAuth {
				code = api.RESTErrPlatformAuthDisabled
			}
		}
		restRespError(w, status, code)
		return nil, nil
	}

	if len(login.domainRoles) == 0 && len(login.extraDomainPermits) == 0 {
		restRespAccessDenied(w, login)
		return nil, login
	}

	acc := access.NewAccessControl(r, op, login.domainRoles, login.extraDomainPermits)
	return acc, login
}

func authLog(ev share.TLogEvent, fullname, remote, session string, roles map[string]string, msg string) { //->
	clog := share.CLUSEventLog{
		Event:          ev,
		HostID:         localDev.Host.ID,
		HostName:       localDev.Host.Name,
		ControllerID:   localDev.Ctrler.ID,
		ControllerName: localDev.Ctrler.Name,
		ReportedAt:     time.Now().UTC(),
		User:           fullname,
		UserRoles:      roles,
		UserAddr:       remote,
		UserSession:    session,
	}

	if msg != "" {
		clog.Msg = msg
	} else {
		switch ev {
		case share.CLUSEvAuthLogin:
			clog.Msg = fmt.Sprintf("User %s login", fullname)
		case share.CLUSEvAuthLogout:
			clog.Msg = fmt.Sprintf("User %s logout", fullname)
		case share.CLUSEvAuthTimeout:
			clog.Msg = fmt.Sprintf("User %s login expires", fullname)
		case share.CLUSEvAuthLoginFailed:
			clog.Msg = fmt.Sprintf("User %s login failed", fullname)
		case share.CLUSEvAuthAccessDenied:
			clog.Msg = fmt.Sprintf("User %s resource access denied", fullname)
		}
	}

	evqueue.Append(&clog)
}

// parameters extraPermits/extraPermitsDomains/remoteRolePermits are for Rancher SSO only
// extraPermits:        extra permissions(other than 'Role') for global domain on local cluster. only for Rancher SSO
// extraPermitsDomains: extra permissions(other than 'RoleDomains') for namespaces on local cluster. only for Rancher SSO
// remoteRolePermits:   domain: role/extra permissions on managed cluster
func lookupShadowUser(server, provider, username, userid, email, role string, roleDomains map[string][]string,
	extraPermits share.NvPermissions, extraPermitsDomains []share.CLUSPermitsAssigned,
	remoteRolePermits *share.CLUSRemoteRolePermits) (*share.CLUSUser, bool) {

	var newUser *share.CLUSUser

	now := time.Now()
	fullname := utils.MakeUserFullname(server, username)
	if userid != "" {
		fullname = fmt.Sprintf("%s(%s)", fullname, userid)
	}
	retry := 0
	for retry < retryClusterMax {
		user, rev, _ := clusHelper.GetUserRev(fullname, access.NewReaderAccessControl())
		if user == nil {
			newUser = &share.CLUSUser{
				Fullname:            fullname,
				Server:              server,
				Username:            username,
				EMail:               email,
				Role:                role,
				RoleDomains:         roleDomains,
				ExtraPermits:        extraPermits,        // extra permissions(other than 'Role') for global domain on local cluster. only for Rancher SSO
				ExtraPermitsDomains: extraPermitsDomains, // extra permissions(other than 'RoleDomains') for namespaces on local cluster. only for Rancher SSO
				RemoteRolePermits:   remoteRolePermits,   // nv role/extra permissions on managed clusters in fed. only for Rancher SSO
				Timeout:             common.DefaultIdleTimeout,
				Locale:              common.OEMDefaultUserLocale,
				LoginCount:          1,
				LastLoginAt:         now,
			}
			user = newUser
		} else {
			user.LoginCount++
			if now.After(user.LastLoginAt) {
				user.LastLoginAt = now
			}

			if email != "" && email != user.EMail {
				user.EMail = email
			}

			if server == share.FlavorRancher || !user.RoleOverride {
				// We do not allow changing role/permissions of shadow users from Rancher SSO.
				// So always over-write this shadow user's role/permissions in every SSO login
				user.Role = role
				user.RoleDomains = roleDomains
				user.ExtraPermits = extraPermits               // extra permissions(other than 'Role') for global domain on local cluster. only for Rancher SSO
				user.ExtraPermitsDomains = extraPermitsDomains // extra permissions(other than 'RoleDomains') for namespaces on local cluster. only for Rancher SSO
				user.RemoteRolePermits = remoteRolePermits     // nv role/extra permissions on managed clusters in fed. only for Rancher SSO
			}
			newUser = user
		}
		if server == share.FlavorRancher && provider != "" {
			mapping := map[string]string{
				"activedirectory": "AD",
				"azure":           "AzureAD",
				"github":          "Github",
				"googleoauth":     "Google",
				"keycloakoidc":    "Keycloak/OIDC",
				"ldap":            "LDAP",
				"oidc":            "OpenID",
				"saml":            "SAML",
				"ping":            "Ping Identity",
				"adfs":            "ADFS",
				"keycloak":        "Keycloak/SAML",
				"okta":            "Okta",
				"shibboleth":      "Shibboleth",
				"openldap":        "OpenLDAP",
				"freeipa":         "FreeIPA",
			}
			if name := mapping[provider]; name != "" {
				provider = name
			}
			user.Server = fmt.Sprintf("%s(%s)", share.FlavorRancher, provider)
		}

		authz := (user.Role != api.UserRoleNone || !user.ExtraPermits.IsEmpty() || len(user.RoleDomains) != 0 || len(user.ExtraPermitsDomains) != 0)
		if !authz {
			return nil, false
		}

		user.FailedLoginCount = 0
		user.BlockLoginSince = time.Time{}

		if err := clusHelper.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"user": user.Fullname, "error": err, "rev": rev}).Error()
			retry++
		} else {
			log.WithFields(log.Fields{"user": user.Fullname}).Debug("Created/updated shadow user in cluster")
			break
		}
	}

	// Even update cluster fails, still return authorized user
	if retry >= retryClusterMax {
		log.WithFields(log.Fields{"user": newUser.Fullname}).Error("Failed to created/updated shadow user")
	}
	log.WithFields(log.Fields{"server": server, "user": newUser}).Debug()

	return newUser, true
}

func loginUser(user *share.CLUSUser, masterRoles access.DomainRole, masterDomainsPermits access.DomainPermissions,
	remote, mainSessionID, mainSessionUser, fedRole string, sso *SsoSession) (*loginSession, int) {

	// 1. When a cluster is promoted to master cluster, the default admin user is automatically assigned fedAdmin role
	// 2. When a master cluster is demoted, users with fed role(fedAdmin) are downgraded to with admin/reader role
	// 3. On master cluster, only users with fedAdmin role can assign fed roles to other users
	// 4. On master cluster, only users with fedAdmin role can delete other users who have fed roles
	// 5. users with fedAdmin role on master cluster can get/set all clusters' settings in the federation
	// 6. users with admin/viewer role can read fed-scope rules settings
	// 7. Only interactive login with fedAdmin role on master cluster can access joint clusters
	// 8. when an interactive fedAdmin login on master cluster access joint clusters, the remote token on joint cluster has admin role
	// 9. when federal rules are deployed to joint clusters, there is no access control checking on joint clusters
	roles := make(map[string]string)                // access.DomainRole
	permits := make(map[string]share.NvPermissions) // access.DomainPermissions
	if mainSessionID != _interactiveSessionID && !strings.HasPrefix(mainSessionID, _rancherSessionPrefix) {
		// meaning it's a remote federal login from master cluster
		for d, r := range masterRoles {
			roles[d] = r
		}
		roles[access.AccessDomainGlobal] = masterRoles[access.AccessDomainGlobal]

		// for Rancher SSO only
		for d, p := range masterDomainsPermits {
			if !p.IsEmpty() {
				permits[d] = p
			}
		}
	} else {
		// meaning it's an interactive local cluster login, or redirected from Rancher console where SSO happens
		// Convert role->domains to domain->role
		for role, domains := range user.RoleDomains {
			for _, d := range domains {
				roles[d] = role
			}
		}
		roles[access.AccessDomainGlobal] = user.Role

		// Convert permissions->domains to domain->permissions. for Rancher SSO only
		for _, permitsDomains := range user.ExtraPermitsDomains {
			for _, domain := range permitsDomains.Domains {
				permits[domain] = permitsDomains.Permits
			}
		}
		permits[access.AccessDomainGlobal] = user.ExtraPermits
	}

	return newLoginSessionFromUser(user, roles, permits, remote, mainSessionID, mainSessionUser, sso)
}

func compareUserWithLogin(user *share.CLUSUser, login *loginSession) bool {
	return login.fullname == user.Fullname
}

func getUserTimeout(timeout uint32) time.Duration {
	return time.Second * time.Duration(timeout)
}

func deleteShadowUsersByServer(server string) {
	if server == "" {
		return
	}

	accReadAll := access.NewReaderAccessControl()
	users := clusHelper.GetAllUsers(accReadAll)
	for _, user := range users {
		if user.Server == server {
			if err := clusHelper.DeleteUser(user.Fullname); err != nil {
				log.WithFields(log.Fields{"error": err, "user": user.Fullname}).Error("Failed to delete the user")
			}
		}
	}
}

func _kickAllLoginSessionsByServer(server string) {
	userMutex.Lock()
	defer userMutex.Unlock()

	for _, login := range loginSessions {
		if server == "" || login.server == server {
			login._logout()
		}
	}
}

func _kickFedLoginSessions() {
	userMutex.Lock()
	defer userMutex.Unlock()

	acc := access.NewFedAdminAccessControl()
	for _, login := range loginSessions {
		if login.hasFedPermission() {
			clearTokensFromJointClusters(acc, login)
			login._logout()
		}
	}
}

func _kickLoginSessions(user *share.CLUSUser) { // `user == nil` means kick all login sessions
	userMutex.Lock()
	defer userMutex.Unlock()

	for _, login := range loginSessions {
		if user == nil || compareUserWithLogin(user, login) {
			if login.hasFedPermission() {
				clearTokensFromJointClusters(access.NewFedAdminAccessControl(), login)
			}
			login._logout()
		}
	}
}

func _kickLoginSessionByToken(tokenHash string) {
	userMutex.Lock()
	defer userMutex.Unlock()

	for _, login := range loginSessions {
		if tokenHash == utils.HashPassword(login.token) {
			login._logout()
			break
		}
	}
}

func kickLoginSessionsOnOtherCtrlers(kickInfo share.CLUSKickLoginSessionsRequest) {
	eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
	for _, ep := range eps {
		if ep.ClusterIP != localDev.Ctrler.ClusterIP {
			go rpc.KickLoginSessions(ep.ClusterIP, ep.RPCServerPort, kickInfo)
		}
	}
}

func resetLoginTokenTimer(tokenInfo share.CLUSLoginTokenInfo) {
	eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
	for _, ep := range eps {
		if ep.ClusterIP != localDev.Ctrler.ClusterIP {
			go rpc.ResetLoginTokenTimer(ep.ClusterIP, ep.RPCServerPort, tokenInfo)
		}
	}
}

func kickAllLoginSessionsByServer(server string) {
	_kickAllLoginSessionsByServer(server)
	kickInfo := share.CLUSKickLoginSessionsRequest{
		Type:     share.KickLoginSessionsType_KickByServer,
		CtrlerID: localDev.Ctrler.ID,
		Server:   server,
	}
	kickLoginSessionsOnOtherCtrlers(kickInfo)
}

func kickFedLoginSessions() {
	_kickFedLoginSessions()
	kickInfo := share.CLUSKickLoginSessionsRequest{
		Type:     share.KickLoginSessionsType_KickByFed,
		CtrlerID: localDev.Ctrler.ID,
	}
	kickLoginSessionsOnOtherCtrlers(kickInfo)
}

func kickLoginSessions(user *share.CLUSUser) { // `user == nil` means kick all login sessions
	_kickLoginSessions(user)
	kickInfo := share.CLUSKickLoginSessionsRequest{
		Type:     share.KickLoginSessionsType_KickByUser,
		CtrlerID: localDev.Ctrler.ID,
	}
	if user != nil {
		kickInfo.UserFullname = user.Fullname
		kickInfo.UserServer = user.Server
		kickInfo.UserName = user.Username
	}
	kickLoginSessionsOnOtherCtrlers(kickInfo)
}

func invalidateImportStatusToken(tempToken string) {
	userMutex.Lock()
	defer userMutex.Unlock()

	claims, err := jwtValidateToken(tempToken, "", nil)
	if err == nil {
		s := &loginSession{
			token:    tempToken,
			fullname: claims.Fullname,
		}
		if claims.ExpiresAt != nil {
			s.eolAt = claims.ExpiresAt.Time
		}
		_deleteSessionToken(s)
	}
}

// for one controller to call other controllers' grpc service, which calls this function, to kick login sessions
func KickLoginSessions(kickInfo *share.CLUSKickLoginSessionsRequest) {
	if kickInfo.CtrlerID != localDev.Ctrler.ID {
		switch kickInfo.Type {
		case share.KickLoginSessionsType_KickByServer:
			_kickAllLoginSessionsByServer(kickInfo.Server)
		case share.KickLoginSessionsType_KickByFed:
			_kickFedLoginSessions()
		case share.KickLoginSessionsType_KickByUser:
			var user *share.CLUSUser
			if kickInfo.UserFullname != "" {
				user = &share.CLUSUser{
					Fullname: kickInfo.UserFullname,
					Server:   kickInfo.UserServer,
					Username: kickInfo.UserName,
				}
			}
			_kickLoginSessions(user)
		}
	}
}

// for one controller to call other controllers' grpc service, which calls this function, to reset a login session
func ResetLoginTokenTimer(tokenInfo *share.CLUSLoginTokenInfo) {
	if tokenInfo.CtrlerID != localDev.Ctrler.ID {
		key := share.CLUSExpiredTokenKey(tokenInfo.LoginToken)
		if _, err := cluster.Get(key); err == nil {
			// one controller has set this token to be expired!
			return
		}

		userMutex.Lock()
		defer userMutex.Unlock()

		if login, ok := loginSessions[tokenInfo.LoginToken]; ok {
			// if this controller does know this token, reset its timer.
			if tokenInfo.LoginID == login.id {
				login.timer.Reset(getUserTimeout(login.timeout))
				login.lastAt = time.Now()
			}
		}
		// else {
		// 	// if this controller doesn't know this token yet, it's fine.
		// 	// later when a resp api request reaches this controller, if the token is still not in kv,
		// 	// this controller will accept it and start a new timer for this token
		// }
	}
}

// for openshift/rancher login only
func KickLoginSessionsForRoleChange(name, domain string) {
	server := global.ORCH.GetAuthServerAlias()
	user := share.CLUSUser{
		Fullname: utils.MakeUserFullname(server, name),
		Server:   server,
		Username: name,
	}
	_kickLoginSessions(&user)
}

func changeTimeoutLoginSessions(user *share.CLUSUser) {
	userMutex.Lock()
	defer userMutex.Unlock()

	for _, login := range loginSessions {
		if !strings.HasPrefix(login.mainSessionID, _rancherSessionPrefix) {
			if compareUserWithLogin(user, login) {
				login._updateTimeout(user.Timeout)
			}
		}
	}
}
func resetFedJointKeys() {
	_httpClientMutex.Lock()
	v, ok := _proxyOptionHistory["rancher"]
	_proxyOptionHistory = make(map[string]int8)
	if ok {
		_proxyOptionHistory["rancher"] = v
	}
	_httpClientMutex.Unlock()

	fedAuthMutex.Lock()
	jointPublicKey = nil
	jointClustersKeyCache = make(map[string]*rsa.PrivateKey)
	fedAuthMutex.Unlock()
}

func setJointKeysInCache(callerFedRole string, jointCluster *share.CLUSFedJointClusterInfo) error {
	var err error
	var data []byte
	var rsaPrivateKey *rsa.PrivateKey
	var rsaPublicKey *rsa.PublicKey
	if data, err = base64.StdEncoding.DecodeString(jointCluster.ClientKey); err == nil {
		if rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(data); err == nil && rsaPrivateKey != nil {
			if data, err = base64.StdEncoding.DecodeString(jointCluster.ClientCert); err == nil {
				if rsaPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(data); err == nil && rsaPublicKey != nil {
					if token := jwtGenFedPingToken(callerFedRole, jointCluster.ID, jointCluster.Secret, rsaPrivateKey); token != "" {
						if _, err := jwtValidateToken(token, jointCluster.Secret, rsaPublicKey); err == nil {
							_setFedJointPrivateKey(jointCluster.ID, rsaPrivateKey)
							if callerFedRole == api.FedRoleJoint {
								_setFedJointPublicKey(rsaPublicKey)
							}
							return nil
						} else {
							log.WithFields(log.Fields{"role": callerFedRole, "err": err}).Error("validate")
						}
					}
				}
			}
		}
	}
	return err
}

func reloadJointPubPrivKey(callerFedRole, clusterID string) {
	var err error
	var data []byte

	log.WithFields(log.Fields{"clusterID": clusterID, "callerFedRole": callerFedRole}).Info()
	if callerFedRole == api.FedRoleJoint {
		// meaning joint cluster wants to reload its public key
		m := clusHelper.GetFedMembership()
		if m != nil && m.FedRole == api.FedRoleJoint {
			if data, err = base64.StdEncoding.DecodeString(m.JointCluster.ClientCert); err == nil {
				var rsaPublicKey *rsa.PublicKey
				if rsaPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(data); err == nil && rsaPublicKey != nil {
					_setFedJointPublicKey(rsaPublicKey)
				}
			}
		}
	} else if callerFedRole == api.FedRoleMaster {
		// meaning master cluster wants to reload a joint cluster's private key
		if jointCluster := clusHelper.GetFedJointCluster(clusterID); jointCluster != nil {
			if data, err = base64.StdEncoding.DecodeString(jointCluster.ClientKey); err == nil {
				var rsaPrivateKey *rsa.PrivateKey
				if rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(data); err == nil && rsaPrivateKey != nil {
					_setFedJointPrivateKey(jointCluster.ID, rsaPrivateKey)
				}
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"clusterID": clusterID, "callerFedRole": callerFedRole, "err": err}).Error("reload failed")
	}
}

// Validate a JWT token.
// If secret is not specified, default secret and default JWT key will be used.
// If secret is specified, specified secret and rsaPublicKey/FedJoint JWT key will be used.
func jwtValidateToken(encryptedToken, secret string, rsaPublicKey *rsa.PublicKey) (*tokenClaim, error) {
	// rsaPublicKey being non-nil is for validating new public/private keys purpose
	var tokenString string
	var publicKey *rsa.PublicKey
	var alternativeKey *rsa.PublicKey

	jwtCert := GetJWTSigningKey()
	installID, err := clusHelper.GetInstallationID()
	if err != nil {
		log.WithError(err).Error("failed to get installation ID")
		return nil, fmt.Errorf("failed to get installation ID: %w", err)
	}

	if secret == "" {
		tokenString = utils.DecryptUserToken(encryptedToken, []byte(installID))
	} else {
		tokenString = utils.DecryptSensitive(encryptedToken, []byte(secret))
	}
	if tokenString == "" {
		return nil, fmt.Errorf("unrecognized token")
	}
	if secret == "" {
		publicKey = jwtCert.jwtPublicKey
		alternativeKey = jwtCert.jwtOldPublicKey
	} else {
		if rsaPublicKey == nil {
			if publicKey = _getFedJointPublicKey(); publicKey == nil {
				if m := clusHelper.GetFedMembership(); m != nil && m.FedRole == api.FedRoleJoint {
					log.Info("reload key")
					if err := setJointKeysInCache(api.FedRoleJoint, &m.JointCluster); err == nil {
						publicKey = _getFedJointPublicKey()
					}
				}
			}
		} else {
			publicKey = rsaPublicKey
		}
	}
	if publicKey == nil {
		return nil, fmt.Errorf("empty public key")
	}
	token, err := jwt.ParseWithClaims(tokenString, &tokenClaim{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		if jwtCert.jwtPublicKeyNotAfter != nil && time.Now().After(*jwtCert.jwtPublicKeyNotAfter) {
			return nil, fmt.Errorf("jwt certificate expired: %v", jwtCert.jwtPublicKeyNotAfter)
		}
		return publicKey, nil
	})

	// Try with old cert if it's available.
	// Note: Ideally we should use extra info stored in claims to do a lookup below.
	//       Luckily jwt verification normally only takes a few ms.  We can revisit when we see abnormal performance impact here.
	if err != nil && alternativeKey != nil {
		token, err = jwt.ParseWithClaims(tokenString, &tokenClaim{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			if jwtCert.jwtOldPublicKeyNotAfter != nil && time.Now().After(*jwtCert.jwtOldPublicKeyNotAfter) {
				return nil, fmt.Errorf("jwt certificate expired: %v", jwtCert.jwtOldPublicKeyNotAfter)
			}
			return alternativeKey, nil
		})
	}

	if err != nil {
		// if it's a joint cluster and rsa verfication of the token from master cluster fails,
		// reload its joint public key from kv
		if err.Error() == rsa.ErrVerification.Error() && secret != "" && rsaPublicKey == nil {
			reloadJointPubPrivKey(api.FedRoleJoint, "")
		}
		return nil, err
	}

	if claims, ok := token.Claims.(*tokenClaim); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("Invalid token structure")
	}
}

func validateEncryptedData(encryptedData, secret string, checkTime bool) error {
	data := utils.DecryptSensitive(encryptedData, []byte(secret))
	if data != "" {
		var c joinTicket
		if err := json.Unmarshal([]byte(data), &c); err == nil {
			if checkTime {
				if time.Now().Unix() < c.ExpiresAt {
					return nil
				} else {
					return errTokenExpired
				}
			} else {
				return nil
			}
		} else {
			return err
		}
	}
	return errors.New("Invalid data")
}

func jwtValidateFedJoinTicket(encryptedTicket, secret string) error {
	return validateEncryptedData(encryptedTicket, secret, true)
}

// permits is for Rancher SSO only
func jwtGenerateToken(user *share.CLUSUser, domainRoles access.DomainRole, extraDomainPermits access.DomainPermissions,
	remote, mainSessionID, mainSessionUser string, sso *SsoSession) (string, string, *tokenClaim) {

	id := utils.GetRandomID(idLength, "")
	installID, err := clusHelper.GetInstallationID()
	if err != nil {
		log.WithError(err).Error("failed to get installation ID")
		return "", "", &tokenClaim{}
	}
	now := time.Now()
	c := tokenClaim{
		Remote:          remote,
		Fullname:        user.Fullname,
		Username:        user.Username,
		Server:          user.Server,
		EMail:           user.EMail,
		Locale:          user.Locale,
		MainSessionID:   mainSessionID,
		MainSessionUser: mainSessionUser,
		Timeout:         user.Timeout,
		Roles:           domainRoles,
		ExtraPermits:    extraDomainPermits,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			Subject:   installID,
			Issuer:    localDev.Ctrler.ID,
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtTokenLife)),
		},
	}
	if sso != nil {
		c.NameID = sso.SAMLNameID
		c.SessionIndex = sso.SAMLSessionIndex
	}
	if r, ok := domainRoles[access.AccessDomainGlobal]; ok && (r == api.UserRoleIBMSA || r == api.UserRoleImportStatus) && len(domainRoles) == 1 {
		if r == api.UserRoleIBMSA {
			c.Timeout = uint32(30 * 60) // jwtIbmSaTokenLife, 30 minutes
			c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(jwtIbmSaTokenLife))
		} else {
			c.Timeout = uint32(10 * 60) // jwtImportStatusTokenLife, 10 minutes
			c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(jwtImportStatusTokenLife))
		}
	}
	c.RegisteredClaims.IssuedAt = jwt.NewNumericDate(now.Add(_halfHourBefore)) // so that token won't be invalidated among controllers because of system time diff & iat

	// Validate token
	jwtCert := GetJWTSigningKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tokenString, err := token.SignedString(jwtCert.jwtPrivateKey)
	if tokenString == "" || err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
	}
	return id, utils.EncryptUserToken(tokenString, []byte(installID)), &c
}

func jwtGenFedJoinToken(masterCluster *api.RESTFedMasterClusterInfo, duration time.Duration) []byte {
	ticketString := jwtGenFedTicket(masterCluster.Secret, duration)
	c := joinToken{
		MasterServer: masterCluster.RestInfo.Server,
		MasterPort:   masterCluster.RestInfo.Port,
		JoinTicket:   ticketString,
	}
	tokenBytes, _ := json.Marshal(&c)
	return tokenBytes
}

func jwtGenFedTicket(secret string, duration time.Duration) string {
	now := time.Now()
	c := joinTicket{
		Salt:      mathRand.Intn(math.MaxInt32),
		ExpiresAt: now.Add(duration).Unix(),
	}
	tokenBytes, _ := json.Marshal(&c)
	return utils.EncryptSensitive(string(tokenBytes), []byte(secret))
}

func _genFedJwtToken(c *tokenClaim, callerFedRole, clusterID, secret string, rsaPrivateKey *rsa.PrivateKey) string {
	// rsaPrivateKey being non-nil is for validating new public/private keys purpose
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, *c)
	var privateKey *rsa.PrivateKey
	if rsaPrivateKey == nil {
		if privateKey = _getFedJointPrivateKey(clusterID); privateKey == nil {
			if jointCluster := clusHelper.GetFedJointCluster(clusterID); jointCluster != nil {
				log.WithFields(log.Fields{"id": jointCluster.ID}).Info("reload key")
				if err := setJointKeysInCache(callerFedRole, jointCluster); err == nil {
					privateKey = _getFedJointPrivateKey(clusterID)
				}
			}
		}
	} else {
		privateKey = rsaPrivateKey
	}
	if privateKey != nil {
		tokenString, _ := token.SignedString(privateKey)
		return utils.EncryptSensitive(tokenString, []byte(secret))
	} else {
		log.WithFields(log.Fields{"id": clusterID}).Error("empty private key")
	}
	return ""
}

func jwtGenFedMasterToken(user *share.CLUSUser, login *loginSession, clusterID, secret string) string {

	if !login.hasFedPermission() {
		// caller needs to have fed role or fed permission
		return ""
	}

	if user.RemoteRolePermits == nil || (len(user.RemoteRolePermits.DomainRole) == 0 && len(user.RemoteRolePermits.ExtraPermits) == 0) {
		return ""
	}

	id := utils.GetRandomID(idLength, "")

	//installID, _ := clusHelper.GetInstallationID()	// no need because it's not verified for master token(multi-clusters)
	now := time.Now()

	c := tokenClaim{
		Fullname:        user.Fullname,
		Username:        user.Username,
		Server:          user.Server,
		EMail:           user.EMail,
		Locale:          user.Locale,
		MainSessionID:   login.id,
		MainSessionUser: login.fullname,
		Timeout:         user.Timeout,
		Roles:           user.RemoteRolePermits.DomainRole,
		ExtraPermits:    user.RemoteRolePermits.ExtraPermits,
		RegisteredClaims: jwt.RegisteredClaims{
			ID: id,
			//Subject: installID,	    // no need because it's not verified for master token(multi-clusters)
			Issuer: localDev.Ctrler.ID,
			//IssuedAt:  now.Unix(),	// for fed master token only : comment out so that iat won't be validated on the joint cluster side
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtFedTokenLife)),
		},
	}

	return _genFedJwtToken(&c, api.FedRoleMaster, clusterID, secret, nil)
}

func jwtGenFedPingToken(callerFedRole, clusterID, secret string, rsaPrivateKey *rsa.PrivateKey) string {
	// rsaPrivateKey being non-nil is for validating new public/private keys purpose
	id := utils.GetRandomID(idLength, "")

	//installID, _ := clusHelper.GetInstallationID()	// no need because it's not verified for master token(multi-clusters)
	now := time.Now()
	// master token must not have fedAdmin role because joint clusters do not recognize fedAdmin role.
	c := tokenClaim{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: id,
			//Subject:   installID, // no need because it's not verified for ping token(multi-clusters)
			Issuer:    localDev.Ctrler.ID,
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtFedTokenLife)),
		},
	}

	return _genFedJwtToken(&c, callerFedRole, clusterID, secret, rsaPrivateKey)
}

func getAuthServersInOrder(acc *access.AccessControl) []*share.CLUSServer {
	servers := make([]*share.CLUSServer, 0)

	cfg := cacher.GetSystemConfig(acc)
	log.WithFields(log.Fields{"auth-order": cfg.AuthOrder}).Debug()

	if len(cfg.AuthOrder) > 0 {
		for _, name := range cfg.AuthOrder {
			if name == api.AuthServerLocal {
				servers = append(servers, &share.CLUSServer{Name: api.AuthServerLocal})
			} else {
				cs, _, _ := clusHelper.GetServerRev(name, acc)
				if cs != nil && isPasswordAuthServer(cs) && cs.Enable {
					servers = append(servers, cs)
				}
			}
		}
		return servers
	}

	// If AuthOrder is not specified, create a list with remote auth server. Put local auth as
	// the first: in case remote server is not accessiable, the user can login with local account.
	servers = append(servers, &share.CLUSServer{Name: api.AuthServerLocal})

	if cfg.AuthByPlatform {
		servers = append(servers, &share.CLUSServer{Name: api.AuthServerPlatform})
	}

	css := clusHelper.GetAllServers(acc)
	for _, cs := range css {
		if isPasswordAuthServer(cs) && cs.Enable {
			servers = append(servers, cs)
		}
	}

	return servers
}

// At this time, the user has already authenticated by the remote server. The server also
// tells us the user's group membership on the server. We lookup role from the group mapping.
func getRoleFromGroupMapping(memberof []string, groupRoleMappings []*share.GroupRoleMapping, defaultRole string,
	caseSensitive bool) (string, map[string][]string) { // returns (global role, roleDomains)
	if len(memberof) <= 0 {
		return defaultRole, make(map[string][]string, 0)
	}

	// groupRoleMappings is already sorted by matching priority so we just use the 1st matched group
	memberSet := utils.NewSet()
	if !caseSensitive {
		for _, m := range memberof {
			memberSet.Add(strings.ToLower(m))
		}
	} else {
		for _, m := range memberof {
			memberSet.Add(m)
		}
	}
	for _, groupRoleMapping := range groupRoleMappings {
		gName := groupRoleMapping.Group
		if !caseSensitive {
			gName = strings.ToLower(gName)
		}
		if memberSet.Contains(gName) {
			var roleDomains map[string][]string
			if groupRoleMapping.RoleDomains != nil {
				roleDomains = groupRoleMapping.RoleDomains
			} else {
				roleDomains = make(map[string][]string)
			}
			return groupRoleMapping.GlobalRole, roleDomains
		}
	}

	return defaultRole, make(map[string][]string)
}

// SAML idp has authenticated the user.
func getSAMLUserFromAttrs(attrs map[string][]string, customGroupClaim string) (string, string, []string) {
	var username, email string

	if emails, ok := attrs[samlEmailKey]; ok && len(emails) > 0 {
		email = emails[0]
	}
	if usernames, ok := attrs[samlUserKey]; ok && len(usernames) > 0 {
		username = usernames[0]
	} else if email != "" {
		username = email
	} else {
		return "", email, nil
	}

	var groups []string
	if customGroupClaim != "" {
		log.WithFields(log.Fields{"group-claim": customGroupClaim}).Debug("Custom group claim")
		if gs, ok := attrs[customGroupClaim]; ok {
			return username, email, gs
		}
	}
	if gs, ok := attrs[samlNVGroupKey]; ok {
		groups = gs
	} else if gs, ok := attrs[samlMSGroupKey]; ok {
		groups = gs
	}
	return username, email, groups
}

// OpenID Connect has authenticated the user.
func getOIDCUserFromClaims(claims map[string]interface{}, customGroupClaim string) (string, string, []string) {
	var username, email string
	if v, ok := claims[oldcEmailKey]; ok {
		email, _ = v.(string)
	}
	if v, ok := claims[oidcPreferredNameKey]; ok {
		username, _ = v.(string)
	} else if v, ok := claims[oidcNameKey]; ok {
		username, _ = v.(string)
	} else if email != "" {
		username = email
	} else {
		return "", email, nil
	}

	var groups []string
	if customGroupClaim != "" {
		log.WithFields(log.Fields{"group-claim": customGroupClaim}).Debug("Custom group claim")
		if v, ok := claims[customGroupClaim]; ok {
			if gs, ok := v.([]string); ok {
				return username, email, gs
			} else if gs, ok := v.([]interface{}); ok {
				groups = make([]string, len(gs))
				for i, g := range gs {
					groups[i], _ = g.(string)
				}
				return username, email, groups
			}
		}
	}
	if v, ok := claims[oidcNVGroupKey]; ok {
		if gs, ok := v.([]string); ok {
			return username, email, gs
		} else if gs, ok := v.([]interface{}); ok {
			groups = make([]string, len(gs))
			for i, g := range gs {
				groups[i], _ = g.(string)
			}
		}
	} else if v, ok := claims[oidcGroupKey]; ok {
		if gs, ok := v.([]string); ok {
			return username, email, gs
		} else if gs, ok := v.([]interface{}); ok {
			groups = make([]string, len(gs))
			for i, g := range gs {
				groups[i], _ = g.(string)
			}
		}
	}

	return username, email, groups
}

func remotePasswordAuth(cs *share.CLUSServer, pw *api.RESTAuthPassword) (*share.CLUSUser, error) {
	if cs.LDAP != nil {
		_, groups, err := remoteAuther.LDAPAuth(cs.LDAP, pw.Username, pw.Password)
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"server": cs.Name, "user": pw.Username, "groups": groups,
		}).Debug("LDAP/AD user authenticated")

		role, roleDomains := getRoleFromGroupMapping(groups, cs.LDAP.GroupMappedRoles, cs.LDAP.DefaultRole, cs.LDAP.Type == api.ServerLDAPTypeOpenLDAP)
		if role != api.UserRoleNone {
			log.WithFields(log.Fields{"server": cs.Name, "user": pw.Username, "role": role}).Debug("Authorized by group role mapping")
		}

		user, authz := lookupShadowUser(cs.Name, "", pw.Username, "", "", role, roleDomains, share.NvPermissions{}, nil, nil)
		if authz {
			return user, nil
		}

		return nil, errors.New("LDAP/AD user failed to map to a valid role")
	}

	return nil, errors.New("Unknown server type")
}

// it returns:
// 1. role on global domain (local cluster)
// 2. role : []namespace    (local cluster)
// 3. extra permissions on global domain (local cluster)
// 4. slice of (extra permissions, []namespace) on local cluster
// 5. domain: role/extra permissions on managed clusters in fed
func rbac2UserRole(rbacDomainRole map[string]string, rbacDomainPermits map[string]share.NvFedPermissions) (
	string, map[string][]string, share.NvPermissions, []share.CLUSPermitsAssigned, share.CLUSRemoteRolePermits) {

	var remoteDomainRole map[string]string
	var remoteExtraPermits map[string]share.NvPermissions

	fedRole := cacher.GetFedMembershipRoleNoAuth()
	gRole := api.UserRoleNone                // for role on global domain (local cluster)
	roleDomains := make(map[string][]string) // role : []domains, for role on namespaces (local cluster)
	gExtraPermits := share.NvPermissions{}   // for extra permits on global domain (local cluster)

	for domain, role := range rbacDomainRole {
		if domain == access.AccessDomainGlobal {
			gRole = role
		} else if role != api.UserRoleNone {
			// for namespaces
			roleDomains[role] = append(roleDomains[role], domain)
		}

		// now calculate for remote cluster access
		if fedRole == api.FedRoleMaster {
			var rAdjusted string
			if role == api.UserRoleFedAdmin {
				rAdjusted = api.UserRoleAdmin
			} else if role == api.UserRoleFedReader {
				rAdjusted = api.UserRoleReader
			}
			if rAdjusted != api.UserRoleNone {
				if remoteDomainRole == nil {
					remoteDomainRole = make(map[string]string, len(rbacDomainRole))
				}
				remoteDomainRole[domain] = rAdjusted
			}
		}
	}

	localPermitsDomains := make(map[share.NvPermissions][]string)
	for domain, permits := range rbacDomainPermits {
		// if the user doesn't have any role/permission on master cluster, it cannot access managed clusters
		if permits.Local.IsEmpty() {
			continue
		}
		if domain == access.AccessDomainGlobal {
			gExtraPermits = permits.Local
		} else {
			// for namespaces
			extraPermits := permits.Local
			extraPermits.FilterPermits(domain, "local", fedRole)
			if !extraPermits.IsEmpty() {
				localPermitsDomains[extraPermits] = append(localPermitsDomains[extraPermits], domain)
			}
		}

		if fedRole == api.FedRoleMaster && !permits.Remote.IsEmpty() {
			remoteDomainPermits := permits.Remote
			remoteDomainPermits.FilterPermits(domain, "remote", fedRole)
			if !remoteDomainPermits.IsEmpty() {
				if remoteExtraPermits == nil {
					remoteExtraPermits = make(map[string]share.NvPermissions, len(rbacDomainPermits))
				}
				remoteExtraPermits[domain] = remoteDomainPermits
			}
		}
	}

	var extraPermitsDomains []share.CLUSPermitsAssigned
	if len(localPermitsDomains) > 0 {
		extraPermitsDomains = make([]share.CLUSPermitsAssigned, 0, len(localPermitsDomains))
		for permits, domains := range localPermitsDomains {
			extraPermitsDomains = append(extraPermitsDomains, share.CLUSPermitsAssigned{Permits: permits, Domains: domains})
		}
	}

	remoteRolePermits := share.CLUSRemoteRolePermits{
		DomainRole:   remoteDomainRole,
		ExtraPermits: remoteExtraPermits,
	}

	return gRole, roleDomains, gExtraPermits, extraPermitsDomains, remoteRolePermits
}

func platformTokenRoleMapping(username string) map[string]string {
	accReadAll := access.NewReaderAccessControl()
	cfg := cacher.GetSystemConfig(accReadAll)
	if !cfg.AuthByPlatform {
		return nil
	}

	roles, _, err := global.ORCH.GetUserRoles(username, resource.SUBJECT_USER)
	if err != nil || roles == nil || len(roles) == 0 {
		return nil
	}

	log.WithFields(log.Fields{"user": username}).Debug("Authorized by platform")
	return roles
}

func tokenServerAuthz(cs *share.CLUSServer, username, email string, groups []string) (*share.CLUSUser, error) {
	var role string

	roleDomains := make(map[string][]string)
	// If platform authz enabled, try to get user role from there; if failed, fallback to group role mapping
	if roles := platformTokenRoleMapping(username); roles != nil {
		role, roleDomains, _, _, _ = rbac2UserRole(roles, nil)
	} else {
		if cs.SAML != nil {
			role, roleDomains = getRoleFromGroupMapping(groups, cs.SAML.GroupMappedRoles, cs.SAML.DefaultRole, true)
		} else if cs.OIDC != nil {
			role, roleDomains = getRoleFromGroupMapping(groups, cs.OIDC.GroupMappedRoles, cs.OIDC.DefaultRole, true)
		}

		if role != api.UserRoleNone {
			log.WithFields(log.Fields{"server": cs.Name, "user": username, "role": role}).Debug("Authorized by group role mapping")
		}
	}

	user, authz := lookupShadowUser(cs.Name, "", username, "", email, role, roleDomains, share.NvPermissions{}, nil, nil)
	if authz {
		return user, nil
	}

	return nil, errors.New("Failed to map to a valid role")
}

func platformPasswordAuth(pw *api.RESTAuthPassword) (*share.CLUSUser, error) {
	server := global.ORCH.GetAuthServerAlias()

	_, token, err := global.ORCH.Login(pw.Username, pw.Password)
	if err != nil {
		return nil, err
	}

	global.ORCH.Logout(pw.Username, token)

	log.WithFields(log.Fields{"server": server, "user": pw.Username}).Debug("Authenticated by platform")

	var role string
	var roleDomains map[string][]string

	// get groups associated with this user
	allRoles := make(map[string]string)
	groups, err := global.ORCH.GetPlatformUserGroups(token)
	if err == nil {
		for _, group := range groups {
			roles, _, err := global.ORCH.GetUserRoles(group, resource.SUBJECT_GROUP)
			if err == nil {
				for k, v := range roles {
					// not to override admin role
					// a subsequent record with reader-role will overwrite admin-role
					if r, found := allRoles[k]; found && r == "admin" {
						log.WithFields(log.Fields{"allRoles": allRoles}).Debug("Skip overwrite role.")
					} else {
						allRoles[k] = v
					}
				}
			}
		}

		log.WithFields(log.Fields{"groups": groups, "allRoles": allRoles}).Debug("combined group roles ")
	}

	roles, _, err := global.ORCH.GetUserRoles(pw.Username, resource.SUBJECT_USER)
	if err != nil || roles == nil || len(roles) == 0 {
		log.WithFields(log.Fields{"user": pw.Username}).Debug("No role available for this user.")
		// roleDomains = make(map[string][]string)
	} else {
		for k, v := range roles {
			if r, found := allRoles[k]; found && r == "admin" {
				log.WithFields(log.Fields{"allRoles": allRoles}).Debug("Skip overwrite role.")
			} else {
				allRoles[k] = v
			}
		}
	}

	role, roleDomains, _, _, _ = rbac2UserRole(allRoles, nil)
	log.WithFields(log.Fields{"role": role, "roleDomains": roleDomains, "allRoles": allRoles}).Debug("combined roles")

	user, authz := lookupShadowUser(server, "", pw.Username, "", "", role, roleDomains, share.NvPermissions{}, nil, nil)
	if authz {
		return user, nil
	}

	return nil, fmt.Errorf("%s user is not authorized", server)
}

type tLocalPwdAuthResult struct {
	blockedForFailedLogin bool
	blockedForExpiredPwd  bool
	userFound             bool
	blockAfterFailedCount int
	newPwdWeak            bool
	newPwdError           string
	pwdProfileBasic       api.RESTPwdProfileBasic
}

func localPasswordAuth(pw *api.RESTAuthPassword, acc *access.AccessControl) (*share.CLUSUser, tLocalPwdAuthResult, error) {
	var user *share.CLUSUser
	var result tLocalPwdAuthResult

	if pw.Username == "" || pw.Username[0] == '~' {
		return nil, result, errors.New("User not found")
	}
	now := time.Now()

	// Retrieve user from the cluster
	retry := 0
	for retry < retryClusterMax {
		var rev uint64

		user, rev, _ = clusHelper.GetUserRev(pw.Username, acc)
		if user == nil {
			return nil, result, errors.New("User not found")
		}

		if user.Server != "" {
			return nil, result, errors.New("User not found")
		}

		result.userFound = true
		origFailedLoginCount := user.FailedLoginCount
		origBlockLoginSince := user.BlockLoginSince
		pwdProfile, _ := cacher.GetPwdProfile(share.CLUSSysPwdProfileName)
		if pwdProfile.EnableBlockAfterFailedLogin {
			result.blockAfterFailedCount = pwdProfile.BlockAfterFailedCount
		}
		if pwdProfile.EnableBlockAfterFailedLogin && !user.BlockLoginSince.IsZero() {
			if time.Now().UTC().Before(user.BlockLoginSince.Add(time.Minute * time.Duration(pwdProfile.BlockMinutes))) {
				user.FailedLoginCount++
				if user.FailedLoginCount == 0 {
					user.FailedLoginCount = uint32(pwdProfile.BlockAfterFailedCount)
				}
				user.BlockLoginSince = time.Now().UTC()
				clusHelper.PutUserRev(user, rev)
				result.blockedForFailedLogin = true
				return nil, result, fmt.Errorf("User %s is temporarily blocked from login because of too many failed login attempts", pw.Username)
			} else {
				// user.BlockLoginSince is not zero time but current time is past user.BlockLoginSince
				// it means this is the 1st time the user tries to login beyond the blocked time window. Giva user a new start for failed login count.
				user.FailedLoginCount = 0
				user.BlockLoginSince = time.Time{}
			}
		} else if !pwdProfile.EnableBlockAfterFailedLogin && (!user.BlockLoginSince.IsZero() || user.FailedLoginCount > 0) {
			// EnableBlockAfterFailedLogin is disabled. so clear failed login info for this user
			user.FailedLoginCount = 0
			user.BlockLoginSince = time.Time{}
		}

		// Validate password
		hash := utils.HashPassword(pw.Password)
		if hash != user.PasswordHash {
			if pwdProfile.EnableBlockAfterFailedLogin {
				user.FailedLoginCount++
				if int(user.FailedLoginCount) >= pwdProfile.BlockAfterFailedCount {
					user.BlockLoginSince = time.Now().UTC()
					result.blockedForFailedLogin = true
				}
			}
			if user.FailedLoginCount != origFailedLoginCount || user.BlockLoginSince != origBlockLoginSince {
				clusHelper.PutUserRev(user, rev)
			}
			return nil, result, errors.New("Wrong password")
		} else {
			if pwdProfile.EnablePwdExpiration && pwdProfile.PwdExpireAfterDays > 0 && !user.PwdResetTime.IsZero() {
				pwdValidUnit := _pwdValidUnit
				if user.Fullname == common.DefaultAdminUser {
					pwdValidUnit = _pwdValidPerDayUnit
				}
				pwdExpireTime := user.PwdResetTime.Add(time.Duration(time.Minute * pwdValidUnit * time.Duration(pwdProfile.PwdExpireAfterDays)))
				if now.After(pwdExpireTime) {
					result.blockedForExpiredPwd = true
					return nil, result, fmt.Errorf("User %s is blocked from login because of expired password", pw.Username)
				}
			}

			if user.ResetPwdInNextLogin {
				if pw.NewPassword == nil {
					return user, result, nil
				}
				if weak, pwdHistoryToKeep, pwdProfileBasic, e := isWeakPassword(*pw.NewPassword, user.PasswordHash, user.PwdHashHistory, nil); weak {
					log.WithFields(log.Fields{"create": pw.Username}).Error(e)
					result.newPwdWeak = true
					result.newPwdError = e
					result.pwdProfileBasic = pwdProfileBasic
					return nil, result, fmt.Errorf("New password is too weak")
				} else {
					if pwdHistoryToKeep <= 1 { // because user.PasswordHash remembers one password hash
						user.PwdHashHistory = nil
					} else {
						user.PwdHashHistory = append(user.PwdHashHistory, user.PasswordHash)
						if i := len(user.PwdHashHistory) - pwdHistoryToKeep; i >= 0 { // len(user.PwdHashHistory) + 1(current password hash) should be <= pwdHistoryToKeep
							user.PwdHashHistory = user.PwdHashHistory[i+1:]
						}
					}
					user.PasswordHash = utils.HashPassword(*pw.NewPassword)
					user.PwdResetTime = time.Now().UTC()
					user.ResetPwdInNextLogin = false
					user.UseBootstrapPwd = false
				}
			}
		}

		user.LoginCount++
		if now.After(user.LastLoginAt) {
			user.LastLoginAt = now
		}
		user.FailedLoginCount = 0
		user.BlockLoginSince = time.Time{}

		if err := clusHelper.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"user": user.Username, "error": err, "rev": rev}).Error()
			retry++
		} else {
			log.WithFields(log.Fields{"user": user.Username}).Debug("Updated user in cluster")
			break
		}
	}

	// Even update cluster fails, still return authorized user
	if retry >= retryClusterMax {
		log.WithFields(log.Fields{"user": user.Username}).Error("Failed to update user in cluster")
	}

	return user, result, nil
}

func fedMasterTokenAuth(userName, masterToken, secret string) (*share.CLUSUser, *tokenClaim, error) {
	var user *share.CLUSUser

	claims, err := jwtValidateToken(masterToken, secret, nil)
	if err != nil {
		return nil, nil, err
	}

	if claims.ExpiresAt == nil {
		return nil, nil, errors.New("token expiration not set")
	}
	if time.Now().After(claims.ExpiresAt.Time) {
		return nil, nil, errTokenExpired
	}

	acc := access.NewAdminAccessControl()
	// Retrieve user from the cluster
	user, _, _ = clusHelper.GetUserRev(userName, acc)
	if user == nil && userName == common.ReservedFedUser {
		secret, _ := utils.GetGuid()
		// hidden fed user for POST("/v1/fed_auth") request on worker clusters
		u := share.CLUSUser{
			Fullname:     userName,
			Username:     userName,
			PasswordHash: utils.HashPassword(secret),
			Domain:       "",
			Role:         api.UserRoleAdmin, // HiddenFedUser is admin role
			Timeout:      common.DefIdleTimeoutInternal,
			RoleDomains:  make(map[string][]string),
			Locale:       common.OEMDefaultUserLocale,
			PwdResetTime: time.Now().UTC(),
		}
		value, _ := json.Marshal(u)
		key := share.CLUSUserKey(userName)
		cluster.PutIfNotExist(key, value, false)
		user, _, _ = clusHelper.GetUserRev(userName, acc)
	}
	if user == nil || user.Server != "" {
		return nil, nil, errors.New("User not found")
	}
	user.Username = claims.Username
	user.Server = claims.Server
	user.Timeout = claims.Timeout

	roleDomains := make(map[string][]string)
	for d, role := range claims.Roles {
		if d == access.AccessDomainGlobal {
			user.Role = role
		} else if role != api.UserRoleNone {
			roleDomains[role] = append(roleDomains[role], d)
		}
	}
	user.RoleDomains = roleDomains

	permitsDomains := make(map[share.NvPermissions][]string)
	for domain, permits := range claims.ExtraPermits {
		if !permits.IsEmpty() {
			if domain == access.AccessDomainGlobal {
				user.ExtraPermits = permits
			} else {
				permitsDomains[permits] = append(permitsDomains[permits], domain)
			}
		}
	}

	if len(permitsDomains) > 0 {
		extraPermitsDomains := make([]share.CLUSPermitsAssigned, 0, len(permitsDomains))
		for permits, domains := range permitsDomains {
			extraPermitsDomains = append(extraPermitsDomains, share.CLUSPermitsAssigned{Permits: permits, Domains: domains})
		}
		user.ExtraPermitsDomains = extraPermitsDomains
	}

	if user.Role == api.UserRoleNone && user.ExtraPermits.IsEmpty() {
		return nil, nil, errors.New("Access denied")
	}
	// do not increase user's LoginCount because this master login requests a real user login in the caller later

	return user, claims, nil
}

func isPasswordExpired(localAuthed bool, userName string, pwdResetTime time.Time) (int, int, bool) {
	pwdDaysUntilExpire := -1
	pwdHoursUntilExpire := 0
	if localAuthed {
		if pwdProfile, err := cacher.GetPwdProfile(share.CLUSSysPwdProfileName); err == nil {
			if pwdProfile.EnablePwdExpiration && pwdProfile.PwdExpireAfterDays > 0 {
				pwdValidUnit := _pwdValidUnit
				if userName == common.DefaultAdminUser {
					pwdValidUnit = _pwdValidPerDayUnit
				}
				pwdExpireTime := pwdResetTime.Add(time.Duration(time.Minute * pwdValidUnit * time.Duration(pwdProfile.PwdExpireAfterDays)))
				if time.Now().UTC().After(pwdExpireTime) {
					return 0, 0, true
				} else {
					hours := int(pwdExpireTime.Sub(time.Now()).Hours())
					pwdDaysUntilExpire = hours / 24
					pwdHoursUntilExpire = hours % 24
				}
			}
		}
	}

	return pwdDaysUntilExpire, pwdHoursUntilExpire, false
}

func handlerAuthLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	var defaultPW bool
	var localAuthed bool
	var remote string
	var mainSessionID string
	var mainSessionUser string
	var auth api.RESTAuthData
	var user *share.CLUSUser
	var rancherUser tRancherUser
	var rsessToken string
	var cacheRancherCookie bool

	accReadAll := access.NewReaderAccessControl()
	if localDev.Host.Platform == share.PlatformKubernetes && localDev.Host.Flavor == share.FlavorRancher {
		if header, ok := r.Header[api.RESTRancherTokenHeader]; ok && len(header) == 1 {
			if rsessToken = header[0]; rsessToken != "" {
				var err error
				var code int
				if cfg := cacher.GetSystemConfig(accReadAll); cfg.AuthByPlatform && cfg.RancherEP != "" {
					code = api.RESTErrUnauthorized
					rancherUser, err = checkRancherUserRole(cfg, rsessToken, accReadAll)
				} else {
					code = api.RESTErrPlatformAuthDisabled
					err = fmt.Errorf("platform auth disabled")
					log.WithFields(log.Fields{"err": err}).Error()
				}
				if err != nil {
					status := http.StatusUnauthorized
					if code == api.RESTErrUnauthorized && rancherUser.userGone {
						status = http.StatusGone
					}
					restRespError(w, status, code)
					return
				}
				cacheRancherCookie = true
			}
		}
	}

	if rancherUser.valid {
		var authz bool
		role, roleDomains, extraPermits, extraPermitsDomains, remoteRolePermits :=
			rbac2UserRole(rancherUser.domainRoles, rancherUser.domainPermissions)
		mainSessionID = fmt.Sprintf("%s%s", _rancherSessionPrefix, rancherUser.token)
		user, authz = lookupShadowUser(share.FlavorRancher, rancherUser.provider, rancherUser.name, rancherUser.id, "", role, roleDomains,
			extraPermits, extraPermitsDomains, &remoteRolePermits)
		if !authz {
			msg := fmt.Sprintf("Failed to map to a valid role: %s(%s)", rancherUser.name, rancherUser.id)
			restRespErrorMessage(w, http.StatusUnauthorized, api.RESTErrUnauthorized, msg)
			return
		}
		if role == api.UserRoleAdmin || role == api.UserRoleFedAdmin {
			if u, _, _ := clusHelper.GetUserRev(common.DefaultAdminUser, accReadAll); u != nil {
				if hash := utils.HashPassword(common.DefaultAdminPass); hash == u.PasswordHash {
					defaultPW = true
				}
			}
		}
		auth = api.RESTAuthData{
			Password: &api.RESTAuthPassword{
				Username: rancherUser.name,
			},
		}
		remote = r.RemoteAddr
		mainSessionUser = user.Fullname
	} else {
		// Read body
		body, _ := io.ReadAll(r.Body)

		err := json.Unmarshal(body, &auth)
		if err != nil || auth.Password == nil {
			log.WithFields(log.Fields{"error": err}).Error("Request error")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		if len(auth.Password.Password) == 0 {
			// Disallow empty password, this is to protect a LDAP server mis-config, https://github.com/Pylons/pyramid_ldap/issues/9
			log.Error("Empty password")
			restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
			return
		}

		username := auth.Password.Username
		remote = auth.ClientIP
		if remote == "" {
			remote = r.RemoteAddr
		}
		if i := strings.Index(remote, ":"); i > 0 {
			remote = remote[:i]
		}

		var errLocalAuth error
		var localAuthEnabled bool
		var localAuthResult tLocalPwdAuthResult

		servers := getAuthServersInOrder(accReadAll)

		// Succeed if one server authenticates the user
		for _, cs := range servers {
			log.WithFields(log.Fields{"server": cs.Name}).Debug()
			if cs.Name == api.AuthServerLocal {
				localAuthEnabled = true
				if user, localAuthResult, err = localPasswordAuth(auth.Password, accReadAll); err == nil {
					localAuthed = true
					break
				} else if localAuthResult.userFound {
					// when a user exists in local & ldap, 'err' will records the ldap auth result. 'errLocalAuth' is for the local auth result
					errLocalAuth = err
				}
			} else if cs.Name == api.AuthServerPlatform {
				if user, err = platformPasswordAuth(auth.Password); err == nil {
					break
				}
			} else {
				if user, err = remotePasswordAuth(cs, auth.Password); err == nil {
					break
				}
			}
			log.WithFields(log.Fields{"user": auth.Password.Username, "error": err}).Info()
		}

		// When local auth is not enabled, allow login using default 'admin' user to prevent
		// lock-out in case the remote server is mis-configured
		if user == nil && !localAuthEnabled && auth.Password.Username == common.DefaultAdminUser {
			log.Debug("Attempt to login with default admin user")
			if user, localAuthResult, err = localPasswordAuth(auth.Password, accReadAll); err != nil {
				log.WithFields(log.Fields{"user": auth.Password.Username, "error": err}).Info()
			} else {
				localAuthed = true
			}
		}

		if user == nil {
			code := api.RESTErrUnauthorized
			var ev share.TLogEvent = share.CLUSEvAuthLoginFailed
			var msg string
			if localAuthResult.userFound {
				if errLocalAuth != nil {
					// when a user exists in local & ldap and both auth failed, we adop the errot message from local auth
					msg = errLocalAuth.Error()
				} else if err != nil {
					msg = err.Error()
				}
				if localAuthResult.blockedForFailedLogin {
					ev = share.CLUSEvAuthLoginBlocked
					code = api.RESTErrUserLoginBlocked
				} else if localAuthResult.blockedForExpiredPwd {
					ev = share.CLUSEvAuthLoginBlocked
					code = api.RESTErrPasswordExpired
				}
			}
			log.WithFields(log.Fields{"user": auth.Password.Username, "msg": msg}).Error("User login failed")
			authLog(ev, auth.Password.Username, remote, "", nil, msg) // when msg is empty, authLog() will compose the msg
			if localAuthResult.newPwdWeak {
				restRespErrorMessageEx(w, http.StatusBadRequest, api.RESTErrWeakPassword, localAuthResult.newPwdError, localAuthResult.pwdProfileBasic)
			} else {
				restRespError(w, http.StatusUnauthorized, code)
			}
			return
		} else {
			// user password passes auth (could be local or remote auth)
			if !localAuthed && localAuthResult.userFound && localAuthResult.blockAfterFailedCount > 0 {
				// user password passes remote auth but not local auth(user found in local). do not increase local user's FailedLoginCount
				retry := 0
				for retry < retryClusterMax {
					if user, rev, _ := clusHelper.GetUserRev(auth.Password.Username, accReadAll); user != nil {
						if user.FailedLoginCount > 0 {
							user.FailedLoginCount--
							if user.FailedLoginCount < uint32(localAuthResult.blockAfterFailedCount) {
								// case: after restoring user's FailedLoginCount, it doesn't match the "block M minutes after N failed login attemps"
								user.BlockLoginSince = time.Time{}
							}
							if err := clusHelper.PutUserRev(user, rev); err != nil {
								retry++
							} else {
								break
							}
						} else {
							break
						}
					}
				}
				if retry >= retryClusterMax {
					log.WithFields(log.Fields{"user": user.Username}).Error("Failed to update user in cluster")
				}
			}
		}

		if username == common.DefaultAdminUser && auth.Password.Password == common.DefaultAdminPass {
			defaultPW = true
		}
		mainSessionID = _interactiveSessionID
	}

	if user != nil && localAuthed && user.ResetPwdInNextLogin {
		// do not login user when the user needs to reset password first
		resp := api.RESTTokenData{NeedToResetPassword: true}
		restRespSuccess(w, r, &resp, nil, nil, nil, "")
		return
	}

	var rc int
	var err error
	var login *loginSession

	fedRole, _ := cacher.GetFedMembershipRole(accReadAll)
	fedUserRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)
	if fedRole == api.FedRoleJoint && (fedUserRoles.Contains(user.Role) || user.ExtraPermits.HasPermFed()) {
		rc = userInvalidRequest
	} else {
		// Login user accounting
		login, rc = loginUser(user, nil, nil, remote, mainSessionID, mainSessionUser, fedRole, nil)
	}
	if rc != userOK {
		ev := share.CLUSEvAuthLoginFailed
		errMsg := "User login failed"
		if rc == userTimeout {
			ev = share.CLUSEvAuthTimeout
			errMsg = "User login timeout"
		}
		log.WithFields(log.Fields{"user": auth.Password.Username}).Error(errMsg)
		authLog(ev, auth.Password.Username, remote, "", nil, "")
		restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
		return
	}

	if len(user.AcceptedAlerts) > 0 {
		if (fedRole == api.FedRoleMaster && (fedUserRoles.Contains(user.Role) || user.ExtraPermits.HasPermFed())) ||
			(fedRole == api.FedRoleJoint && (user.Role == api.UserRoleAdmin || user.Role == api.UserRoleReader)) {
			var ids map[string]bool
			if fedRole == api.FedRoleMaster {
				ids = cacher.GetFedJoinedClusterIdMap(accReadAll)
			} else {
				if m := cacher.GetFedMasterCluster(accReadAll); m.ID != "" {
					ids = map[string]bool{
						m.ID: true,
					}
				}
			}
			if len(ids) > 0 {
				acceptedAlerts := utils.NewSetFromStringSlice(user.AcceptedAlerts)
				for id := range ids {
					s := cacher.GetFedJoinedClusterStatus(id, accReadAll)
					if s.SwitchToUnreachable > 0 {
						if elapsed := time.Since(s.LastConnectedTime); elapsed > (time.Duration(_teleFreq) * time.Minute) {
							key, _ := getFedDisconnectAlert(fedRole, id, accReadAll)
							if acceptedAlerts.Contains(key) {
								acceptedAlerts.Remove(key)
							}
						}
					}
				}
				if acceptedAlerts.Cardinality() != len(user.AcceptedAlerts) {
					if user, rev, _ := clusHelper.GetUserRev(auth.Password.Username, accReadAll); user != nil {
						user.AcceptedAlerts = acceptedAlerts.ToStringSlice()
						clusHelper.PutUserRev(user, rev)
					}
				}
			}
		}
	}

	resp := api.RESTTokenData{
		Token: &api.RESTToken{
			Token:    login.token,
			RESTUser: *user2REST(user, nil),
		},
	}
	resp.Token.DefaultPWD = defaultPW

	if cacheRancherCookie {
		rancherCookieMutex.Lock()
		rancherCookieCache[rsessToken] = time.Now().Add(time.Minute).Unix()
		rancherCookieMutex.Unlock()
	}
	if !rancherUser.valid || rancherUser.token == "" {
		pwdDaysUntilExpire, pwdHoursUntilExpire, expired := isPasswordExpired(localAuthed, user.Fullname, user.PwdResetTime)
		if expired {
			restRespError(w, http.StatusUnauthorized, api.RESTErrPasswordExpired)
			return
		}
		resp.PwdDaysUntilExpire = pwdDaysUntilExpire
		resp.PwdHoursUntilExpire = pwdHoursUntilExpire
		resp.Token.GlobalPermits, resp.Token.DomainPermits, err = access.GetUserPermissions(user.Role, user.RoleDomains, share.NvPermissions{}, nil)
	} else {
		resp.PwdDaysUntilExpire = -1
		resp.PwdHoursUntilExpire = -1
		resp.Token.GlobalPermits, resp.Token.DomainPermits, err = access.GetUserPermissions(user.Role, user.RoleDomains, user.ExtraPermits, user.ExtraPermitsDomains)
	}
	if err != nil {
		log.WithFields(log.Fields{"user": user.Fullname, "err": err}).Warn()
		restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
	} else {
		restRespSuccess(w, r, &resp, nil, login, nil, "")
	}
}

func handlerFedAuthLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	accReadAll := access.NewReaderAccessControl()
	if !isNoAuthFedOpAllowed(api.FedRoleJoint, w, r, accReadAll) {
		return
	}

	var err error
	// first check if it's in federation
	jointCluster := cacher.GetFedLocalJointCluster(accReadAll)
	if jointCluster.ID == "" {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	// Read body
	var auth api.RESTFedAuthData
	body, _ := io.ReadAll(r.Body)
	err = json.Unmarshal(body, &auth)
	if err != nil || auth.MasterToken == "" {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	remote := auth.ClientIP
	if remote == "" {
		remote = r.RemoteAddr
	}
	if i := strings.Index(remote, ":"); i > 0 {
		remote = remote[:i]
	}

	userName := auth.JointUsername
	if auth.JointUsername == common.DefaultAdminUser {
		userName = common.ReservedFedUser
	}
	user, claims, err := fedMasterTokenAuth(userName, auth.MasterToken, jointCluster.Secret)
	if err != nil || user == nil {
		var status = http.StatusUnauthorized
		if err == errTokenExpired {
			status = http.StatusRequestTimeout
		} else {
			fullname := fmt.Sprintf("%s(from %s)", auth.JointUsername, auth.MasterUsername)
			authLog(share.CLUSEvAuthLoginFailed, fullname, remote, "", nil, "")
			log.WithFields(log.Fields{"user": fullname, "error": err}).Error("Fed auth failed")
		}
		restRespError(w, status, api.RESTErrUnauthorized)
		return
	}

	// Login user accounting
	login, rc := loginUser(user, claims.Roles, claims.ExtraPermits, remote, claims.MainSessionID, claims.MainSessionUser, api.FedRoleJoint, nil)
	if rc != userOK {
		log.WithFields(log.Fields{"user": auth.JointUsername, "rc": rc}).Error("Fed master login failed")
		authLog(share.CLUSEvAuthLoginFailed, auth.JointUsername, remote, "", nil, "")
		restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
		return
	}
	userMutex.Lock()
	defer userMutex.Unlock()
	updateFedLoginSession(login)

	// Respond
	resp := api.RESTTokenData{
		Token: &api.RESTToken{
			Token: login.token,
		},
	}

	restRespSuccess(w, r, &resp, nil, login, nil, "")
}

func handlerAuthLoginServer(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	// Read body
	body, _ := io.ReadAll(r.Body)

	var data api.RESTAuthData
	err := json.Unmarshal(body, &data)
	if err != nil || (data.Password == nil && data.Token == nil) {
		e := "Request error"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	server := ps.ByName("server")

	remote := data.ClientIP
	if remote == "" {
		remote = r.RemoteAddr
	}
	if i := strings.Index(remote, ":"); i > 0 {
		remote = remote[:i]
	}

	accReadAll := access.NewReaderAccessControl()

	var user *share.CLUSUser
	var defaultPW bool
	var localAuthed bool
	var localAuthResult tLocalPwdAuthResult
	var sso SsoSession

	if data.Password != nil {
		if len(data.Password.Password) == 0 {
			// Disallow empty password, this is to protect a LDAP server mis-config, https://github.com/Pylons/pyramid_ldap/issues/9
			log.Error("Empty password")
			restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
			return
		}

		username := data.Password.Username

		log.WithFields(log.Fields{"server": server}).Debug()
		if server == api.AuthServerLocal {
			user, localAuthResult, err = localPasswordAuth(data.Password, accReadAll)
			if user != nil && err == nil {
				localAuthed = true
			}
		} else if server == api.AuthServerPlatform {
			user, err = platformPasswordAuth(data.Password)
		} else {
			cs, _, _ := clusHelper.GetServerRev(server, accReadAll)
			if cs == nil {
				e := "Server not found"
				log.WithFields(log.Fields{"server": server}).Error(e)
				restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
				return
			}
			user, err = remotePasswordAuth(cs, data.Password)
		}

		if err != nil {
			log.WithFields(log.Fields{"server": server, "user": data.Password.Username, "blockedLogin": localAuthResult.blockedForFailedLogin,
				"blockedPwd": localAuthResult.blockedForExpiredPwd, "error": err}).Error("User login failed")
			if server == api.AuthServerLocal && localAuthResult.newPwdWeak {
				restRespErrorMessageEx(w, http.StatusBadRequest, api.RESTErrWeakPassword, localAuthResult.newPwdError, localAuthResult.pwdProfileBasic)
			} else {
				code := api.RESTErrUnauthorized
				var ev share.TLogEvent = share.CLUSEvAuthLoginFailed
				var msg string
				if localAuthResult.userFound {
					msg = err.Error()
					if localAuthResult.blockedForFailedLogin {
						ev = share.CLUSEvAuthLoginBlocked
						code = api.RESTErrUserLoginBlocked
					} else if localAuthResult.blockedForExpiredPwd {
						ev = share.CLUSEvAuthLoginBlocked
						code = api.RESTErrPasswordExpired
					}
				}
				authLog(ev, data.Password.Username, remote, "", nil, msg)
				restRespError(w, http.StatusUnauthorized, code)
			}
			return
		}

		if username == common.DefaultAdminUser && data.Password.Password == common.DefaultAdminPass {
			defaultPW = true
		}
	} else if data.Token != nil {
		cs, _, _ := clusHelper.GetServerRev(server, accReadAll)
		if cs == nil {
			log.WithFields(log.Fields{"server": server}).Error("Server not found")
			restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
			return
		}
		if !cs.Enable {
			log.WithFields(log.Fields{"server": server}).Error("Server not enabled")
			restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
			return
		}

		if cs.SAML != nil {
			nameid, sessionIndex, attrs, err := remoteAuther.SAMLSPAuth(cs.SAML, data.Token)
			if err != nil || attrs == nil {
				log.WithFields(log.Fields{"server": server, "error": err}).Error("User login failed")
				authLog(share.CLUSEvAuthLoginFailed, "", remote, "", nil, "")
				restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
				return
			}

			log.WithFields(log.Fields{"server": server, "attrs": attrs}).Debug("Token validation succeeded")

			username, email, groups := getSAMLUserFromAttrs(attrs, cs.SAML.GroupClaim)
			if username == "" {
				err = errors.New("Unable to locate username")
			} else {
				user, err = tokenServerAuthz(cs, username, email, groups)
			}
			if err != nil {
				log.WithFields(log.Fields{"server": server, "user": username, "groups": groups, "error": err}).Error("Failed to get user from attribute")
				fullname := utils.MakeUserFullname(cs.Name, username)
				authLog(share.CLUSEvAuthLoginFailed, fullname, remote, "", nil, "")
				restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
				return
			}
			sso.SAMLNameID = nameid
			sso.SAMLSessionIndex = sessionIndex
		} else if cs.OIDC != nil {
			claims, err := remoteAuther.OIDCAuth(cs.OIDC, data.Token)
			if err != nil || claims == nil {
				log.WithFields(log.Fields{"server": server, "error": err}).Error("User login failed")
				authLog(share.CLUSEvAuthLoginFailed, "", remote, "", nil, "")
				restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
				return
			}

			log.WithFields(log.Fields{"server": server, "claims": claims}).Debug("Token validation succeeded")

			username, email, groups := getOIDCUserFromClaims(claims, cs.OIDC.GroupClaim)
			if username == "" {
				err = errors.New("Unable to locate username")
			} else {
				user, err = tokenServerAuthz(cs, username, email, groups)
			}
			if err != nil {
				log.WithFields(log.Fields{"server": server, "user": username, "groups": groups, "error": err}).Error("Failed to get user from claims")
				fullname := utils.MakeUserFullname(cs.Name, username)
				authLog(share.CLUSEvAuthLoginFailed, fullname, remote, "", nil, "")
				restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
				return
			}
		} else {
			log.WithFields(log.Fields{"server": server}).Error("Unsupported server type")
			restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
			return
		}
	}

	if user != nil && localAuthed && user.ResetPwdInNextLogin {
		// do not login user when the user needs to reset password first
		resp := api.RESTTokenData{NeedToResetPassword: true}
		restRespSuccess(w, r, &resp, nil, nil, nil, "")
		return
	}

	fedRole, _ := cacher.GetFedMembershipRole(accReadAll)
	// Login user accounting
	login, rc := loginUser(user, nil, nil, remote, _interactiveSessionID, "", fedRole, &sso)
	if rc != userOK {
		ev := share.CLUSEvAuthLoginFailed
		errMsg := "User login failed"
		if rc == userTimeout {
			ev = share.CLUSEvAuthTimeout
			errMsg = "User login timeout"
		}
		log.WithFields(log.Fields{"user": user.Fullname}).Error(errMsg)
		authLog(ev, user.Fullname, remote, "", nil, "")
		restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
		return
	}

	pwdDaysUntilExpire, pwdHoursUntilExpire, expired := isPasswordExpired(localAuthed, user.Fullname, user.PwdResetTime)
	if expired {
		restRespError(w, http.StatusUnauthorized, api.RESTErrPasswordExpired)
		return
	}

	// Respond
	resp := api.RESTTokenData{
		Token: &api.RESTToken{
			Token: login.token,
			RESTUser: api.RESTUser{
				Fullname:    user.Fullname,
				Server:      user.Server,
				Username:    user.Username,
				EMail:       user.EMail,
				Role:        user.Role,
				Timeout:     user.Timeout,
				Locale:      user.Locale,
				DefaultPWD:  defaultPW,
				RoleDomains: user.RoleDomains,
			},
		},
		PwdDaysUntilExpire:  pwdDaysUntilExpire,
		PwdHoursUntilExpire: pwdHoursUntilExpire,
	}
	resp.Token.GlobalPermits, resp.Token.DomainPermits, err = access.GetUserPermissions(user.Role, user.RoleDomains, share.NvPermissions{}, nil)
	if err != nil {
		log.WithFields(log.Fields{"user": user.Fullname, "err": err}).Warn()
		restRespError(w, http.StatusUnauthorized, api.RESTErrUnauthorized)
	} else {
		restRespSuccess(w, r, &resp, nil, login, nil, "")
	}
}

func clearTokensFromJointClusters(acc *access.AccessControl, login *loginSession) {
	fedRole, err := cacher.GetFedMembershipRole(acc)
	if err == nil && fedRole == api.FedRoleMaster {
		ids := cacher.GetFedJoinedClusterIdMap(acc)
		for id := range ids {
			joinedCluster := cacher.GetFedJoinedCluster(id, acc)
			if joinedCluster.ID != "" {
				talkToJointCluster(&joinedCluster, http.MethodDelete, "v1/fed_auth", id, "logout", []byte("{}"), nil, acc, login, []bool{false})
				cacher.SetFedJoinedClusterToken(id, login.id, "")
			}
		}
		cacher.SetFedJoinedClusterToken("", login.id, "")
	}
}

func handlerAuthLogout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if login.hasFedPermission() {
		clearTokensFromJointClusters(acc, login)
	}

	userMutex.Lock()
	login._logout()
	userMutex.Unlock()

	restRespSuccess(w, r, nil, acc, login, nil, "")
}

func (s *loginSession) hasFedPermission() bool {
	fedUserRoles := utils.NewSet(api.UserRoleFedAdmin, api.UserRoleFedReader)
	if role, ok := s.domainRoles[access.AccessDomainGlobal]; ok && fedUserRoles.Contains(role) {
		return true
	}
	for _, permits := range s.extraDomainPermits {
		if (permits.ReadValue&share.PERM_FED != 0) || (permits.WriteValue&share.PERM_FED != 0) {
			return true
		}
	}

	return false
}

// The request is from master cluster.
// It's for asking joint clusters to logout the sessions for the jwt tokens generated by serving POST(v1/fed_auth) requests from master cluster
func handlerFedAuthLogout(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := isFedOpAllowed(api.FedRoleJoint, _adminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	userMutex.Lock()
	login._delJointFedSessions()
	login._logout()
	userMutex.Unlock()

	restRespSuccess(w, r, nil, acc, login, nil, "")
}

func handlerAuthRefresh(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	// User lastAt updated to 'now'.
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	log.WithFields(log.Fields{"user": login.fullname}).Debug("Login keep-alive")

	restRespSuccess(w, r, nil, acc, login, nil, "")
}

// delete all login sessions/tokens that have the master cluster's mainSessionID. it means the joint cluster is leaving the federation
func delAllFedSessionTokens() {
	userMutex.Lock()
	defer userMutex.Unlock()
	if recordFedAuthSessions {
		for mainSessionID, tokenSet := range loginFedSessions {
			if mainSessionID != _interactiveSessionID && !strings.HasPrefix(mainSessionID, _rancherSessionPrefix) {
				for _, token := range tokenSet.ToStringSlice() {
					if s, ok := loginSessions[token]; ok {
						s._delete()
					}
				}
				delete(loginFedSessions, mainSessionID)
			}
		}
	} else {
		for _, s := range loginSessions {
			if s.mainSessionID != _interactiveSessionID && !strings.HasPrefix(s.mainSessionID, _rancherSessionPrefix) {
				s._delete()
			}
		}
	}
}

// With userMutex locked when calling this
func updateFedLoginSession(login *loginSession) {
	if !recordFedAuthSessions {
		return
	}

	if set, exist := loginFedSessions[login.mainSessionID]; !exist {
		loginFedSessions[login.mainSessionID] = utils.NewSet(login.token)
	} else if !set.Contains(login.token) {
		set.Add(login.token)
	}
}

func _getFedJointPublicKey() *rsa.PublicKey {
	fedAuthMutex.RLock()
	defer fedAuthMutex.RUnlock()
	return jointPublicKey
}

func _setFedJointPublicKey(key *rsa.PublicKey) {
	fedAuthMutex.Lock()
	defer fedAuthMutex.Unlock()
	jointPublicKey = key
}

func _getFedJointPrivateKey(id string) *rsa.PrivateKey {
	fedAuthMutex.RLock()
	defer fedAuthMutex.RUnlock()

	if key, exist := jointClustersKeyCache[id]; exist {
		return key
	}
	return nil
}

func _setFedJointPrivateKey(id string, key *rsa.PrivateKey) {
	fedAuthMutex.Lock()
	defer fedAuthMutex.Unlock()

	if key != nil {
		jointClustersKeyCache[id] = key
	} else {
		delete(jointClustersKeyCache, id)
	}
}

/* TEST only. Must be comment out in release build
type RESTRegularAuthTestDataDetail struct {
	ID              string `json:"id"`
	MainSessionID   string `json:"main_session_id"`
	MainSessionUser string `json:"main_session_user"`
	Token           string `json:"token"`
	User            string `json:"user"`
	Role            string `json:"role"`
}

type RESTFedAuthTestDataDetail struct {
	MainSessionID   string   `json:"main_session_id"`
	MainSessionUser string   `json:"main_session_user"`
	Tokens          []string `json:"tokens"`
}

type RESTAuthTestData struct {
	RegularSessions []*RESTRegularAuthTestDataDetail `json:"regular,omitempty"`
	FedSessions     []*RESTFedAuthTestDataDetail     `json:"fed,omitempty"`
}

func handlerDumpAuthData(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := isFedOpAllowed("*", _readerRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	userMutex.Lock()
	defer userMutex.Unlock()
	resp := RESTAuthTestData{
		RegularSessions: make([]*RESTRegularAuthTestDataDetail, 0, len(loginSessions)),
		FedSessions:     make([]*RESTFedAuthTestDataDetail, 0, len(loginFedSessions)),
	}

	for _, login := range loginSessions {
		d := &RESTRegularAuthTestDataDetail{
			ID:              login.id,
			MainSessionID:   login.mainSessionID,
			MainSessionUser: login.mainSessionUser,
			Token:           login.token,
			User:            login.fullname,
			Role:            login.domainRoles[""],
		}
		resp.RegularSessions = append(resp.RegularSessions, d)
	}

	for mainSessionID, tokenSet := range loginFedSessions {
		d := &RESTFedAuthTestDataDetail{
			MainSessionID:   mainSessionID,
			MainSessionUser: mainSessionUser,
			Tokens:          tokenSet.ToStringSlice(),
		}
		resp.FedSessions = append(resp.FedSessions, d)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get auth data")
}
*/
