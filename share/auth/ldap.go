package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Conn               *ldap.Conn
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string
	Host               string
	ServerName         string
	UserFilter         string
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	Timeout            time.Duration
}

// Connect connects to the ldap backend.
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			l, err = ldap.DialTLS("tcp", address, &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			})
			if err != nil {
				return err
			}
		}

		l.SetTimeout(lc.Timeout)
		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// Authenticate authenticates the user against the ldap backend.
func (lc *LDAPClient) Authenticate(password string) (string, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return "", nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return "", nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		lc.UserFilter,
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", nil, err
	}

	if len(sr.Entries) < 1 {
		return "", nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return "", nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	attrs := map[string]string{}
	for _, attr := range lc.Attributes {
		attrs[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return "", attrs, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return userDN, attrs, err
		}
	}

	log.WithFields(log.Fields{"dn": userDN}).Debug("authenticated")
	return userDN, attrs, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *LDAPClient) GetGroupsOfUser() ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{"filter": lc.GroupFilter}).Debug()
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		lc.GroupFilter,
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		log.WithFields(log.Fields{"cn": entry.GetAttributeValue("cn")}).Debug("group")
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
