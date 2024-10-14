package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func restPermissionsToCLUS(roleName string, restPermissions []*api.RESTRolePermission) ([]*share.CLUSRolePermission, error) {
	permissionOptions := make(map[string]*api.RESTRolePermitOptionInternal, len(access.PermissionOptions))
	for _, option := range access.PermissionOptions {
		permissionOptions[option.ID] = option
	}
	pIDs := utils.NewSet()
	permissions := make([]*share.CLUSRolePermission, 0, len(restPermissions))
	for _, p := range restPermissions {
		if p == nil || access.HiddenPermissions.Contains(p.ID) {
			continue // ignore hidden permissions
		}
		if pIDs.Contains(p.ID) {
			return nil, fmt.Errorf("Duplicate permission %s", p.ID)
		}
		pIDs.Add(p.ID)
		permission := &share.CLUSRolePermission{
			ID: p.ID,
		}
		if option, ok := permissionOptions[p.ID]; ok {
			if p.Read {
				if option.ReadSupported {
					permission.Read = true
				} else {
					return nil, fmt.Errorf("invalid read permission %s", p.ID)
				}
			}
			if p.Write {
				if option.WriteSupported {
					permission.Write = true
					if option.ReadSupported {
						// is role has a write permission, it has the read permission(if supported) as well
						permission.Read = true
					}
				} else {
					return nil, fmt.Errorf("invalid write permission %s", p.ID)
				}
			}
		} else {
			return nil, fmt.Errorf("invalid permission %s", p.ID)
		}
		if permission.Read || permission.Write {
			permissions = append(permissions, permission)
		}
	}
	if len(permissions) == 0 {
		return nil, fmt.Errorf("No Permission configured")
	}

	return permissions, nil
}

func restUserRoleToCLUS(rConfig *api.RESTUserRoleConfig) (*share.CLUSUserRole, error) {
	permissions, err := restPermissionsToCLUS(rConfig.Name, rConfig.Permissions)
	if err != nil {
		return nil, err
	}
	role := &share.CLUSUserRole{
		Name:        rConfig.Name,
		Comment:     rConfig.Comment,
		Permissions: permissions,
	}

	return role, nil
}

func handlerGetRolePermissionOptions(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSUserRole{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	global_options := make([]*api.RESTUserPermitOption, 0, len(access.PermissionOptions)-access.HiddenPermissions.Cardinality())
	domain_options := make([]*api.RESTUserPermitOption, 0, len(access.PermissionOptions)-access.HiddenPermissions.Cardinality())
	for _, p := range access.PermissionOptions {
		if access.HiddenPermissions.Contains(p.ID) {
			continue
		}
		option := &api.RESTUserPermitOption{
			ID:             p.ID,
			ReadSupported:  p.ReadSupported,
			WriteSupported: p.WriteSupported,
		}
		if access.CONST_PERM_SUPPORT_GLOBAL == (p.SupportScope & access.CONST_PERM_SUPPORT_GLOBAL) {
			global_options = append(global_options, option)
		}
		if access.CONST_PERM_SUPPORT_DOMAIN == (p.SupportScope & access.CONST_PERM_SUPPORT_DOMAIN) {
			domain_options = append(domain_options, option)
		}
	}

	resp := api.RESTAllUserPermitOptions{
		Options: api.RESTUserPermitOptions{
			GlobalOptions: global_options,
			DomainOptions: domain_options,
		},
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get permission options")
}

func handlerRoleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var role share.CLUSUserRole
	if !acc.Authorize(&role, nil) {
		restRespAccessDenied(w, login)
		return
	}

	resp := api.RESTUserRolesData{
		Roles: access.GetRoleList(),
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get role list")
}

func handlerRoleShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSUserRole{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name, _ := url.PathUnescape(ps.ByName("name"))
	if role := access.GetRoleDetails(name); role != nil {
		resp := api.RESTUserRoleData{Role: role}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get role details")
	} else {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
	}
}

func handlerRoleCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSUserRole{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTUserRoleConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	} else if role := access.GetRoleDetails(rconf.Config.Name); role != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, common.ErrObjectExists.Error())
		return
	}
	if reserved := access.GetReservedRoleNames(); reserved.Contains(rconf.Config.Name) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "reserved role name")
		return
	}

	if !isObjectNameValid(rconf.Config.Name) || strings.EqualFold(rconf.Config.Name, "none") {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidName)
		return
	}

	// Validate role permissions
	if role, err := restUserRoleToCLUS(rconf.Config); err != nil {
		log.WithFields(log.Fields{"err": err}).Error()
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	} else {
		var lock cluster.LockInterface
		if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
			return
		}
		defer clusHelper.ReleaseLock(lock)

		if err := clusHelper.CreateCustomRole(role, acc); err != nil {
			log.WithFields(log.Fields{"error": err, "role": rconf.Config.Name}).Error()
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, err.Error())
			return
		}

		restRespSuccess(w, r, nil, acc, login, &rconf, "Create role")
	}
}

func handlerRoleConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSUserRole{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name, _ := url.PathUnescape(ps.ByName("name")) // role name
	if reserved := access.GetReservedRoleNames(); reserved.Contains(name) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "reserved role")
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTUserRoleConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if role already exists
	if role, rev, err := clusHelper.GetCustomRoleRev(name, acc); err != nil {
		if role := access.GetRoleDetails(name); role != nil && role.Reserved {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "read-only role")
			return
		}
		log.WithFields(log.Fields{"role": name, "err": err}).Error()
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return
	} else {
		if role.Reserved {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "read-only role")
			return
		} else {
			// Validate role permissions
			if userRole, err := restUserRoleToCLUS(rconf.Config); err != nil {
				log.WithFields(log.Fields{"err": err}).Error()
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return
			} else {
				role.Comment = userRole.Comment
				role.Permissions = userRole.Permissions
				if err := clusHelper.PutCustomRoleRev(role, rev, acc); err != nil {
					log.WithFields(log.Fields{"role": name, "error": err}).Error()
					restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, err.Error())
					return
				}
			}
		}
	}
	restRespSuccess(w, r, nil, acc, login, &rconf, "Config role")
}

func recordRoleInUse(roleRefInfo map[string][]string, refByType, refBy string) {
	var ok bool

	var refInfo []string
	if refInfo, ok = roleRefInfo[refByType]; !ok {
		refInfo = make([]string, 0, 1)
	}
	refInfo = append(refInfo, refBy)
	roleRefInfo[refByType] = refInfo
}

func handlerRoleDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSUserRole{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	name, _ := url.PathUnescape(ps.ByName("name")) // role name
	if reserved := access.GetReservedRoleNames(); reserved.Contains(name) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "reserved role")
		return
	}
	if role := access.GetRoleDetails(name); role != nil && role.Reserved {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "read-only role")
		return
	}

	// Check if the role is referenced by any user/group
	roleRefInfo := make(map[string][]string) // key is refByType, value is user/server names
	users := clusHelper.GetAllUsers(acc)
	for _, user := range users {
		if user.Role == name {
			recordRoleInUse(roleRefInfo, "User", user.Fullname)
		} else {
			if domains, ok := user.RoleDomains[name]; ok && len(domains) > 0 {
				recordRoleInUse(roleRefInfo, "User", user.Fullname)
			}
		}
	}
	var serverType string
	var serverDefaultRole string
	var serverRoleGroups map[string][]string
	var serverGroupMappedRoles []*share.GroupRoleMapping
	servers := clusHelper.GetAllServers(acc)
	for _, server := range servers {
		if server.LDAP != nil {
			serverType = "LDAP"
			serverDefaultRole = server.LDAP.DefaultRole
			serverRoleGroups = server.LDAP.RoleGroups
			serverGroupMappedRoles = server.LDAP.GroupMappedRoles
		}
		if server.SAML != nil {
			serverType = "SAML"
			serverDefaultRole = server.SAML.DefaultRole
			serverRoleGroups = server.SAML.RoleGroups
			serverGroupMappedRoles = server.SAML.GroupMappedRoles
		}
		if server.OIDC != nil {
			serverType = "OIDC"
			serverDefaultRole = server.OIDC.DefaultRole
			serverRoleGroups = server.OIDC.RoleGroups
			serverGroupMappedRoles = server.OIDC.GroupMappedRoles
		}
		if serverDefaultRole == name {
			recordRoleInUse(roleRefInfo, serverType, server.Name)
		} else {
			if serverRoleGroups != nil {
				if groups, ok := serverRoleGroups[name]; ok && len(groups) > 0 {
					recordRoleInUse(roleRefInfo, serverType, server.Name)
					continue
				}
			}
			for _, groupRoleMapping := range serverGroupMappedRoles {
				if groupRoleMapping.GlobalRole == name {
					recordRoleInUse(roleRefInfo, serverType, server.Name)
					continue
				} else {
					if groupRoleMapping.RoleDomains != nil {
						if domains, ok := groupRoleMapping.RoleDomains[name]; ok && len(domains) > 0 {
							recordRoleInUse(roleRefInfo, serverType, server.Name)
							continue
						}
					}
				}
			}
		}
	}

	// Check if the role is referenced by any apikey
	now := time.Now()
	apikeys := clusHelper.GetAllApikeysNoAuth()
	for _, apikey := range apikeys {
		if now.UTC().Unix() >= apikey.ExpirationTimestamp {
			continue
		}

		if apikey.Role == name {
			recordRoleInUse(roleRefInfo, "Apikey", apikey.Name)
		} else {
			if domains, ok := apikey.RoleDomains[name]; ok && len(domains) > 0 {
				recordRoleInUse(roleRefInfo, "Apikey", apikey.Name)
			}
		}
	}

	var sb strings.Builder
	if len(roleRefInfo) > 0 { // this role is referenced at leaset by one refByType
		firstRefByType := true
		for refByType, refBy := range roleRefInfo {
			if firstRefByType {
				str := fmt.Sprintf("Role %s is referenced by\n", name)
				sb.WriteString(str)
				firstRefByType = false
			}
			str := fmt.Sprintf("%s: %s\n", refByType, strings.Join(refBy, ","))
			sb.WriteString(str)
		}
	}
	msg := sb.String()
	if len(msg) > 0 {
		log.WithFields(log.Fields{"msg": msg}).Error()
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrObjectInuse, msg)
		return
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockUserKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if role exists
	if _, _, err := clusHelper.GetCustomRoleRev(name, acc); err != nil {
		log.WithFields(log.Fields{"role": name, "err": err}).Error("get role")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrObjectNotFound, err.Error())
		return
	} else {
		if err := clusHelper.DeleteCustomRole(name); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("delete role")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, err.Error())
			return
		}
	}
	restRespSuccess(w, r, nil, acc, login, nil, "Delete role")
}
