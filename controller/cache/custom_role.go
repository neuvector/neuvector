package cache

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

func getAccessObjectFuncNoLock(g string) share.AccessObject {
	return getGroupWithoutLock(g)
}

func parseUserRolePermissions(r *share.CLUSUserRole) *share.CLUSUserRoleInternal {
	permissionOptions := make(map[string]*api.RESTRolePermitOptionInternal, len(access.PermissionOptions))
	for _, option := range access.PermissionOptions {
		permissionOptions[option.ID] = option
	}
	var readPermits, writePermits uint32
	for _, permission := range r.Permissions {
		if option, ok := permissionOptions[permission.ID]; ok {
			if access.HiddenPermissions.Contains(permission.ID) {
				continue
			}
			if len(option.ComplexPermits) > 0 {
				for _, option2 := range option.ComplexPermits {
					if permission.Read && option2.ReadSupported {
						readPermits |= option2.Value
					}
					if permission.Write && option2.WriteSupported {
						writePermits |= option2.Value
					}
				}
			} else {
				if permission.Read && option.ReadSupported {
					readPermits |= option.Value
				}
				if permission.Write && option.WriteSupported {
					writePermits |= option.Value
				}
			}
		}
	}

	userRole := &share.CLUSUserRoleInternal{
		Name:         r.Name,
		Comment:      r.Comment,
		Reserved:     r.Reserved,
		ReadPermits:  readPermits,
		WritePermits: writePermits,
	}
	return userRole
}

func userRoleConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug()
	name := share.CLUSGroupKey2Name(key)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var role share.CLUSUserRole
		_ = json.Unmarshal(value, &role)
		if roleInternal := parseUserRolePermissions(&role); roleInternal != nil {
			access.AddRole(name, roleInternal)
		}
	case cluster.ClusterNotifyDelete:
		access.DeleteRole(name)
	}
}

func (m CacheMethod) AuthorizeCustomCheck(name string, acc *access.AccessControl) bool { // name is group name
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	return acc.Authorize(&share.CLUSCustomCheck{Name: name}, getAccessObjectFuncNoLock)
}

func (m CacheMethod) AuthorizeFileMonitorProfile(name string, acc *access.AccessControl) bool { // name is group name
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	return acc.Authorize(&share.CLUSCustomCheck{Name: name}, getAccessObjectFuncNoLock)
}

func (m CacheMethod) PutCustomRoles(roles map[string]*share.CLUSUserRole) {
	for _, role := range roles {
		key := share.CLUSUserRoleKey(role.Name)
		value, _ := json.Marshal(role)
		userRoleConfigUpdate(cluster.ClusterNotifyAdd, key, value)
	}
}
