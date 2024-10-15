package kv

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type purgeFilterFunc func(epName, key string) bool

type cfgEndpoint struct {
	name        string
	key         string
	section     string
	lock        string
	isStore     bool
	purgeFilter purgeFilterFunc
}

const (
	_filterFedPolicyObjects = iota + 1
)

type fedKeyInfo struct {
	filterFedObjectType int      // the fed policy objects to filter on non-master clusters under an endpoint
	fedMasterOnlyKeys   []string // the keys to filter on non-master clusters under an endpoint, like "object/config/admission_control/fed/"
	filterSubKeyPrefix  []string // the subkey prefix to filter on non-master clusters under an endpoint, like "fed.xyz"
	alwaysFilterKeys    []string // the keys to always skip under an endpoint, like "object/config/federation/clusters_status/"
}

// for backup/restore filtering of joint-clusters in a fed
var _fedKeyInfo = map[string]fedKeyInfo{
	share.CFGEndpointGroup:            {filterSubKeyPrefix: []string{api.FederalGroupPrefix}}, // filter keys like object/config/group/fed.group-1
	share.CFGEndpointPolicy:           {filterFedObjectType: _filterFedPolicyObjects},
	share.CFGEndpointProcessProfile:   {filterSubKeyPrefix: []string{api.FederalGroupPrefix}},
	share.CFGEndpointFileMonitor:      {filterSubKeyPrefix: []string{api.FederalGroupPrefix}},
	share.CFGEndpointFileAccessRule:   {filterSubKeyPrefix: []string{api.FederalGroupPrefix}},
	share.CFGEndpointResponseRule:     {fedMasterOnlyKeys: []string{share.CLUSConfigFedResponseRuleKey}},
	share.CFGEndpointAdmissionControl: {fedMasterOnlyKeys: []string{share.CLUSConfigFedAdmCtrlKey}},
	share.CFGEndpointRegistry:         {filterSubKeyPrefix: []string{api.FederalGroupPrefix}}, // filter keys like object/config/registry/fed.registry-1
	share.CFGEndpointFederation: {
		alwaysFilterKeys:   []string{share.CLUSFedKey(share.CLUSFedClustersStatusSubKey), share.CLUSFedKey(share.CLUSFedToPingPollSubKey)},
		fedMasterOnlyKeys:  []string{share.CLUSFedKey(share.CFGEndpointSystem)},
		filterSubKeyPrefix: []string{share.CLUSFedRulesRevisionSubKey},
	},
}

// for import/purge filtering
var _skipKeyInfo = map[string][]string{
	share.CFGEndpointAdmissionControl: {share.CLUSAdmissionCertKey(share.CLUSConfigAdmissionControlStore, share.DefaultPolicyName)},
	share.CFGEndpointCrd:              {share.CLUSAdmissionCertKey(share.CLUSConfigCrdStore, share.DefaultPolicyName)},
}

var fedCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointFederation, key: share.CLUSConfigFederationStore, isStore: true,
	section: api.ConfSectionPolicy, lock: share.CLUSLockFedKey, purgeFilter: purgeFedFilter} // federation cfgEndpoint
var groupCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointGroup, key: share.CLUSConfigGroupStore, isStore: true,
	section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey, purgeFilter: purgeGroupFilter} // group cfgEndpoint
var pprofileCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointProcessProfile, key: share.CLUSConfigProcessProfileStore, isStore: true,
	section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey, purgeFilter: purgeGroupFilter} // process profile cfgEndpoint
var fmonitorCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointFileMonitor, key: share.CLUSConfigFileMonitorStore, isStore: true,
	section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey, purgeFilter: purgeGroupFilter} // file monitor cfgEndpoint
var faccessCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointFileAccessRule, key: share.CLUSConfigFileAccessRuleStore, isStore: true,
	section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey, purgeFilter: purgeGroupFilter} // file access cfgEndpoint
var registryCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointRegistry, key: share.CLUSConfigRegistryStore, isStore: true,
	section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey}
var sigstoreCfgEndpoint *cfgEndpoint = &cfgEndpoint{name: share.CFGEndpointSigstoreRootsOfTrust, key: share.CLUSConfigSigstoreRootsOfTrust, isStore: true,
	section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey}

// Order is important
var cfgEndpoints []*cfgEndpoint = []*cfgEndpoint{
	fedCfgEndpoint,
	{name: share.CFGEndpointUserRole, key: share.CLUSConfigUserRoleStore, isStore: true,
		section: api.ConfSectionUser, lock: share.CLUSLockUserKey},
	{name: share.CFGEndpointPwdProfile, key: share.CLUSConfigPwdProfileStore, isStore: true,
		section: api.ConfSectionUser, lock: share.CLUSLockUserKey},
	{name: share.CFGEndpointUser, key: share.CLUSConfigUserStore, isStore: true,
		section: api.ConfSectionUser, lock: share.CLUSLockUserKey},

	{name: share.CFGEndpointApikey, key: share.CLUSConfigApikeyStore, isStore: true,
		section: api.ConfSectionUser, lock: share.CLUSLockApikeyKey},

	{name: share.CFGEndpointLicense, key: share.CLUSConfigLicenseKey, isStore: false,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointEULA, key: share.CLUSConfigEULAKey, isStore: false,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},

	// Not to export uniconf, if the exported config is going to be used on other systems,
	// uniconf settings are not portable; if the export config is used on the system itself,
	// the current state is kept, no refresh of uniconf keys.
	// {name: "uniconf", key: share.CLUSUniconfStore, isStore: true,
	//	section: api.ConfEndpointIDConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointServer, key: share.CLUSConfigServerStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointSystem, key: share.CLUSConfigSystemKey, isStore: false,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointScan, key: share.CLUSConfigScanKey, isStore: false,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	sigstoreCfgEndpoint,
	registryCfgEndpoint,
	{name: share.CFGEndpointAdmissionControl, key: share.CLUSConfigAdmissionControlStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockAdmCtrlKey},
	groupCfgEndpoint,
	{name: share.CFGEndpointPolicy, key: share.CLUSConfigPolicyStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	pprofileCfgEndpoint,
	fmonitorCfgEndpoint,
	faccessCfgEndpoint,
	{name: share.CFGEndpointResponseRule, key: share.CLUSConfigResponseRuleStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointCrd, key: share.CLUSConfigCrdStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointDlpRule, key: share.CLUSConfigDlpRuleStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointDlpGroup, key: share.CLUSConfigDlpGroupStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointWafRule, key: share.CLUSConfigWafRuleStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointWafGroup, key: share.CLUSConfigWafGroupStore, isStore: true,
		section: api.ConfSectionPolicy, lock: share.CLUSLockPolicyKey},
	{name: share.CFGEndpointScript, key: share.CLUSConfigScriptStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointCompliance, key: share.CLUSConfigComplianceStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointVulnerability, key: share.CLUSConfigVulnerabilityStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointDomain, key: share.CLUSConfigDomainStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
	{name: share.CFGEndpointCloud, key: share.CLUSConfigCloudStore, isStore: true,
		section: api.ConfSectionConfig, lock: share.CLUSLockConfigKey},
}

// Endpoint name to endping
var cfgEndpointMap map[string]*cfgEndpoint = make(map[string]*cfgEndpoint)

func purgeFedFilter(epName, key string) bool {
	return false // no purge
}

func purgeGroupFilter(epName, key string) bool {
	accAdmin := access.NewFedAdminAccessControl()

	name := share.CLUSGroupKey2Name(key)
	group, _, _ := clusHelper.GetGroup(name, accAdmin)

	// Keep the learned, ground group & reserved local/fed groups
	return group == nil || ((group.CfgType == share.FederalCfg || group.CfgType == share.UserCreated) && !group.Reserved)
}

func skipCertFilter(epName, key string) bool { // return true means to skip the key
	if skipKeys, ok := _skipKeyInfo[epName]; ok {
		for _, skipKeyPath := range skipKeys {
			if key == skipKeyPath { // this key should be skipped
				return true
			}
		}
	}
	return false
}

func readKeyValue(reader *bufio.Reader) (string, string, error) {
	for {
		key, err := reader.ReadString('\n')
		if err == io.EOF || err != nil {
			return "", "", err
		} else if key == "\n" {
			continue
		}

		value, err := reader.ReadString('\n')
		if err == io.EOF || err != nil {
			return "", "", err
		}

		if !strings.HasPrefix(key, "#") && !strings.HasPrefix(value, "#") {
			// Remove trailing \n !!
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			return key, value, nil
		}
	}
}

func isFedObject(filterFedObjectType int, key string, value []byte, restore bool) (bool, []byte) {
	switch filterFedObjectType {
	case _filterFedPolicyObjects:
		policyRulePrefix := share.CLUSConfigPolicyStore + "default/rule/"
		if strings.HasPrefix(key, policyRulePrefix) {
			idRaw, _ := strconv.Atoi(key[len(policyRulePrefix):])
			id := uint32(idRaw)
			if id > api.PolicyFedRuleIDBase && id < api.PolicyFedRuleIDMax {
				return true, nil
			}
		} else {
			if key == share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName) {
				var rhs []*share.CLUSRuleHead
				var uzb []byte
				var tmpvalue []byte = value

				//for backup case unzip rulelist before save to file
				if !restore {
					//do unzip
					uzb = utils.GunzipBytes(value)
					if uzb == nil {
						log.Error("Failed to unzip data")
						return true, nil
					}
					tmpvalue = uzb
				}

				if nvJsonUnmarshal(key, tmpvalue, &rhs) == nil {
					// because fed policies are always in top, we can simply iterate thru rhs
					firstNonFedIdx := len(rhs)
					for idx, rh := range rhs {
						if rh != nil && rh.CfgType != share.FederalCfg {
							firstNonFedIdx = idx
							break
						}
					}
					if firstNonFedIdx > 0 {
						newValue, _ := json.Marshal(rhs[firstNonFedIdx:])
						return false, newValue
					} else {
						//in case there are no fed policies
						if !restore {
							return false, uzb
						}
					}
				} else {
					if !restore {
						return false, uzb
					}
				}
			}
		}
	default:
		//for FedRoleMaster unzip policy rulelist before save to storage
		if !restore && key == share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName) {
			//do unzip
			uzb := utils.GunzipBytes(value)
			if uzb == nil {
				log.Error("Failed to unzip policy rulelist")
				return true, nil
			}
			return false, uzb
		}
	}

	if key == share.CLUSPolicyRuleListKey(share.DefaultPolicyName) {
		//since 3.2.1 rulelist key is changed to CLUSPolicyZipRuleListKey
		//so skip backup/export using CLUSPolicyRuleListKey
		//for restore we still need to restore older version backup file that only
		//has CLUSPolicyRuleListKey
		return !restore, nil
	}

	return false, nil
}

func (ep cfgEndpoint) getBackupFilename() string {
	return fmt.Sprintf("%s%s.backup", configBackupDir, ep.name)
}

func (ep cfgEndpoint) getTempFilePrefix() string {
	return fmt.Sprintf("nvcfg.%s", ep.name)
}

// the written-to-file backup values are always in text format
func (ep cfgEndpoint) backup(fedRole string) error {
	log.WithFields(log.Fields{"endpoint": ep.name}).Debug()

	if _, err := os.Stat(configBackupDir); os.IsNotExist(err) {
		if err = os.MkdirAll(configBackupDir, 0755); err != nil {
			log.WithFields(log.Fields{"error": err, "dir": configBackupDir}).Error("Failed to make directory")
			return err
		}
	}

	prefix := ep.getTempFilePrefix()

	// Cannot be in /tmp, because /tmp is of different partition of /var/neuvector, os.rename() will fail
	err := filepath.Walk(configBackupDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithFields(log.Fields{"path": path, "error": err.Error()}).Error()
			return err
		}
		if info.IsDir() {
			if path == configBackupDir {
				return nil
			} else {
				return filepath.SkipDir
			}
		}
		if strings.HasPrefix(info.Name(), prefix) {
			log.WithFields(log.Fields{"path": path}).Error("Remove leftover temp file")
			os.Remove(path)
		}
		return nil
	})
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Failed to walk directory")
	}

	tmpfile, err := os.CreateTemp(configBackupDir, prefix)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create temp. file")
		return err
	}

	defer os.Remove(tmpfile.Name())

	// Write key/value to file
	wfp := bufio.NewWriter(tmpfile)
	if err = ep.write(wfp, fedRole); err != nil {
		log.WithFields(log.Fields{"error": err, "file": tmpfile.Name()}).Error("Failed to write temp. file")
		tmpfile.Close()
		return err
	}
	wfp.Flush()

	if err = tmpfile.Close(); err != nil {
		log.WithFields(log.Fields{"error": err, "file": tmpfile.Name()}).Error("Failed to close temp. file")
		return err
	}

	stat, err := os.Stat(tmpfile.Name())
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": tmpfile.Name()}).Error("Failed to stat temp. file")
		return err
	}
	if stat.Size() == 0 && ep.name == share.CFGEndpointUser {
		log.WithFields(log.Fields{"endpoint": ep.name}).Error("Ingore empty backup file")
		return fmt.Errorf("Empty backup file")
	}

	target := ep.getBackupFilename()
	if err = os.Rename(tmpfile.Name(), target); err != nil {
		log.WithFields(log.Fields{
			"error": err, "file": tmpfile.Name(), "target": target,
		}).Error("Failed to move temp. file")
		return err
	}

	return nil
}

// value of each key in the file is always in text format (i.e. non-gzip format). Compress it if it's >= 512k before restoring to kv
func (ep cfgEndpoint) restore(importInfo *fedRulesRevInfo, txn *cluster.ClusterTransact) error {
	fedEndpointCfg := false
	source := ep.getBackupFilename()
	if ep.name == share.CFGEndpointFederation {
		fedEndpointCfg = true
	}
	if _, err := os.Stat(source); os.IsNotExist(err) {
		// Config files might not be persistent or directory might not be mapped.
		log.WithFields(log.Fields{"error": err, "file": source}).Info("File not exist")
		return err
	}

	if fedEndpointCfg {
		f, err := os.Open(source)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "file": source}).Error("Unable to open file to read")
			return err
		}
		r := bufio.NewReader(f)
		for {
			key, value, err := readKeyValue(r)
			if err == io.EOF {
				break
			} else if err != nil {
				break
			}
			// get fedRole first
			subKey := share.CLUSKeyNthToken(key, 3)
			if subKey == share.CLUSFedMembershipSubKey {
				var m share.CLUSFedMembership
				if nvJsonUnmarshal(key, []byte(value), &m) == nil {
					importInfo.fedRole = m.FedRole
					log.WithFields(log.Fields{"fedRole": importInfo.fedRole}).Info()
				}
				break
			}
		}
		f.Close()
	}

	f, err := os.Open(source)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": source}).Error("Unable to open file to read")
		return err
	}

	defer f.Close()

	var filterFedObjectType int
	var fedMasterOnlyKeys, filterSubKeyPrefix, alwaysFilterKeys []string
	if keyInfo, ok := _fedKeyInfo[ep.name]; ok {
		if importInfo.fedRole != api.FedRoleMaster { // need to filter fed rule keys on non-master cluster
			filterFedObjectType = keyInfo.filterFedObjectType
			fedMasterOnlyKeys = keyInfo.fedMasterOnlyKeys
			filterSubKeyPrefix = keyInfo.filterSubKeyPrefix
		}
		alwaysFilterKeys = keyInfo.alwaysFilterKeys
	}

	// Restore key/value from files
	count := 0
	r := bufio.NewReader(f)
	policyZipRuleListKey := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)
	for {
		key, value, err := readKeyValue(r)
		if err == io.EOF {
			return errDone
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to read line")
			return ErrInvalidFileFormat
		}

		if skipCertFilter(ep.name, key) {
			continue
		}

		if fedEndpointCfg && importInfo.fedRole == api.FedRoleMaster {
			subKey := share.CLUSKeyNthToken(key, 3)
			if subKey == share.CLUSFedRulesRevisionSubKey {
				importInfo.fedRulesRevValue = value
				// do not write to kv now. postpone it at the last write
				continue
			}
		}

		if ep.name == share.CFGEndpointUser {
			var u share.CLUSUser
			if nvJsonUnmarshal(key, []byte(value), &u) == nil {
				u.FailedLoginCount = 0
				u.BlockLoginSince = time.Time{}
				u.PwdResetTime = time.Now().UTC()
				data, _ := json.Marshal(&u)
				value = string(data)
				if u.Fullname == common.DefaultAdminUser && u.Server == "" {
					importInfo.defAdminRestored = true
				}
			}
		}

		skip := false
		for _, prefix := range fedMasterOnlyKeys {
			if strings.HasPrefix(key, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			for _, filterKey := range alwaysFilterKeys {
				if strings.HasPrefix(key, filterKey) {
					skip = true
					break
				}
			}
		}
		if !skip {
			yes, newValue := isFedObject(filterFedObjectType, key, []byte(value), true)
			if yes {
				skip = true // filter fed policy objects on non-master cluster
			} else if newValue != nil {
				value = string(newValue)
			}
		}
		if !skip {
			ss := strings.Split(key, "/")
			if len(ss) > 0 {
				kLast := ss[len(ss)-1]
				for _, prefix := range filterSubKeyPrefix {
					if strings.HasPrefix(kLast, prefix) {
						skip = true
						break
					}
				}
			}
		}

		// Value can be empty if a key was never been written when it's exported
		if !skip && len(value) != 0 {
			array, err := upgrade(key, []byte(value))
			if err != nil {
				log.WithFields(log.Fields{"error": err, "key": key, "value": value}).Error("Failed to upgrade key/value")
				return ErrInvalidFileFormat
			}
			if key == policyZipRuleListKey {
				applyTransaction(txn, nil, false, 0)
				//zip rulelist before put to cluster during restore
				_ = clusHelper.PutPolicyRuleListZip(key, array)
			} else {
				_ = clusHelper.DuplicateNetworkKeyTxn(txn, key, array)
				//for CLUSConfigSystemKey only
				_ = clusHelper.DuplicateNetworkSystemKeyTxn(txn, key, array)
				if len(array) >= cluster.KVValueSizeMax && strings.HasPrefix(key, share.CLUSConfigCrdStore) { // 512 * 1024
					zb := utils.GzipBytes(array)
					txn.PutBinary(key, zb)
				} else {
					txn.Put(key, array)
				}
				if txn.Size() >= 64 {
					applyTransaction(txn, nil, false, 0)
				}
			}

			count++
		}
	}
}

// the written-to-file values are always in text format. If it's in gzip format, unzip it before writing to file for the backup/export
func (ep cfgEndpoint) write(writer *bufio.Writer, fedRole string) error {
	var filterFedObjectType int
	var fedMasterOnlyKeys, filterSubKeyPrefix, alwaysFilterKeys []string
	if keyInfo, ok := _fedKeyInfo[ep.name]; ok {
		if fedRole != api.FedRoleMaster { // need to filter fed rule keys on non-master cluster
			filterFedObjectType = keyInfo.filterFedObjectType
			fedMasterOnlyKeys = keyInfo.fedMasterOnlyKeys
			filterSubKeyPrefix = keyInfo.filterSubKeyPrefix
		}
		alwaysFilterKeys = keyInfo.alwaysFilterKeys
	}

	if ep.isStore {
		if kvPairs, err := cluster.List(ep.key); err == nil || err == cluster.ErrEmptyStore {
			for _, kvPair := range kvPairs {
				key := kvPair.Key
				skip := false
				if skipCertFilter(ep.name, key) {
					continue
				}
				for _, prefix := range fedMasterOnlyKeys {
					if strings.HasPrefix(key, prefix) {
						skip = true
						break
					}
				}
				if !skip {
					for _, filterKey := range alwaysFilterKeys {
						if strings.HasPrefix(key, filterKey) {
							skip = true
							break
						}
					}
				}
				if !skip {
					ss := strings.Split(key, "/")
					if len(ss) > 0 {
						kLast := ss[len(ss)-1]
						for _, prefix := range filterSubKeyPrefix {
							if strings.HasPrefix(kLast, prefix) {
								skip = true
								break
							}
						}
					}
				}
				if !skip {
					value := kvPair.Value
					yes, newValue := isFedObject(filterFedObjectType, key, value, false)
					if yes {
						continue // filter fed policy objects on non-master cluster
					} else if newValue != nil {
						value = newValue
					}
					// [31, 139] is the first 2 bytes of gzip-format data
					if strings.HasPrefix(key, share.CLUSConfigCrdStore) && len(value) >= 2 && value[0] == 31 && value[1] == 139 {
						if value = utils.GunzipBytes(value); value == nil {
							log.WithFields(log.Fields{"key": key}).Error("Failed to unzip data")
							continue
						}
					}
					line := fmt.Sprintf("%s\n%s\n", key, value)
					if _, err = writer.WriteString(line); err != nil {
						return err
					}
				}
			}
		} else {
			return err
		}
	} else {
		if value, err := cluster.Get(ep.key); err == nil || err == cluster.ErrKeyNotFound {
			line := fmt.Sprintf("%s\n%s\n", ep.key, value)
			if _, err = writer.WriteString(line); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func (ep cfgEndpoint) purge(txn *cluster.ClusterTransact, importTask *share.CLUSImportTask) error {
	if ep.isStore {
		keys, _ := cluster.GetStoreKeys(ep.key)
		if len(keys) > 0 {
			for _, key := range keys {
				if ep.purgeFilter == nil || ep.purgeFilter(ep.name, key) {
					txn.Delete(key)
				}
			}
		}
	} else {
		if ep.purgeFilter == nil || ep.purgeFilter(ep.name, ep.key) {
			txn.Delete(ep.key)
		}
	}
	if txn.Size() >= 64 {
		applyTransaction(txn, importTask, true, 0)
	}

	return nil
}
