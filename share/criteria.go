package share

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	CriteriaKeyImage     string = "image"
	CriteriaKeyHost      string = "node"
	CriteriaKeyWorkload  string = "container"
	CriteriaKeyService   string = "service"
	CriteriaKeyAddress   string = "address"
	CriteriaKeyLabel     string = "label"
	CriteriaKeyDomain    string = "domain"
	CriteriaKeyNamespace string = "namespace"
	// CriteriaKeyApp      string = "application"
	// CriteriaKeyWorkloadID string = "container_id"
	// CriteriaKeyGroup      string = "nv.group"
	// CriteriaKeyCIDR       string = "cidr"
	CriteriaKeyUser                          string = "user"
	CriteriaKeyK8sGroups                     string = "userGroups"
	CriteriaKeyImageRegistry                 string = "imageRegistry"
	CriteriaKeyLabels                        string = "labels"
	CriteriaKeyMountVolumes                  string = "mountVolumes"
	CriteriaKeyEnvVars                       string = "envVars"
	CriteriaKeyBaseImage                     string = "baseImage"
	CriteriaKeyCVENames                      string = "cveNames"
	CriteriaKeyCVECriticalCount              string = "cveCriticalCount"
	CriteriaKeyCVEHighCount                  string = "cveHighCount"
	CriteriaKeyCVEHighCountNoCritical        string = "cveHighCountNoCritical"
	CriteriaKeyCVEMediumCount                string = "cveMediumCount"
	CriteriaKeyCVECriticalWithFixCount       string = "cveCriticalWithFixCount"
	CriteriaKeyCVEHighWithFixCount           string = "cveHighWithFixCount"
	CriteriaKeyCVEHighWithFixCountNoCritical string = "cveHighWithFixCountNoCritical"
	CriteriaKeyCVEScore                      string = "cveScore"
	CriteriaKeyCVEScoreCount                 string = "cveScoreCount"
	CriteriaKeyImageScanned                  string = "imageScanned"
	CriteriaKeyImageSigned                   string = "imageSigned"
	CriteriaKeyRunAsRoot                     string = "runAsRoot"
	CriteriaKeyRunAsPrivileged               string = "runAsPrivileged"
	CriteriaKeyImageCompliance               string = "imageCompliance" // secrets, setIdPerm from scanning image results
	CriteriaKeyEnvVarSecrets                 string = "envVarSecrets"   // secrets from yaml resources
	CriteriaKeyImageNoOS                     string = "imageNoOS"
	CriteriaKeySharePidWithHost              string = "sharePidWithHost"
	CriteriaKeyShareIpcWithHost              string = "shareIpcWithHost"
	CriteriaKeyShareNetWithHost              string = "shareNetWithHost"
	CriteriaKeyAllowPrivEscalation           string = "allowPrivEscalation"
	CriteriaKeyPspCompliance                 string = "pspCompliance" // psp compliance violation
	CriteriaKeyRequestLimit                  string = "resourceLimit"
	CriteriaKeyModules                       string = "modules"
	CriteriaKeyHasPssViolation               string = "violatePssPolicy"
	CriteriaKeyCustomPath                    string = "customPath"
	CriteriaKeySaBindRiskyRole               string = "saBindRiskyRole"
	CriteriaKeyImageVerifiers                string = "imageVerifiers"
	CriteriaKeyAnnotations                   string = "annotations"
	CriteriaKeyStorageClassName              string = "storageClassName"
)

const (
	SubCriteriaPublishDays   string = "publishDays"
	SubCriteriaCount         string = "count"
	SubCriteriaCpuRequest    string = "cpuRequest"
	SubCriteriaCpuLimit      string = "cpuLimit"
	SubCriteriaMemoryRequest string = "memoryRequest"
	SubCriteriaMemoryLimit   string = "memoryLimit"
)

const (
	CriteriaOpEqual               string = "="
	CriteriaOpNotEqual            string = "!="
	CriteriaOpContains            string = "contains"
	CriteriaOpPrefix              string = "prefix"
	CriteriaOpRegex               string = "regex"
	CriteriaOpNotRegex            string = "!regex"
	CriteriaOpBiggerEqualThan     string = ">="
	CriteriaOpBiggerThan          string = ">"
	CriteriaOpLessEqualThan       string = "<="
	CriteriaOpContainsAll         string = "containsAll"
	CriteriaOpContainsAny         string = "containsAny"
	CriteriaOpNotContainsAny      string = "notContainsAny"
	CriteriaOpContainsOtherThan   string = "containsOtherThan"
	CriteriaOpRegexContainsAny    string = "regexContainsAnyEx"
	CriteriaOpRegexNotContainsAny string = "!regexContainsAnyEx"
	CriteriaOpExist               string = "exist"
	CriteriaOpNotExist            string = "notExist"
	CriteriaOpContainsTagAny      string = "containsTagAny"

	CriteriaOpRegex_Deprecated    string = "regexContainsAny"  // notice: it's the same as CriteriaOpRegex since 5.3.2
	CriteriaOpNotRegex_Deprecated string = "!regexContainsAny" // notice: it's the same as CriteriaOpNotRegex since 5.3.2
)

const (
	CriteriaValueTrue  string = "true"
	CriteriaValueFalse string = "false"
)

const CriteriaValueAny string = "any"

const (
	PssPolicyBaseline   string = "baseline"
	PssPolicyRestricted string = "restricted"
)

func IsSvcIpGroupMember(usergroup *CLUSGroup, svcipgroup *CLUSGroup) bool {
	if usergroup == nil || svcipgroup == nil {
		return false
	}
	if !IsSvcIpGroupSelected(svcipgroup, usergroup.Criteria) {
		return false
	} else if usergroup.CreaterDomains == nil {
		return true
	} else {
		for _, d := range usergroup.CreaterDomains {
			if d == svcipgroup.Domain {
				return true
			}
		}
	}
	return false
}

func IsSvcIpGroupSelected(svcipgroup *CLUSGroup, selector []CLUSCriteriaEntry) bool {
	var ret, positive bool
	var rets map[string]bool = make(map[string]bool)
	var poss map[string]bool = make(map[string]bool)
	for _, crt := range selector {
		key := crt.Key

		if key != CriteriaKeyDomain && key != CriteriaKeyNamespace {
			continue
		}

		ret, positive = isCriterionMet(&crt, svcipgroup.Domain)

		if v, ok := rets[key]; !ok {
			rets[key] = ret
			poss[key] = positive
		} else {
			p := poss[key]
			if !positive && !p {
				rets[key] = v && ret
			} else {
				rets[key] = v || ret
			}
			poss[key] = p || positive
		}
	}

	if len(rets) == 0 {
		return false
	}
	for _, ret = range rets {
		if !ret {
			return false
		}
	}

	return true
}

func IsGroupMember(group *CLUSGroup, workload *CLUSWorkload, domain *CLUSDomain) bool {
	if group == nil || workload == nil {
		return false
	}
	if !IsWorkloadSelected(workload, group.Criteria, domain) {
		return false
	} else if group.CreaterDomains == nil {
		return true
	} else {
		for _, d := range group.CreaterDomains {
			if d == workload.Domain {
				return true
			}
		}
	}
	return false
}

// For criteria of same type, apply 'or' if there is at least one positive match;
//
//	apply 'and' if all are negative match;
//
// For different criteria type, apply 'and'
func IsWorkloadSelected(workload *CLUSWorkload, selector []CLUSCriteriaEntry, domain *CLUSDomain) bool {
	var ret, positive bool
	var rets map[string]bool = make(map[string]bool)
	var poss map[string]bool = make(map[string]bool)
	for _, crt := range selector {
		key := crt.Key
		switch key {
		case CriteriaKeyImage:
			ret, positive = isCriterionMet(&crt, workload.Image)
		case CriteriaKeyHost:
			ret, positive = isCriterionMet(&crt, workload.HostName)
		case CriteriaKeyWorkload:
			ret, positive = isCriterionMet(&crt, workload.Name)
		case CriteriaKeyService:
			ret, positive = isCriterionMet(&crt, workload.Service)
		case CriteriaKeyDomain, CriteriaKeyNamespace:
			ret, positive = isCriterionMet(&crt, workload.Domain)
		case CriteriaKeyAddress:
			// Address criteria doesn't match workload address for now
			return false
		default:
			ret = false
			positive = true
			if strings.HasPrefix(crt.Key, "ns:") {
				if domain != nil {
					key = "ns-label" // create "or" combination
					if v, ok := domain.Labels[crt.Key[3:]]; ok {
						ret, positive = isCriterionMet(&crt, v)
					}
				}
			} else {
				key = "pod-label" // create "or" combination
				if v, ok := workload.Labels[crt.Key]; ok {
					ret, positive = isCriterionMet(&crt, v)
				}
			}
		}

		if v, ok := rets[key]; !ok {
			rets[key] = ret
			poss[key] = positive
		} else {
			p := poss[key]
			if !positive && !p {
				rets[key] = v && ret
			} else {
				rets[key] = v || ret
			}
			poss[key] = p || positive
		}
	}

	if len(rets) == 0 {
		return false
	}
	for _, ret = range rets {
		if !ret {
			return false
		}
	}

	return true
}

func EqualMatch(match, value string) bool {
	if !strings.ContainsAny(match, "?*") {
		return match == value
	}

	re := strings.Replace(match, ".", "\\.", -1)
	re = strings.Replace(re, "?", ".", -1)
	re = strings.Replace(re, "*", ".*", -1)
	re = fmt.Sprintf("^%s$", re)

	if regex, err := regexp.Compile(re); err != nil {
		return match == value
	} else {
		return regex.MatchString(value)
	}
}

func isCriterionMet(crt *CLUSCriteriaEntry, value string) (bool, bool) {
	switch crt.Op {
	case CriteriaOpEqual:
		if crt.Value == CriteriaValueAny {
			return true, true
		} else {
			return EqualMatch(crt.Value, value), true
		}
	case CriteriaOpNotEqual:
		return !EqualMatch(crt.Value, value), false
	case CriteriaOpContains:
		return strings.Contains(value, crt.Value), true
	case CriteriaOpPrefix:
		return strings.HasPrefix(value, crt.Value), true
	case CriteriaOpRegex:
		matched, _ := regexp.MatchString(crt.Value, value)
		return matched, true
	case CriteriaOpNotRegex:
		matched, _ := regexp.MatchString(crt.Value, value)
		return !matched, false
	}

	return false, true
}
