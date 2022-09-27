package cache

import (
	"strings"

	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
)

// The following functions are meant to represent the policy controls as listed
// in the Kubernetes Policy Security Standards
// https://kubernetes.io/docs/concepts/security/pod-security-standards/
//
// There are two exceptions:
// (1) The "HostProcess" check is not implemented since we do not support Windows
// (2) In the "Host Ports" check, there is no behavior related to allowing a
//     "known" list. This is also the case in the Kubernetes source code as of
//     September 27th, 2022.

// Baseline Policy - Host Namespaces
func sharesHostNamespace(c *nvsysadmission.AdmContainerInfo) bool {
	return c.HostNetwork || c.HostPID || c.HostIPC
}

// Baseline Policy - Privileged Containers
func allowsPrivelegedContainers(c *nvsysadmission.AdmContainerInfo) bool {
	return c.Privileged
}

// Baseline Policy - Capabilities
func exceedsBaselineCapabilites(c *nvsysadmission.AdmContainerInfo) bool {
	baselineCapabilities := map[string]bool{
		"AUDIT_WRITE":      true,
		"CHOWN":            true,
		"DAC_OVERRIDE":     true,
		"FOWNER":           true,
		"FSETID":           true,
		"KILL":             true,
		"MKNOD":            true,
		"NET_BIND_SERVICE": true,
		"SETFCAP":          true,
		"SETGID":           true,
		"SETPCAP":          true,
		"SETUID":           true,
		"SYS_CHROOT":       true,
	}

	for _, capability := range c.Capabilities.Add {
		if _, found := baselineCapabilities[strings.ToUpper(capability)]; !found {
			return true
		}
	}

	return false
}

// Baseline Policy - HostPath Volumes
func hasHostPathVolumes(c *nvsysadmission.AdmContainerInfo) bool {
	for _, volume := range c.Volumes {
		if volume.HostPath != nil {
			return true
		}
	}

	return false
}

// Baseline Policy - Host Ports
func usesHostPorts(c *nvsysadmission.AdmContainerInfo) bool {
	for _, hostPort := range c.HostPorts {
		if hostPort != 0 {
			return true
		}
	}

	return false
}

const (
	AppArmorDefault   = "runtime/default"
	AppArmorLocalhost = "localhost/"
)

// Baseline Policy - AppArmor
func usesIllegalAppArmorProfile(c *nvsysadmission.AdmContainerInfo) bool {
	if c.AppArmorProfile == nil {
		return false
	}

	if *c.AppArmorProfile == AppArmorDefault {
		return false
	}

	if (*c.AppArmorProfile)[:len(AppArmorLocalhost)] == AppArmorLocalhost {
		return false
	}

	return true
}

// Baseline Policy - SELinux
func usesIllegalSELinuxOptions(c *nvsysadmission.AdmContainerInfo) bool {
	legalTypes := map[string]bool{
		"":                 true,
		"container_t":      true,
		"container_init_t": true,
		"container_kvm_t":  true,
	}

	if _, isLegalType := legalTypes[c.SELinuxOptions.Type]; !isLegalType {
		return true
	}

	if c.SELinuxOptions.User != "" || c.SELinuxOptions.Role != "" {
		return true
	}

	return false
}

// Baseline Policy - /proc Mount Type
func usesCustomProcMount(c *nvsysadmission.AdmContainerInfo) bool {
	return c.ProcMount != "" || !strings.EqualFold(c.ProcMount, "default")
}

// Baseline Policy - Seccomp
func usesIllegalSeccompProfile(c *nvsysadmission.AdmContainerInfo) bool {
	profile := strings.ToLower(c.SeccompProfile)
	return profile != "" && profile != "runtimedefault" && profile != "localhost"
}

// Baseline Policy - Sysctls
func usesIllegalSysctls(c *nvsysadmission.AdmContainerInfo) bool {
	legalSysctls := map[string]bool{
		"kernel.shm_rmid_forced":              true,
		"net.ipv4.ip_local_port_range":        true,
		"net.ipv4.ip_unprivileged_port_start": true,
		"net.ipv4.tcp_syncookies":             true,
		"net.ipv4.ping_group_range":           true,
	}

	for _, sysctl := range c.Sysctls {
		if _, found := legalSysctls[strings.ToLower(sysctl)]; !found {
			return true
		}
	}

	return false
}

// Restricted Policy - Volume Types
func usesIllegalVolumeTypes(c *nvsysadmission.AdmContainerInfo) bool {
	if len(c.Volumes) == 0 {
		return false
	}

	for _, volume := range c.Volumes {
		legalVolumesSet := []bool{
			volume.ConfigMap != nil,
			volume.CSI != nil,
			volume.DownwardAPI != nil,
			volume.EmptyDir != nil,
			// volume.VolumeSource.Ephemeral != nil, // TODO: update k8s.io package
			volume.PersistentVolumeClaim != nil,
			volume.Projected != nil,
			volume.Secret != nil,
		}

		setsLegalVolume := false
		for _, legalVolumeSet := range legalVolumesSet {
			if legalVolumeSet {
				setsLegalVolume = true
				break
			}
		}
		if !setsLegalVolume {
			return true
		}
	}

	return false
}

// Restricted Policy - Privilege Escalation
func allowsPrivelegeEscalation(c *nvsysadmission.AdmContainerInfo) bool {
	return c.AllowPrivilegeEscalation
}

// Restricted Policy - Running as Non-root & Running as Non-root user (v1.23+)
func allowsRootUsers(c *nvsysadmission.AdmContainerInfo) bool {
	return c.RunAsUser != 0
}

// Restricted Policy - Seccomp (v1.19+)
func doesNotSetLegalSeccompProfile(c *nvsysadmission.AdmContainerInfo) bool {
	profile := strings.ToLower(c.SeccompProfile)
	return profile != "runtimedefault" && profile != "localhost"
}

// Restricted Policy - Capabilities (v1.22+)
func exceedsRestrictedCapabilities(c *nvsysadmission.AdmContainerInfo) bool {
	dropsAll := false
	for _, capability := range c.Capabilities.Drop {
		if strings.EqualFold(capability, "ALL") {
			dropsAll = true
			break
		}
	}
	if !dropsAll {
		return true
	}

	if len(c.Capabilities.Add) > 1 {
		return true
	}

	if len(c.Capabilities.Add) == 0 {
		return false
	}

	return !strings.EqualFold(c.Capabilities.Add[0], "NET_BIND_SERVICE")
}

type policyViolationCheck func(*nvsysadmission.AdmContainerInfo) bool

func triggersPolicyViolation(c *nvsysadmission.AdmContainerInfo, checks []policyViolationCheck) bool {
	for _, inViolation := range checks {
		if inViolation(c) {
			return true
		}
	}

	return false
}

func violatesBaseLinePolicy(c *nvsysadmission.AdmContainerInfo) bool {
	baselineViolations := []policyViolationCheck{
		sharesHostNamespace,
		allowsPrivelegedContainers,
		exceedsBaselineCapabilites,
		hasHostPathVolumes,
		usesIllegalAppArmorProfile,
		usesIllegalSELinuxOptions,
		usesCustomProcMount,
		usesIllegalSeccompProfile,
		usesIllegalSysctls,
	}

	return triggersPolicyViolation(c, baselineViolations)
}

func violatesRestrictedPolicy(c *nvsysadmission.AdmContainerInfo) bool {
	if violatesBaseLinePolicy(c) {
		return true
	}

	restrictedViolations := []policyViolationCheck{
		usesIllegalVolumeTypes,
		allowsPrivelegeEscalation,
		allowsRootUsers,
		doesNotSetLegalSeccompProfile,
	}

	return triggersPolicyViolation(c, restrictedViolations)
}
