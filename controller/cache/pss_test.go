package cache

import (
	"testing"

	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	corev1 "k8s.io/api/core/v1"
)

func getValidTestContainer() nvsysadmission.AdmContainerInfo {
	validProfileType := corev1.SeccompProfileTypeRuntimeDefault
	return nvsysadmission.AdmContainerInfo{
		HostNetwork: false,
		HostPID:     false,
		HostIPC:     false,
		Privileged:  false,
		Capabilities: nvsysadmission.LinuxCapabilities{
			Add:  []string{"NET_BIND_SERVICE"},
			Drop: []string{"ALL"},
		},
		Volumes:         []corev1.Volume{},
		HostPorts:       []int32{},
		AppArmorProfile: nil,
		SELinuxOptions: nvsysadmission.SELinuxOptions{
			Type: "",
			User: "",
			Role: "",
		},
		Sysctls:                  []string{},
		AllowPrivilegeEscalation: false,
		RunAsUser:                1,
		RunAsNonRoot:             true,
		SeccompProfileType:       &validProfileType,
	}
}

func TestSharesHostNamespace_HostNetwork(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.HostNetwork = true
	if !sharesHostNamespace(&testContainer) {
		t.Error("container with HostNetwork set to true should violate baseline policy")
	}

	postTest()
}

func TestSharesHostNamespace_HostPID(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.HostPID = true
	if !sharesHostNamespace(&testContainer) {
		t.Error("container with HostPID set to true should violate baseline policy")
	}

	postTest()
}

func TestSharesHostNamespace_IPC(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.HostIPC = true
	if !sharesHostNamespace(&testContainer) {
		t.Error("container with HostIPC set to true should violate baseline policy")
	}

	postTest()
}

func TestAllowsPrivilegedContainers(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Privileged = true
	if !allowsPrivelegedContainers(&testContainer) {
		t.Error("container with Privileged set to true should violate baseline policy")
	}

	postTest()
}

func TestExceedsBaselineCapabilities(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Capabilities.Add = append(testContainer.Capabilities.Add, "SOME_ILLEGAL_CAPABILITY")
	if !exceedsBaselineCapabilites(&testContainer) {
		t.Error("container with invalid added capability should violate baseline policy")
	}

	postTest()
}

func TestHasHostPathVolumes(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Volumes = append(testContainer.Volumes, corev1.Volume{
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{},
		},
	})
	if !hasHostPathVolumes(&testContainer) {
		t.Error("container with HostPath volume should violate baseline policy")
	}

	postTest()
}

func TestUsesHostPorts(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.HostPorts = append(testContainer.HostPorts, 12345)
	if !usesHostPorts(&testContainer) {
		t.Error("container with HostPorts should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalAppArmorProfile(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	illegalAppArmorProfile := "illegal_apparmor_profile"
	testContainer.AppArmorProfile = &illegalAppArmorProfile
	if !usesIllegalAppArmorProfile(&testContainer) {
		t.Error("container with illegal AppArmor profile should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalSeLinuxOptions_Type(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.SELinuxOptions.Type = "illegal_type"
	if !usesIllegalSELinuxOptions(&testContainer) {
		t.Error("container with illegal SeLinux options type should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalSeLinuxOptions_User(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.SELinuxOptions.User = "any set user is illegal"
	if !usesIllegalSELinuxOptions(&testContainer) {
		t.Error("container with any SeLinux options user set should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalSeLinuxOptions_Role(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.SELinuxOptions.Role = "any set role is illegal"
	if !usesIllegalSELinuxOptions(&testContainer) {
		t.Error("container with any SeLinux options role set should violate baseline policy")
	}

	postTest()
}

func TestUsesCustomProcMount(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.ProcMount = "some non default procmount string"
	if !usesCustomProcMount(&testContainer) {
		t.Error("container with custom ProcMount should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalSeccompProfile(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	invalidProfileType := corev1.SeccompProfileTypeUnconfined
	testContainer.SeccompProfileType = &invalidProfileType
	if !doesNotSetLegalSeccompProfile(&testContainer) {
		t.Error("container that sets seccomp profile to unconfined should violate restricted policy")
	}

	postTest()
}

func TestUsesIllegalSysctls(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Sysctls = append(testContainer.Sysctls, "some_illegal_sysctl")
	if !usesIllegalSysctls(&testContainer) {
		t.Error("container with illegal sysctl should violate baseline policy")
	}

	postTest()
}

func TestUsesIllegalVolumeTypes_IllegalSet(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Volumes = []corev1.Volume{
		{
			VolumeSource: corev1.VolumeSource{
				Cinder: &corev1.CinderVolumeSource{},
			},
		},
	}
	if !usesIllegalVolumeTypes(&testContainer) {
		t.Error("container with illegal volume type set should violate restricted policy")
	}

	postTest()
}

func TestAllowsPrivelegeEscalation(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.AllowPrivilegeEscalation = true
	if !allowsPrivelegeEscalation(&testContainer) {
		t.Error("container that allows privilege escalation should violate restricted policy")
	}

	postTest()
}

func TestDoesNotSetLegalSeccompProfile(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	invalidProfileType := corev1.SeccompProfileTypeUnconfined
	testContainer.SeccompProfileType = &invalidProfileType
	if !doesNotSetLegalSeccompProfile(&testContainer) {
		t.Error("container that does not explicitly set legal seccomp profile should violate restricted policy")
	}

	postTest()
}

func TestExceedsRestrictedCapabilities_NoDropAll(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Capabilities.Drop = []string{}
	if !exceedsRestrictedCapabilities(&testContainer) {
		t.Error("container that does not drop all capabilities should violate restricted policy")
	}

	postTest()
}

func TestExceedsRestrictedCapabilities_AddsIllegal(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	testContainer.Capabilities.Add = append(testContainer.Capabilities.Add, "illegal_capability")
	if !exceedsRestrictedCapabilities(&testContainer) {
		t.Error("container that adds more capabilities than NET_BIND_SERVICE should violate restricted policy")
	}

	postTest()
}

func TestBaselinePolicy_ValidContainer(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	if len(baselinePolicyViolations(&testContainer)) > 0 {
		t.Error("valid container should not violate baseline policy")
	}

	postTest()
}

func TestRestrictedPolicy_ValidContainer(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	if len(restrictedPolicyViolations(&testContainer, false)) > 0 {
		t.Error("valid container should not violate restricted policy")
	}

	postTest()
}

func TestRestrictedPolicy_ImageRunsAsRoot(t *testing.T) {
	preTest()

	testContainer := getValidTestContainer()
	imageRunsAsRoot := true
	if len(restrictedPolicyViolations(&testContainer, imageRunsAsRoot)) != 1 {
		t.Error("image running as root should violate restricted policy")
	}
}
