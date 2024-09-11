package cache

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type rancherOSCVEInfo struct {
	name        string
	severity    string
	score       float32
	vector      string
	scoreV3     float32
	vectorV3    string
	link        string
	os          string
	kernel      string
	description string
	date        string
	fixed       string
}

var rancherOSCVEs = []rancherOSCVEInfo{
	{
		name: "CVE-2017-5753", os: "1.4.0", kernel: "4.14.32", date: "2018/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.",
		fixed:       "RancherOS v1.4.0 using Linux v4.14.32",
	},
	{
		name: "CVE-2018-8897", os: "1.4.0", kernel: "4.14.32", date: "2018/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8897",
		severity: share.VulnSeverityHigh, score: 7.2, vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C", scoreV3: 7.8, vectorV3: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		description: "A statement in the System Programming Guide of the Intel 64 and IA-32 Architectures Software Developer’s Manual (SDM) was mishandled in the development of some or all operating-system kernels, resulting in unexpected behavior for #DB exceptions that are deferred by MOV SS or POP SS, as demonstrated by (for example) privilege escalation in Windows, macOS, some Xen configurations, or FreeBSD, or a Linux kernel crash.",
		fixed:       "RancherOS v1.4.0 using Linux v4.14.32",
	},
	{
		name: "CVE-2018-3620", os: "1.4.1", kernel: "4.14.67", date: "2018/9/19", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "L1 Terminal Fault is a hardware vulnerability which allows unprivileged speculative access to data which is available in the Level 1 Data Cache when the page table entry controlling the virtual address, which is used for the access, has the Present bit cleared or other reserved bits set.",
		fixed:       "RancherOS v1.4.1 using Linux v4.14.67",
	},
	{
		name: "CVE-2018-3639", os: "1.4.1", kernel: "4.14.67", date: "2018/9/19", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639",
		severity: share.VulnSeverityMedium, score: 4.9, vector: "AV:L/AC:L/Au:N/C:C/I:N/A:N", scoreV3: 5.5, vectorV3: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		description: "Systems with microprocessors utilizing speculative execution and speculative execution of memory reads before the addresses of all prior memory writes are known may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis, aka Speculative Store Bypass (SSB), Variant 4.",
		fixed:       "RancherOS v1.4.1 using Linux v4.14.67",
	},
	{
		name: "CVE-2018-17182", os: "1.4.2", kernel: "4.14.73", date: "2018/10/18", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17182",
		severity: share.VulnSeverityHigh, score: 7.2, vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C", scoreV3: 7.8, vectorV3: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		description: "The vmacache_flush_all function in mm/vmacache.c mishandles sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations.",
		fixed:       "RancherOS v1.4.2 using Linux v4.14.73",
	},
	{
		name: "CVE-2019-5736", os: "1.5.1", kernel: "", date: "2018/10/18", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5736",
		severity: share.VulnSeverityHigh, score: 9.3, vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C", scoreV3: 8.6, vectorV3: "AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
		description: "runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.",
		fixed:       "RancherOS v1.5.1",
	},
	// --
	{
		name: "CVE-2018-12126", os: "1.5.2", kernel: "4.14.122", date: "2019/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12127",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "Microarchitectural Data Sampling (MDS) is a family of side channel attacks on internal buffers in Intel CPUs.",
		fixed:       "RancherOS v1.5.2 using Linux v4.14.122",
	},
	{
		name: "CVE-2018-12127", os: "1.5.2", kernel: "4.14.122", date: "2019/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12126",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "Microarchitectural Data Sampling (MDS) is a family of side channel attacks on internal buffers in Intel CPUs.",
		fixed:       "RancherOS v1.5.2 using Linux v4.14.122",
	},
	{
		name: "CVE-2018-12130", os: "1.5.2", kernel: "4.14.122", date: "2019/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12130",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "Microarchitectural Data Sampling (MDS) is a family of side channel attacks on internal buffers in Intel CPUs.",
		fixed:       "RancherOS v1.5.2 using Linux v4.14.122",
	},
	{
		name: "CVE-2019-11091", os: "1.5.2", kernel: "4.14.122", date: "2019/5/31", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11091",
		severity: share.VulnSeverityMedium, score: 4.7, vector: "AV:L/AC:M/Au:N/C:C/I:N/A:N", scoreV3: 5.6, vectorV3: "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
		description: "Microarchitectural Data Sampling (MDS) is a family of side channel attacks on internal buffers in Intel CPUs.",
		fixed:       "RancherOS v1.5.2 using Linux v4.14.122",
	},
	// --
	{
		name: "CVE-2019-11477", os: "1.5.3", kernel: "", date: "2019/7/11", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11477",
		severity: share.VulnSeverityHigh, score: 7.8, vector: "AV:N/AC:L/Au:N/C:N/I:N/A:C", scoreV3: 7.5, vectorV3: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		description: "Selective acknowledgment (SACK) is a technique used by TCP to help alleviate congestion that can arise due to the retransmission of dropped packets. It allows the endpoints to describe which pieces of the data they have received, so that only the missing pieces need to be retransmitted. However, a bug was recently found in the Linux implementation of SACK that allows remote attackers to panic the system by sending crafted SACK information.",
		fixed:       "RancherOS v1.5.3",
	},
	{
		name: "CVE-2019-11478", os: "1.5.3", kernel: "", date: "2019/7/11", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11478",
		severity: share.VulnSeverityHigh, score: 5.0, vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P", scoreV3: 7.5, vectorV3: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		description: "Selective acknowledgment (SACK) is a technique used by TCP to help alleviate congestion that can arise due to the retransmission of dropped packets. It allows the endpoints to describe which pieces of the data they have received, so that only the missing pieces need to be retransmitted. However, a bug was recently found in the Linux implementation of SACK that allows remote attackers to panic the system by sending crafted SACK information.",
		fixed:       "RancherOS v1.5.3",
	},
	{
		name: "CVE-2019-11479", os: "1.5.3", kernel: "", date: "2019/7/11", link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11479",
		severity: share.VulnSeverityHigh, score: 5.0, vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P", scoreV3: 7.5, vectorV3: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		description: "Selective acknowledgment (SACK) is a technique used by TCP to help alleviate congestion that can arise due to the retransmission of dropped packets. It allows the endpoints to describe which pieces of the data they have received, so that only the missing pieces need to be retransmitted. However, a bug was recently found in the Linux implementation of SACK that allows remote attackers to panic the system by sending crafted SACK information.",
		fixed:       "RancherOS v1.5.3",
	},
}

func locateRancherOSCVE(os, kernel string) []*share.ScanVulnerability {
	vulns := make([]*share.ScanVulnerability, 0)

	osVer, _ := utils.NewVersion(os)
	kVer, _ := utils.NewVersion(kernel)
	for _, cve := range rancherOSCVEs {
		cveOSVer, _ := utils.NewVersion(cve.os)
		cveKVer, _ := utils.NewVersion(cve.kernel)
		osCompare := osVer.Compare(cveOSVer)
		if osCompare < 0 || (osCompare == 0 && (cve.kernel != "" && kVer.Compare(cveKVer) < 0)) {
			vulns = append(vulns, &share.ScanVulnerability{
				Name:           cve.name,
				Severity:       cve.severity,
				Score:          cve.score,
				Vectors:        cve.vector,
				ScoreV3:        cve.scoreV3,
				VectorsV3:      cve.vectorV3,
				PackageName:    "RancherOS",
				PackageVersion: os,
				Description:    cve.description,
				Link:           cve.link,
				FixedVersion:   cve.fixed,
			})
		}
	}

	return vulns
}

func appendRancherOSCVE(id string, result *share.ScanResult, err error) (*share.ScanResult, error) {
	if result.Error != share.ScanErrorCode_ScanErrNone && result.Error != share.ScanErrorCode_ScanErrNotSupport {
		return result, err
	}

	hc := getHostCache(id)
	if hc == nil || hc.host == nil {
		return result, err
	}

	var osver, kernel string
	if strings.HasPrefix(result.Namespace, "rancheros:v") {
		osver = strings.TrimPrefix(result.Namespace, "rancheros:v")
	} else if strings.HasPrefix(hc.host.OS, "RancherOS v") {
		osver = strings.TrimPrefix(hc.host.OS, "RancherOS v")
	} else {
		return result, err
	}

	if strings.HasSuffix(hc.host.Kernel, "-rancher") {
		kernel = strings.TrimSuffix(hc.host.Kernel, "-rancher")
	} else if strings.HasSuffix(hc.host.Kernel, "-rancher2") {
		kernel = strings.TrimSuffix(hc.host.Kernel, "-rancher2")
	} else {
		return result, err
	}

	result.Vuls = locateRancherOSCVE(osver, kernel)
	result.Error = share.ScanErrorCode_ScanErrNone

	cctx.ScanLog.WithFields(log.Fields{
		"id": id, "os": osver, "kernel": kernel, "vulnerability": len(result.Vuls),
	}).Debug()

	return result, nil
}
