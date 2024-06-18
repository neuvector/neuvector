package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/hashicorp/go-version"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	log "github.com/sirupsen/logrus"
)

var (
	dstPrefix                 = "/usr/local/bin/scripts/cis_yamls/"
	primeConfigPrefix         = "/etc/neuvector/prime/compliance/"
	kube160                   = "cis-1.6.0"
	kube123                   = "cis-1.23"
	kube124                   = "cis-1.24"
	kube180                   = "cis-1.8.0"
	rh140                     = "rh-1.4.0"
	gke140                    = "gke-1.4.0"
	aks140                    = "aks-1.4.0"
	eks140                    = "eks-1.4.0"
	defaultCISVersion         = "cis-1.8.0"
	catchDescription          = regexp.MustCompile(`^(.*?) \([^)]*\)$`)
	complianceMetas           []api.RESTBenchMeta
	complianceMetaMap         = make(map[string]api.RESTBenchMeta)
	imageBenchMetas           []api.RESTBenchMeta
	imageBenchMetaMap         = make(map[string]api.RESTBenchMeta)
	once                      sync.Once
	backupCISItems            = make(map[string]api.RESTBenchCheck)
	backupDockerImageCISItems = make(map[string]api.RESTBenchCheck)
	cisVersion                string
	remediationFolder         string
	isUpdateImageBenchMetaMap = false
	isUpdateComplianceMetaMap = false
)

var dockerImageCISItems = map[string]api.RESTBenchCheck{
	"I.4.1": api.RESTBenchCheck{
		TestNum:     "I.4.1",
		Type:        "image",
		Category:    "image",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure a user for the container has been created",
	},
	"I.4.6": api.RESTBenchCheck{
		TestNum:     "I.4.6",
		Type:        "image",
		Category:    "image",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that HEALTHCHECK instructions have been added to container images",
	},
	"I.4.8": api.RESTBenchCheck{
		TestNum:     "I.4.8",
		Type:        "image",
		Category:    "image",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure setuid and setgid permissions are removed",
	},
	"I.4.9": api.RESTBenchCheck{
		TestNum:     "I.4.9",
		Type:        "image",
		Category:    "image",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that COPY is used instead of ADD in Dockerfiles",
	},
	"I.4.10": api.RESTBenchCheck{
		TestNum:     "I.4.10",
		Type:        "secret",
		Category:    "image",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure secrets are not stored in container images",
	},
}

var cisItems = map[string]api.RESTBenchCheck{
	"D.1.1.1": api.RESTBenchCheck{
		TestNum:     "D.1.1.1",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure a separate partition for containers has been created",
		Remediation: "For new installations, you should create a separate partition for the /var/lib/docker mount point. For systems that have already been installed, you should use the Logical Volume Manager (LVM) within Linux to create a new partition.",
	},
	"D.1.1.2": api.RESTBenchCheck{
		TestNum:     "D.1.1.2",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure only trusted users are allowed to control Docker daemon",
		Remediation: "You should remove any untrusted users from the docker group using command sudo gpasswd -d <your-user> docker or add trusted users to the docker group using command sudo usermod -aG docker <your-user>. You should not create a mapping of sensitive directories from the host to container volumes.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.3": api.RESTBenchCheck{
		TestNum:     "D.1.1.3",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for the Docker daemon",
		Remediation: "Install auditd. Add -w /usr/bin/dockerd -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.4": api.RESTBenchCheck{
		TestNum:     "D.1.1.4",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /run/containerd",
		Remediation: "Install auditd. Add -a exit,always -F path=/run/containerd -F perm=war -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.5": api.RESTBenchCheck{
		TestNum:     "D.1.1.5",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /var/lib/docker",
		Remediation: "Install auditd. Add -w /var/lib/docker -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.6": api.RESTBenchCheck{
		TestNum:     "D.1.1.6",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /etc/docker",
		Remediation: "Install auditd. Add -w /etc/docker -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.7": api.RESTBenchCheck{
		TestNum:     "D.1.1.7",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - docker.service",
		Remediation: "Install auditd. Add -w $(get_service_file docker.service) -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.8": api.RESTBenchCheck{
		TestNum:     "D.1.1.8",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - containerd.sock",
		Remediation: "Install auditd. Add -w $(get_service_file containerd.socket) -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.9": api.RESTBenchCheck{
		TestNum:     "D.1.1.9",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - docker.socket",
		Remediation: "Install auditd. Add -w $(get_service_file docker.socket) -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.10": api.RESTBenchCheck{
		TestNum:     "D.1.1.10",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /etc/default/docker",
		Remediation: "Install auditd. Add -w /etc/default/docker -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.11": api.RESTBenchCheck{
		TestNum:     "D.1.1.11",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Dockerfiles and directories - /etc/docker/daemon.json",
		Remediation: "Install auditd. Add -w /etc/docker/daemon.json -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.12": api.RESTBenchCheck{
		TestNum:     "D.1.1.12",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Dockerfiles and directories - /etc/containerd/config.toml",
		Remediation: "Install auditd. Add -w /etc/containerd/config.toml -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.13": api.RESTBenchCheck{
		TestNum:     "D.1.1.13",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /etc/sysconfig/docker",
		Remediation: "Install auditd. Add -w /etc/sysconfig/docker -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.14": api.RESTBenchCheck{
		TestNum:     "D.1.1.14",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd",
		Remediation: "Install auditd. Add -w /usr/bin/containerd -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.15": api.RESTBenchCheck{
		TestNum:     "D.1.1.15",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim",
		Remediation: "Install auditd. Add -w /usr/bin/containerd-shim -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.16": api.RESTBenchCheck{
		TestNum:     "D.1.1.16",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim-runc-v1",
		Remediation: "Install auditd. Add -w /usr/bin/containerd-shim-runc-v1 -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.17": api.RESTBenchCheck{
		TestNum:     "D.1.1.17",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /usr/bin/containerd-shim-runc-v2",
		Remediation: "Install auditd. Add -w /usr/bin/containerd-shim-runc-v2 -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.1.18": api.RESTBenchCheck{
		TestNum:     "D.1.1.18",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure auditing is configured for Docker files and directories - /usr/bin/runc",
		Remediation: "Install auditd. Add -w /usr/bin/runc -k docker to the /etc/audit/rules.d/audit.rules file. Then restart the audit daemon using command service auditd restart.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.1.2.1": api.RESTBenchCheck{
		TestNum:     "D.1.2.1",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the container host has been Hardened`",
		Remediation: "You may consider various Security Benchmarks for your container host.",
	},
	"D.1.2.2": api.RESTBenchCheck{
		TestNum:     "D.1.2.2",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the version of Docker is up to date",
		Remediation: "You should monitor versions of Docker releases and make sure your software is updated as required.",
	},
	"D.2.1": api.RESTBenchCheck{
		TestNum:     "D.2.1",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Run the Docker daemon as a non-root user, if possible",
		Remediation: "Follow the current Dockerdocumentation on how to install the Docker daemon as a non-root user.",
	},
	"D.2.2": api.RESTBenchCheck{
		TestNum:     "D.2.2",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure network traffic is restricted between containers on the default bridge",
		Remediation: "Edit the Docker daemon configuration file to ensure that inter-container communication is disabled: icc: false.",
	},
	"D.2.3": api.RESTBenchCheck{
		TestNum:     "D.2.3",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the logging level is set to 'info'",
		Remediation: "Ensure that the Docker daemon configuration file has the following configuration included log-level: info. Alternatively, run the Docker daemon as following: dockerd --log-level=info",
	},
	"D.2.4": api.RESTBenchCheck{
		TestNum:     "D.2.4",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure Docker is allowed to make changes to iptables",
		Remediation: "Do not run the Docker daemon with --iptables=false option.",
	},
	"D.2.5": api.RESTBenchCheck{
		TestNum:     "D.2.5",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure insecure registries are not used",
		Remediation: "You should ensure that no insecure registries are in use.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.2.6": api.RESTBenchCheck{
		TestNum:     "D.2.6",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure aufs storage driver is not used",
		Remediation: "Do not start Docker daemon as using dockerd --storage-driver aufs option.",
	},
	"D.2.7": api.RESTBenchCheck{
		TestNum:     "D.2.7",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure TLS authentication for Docker daemon is configured",
		Remediation: "Follow the steps mentioned in the Docker documentation or other references. By default, TLS authentication is not configured.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.2.8": api.RESTBenchCheck{
		TestNum:     "D.2.8",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the default ulimit is configured appropriately",
		Remediation: "Run Docker in daemon mode and pass --default-ulimit as option with respective ulimits as appropriate in your environment and in line with your security policy. Example: dockerd --default-ulimit nproc=1024:2048 --default-ulimit nofile=100:200",
	},
	"D.2.9": api.RESTBenchCheck{
		TestNum:     "D.2.9",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Enable user namespace support",
		Remediation: "",
	},
	"D.2.10": api.RESTBenchCheck{
		TestNum:     "D.2.10",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure the default cgroup usage has been confirmed",
		Remediation: "",
	},
	"D.2.11": api.RESTBenchCheck{
		TestNum:     "D.2.11",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure base device size is not changed until needed",
		Remediation: "",
	},
	"D.2.12": api.RESTBenchCheck{
		TestNum:     "D.2.12",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that authorization for Docker client commands is enabled",
		Remediation: "",
	},
	"D.2.13": api.RESTBenchCheck{
		TestNum:     "D.2.13",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure centralized and remote logging is configured",
		Remediation: "",
	},
	"D.2.14": api.RESTBenchCheck{
		TestNum:     "D.2.14",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure containers are restricted from acquiring new privileges",
		Remediation: "You should run the Docker daemon using command: dockerd --no-new-privileges",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.2.15": api.RESTBenchCheck{
		TestNum:     "D.2.15",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure live restore is enabled",
		Remediation: "Run Docker in daemon mode and pass --live-restore option.",
	},
	"D.2.16": api.RESTBenchCheck{
		TestNum:     "D.2.16",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure Userland Proxy is Disabled",
		Remediation: "You should run the Docker daemon using command: dockerd --userland-proxy=false",
	},
	"D.2.17": api.RESTBenchCheck{
		TestNum:     "D.2.17",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that a daemon-wide custom seccomp profile is applied if appropriate",
		Remediation: "By default, Docker's default seccomp profile is applied. If this is adequate for your environment, no action is necessary.",
	},
	"D.2.18": api.RESTBenchCheck{
		TestNum:     "D.2.18",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that experimental features are not implemented in production",
		Remediation: "You should not pass --experimental as a runtime parameter to the Docker daemon on production systems.",
	},
	"D.3.1": api.RESTBenchCheck{
		TestNum:     "D.3.1",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that docker.service file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.2": api.RESTBenchCheck{
		TestNum:     "D.3.2",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that docker.service file permissions are appropriately set",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.3": api.RESTBenchCheck{
		TestNum:     "D.3.3",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that docker.socket file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.4": api.RESTBenchCheck{
		TestNum:     "D.3.4",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that docker.socket file permissions are set to 644 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.5": api.RESTBenchCheck{
		TestNum:     "D.3.5",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that /etc/docker directory ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.6": api.RESTBenchCheck{
		TestNum:     "D.3.6",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that /etc/docker directory permissions are set to 755 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.7": api.RESTBenchCheck{
		TestNum:     "D.3.7",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that registry certificate file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.8": api.RESTBenchCheck{
		TestNum:     "D.3.8",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that registry certificate file permissions are set to 444 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.9": api.RESTBenchCheck{
		TestNum:     "D.3.9",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that TLS CA certificate file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.10": api.RESTBenchCheck{
		TestNum:     "D.3.10",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that TLS CA certificate file permissions are set to 444 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.11": api.RESTBenchCheck{
		TestNum:     "D.3.11",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker server certificate file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.12": api.RESTBenchCheck{
		TestNum:     "D.3.12",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker server certificate file permissions are set to 444 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.13": api.RESTBenchCheck{
		TestNum:     "D.3.13",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker server certificate key file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.14": api.RESTBenchCheck{
		TestNum:     "D.3.14",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker server certificate key file permissions are set to 400",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.15": api.RESTBenchCheck{
		TestNum:     "D.3.15",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker socket file ownership is set to root:docker",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.16": api.RESTBenchCheck{
		TestNum:     "D.3.16",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker socket file permissions are set to 660 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.17": api.RESTBenchCheck{
		TestNum:     "D.3.17",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that daemon.json file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.18": api.RESTBenchCheck{
		TestNum:     "D.3.18",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that daemon.json file permissions are set to 644 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.19": api.RESTBenchCheck{
		TestNum:     "D.3.19",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that /etc/default/docker file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.20": api.RESTBenchCheck{
		TestNum:     "D.3.20",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the /etc/sysconfig/docker file ownership is set to root:root",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.21": api.RESTBenchCheck{
		TestNum:     "D.3.21",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that /etc/sysconfig/docker file permissions are set to 644 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.3.22": api.RESTBenchCheck{
		TestNum:     "D.3.22",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that /etc/default/docker file permissions are set to 644 or more restrictive",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"D.4.1": api.RESTBenchCheck{
		TestNum:     "D.4.1",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure a user for the container has been created",
		Remediation: "",
	},
	"D.4.2": api.RESTBenchCheck{
		TestNum:     "D.4.2",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that containers use only trusted base images",
		Remediation: "",
	},
	"D.4.3": api.RESTBenchCheck{
		TestNum:     "D.4.3",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that unnecessary packages are not installed in the container",
		Remediation: "",
	},
	"D.4.4": api.RESTBenchCheck{
		TestNum:     "D.4.4",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure images are scanned and rebuilt to include security patches",
		Remediation: "",
	},
	"D.4.5": api.RESTBenchCheck{
		TestNum:     "D.4.5",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure Content trust for Docker is Enabled",
		Remediation: "",
	},
	"D.4.6": api.RESTBenchCheck{
		TestNum:     "D.4.6",
		Type:        "host",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that HEALTHCHECK instructions have been added to container images",
		Remediation: "",
	},
	"D.4.7": api.RESTBenchCheck{
		TestNum:     "D.4.7",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure update instructions are not use alone in the Dockerfile",
		Remediation: "",
	},
	"D.4.8": api.RESTBenchCheck{
		TestNum:     "D.4.8",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure setuid and setgid permissions are removed",
		Remediation: "",
	},
	"D.4.9": api.RESTBenchCheck{
		TestNum:     "D.4.9",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that COPY is used instead of ADD in Dockerfiles",
		Remediation: "",
	},
	"D.4.10": api.RESTBenchCheck{
		TestNum:     "D.4.10",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure secrets are not stored in Dockerfiles",
		Remediation: "",
	},
	"D.4.11": api.RESTBenchCheck{
		TestNum:     "D.4.11",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure only verified packages are installed",
		Remediation: "",
	},
	"D.4.12": api.RESTBenchCheck{
		TestNum:     "D.4.12",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure all signed artifacts are validated",
		Remediation: "Validate artifacts signatures before uploading to the package registry.",
	},
	"D.6.1": api.RESTBenchCheck{
		TestNum:     "D.6.1",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that image sprawl is avoided",
		Remediation: "",
	},
	"D.6.2": api.RESTBenchCheck{
		TestNum:     "D.6.2",
		Type:        "host",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that container sprawl is avoided",
		Remediation: "",
	},
	"D.5.1": api.RESTBenchCheck{
		TestNum:     "D.5.1",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that, if applicable, an AppArmor Profile is enabled",
		Remediation: "",
	},
	"D.5.2": api.RESTBenchCheck{
		TestNum:     "D.5.2",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that, if applicable, SELinux security options are set",
		Remediation: "",
	},
	"D.5.3": api.RESTBenchCheck{
		TestNum:     "D.5.3",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure Linux Kernel Capabilities are restricted within containers",
		Remediation: "",
	},
	"D.5.4": api.RESTBenchCheck{
		TestNum:     "D.5.4",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that privileged containers are not used",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.5": api.RESTBenchCheck{
		TestNum:     "D.5.5",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure sensitive host system directories are not mounted on containers",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.6": api.RESTBenchCheck{
		TestNum:     "D.5.6",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure sshd is not run within containers",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.7": api.RESTBenchCheck{
		TestNum:     "D.5.7",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure privileged ports are not mapped within containers",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.8": api.RESTBenchCheck{
		TestNum:     "D.5.8",
		Type:        "container",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that only needed ports are open on the container",
		Remediation: "",
	},
	"D.5.9": api.RESTBenchCheck{
		TestNum:     "D.5.9",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the host's network namespace is not shared",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.10": api.RESTBenchCheck{
		TestNum:     "D.5.10",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the memory usage for containers is limited",
		Remediation: "",
	},
	"D.5.11": api.RESTBenchCheck{
		TestNum:     "D.5.11",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure CPU priority is set appropriately on the container",
		Remediation: "",
	},
	"D.5.12": api.RESTBenchCheck{
		TestNum:     "D.5.12",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the container's root filesystem is mounted as read only",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.13": api.RESTBenchCheck{
		TestNum:     "D.5.13",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that incoming container traffic is bound to a specific host interface",
		Remediation: "",
	},
	"D.5.14": api.RESTBenchCheck{
		TestNum:     "D.5.14",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the 'on-failure' container restart policy is set to '5'",
		Remediation: "",
	},
	"D.5.15": api.RESTBenchCheck{
		TestNum:     "D.5.15",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the host's process namespace is not shared",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.16": api.RESTBenchCheck{
		TestNum:     "D.5.16",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the host's IPC namespace is not shared",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.17": api.RESTBenchCheck{
		TestNum:     "D.5.17",
		Type:        "container",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that host devices are not directly exposed to containers",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.18": api.RESTBenchCheck{
		TestNum:     "D.5.18",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the default ulimit is overwritten at runtime if needed",
		Remediation: "",
	},
	"D.5.19": api.RESTBenchCheck{
		TestNum:     "D.5.19",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure mount propagation mode is not set to shared",
		Remediation: "",
	},
	"D.5.20": api.RESTBenchCheck{
		TestNum:     "D.5.20",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the host's UTS namespace is not shared",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.21": api.RESTBenchCheck{
		TestNum:     "D.5.21",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure the default seccomp profile is not Disabled",
		Remediation: "",
	},
	"D.5.22": api.RESTBenchCheck{
		TestNum:     "D.5.22",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure docker exec commands are not used with privileged option",
		Remediation: "",
	},
	"D.5.23": api.RESTBenchCheck{
		TestNum:     "D.5.23",
		Type:        "container",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that docker exec commands are not used with the user=root option",
		Remediation: "",
	},
	"D.5.24": api.RESTBenchCheck{
		TestNum:     "D.5.24",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that cgroup usage is confirmed",
		Remediation: "",
	},
	"D.5.25": api.RESTBenchCheck{
		TestNum:     "D.5.25",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the container is restricted from acquiring additional privileges",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.26": api.RESTBenchCheck{
		TestNum:     "D.5.26",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that container health is checked at runtime",
		Remediation: "",
	},
	"D.5.27": api.RESTBenchCheck{
		TestNum:     "D.5.27",
		Type:        "container",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that Docker commands always make use of the latest version of their image",
		Remediation: "",
	},
	"D.5.28": api.RESTBenchCheck{
		TestNum:     "D.5.28",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the PIDs cgroup limit is used",
		Remediation: "",
	},
	"D.5.29": api.RESTBenchCheck{
		TestNum:     "D.5.29",
		Type:        "container",
		Category:    "docker",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that Docker's default bridge 'docker0' is not used",
		Remediation: "",
	},
	"D.5.30": api.RESTBenchCheck{
		TestNum:     "D.5.30",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the host's user namespaces are not shared",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"D.5.31": api.RESTBenchCheck{
		TestNum:     "D.5.31",
		Type:        "container",
		Category:    "docker",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Docker socket is not mounted inside any containers",
		Remediation: "",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.1.1": api.RESTBenchCheck{
		TestNum:     "K.1.1.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.2": api.RESTBenchCheck{
		TestNum:     "K.1.1.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the API server pod specification file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.3": api.RESTBenchCheck{
		TestNum:     "K.1.1.3",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/manifests/kube-controller-manager.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.4": api.RESTBenchCheck{
		TestNum:     "K.1.1.4",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the controller manager pod specification file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/manifests/kube-controller-manager.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.5": api.RESTBenchCheck{
		TestNum:     "K.1.1.5",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/manifests/kube-scheduler.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.6": api.RESTBenchCheck{
		TestNum:     "K.1.1.6",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the scheduler pod specification file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/manifests/kube-scheduler.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.7": api.RESTBenchCheck{
		TestNum:     "K.1.1.7",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the etcd pod specification file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/manifests/etcd.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.8": api.RESTBenchCheck{
		TestNum:     "K.1.1.8",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the etcd pod specification file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/manifests/etcd.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.9": api.RESTBenchCheck{
		TestNum:     "K.1.1.9",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Container Network Interface file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 <path/to/cni/files>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.10": api.RESTBenchCheck{
		TestNum:     "K.1.1.10",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Container Network Interface file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root <path/to/cni/files>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.11": api.RESTBenchCheck{
		TestNum:     "K.1.1.11",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the etcd data directory permissions are set to 700 or more restrictive",
		Remediation: "On the etcd server node, get the etcd data directory, passed as an argument --data-dir, from the below command: ps -ef | grep etcd Run the below command (based on the etcd data directory found above). For example, chmod 700 /var/lib/etcd",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.12": api.RESTBenchCheck{
		TestNum:     "K.1.1.12",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the etcd data directory ownership is set to etcd:etcd",
		Remediation: "On the etcd server node, get the etcd data directory, passed as an argument --data-dir, from the below command: ps -ef | grep etcd Run the below command (based on the etcd data directory found above). For example, chown etcd:etcd /var/lib/etcd",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.13": api.RESTBenchCheck{
		TestNum:     "K.1.1.13",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admin.conf file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/admin.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.14": api.RESTBenchCheck{
		TestNum:     "K.1.1.14",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admin.conf file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/admin.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.15": api.RESTBenchCheck{
		TestNum:     "K.1.1.15",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the scheduler.conf file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/scheduler.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.16": api.RESTBenchCheck{
		TestNum:     "K.1.1.16",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the scheduler.conf file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/scheduler.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.17": api.RESTBenchCheck{
		TestNum:     "K.1.1.17",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod 644 /etc/kubernetes/controller-manager.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.18": api.RESTBenchCheck{
		TestNum:     "K.1.1.18",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the controller-manager.conf file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown root:root /etc/kubernetes/controller-manager.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.19": api.RESTBenchCheck{
		TestNum:     "K.1.1.19",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chown -R root:root /etc/kubernetes/pki/",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.20": api.RESTBenchCheck{
		TestNum:     "K.1.1.20",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Kubernetes PKI certificate file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod -R 644 /etc/kubernetes/pki/*.crt",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.1.21": api.RESTBenchCheck{
		TestNum:     "K.1.1.21",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Kubernetes PKI key file permissions are set to 600",
		Remediation: "Run the below command (based on the file location on your system) on the master node. For example, chmod -R 600 /etc/kubernetes/pki/*.key",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.1": api.RESTBenchCheck{
		TestNum:     "K.1.2.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --anonymous-auth argument is set to false",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. --anonymous-auth=false",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.2": api.RESTBenchCheck{
		TestNum:     "K.1.2.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --basic-auth-file argument is not set",
		Remediation: "Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --basic-auth-file=<filename> parameter.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.3": api.RESTBenchCheck{
		TestNum:     "K.1.2.3",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --token-auth-file parameter is not set",
		Remediation: "Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.4": api.RESTBenchCheck{
		TestNum:     "K.1.2.4",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --kubelet-https argument is set to true",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --kubelet-https parameter.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.5": api.RESTBenchCheck{
		TestNum:     "K.1.2.5",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
		Remediation: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets. Then, edit API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the kubelet client certificate and key parameters as below. --kubelet-client-certificate=<path/to/client-certificate-file> --kubelet-client-key=<path/to/client-key-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.6": api.RESTBenchCheck{
		TestNum:     "K.1.2.6",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
		Remediation: "Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the -- kubelet-certificate-authority parameter to the path to the cert file for the certificate authority. --kubelet-certificate-authority=<ca-string>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.7": api.RESTBenchCheck{
		TestNum:     "K.1.2.7",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to values other than AlwaysAllow . One such example could be as below. --authorization-mode=RBAC",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.8": api.RESTBenchCheck{
		TestNum:     "K.1.2.8",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --authorization-mode argument includes Node",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to a value that includes Node . --authorization-mode=Node,RBAC",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.9": api.RESTBenchCheck{
		TestNum:     "K.1.2.9",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --authorization-mode argument includes RBAC",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --authorization-mode parameter to a value that includes RBAC, for example:--authorization-mode=Node,RBAC",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.10": api.RESTBenchCheck{
		TestNum:     "K.1.2.10",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin EventRateLimit is set",
		Remediation: "Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters.  --enable-admission-plugins=...,EventRateLimit,... --admission-control-config-file=<path/to/configuration/file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.11": api.RESTBenchCheck{
		TestNum:     "K.1.2.11",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin AlwaysAdmit is not set",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and either remove the --enable-admission-plugins parameter, or set it to a value that does not include AlwaysAdmit.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.12": api.RESTBenchCheck{
		TestNum:     "K.1.2.12",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin AlwaysPullImages is set",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to include AlwaysPullImages.  --enable-admission-plugins=...,AlwaysPullImages,...",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.13": api.RESTBenchCheck{
		TestNum:     "K.1.2.13",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place.  --enable-admission-plugins=...,SecurityContextDeny,...",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.14": api.RESTBenchCheck{
		TestNum:     "K.1.2.14",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin ServiceAccount is set",
		Remediation: "Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is set to a value that does not include ServiceAccount.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.15": api.RESTBenchCheck{
		TestNum:     "K.1.2.15",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin NamespaceLifecycle is set",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.16": api.RESTBenchCheck{
		TestNum:     "K.1.2.16",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin PodSecurityPolicy is set",
		Remediation: "Follow the documentation and create Pod Security Policy objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes PodSecurityPolicy: --enable-admission-plugins=...,PodSecurityPolicy,... Then restart the API Server.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.17": api.RESTBenchCheck{
		TestNum:     "K.1.2.17",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the admission control plugin NodeRestriction is set",
		Remediation: "Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction. --enable-admission-plugins=...,NodeRestriction,...",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
		},
	},
	"K.1.2.18": api.RESTBenchCheck{
		TestNum:     "K.1.2.18",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --insecure-bind-address argument is not set",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and remove the --insecure-bind-address parameter.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.19": api.RESTBenchCheck{
		TestNum:     "K.1.2.19",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --insecure-port argument is set to 0",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. --insecure-port=0",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.20": api.RESTBenchCheck{
		TestNum:     "K.1.2.20",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --secure-port argument is not set to 0",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and either remove the --secure-port parameter or set it to a different (non-zero) desired port.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.21": api.RESTBenchCheck{
		TestNum:     "K.1.2.21",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --profiling argument is set to false",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. --profiling=false",
	},
	"K.1.2.22": api.RESTBenchCheck{
		TestNum:     "K.1.2.22",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --audit-log-path argument is set",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-path parameter to a suitable path and file where you would like audit logs to be written, for example: --audit-log-path=/var/log/apiserver/audit.log",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.23": api.RESTBenchCheck{
		TestNum:     "K.1.2.23",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days: --audit-log-maxage=30",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.24": api.RESTBenchCheck{
		TestNum:     "K.1.2.24",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value. --audit-log-maxbackup=10",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.25": api.RESTBenchCheck{
		TestNum:     "K.1.2.25",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --audit-log-maxsize parameter to an appropriate size in MB. For example, to set it as 100 MB: --audit-log-maxsize=100",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.26": api.RESTBenchCheck{
		TestNum:     "K.1.2.26",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --request-timeout argument is set as appropriate",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameter as appropriate and if needed. For example, --request-timeout=300s",
	},
	"K.1.2.27": api.RESTBenchCheck{
		TestNum:     "K.1.2.27",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --service-account-lookup argument is set to true",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter. --service-account-lookup=true",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.28": api.RESTBenchCheck{
		TestNum:     "K.1.2.28",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --service-account-key-file argument is set as appropriate",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --service-account-key-file parameter to the public key file for service accounts: --service-account-key-file=<filename>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.29": api.RESTBenchCheck{
		TestNum:     "K.1.2.29",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
		Remediation: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters.  --etcd-certfile=<path/to/client-certificate-file> --etcd-keyfile=<path/to/client-key-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.30": api.RESTBenchCheck{
		TestNum:     "K.1.2.30",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		Remediation: "Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the TLS certificate and private key file parameters. --tls-cert-file=<path/to/tls-certificate-file> --tls-private-key-file=<path/to/tls-key-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.31": api.RESTBenchCheck{
		TestNum:     "K.1.2.31",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --client-ca-file argument is set as appropriate",
		Remediation: "Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the client certificate authority file. --client-ca-file=<path/to/client-ca-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.32": api.RESTBenchCheck{
		TestNum:     "K.1.2.32",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --etcd-cafile argument is set as appropriate",
		Remediation: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate authority file parameter. --etcd-cafile=<path/to/ca-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.33": api.RESTBenchCheck{
		TestNum:     "K.1.2.33",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --encryption-provider-config argument is set as appropriate",
		Remediation: "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file: --encryption-provider-config=</path/to/EncryptionConfig/File>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.34": api.RESTBenchCheck{
		TestNum:     "K.1.2.34",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that encryption providers are appropriately configured",
		Remediation: "Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, choose aescbc, kms or secretbox as the encryption provider.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.2.35": api.RESTBenchCheck{
		TestNum:     "K.1.2.35",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
		Remediation: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the below parameter as follows, or to a subset of these values. --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM _SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM _SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM _SHA384",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.3.1": api.RESTBenchCheck{
		TestNum:     "K.1.3.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --terminated-pod-gc-threshold to an appropriate threshold, for example: --terminated-pod-gc-threshold=10",
	},
	"K.1.3.2": api.RESTBenchCheck{
		TestNum:     "K.1.3.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --profiling argument is set to false",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the below parameter. --profiling=false",
	},
	"K.1.3.3": api.RESTBenchCheck{
		TestNum:     "K.1.3.3",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --use-service-account-credentials argument is set to true",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node to set the below parameter. --use-service-account-credentials=true",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.3.4": api.RESTBenchCheck{
		TestNum:     "K.1.3.4",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --service-account-private-key-file argument is set as appropriate",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --service-account-private- key-file parameter to the private key file for service accounts. --service-account-private-key-file=<filename>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.3.5": api.RESTBenchCheck{
		TestNum:     "K.1.3.5",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --root-ca-file argument is set as appropriate",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --root-ca-file parameter to the certificate bundle file`. --root-ca-file=<path/to/file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.3.6": api.RESTBenchCheck{
		TestNum:     "K.1.3.6",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that the RotateKubeletServerCertificate argument is set to true",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true. --feature-gates=RotateKubeletServerCertificate=true",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.1.3.7": api.RESTBenchCheck{
		TestNum:     "K.1.3.7",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --bind-address argument is set to 127.0.0.1",
		Remediation: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the master node and ensure the correct value for the --bind-address parameter.",
	},
	"K.1.4.1": api.RESTBenchCheck{
		TestNum:     "K.1.4.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --profiling argument is set to false",
		Remediation: "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the master node and set the below parameter. --profiling=false",
	},
	"K.1.4.2": api.RESTBenchCheck{
		TestNum:     "K.1.4.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --bind-address argument is set to 127.0.0.1",
		Remediation: "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the master node and ensure the correct value for the --bind-address parameter",
	},
	"K.2.1": api.RESTBenchCheck{
		TestNum:     "K.2.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --cert-file and --key-file arguments are set as appropriate",
		Remediation: "Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.  --cert-file=</path/to/ca-file> --key-file=</path/to/key-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.2": api.RESTBenchCheck{
		TestNum:     "K.2.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --client-cert-auth argument is set to true",
		Remediation: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. --client-cert-auth=\"true\"",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.3": api.RESTBenchCheck{
		TestNum:     "K.2.3",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --auto-tls argument is not set to true",
		Remediation: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter or set it to false. --auto-tls=false",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.4": api.RESTBenchCheck{
		TestNum:     "K.2.4",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
		Remediation: "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters.  --peer-cert-file=</path/to/peer-cert-file> --peer-key-file=</path/to/peer-key-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.5": api.RESTBenchCheck{
		TestNum:     "K.2.5",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --peer-client-cert-auth argument is set to true",
		Remediation: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. --peer-client-cert-auth=true",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.6": api.RESTBenchCheck{
		TestNum:     "K.2.6",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --peer-auto-tls argument is not set to true",
		Remediation: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --peer-auto-tls parameter or set it to false. --peer-auto-tls=false",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.2.7": api.RESTBenchCheck{
		TestNum:     "K.2.7",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that a unique Certificate Authority is used for etcd",
		Remediation: "Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service. Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter. --trusted-ca-file=</path/to/ca-file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.3.1.1": api.RESTBenchCheck{
		TestNum:     "K.3.1.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Client certificate authentication should not be used for users",
		Remediation: "Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of client certificates.",
	},
	"K.3.2.1": api.RESTBenchCheck{
		TestNum:     "K.3.2.1",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that a minimal audit policy is created",
		Remediation: "Create an audit policy file for your cluster.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.3.2.2": api.RESTBenchCheck{
		TestNum:     "K.3.2.2",
		Type:        "master",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   false,
		Description: "Ensure that the audit policy covers key security concerns",
		Remediation: "Consider modification of the audit policy in use on the cluster to include these items, at a minimum.",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.1": api.RESTBenchCheck{
		TestNum:     "K.4.1.1",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the kubelet service file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chmod 644 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.2": api.RESTBenchCheck{
		TestNum:     "K.4.1.2",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the kubelet service file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root /etc/systemd/system/kubelet.service.d/10-kubeadm.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.3": api.RESTBenchCheck{
		TestNum:     "K.4.1.3",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chmod 644 <proxy kubeconfig file",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.4": api.RESTBenchCheck{
		TestNum:     "K.4.1.4",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the proxy kubeconfig file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root <proxy kubeconfig file>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.5": api.RESTBenchCheck{
		TestNum:     "K.4.1.5",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the kubelet.conf file permissions are set to 644 or more restrictive",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chmod 644 /etc/kubernetes/kubelet.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.6": api.RESTBenchCheck{
		TestNum:     "K.4.1.6",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the kubelet.conf file ownership is set to root:root",
		Remediation: "Run the below command (based on the file location on your system) on the each worker node. For example, chown root:root /etc/kubernetes/kubelet.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.7": api.RESTBenchCheck{
		TestNum:     "K.4.1.7",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the certificate authorities file permissions are set to 644 or more restrictive",
		Remediation: "Run the following command to modify the file permissions of the --client-ca-file chmod 644 <filename>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.8": api.RESTBenchCheck{
		TestNum:     "K.4.1.8",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the client certificate authorities file ownership is set to root:root",
		Remediation: "Run the following command to modify the ownership of the --client-ca-file. chown root:root <filename>",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.9": api.RESTBenchCheck{
		TestNum:     "K.4.1.9",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the kubelet configuration file has permissions set to 644 or more restrictive",
		Remediation: "Run the following command (using the config file location identied in the Audit step) chmod 644 /var/lib/kubelet/config.yaml",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.1.10": api.RESTBenchCheck{
		TestNum:     "K.4.1.10",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the kubelet configuration file ownership is set to root:root",
		Remediation: "Run the following command (using the config file location identied in the Audit step) chown root:root /etc/kubernetes/kubelet.conf",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.1": api.RESTBenchCheck{
		TestNum:     "K.4.2.1",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the anonymous-auth argument is set to false",
		Remediation: "If using a Kubelet config file, edit the file to set authentication: anonymous: enabled to false. If using executable arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. --anonymous-auth=false Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.2": api.RESTBenchCheck{
		TestNum:     "K.4.2.2",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		Remediation: "If using a Kubelet config file, edit the file to set authorization: mode to Webhook. If using executable arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_AUTHZ_ARGS variable. --authorization-mode=Webhook Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.3": api.RESTBenchCheck{
		TestNum:     "K.4.2.3",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the --client-ca-file argument is set as appropriate",
		Remediation: "If using a Kubelet config file, edit the file to set authentication: x509: clientCAFile to the location of the client CA file. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_AUTHZ_ARGS variable. --client-ca-file=<path/to/client-ca-file> Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.4": api.RESTBenchCheck{
		TestNum:     "K.4.2.4",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the --read-only-port argument is set to 0",
		Remediation: "If using a Kubelet config file, edit the file to set readOnlyPort to 0. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. --read-only-port=0 Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.5": api.RESTBenchCheck{
		TestNum:     "K.4.2.5",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
		Remediation: "If using a Kubelet config file, edit the file to set streamingConnectionIdleTimeout to a value other than 0. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. --streaming-connection-idle-timeout=5m Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
	},
	"K.4.2.6": api.RESTBenchCheck{
		TestNum:     "K.4.2.6",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --protect-kernel-defaults argument is set to true",
		Remediation: "If using a Kubelet config file, edit the file to set protectKernelDefaults: true. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. --protect-kernel-defaults=true Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.7": api.RESTBenchCheck{
		TestNum:     "K.4.2.7",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --make-iptables-util-chains argument is set to true",
		Remediation: "If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove the --make-iptables-util-chains argument from the KUBELET_SYSTEM_PODS_ARGS variable. Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
	},
	"K.4.2.8": api.RESTBenchCheck{
		TestNum:     "K.4.2.8",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --hostname-override argument is not set",
		Remediation: "Edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove the --hostname-override argument from the KUBELET_SYSTEM_PODS_ARGS variable. Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
	},
	"K.4.2.9": api.RESTBenchCheck{
		TestNum:     "K.4.2.9",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 2",
		Automated:   true,
		Description: "Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
		Remediation: "If using a Kubelet config file, edit the file to set eventRecordQPS: to an appropriate level. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable. Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
	},
	"K.4.2.10": api.RESTBenchCheck{
		TestNum:     "K.4.2.10",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   true,
		Description: "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		Remediation: "If using a Kubelet config file, edit the file to set tlsCertFile to the location of the certificate file to use to identify this Kubelet, and tlsPrivateKeyFile to the location of the corresponding private key file. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameters in KUBELET_CERTIFICATE_ARGS variable.  --tls-cert-file=<path/to/tls-certificate-file> --tls-private-key- file=<path/to/tls-key-file> Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.11": api.RESTBenchCheck{
		TestNum:     "K.4.2.11",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the --rotate-certificates argument is not set to false",
		Remediation: "If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value. If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove --rotate-certificates=false argument from the KUBELET_CERTIFICATE_ARGS variable. Based on your system, restart the kubelet service. For example: systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.12": api.RESTBenchCheck{
		TestNum:     "K.4.2.12",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the RotateKubeletServerCertificate argument is set to true",
		Remediation: "On the master edit /var/lib/kubelet/kubeadm-flags.env and set the parameter KUBELET_CERTIFICATE_ARGS --feature-gates=RotateKubeletServerCertificate=true or as an alternative, and suggested as a last resort, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the below parameter in KUBELET_CERTIFICATE_ARGS variable. --feature-gates=RotateKubeletServerCertificate=true Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
	"K.4.2.13": api.RESTBenchCheck{
		TestNum:     "K.4.2.13",
		Type:        "worker",
		Category:    "kubernetes",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
		Remediation: "If using a Kubelet config file, edit the file to set TLSCipherSuites: to TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256 or to a subset of these values. If using executable arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and set the --tls-cipher-suites parameter as follows, or to a subset of these values. --tls-cipher- suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM _SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM _SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM _SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256 Based on your system, restart the kubelet service. For example:  systemctl daemon-reload systemctl restart kubelet.service",
		Tags: map[string]share.TagDetails{
			"HIPAA": share.TagDetails{},
			"PCI":   share.TagDetails{},
			"GDPR":  share.TagDetails{},
		},
	},
}

type CISCheck struct {
	ID          string                      `yaml:"id"`
	Description string                      `yaml:"description"`
	Type        string                      `yaml:"type"`
	Category    string                      `yaml:"category"`
	Scored      bool                        `yaml:"scored"`
	Profile     string                      `yaml:"profile"`
	Automated   bool                        `yaml:"automated"`
	Tags        map[string]share.TagDetails `yaml:"tags,omitempty"`
	Remediation string                      `yaml:"remediation"`
}

type Group struct {
	CISChecks []CISCheck `yaml:"checks"`
}

type CISBenchmarkConfig struct {
	Groups []Group `yaml:"groups"`
}

type CISCheckWithTags struct {
	ID   string                      `yaml:"id"`
	Tags map[string]share.TagDetails `yaml:"tags,omitempty"`
}

type PrimeCISBenchmarkConfig struct {
	CISChecksWithTags []CISCheckWithTags `yaml:"checks"`
}

func InitComplianceMeta(platform, flavor, cloudPlatform string) ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {
	// Ensuring initialization happens only once
	once.Do(func() {
		// For fast rollback to original setting when fail
		PrepareBackup()
		// Check the current k8s version, then read the correct folder
		GetCISFolder(platform, flavor, cloudPlatform)
		GetK8sCISMeta(remediationFolder, cisItems)
		PrepareBenchMeta(cisItems, &complianceMetas, complianceMetaMap, &isUpdateComplianceMetaMap)
	})

	if isUpdateComplianceMetaMap {
		updateMetasFromMap(&complianceMetas, complianceMetaMap, &isUpdateComplianceMetaMap)
	}

	return complianceMetas, complianceMetaMap
}

func GetComplianceMeta() ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {

	if complianceMetas == nil || complianceMetaMap == nil {
		// if this is still nil, wait for the InitComplianceMeta
		// scanUtils.InitComplianceMeta() is called in controller\controller.go before cache/rest call GetComplianceMeta => we can assume the platform / flavor is correct at this point
		return InitComplianceMeta("", "", "")
	}

	if isUpdateComplianceMetaMap {
		updateMetasFromMap(&complianceMetas, complianceMetaMap, &isUpdateComplianceMetaMap)
	}

	return complianceMetas, complianceMetaMap
}

func InitImageBenchMeta() ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {
	// Ensuring initialization happens only once
	once.Do(func() {
		PrepareBenchMeta(dockerImageCISItems, &imageBenchMetas, imageBenchMetaMap, &isUpdateImageBenchMetaMap)
	})

	if isUpdateImageBenchMetaMap {
		updateMetasFromMap(&imageBenchMetas, imageBenchMetaMap, &isUpdateImageBenchMetaMap)
	}

	return imageBenchMetas, imageBenchMetaMap
}

func GetImageBenchMeta() ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {

	if imageBenchMetas == nil || imageBenchMetaMap == nil {
		// if this is still nil, wait for the InitComplianceMeta
		return InitImageBenchMeta()
	}

	if isUpdateImageBenchMetaMap {
		updateMetasFromMap(&imageBenchMetas, imageBenchMetaMap, &isUpdateImageBenchMetaMap)
	}

	return imageBenchMetas, imageBenchMetaMap
}

func GetImageBencheMeta() ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {

	if imageBenchMetas == nil || imageBenchMetaMap == nil {
		// if this is still nil, wait for the InitComplianceMeta
		return InitImageBenchMeta()
	}
	return imageBenchMetas, imageBenchMetaMap
}

func updateMetasFromMap(slice *[]api.RESTBenchMeta, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) {
	*slice = make([]api.RESTBenchMeta, 0, len(metaMap))
	for _, item := range metaMap {
		*slice = append(*slice, item)
	}
	sort.Slice(*slice, func(i, j int) bool { return (*slice)[i].TestNum < (*slice)[j].TestNum })
	*updateFlag = false
}

func PrepareBackup() {
	for key, value := range cisItems {
		backupCISItems[key] = DeepCopyRESTBenchCheck(value)
	}

	for key, value := range dockerImageCISItems {
		backupDockerImageCISItems[key] = DeepCopyRESTBenchCheck(value)
	}
}

func DeepCopyRESTBenchCheck(orig api.RESTBenchCheck) api.RESTBenchCheck {
	copy := api.RESTBenchCheck{
		TestNum:     orig.TestNum,
		Type:        orig.Type,
		Category:    orig.Category,
		Scored:      orig.Scored,
		Profile:     orig.Profile,
		Automated:   orig.Automated,
		Description: orig.Description,
		Remediation: orig.Remediation,
		Tags:        nil,
	}

	// Deep copy the Tags map
	if orig.Tags != nil {
		copy.Tags = make(map[string]share.TagDetails)
		for compliance, detailsMap := range orig.Tags {
			copiedDetailsMap := make(share.TagDetails)
			for key, detail := range detailsMap {
				copiedDetailsMap[key] = share.TagDetail{
					ID:              detail.ID,
					Title:           detail.Title,
					Description:     detail.Description,
					CIS_Sub_Control: detail.CIS_Sub_Control,
				}
			}
			copy.Tags[compliance] = copiedDetailsMap
		}
	}

	return copy
}

func GetCISFolder(platform, flavor, cloudPlatform string) {
	if global.ORCH != nil {
		k8sVer, ocVer := global.ORCH.GetVersion(false, false)
		if platform == share.PlatformKubernetes && cloudPlatform == share.CloudGKE {
			kVer, err := version.NewVersion(k8sVer)
			if err != nil {
				cisVersion = gke140
			} else if kVer.Compare(version.Must(version.NewVersion("1.23"))) >= 0 {
				cisVersion = gke140
			} else {
				cisVersion = defaultCISVersion
			}
		} else if platform == share.PlatformKubernetes && cloudPlatform == share.CloudAKS {
			// Currently support AKS-1.4.0 only
			cisVersion = aks140
		} else if platform == share.PlatformKubernetes && cloudPlatform == share.CloudEKS {
			// Currently support EKS-1.4.0 only
			cisVersion = eks140
		} else if platform == share.PlatformKubernetes && flavor == share.FlavorOpenShift {
			ocVer, err := version.NewVersion(ocVer)
			if err != nil {
				cisVersion = rh140
			} else if ocVer.Compare(version.Must(version.NewVersion("4.6"))) >= 0 {
				cisVersion = rh140
			} else {
				cisVersion = defaultCISVersion
			}
		} else {
			kVer, err := version.NewVersion(k8sVer)
			if err != nil {
				cisVersion = kube180
			} else if kVer.Compare(version.Must(version.NewVersion("1.27"))) >= 0 {
				cisVersion = kube180
			} else if kVer.Compare(version.Must(version.NewVersion("1.24"))) >= 0 {
				cisVersion = kube124
			} else if kVer.Compare(version.Must(version.NewVersion("1.23"))) >= 0 {
				cisVersion = kube123
			} else if kVer.Compare(version.Must(version.NewVersion("1.16"))) >= 0 {
				cisVersion = kube160
			} else {
				cisVersion = defaultCISVersion
			}
		}
	} else {
		cisVersion = defaultCISVersion
	}

	remediationFolder = fmt.Sprintf("%s%s/", dstPrefix, cisVersion)
}

func processCISBenchmarkYAML(path string, cis_bench_items map[string]api.RESTBenchCheck) error {
	fileContent, err := os.ReadFile(path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error reading file")
		return err
	}

	var cisBenchmarkConfig CISBenchmarkConfig
	err = yaml.Unmarshal(fileContent, &cisBenchmarkConfig)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error unmarshalling YAML file")
		return err
	}

	for _, group := range cisBenchmarkConfig.Groups {
		for _, check := range group.CISChecks {
			cis_bench_items[check.ID] = api.RESTBenchCheck{
				TestNum:     check.ID,
				Type:        check.Type,
				Category:    check.Category,
				Scored:      check.Scored,
				Profile:     check.Profile,
				Automated:   check.Automated,
				Description: catchDescription.ReplaceAllString(check.Description, "$1"),
				Remediation: check.Remediation,
				Tags:        check.Tags,
			}
		}
	}
	return nil
}

func GetK8sCISMeta(remediationFolder string, cis_bench_items map[string]api.RESTBenchCheck) {
	// Read every yaml under the folder, then dynamically update the cis_bench_items
	err := filepath.Walk(remediationFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error encountered while walking through the path")
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".yaml" {
			return processCISBenchmarkYAML(path, cis_bench_items)
		}
		return nil
	})

	// if Failed at walk, stay with original value
	if err != nil {
		cisItems = backupCISItems
		dockerImageCISItems = backupDockerImageCISItems
	}
}

func PrepareBenchMeta(items map[string]api.RESTBenchCheck, metas *[]api.RESTBenchMeta, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) {
	for _, item := range items {
		metaMap[item.TestNum] = api.RESTBenchMeta{RESTBenchCheck: item}
	}
	*updateFlag = true
}

func updateWithPrimeConfig(primeConfig string, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) {
	fileContent, err := os.ReadFile(primeConfig)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error reading file")
	}

	var primeCISBenchmarkConfig PrimeCISBenchmarkConfig
	err = yaml.Unmarshal(fileContent, &primeCISBenchmarkConfig)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error unmarshalling YAML file")
		return
	}

	for _, check := range primeCISBenchmarkConfig.CISChecksWithTags {
		if metaData, exists := metaMap[check.ID]; exists {
			primeMetaData := metaData

			if primeMetaData.Tags == nil {
				primeMetaData.Tags = make(map[string]share.TagDetails)
			}

			for compliance, complianceDetails := range check.Tags {
				primeMetaData.Tags[compliance] = complianceDetails
			}

			metaMap[check.ID] = primeMetaData
		} else {
			log.WithFields(log.Fields{"check.Id": check.ID}).Info("check.ID is not in metaMap: ")
			break
		}
	}
	*updateFlag = true
}

func LoadConfig(primeConfig string, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) {
	if _, err := os.Stat(primeConfig); err == nil {
		updateWithPrimeConfig(primeConfig, metaMap, updateFlag)
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Init watcher error ")
		return
	}

	defer watcher.Close()
	done := make(chan bool)

	if _, err := os.Stat(filepath.Dir(primeConfig)); os.IsNotExist(err) {
		log.WithFields(log.Fields{"directory": filepath.Dir(primeConfig)}).Info("Directory does not exist, skipping watcher setup")
		return
	} else {
		err = watcher.Add(filepath.Dir(primeConfig))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to add directory to watcher")
			return
		}
	}

	go func() {
		defer close(done)
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				switch {
				case event.Op&fsnotify.Create == fsnotify.Create && event.Name == primeConfig:
					updateWithPrimeConfig(primeConfig, metaMap, updateFlag)
					return
				case event.Op&fsnotify.Write == fsnotify.Write && event.Name == primeConfig:
					updateWithPrimeConfig(primeConfig, metaMap, updateFlag)
					return
				}
			case err, ok := <-watcher.Errors:
				if !ok && err == nil {
					return
				}
				log.WithFields(log.Fields{"error": err, "ok": ok}).Error("LoadPrimeConfig error: ")
				return
			}
		}
	}()
	<-done
}

func UpdateComplianceConfigs() {
	// update prime cis configs
	primeCISConfig := fmt.Sprintf("%s%s.yaml", primeConfigPrefix, cisVersion)

	// update prime cis docker configs
	primeDockerConfig := fmt.Sprintf("%s%s.yaml", primeConfigPrefix, "cis-docker")

	// update prime cis docker image configs
	primeDockerImageConfig := fmt.Sprintf("%s%s.yaml", primeConfigPrefix, "cis-docker-image")

	go LoadConfig(primeCISConfig, complianceMetaMap, &isUpdateComplianceMetaMap)
	go LoadConfig(primeDockerConfig, complianceMetaMap, &isUpdateComplianceMetaMap)
	go LoadConfig(primeDockerImageConfig, imageBenchMetaMap, &isUpdateImageBenchMetaMap)
}
