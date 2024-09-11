package scan

import (
	"testing"
)

func TestParseSocket(t *testing.T) {
	tests := [][]string{
		{"tcp://example.com/calico/agent", "tcp://example.com", "calico/agent"},
		{"tcp://example.com/alpine", "tcp://example.com", "alpine"},
		{"tcp://example.com/", "tcp://example.com", ""},
		{"tcp://example.com", "", "tcp://example.com"},
		{"tcp:/example.com/calico/agent", "", "tcp:/example.com/calico/agent"},
		{"", "", ""},
	}

	for _, test := range tests {
		sock, repo := parseSocketFromRepo(test[0])
		if sock != test[1] || repo != test[2] {
			t.Errorf("Incorrect: %s ==> %s, %s\n", test[0], sock, repo)
		}
	}
}

func TestParseImageCmds(t *testing.T) {
	{
		cmds := []string{
			"ADD file:102f967d15c3ceeba444c8ea6479e7ff6f859a8ba2310051729d981a7a771ace in /",
			"ADD d94974b7ca315d3269b037de15d4d4ee2a2acbe839ef4c2962cf365db6c94fdd in /",
			"CMD [\"/bin/sh\"]",
			"ADD file:c92c248239f8c7b9b3c067650954815f391b7bcb09023f984972c082ace2a8d0 in /",
		}
		_, hasADD, _ := ParseImageCmds(cmds)
		if !hasADD {
			t.Errorf("Should report ADD is used for remote download\n")
		}
	}
	{
		cmds := []string{
			"ADD file:102f967d15c3ceeba444c8ea6479e7ff6f859a8ba2310051729d981a7a771ace in /",
			"CMD [\"/bin/sh\"]",
			"ADD file:c92c248239f8c7b9b3c067650954815f391b7bcb09023f984972c082ace2a8d0 in /",
		}
		_, hasADD, _ := ParseImageCmds(cmds)
		if hasADD {
			t.Errorf("Should not report ADD is used for remote download\n")
		}
	}

	// runAsRoot
	{
		cmds := []string{
			"USER 1000",
			"CMD [\"/bin/sh\"]",
		}
		runAsRoot, _, _ := ParseImageCmds(cmds)
		if runAsRoot {
			t.Errorf("Should not report runAsRoot\n")
			t.Errorf("  %s\n", cmds)
		}
	}
	{
		cmds := []string{
			"CMD [\"/bin/sh\"]",
		}
		runAsRoot, _, _ := ParseImageCmds(cmds)
		if !runAsRoot {
			t.Errorf("Should report runAsRoot\n")
			t.Errorf("  %s\n", cmds)
		}
	}
	{
		cmds := []string{
			"USER root",
			"CMD [\"/bin/sh\"]",
		}
		runAsRoot, _, _ := ParseImageCmds(cmds)
		if !runAsRoot {
			t.Errorf("Should report runAsRoot\n")
			t.Errorf("  %s\n", cmds)
		}
	}
	{
		cmds := []string{
			"USER 0",
			"CMD [\"/bin/sh\"]",
		}
		runAsRoot, _, _ := ParseImageCmds(cmds)
		if !runAsRoot {
			t.Errorf("Should report runAsRoot\n")
			t.Errorf("  %s\n", cmds)
		}
	}

}

func TestNormalizeImageCmds(t *testing.T) {
	tests := map[string]string{
		"/bin/sh -c #(nop)  USER [manager]":                                                 "USER [manager]",
		"|1 NV_TAG=jenkins-nv-build-manager-2422 /bin/sh -c adduser -S manager":             "RUN adduser -S manager",
		"/bin/sh -c set -x && apk add --update ca-certificates iproute2 lsof procps python": "RUN set -x && apk add --update ca-certificates iproute2 lsof procps python",
	}
	for in, exp := range tests {
		out := NormalizeImageCmd(in)
		if out != exp {
			t.Errorf("Incorrect: %s ==> %s\n", in, out)
		}
	}
}
