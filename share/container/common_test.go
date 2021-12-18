package container

import (
	"testing"
)

func TestTrimImageName(t *testing.T) {
	repls := map[string]string{
		"nginx":                                 "nginx",
		"nginx:5":                               "nginx",
		"neuvector/nginx:5":                     "neuvector/nginx",
		"1.2.3.4/neuvector/nginx:5":             "1.2.3.4/neuvector/nginx",
		"1.2.3.4:5000/neuvector/nginx:5":        "1.2.3.4:5000/neuvector/nginx",
		"1.2.3.4:5000/neuvector/nginx":          "1.2.3.4:5000/neuvector/nginx",
		"1.2.3.4:5000/neuvector/nginx:5:latest": "1.2.3.4:5000/neuvector/nginx:5",
		"docker.io/neuvector/nginx:5:latest":    "docker.io/neuvector/nginx:5",
	}

	for k, v := range repls {
		out := TrimContainerImageVersion(k)
		if v != out {
			t.Errorf("Error: %v\n", k)
			t.Errorf("  Expect: %v\n", v)
			t.Errorf("  Actual: %v\n", out)
		}
	}
}

func TestTrimImageRepo(t *testing.T) {
	repls := map[string]string{
		"nginx":                                           "nginx",
		"nginx:5":                                         "nginx:5",
		"neuvector/nginx:5":                               "neuvector/nginx:5",
		"1.2.3.4/neuvector/nginx:5":                       "neuvector/nginx:5",
		"1.2.3.4:5000/neuvector/nginx:5":                  "neuvector/nginx:5",
		"1.2.3.4:5000/neuvector/nginx":                    "neuvector/nginx",
		"1.2.3.4:5000/neuvector/nginx:5:latest":           "neuvector/nginx:5:latest",
		"300.2.3.4:5000/neuvector/nginx:5:latest":         "neuvector/nginx:5:latest",
		"docker.io/neuvector/nginx:5:latest":              "neuvector/nginx:5:latest",
		"registry.access.redhat.com/rhel7-atomic:7.5-217": "rhel7-atomic:7.5-217",
	}

	for k, v := range repls {
		out := TrimContainerImageRepo(k)
		if v != out {
			t.Errorf("Error: %v\n", k)
			t.Errorf("  Expect: %v\n", v)
			t.Errorf("  Actual: %v\n", out)
		}
	}
}
