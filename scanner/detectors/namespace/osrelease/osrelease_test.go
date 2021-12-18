package osrelease

import (
	"testing"

	"github.com/neuvector/neuvector/scanner/detectors"
)

func Test_AMZN(t *testing.T) {
	osr := `"NAME="Amazon Linux"
VERSION="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2"
HOME_URL="https://amazonlinux.com/"`

	data := map[string]*detectors.FeatureFile{
		"etc/os-release": &detectors.FeatureFile{Data: []byte(osr)},
	}

	var d OsReleaseNamespaceDetector
	ns := d.Detect(data)
	if ns.Name != "amzn:2" {
		t.Errorf("Invalid namespace: %v", ns.Name)
	}
}
