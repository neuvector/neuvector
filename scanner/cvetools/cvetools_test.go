package cvetools

import (
	"os"
	"testing"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
)

const testTmpPath = "/tmp/scanner_test/"

func checkVul(vuls []vulFullReport, name string) bool {
	for _, vul := range vuls {
		if vul.Vf.Name == name {
			return true
		}
	}
	return false
}

func makePlatformReq(k8s, oc string) []scan.AppPackage {
	pkgs := make([]scan.AppPackage, 0)
	if oc != "" {
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "openshift",
			ModuleName: "openshift.kubernetes",
			Version:    oc,
			FileName:   "kubernetes",
		})
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "openshift",
			ModuleName: "openshift",
			Version:    oc,
			FileName:   "openshift",
		})
	} else if k8s != "" {
		pkgs = append(pkgs, scan.AppPackage{
			AppName:    "kubernetes",
			ModuleName: "kubernetes",
			Version:    k8s,
			FileName:   "kubernetes",
		})
	}
	return pkgs
}

func TestCVE_2018_1002105(t *testing.T) {
	// acquire tool
	sys := system.NewSystemTools()
	cveTools = NewCveTools("", scan.NewScanUtil(sys))
	ver, _, _, _, err := common.LoadCveDb("../../data/", testTmpPath)
	if err != nil {
		t.Errorf("CVEDB read error: %+v", err)
		return
	}

	oc := ""
	k8s := "1.10.1"
	appvuls := cveTools.DetectAppVul(testTmpPath, makePlatformReq(k8s, ""), "")
	if !checkVul(appvuls, "CVE-2018-1002105") {
		t.Errorf("vulnerability false negative: db=%s k8s=%s", ver, k8s)
	}

	k8s = "1.11.5"
	appvuls = cveTools.DetectAppVul(testTmpPath, makePlatformReq(k8s, ""), "")
	if checkVul(appvuls, "CVE-2018-1002105") {
		t.Errorf("vulnerability false positive: db=%s k8s=%s", ver, k8s)
	}

	// k8s vulnerable, but oc not
	k8s = "1.11.2"
	oc = "3.11.82"
	appvuls = cveTools.DetectAppVul(testTmpPath, makePlatformReq(k8s, oc), "")
	if checkVul(appvuls, "CVE-2018-1002105") {
		t.Errorf("vulnerability false positive: db=%s k8s=%s oc=%s", ver, k8s, oc)
	}

	// both vulnerable
	k8s = "1.11.2"
	oc = "3.11.10"
	appvuls = cveTools.DetectAppVul(testTmpPath, makePlatformReq(k8s, oc), "")
	if !checkVul(appvuls, "CVE-2018-1002105") {
		t.Errorf("vulnerability false negative: db=%s k8s=%s oc=%s", ver, k8s, oc)
	}
	os.RemoveAll(testTmpPath)
}
