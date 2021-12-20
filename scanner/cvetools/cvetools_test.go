package cvetools

import (
	"github.com/neuvector/neuvector/share/scan"
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
