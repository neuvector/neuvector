package cvetools

import (
	"testing"

	"github.com/neuvector/neuvector/scanner/common"
)

type versionTestCase struct {
	result  bool
	version string
	dbVer   []common.AppModuleVersion
}

func TestAffectedVersion(t *testing.T) {
	cases := []versionTestCase{
		versionTestCase{result: false, version: "1.2.3", dbVer: []common.AppModuleVersion{}},
		versionTestCase{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "lt", Version: "1.2.4"}}},
		versionTestCase{result: false, version: "1.2.4", dbVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "lt", Version: "1.2.4"}}},
		versionTestCase{result: true, version: "4.0.1", dbVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "", Version: "4.0.1"}}},
		versionTestCase{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"gt", "1.2.0"}}},
		versionTestCase{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"gt", "1.2.0"}, {"orlt", "1.3.5"}}},
		versionTestCase{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"gt", "1.2.0"}, {"lt", "1.3.5"}}},
		versionTestCase{result: false, version: "1.3.4", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"lt", "1.3.5"}}},
		versionTestCase{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"orlt", "1.3.5"}}},
		versionTestCase{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"orlt", "1.3.5"}, {"gteq", "1.3.4"}}},
		versionTestCase{result: false, version: "1.3.3", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"orlt", "1.3.5"}, {"gteq", "1.3.4"}}},
		versionTestCase{result: true, version: "1.1.1", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}}},
		versionTestCase{result: false, version: "1.1.1", dbVer: []common.AppModuleVersion{{"lt", "1.2.4,1.2"}}},
		versionTestCase{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"lt", "1.3.7"}, {"gt", "1.3.5"}}},
		versionTestCase{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{"lt", "1.2.4"}, {"orlt", "1.3.7"}, {"gt", "1.3.5"}}},
		versionTestCase{result: false, version: "2.9.1-6.el7.4", dbVer: []common.AppModuleVersion{{"lt", "2.9.1-6.el7_2.2"}}},
		versionTestCase{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{"lt", "4.18.0-193.19.1.el8"}}},
		versionTestCase{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{"lt", "4.18.0-193.el8"}}},
		versionTestCase{result: true, version: "4.18.0-193.19.1.el8", dbVer: []common.AppModuleVersion{{"lt", "4.18.0-193.19.1.el8_2"}}},
		versionTestCase{result: false, version: "4.18.0.el8_2", dbVer: []common.AppModuleVersion{{"lt", "4.18.0.el8"}}},
		versionTestCase{result: false, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{"lt", "5.2.4.3,5.2"}, {"orlt", "6.0.3.1"}}},
		versionTestCase{result: true, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{"gteq", "5.2.4.3,5.2"}, {"orgteq", "6.0.3.1"}}},
		versionTestCase{result: false, version: "5.0.11", dbVer: []common.AppModuleVersion{{"gteq", "5.0"}, {"lteq", "5.0.8"}, {"orgteq", "2.1"}, {"lteq", "2.1.28"}, {"orgteq", "3.1"}, {"lteq", "3.1.17"}, {"orgteq", "7.0"}, {"lt", "7.0.7"}, {"orgteq", "7.1"}, {"lt", "7.1.4"}}},
	}

	for _, c := range cases {
		v, _ := common.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, affected %v => %v", c.version, c.dbVer, ret)
		}
	}
}

func TestFixedVersion(t *testing.T) {
	cases := []versionTestCase{
		versionTestCase{result: true, version: "4.0.2", dbVer: []common.AppModuleVersion{{"gteq", "2.12.5"}, {"lt", "3.0.0"}, {"orgteq", "3.7.2"}, {"lt", "4.0.0"}, {"orgteq", "4.0.0.beta8"}}},
	}
	for _, c := range cases {
		v, _ := common.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, fixed %v => %v", c.version, c.dbVer, ret)
		}
	}
}
