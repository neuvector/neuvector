package cache

import (
	"testing"

	"github.com/neuvector/neuvector/share/utils"
)

func TestRancherOSCVE(t *testing.T) {
	cases := []struct {
		os     string
		kernel string
		cves   utils.Set
	}{
		{
			"1.4.1", "4.14.67",
			utils.NewSet("CVE-2018-17182", "CVE-2019-5736", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2018-12127", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479"),
		},
		{
			"1.5.0", "4.14.73",
			utils.NewSet("CVE-2019-5736", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2018-12127", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479"),
		},
		{
			"1.5.1", "4.14.73",
			utils.NewSet("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2018-12127", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479"),
		},
		{
			"1.5.2", "4.14.122",
			utils.NewSet("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479"),
		},
		{
			"1.5.4", "4.14.122",
			utils.NewSet(),
		},
	}

	for _, c := range cases {
		vulns := locateRancherOSCVE(c.os, c.kernel)
		cves := utils.NewSet()
		for _, v := range vulns {
			cves.Add(v.Name)
		}
		if !cves.Equal(c.cves) {
			t.Errorf("Expect: %v", c.cves)
			t.Errorf("Actual: %v", cves)
		}
	}
}
