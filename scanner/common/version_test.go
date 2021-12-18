package common

import (
	"testing"
)

func TestVersionCompare(t *testing.T) {
	// The first element should be less than the second
	cases := [][]string{
		[]string{"2.9.1-6.el7_2.2", "2.9.1-6.el7.4"},
		[]string{"4.18.0-193.19.1.el8", "4.18.0-193.19.1.el8_2"},
		[]string{"4.18.0-193.el8", "4.18.0-193.19.1.el8_2"},
		[]string{"4.18.0-193.19.1.el8", "4.18.0-193.19.1.el8_2"},
		[]string{"4.18.0.el8", "4.18.0.el8_2"},
		[]string{"1.6_rc1-r0", "1.6-r1"},
		[]string{"1.2.2_pre2-r0", "1.2.2-r0"},
		[]string{"2:svn28991.0-45.el7", "2:svn28991.1-45.el7"},
		[]string{"2:svn28991.0-45.el7", "3:svn28991.0-45.el7"},
	}

	for i, _ := range cases {
		c1, err := NewVersion(cases[i][0])
		if err != nil {
			t.Errorf("%d: %s - %s", i, c1, err)
		}
		c2, err := NewVersion(cases[i][1])
		if err != nil {
			t.Errorf("%d: %s - %s", i, c2, err)
		}
		if c1.Compare(c2) >= 0 {
			t.Errorf("%d: %s should be smaller than %s", i, c1, c2)
		}
	}
}

func TestVersion(t *testing.T) {
	cases := []string{
		"2:svn28991.0-45.el7",
	}
	for i, _ := range cases {
		_, err := NewVersion(cases[i])
		if err != nil {
			t.Errorf("%d: %s - %s", i, cases[i], err)
		}
	}
}
