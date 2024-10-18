package utils

import (
	"fmt"
	"testing"
)

type versionCompareTestCase struct {
	versionA       string
	versionB       string
	expectedResult int
}

func (tc *versionCompareTestCase) FailureMessage() string {
	var expectationMessage string
	switch tc.expectedResult {
	case -1:
		expectationMessage = "an earlier version than"
	case 0:
		expectationMessage = "an equal version to"
	case 1:
		expectationMessage = "a later version than"
	}
	return fmt.Sprintf("%s should be considered %s %s", tc.versionA, expectationMessage, tc.versionB)
}

func TestVersionCompare(t *testing.T) {
	testCases := []versionCompareTestCase{
		{
			versionA:       "2.9.1-6.el7_2.2",
			versionB:       "2.9.1-6.el7.4",
			expectedResult: -1,
		},
		{
			versionA:       "4.18.0-193.19.1.el8",
			versionB:       "4.18.0-193.19.1.el8_2",
			expectedResult: -1,
		},
		{
			versionA:       "4.18.0-193.el8",
			versionB:       "4.18.0-193.19.1.el8_2",
			expectedResult: -1,
		},
		{
			versionA:       "4.18.0-193.19.1.el8",
			versionB:       "4.18.0-193.19.1.el8_2",
			expectedResult: -1,
		},
		{
			versionA:       "4.18.0.el8",
			versionB:       "4.18.0.el8_2",
			expectedResult: -1,
		},
		{
			versionA:       "1.6_rc1-r0",
			versionB:       "1.6-r1",
			expectedResult: -1,
		},
		{
			versionA:       "1.2.2_pre2-r0",
			versionB:       "1.2.2-r0",
			expectedResult: -1,
		},
		{
			versionA:       "2:svn28991.0-45.el7",
			versionB:       "2:svn28991.1-45.el7",
			expectedResult: -1,
		},
		{
			versionA:       "2:svn28991.0-45.el7",
			versionB:       "3:svn28991.0-45.el7",
			expectedResult: -1,
		},
		{
			versionA:       "1.2.2-r0",
			versionB:       "1.2.2-r0",
			expectedResult: 0,
		},
		{
			versionA:       "1.2.3",
			versionB:       "1.2.2",
			expectedResult: 1,
		},
		// Since our version type implementation is based on debian versions, and not
		// exactly the semantic version protocol, "1.2.2-r0" is actually a later
		// version than "1.2.2" since the "-r0" component in a debian version implies
		// that this is a revision of a package for the debian environment
		// (in semantic versioning, the hyphen actually denotes a prerelease tag)
		{
			versionA:       "1.2.2-r0",
			versionB:       "1.2.2",
			expectedResult: 1,
		},
		{
			versionA:       "7.2_p2-r0",
			versionB:       "7.2_p2-r0",
			expectedResult: 0,
		},
		{
			versionA:       "7.3",
			versionB:       "7.2_p2-r0",
			expectedResult: 1,
		},
		{
			versionA:       "4.20.0",
			versionB:       "4.18.0.el8_2",
			expectedResult: 1,
		},
	}

	for i, testCase := range testCases {
		c1, err := NewVersion(testCase.versionA)
		if err != nil {
			t.Errorf("%d: %s - %s", i, c1, err)
		}
		c2, err := NewVersion(testCase.versionB)
		if err != nil {
			t.Errorf("%d: %s - %s", i, c2, err)
		}
		if got := c1.Compare(c2); got != testCase.expectedResult {
			t.Errorf(
				"failed version compare test case %d, got %d expected %d: %s",
				i,
				got,
				testCase.expectedResult,
				testCase.FailureMessage(),
			)
		}
	}
}

func TestVersion(t *testing.T) {
	cases := []string{
		"2:svn28991.0-45.el7",
	}
	for i := range cases {
		_, err := NewVersion(cases[i])
		if err != nil {
			t.Errorf("%d: %s - %s", i, cases[i], err)
		}
	}
}
