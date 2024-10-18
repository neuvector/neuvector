package utils

import (
	"database/sql/driver"
	"encoding/json"
	"errors"

	// "fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Version represents a package version
type Version struct {
	epoch    int
	version  string
	revision string
	el_ver   string // Redhat Enterprise Linux
}

var (
	// MinVersion is a special package version which is always sorted first
	MinVersion = Version{version: "#MINV#"}
	// MaxVersion is a special package version which is always sorted last
	MaxVersion = Version{version: "#MAXV#"}

	versionAllowedSymbols  = []rune{'.', '-', '+', '~', ':', '_'}
	revisionAllowedSymbols = []rune{'.', '+', '~', '_'}
)

// NewVersion function parses a string into a Version struct which can be compared
//
// The implementation is based on http://man.he.net/man5/deb-version
// on https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
//
// It uses the dpkg-1.17.25's algorithm  (lib/parsehelp.c)
func NewVersion(str string) (Version, error) {
	var version Version

	// Trim leading and trailing space
	str = strings.TrimSpace(str)

	if len(str) == 0 {
		return Version{}, errors.New("Version string is empty")
	}

	// Max/Min versions
	if str == MaxVersion.String() {
		return MaxVersion, nil
	}
	if str == MinVersion.String() {
		return MinVersion, nil
	}

	// Find epoch
	sepepoch := strings.Index(str, ":")
	if sepepoch > -1 {
		intepoch, err := strconv.Atoi(str[:sepepoch])
		if err == nil {
			version.epoch = intepoch
		} else {
			return Version{}, errors.New("epoch in version is not a number")
		}
		if intepoch < 0 {
			return Version{}, errors.New("epoch in version is negative")
		}
	} else {
		version.epoch = 0
	}

	// Find version / revision / el_ver
	seprevision := strings.LastIndex(str, "-")
	if seprevision > -1 {
		version.version = str[sepepoch+1 : seprevision]
		version.revision = str[seprevision+1:]

		el := strings.LastIndex(version.revision, ".el")
		if el > -1 {
			rev := version.revision
			version.revision = rev[:el]
			version.el_ver = rev[el+1:]
		}
	} else {
		version.version = str[sepepoch+1:]
		version.revision = ""

		el := strings.LastIndex(version.version, ".el")
		if el > -1 {
			rev := version.version
			version.version = rev[:el]
			version.el_ver = rev[el+1:]
		}
	}
	// Verify format
	if len(version.version) == 0 {
		return Version{}, errors.New("No version")
	}

	// to support version string such as, 2:svn28991.0-45.el7
	/*
		if !unicode.IsDigit(rune(version.version[0])) {
			return Version{}, errors.New("version does not start with digit")
		}
	*/

	for i := 0; i < len(version.version); i = i + 1 {
		r := rune(version.version[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !containsRune(versionAllowedSymbols, r) {
			return Version{}, errors.New("invalid character in version")
		}
	}

	for i := 0; i < len(version.revision); i = i + 1 {
		r := rune(version.revision[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !containsRune(revisionAllowedSymbols, r) {
			return Version{}, errors.New("invalid character in revision")
		}
	}

	for i := 0; i < len(version.el_ver); i = i + 1 {
		r := rune(version.el_ver[i])
		if !unicode.IsDigit(r) && !unicode.IsLetter(r) && !containsRune(revisionAllowedSymbols, r) {
			return Version{}, errors.New("invalid character in revision")
		}
	}

	return version, nil
}

// NewVersionUnsafe is just a wrapper around NewVersion that ignore potentiel
// parsing error. Useful for test purposes
func NewVersionUnsafe(str string) Version {
	v, _ := NewVersion(str)
	return v
}

// Compare function compares two Debian-like package version
//
// The implementation is based on http://man.he.net/man5/deb-version
// on https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
//
// It uses the dpkg-1.17.25's algorithm  (lib/version.c)
func (a Version) Compare(b Version) int {
	// Quick check
	if a == b {
		return 0
	}

	// Max/Min comparison
	if a == MinVersion || b == MaxVersion {
		return -1
	}
	if b == MinVersion || a == MaxVersion {
		return 1
	}

	// Compare epochs
	if a.epoch > b.epoch {
		return 1
	}
	if a.epoch < b.epoch {
		return -1
	}

	// Compare version
	rc := verrevcmp(a.version, b.version)
	if rc != 0 {
		return signum(rc)
	}

	// Compare revision
	rc = verrevcmp(a.revision, b.revision)
	if rc != 0 {
		return signum(rc)
	}

	// Compare el_ver
	return signum(verrevcmp(a.el_ver, b.el_ver))
}

// CompareWithoutEpoch uses same comparison logic as Compare but doesn't compare epoch.
func (a Version) CompareWithoutEpoch(b Version) int {
	// Quick check
	if a == b {
		return 0
	}

	// Max/Min comparison
	if a == MinVersion || b == MaxVersion {
		return -1
	}
	if b == MinVersion || a == MaxVersion {
		return 1
	}

	// Compare version
	rc := verrevcmp(a.version, b.version)
	if rc != 0 {
		return signum(rc)
	}

	// Compare revision
	rc = verrevcmp(a.revision, b.revision)
	if rc != 0 {
		return signum(rc)
	}

	// Compare el_ver
	return signum(verrevcmp(a.el_ver, b.el_ver))
}

// String returns the string representation of a Version
func (v Version) String() (s string) {
	if v.epoch != 0 {
		s = strconv.Itoa(v.epoch) + ":"
	}
	s += v.version
	if v.revision != "" {
		s += "-" + v.revision
	}
	if v.el_ver != "" {
		s += "." + v.el_ver
	}
	return
}

func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *Version) UnmarshalJSON(b []byte) (err error) {
	var str string
	if err = json.Unmarshal(b, &str); err == nil {
		vp := NewVersionUnsafe(str)
		*v = vp
	}
	return
}

func (v *Version) Scan(value interface{}) (err error) {
	val, ok := value.([]byte)
	if !ok {
		return errors.New("could not scan a Version from a non-string input")
	}
	*v, err = NewVersion(string(val))
	return
}

func (v *Version) Value() (driver.Value, error) {
	return v.String(), nil
}

var rcRegex = regexp.MustCompile("(rc[0-9]|pre[0-9])")

func verrevcmp(t1, t2 string) int {
	// fmt.Printf("t1=%v t2=%v\n", t1, t2)
	t1, rt1 := nextRune(t1)
	t2, rt2 := nextRune(t2)

	for rt1 != nil || rt2 != nil {
		firstDiff := 0

		for (rt1 != nil && !unicode.IsDigit(*rt1)) || (rt2 != nil && !unicode.IsDigit(*rt2)) {
			ac := 0
			bc := 0
			if rt1 != nil {
				ac = order(*rt1)
				// fmt.Printf("rt1=%v ac=%v\n", *rt1, ac)
			}
			if rt2 != nil {
				bc = order(*rt2)
				// fmt.Printf("rt2=%v bc=%v\n", *rt2, bc)
			}

			// NVSHAS-4684, 2.9.1-6.el7.4 > 2.9.1-6.el7_2.2
			if ac == 302 && bc == 351 { // ac == '.' && bc == '_'
				return 1
			} else if ac == 351 && bc == 302 {
				return -1
			}

			// fmt.Printf("ac=%v bc=%v t1=%s t2=%s\n", ac, bc, t1, t2)
			if ac != bc {
				// NVSHAS-4818, 1.6_rc1-r0 < 1.6-r1
				if ac > bc && bc == 0 && rcRegex.MatchString(t1) {
					return -1
				}
				if ac < bc && ac == 0 && rcRegex.MatchString(t2) {
					return 1
				}

				return ac - bc
			}

			t1, rt1 = nextRune(t1)
			t2, rt2 = nextRune(t2)
		}
		for rt1 != nil && *rt1 == '0' {
			t1, rt1 = nextRune(t1)
		}
		for rt2 != nil && *rt2 == '0' {
			t2, rt2 = nextRune(t2)
		}
		for rt1 != nil && unicode.IsDigit(*rt1) && rt2 != nil && unicode.IsDigit(*rt2) {
			if firstDiff == 0 {
				firstDiff = int(*rt1) - int(*rt2)
			}
			t1, rt1 = nextRune(t1)
			t2, rt2 = nextRune(t2)
		}
		if rt1 != nil && unicode.IsDigit(*rt1) {
			return 1
		}
		if rt2 != nil && unicode.IsDigit(*rt2) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}

	return 0
}

// order compares runes using a modified ASCII table
// so that letters are sorted earlier than non-letters
// and so that tildes sorts before anything
func order(r rune) int {
	if unicode.IsDigit(r) {
		return 0
	}

	if unicode.IsLetter(r) {
		return int(r)
	}

	if r == '~' {
		return -1
	}

	return int(r) + 256
}

func nextRune(str string) (string, *rune) {
	if len(str) >= 1 {
		r := rune(str[0])
		return str[1:], &r
	}
	return str, nil
}

func containsRune(s []rune, e rune) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func signum(a int) int {
	switch {
	case a < 0:
		return -1
	case a > 0:
		return +1
	}

	return 0
}
