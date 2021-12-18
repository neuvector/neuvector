package common

import (
	"time"
)

type NVDMetadata struct {
	Description      string `json:"description,omitempty"`
	CVSSv2           NVDmetadataCVSS
	CVSSv3           NVDmetadataCVSS
	VulnVersions     []NVDvulnerableVersion
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

type NVDvulnerableVersion struct {
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

type NVDmetadataCVSS struct {
	Vectors string
	Score   float64
}

// database format

type KeyVersion struct {
	Version    string
	UpdateTime string
	Keys       map[string]string
	Shas       map[string]string
}

type FeaShort struct {
	Name    string `json:"N"`
	Version string `json:"V"`
	MinVer  string `json:"MV"`
}

type VulShort struct {
	Name      string `json:"N"`
	Namespace string `json:"NS"`
	Fixin     []FeaShort
	CPEs      []string `json:"CPE"`
}

type FeaFull struct {
	Name      string `json:"N"`
	Namespace string `json:"NS"`
	Version   string `json:"V"`
	MinVer    string `json:"MV"`
	AddedBy   string `json:"A"`
}

type VulFull struct {
	Name        string                 `json:"N"`
	Namespace   string                 `json:"NS"`
	Description string                 `json:"D"`
	Link        string                 `json:"L"`
	Severity    string                 `json:"S"`
	Metadata    map[string]NVDMetadata `json:"M"`
	FixedBy     string                 `json:"FB"`
	FixedIn     []FeaFull              `json:"FI"`
	CPEs        []string               `json:"CPE,omitempty"`
	CVEs        []string               `json:"CVE,omitempty"`
	FeedRating  string                 `json:"RATE,omitempty"`
}

type AppModuleVersion struct {
	OpCode  string `json:"O"`
	Version string `json:"V"`
}

type AppModuleVul struct {
	VulName       string             `json:"VN"`
	ModuleName    string             `json:"MN"`
	Description   string             `json:"D"`
	Link          string             `json:"L"`
	Score         float64            `json:"SC"`
	Vectors       string             `json:"VV2"`
	ScoreV3       float64            `json:"SC3"`
	VectorsV3     string             `json:"VV3"`
	Severity      string             `json:"SE"`
	AffectedVer   []AppModuleVersion `json:"AV"`
	FixedVer      []AppModuleVersion `json:"FV"`
	UnaffectedVer []AppModuleVersion `json:"UV",omitempty`
	IssuedDate    time.Time          `json:"Issue"`
	LastModDate   time.Time          `json:"LastMod"`
	CVEs          []string           `json:"-"`
}

// ---

// UbuntuReleasesMapping translates Ubuntu code names to version numbers
var UbuntuReleasesMapping = map[string]string{
	"upstream":         "upstream",
	"precise":          "12.04",
	"precise/esm":      "12.04",
	"quantal":          "12.10",
	"raring":           "13.04",
	"trusty":           "14.04",
	"trusty/esm":       "14.04",
	"utopic":           "14.10",
	"vivid":            "15.04",
	"wily":             "15.10",
	"xenial":           "16.04",
	"esm-infra/xenial": "16.04",
	"yakkety":          "16.10",
	"zesty":            "17.04",
	"artful":           "17.10",
	"bionic":           "18.04",
	"cosmic":           "18.10",
	"disco":            "19.04",
	"eoan":             "19.10",
	"focal":            "20.04",
	"groovy":           "20.10",
	"hirsute":          "21.04",
	"impish":           "21.10",
}

var DebianReleasesMapping = map[string]string{
	// Code names
	"squeeze":  "6",
	"wheezy":   "7",
	"jessie":   "8",
	"stretch":  "9",
	"buster":   "10",
	"bullseye": "11",
	"sid":      "unstable",

	// Class names
	"oldoldstable": "7",
	"oldstable":    "8",
	"stable":       "9",
	"testing":      "10",
	"unstable":     "unstable",
}
