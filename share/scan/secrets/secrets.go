package secrets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

// FileType is a file spefification
type FileType struct {
	Description string
	Expression  string
	Regex       *regexp.Regexp
	MinEntropy  float64
}

// Entropy represents an entropy range
type Entropy struct {
	Group int // index of capturing groups, 0: all
	Min   float64
	Max   float64 // 5.95 for key[56]1..0A..Z..az
}

// Rule is used in the Config struct as an array of Rules and is iterated
// over during an audit. Each rule will be checked.
type Rule struct {
	Description string
	Expression  string
	ExprFName   string
	ExprFPath   string
	Regex       *regexp.Regexp
	FNameRegex  *regexp.Regexp
	FPathRegex  *regexp.Regexp
	Tags        []string
	Entropies   []Entropy
	Suggestion  string
}

// Config is a configuration is a composite struct of RuleList and file lists
type Config struct {
	RuleList    []Rule
	Whitelist   []FileType
	Blacklist   []FileType // most common
	SkipFolder  []FileType //
	MaxFileSize int        // default: 0 as 4kb, -1 as any size
	MiniWeight  float64    // minimum portion of a secret file, excluding x.509, <= 0.0: no minimum
	TimeoutSec  uint       // in seconds
}

// TBD: suggestion examples, needs more specific recommdation on the exposed secrets
const (
	msgCloak       = "Please cloak your password and secret key"
	msgRemove      = "Please remove the file if it is not necessary"
	msgReferVender = "Please refer the API pages of your vender to reduce the risk"
)

// DefaultRules defines a default rule set
var DefaultRules []Rule = []Rule{
	// Textual Encodings of PKIX, PKCS, and CMS Structures: https://tools.ietf.org/html/rfc7468
	{Description: "Private.Key",
		Expression: `^-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH|SSH2) )?PRIVATE KEY( BLOCK)?-----`, Tags: []string{share.SecretPrivateKey, "GeneralPrivateKey"},
		Suggestion: msgRemove},
	{Description: "Private.Key",
		Expression: `^PuTTY-User-Key-File-2:`, Tags: []string{share.SecretPrivateKey, "PuttyPrivateKey"},
		Suggestion: msgRemove},
	{Description: "XML.Signature.Private.Key",
		Expression: `(?m)^<RSAKeyValue>`, Tags: []string{share.SecretPrivateKey, "XmlPrivateKey"},
		Suggestion: msgRemove},
	//	{Description: "Certificate",
	//		Expression: `^-----BEGIN (CERTIFICATE|CMS|PKCS7|X509 CRL)-----`, Tags: []string{share.SecretX509, "Certificate"},
	//		Suggestion: msgRemove},
	//	{Description: "Public.Key",
	//		Expression: `^-----BEGIN PUBLIC KEY-----`, Tags: []string{share.SecretX509, "PublicKey"},
	//		Suggestion: msgRemove},
	//	{Description: "Public.Key",
	//		Expression: `^ssh-rsa`, Tags: []string{share.SecretX509, "PublicKey"},
	//		Suggestion: msgRemove},

	// Amazon: https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
	// AWS IAM: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
	{Description: "AWS.Manager.ID",
		Expression: `(?m)[\s|"|'|=|:]+(A3T[A-Z0-9]|ACCA|AKIA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)([A-Z0-9]{16})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "AWs"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 2, Min: 3.375, Max: 6.0}}},
	// TBD: Rule{ Description:"AWS Secret Key",
	//	Expression: `(?i)aws(.{0,20})?(?-i)[0-9a-zA-Z\/+]{40}`, Tags:[]string{share.SecretRegular, "AWS"},
	//	Suggestion: msgReferVender},
	{Description: "AWS.MWS.Key",
		Expression: `(?m)[\s|"|'|=|:]+amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\s|"|')`, Tags: []string{share.SecretRegular, "AWS", "MWS"},
		Suggestion: msgReferVender},

	// Facebook: https://developers.facebook.com/docs/facebook-login/access-tokens/
	// API calls
	{Description: "Facebook.Client.Secret",
		Expression: `(?im)(facebook|fb)\S{0,32}access_token(.{0,128})client_secret=(?-i)([0-9a-f]{32}\b)`, Tags: []string{share.SecretProgram, "Facebook"},
		Suggestion: msgReferVender},
	{Description: "Facebook.Endpoint.Secret",
		Expression: `(?im)(facebook|fb)\S{0,32}&access_token=([0-9a-f]{32}\b)`, Tags: []string{share.SecretProgram, "Facebook"},
		Suggestion: msgReferVender},
	{Description: "Facebook.App.Secret",
		Expression: `(?im)^\s*\w*(facebook|fb)\S*\s*[:=]+\s*['"]?([0-9a-f]{32})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Facebook"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 2, Min: 3.6, Max: 6.0}}},

	// Facebook SDK: https://github.com/facebook/facebook-nodejs-business-sdk, https://github.com/facebook/facebook-python-business-sdk
	//{	Description:"Facebook SDK access token",
	//	Expression: `(?m)\sFacebookAdsApi.init\(`, ExprFName: `.*\.(js|py)`, Tags:[]string{share.SecretProgram, "Facebook"},
	//	Suggestion: msgReferVender},

	// Twitter: https://developer.twitter.com/en/docs/basics/authentication/oauth-2-0/
	// strict: it should match another string = "grant_type=client_credentials"
	//{	Description:"Twitter Oath2 Secret",
	//	Expression: `(?im)\s(https:\/\/api.twitter.com\/oauth2\/token)`, Tags:[]string{share.SecretProgram, "Twitter"},
	//	Suggestion: msgReferVender},

	// it guesses the secret variables ....
	{Description: "Twitter.Client.ID",
		Expression: `(?im)^\s*\w*twitter\S*\s*[:=]+\s*['"]?([0-9a-z]{18,25})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Twitter"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 3.75, Max: 6.0}}},
	{Description: "Twitter.Secret.Key",
		Expression: `(?im)^\s*\w*twitter\S*\s*[:=]+\s*['"]?([0-9a-z]{35,44})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Twitter"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 4.0, Max: 6.0}}},

	// Github : it guesses the secret variables ....
	{Description: "Github.Secret",
		Expression: `(?im)^\s*\w*github\S*\s*[:=]+\s*['"]?([0-9a-z]{35,40})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Github"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 4.0, Max: 6.0}}},

	// Paypal Braintree: Python, PHP5, NodeJS SDKs: https://articles.braintreepayments.com/control-panel/important-gateway-credentials
	//{	Description:"PayPal Braintree SDK Gateway",
	//	Expression: `(?m)\s(braintree.BraintreeGateway\(|new Braintree\\Gateway|braintree.connect\()`, ExprFName: `.*\.(js|py|php)`, Tags:[]string{share.SecretProgram, "Paypal"},
	//	Suggestion: msgReferVender},

	// TBD
	//{	Description:"PayPal Braintree Tokens",
	//	Expression: `(?m)access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, Tags:[]string{share.SecretProgram, "Paypal"},
	//	Suggestion: msgReferVender},

	// Square: product, https://developer.squareup.com/apps/
	{Description: "Square.Product.ID",
		Expression: `(?m)[\s|"|'|=|:]+sq0(at|id)p-[0-9A-Za-z\-_]{22}(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "square"},
		Suggestion: msgReferVender},
	{Description: "Square.OAuth.Secret",
		Expression: `(?m)[\s|"|'|=|:]+sq0csp-[0-9A-Za-z]{10}-[0-9A-Za-z]{6}_[0-9A-Za-z]{25}(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "square"},
		Suggestion: msgReferVender},

	// Stripe: https://dashboard.stripe.com/test/apikeys
	{Description: "Stripe.Access.Key",
		Expression: `(?m)[\s|"|'|=|:]+(?:r|s|p)k_(live|test)_([0-9a-zA-Z]{24,34})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Stripe"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 2, Min: 4.0, Max: 6.0}}},

	// Slack: https://api.slack.com/web
	{Description: "Slack.API.tokens",
		Expression: `(?m)[\s|"|'|=|:]+xox[baprs]-[0-9a-zA-Z]{4,21}-[0-9a-zA-Z]{4,21}(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Slack"},
		Suggestion: msgReferVender},
	{Description: "Slack Webhook",
		Expression: `(?m)\shttps://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`, Tags: []string{share.SecretProgram, "slack"},
		Suggestion: msgReferVender},

	// Linkedin: https://www.linkedin.com/developers/
	{Description: "LinkedIn.Client.ID",
		Expression: `(?im)^\s*\w*linkedin\S*\s*[:=]+\s*['"]?(?-i)([0-9a-z]{14})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "LinkedIn"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 3.5, Max: 6.0}}},
	{Description: "LinkedIn.Secret.Key",
		Expression: `(?im)^\s*\w*linkedin\S*\s*[:=]+\s*['"]?([0-9a-zA-Z]{16})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "LinkedIn"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 3.75, Max: 6.0}}},

	//TBD: API calls
	//{	Description:"LinkedIn OAuth secret",
	//	Expression: `(?im)https://www.linkedin.com/oauth/v2/accessToken`, Tags:[]string{share.SecretProgram, "LinkedIn"},
	//	Suggestion: msgReferVender},
	//{	Description:"LinkedIn API token",
	//	Expression: `(?im)https://api.linkedin.com/v2/me`, Tags:[]string{share.SecretProgram, "LinkedIn"},
	//	Suggestion: msgReferVender},
	//{	Description:"LinkedIn OAuth secret",

	// Below: have not been tested
	// Google: TBD
	{Description: "Google.API.Key",
		Expression: `(?m)[\s|"|'|=|:]+AIza([0-9A-Za-z\\-_]{35})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Google"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 4.0, Max: 6.0}}},
	//{	Description:"Google (GCP) Service Account",
	//	Expression: `(?m)\s"type": "service_account"`, Tags:[]string{share.SecretProgram, "Google"},
	//	Suggestion: msgReferVender},

	// Misc:
	{Description: "SendGrid.API.Key",
		Expression: `(?m)\sSG\.[\w_]{16,32}\.[\w_]{16,64}(?:\s|"|')`, Tags: []string{share.SecretRegular, "SendGrid"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 0, Min: 4.0, Max: 6.0}}},
	{Description: "Twilio.API.Key",
		Expression: `(?im)^\s*\w*twilio\S*\s*[:=]+\s*['"]?(SK[0-9a-f]{32})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "twilio"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 4.0, Max: 6.0}}},
	{Description: "Heroku.API.Key",
		Expression: `(?im)^\s*\w*wheroku\S*\s*[:=]+\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\s|$|"|)'`, Tags: []string{share.SecretRegular, "Heroku"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 1, Min: 4.0, Max: 6.0}}},
	{Description: "MailChimp.API.Key",
		Expression: `(?im)^\s*\w*(mailchimp|mc)\S*\s*[:=]+\s*['"]?([0-9a-f]{32}-us[0-9]{1,2})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Mailchimp"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 2, Min: 4.0, Max: 6.0}}},
	{Description: "Mailgun.API.Key",
		Expression: `(?im)^\s*\w*(mailgun|mg)\S*\s*[:=]+\s*['"]?(key-[0-9a-z]{32})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "Mailgun"},
		Suggestion: msgReferVender,
		Entropies:  []Entropy{{Group: 2, Min: 4.0, Max: 6.0}}},

	// Generic: many false-positive cases
	// Credential: one of leading text, at least 8 charactres[special characters] and no space is allowed in the secret, up to 120
	// to reduce the false-positive: the secret context is guarded between " or '
	// ^: at beginning of text or line (m=true), does not work with json files
	// ignore . in the secret, it could be a structure pointer for a program
	{Description: "Credential",
		Expression: `(?im)^\s*\w*(passwd|api_key|apikey|password|secret)\S*\s*[:=]+\s*['"]?([0-9a-z-_.\|!"$%&\/\(\)\?\^\'\\\+\-\*@~\[\];]{20,120})(?:\s|$|"|')`, Tags: []string{share.SecretRegular, "API", "generic"},
		Suggestion: msgCloak,
		Entropies:  []Entropy{{Group: 2, Min: 4.00, Max: 6.0}}},

	// Only on certain files, remove repo_token
	{Description: "Password.in.YML",
		Expression: `(?i)(password|passwd|api_token)\S{0,32}\s*:\s*(?-i)([0-9a-zA-Z\/+]{16,40}\b)`, ExprFName: `.*\.ya?ml`, Tags: []string{share.SecretProgram, "yaml", "yml"},
		Suggestion: msgReferVender},

	// Only on certain files/paths
	//	{	Description:"Password in Property",
	//		Expression: `(?i)(password|token)\S{0,32}\s*:\s*[:]\s*?(?-i)([0-9a-zA-Z\/+]{4,40}\b)`, ExprFName: `.*\.properties`,	ExprFPath: `config(guration)?`,	Tags: []string{share.SecretProgram, "yaml", "yml"},
	//		Suggestion: msgReferVender},
}

// DefaultFileType is for default profile
var DefaultFileType []FileType = []FileType{
	{Description: "ALL", Expression: `.*`},
}

// buildConfig(): build the necessary filters
func buildConfig(config Config) (Config, error) {
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 4 * 1024
	}

	if config.RuleList == nil {
		config.RuleList = DefaultRules
	}

	if config.Blacklist == nil {
		// 2nd-layer screen: skip common binary extension (program-able from input configuration)
		config.Blacklist = []FileType{
			{Description: "common binary files", Expression: `\S[.](jpg|png|gif|mov|avi|mpeg|pdf|mp4|mp3|svg|tar|gz|zip)$`},
			{Description: "common program files", Expression: `\S[.](js|jar|java|rb|rbw|py|pyc|md|cpp|cxx|html|htm|scala|pl)$`},
			{Description: "auto-generated files", Expression: `[0-9a-zA-Z_-]{32,64}`, MinEntropy: 3.0},
		}
	}

	if config.SkipFolder == nil {
		// skip common unused flders during production: test/unittest/..... for a prject following a common practice
		// for example, node js: https://gist.github.com/tracker1/59f2c13044315f88bee9
		config.SkipFolder = []FileType{
			{Description: "nodeJS project", Expression: `\/node_modules\/\S+\/(test|unit|integration|env|testing)$`},
			//	FileType{Description:"packages info", Expression: `\/var\/lib\/dpkg\/`},
		}
	}

	///// blacklist: exclude files from scan
	for i, file := range config.Blacklist {
		re, err := regexp.Compile(file.Expression)
		if err != nil {
			log.WithFields(log.Fields{"file": file, "err": err}).Error()
			return config, fmt.Errorf("err: build blacklist: %v[%v]", err, file)
		}
		config.Blacklist[i].Regex = re
	}

	///// whitelist: only scan fulfilled files
	for i, file := range config.Whitelist {
		re, err := regexp.Compile(file.Expression)
		if err != nil {
			return config, fmt.Errorf("err: build whitelist: %v[%v]", err, file)
		}
		config.Whitelist[i].Regex = re
	}

	///// SkipFolder: skipped folders
	for i, file := range config.SkipFolder {
		re, err := regexp.Compile(file.Expression)
		if err != nil {
			return config, fmt.Errorf("err: build SkipFolder: %v[%v]", err, file)
		}
		config.SkipFolder[i].Regex = re
	}

	/////
	for i, rule := range config.RuleList {
		re, err := regexp.Compile(rule.Expression)
		if err != nil {
			log.WithFields(log.Fields{"rule": rule.Expression, "desc": rule.Description}).Error()
			return config, fmt.Errorf("err: build rule: %v[%v]", err, rule)
		}
		config.RuleList[i].Regex = re

		if rule.ExprFName != "" {
			reName, err := regexp.Compile(rule.ExprFName)
			if err != nil {
				return config, fmt.Errorf("err: build file name : %v[%v]", err, rule)
			}
			config.RuleList[i].FNameRegex = reName
		}

		if rule.ExprFPath != "" {
			rePath, err := regexp.Compile(rule.ExprFPath)
			if err != nil {
				return config, fmt.Errorf("err: build file path: %v[%v]", err, rule)
			}
			config.RuleList[i].FPathRegex = rePath
		}
	}
	return config, nil
}

// Purpose of Shannon entropy is to verify the irreversibility of a found "cipher-ed" secret key.
// If the repeating chars are too much, the entropy increases and not likely a real key (not cipher correctly).
// The cipher-key should fulfill the low entropy requirement in the information theory
func trippedEntropy(secretText string, rule Rule) bool {
	groups := rule.Regex.FindStringSubmatch(secretText)
	log.WithFields(log.Fields{"text": secretText, "desc": rule.Description}).Trace()
	for _, e := range rule.Entropies {
		if len(groups) > e.Group {
			str := groups[e.Group]
			if strings.Contains(strings.ToLower(str), "example") {
				log.WithFields(log.Fields{"str": str}).Trace("Possible SDK examples")
				continue
			}

			entropy := shannonEntropy(str)
			log.WithFields(log.Fields{"entropy": entropy, "full-str": secretText}).Trace()
			if entropy >= e.Min && entropy <= e.Max {
				log.WithFields(log.Fields{"entropy": entropy, "str": str}).Trace("Good")
				return true
			}
		}
	}
	return false
}

// shannonEntropy: https://en.wiktionary.org/wiki/Shannon_entropy
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

func isValidRegexString(re *regexp.Regexp, str string) bool {
	if re == nil || re.String() == "" {
		return true
	}
	return re.FindString(str) != ""
}

func isSelectedFile(filename string, list []FileType) bool {
	if len(list) > 0 {
		for _, flt := range list {
			if isValidRegexString(flt.Regex, filename) {
				if flt.MinEntropy > 0.0 {
					length := len(filename)
					if length > 32 {
						length = 32 // check first 32 bytes only
					}
					entropy := shannonEntropy(filename[:length])
					if entropy < flt.MinEntropy {
						log.WithFields(log.Fields{"entropy": entropy, "file": filename}).Debug("SCRT")
						continue
					}
				}
				return true
			}
		}
	}
	return false
}

/*
func isBinaryCerticiate(reportPath, ext string) (*share.CLUSSecretLog, bool) {
	// base64: pem, crt, key, p7b, p7c
	// binary: der, pfx, p12
	// both: cer
	switch ext {
	case ".der":
	case ".pfx":
	case ".p12":
	case ".cer":
	default:
		return nil, false
	}

	// special cases
	seclog := &share.CLUSSecretLog{
		Type:       share.SecretX509,
		Text:       ext,
		Line:       ext,
		File:       reportPath,
		RuleDesc:   "Certificate (binary)",
		Suggestion: msgRemove,
	}
	return seclog, true
}
*/

// exclude comment lines from the original content
// #, <!, and {*
func activeContentLength(content []byte) int {
	count := 1 // avoid: divided-by-zero
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		pBytes := scanner.Bytes()
		if bytes.HasPrefix(pBytes, []byte("#")) ||
			bytes.HasPrefix(pBytes, []byte("<!")) || // less-likely: HTML
			bytes.HasPrefix(pBytes, []byte("{*")) { // less-likely: HTML template
			continue
		}
		count += len(scanner.Text())
	}
	return count
}

// inspectFileContents: provide a method to scan content in []byte format
// If the rule contains entropy checks then entropy will be checked first.
// Next, if the rule contains a regular expression then that will be checked.
func inspectFileContents(content []byte, path string, rule Rule) []share.CLUSSecretLog {
	res := make([]share.CLUSSecretLog, 0)
	locs := rule.Regex.FindAllIndex(content, -1)
	if len(locs) != 0 {
		for _, loc := range locs {
			start := loc[0]
			end := loc[1]
			for start != 0 && content[start] != '\n' {
				start = start - 1
			}
			if start != 0 {
				// skip newline
				start = start + 1
			}

			for end < len(content)-1 && content[end] != '\n' {
				end = end + 1
			}

			// stripped the last unnecessary tokens
			secretText := strings.TrimRight(string(content[loc[0]:loc[1]]), "'\"\n\t")
			// verifying key by its entropy of information theory
			if len(rule.Entropies) > 0 && !trippedEntropy(secretText, rule) {
				continue
			}

			secType := share.SecretRegular
			if rule.Tags != nil {
				secType = rule.Tags[0]
			}

			seclog := share.CLUSSecretLog{
				Type:       secType,
				Text:       secretText,
				Line:       string(content[start:end]),
				File:       path,
				RuleDesc:   rule.Description,
				Suggestion: rule.Suggestion,
			}

			res = append(res, seclog)
		}
	}
	return res
}

// InspectFile provides a method to scan files
func InspectFile(fullpath, reportPath string, config Config) ([]share.CLUSSecretLog, bool) {
	res := make([]share.CLUSSecretLog, 0)
	filename := filepath.Base(reportPath)
	dir := filepath.Dir(reportPath)
	ext := filepath.Ext(reportPath)

	// We want to check if there is a global check-list for this file
	// blacklist: ignore
	if isSelectedFile(filename, config.Blacklist) {
		return res, false
	}

	// whitelist: must include
	if len(config.Whitelist) > 0 && !isSelectedFile(filename, config.Whitelist) {
		return res, false
	}

	// load the content
	content, err := os.ReadFile(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"filepath": dir + "/" + filename}).Error()
		return res, false
	}

	// empty file or exceeding the maximum file size
	length := len(content)
	if length == 0 {
		return res, false
	}

	// 3rd-layer screen: skip large-sized non-text mime-type files
	mimeType := utils.GetFileContentType(content)
	// log.WithFields(log.Fields{"file": reportPath, "mimeType": mimeType}).Info()
	if (mimeType != "unknown-type") && (!strings.HasPrefix(mimeType, "text/")) {
		//	if result, yes := isBinaryCerticiate(reportPath, ext); yes { // x509
		//		res = append(res, *result)
		//	}
		return res, false
	}

	// it iterates over all the rules on the content of file
	qualified := false
	foundSecrets := make([]share.CLUSSecretLog, 0)
	for _, rule := range config.RuleList {
		if !isValidRegexString(rule.FNameRegex, filename) {
			continue
		}

		if !isValidRegexString(rule.FPathRegex, dir) {
			continue
		}

		results := inspectFileContents(content, reportPath, rule)
		foundSecrets = append(foundSecrets, results...)
		if len(results) > 0 && rule.Tags[0] == share.SecretPrivateKey {
			// x509 types, skip scanning to save some time
			break
		}
	}

	// Bypass json file on matching the minimum weight
	if ext == ".json" || config.MiniWeight <= 0.0 || config.MiniWeight >= 1.0 {
		qualified = true
	} else if len(foundSecrets) > 0 {
		// computing the minimum portion and does it qualify the mark?
		acc := 0
		for _, f := range foundSecrets {
			if f.Type == share.SecretPrivateKey || f.Type == share.SecretProgram { // x509 or program
				qualified = true
				break
			}
			acc += len(f.Line) // original line
		}

		if !qualified {
			counts := activeContentLength(content)         // len(content)
			mq := int(float64(counts) * config.MiniWeight) // minimum qualified count
			qualified = (acc >= mq)
			// log.WithFields(log.Fields{"file": reportPath, "acc": acc, "counts": counts, "weight" : float64(acc)/float64(counts)}).Debug()
			if !qualified {
				log.WithFields(log.Fields{"file": reportPath, "acc": acc, "weight": float64(acc) / float64(len(content))}).Debug()
			}
		}
	}

	if qualified {
		res = append(res, foundSecrets...)
	}
	return res, true
}

// var scanFileTotal int

// $EnvVariables provides a common function for recursive search
func FindSecretsByRootpath(rootPath string, envVars []byte, config Config) ([]share.CLUSSecretLog, []share.CLUSSetIdPermLog, error) {
	res := make([]share.CLUSSecretLog, 0)
	perm := make([]share.CLUSSetIdPermLog, 0)
	config, err := buildConfig(config)
	if err != nil {
		return res, perm, err
	}

	if len(envVars) > 0 {
		// log.WithFields(log.Fields{"envVars": string(envVars)}).Debug()
		// verify its environment variables
		// "$EnvVariables" because "$" is not allowed to be found in the filepath
		for _, rule := range config.RuleList {
			results := inspectFileContents(envVars, "$EnvVariables", rule)
			res = append(res, results...)
		}
	}

	// empty path
	if rootPath == "" {
		return res, perm, nil
	}

	rootPath = filepath.Clean(rootPath)
	rootPath += "/"

	// If it hits timeout, the enum function will return an incomplete results.
	// Thus, we can make partial protections here
	if config.TimeoutSec == 0 {
		config.TimeoutSec = 2 * 60
		//	log.WithFields(log.Fields{"timeout" : config.TimeoutSec}).Debug()
	}

	bTimeoutFlag := false
	errorCnt := 0
	go func() {
		time.Sleep(time.Duration(config.TimeoutSec) * time.Second)
		bTimeoutFlag = true
	}()

	start_time := time.Now()
	log.Debug("SCRT start")

	cnt := 0
	err = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if bTimeoutFlag {
			return errors.New("Timeout")
		}

		if err != nil {
			if strings.Contains(err.Error(), "no such file") ||
				strings.Contains(err.Error(), "permission denied") {
				errorCnt++
				if errorCnt < 1000 {
					return nil
				}
			}
			return err
		}

		inpath := path[len(rootPath)-1:]
		if info.IsDir() {
			// avoid mounted file systems on the hosts: /proc, /dev, /sys
			if utils.IsMountPoint(path) {
				return filepath.SkipDir
			}

			////
			if p, yes := hasChangeAccessPerm(inpath, info.Mode()); yes {
				// log.WithFields(log.Fields{"set-perm": p}).Debug()
				perm = append(perm, *p)
			}

			// Skipped folders
			if isSelectedFile(path, config.SkipFolder) {
				// log.WithFields(log.Fields{"path": path}).Info("SCRT skip folder")
				return filepath.SkipDir
			}
		} else {
			if utils.IsMountPoint(path) {
				return nil
			}

			////
			if p, yes := hasChangeAccessPerm(inpath, info.Mode()); yes {
				log.WithFields(log.Fields{"set-perm": perm}).Debug()
				perm = append(perm, *p)
			}

			// an unlikely file
			if info.Size() == 0 {
				return nil
			}

			if config.MaxFileSize > 0 && info.Size() > int64(config.MaxFileSize) {
				// log.WithFields(log.Fields{"length": length, "filepath": dir + "/" + filename}).Debug("File size too big")
				return nil
			}

			// 1st-layer screen: regular files and not ELF binaries
			if info.Mode().IsRegular() && !utils.IsExecutableLinkableFile(path) {
				results, scanned := InspectFile(path, inpath, config)
				if scanned {
					//	log.WithFields(log.Fields{"path": inpath, "found": len(results)}).Debug("SCRT")
					cnt++
					res = append(res, results...)
				}

			}
		}
		return nil
	})

	if err != nil {
		err = fmt.Errorf("Exited by error: path=%s, error=%s", rootPath, err)
	}
	//	scanFileTotal += cnt
	//	log.WithFields(log.Fields{"scanFileTotal": scanFileTotal}).Debug("SCRT")
	log.WithFields(log.Fields{"scan_cnt": cnt, "duration": time.Since(start_time), "perm_cnt": len(perm), "secret_cnt": len(res)}).Debug("SCRT done")
	return res, perm, err
}

// For registry scan
func FindSecretsByFilePathMap(fileMap map[string]string, envVars []byte, config Config) ([]share.CLUSSecretLog, []share.CLUSSetIdPermLog, error) {
	res := make([]share.CLUSSecretLog, 0)
	perm := make([]share.CLUSSetIdPermLog, 0)

	config, err := buildConfig(config)
	if err != nil {
		return res, perm, err
	}

	if len(envVars) > 0 {
		// log.WithFields(log.Fields{"envVars": string(envVars)}).Debug()
		// verify its environment variables
		// "$EnvVariables" because "$" is not allowed to be found in the filepath
		for _, rule := range config.RuleList {
			results := inspectFileContents(envVars, "$EnvVariables", rule)
			res = append(res, results...)
		}
	}

	// empty fileMap
	if len(fileMap) == 0 {
		return res, perm, nil
	}

	// If it hits timeout, the enum function will return an incomplete results.
	// Thus, we can make partial protections here
	if config.TimeoutSec == 0 {
		config.TimeoutSec = 10 * 60
		//	log.WithFields(log.Fields{"timeout" : config.TimeoutSec}).Debug()
	}

	bTimeoutFlag := false
	cnt := 0
	go func() {
		time.Sleep(time.Duration(config.TimeoutSec) * time.Second)
		bTimeoutFlag = true
	}()

	start_time := time.Now()
	log.Debug("SCRT start")
	for file, mpath := range fileMap {
		if bTimeoutFlag {
			break
		}

		if info, err := os.Stat(mpath); err == nil {
			if p, yes := hasChangeAccessPerm(file, info.Mode()); yes {
				// log.WithFields(log.Fields{"set-perm": p}).Debug()
				perm = append(perm, *p)
			}

			// an unlikely file
			if info.Size() == 0 {
				continue
			}

			if config.MaxFileSize > 0 && info.Size() > int64(config.MaxFileSize) {
				// log.WithFields(log.Fields{"length": length, "filepath": dir + "/" + filename}).Debug("File size too big")
				continue
			}

			// 1st-layer screen: regular files and not ELF binaries
			if info.Mode().IsRegular() && !utils.IsExecutableLinkableFile(mpath) {
				results, scanned := InspectFile(mpath, file, config)
				if scanned {
					//	log.WithFields(log.Fields{"path": mpath}).Debug("SCRT")
					cnt++
					res = append(res, results...)
				}
			}
		}
	}

	if bTimeoutFlag {
		err = fmt.Errorf("Timeout")
	}

	log.WithFields(log.Fields{"scan_cnt": cnt, "duration": time.Since(start_time), "perm_cnt": len(perm), "secret_cnt": len(res)}).Debug("SCRT done")
	return res, perm, err
}

func hasChangeAccessPerm(reportPath string, mode os.FileMode) (*share.CLUSSetIdPermLog, bool) {
	if mode&(os.ModeSetuid|os.ModeSetgid) == 0 {
		return nil, false // quick return
	}

	var cause string
	if mode&os.ModeSetuid != 0 {
		cause = "setuid "
	}

	if mode&os.ModeSetgid != 0 {
		cause += "setgid "
	}

	// log.WithFields(log.Fields{"reportPath": reportPath, "cause": cause}).Debug("SCRT: found")
	permlog := &share.CLUSSetIdPermLog{
		Types:    strings.TrimSpace(cause),
		File:     reportPath,
		Evidence: mode.String(),
	}
	return permlog, true
}
