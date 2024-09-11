////////////////////////////////////////////////////////////////////
/////// Read the results by runing as "go test -v"
/////////////////////////////////////////////////////////////////////

package secrets

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/share/utils"
)

// ////////////////////
func TestSampleFiles(t *testing.T) {
	path, _ := filepath.Abs("samples")
	// path, _ := filepath.Abs("/etc")

	/////
	var myFileSpec []FileType = []FileType{
		{Description: "test files", Expression: `(.*?)(yaml|key|txt)`},
	}

	////
	var myRules []Rule = []Rule{
		{Description: "AWS.Manager.ID", Expression: `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, Tags: []string{"key", "AWs"}},
	}

	_, _ = myRules, myFileSpec
	////// default
	var config Config = Config{
		//	RuleList:   DefaultRules, // myRules, DefaultSecretRules
		Whitelist:  myFileSpec, // myFileSpec, DefaultSecretFileType
		MiniWeight: 0.0001,     // Some other texts can dilute the weight result, so it is better to stay at a smaller weight
	}

	var envVars []byte
	if res, perms, err := FindSecretsByRootpath(path, envVars, config); err == nil {
		v := utils.NewSet()
		for _, r := range res {
			filename := filepath.Base(r.File)
			// design for one violation per sample file
			if v.Contains(filename) && filename != "Nothing.txt" {
				t.Errorf("\nExtra violation: %v\n\n", filename)
			}
			v.Add(filename)

			if !strings.HasPrefix(filename, r.RuleDesc) {
				t.Errorf("\nfalse-positive: %v [%v], %v\n", filename, r.RuleDesc, r.Text)
			}
			t.Logf("%v\n", r.RuleDesc)
		}
		for _, p := range perms {
			t.Logf("%v:%v\n", p.File, p.Evidence)
		}
		t.Logf("Result: %d\n", len(res))
	} else {
		t.Errorf("failed: %v\n", err)
	}
}
