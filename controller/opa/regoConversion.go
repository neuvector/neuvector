package opa

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

// RegoConversionOptions configures how Rego code is generated.
// This allows customization of package name and violation function generation
// without requiring string replacement in downstream code.
type RegoConversionOptions struct {
	PackageName            string
	GenerateKubewardenMode bool
}

// GeneratedRego represent the generated result would filled into the tmpl
type GeneratedRego struct {
	PackageName       string
	CustomChecks      []string
	ViolationMessages []string
	DebugMessages     []string
}

// DefaultRegoGenConfig returns the default configuration for NeuVector compatibility.
func DefaultRegoGenConfig(ruleID uint32) *RegoConversionOptions {
	return &RegoConversionOptions{
		PackageName:            fmt.Sprintf("neuvector_policy_%d", ruleID),
		GenerateKubewardenMode: false,
	}
}

func ConvertToRegoRule(rule *share.CLUSAdmissionRule) string {
	defaultOptions := DefaultRegoGenConfig(rule.ID)
	return ConvertToRegoRuleWithOptions(rule, defaultOptions)
}

func ConvertToRegoRuleWithOptions(rule *share.CLUSAdmissionRule, options *RegoConversionOptions) string {
	// has custom criteria
	hasCusomCriteria := false
	for _, c := range rule.Criteria {
		if c.Type == "saBindRiskyRole" {
			return ""
		}

		if c.Type != "" {
			hasCusomCriteria = true

			// normalize the path
			c.Path = strings.Replace(c.Path, ".0", "[_]", -1)
		}
	}

	if !hasCusomCriteria {
		return ""
	}

	log.WithFields(log.Fields{"rule": rule}).Debug("ConvertToRego")

	// print header
	packageName := fmt.Sprintf("package neuvector_policy_%d", rule.ID)

	if options == nil {
		options = DefaultRegoGenConfig(rule.ID)
	}
	regoStr, err := GenerateRegoCode(rule, options)
	if err != nil {
		return ""
	}
	policyUrl := formatPolicyUrl(rule.ID)

	success := AddPolicy(policyUrl, regoStr)
	log.WithFields(log.Fields{"policyUrl": policyUrl, "success": success}).Debug("Add Policy")

	if !success {
		// unable to add the rego
		// write another version of Rego of all comment to ensure it will success

		rego2 := []string{}
		rego2 = append(rego2, packageName)
		rego2 = append(rego2, "############# THIS IS DEBUG VERSION #############")

		items := strings.Split(regoStr, "\n")
		for _, v := range items {
			rego2 = append(rego2, "#! "+v)
		}

		AddPolicy(policyUrl, strings.Join(rego2, "\n"))

		log.WithFields(log.Fields{"policyUrl": policyUrl}).Error("Add Policy with all comments")
	}

	return regoStr
}

func GenerateRegoCode(rule *share.CLUSAdmissionRule, options *RegoConversionOptions) (string, error) {
	generatedRego := GeneratedRego{
		PackageName:       options.PackageName,
		CustomChecks:      []string{},
		ViolationMessages: []string{},
		DebugMessages:     []string{},
	}

	if options.GenerateKubewardenMode {
		generatedRego.ViolationMessages = GenerateSeparateDenyRules(rule)
	} else {
		generatedRego.CustomChecks = GenerateViolationFunction(rule)
	}

	// handling type=1 (general) individual criteria conversion
	for j, c := range rule.Criteria {
		log.WithFields(log.Fields{"criteria": c}).Debug("ConvertToRego-Criteria")

		if c.Type == "" {
			// if it's predefined then the type is empty string, we don't need to handle it
			continue
		}

		if c.Type == "customPath" {
			c_rego := convertGenericCriteria(j, c)
			generatedRego.CustomChecks = append(generatedRego.CustomChecks, c_rego...)
		}
	}

	generatedRego.DebugMessages = GenerateDebugMessages(rule)

	tmpl, err := template.New("regoTemplate").Parse(regoTemplate)
	if err != nil {
		return "", err
	}

	var regoStr strings.Builder
	err = tmpl.Execute(&regoStr, generatedRego)
	if err != nil {
		return "", err
	}

	return regoStr.String(), nil
}

func GenerateDebugMessages(rule *share.CLUSAdmissionRule) []string {
	rego := []string{}
	// generate troubleshooting code
	// handling type=1 (general) keep track each individual criteria result
	for j, c := range rule.Criteria {
		if c.Type == "customPath" {
			info := fmt.Sprintf("check [%s] with [%s] op", c.Path, c.Op)

			rego = append(rego, `
violationmsgs[msg]{
	request := _get_input("get")
`)
			rego = append(rego, "\t"+convertCriteriaFunctionCall(j, c, true))
			rego = append(rego, fmt.Sprintf(`	msg:="criteria_%d met. (%s)"`, j, info))
			rego = append(rego, "}")

			rego = append(rego, `
violationmsgs[msg]{
	request := _get_input("get")
`)
			rego = append(rego, "	not "+convertCriteriaFunctionCall(j, c, true))
			rego = append(rego, fmt.Sprintf(`	msg:="criteria_%d not met. (%s)"`, j, info))
			rego = append(rego, "}")
		}
	}
	return rego
}

// GenerateViolationFunction generates the main violation rule that combines all criteria.
// The generated function uses AND logic: all criteria must be met for a violation.
// Example output:
//
//	violation[result]{
//	    request := _get_input("get")
//	    criteria_0(request)    # check [path] with [op]
//	    criteria_1(request)    # check [path] with [op]
//	    result:={"message": "all criteria have been met"}
//	}
func GenerateViolationFunction(rule *share.CLUSAdmissionRule) []string {
	rego := []string{}
	mainFunc := `
violation[result]{
	request := _get_input("get")
	`

	rego = append(rego, mainFunc)

	for j, c := range rule.Criteria {
		if c.Type == "customPath" {
			rego = append(rego, "\t"+convertCriteriaFunctionCall(j, c, true))
		}
	}

	mainFunc = `
	result:={
		"message": "all criteria have been met"
	}
}
	`
	rego = append(rego, mainFunc)
	return rego
}

// GenerateSeparateDenyRules generates individual deny/violation rules for each criterion (OR logic).
// This is used when ViolationLogic is "or" - any criterion can trigger a violation.
// only for kubewarden mode
// Example output:
//
//	deny[msg] {
//	    request := _get_input("get")
//	    criteria_0(request)
//	    msg := "Denied by NeuVector rule #1001: [path op value]"
//	}
func GenerateSeparateDenyRules(rule *share.CLUSAdmissionRule) []string {
	rego := []string{}
	ruleName := "deny"

	for j, c := range rule.Criteria {
		if c.Type == "customPath" {
			msg := fmt.Sprintf("Denied by NeuVector rule #%d: [%s %s %s]",
				rule.ID, c.Path, c.Op, c.Value)

			rego = append(rego, fmt.Sprintf(`
%s[msg] {
	request := _get_input("get")
	criteria_%d(request)
	msg := %q
}
`, ruleName, j, msg))
		}
	}

	return rego
}

func formatPolicyUrl(ruleID uint32) string {
	return fmt.Sprintf("/v1/policies/policy/rule_%d", ruleID)
}

func convertCriteriaFunctionCall(idx int, c *share.CLUSAdmRuleCriterion, withComment bool) string {

	if withComment {
		return fmt.Sprintf("criteria_%d(request)    # check [%s] with [%s]", idx, c.Path, c.Op)
	}

	return fmt.Sprintf("criteria_%d(request)", idx)
}

func convertGenericCriteria(idx int, c *share.CLUSAdmRuleCriterion) []string {

	rego := []string{}

	functionName := convertCriteriaFunctionCall(idx, c, false)

	rego = append(rego, functionName)
	rego = append(rego, "{")

	rego = append(rego, fmt.Sprintf("	# custom criteria name = %v", c.Name))
	rego = append(rego, fmt.Sprintf("	# op = %v", c.Op))
	rego = append(rego, fmt.Sprintf("	# value = %v", c.Value))
	rego = append(rego, fmt.Sprintf("	# valueType = %v", c.ValueType))
	rego = append(rego, fmt.Sprintf("	# path(orig) = %v\n", c.Path))

	path := c.Path
	if strings.HasPrefix(c.Path, "item.") {
		path = "request" + c.Path[4:]
	}

	if strings.LastIndex(path, ".") == -1 {
		rego = append(rego, fmt.Sprintf("	# Invalid path = %v\n", path))
		return rego
	}

	// all ValueType (key, string, number, boolean) has "exist" and "notExist"
	if c.Op == "exist" {
		upPath, key := splitPathKey(path)
		rego = append(rego, addSidecarContainerCheck(path)...)
		upPath = replacePerContainerPath(upPath)

		rego = append(rego, fmt.Sprintf("	has_key(%s, %q)", upPath, strings.TrimSuffix(key, "[_]")))
		rego = append(rego, "}")
		rego = append(rego, "\n")
	} else if c.Op == "notExist" {
		// end current function context first
		rego = append(rego, "	1 == 2  # op=notExist, it needs to check all the way up to root. Expanded below.")
		rego = append(rego, "}")
		rego = append(rego, "\n")

		path = replacePerContainerPath(path)
		rego = append(rego, generateNotExitFunctions(idx, path)...)
	} else if c.ValueType == "string" {
		quotedString := parseQuotedSimpleRegexString(c.Value)
		line := fmt.Sprintf("	user_provided_data := [%s]\n", strings.Join(quotedString, ","))
		rego = append(rego, line)

		rego = append(rego, addSidecarContainerCheck(path)...)
		path = replacePerContainerPath(path)

		rego = append(rego, fmt.Sprintf("	value = %s", strings.TrimSuffix(path, "[_]")))

		if c.Op == "containsAll" {
			rego = append(rego, "	operator_contains_all(user_provided_data, value)")
		} else if c.Op == "containsAny" {
			rego = append(rego, "	operator_contains_any(user_provided_data, value)")
		} else if c.Op == "notContainsAny" {
			rego = append(rego, "	operator_not_contains_any(user_provided_data, value)")
		} else if c.Op == "containsOtherThan" {
			rego = append(rego, "	operator_contains_other_than(user_provided_data, value)")
		}

		rego = append(rego, "}")
		rego = append(rego, "\n")
	} else if c.ValueType == "number" {
		rego = append(rego, fmt.Sprintf("	user_provided_data := %s", c.Value))
		rego = append(rego, addSidecarContainerCheck(path)...)
		path = replacePerContainerPath(path)

		opStr := "=="
		if c.Op == "=" {
			opStr = "=="
		} else if c.Op == "!=" {
			opStr = "!="
		} else if c.Op == ">=" {
			opStr = ">="
		} else if c.Op == ">" {
			opStr = ">"
		} else if c.Op == "<=" {
			opStr = "<="
		}

		rego = append(rego, fmt.Sprintf("	value = %s", path))
		rego = append(rego, fmt.Sprintf("	value %s user_provided_data", opStr))
		rego = append(rego, "}")
		rego = append(rego, "\n")
	} else if c.ValueType == "boolean" {
		rego = append(rego, fmt.Sprintf("	user_provided_data := %s", c.Value))
		rego = append(rego, addSidecarContainerCheck(path)...)
		path = replacePerContainerPath(path)

		rego = append(rego, fmt.Sprintf("	value = %s", path))

		if c.Op == "=" {
			rego = append(rego, "	value == user_provided_data")
		}

		rego = append(rego, "}")
		rego = append(rego, "\n")
	}

	return rego
}

func parseQuotedSimpleRegexString(input string) []string {
	quotedString := []string{}

	s := strings.Split(input, ",")
	for _, v := range s {

		v = strings.TrimSpace(v)
		if strings.ContainsAny(v, "?*") {
			v = strings.Replace(v, ".", "\\.", -1)
			v = strings.Replace(v, "?", ".", -1)
			v = strings.Replace(v, "*", ".*", -1)

			v = fmt.Sprintf("^%s$", v)
		} else {
			v = fmt.Sprintf("^%s$", v)
		}

		quotedString = append(quotedString, fmt.Sprintf("%q", strings.TrimSpace(v)))
	}

	return quotedString
}

func splitPathKey(path string) (string, string) {
	idx := strings.LastIndex(path, ".")
	if idx != -1 {
		return path[0:idx], path[idx+1:]
	}
	return path, ""
}

func addSidecarContainerCheck(path string) []string {
	rego := []string{}

	rego = append(rego, fmt.Sprintf("	# parameter path = %s", path))

	if strings.Contains(path, "containers[_]") {
		rego = append(rego, "	image := request.spec.containers[i].image")
		rego = append(rego, "	not inSidecarContainerList(image)\n")
	} else if strings.Contains(path, "initContainers[_]") {
		rego = append(rego, "	image := request.spec.initContainers[i].image")
		rego = append(rego, "	not inSidecarContainerList(image)\n")
	} else if strings.Contains(path, "ephemeralContainers[_]") {
		rego = append(rego, "	image := request.spec.ephemeralContainers[i].image")
		rego = append(rego, "	not inSidecarContainerList(image)\n")
	}
	return rego
}

func replacePerContainerPath(path string) string {
	if strings.Contains(path, "containers[_]") {
		return strings.Replace(path, "containers[_]", "containers[i]", 1)
	} else if strings.Contains(path, "initContainers[_]") {
		return strings.Replace(path, "initContainers[_]", "initContainers[i]", 1)
	} else if strings.Contains(path, "ephemeralContainers[_]") {
		return strings.Replace(path, "ephemeralContainers[_]", "ephemeralContainers[i]", 1)
	}
	return path
}

func generateNotExitFunctions(criteria_index int, path string) []string {
	rego := []string{}
	containerKeys := []string{"request.spec.containers[i]", "request.spec.initContainers[i]", "request.spec.ephemeralContainers[i]"}
	containerKeys2 := []string{"containers", "initContainers", "ephemeralContainers"}

	for i, containerKey := range containerKeys {
		if strings.HasPrefix(path, containerKey) {
			rego = append(rego, fmt.Sprintf("criteria_%d(request)", criteria_index))
			rego = append(rego, "{")
			rego = append(rego, `	not has_key(request, "spec")`)
			rego = append(rego, "}\n")

			rego = append(rego, fmt.Sprintf("criteria_%d(request)", criteria_index))
			rego = append(rego, "{")
			rego = append(rego, fmt.Sprintf("	not has_key(request.spec, %q)", containerKeys2[i]))

			rego = append(rego, "}\n")

			items := strings.Split(path[len(containerKey)+1:], ".")

			for idx, item := range items {
				rego = append(rego, fmt.Sprintf("criteria_%d(request)", criteria_index))
				rego = append(rego, "{")
				if idx > 0 {
					rego = append(rego, fmt.Sprintf("	image := %s.image", containerKey))
					rego = append(rego, "	not inSidecarContainerList(image)\n")

					itemsForKey := items[0:idx]
					key := fmt.Sprintf("%s.%s", containerKey, strings.Join(itemsForKey, "."))

					rego = append(rego, fmt.Sprintf("	items:=[i | has_key(%s,%q)]", key, strings.TrimSuffix(item, "[_]")))
					rego = append(rego, "	count(items)==0")
				} else {
					rego = append(rego, fmt.Sprintf("	items:=[i | has_key(%s,%q)]", containerKey, strings.TrimSuffix(item, "[_]")))
					rego = append(rego, "	count(items)==0")
				}
				rego = append(rego, "}\n")
			}
		}
	}

	// not within containers
	if len(rego) == 0 {
		rego = append(rego, fmt.Sprintf("criteria_%d(request)", criteria_index))
		rego = append(rego, "{")
		rego = append(rego, `	not has_key(request, "spec")`)
		rego = append(rego, "}\n")

		items := strings.Split(path[len("request.spec")+1:], ".")
		for idx, item := range items {
			rego = append(rego, fmt.Sprintf("criteria_%d(request)", criteria_index))
			rego = append(rego, "{")
			if idx > 0 {
				itemsForKey := items[0:idx]
				key := fmt.Sprintf("request.spec.%s", strings.Join(itemsForKey, "."))

				if strings.Contains(key, "[_]") {
					rego = append(rego, fmt.Sprintf("	items:=[ v | has_key(%s,%q); v:=%q]", key, strings.TrimSuffix(item, "[_]"), strings.TrimSuffix(item, "[_]")))
					rego = append(rego, "	count(items)==0")
				} else {
					rego = append(rego, fmt.Sprintf("	not has_key(%s,%q)", key, strings.TrimSuffix(item, "[_]")))
				}
			} else {
				rego = append(rego, fmt.Sprintf("	not has_key(%s,%q)", "request.spec", strings.TrimSuffix(item, "[_]")))
			}
			rego = append(rego, "}\n")
		}
	}

	return rego
}
