package opa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type EvaluationResultSpec struct {
	Spec RegoSpecification `json:"specification"`
}

type OpaEvalResultSpec struct {
	Result EvaluationResultSpec `json:"result"`
}

type RegoResultEntryV1 struct {
	Message     string `json:"message"`
	CustomField string `json:"additional_message,omitempty"`
}

type RegoSpecification struct {
	Version     string `json:"version"`
	Description string `json:"description"`
}

// for spec.Version=="v1"
type EvaluationResultV1 struct {
	Violations    []RegoResultEntryV1 `json:"violation"`
	ViolationMsgs []string            `json:"violationmsgs"`
	Spec          RegoSpecification   `json:"specification"`
}

type OpaEvalResultV1 struct {
	Result EvaluationResultV1 `json:"result"`
}

var isRestoring = false
var opaCacheDoc map[string]string = make(map[string]string)
var opaCachePolicy map[string]string = make(map[string]string)
var opaCacheDocMutex = &sync.RWMutex{}
var opaCachePolicyMutex = &sync.RWMutex{}

var (
	opaServer       = "http://localhost:8181"
	ContentTypeJson = "application/json; charset=utf-8"
	ContentTypeText = "text/plain; charset=utf-8"
	opaInitKey      = "/v1/data/neuvector/ready"
)

func InitOpaServer() {
	t := time.Now()
	tUnixNano := t.UnixNano()
	data, _ := json.Marshal(tUnixNano)
	AddDocument(opaInitKey, string(data))
	log.WithFields(log.Fields{"ready": string(data)}).Debug("InitOpaServer.")
}

func IsOpaRestarted() bool {
	if isRestoring {
		return false
	}

	client := getOpaHTTPClient()

	url := fmt.Sprintf("%s%s", opaServer, opaInitKey)
	resp, getErr := client.Get(url)
	if getErr != nil {
		log.WithFields(log.Fields{"url": url, "error": getErr}).Error("OPA request")
		return false
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.WithFields(log.Fields{"error": readErr}).Error("OPA error on ReadAll")
		return false
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "result") {
		return false // exist
	}

	return true
}

func StartOpaServer() *exec.Cmd {
	// http
	// cmd = exec.Command("./opa_binary/opa_linux_amd64_static", "run", "--server", "--ignore=.*", "--addr=:8181")
	cmd := exec.Command("/usr/local/bin/opa", "run", "--server", "--ignore=.*", "--addr=:8181", "--log-level=error", "--disable-telemetry")

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start() // *** use Start()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("create opa failed")
		return nil
	} else {
		log.Info(fmt.Sprintf("run opa success, the pid is %d\n", cmd.Process.Pid))
		time.Sleep(2 * time.Second) // wait a while to let opa server start correctly..
	}

	InitOpaServer()

	return cmd
}

func getOpaHTTPClient() *http.Client {
	return &http.Client{}
}

func addObject(key string, contentType string, data string) bool {

	if IsOpaRestarted() {
		RestoreOpaData()
	}

	client := getOpaHTTPClient()

	// set the HTTP method, url, and request body
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", opaServer, key), strings.NewReader(data))
	if err != nil {
		log.WithFields(log.Fields{"key": key, "contentType": contentType, "error": err}).Error("OPA addObject NewRequest")
		return false
	}

	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"key": key, "contentType": contentType, "error": err}).Error("OPA addObject NewRequest - client.Do(req)")
		return false
	}
	defer resp.Body.Close()

	_, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.WithFields(log.Fields{"key": key, "contentType": contentType, "error": err}).Error("OPA addObject NewRequest")
		return false
	}

	if resp.StatusCode == 200 || resp.StatusCode == 204 {
		return true
	}
	return false
}

func AddPolicy(key string, regoStr string) bool {
	result := addObject(key, ContentTypeText, regoStr)

	// no need to add to cache if in restoring stage... it's already in cache..
	if !isRestoring && result {
		opaCachePolicyMutex.Lock()
		opaCachePolicy[key] = regoStr
		opaCachePolicyMutex.Unlock()
	}

	return result
}

func AddDocument(key string, jsonData string) bool {
	result := addObject(key, ContentTypeJson, jsonData)

	// no need to add to cache if in restoring stage... it's already in cache..
	if !isRestoring && result {
		opaCacheDocMutex.Lock()
		opaCacheDoc[key] = jsonData
		opaCacheDocMutex.Unlock()
	}

	return result
}

func DeletePolicy(ruleId uint32) {
	DeleteDocument(formatPolicyUrl(ruleId))
}

func DeleteDocument(key string) {
	if IsOpaRestarted() {
		RestoreOpaData()
	}

	client := getOpaHTTPClient()

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s%s", opaServer, key), nil)
	if err != nil {
		log.WithFields(log.Fields{"key": key, "error": err}).Error("OPA delDocument NewRequest")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"key": key, "error": err}).Error("OPA delDocument NewRequest")
		return
	}
	defer resp.Body.Close()

	_, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.WithFields(log.Fields{"key": key, "error": readErr}).Error("OPA delDocument NewRequest")
		return
	}

	opaCacheDocMutex.Lock()
	delete(opaCacheDoc, key)
	opaCacheDocMutex.Unlock()

	opaCachePolicyMutex.Lock()
	delete(opaCachePolicy, key)
	opaCachePolicyMutex.Unlock()
}

func OpaEval(policyPath string, inputFile string) (int, string, error) {
	bytes, err := os.ReadFile(inputFile)
	if err != nil {
		return -1, "", err
	}

	return OpaEvalByString(policyPath, string(bytes))
}

func OpaEvalByString(policyPath string, inputData string) (int, string, error) {
	if IsOpaRestarted() {
		RestoreOpaData()
	}

	client := getOpaHTTPClient()

	// set the HTTP method, url, and request body
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", opaServer, policyPath), strings.NewReader(inputData))
	if err != nil {
		return -1, "", err
	}

	// set the request header Content-Type for json
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return -1, "", err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(body), nil
}

func RestoreOpaData() {
	log.WithFields(log.Fields{"doc_count": len(opaCacheDoc), "policy_count": len(opaCachePolicy)}).Debug("RestoreOpaData")

	isRestoring = true
	InitOpaServer()

	for k, v := range opaCacheDoc {
		AddDocument(k, v)
	}
	for k, v := range opaCachePolicy {
		AddPolicy(k, v)
	}

	isRestoring = false
}

// this function should return matched or not
// needs to return same information as we need in NeuVector controller webhook..
func AnalyzeResult(response string) (bool, error) {
	// check the spec first
	var spec OpaEvalResultSpec
	if err := json.Unmarshal([]byte(response), &spec); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("AnalyzeResult Unmarshal() to get spec.")
		return false, errors.New("rego execution error, no specification found")
	}

	if spec.Result.Spec.Version == "v1" {
		var results OpaEvalResultV1 // ## define a version,,   like OpaEvalResultV1 for extensibility.., and have a data field to indicate what version we should use
		if err := json.Unmarshal([]byte(response), &results); err != nil {
			log.WithFields(log.Fields{"spec": spec, "error": err}).Error("AnalyzeResult Unmarshal()")
			return false, errors.New("rego execution error, unable to parse to v1 specification")
		}

		return len(results.Result.Violations) > 0, nil
	} else {
		log.WithFields(log.Fields{"spec": spec}).Error("AnalyzeResult unsupported spec.")
		return false, errors.New("rego execution error, unsupported spec")
	}
}
