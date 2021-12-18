package main

//// Use tests locally by replacing the first character of function name, "t", with "T"

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/cvetools"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
)

////
const dbPath = "../../data/"
const outPath = "test_output.json"
const testTmpPath = "/tmp/neuvector/db/"
const rtSock = "unix:///var/run/docker.sock"

// -- Logger
// LogFormatter emulates the form of the traditional built-in logger.
type logFormatter struct {
	Module string
}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%-10s|%s|", entry.Time.Format("04:05.999"), strings.ToUpper(entry.Level.String())[0:4])
	if len(entry.Message) > 0 {
		fmt.Fprintf(b, "%s", entry.Message)
	}

	fmt.Fprintf(b, " - ")
	for key, value := range entry.Data {
		b.WriteString(key)
		b.WriteByte('=')
		fmt.Fprintf(b, "%+v ", value)
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func initEnv() (*taskMain, string, bool) {
	os.RemoveAll(outPath)
	os.RemoveAll(scan.ImageWorkingPath)
	os.MkdirAll(scan.ImageWorkingPath, 0755)

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel) // change it later: log.DebugLevel
	log.SetFormatter(&logFormatter{Module: "SCT"})

	// acquire tool
	sys := system.NewSystemTools()
	cveTools = cvetools.NewCveTools(rtSock, scan.NewScanUtil(sys))

	if v, _, err := common.GetDbVersion(dbPath); err == nil {
		fmt.Printf("CVE database version: %.3f\n", v)
	} else {
		fmt.Printf("Error: %v\n", err)
		return nil, "", false
	}

	_, _, _, _, err := common.LoadCveDb("../../data/", testTmpPath)
	if err != nil {
		fmt.Printf("load cvedb error: %+v\n", err)
		return nil, "", false
	}

	if !checkDbReady() {
		fmt.Printf("db is not ready\n")
		return nil, "", false
	}

	tm, ok := InitTaskMain(outPath)
	if !ok {
		fmt.Printf("Failed Init task\n")
		return nil, "", false
	}
	return tm, scan.CreateImagePath(""), true
}

func testDockerImageScan(t *testing.T) {
	fmt.Printf("TestDockerImageScan: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	req := share.ScanImageRequest{ // assemble request here
		Registry:    "https://registry.hub.docker.com/",
		Username:    "",
		Password:    "",
		Repository:  "library/alpine", // "library/mysql", "library/alpine"
		Tag:         "latest",         // latest
		Proxy:       "",
		ScanLayers:  true,
		ScanSecrets: true,
	}

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestDockerImageScan: Done[%d]\n\n", rt)
}

func testScanAppPackages(t *testing.T) {
	fmt.Printf("TestScanAppPackages: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	var req share.ScanAppRequest

	oc := "3.11.82"
	req.Packages = append(req.Packages, &share.ScanAppPackage{
		AppName:    "openshift",
		ModuleName: "openshift.kubernetes",
		Version:    oc,
		FileName:   "kubernetes",
	})

	req.Packages = append(req.Packages, &share.ScanAppPackage{
		AppName:    "openshift",
		ModuleName: "openshift",
		Version:    oc,
		FileName:   "openshift",
	})

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestScanAppPackages: Done[%d]\n\n", rt)
}

func testScanData(t *testing.T) {
	fmt.Printf("TestScanData: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	var req share.ScanData
	req.Buffer = nil
	req.Error = share.ScanErrorCode_ScanErrNone

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestScanData: Done[%d]\n\n", rt)
}

func testAwsLambda(t *testing.T) {
	fmt.Printf("TestAwsLambda: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	// Renew the token before making this test
	// the function links has expirty requirement(10 minutes), cann not be reused.
	var req share.ScanAwsLambdaRequest
	req.ResType = "aws_lambda_func"
	req.FuncName = "test123-dev-hello"
	req.Region = "us-east-1"
	req.FuncLink = "https://prod-04-2014-tasks.s3.us-east-1.amazonaws.com/snapshots/044529968248/xsunslstry-dev-hello-94252122-4e9d-410c-a1f0-54e97c8607a9?versionId=_68ic.6KPD8bUUCReDn23nGs6C5xhlqA&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEBMaCXVzLWVhc3QtMSJHMEUCIQD9%2FBDemkBkNAgE0rUvh7P4s52xB4sVVnPHBy2pa3la5QIgKxAzRs8HckHFlo5RbIrLlWbfThRGQ%2Fftc4CptZ9d14AqtAMIexAAGgw3NDk2Nzg5MDI4MzkiDOUkdHc8CKp3OlvDKSqRA3xwVJ5MdycfRbEl%2BgHw%2F1721nWb2e5YTMDusJj3WVCiAMN%2F%2Fb9bPPeIuKcU4noqDEwU%2FgscG3k4OB2r2c7Xz02FAAMLTB%2FXwbHIdPd51fg1DayZ2JyJ3JDOgT%2Bj522QrM8iB3h7Gu5U7Iopka5qMgwAVj0mppUKRq%2BPSkajV2%2BmQ3KCSapWY2mI3aF810f29691yXst4qd1TfJWTYeJwPSQFlwmYszGTezsH6uLW0b%2BO%2F4JdhdwdiOvZEXtKtStRd65gRWAt6OMDCQRk8xF%2BiqBDeybbGo8jb8zjVGzkOU2gJda8VJNrxkMoKcyoWmn1x6vhV3P4h7VmwQkkMMBhZeuBEMUmH3W3NiZ61wzhQDMSzh%2B0CzDnTVFxtVV13U9fyLUWMelWGLUifXy22IYFXzHCgQzR4M%2BpcwZE40RmPzX5VGBPH%2Fodpva6RoUfoWUMn2Gc1h9NoagedPpGEm2JotDcjlI0vTongAiv%2FGa0B52X7o4Y4vNg8gkiV3xwNJx%2BXwdBaa%2FfJsVEOJV8KKnWPk8MMjS3%2FYFOusBX2qF07i3Rgv0xjdqhSZl015Y8EscyzMWYlD0EILCBDM%2BNoYUxoPuaj0abKw0w9unIG5CMDDYX%2BGrwa%2FuHuqm9bdudwhhZx72QiUmrtNzMwISC8Z5o4Mfaa6SI0hp%2B%2BtDskjTO8tY9uPiT3MgRBjwaf1%2FhH8fCqceqorJkpgXj38ce5RnXj6B9W8aBWIJ3brlOEN8URjx5lyn85cTbYkgntcHCDofbppRBSyplvNS7BJxtlcj0%2FsGubeIieTKnWWiWlZbQ6mEKQmAc4Vz7I2XS5CmxBuyZxG%2FP00PNL%2BsLqy0dDCPCItEfLfLpg%3D%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20200603T200011Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIA25DCYHY3623B6L2A%2F20200603%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=21f378b4ab5bbb17a7aea1dcddb4d040ca8825f7cadf946fe2807f0186d23b48"
	req.ScanSecrets = true

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestAwsLambda: Done[%d]\n\n", rt)
}

func testLocalImageScan(t *testing.T) {
	fmt.Printf("TestLocalImageScan: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	req := share.ScanImageRequest{ // assemble request here
		Registry:    "",
		Username:    "",
		Password:    "",
		Repository:  "nvlab/iperf", // need to pull it at first, "nvlab/iperf", "nvpublic/al"
		Tag:         "latest",      // "latest"
		Proxy:       "",
		ScanLayers:  true,
		ScanSecrets: true,
	}

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestLocalImageScan: Done[%d]\n\n", rt)
}

func testAwsImageScan(t *testing.T) {
	fmt.Printf("TestAwsImageScan: Start ...\n")
	tm, wpath, ok := initEnv()
	if !ok {
		t.Errorf("Failed Init\n")
		return
	}

	req := share.ScanImageRequest{ // assemble request here
		Registry:    "https://596840562787.dkr.ecr.us-west-2.amazonaws.com/",
		Username:    "AWS",
		Password:    "eyJwYXlsb2FkIjoib1grYjlaemUvL3MvNmx4WHBBbUpYRDJwWDNqSFlUcVNDWmVqNGtIVVVHREtheXdFTkZRdzk1eGZTVzdRc2ZkVmY5R3FNdEhhYjVka016NXc0U3BLY3NyY09oNjFVTW1qczNBTm1UTTBTbktVRW1qblk4YlpPRmhxNXVqcERNeUlRRDI4ZFE3cXk5aHNhTzA2d3c2anIxYWxFOGE1bE1oRjdPdmxwYmdYRmNJWmVWSFFvVHBRcXc3OFNGWXVlcXoyV2RWRHpXaE16TFFCMEpxc2tsT1RoRjN2a3E2bWxHbHJaOE1VdEJFdzdwY2VmM2NmNkF6K0RCUlEwOGFuaU9Ec2JnNjZjMGRXb3hGcVRVYm0yU1JtdzM1VjJQMFhYN1lSM1hhYlcrUFdFdW5EMi9xamlYTzM0bVMyRWY3ekZKNXUwajNWSDU3TklZS1M4ZFdUV0J3SUZHL0VHN2Urc2Z5RzVNUDVLd2R1WE1PL2JISWVuZjJ6TDNGbWJwMmJNMDNBR1JoQzgxclk4SEprdXVJZFVnVnZOVllQNkNXTHVUa09FOG1PODlTNEZnRmRnWkZxb2JMbExtdThadGxFZkgzMmFDWGJnVHVFdUpXVDVMM3pJcHJKRHhnM0dXdkhKZmFrdUZTaTVyU2w4TXFKTlNYQXJNZWQxWHNUcUgzcmpYVyt2c01lQ1BBVWZWeWxsNjRwQUF5YkJWVjYyOW1hWmFGOWowcmRRblliRVdMTVVqaEw1cjJKSUp3REdtaWs5RnA2OGZzNzd0Q1Y3ekFoMzlkNDJ5cDh0Q05ndHE2K2ZqWEJNN05VUGRHanYvYmViUG03cTZhZmZ0aml4Nit1aW5USDU2WVRqemlWcDV0VjlWVFFUL254TFZxNlJlc1FDdEk0YjJUamxsMGRsd0YwN0NtWlRsUTVMaDhPMG5lZWU0NytHVHRHR1RxUDV5d1pRQ3luME9OOWwwd1V4bVVMUmVBYnlOVGxVWWwvTlJpczZ2SS9JN1RxekNIVXFSb2NYd1c0OU9lcnppOEo0TWp4YXN6WWNhZE5lOVRGQk9HUk5iN21aNVBsZTNPTFdQQ3M4SlpYV3FySkNNSVhXaXQ4a0s2NFVVVVVqL0FrbDNnSW4rSUIwdS9sTTlXQlZFaURHbXRrN0FaR2dCMlBkc3BmR0JOVU9UbGUyS1J0bGpKalZXcDdIVXdyUVBJdGhiTUYyZFNQaVhjVzdQNjJxQVNXVE1YS3h3alZkaklVU2dWYWhRS080UXMyV1V1RXo2enFMVmlLL3NkeFUwOVVwcGVWOFUrR0RKaWlRNFhxeFpvMndHTFFSRnlWdmMrekhuZE44cFl3T1dxQ0prUUhvaFl5cUZ2RHVkU3B5NHpyUkdhNll6ZlgxaWN2ellKNmpWTmM1ZWJRREYzSWJjSTA2YVlRb0ZSa3QxOFBjMDFrb1lzeWpLTEwwQW94K0hScVM0aTBrUURsZ0RWVVNqa2NIbFFNRkR1a05sbXBENHpRcTVGa3BPME9GVDNvL1F6U3h3UmxIWXJIZmxlclB4Q3YyUm8vR0l0Q3FZVT0iLCJkYXRha2V5IjoiQVFFQkFIajZsYzRYSUp3LzdsbjBIYzAwRE1lazZHRXhIQ2JZNFJJcFRNQ0k1OEluVXdBQUFINHdmQVlKS29aSWh2Y05BUWNHb0c4d2JRSUJBREJvQmdrcWhraUc5dzBCQndFd0hnWUpZSVpJQVdVREJBRXVNQkVFREM3RjFBWGxqV0p3b2dpZWFBSUJFSUE3cjlTMzAzMm9NcG5GOVJIV2RBMUFlMzRtSDZKQjQ1NWYwaEE2d3c2aGlZRDQydUxpL1AwaUk5Y2R3L0YxZVd1QnJDMzl4K1dTNTdGSklEUT0iLCJ2ZXJzaW9uIjoiMiIsInR5cGUiOiJEQVRBX0tFWSIsImV4cGlyYXRpb24iOjE2MDI1OTIzODd9",
		Repository:  "alpine",
		Tag:         "3.4",
		Proxy:       "",
		ScanLayers:  true,
		ScanSecrets: true,
	}

	rt := tm.doScanTask(req, wpath)
	if rt < 0 {
		t.Errorf("")
	}
	fmt.Printf("TestAwsImageScan: Done[%d]\n\n", rt)
}
