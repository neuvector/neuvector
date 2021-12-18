package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

// The user must mount volume to /var/neuvector and the result will be written to the mounted folder
const scanOutputDir = "/var/neuvector"
const scanOutputFile = "scan_result.json"

const apiCallTimeout = time.Duration(30 * time.Second)

type scanOnDemandReportData struct {
	ErrMsg string                  `json:"error_message"`
	Report *api.RESTScanRepoReport `json:"report"`
}

func scanOnDemand(req *share.ScanImageRequest, cvedb map[string]*share.ScanVulnerability) *share.ScanResult {
	var result *share.ScanResult
	var err error

	newDB := &share.CLUSScannerDB{
		CVEDBVersion:    cveTools.CveDBVersion,
		CVEDBCreateTime: cveTools.CveDBCreateTime,
		CVEDB:           cvedb,
	}
	common.SetScannerDB(newDB)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	if scanTasker != nil {
		result, err = scanTasker.Run(ctx, *req)
	} else {
		result, err = cveTools.ScanImage(ctx, req, "")
	}
	cancel()

	var rptData scanOnDemandReportData

	if result == nil {
		rptData.ErrMsg = err.Error()

		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": rptData.ErrMsg,
		}).Error()
	} else if result.Error != share.ScanErrorCode_ScanErrNone {
		rptData.ErrMsg = scanUtils.ScanErrorToStr(result.Error)

		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": rptData.ErrMsg,
		}).Error("Failed to scan repository")
	} else {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag,
		}).Info("Scan repository finish")

		rpt := common.ScanRepoResult2REST(result, nil)
		rptData.Report = rpt
	}

	data, _ := json.MarshalIndent(rptData, "", "    ")

	if _, err = os.Stat(scanOutputDir); os.IsNotExist(err) {
		if err = os.MkdirAll(scanOutputDir, 0775); err != nil {
			log.WithFields(log.Fields{
				"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": err.Error(), "output": scanOutputDir,
			}).Error("Failed to create output directory")
			return result
		}
	}

	output := fmt.Sprintf("%s/%s", scanOutputDir, scanOutputFile)
	err = ioutil.WriteFile(output, data, 0644)
	if err == nil {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "output": output,
		}).Info("Write scan result to file")
	} else {
		log.WithFields(log.Fields{
			"registry": req.Registry, "repo": req.Repository, "tag": req.Tag, "error": err.Error(), "output": output,
		}).Error("Failed to write scan result")
	}

	return result
}

type apiClient struct {
	urlBase string
	token   string
	client  *http.Client
}

func newAPIClient(ctrlIP string, ctrlPort uint16) *apiClient {
	return &apiClient{
		urlBase: fmt.Sprintf("https://%s:%d", ctrlIP, ctrlPort),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: apiCallTimeout,
		},
	}
}

func apiLogin(c *apiClient, myIP string, user, pass string) error {
	data := api.RESTAuthData{ClientIP: myIP, Password: &api.RESTAuthPassword{Username: user, Password: pass}}
	body, _ := json.Marshal(&data)

	req, err := http.NewRequest("POST", c.urlBase+"/v1/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Login failed with status code %d", resp.StatusCode)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var token api.RESTTokenData
	err = json.Unmarshal(body, &token)
	if err != nil {
		return err
	}

	c.token = token.Token.Token
	return nil
}

func apiLogout(c *apiClient) error {
	req, err := http.NewRequest("DELETE", c.urlBase+"/v1/auth", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set(api.RESTTokenHeader, c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Logout failed with status code %d", resp.StatusCode)
	}

	c.token = ""
	return nil
}

func apiSubmitResult(c *apiClient, result *share.ScanResult) error {
	data := api.RESTScanRepoSubmitData{Result: result}
	body, _ := json.Marshal(&data)

	req, err := http.NewRequest("POST", c.urlBase+"/v1/scan/result/repository", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(api.RESTTokenHeader, c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Submit scan result failed with status code %d", resp.StatusCode)
	}

	return nil
}

func scanSubmitResult(ctrlIP string, ctrlPort uint16, myIP string, user, pass string, result *share.ScanResult) error {
	log.WithFields(log.Fields{"join": fmt.Sprintf("%s:%d", ctrlIP, ctrlPort)}).Debug()

	c := newAPIClient(ctrlIP, ctrlPort)

	if err := apiLogin(c, myIP, user, pass); err != nil {
		return err
	}
	if err := apiSubmitResult(c, result); err != nil {
		return err
	}
	if err := apiLogout(c); err != nil {
		return err
	}

	return nil
}
