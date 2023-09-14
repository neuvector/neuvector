package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

func crdProcEnqueue(ar *admissionv1beta1.AdmissionReview) {
	if detail, err := crdProcEnqueueInternal(ar); err != nil {
		crUid := ""
		req := ar.Request
		var raw []byte
		var secRulePartial resource.NvSecurityRulePartial
		if req.Operation == "DELETE" {
			raw = req.OldObject.Raw
		} else {
			raw = req.Object.Raw
		}
		if err := json.Unmarshal(raw, &secRulePartial); err == nil && secRulePartial.Metadata != nil {
			crUid = secRulePartial.Metadata.GetUid()
		}
		msg := fmt.Sprintf("CRD request(%s %s %s %s) Failed", req.Operation, req.Kind.Kind, req.Name, crUid)
		k8sResourceLog(share.CLUSEvCrdErrDetected, msg, []string{detail})
		log.WithFields(log.Fields{"error": err}).Error(detail)
	}
}

func crdProcEnqueueInternal(ar *admissionv1beta1.AdmissionReview) (string, error) {
	if clusHelper == nil {
		clusHelper = kv.GetClusterHelper()
	}
	var ruleNs string
	req := ar.Request
	if req.Kind.Kind == resource.NvSecurityRuleKind {
		ruleNs = req.Namespace
	} else {
		ruleNs = "default"
	}
	// each crd event have unique UID and use this as part of key to save the crd content
	// Also put this name in the crd event queue for process rutaines to hand in order
	// It also can prevent controller crash, except the one already dequeued may lost
	name := fmt.Sprintf("%s-%s-%s-%s", req.Kind.Kind, ruleNs, req.Name, req.UID)

	// This lock is shared between goroutines handle this queue only, so it is ok to wait long
	lock, err := clusHelper.AcquireLock(share.CLUSLockCrdQueueKey, time.Minute*5)
	if err != nil {
		return "Crd enqueue Acquire crd lock error", err
	}
	defer clusHelper.ReleaseLock(lock)
	// first save the whole content of crd, key is the unique name contain UID
	var crdQueue share.CLUSCrdRecord
	crdQueue.CrdRecord = ar
	if req.Operation == "UPDATE" { // there is no need to save OldObject.Raw because we only check Object.Raw for UPDATE requests
		crdQueue.CrdRecord.Request.OldObject.Raw = nil
	}
	if err := clusHelper.PutCrdRecord(&crdQueue, name); err != nil {
		return "Enqueu crd put error", err
	}

	// second save the unique name of the crd event in the queue for orderly process
	crdEventQueue := clusHelper.GetCrdEventQueue()
	if crdEventQueue == nil {
		crdEventQueue = new(share.CLUSCrdEventRecord)
	}
	crdEventQueue.CrdEventRecord = append(crdEventQueue.CrdEventRecord, name)
	if err := clusHelper.PutCrdEventQueue(crdEventQueue); err != nil {
		errStr := err.Error()
		if strings.HasPrefix(errStr, "zip data(") && strings.HasSuffix(errStr, ") too big") {
			if req.Operation == "DELETE" && len(crdEventQueue.CrdEventRecord) > 0 {
				// failed to queue CRD DELETE request because crdEventQueue.CrdEventRecord is full(by kv key size limitation).
				j := 0 // new index
				found := false
				namePrefix := fmt.Sprintf("%s-%s-%s-", req.Kind.Kind, ruleNs, req.Name)
				// 1. remove this request from the queue
				crdEventQueue.CrdEventRecord = crdEventQueue.CrdEventRecord[:len(crdEventQueue.CrdEventRecord)-1]
				// 2. go thru the queue entries & delete those that have the same CR name (i.e. the prior CREATE/UPDATE requests for this DELETE request are not processed yet)
				for i, n := range crdEventQueue.CrdEventRecord {
					// the last entity in the name is req.UID which is different in each request for the same CR object
					if strings.HasPrefix(n, namePrefix) && ((len(namePrefix) + 36) == len(n)) {
						found = true
					} else {
						crdEventQueue.CrdEventRecord[j] = crdEventQueue.CrdEventRecord[i]
						j += 1
					}
				}
				if found {
					// 3. if any queue entry is deleted, append this DELETE request to the queue.
					crdEventQueue.CrdEventRecord = crdEventQueue.CrdEventRecord[:j]
					crdEventQueue.CrdEventRecord = append(crdEventQueue.CrdEventRecord, name)
					err = clusHelper.PutCrdEventQueue(crdEventQueue)
					// => TODO : what if it fails again because the key value size is still too big?
				} else {
					// => TODO: what if no queue entry is deleted?
				}
				if err == nil {
					return "", nil
				}
			}
		}
		clusHelper.DeleteCrdRecord(name)
		return fmt.Sprintf("Enqueu crd event put error(%d entries)", len(crdEventQueue.CrdEventRecord)), err
	}
	return "", nil
}

func deleteCrInK8s(kind, recordName string, crdSecRule interface{}) {
	if crdSecRule == nil {
		return
	}

	var err error

	switch kind {
	case resource.NvSecurityRuleKind:
		err = global.ORCH.DeleteResource(resource.RscTypeCrdSecurityRule, crdSecRule)
	case resource.NvClusterSecurityRuleKind:
		if gfwrule, ok := crdSecRule.(*resource.NvSecurityRule); ok && gfwrule != nil {
			r := resource.NvClusterSecurityRule(*gfwrule)
			err = global.ORCH.DeleteResource(resource.RscTypeCrdClusterSecurityRule, &r)
		}
	case resource.NvAdmCtrlSecurityRuleKind:
		err = global.ORCH.DeleteResource(resource.RscTypeCrdAdmCtrlSecurityRule, crdSecRule)
	case resource.NvDlpSecurityRuleKind:
		err = global.ORCH.DeleteResource(resource.RscTypeCrdDlpSecurityRule, crdSecRule)
	case resource.NvWafSecurityRuleKind:
		err = global.ORCH.DeleteResource(resource.RscTypeCrdWafSecurityRule, crdSecRule)
	}
	if err != nil {
		log.WithFields(log.Fields{"kind": kind, "error": err}).Error(recordName)
	}
}

func writeCrOpEvent(kind, recordName, uid string, ev share.TLogEvent, msg string, subMsgs []string) {
	detail := make([]string, 0, len(subMsgs))
	for _, subMsg := range subMsgs {
		if subMsg != "" {
			detail = append(detail, subMsg)
		}
	}
	k8sResourceLog(ev, msg, detail)
}

// The process thread do it periodically every 10s
// First it will dequeue first crd event name.
// Second it will use the name to find the crd content
// Third it will call process. if failed a crd delete will issued to remove from k8s
func CrdQueueProc() {
	for {
		select {
		case <-crdEventProcTicker.C:
			// after wake-up the thread will try to drain crd event queue
		NEXT_CRD:
			// add peek at beginning to avoid lock everytime.
			crdEventsCount := clusHelper.GetCrdEventQueueCount()
			if crdEventsCount == 0 {
				time.Sleep(time.Second)
				continue
			}
			lock, err := clusHelper.AcquireLock(share.CLUSLockCrdQueueKey, time.Minute*5)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Dequeue Acquire crd lock error")
				continue
			}
			// reread the kv after lock
			// First get the name of the crd in event queue, this queue keep the event order
			crdEventQueue := clusHelper.GetCrdEventQueue()
			if crdEventQueue == nil || len(crdEventQueue.CrdEventRecord) == 0 {
				// never have crd event so the store key never extablished
				clusHelper.ReleaseLock(lock)
				continue
			}
			name := crdEventQueue.CrdEventRecord[0]
			// dequeue the first event from head
			crdEventQueue.CrdEventRecord = crdEventQueue.CrdEventRecord[1:]
			if len(crdEventQueue.CrdEventRecord) == 0 {
				// release the under laying slice memory when queue is empty.
				crdEventQueue.CrdEventRecord = nil
			}
			if err := clusHelper.PutCrdEventQueue(crdEventQueue); err != nil {
				log.WithFields(log.Fields{"Dequeu crd event put error": err}).Error()
				clusHelper.ReleaseLock(lock)
				continue
			}
			// Second use the name go get the content of the crd
			crdProcRecord := clusHelper.GetCrdRecord(name)
			if crdProcRecord == nil {
				log.WithFields(log.Fields{"Dequeu  crd can't find record": name}).Error()
				clusHelper.ReleaseLock(lock)
				continue
			}
			clusHelper.DeleteCrdRecord(name)
			clusHelper.ReleaseLock(lock)

			var lockKey string
			var crdHandler nvCrdHandler
			record := crdProcRecord.CrdRecord
			if record.Request.Kind.Kind == resource.NvAdmCtrlSecurityRuleKind {
				lockKey = share.CLUSLockAdmCtrlKey
			} else {
				lockKey = share.CLUSLockPolicyKey
			}
			crdHandler.Init(lockKey)
			retryCount := 0
			req := record.Request // *admissionv1beta1.AdmissionRequest
			crdEventsCount = len(crdEventQueue.CrdEventRecord)

			var kind string
			var secRulePartial resource.NvSecurityRulePartial
			var gfwrule resource.NvSecurityRule
			var admCtrlSecRule resource.NvAdmCtrlSecurityRule
			var dlpSecRule resource.NvDlpSecurityRule
			var wafSecRule resource.NvWafSecurityRule
			var crdSecRule interface{}
			var errCount, cachedRecords int
			var errMsg string
			var crInfo, crWarning string
			var usedTime int64
			var processed bool

			err = nil
			kind = req.Kind.Kind
			ruleNs := req.Namespace
			if req.Namespace == "" {
				ruleNs = "default"
			}
			recordName := fmt.Sprintf("%s-%s-%s", kind, ruleNs, req.Name)

			switch req.Operation {
			case "DELETE":
				if err = json.Unmarshal(req.OldObject.Raw, &secRulePartial); err == nil && secRulePartial.Metadata != nil {
					kind = *secRulePartial.Kind
					if req.Name == "" {
						req.Name = secRulePartial.Metadata.GetName()
					}
					crdHandler.crUid = secRulePartial.Metadata.GetUid()
					crdHandler.mdName = req.Name
				} else {
					errCount = 1
					errMsg = fmt.Sprintf("CRD Rule format error")
				}
			case "CREATE", "UPDATE":
				switch kind {
				case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind:
					err = json.Unmarshal(req.Object.Raw, &gfwrule)
					crdSecRule = &gfwrule
					crdHandler.crUid = gfwrule.Metadata.GetUid()

					if req.Namespace != "" {
						// if the namespace of the CR does not exist in k8s, skip processing this CREATE/DELETE request
						_, err2 := global.ORCH.GetResource(resource.RscTypeNamespace, "", req.Namespace)
						if err2 != nil && strings.Contains(err2.Error(), " 404 ") {
							crInfo = "namespace not found"
							goto SKIP_CRD_HANDLER
						}
					}
				case resource.NvAdmCtrlSecurityRuleKind:
					err = json.Unmarshal(req.Object.Raw, &admCtrlSecRule)
					crdSecRule = &admCtrlSecRule
					crdHandler.crUid = admCtrlSecRule.Metadata.GetUid()
				case resource.NvDlpSecurityRuleKind:
					err = json.Unmarshal(req.Object.Raw, &dlpSecRule)
					crdSecRule = &dlpSecRule
					crdHandler.crUid = dlpSecRule.Metadata.GetUid()
				case resource.NvWafSecurityRuleKind:
					err = json.Unmarshal(req.Object.Raw, &wafSecRule)
					crdSecRule = &wafSecRule
					crdHandler.crUid = wafSecRule.Metadata.GetUid()
				default:
					err = fmt.Errorf("unsupported Kubernetese resource kind")
				}
				if err != nil {
					errCount = 1
					errMsg = fmt.Sprintf("CRD Rule format error")
				}
			}

		RETRY_POLICY_LOCK:
			if errCount == 0 {
				if !crdHandler.AcquireLock(2 * clusterLockWait) {
					if retryCount > 3 {
						log.Printf("Crd dequeu proc Plicy lock FAILED")
						continue
					} else {
						retryCount++
						log.Printf("Policy lock retry on proc crd %d", retryCount)
						goto RETRY_POLICY_LOCK
					}
				}

				before := time.Now()
				_, crInfo, crWarning, errMsg, errCount, cachedRecords, processed = crdHandler.crdSecRuleHandler(req, kind, crdSecRule)
				usedTime = time.Since(before).Milliseconds()
				crdHandler.ReleaseLock()

				if errMsg != "" {
					errMsg = fmt.Sprintf("Error: %s", errMsg)
				}
			}

		SKIP_CRD_HANDLER:
			logFields := log.Fields{
				"crdName":        recordName,
				"op":             req.Operation,
				"queued":         crdEventsCount,
				"cached_records": cachedRecords,
				"used_time":      usedTime,
			}
			// write event about handling result
			detail := []string{fmt.Sprintf("%s %s", req.Operation, crdHandler.crUid), crInfo, crWarning, errMsg}
			if crWarning != "" {
				log.WithFields(log.Fields{"recordName": recordName}).Warn(crWarning)
			}
			if !processed {
				msg := fmt.Sprintf("CRD %s Skipped", recordName)
				writeCrOpEvent(kind, recordName, crdHandler.crUid, share.CLUSEvCrdSkipped, msg, detail)
				log.WithFields(logFields).Info("CRD skipped")
			} else {
				switch req.Operation {
				case "DELETE":
					msg := fmt.Sprintf("CRD %s", recordName)
					writeCrOpEvent(kind, recordName, crdHandler.crUid, share.CLUSEvCrdRemoved, msg, detail)
					log.WithFields(logFields).Info("CRD deleted")
				case "CREATE", "UPDATE":
					if errCount > 0 {
						deleteCrInK8s(kind, recordName, crdSecRule)
						msg := fmt.Sprintf("CRD %s Removed", recordName)
						writeCrOpEvent(kind, recordName, crdHandler.crUid, share.CLUSEvCrdErrDetected, msg, detail)
						log.WithFields(logFields).Error("Failed to add CRD")
					} else {
						msg := fmt.Sprintf("CRD %s Processed", recordName)
						writeCrOpEvent(kind, recordName, crdHandler.crUid, share.CLUSEvCrdImported, msg, detail)
						log.WithFields(logFields).Info("CRD processed")
					}
				}
			}

			if !processed {
				time.Sleep(time.Millisecond * 100)
			} else {
				// For multiple controller, need give other controller a chance
				time.Sleep(time.Second)
			}
			goto NEXT_CRD
		}
	}
}

func (whsvr *WebhookServer) crdserveK8s(w http.ResponseWriter, r *http.Request, body []byte) {
	ar := admissionv1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("can't decode body")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	} else {
		var reqOp admissionv1beta1.Operation
		if ar.Request != nil {
			reqOp = ar.Request.Operation
		}
		if (ar.Request == nil || len(ar.Request.Object.Raw) == 0) && (reqOp != admissionv1beta1.Delete) {
			log.WithFields(log.Fields{"reqOp": reqOp}).Warn("disallow because of no request/raw data")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if ar.Request.Name == "" {
			req := ar.Request
			if req != nil && reqOp == admissionv1beta1.Delete && req.Name == "" {
				var secRulePartial resource.NvSecurityRulePartial
				if err := json.Unmarshal(req.OldObject.Raw, &secRulePartial); err == nil && secRulePartial.Metadata != nil {
					req.Name = secRulePartial.Metadata.GetName()
				} else {
					recordName := fmt.Sprintf("%s-%s-%s", req.Kind.Kind, req.Namespace, req.Name)
					msg := fmt.Sprintf("CRD request(%s %s) Error", recordName, reqOp)
					k8sResourceLog(share.CLUSEvCrdErrDetected, msg, []string{err.Error()})
				}
			}
		}

		var sizeErrMsg string
		if len(body) > cluster.KVValueSizeMax {
			crdRecord := share.CLUSCrdRecord{CrdRecord: &ar}
			value, _ := json.Marshal(crdRecord)
			if len(value) >= cluster.KVValueSizeMax {
				zb := utils.GzipBytes(value)
				if len(zb) >= cluster.KVValueSizeMax {
					var name string
					if ar.Request != nil {
						name = ar.Request.Name
					}
					sizeErrMsg = fmt.Sprintf("CRD resource size(%d) is too big", len(body))
					log.WithFields(log.Fields{"name": name, "size": len(value), "compressed": len(zb)}).Error(sizeErrMsg)
				}
			}
		}

		if len(sizeErrMsg) == 0 && reqOp == admissionv1beta1.Create && ar.Request.Kind.Kind == resource.NvAdmCtrlSecurityRuleKind {
			var admCtrlSecRule resource.NvAdmCtrlSecurityRule
			if err := json.Unmarshal(ar.Request.Object.Raw, &admCtrlSecRule); err == nil {
				name := ""
				if admCtrlSecRule.Metadata.Name != nil {
					name = *admCtrlSecRule.Metadata.Name
				}
				if name != share.ScopeLocal {
					sizeErrMsg = fmt.Sprintf("CRD resource metadata name(%s) is not allowed", name)
				}
			}
		}

		var skip bool
		var allowed bool
		var resultMsg string
		if len(sizeErrMsg) > 0 {
			skip = true
			resultMsg = fmt.Sprintf(" %s denied: %s", reqOp, sizeErrMsg)
		} else {
			if ar.Request.DryRun != nil && *ar.Request.DryRun {
				skip = true
				resultMsg = fmt.Sprintf(" %s denied in dry-run", reqOp)
			} else {
				allowed = true
				if reqOp != "DELETE" && reqOp != "CREATE" && reqOp != "UPDATE" {
					log.WithFields(log.Fields{"op": reqOp, "name": ar.Request.Name}).Debug("unsupported operation")
					skip = true
				} else {
					resultMsg = fmt.Sprintf(" %s done", reqOp)
				}
			}
		}

		admissionReview := admissionv1beta1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       resource.K8sKindAdmissionReview,
				APIVersion: resource.AdmissionK8sIoV1Beta1, // [2021/09/21] currently our webhook server only support k8s.io/api/admission/v1beta1
			},
			Response: &admissionv1beta1.AdmissionResponse{
				Allowed: allowed,
				Result:  &metav1.Status{Message: resultMsg},
				UID:     ar.Request.UID,
			},
		}
		resp, err := json.Marshal(admissionReview)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("can't encode response")
			http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		} else {
			if _, err := w.Write(resp); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("can't write response")
				http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
			}
		}

		if !skip {
			// Return the rest call early to prevent webhookvalidating timeout
			// use gorutines to do the enqueue as it need wait in lock write to kv to mantaine order
			go crdProcEnqueue(&ar)
		}
	}
}

// Serve method for Admission Control webhook server
func (whsvr *WebhookServer) crdserve(w http.ResponseWriter, r *http.Request) {

	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		log.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.WithFields(log.Fields{"contentType": contentType}).Error("unexpectd header")
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	whsvr.crdserveK8s(w, r, body)
}

func CrdValidateRestServer(port uint, clientAuth, debug bool) {
	k8sWebhookRestServer(resource.NvCrdSvcName, port, clientAuth, debug)
}
