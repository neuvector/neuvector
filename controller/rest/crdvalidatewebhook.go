package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func (h *nvCrdHandler) crdvalidate(ar *admissionv1beta1.AdmissionReview) {
	req := ar.Request

	switch req.Kind.Kind {
	case resource.NvSecurityRuleKind, resource.NvClusterSecurityRuleKind, resource.NvAdmCtrlSecurityRuleKind,
		resource.NvDlpSecurityRuleKind, resource.NvWafSecurityRuleKind:
		h.crdGFwRuleHandler(req)
	}
	return
}

func writeCrdFailedLog(req *admissionv1beta1.AdmissionRequest, errMsg string) {
	if req != nil {
		reqName := req.Name
		var err error = common.ErrUnsupported
		var secRulePartial resource.NvSecurityRulePartial
		switch req.Operation {
		case "DELETE":
			err = json.Unmarshal(req.OldObject.Raw, &secRulePartial)
		case "CREATE", "UPDATE":
			err = json.Unmarshal(req.Object.Raw, &secRulePartial)
		}
		if err == nil && reqName == "" && secRulePartial.Metadata != nil {
			reqName = secRulePartial.Metadata.GetName()
		}
		e := fmt.Sprintf("CRD request(%s %s %s) Failed", req.Operation, req.Kind.Kind, reqName)
		k8sResourceLog(share.CLUSEvCrdErrDetected, e, []string{errMsg})
	}
}

func crdProcEnqueue(ar *admissionv1beta1.AdmissionReview) error {
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
		writeCrdFailedLog(ar.Request, err.Error())
		log.WithFields(log.Fields{"error": err}).Error("Crd enqueue Acquire crd lock error")
		return err
	}
	defer clusHelper.ReleaseLock(lock)
	// first save the whole content of crd, key is the unique name contain UID
	var crdQueue share.CLUSCrdRecord
	crdQueue.CrdRecord = ar
	if err := clusHelper.PutCrdRecord(&crdQueue, name); err != nil {
		writeCrdFailedLog(ar.Request, err.Error())
		log.WithFields(log.Fields{"Enqueu crd put error": err}).Error()
		return err
	}

	// second save the unique name of the crd event in the queue for orderly process
	crdEventQueue := clusHelper.GetCrdEventQueue()
	if crdEventQueue == nil {
		crdEventQueue = new(share.CLUSCrdEventRecord)
	}
	crdEventQueue.CrdEventRecord = append(crdEventQueue.CrdEventRecord, name)
	if err := clusHelper.PutCrdEventQueue(crdEventQueue); err != nil {
		clusHelper.DeleteCrdRecord(name)
		writeCrdFailedLog(ar.Request, err.Error())
		log.WithFields(log.Fields{"Enqueu crd event put error": err}).Error()
		return err
	}
	return nil
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
			crdEventQueue := clusHelper.GetCrdEventQueue()
			if crdEventQueue == nil || len(crdEventQueue.CrdEventRecord) == 0 {
				continue
			}
			lock, err := clusHelper.AcquireLock(share.CLUSLockCrdQueueKey, time.Minute*5)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Dequeue Acquire crd lock error")
				continue
			}
			// reread the kv after lock
			// First get the name of the crd in event queue, this queue keep the event order
			crdEventQueue = clusHelper.GetCrdEventQueue()
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

		RETRY_POLICY_LOCK:
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
			crdHandler.crdvalidate(record)
			crdHandler.ReleaseLock()
			// For multiple controller, need give other controller a chance
			time.Sleep(1 * time.Second)
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
		if whsvr.dumpRequestObj && ar.Request.Operation != admissionv1beta1.Delete {
			if b, err := json.Marshal(ar); err == nil {
				log.WithFields(log.Fields{"AdmissionReview": string(b)}).Debug()
			}
		}
		if (ar.Request == nil || len(ar.Request.Object.Raw) == 0) && (ar.Request.Operation != admissionv1beta1.Delete) {
			log.Warn("disallow because of no request/raw data")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
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

		if len(sizeErrMsg) == 0 && ar.Request.Operation == admissionv1beta1.Create && ar.Request.Kind.Kind == resource.NvAdmCtrlSecurityRuleKind {
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
			resultMsg = fmt.Sprintf(" %s denied: %s", ar.Request.Operation, sizeErrMsg)
		} else {
			if ar.Request.DryRun != nil && *ar.Request.DryRun {
				skip = true
				resultMsg = fmt.Sprintf(" %s denied in dry-run", ar.Request.Operation)
			} else {
				allowed = true
				resultMsg = fmt.Sprintf(" %s done", ar.Request.Operation)
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
