package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"sort"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
)

const defaultPcapFileSizeInMB = 2 // 2MB
const defaultPcapFileNumber = 5   // 10MB
const maxPcapFileNumber = 50      // 100MB

func parseSnifferStatus(status share.SnifferStatus) string {
	switch status {
	case share.SnifferStatus_Running:
		return api.SnifferStRunning
	case share.SnifferStatus_Stopped:
		return api.SnifferStStopped
	case share.SnifferStatus_Failed:
		return api.SnifferStFailed
	default:
		return api.SnifferStFailed
	}
}

// sniffer ID: sniffer(8)+agentID
func getAgentBySniffer(sniffer string) string {
	if len(sniffer) <= share.SnifferIdAgentField ||
		cacher.GetAgent(sniffer[share.SnifferIdAgentField:], access.NewReaderAccessControl()) == nil {
		return ""
	}
	return sniffer[share.SnifferIdAgentField:]
}

func isSnifferAccessible(id string, acc *access.AccessControl) (string, []*share.CLUSSniffer, error) {
	agentId := getAgentBySniffer(id)
	if agentId == "" {
		log.WithFields(log.Fields{"id": id}).Error("Failed to get agent id")
		return "", nil, common.ErrObjectNotFound
	}

	// when the id is valid and we can find the sniffed workload in cache, we do authorization to see if the caller can do it
	f := &share.CLUSSnifferFilter{ID: id}
	status, err := rpc.GetSniffers(agentId, f)
	if err == nil && len(status) == 1 {
		// authorize here because we should know the workload now
		if wl, err := cacher.GetWorkloadBrief(status[0].WorkloadID, "", acc); err == nil {
			// now we know the caller can access the workload, but we don't know the caller has PERMS_RUNTIME_POLICIES permissions on the workload's domain yet
			if !acc.Authorize(&share.CLUSSnifferDummy{WorkloadDomain: wl.Domain}, nil) {
				status = nil
				err = common.ErrObjectAccessDenied
				return agentId, status, err
			}
		}
	}

	return agentId, status, err
}

func handlerSnifferList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		resp := api.RESTSniffersData{Sniffers: make([]*api.RESTSnifferInfo, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get sniffer list")
		return
	}

	query := restParseQuery(r)

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc) // returned wlID could be empty if it's to list all sniffer sessions on an agent
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	f := &share.CLUSSnifferFilter{Workload: wlID}
	sniffers, err := rpc.GetSniffers(agentID, f)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Failed to get sniffers")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrAgentError, err.Error())
	}

	// Sort sniffer by starting time
	sort.Slice(sniffers, func(i, j int) bool { return sniffers[i].StartTime < sniffers[j].StartTime })

	resp := api.RESTSniffersData{Sniffers: make([]*api.RESTSnifferInfo, 0, len(sniffers))}
	for _, sniffer := range sniffers {
		// check if caller is authorized to access this sniffer session
		if wl, err := cacher.GetWorkloadBrief(sniffer.WorkloadID, "", acc); wl != nil {
			if !acc.Authorize(&share.CLUSSnifferDummy{WorkloadDomain: wl.Domain}, nil) {
				continue
			}
		} else {
			log.WithFields(log.Fields{"workloadID": sniffer.WorkloadID, "error": err}).Warn("Failed to get workload for sniffer")
		}

		snifferInfo := &api.RESTSnifferInfo{
			ID:         sniffer.ID,
			AgentID:    sniffer.AgentID,
			WorkloadID: sniffer.WorkloadID,
			FileNumber: sniffer.FileNumber,
			Size:       sniffer.Size,
			Status:     parseSnifferStatus(sniffer.Status),
			Args:       sniffer.Args,
			StartTime:  sniffer.StartTime,
			StopTime:   sniffer.StopTime,
		}
		resp.Sniffers = append(resp.Sniffers, snifferInfo)
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get sniffer list")
}

func handlerSnifferShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	if _, status, err := isSnifferAccessible(id, acc); err == nil && len(status) <= 1 {
		if len(status) == 1 {
			resp := api.RESTSnifferData{
				Sniffer: &api.RESTSnifferInfo{
					ID:         status[0].ID,
					AgentID:    status[0].AgentID,
					WorkloadID: status[0].WorkloadID,
					FileNumber: status[0].FileNumber,
					Size:       status[0].Size,
					Status:     parseSnifferStatus(status[0].Status),
					Args:       status[0].Args,
					StartTime:  status[0].StartTime,
					StopTime:   status[0].StopTime,
				},
			}
			restRespSuccess(w, r, &resp, acc, login, nil, "Get sniffer detail")
		} else if len(status) == 0 {
			restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		}
	} else {
		if err == common.ErrObjectNotFound || err == common.ErrObjectAccessDenied {
			restRespNotFoundLogAccessDenied(w, login, err)
		} else {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, "Error in rpc")
		}
	}
}

func handlerSnifferStart(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var proc api.RESTSnifferArgsData
	err := json.Unmarshal(body, &proc)
	if err != nil || proc.Sniffer == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	query := restParseQuery(r)

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Check if we can config workload
	wl, err := cacher.GetWorkloadBrief(wlID, "", acc)
	if wl == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if !acc.Authorize(&share.CLUSSnifferDummy{WorkloadDomain: wl.Domain}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if !wl.CapSniff {
		err := "Unable to capture the container traffic"
		log.WithFields(log.Fields{"id": wlID}).Error(err)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err)
		return
	}

	args := proc.Sniffer
	req := &share.CLUSSnifferRequest{WorkloadID: wlID, Cmd: share.SnifferCmd_StartSniffer}
	if args.FileNumber != nil {
		if *args.FileNumber > maxPcapFileNumber {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrNotEnoughFilter,
				fmt.Sprintf("Maximum pcap file count is %v", maxPcapFileNumber))
			return
		}

		req.FileNumber = *args.FileNumber
	} else {
		req.FileNumber = defaultPcapFileNumber
	}

	if args.Duration != nil {
		req.DurationInSecond = *args.Duration
	}

	req.FileSizeInMB = defaultPcapFileSizeInMB

	if args.Filter != nil {
		req.Filter = *args.Filter
	}

	res, err := rpc.SnifferCmd(agentID, req)
	if err != nil {
		switch status.Code(err) {
		case codes.InvalidArgument:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Invalid argument")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		case codes.Internal:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to start sniffer")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrAgentError, "Failed to start sniffer")
		default:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to start sniffer")
			restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		}
		return
	}

	resp := api.RESTSnifferResultData{
		Result: &api.RESTSnifferResult{
			ID: res.ID,
		},
	}
	restRespSuccess(w, r, &resp, acc, login, &proc, "Start sniffer")
}

func handlerSnifferStop(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	agentId, _, err := isSnifferAccessible(id, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	req := &share.CLUSSnifferRequest{ID: id, Cmd: share.SnifferCmd_StopSniffer}
	_, err = rpc.SnifferCmd(agentId, req)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			log.Error("Failed to locate sniffer")
			restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		case codes.InvalidArgument:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Invalid argument")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		case codes.Internal:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to stop sniffer")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrAgentError, "Failed to stop sniffer")
		default:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to stop sniffer")
			restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		}
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Stop sniffer")
}

func handlerSnifferDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	agentId, _, err := isSnifferAccessible(id, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	req := &share.CLUSSnifferRequest{ID: id, Cmd: share.SnifferCmd_RemoveSniffer}
	_, err = rpc.SnifferCmd(agentId, req)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			log.Error("Failed to locate sniffer")
			restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		case codes.InvalidArgument:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Invalid argument")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		case codes.Internal:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to remove sniffer")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrAgentError, "Failed to remove sniffer")
		default:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Debug("Failed to delete sniffer")
			restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		}
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete sniffer")
}

func handlerSnifferGetFile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	agentId, _, err := isSnifferAccessible(id, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	query := restParseQuery(r)

	if query.limit == 0 {
		query.limit = defaultPcapFileSizeInMB * 1024 * 1024 * maxPcapFileNumber
	}

	pcap, err := rpc.GetSnifferPcap(agentId, id, query.limit)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			log.Error("Failed to locate sniffer")
			restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		case codes.Internal:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Error("Failed to download pcap file")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrAgentError, "Failed to download pcap file")
		default:
			log.WithFields(log.Fields{"error": status.Convert(err).Message()}).Debug("Failed to download pcap file")
			restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		}
		return
	}

	mpw := multipart.NewWriter(w)
	defer mpw.Close()

	w.Header().Set("Content-Type", "multipart/form-data; boundary="+mpw.Boundary())
	w.WriteHeader(http.StatusOK)

	filename := id + ".pcap"
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", "pcap", filename))
	h.Set("Content-Type", "application/cap")

	if cfgw, err := mpw.CreatePart(h); err == nil {
		cfgw.Write(pcap)
	}
}
