package main

// #include "../defs.h"
import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/pipe"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const sessionListLimitMax int = 1024
const meterListLimitMax int = 3072
const packetSize int = 2 * 1024 * 1024

type paginationState uint8

const (
	pageUnder paginationState = iota
	pageMiddle
	pageAbove
)

type sessionCountParam struct {
	count *share.CLUSSessionCounter
}

type sessionListParam struct {
	filter share.CLUSFilter
	list   []*share.CLUSSession
	state  paginationState
	stream share.EnforcerService_GetSessionListServer
}

type meterListParam struct {
	filter share.CLUSFilter
	list   []*share.CLUSMeter
	state  paginationState
	stream share.EnforcerService_GetMeterListServer
}

type datapathCountParam struct {
	count *share.CLUSDatapathCounter
}

type RPCService struct {
}

func (rs *RPCService) Kick(ctx context.Context, k *share.CLUSKick) (*share.RPCVoid, error) {
	go func() {
		log.WithFields(log.Fields{"reason": k.Reason}).Info("Kicked")
		restartChan <- nil
	}()
	return &share.RPCVoid{}, nil
}

func (rs *RPCService) sendSessionList(pm *sessionListParam) {
	log.WithFields(log.Fields{"count": len(pm.list)}).Debug("")
	if dbgError := pm.stream.Send(&share.CLUSSessionArray{Sessions: pm.list}); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	pm.list = make([]*share.CLUSSession, 0)
}

func (rs *RPCService) paginateSessionList(pm *sessionListParam) {
	switch pm.state {
	case pageUnder, pageMiddle:
		listLen := uint32(len(pm.list))
		if pm.filter.Start > listLen {
			if len(pm.list) > 0 {
				pm.filter.Start -= listLen
				pm.list = make([]*share.CLUSSession, 0)
			}
		} else if pm.filter.Limit == 0 {
			pm.list = pm.list[pm.filter.Start:]
			pm.filter.Start = 0
			pm.state = pageMiddle
		} else if pm.filter.Start+pm.filter.Limit > listLen {
			pm.list = pm.list[pm.filter.Start:listLen]
			pm.filter.Start = 0
			pm.state = pageMiddle
		} else {
			pm.list = pm.list[pm.filter.Start : pm.filter.Start+pm.filter.Limit]
			pm.filter.Limit = 0
			pm.filter.Start = 0
			pm.state = pageAbove
		}
	case pageAbove:
		if len(pm.list) > 0 {
			pm.list = make([]*share.CLUSSession, 0)
		}
	}
}

func (rs *RPCService) parseSessionListHeader(msg []byte) *C.DPMsgSessionHdr {
	var sessHdr C.DPMsgSessionHdr

	// Verify session header length
	sessHdrLen := int(unsafe.Sizeof(sessHdr))
	if len(msg) < sessHdrLen {
		log.WithFields(log.Fields{
			"expect": sessHdrLen, "actual": len(msg),
		}).Error("Short session header")
		return nil
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &sessHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	// Verify total length
	var sess C.DPMsgSession
	sessions := int(sessHdr.Sessions)
	totalLen := sessHdrLen + int(unsafe.Sizeof(sess))*sessions
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"sessions": sessions, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return nil
	}

	return &sessHdr
}

func (rs *RPCService) convertOneSession(sess *C.DPMsgSession, workload string) *share.CLUSSession {
	s := share.CLUSSession{
		ID:             uint32(sess.ID),
		EtherType:      uint32(sess.EtherType),
		IPProto:        uint32(sess.IPProto),
		Application:    uint32(sess.Application),
		ClientPort:     uint32(sess.ClientPort),
		ServerPort:     uint32(sess.ServerPort),
		ClientState:    uint32(sess.ClientState),
		ServerState:    uint32(sess.ServerState),
		ICMPCode:       uint32(sess.ICMPCode),
		ICMPType:       uint32(sess.ICMPType),
		ClientPkts:     uint32(sess.ClientPkts),
		ServerPkts:     uint32(sess.ServerPkts),
		ClientBytes:    uint64(sess.ClientBytes),
		ServerBytes:    uint64(sess.ServerBytes),
		ClientAsmPkts:  uint32(sess.ClientAsmPkts),
		ServerAsmPkts:  uint32(sess.ServerAsmPkts),
		ClientAsmBytes: uint64(sess.ClientAsmBytes),
		ServerAsmBytes: uint64(sess.ServerAsmBytes),
		Age:            uint32(sess.Age),
		Idle:           uint32(sess.Idle),
		Life:           uint32(sess.Life),
		PolicyAction:   uint32(sess.PolicyAction),
		PolicyId:       uint32(sess.PolicyId),
		Workload:       workload,
		XffApp:         uint32(sess.XffApp),
		XffPort:        uint32(sess.XffPort),
	}
	s.XffIP = net.IP(C.GoBytes(unsafe.Pointer(&sess.XffIP[0]), 4))
	s.ClientMAC = net.HardwareAddr(C.GoBytes(unsafe.Pointer(&sess.ClientMAC[0]), 6))
	s.ServerMAC = net.HardwareAddr(C.GoBytes(unsafe.Pointer(&sess.ServerMAC[0]), 6))
	switch s.EtherType {
	case syscall.ETH_P_IP:
		s.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&sess.ClientIP[0]), 4))
		s.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&sess.ServerIP[0]), 4))
	case syscall.ETH_P_IPV6:
		s.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&sess.ClientIP[0]), 16))
		s.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&sess.ServerIP[0]), 16))
	}
	if (sess.Flags & C.DPSESS_FLAG_INGRESS) != 0 {
		s.Ingress = true
	}
	if (sess.Flags & C.DPSESS_FLAG_TAP) != 0 {
		s.Tap = true
	}
	if (sess.Flags & C.DPSESS_FLAG_MID) != 0 {
		s.Mid = true
	}

	return &s
}

func (rs *RPCService) cbSessionList(buf []byte, param interface{}) bool {
	log.Debug("")

	pm, _ := param.(*sessionListParam)

	if buf == nil {
		log.Error("Empty buffer")
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_SESSION_LIST {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	log.WithFields(log.Fields{"kind": hdr.Kind, "len": hdr.Length, "more": hdr.More}).Debug("")

	if pm.state == pageAbove {
		return hdr.More == 0
	}

	// Check session header
	offset := int(unsafe.Sizeof(*hdr))
	sessHdr := rs.parseSessionListHeader(buf[offset:])
	if sessHdr == nil {
		return true
	}

	sessions := int(sessHdr.Sessions)

	offset += int(unsafe.Sizeof(*sessHdr))
	r := bytes.NewReader(buf[offset:])

	// Going through session list
	var sess C.DPMsgSession
	for i := 0; i < sessions; i++ {
		if dbgError := binary.Read(r, binary.BigEndian, &sess); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		var workload string
		mac := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&sess.EPMAC[0]), 6))
		gInfoRLock()
		if id, ok := gInfo.macContainerMap[mac.String()]; ok {
			workload = id
		}
		gInfoRUnlock()

		// Apply filters
		if pm.filter.Workload != "" && pm.filter.Workload != workload {
			continue
		}
		// Host-mode container sessions all have ID 0. They cannot filtered by ID.
		if pm.filter.ID != 0 && pm.filter.ID != uint32(sess.ID) {
			continue
		}

		pm.list = append(pm.list, rs.convertOneSession(&sess, workload))
	}

	rs.paginateSessionList(pm)
	if len(pm.list) > sessionListLimitMax {
		rs.sendSessionList(pm)
	}

	return hdr.More == 0
}

func (rs *RPCService) GetSessionList(f *share.CLUSFilter, stream share.EnforcerService_GetSessionListServer) error {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	var list []*share.CLUSSession

	// If workload is specified, check if it's host-mode container, to return the result faster.
	if f.Workload != "" {
		var pods utils.Set
		if c, ok := gInfoReadActiveContainer(f.Workload); ok {
			_, parent := getSharedContainer(c.info)
			if isContainerNetHostMode(c.info, parent) {
				// Return child's session if querying the children;
				// return sessions of all children if querying the parent.
				pods = c.pods.Clone()
				pods.Add(c.info.ID)
			}
		}

		if pods != nil {
			// host mode
			list = prober.GetHostModeSessions(pods)
			if dbgError := stream.Send(&share.CLUSSessionArray{Sessions: list}); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return nil
		}

		list = make([]*share.CLUSSession, 0)
	} else {
		// Add host mode container sessions if not filtered by workload.
		// TODO: a bit of hack here. We assume host-mode container won't be filtered later.
		list = prober.GetHostModeSessions(nil)
	}

	param := sessionListParam{stream: stream, filter: *f, list: list, state: pageUnder}
	rs.paginateSessionList(&param)
	if param.state == pageAbove {
		rs.sendSessionList(&param)
		return nil
	}

	dp.DPCtrlListSession(rs.cbSessionList, &param)
	rs.sendSessionList(&param)

	return nil
}

func (rs *RPCService) ClearSession(ctx context.Context, f *share.CLUSFilter) (*share.RPCVoid, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	dp.DPCtrlClearSession(f.ID)
	return &share.RPCVoid{}, nil
}

func (rs *RPCService) sendMeterList(pm *meterListParam) {
	log.WithFields(log.Fields{"count": len(pm.list)}).Debug("")
	if dbgError := pm.stream.Send(&share.CLUSMeterArray{Meters: pm.list}); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	pm.list = make([]*share.CLUSMeter, 0)
}

func (rs *RPCService) paginateMeterList(pm *meterListParam) {
	switch pm.state {
	case pageUnder, pageMiddle:
		listLen := uint32(len(pm.list))
		if pm.filter.Start > listLen {
			if len(pm.list) > 0 {
				pm.filter.Start -= listLen
				pm.list = make([]*share.CLUSMeter, 0)
			}
		} else if pm.filter.Limit == 0 {
			pm.list = pm.list[pm.filter.Start:]
			pm.filter.Start = 0
			pm.state = pageMiddle
		} else if pm.filter.Start+pm.filter.Limit > listLen {
			pm.list = pm.list[pm.filter.Start:listLen]
			pm.filter.Start = 0
			pm.state = pageMiddle
		} else {
			pm.list = pm.list[pm.filter.Start : pm.filter.Start+pm.filter.Limit]
			pm.filter.Limit = 0
			pm.filter.Start = 0
			pm.state = pageAbove
		}
	case pageAbove:
		if len(pm.list) > 0 {
			pm.list = make([]*share.CLUSMeter, 0)
		}
	}
}

func (rs *RPCService) parseMeterListHeader(msg []byte) *C.DPMsgMeterHdr {
	var meterHdr C.DPMsgMeterHdr

	// Verify meter header length
	meterHdrLen := int(unsafe.Sizeof(meterHdr))
	if len(msg) < meterHdrLen {
		log.WithFields(log.Fields{
			"expect": meterHdrLen, "actual": len(msg),
		}).Error("Short meter header")
		return nil
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &meterHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	// Verify total length
	var meter C.DPMsgMeter
	meters := int(meterHdr.Meters)
	totalLen := meterHdrLen + int(unsafe.Sizeof(meter))*meters
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"meters": meters, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return nil
	}

	return &meterHdr
}

func (rs *RPCService) convertOneMeter(meter *C.DPMsgMeter, workload string) *share.CLUSMeter {
	m := share.CLUSMeter{
		Count:      uint32(meter.Count),
		LastCount:  uint32(meter.LastCount),
		Idle:       uint32(meter.Idle),
		MeterID:    uint32(meter.MeterID),
		Span:       uint32(meter.Span),
		UpperLimit: uint32(meter.UpperLimit),
		LowerLimit: uint32(meter.LowerLimit),
		Workload:   workload,
	}

	if (meter.Flags & C.DPMETER_FLAG_IPV4) != 0 {
		m.PeerIP = net.IP(C.GoBytes(unsafe.Pointer(&meter.PeerIP[0]), 4))
	} else {
		m.PeerIP = net.IP(C.GoBytes(unsafe.Pointer(&meter.PeerIP[0]), 16))
	}
	if (meter.Flags & C.DPMETER_FLAG_TAP) != 0 {
		m.Tap = true
	}

	return &m
}

func (rs *RPCService) cbMeterList(buf []byte, param interface{}) bool {
	log.Debug("")

	pm, _ := param.(*meterListParam)

	if buf == nil {
		log.Error("Empty buffer")
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_METER_LIST {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	log.WithFields(log.Fields{"kind": hdr.Kind, "len": hdr.Length, "more": hdr.More}).Debug("")

	if pm.state == pageAbove {
		return hdr.More == 0
	}

	// Check meter header
	offset := int(unsafe.Sizeof(*hdr))
	meterHdr := rs.parseMeterListHeader(buf[offset:])
	if meterHdr == nil {
		return true
	}

	meters := int(meterHdr.Meters)

	offset += int(unsafe.Sizeof(*meterHdr))
	r := bytes.NewReader(buf[offset:])

	// Going through meter list
	var meter C.DPMsgMeter
	for i := 0; i < meters; i++ {
		if dbgError := binary.Read(r, binary.BigEndian, &meter); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		var workload string
		mac := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&meter.EPMAC[0]), 6))
		gInfoRLock()
		if id, ok := gInfo.macContainerMap[mac.String()]; ok {
			workload = id
		}
		gInfoRUnlock()

		// Apply filters
		if pm.filter.Workload != "" && pm.filter.Workload != workload {
			continue
		}

		pm.list = append(pm.list, rs.convertOneMeter(&meter, workload))
	}

	rs.paginateMeterList(pm)
	if len(pm.list) > meterListLimitMax {
		rs.sendMeterList(pm)
	}

	return hdr.More == 0
}

func (rs *RPCService) GetMeterList(f *share.CLUSFilter, stream share.EnforcerService_GetMeterListServer) error {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	var list []*share.CLUSMeter

	param := meterListParam{stream: stream, filter: *f, list: list, state: pageUnder}
	rs.paginateMeterList(&param)
	if param.state == pageAbove {
		rs.sendMeterList(&param)
		return nil
	}

	dp.DPCtrlListMeter(rs.cbMeterList, &param)
	rs.sendMeterList(&param)

	return nil
}

// -- GetStats
func populateTrafficStats(data *share.CLUSStats, stats *C.DPMsgStats) {
	data.Total.SessionIn = uint32(stats.SessionIn)
	data.Total.SessionOut = uint32(stats.SessionOut)
	data.Total.SessionCurIn = uint32(stats.SessionCurIn)
	data.Total.SessionCurOut = uint32(stats.SessionCurOut)
	data.Total.PacketIn = uint64(stats.PacketIn)
	data.Total.PacketOut = uint64(stats.PacketOut)
	data.Total.ByteIn = uint64(stats.ByteIn)
	data.Total.ByteOut = uint64(stats.ByteOut)

	data.Span1.SessionIn = uint32(stats.SessionIn1)
	data.Span1.SessionOut = uint32(stats.SessionOut1)
	data.Span1.PacketIn = uint64(stats.PacketIn1)
	data.Span1.PacketOut = uint64(stats.PacketOut1)
	data.Span1.ByteIn = uint64(stats.ByteIn1)
	data.Span1.ByteOut = uint64(stats.ByteOut1)

	data.Span12.SessionIn = uint32(stats.SessionIn12)
	data.Span12.SessionOut = uint32(stats.SessionOut12)
	data.Span12.PacketIn = uint64(stats.PacketIn12)
	data.Span12.PacketOut = uint64(stats.PacketOut12)
	data.Span12.ByteIn = uint64(stats.ByteIn12)
	data.Span12.ByteOut = uint64(stats.ByteOut12)

	data.Span60.SessionIn = uint32(stats.SessionIn60)
	data.Span60.SessionOut = uint32(stats.SessionOut60)
	data.Span60.PacketIn = uint64(stats.PacketIn60)
	data.Span60.PacketOut = uint64(stats.PacketOut60)
	data.Span60.ByteIn = uint64(stats.ByteIn60)
	data.Span60.ByteOut = uint64(stats.ByteOut60)
}

func cbContainerStats(buf []byte, param interface{}) bool {
	data, _ := param.(*share.CLUSStats)

	if buf == nil {
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_MAC_STATS {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	data.ReadAt = time.Now().UTC().Unix()
	data.Interval = statsInterval

	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])

	var stats C.DPMsgStats
	if dbgError := binary.Read(r, binary.BigEndian, &stats); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	populateTrafficStats(data, &stats)

	return true
}

func cbAgentStats(buf []byte, param interface{}) bool {
	log.Debug("")

	data, _ := param.(*share.CLUSStats)

	if buf == nil {
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_DEVICE_STATS {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	data.ReadAt = time.Now().UTC().Unix()
	data.Interval = statsInterval

	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])

	var stats C.DPMsgStats
	if dbgError := binary.Read(r, binary.BigEndian, &stats); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	populateTrafficStats(data, &stats)

	return true
}

func (rs *RPCService) GetStats(ctx context.Context, f *share.CLUSFilter) (*share.CLUSStats, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	stats := share.CLUSStats{
		Total:  &share.CLUSMetry{},
		Span1:  &share.CLUSMetry{},
		Span12: &share.CLUSMetry{},
		Span60: &share.CLUSMetry{},
	}

	if f.Workload != "" {
		if c, ok := gInfoReadActiveContainer(f.Workload); ok {
			var macs []*net.HardwareAddr
			for _, pair := range c.intcpPairs {
				macs = append(macs, &pair.MAC)
			}

			dp.DPCtrlStatsMAC(macs, cbContainerStats, &stats)

			gInfoRLock()
			system.PopulateSystemStats(&stats, &c.stats)
			gInfoRUnlock()
		}
	} else {
		dp.DPCtrlStatsAgent(cbAgentStats, &stats)

		if agentEnv.runInContainer {
			gInfoRLock()
			system.PopulateSystemStats(&stats, &gInfo.agentStats)
			gInfoRUnlock()
		}
	}

	return &stats, nil
}

func (rs *RPCService) GetGroupStats(ctx context.Context, f *share.CLUSWlIDArray) (*share.CLUSStats, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	stats := share.CLUSStats{
		Total:  &share.CLUSMetry{},
		Span1:  &share.CLUSMetry{},
		Span12: &share.CLUSMetry{},
		Span60: &share.CLUSMetry{},
	}

	if len(f.WlID) > 0 {
		var macs []*net.HardwareAddr
		for _, wld := range f.WlID {
			tstats := share.CLUSStats{
				Total:  &share.CLUSMetry{},
				Span1:  &share.CLUSMetry{},
				Span12: &share.CLUSMetry{},
				Span60: &share.CLUSMetry{},
			}
			if c, ok := gInfoReadActiveContainer(wld); ok {
				for _, pair := range c.intcpPairs {
					macs = append(macs, &pair.MAC)
				}
				gInfoRLock()
				system.PopulateSystemStats(&tstats, &c.stats)
				gInfoRUnlock()
				stats.Span1.CPU += tstats.Span1.CPU
				stats.Span1.Memory += tstats.Span1.Memory
				stats.Span12.CPU += tstats.Span12.CPU
				stats.Span12.Memory += tstats.Span12.Memory
				stats.Span60.CPU += tstats.Span60.CPU
				stats.Span60.Memory += tstats.Span60.Memory
			}
		}
		dp.DPCtrlStatsMAC(macs, cbContainerStats, &stats)
	}

	return &stats, nil
}

// --

func (rs *RPCService) cbSessionCount(buf []byte, param interface{}) bool {
	log.Debug("")

	pm, _ := param.(*sessionCountParam)

	if buf == nil {
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_SESSION_COUNT {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])

	var count C.DPMsgSessionCount
	if dbgError := binary.Read(r, binary.BigEndian, &count); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	pm.count = &share.CLUSSessionCounter{
		CurSessions:     uint32(count.CurSess),
		CurTCPSessions:  uint32(count.CurTCPSess),
		CurUDPSessions:  uint32(count.CurUDPSess),
		CurICMPSessions: uint32(count.CurICMPSess),
		CurIPSessions:   uint32(count.CurIPSess),
	}

	return true
}

func (rs *RPCService) GetSessionCounter(ctx context.Context, v *share.RPCVoid) (*share.CLUSSessionCounter, error) {
	log.Debug("")

	var param sessionCountParam
	dp.DPCtrlCountSession(rs.cbSessionCount, &param)
	return param.count, nil
}

func (rs *RPCService) cbAgentCounter(buf []byte, param interface{}) bool {
	log.Debug("")

	pm, _ := param.(*datapathCountParam)

	if buf == nil {
		return true
	}

	// Check message header
	hdr := dp.ParseDPMsgHeader(buf)
	if hdr == nil {
		return true
	}
	if hdr.Kind != C.DP_KIND_DEVICE_COUNTER {
		log.WithFields(log.Fields{"kind": hdr.Kind}).Error("Invalid message type")
		return true
	}

	// Disable lsof because of NVSHAS-6356, hangs on centos
	// pid := os.Getpid()
	// lsof, _ := sh.Command("lsof", "-Pn", "-p", strconv.Itoa(pid)).Command("grep", "-v", "IPv4\\|IPv6").Output()
	lsof := []byte("lsof disabled")
	ps, _ := sh.Command("ps", "-o", "pid,ppid,vsz,rss,comm", "-g", strconv.Itoa(Agent.Pid)).Output()

	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])

	var count C.DPMsgDeviceCounter
	if dbgError := binary.Read(r, binary.BigEndian, &count); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	pm.count = &share.CLUSDatapathCounter{
		RXPackets:           uint64(count.RXPackets),
		RXDropPackets:       uint64(count.RXDropPackets),
		TXPackets:           uint64(count.TXPackets),
		TXDropPackets:       uint64(count.TXDropPackets),
		ErrorPackets:        uint64(count.ErrorPackets),
		NoWorkloadPackets:   uint64(count.NoWorkloadPackets),
		IPv4Packets:         uint64(count.IPv4Packets),
		IPv6Packets:         uint64(count.IPv6Packets),
		TCPPackets:          uint64(count.TCPPackets),
		TCPNoSessionPackets: uint64(count.TCPNoSessionPackets),
		UDPPackets:          uint64(count.UDPPackets),
		ICMPPackets:         uint64(count.ICMPPackets),
		OtherPackets:        uint64(count.OtherPackets),
		Assemblys:           uint64(count.Assemblys),
		FreedAssemblys:      uint64(count.FreedAssemblys),
		Fragments:           uint64(count.Fragments),
		FreedFragments:      uint64(count.FreedFragments),
		TimeoutFragments:    uint64(count.TimeoutFragments),
		TotalSessions:       uint64(count.TotalSessions),
		TCPSessions:         uint64(count.TCPSessions),
		UDPSessions:         uint64(count.UDPSessions),
		ICMPSessions:        uint64(count.ICMPSessions),
		IPSessions:          uint64(count.IPSessions),
		DropMeters:          uint64(count.DropMeters),
		ProxyMeters:         uint64(count.ProxyMeters),
		CurMeters:           uint64(count.CurMeters),
		CurLogCaches:        uint64(count.CurLogCaches),
		LimitDropConns:      uint64(count.LimitDropConns),
		LimitPassConns:      uint64(count.LimitPassConns),
		ParserSessions:      make([]uint64, C.DPI_PARSER_MAX),
		ParserPackets:       make([]uint64, C.DPI_PARSER_MAX),
		PolicyType1Rules:    uint32(count.PolicyType1Rules),
		PolicyType2Rules:    uint32(count.PolicyType2Rules),
		PolicyDomains:       uint32(count.PolicyDomains),
		PolicyDomainIPs:     uint32(count.PolicyDomainIPs),
		GoRoutines:          uint32(runtime.NumGoroutine()),
		Lsof:                lsof,
		PS:                  ps,
	}

	var i int
	for i = 0; i < C.DPI_PARSER_MAX; i++ {
		pm.count.ParserSessions[i] = uint64(count.ParserSessions[i])
		pm.count.ParserPackets[i] = uint64(count.ParserPackets[i])
	}

	return true
}

func (rs *RPCService) GetDatapathCounter(ctx context.Context, v *share.RPCVoid) (*share.CLUSDatapathCounter, error) {
	log.Debug("")

	var param datapathCountParam
	dp.DPCtrlCounterAgent(rs.cbAgentCounter, &param)
	return param.count, nil
}

func (rs *RPCService) convertIPPolicy(pol *dp.DPWorkloadIPPolicy) *share.CLUSDerivedPolicyRuleArray {
	rules := make([]*share.CLUSDerivedPolicyRule, len(pol.IPRules))
	for i, r := range pol.IPRules {
		rules[i] = &share.CLUSDerivedPolicyRule{
			ID:      r.ID,
			SrcIP:   r.SrcIP,
			DstIP:   r.DstIP,
			SrcIPR:  r.SrcIPR,
			DstIPR:  r.DstIPR,
			Port:    uint32(r.Port),
			PortR:   uint32(r.PortR),
			IPProto: uint32(r.IPProto),
			Action:  uint32(r.Action),
			Ingress: r.Ingress,
			FQDN:    r.Fqdn,
			Apps:    make([]*share.CLUSDerivedPolicyApp, len(r.Apps)),
		}
		for j, a := range r.Apps {
			rules[i].Apps[j] = &share.CLUSDerivedPolicyApp{
				App:    a.App,
				Action: uint32(a.Action),
				RuleID: a.RuleID,
			}
		}
	}
	return &share.CLUSDerivedPolicyRuleArray{Rules: rules}
}

func (rs *RPCService) GetDerivedPolicyRules(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedPolicyRuleMap, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	policy := pe.GetNetworkPolicy()
	var ruleMap map[string]*share.CLUSDerivedPolicyRuleArray
	if f.Workload != "" {
		ruleMap = make(map[string]*share.CLUSDerivedPolicyRuleArray, 1)
		if pInfo, ok := policy[f.Workload]; ok {
			ruleMap[pInfo.Policy.WlID] = rs.convertIPPolicy(&pInfo.Policy)
		}
	} else {
		ruleMap = make(map[string]*share.CLUSDerivedPolicyRuleArray, len(policy))
		for _, pInfo := range policy {
			ruleMap[pInfo.Policy.WlID] = rs.convertIPPolicy(&pInfo.Policy)
		}
	}

	value, _ := json.Marshal(ruleMap)
	zb := utils.GzipBytes(value)
	return &share.CLUSDerivedPolicyRuleMap{RuleByte: zb}, nil
}

func (rs *RPCService) ProbeSummary(ctx context.Context, v *share.RPCVoid) (*share.CLUSProbeSummary, error) {
	summary := prober.GetProbeSummary()
	return summary, nil
}

func (rs *RPCService) ProbeProcessMap(ctx context.Context, v *share.RPCVoid) (*share.CLUSProbeProcessArray, error) {
	procs := prober.GetProcessMap()
	res := &share.CLUSProbeProcessArray{Processes: procs}
	return res, nil
}

func (rs *RPCService) ProbeContainerMap(ctx context.Context, v *share.RPCVoid) (*share.CLUSProbeContainerArray, error) {
	cons := prober.GetContainerMap()
	res := &share.CLUSProbeContainerArray{Containers: cons}
	return res, nil
}

func (rs *RPCService) SnifferCmd(ctx context.Context, req *share.CLUSSnifferRequest) (*share.CLUSSnifferResponse, error) {
	if req.Cmd == share.SnifferCmd_StartSniffer {
		id, err := startSniffer(req)
		return &share.CLUSSnifferResponse{ID: id}, err
	} else if req.Cmd == share.SnifferCmd_StopSniffer {
		return &share.CLUSSnifferResponse{}, stopSniffer(req.ID)
	} else if req.Cmd == share.SnifferCmd_RemoveSniffer {
		return &share.CLUSSnifferResponse{}, removeSniffer(req.ID)
	}
	return &share.CLUSSnifferResponse{}, status.Errorf(codes.InvalidArgument, "Invalid sniffer command")
}

func (rs *RPCService) GetSniffers(ctx context.Context, f *share.CLUSSnifferFilter) (*share.CLUSSnifferArray, error) {
	if f.ID == "" {
		return &share.CLUSSnifferArray{Sniffers: listSniffer(f.Workload)}, nil
	} else {
		return &share.CLUSSnifferArray{Sniffers: showSniffer(f.ID)}, nil
	}
}

func (rs *RPCService) GetSnifferPcap(req *share.CLUSSnifferDownload, stream share.EnforcerService_GetSnifferPcapServer) error {
	log.WithFields(log.Fields{"download": req}).Debug("")

	proc, ok := snifferPidMap[req.ID]
	if !ok {
		log.WithFields(log.Fields{"id": req.ID}).Error("Sniffer not found")
		return status.Errorf(codes.NotFound, "Sniffer not found")
	}

	fileList := getFileList(proc.fileNumber, proc.fileName)
	if len(fileList) > 0 {
		for _, fpath := range fileList {
			if dat, err := os.ReadFile(fpath); err == nil {
				packet := &share.CLUSSnifferPcap{
					Pcap: dat,
				}
				err := stream.Send(packet)
				errCode := status.Code(err)
				if err != nil {
					if errCode != codes.Canceled {
						log.WithFields(log.Fields{"err": err}).Error("GRPC send file fail")
						return err
					}
					break
				}
			}
		}
	}
	return nil
}

func (rs *RPCService) GetContainerLogs(f *share.CLUSContainerLogReq, stream share.EnforcerService_GetContainerLogsServer) error {
	log.WithFields(log.Fields{"filter": f}).Debug("")
	return status.Errorf(codes.Unimplemented, "Get container logs not supported")
	/*
		// OpenShift by default using journald log driver so we can't read the file, but still avoid using docker API for now.
		// data, err := global.RT.GetContainerLogs(Host.Flavor == share.FlavorOpenShift, f.Id, int(f.Start), int(f.Limit))
		data, err := global.RT.GetContainerLogs(false, f.Id, int(f.Start), int(f.Limit))
		if err != nil {
			return status.Errorf(codes.Internal, "Get container log fail, error:%v", err)
		}
		for i := 0; i < len(data); i += packetSize {
			var packet share.CLUSContainerLogRes
			if len(data[i:]) > packetSize {
				packet.LogZb = data[i : i+packetSize-1]
			} else {
				packet.LogZb = data[i:]
			}
			if dbgError := stream.Send(&packet); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		return nil
	*/
}

func (rs *RPCService) RunDockerBench(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	if Host.CapDockerBench {
		bench.RerunDocker(true)
	}
	return &share.RPCVoid{}, nil
}

func (rs *RPCService) RunKubernetesBench(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	if Host.CapKubeBench {
		bench.RerunKube("", "", true)
	}
	return &share.RPCVoid{}, nil
}

func (rs *RPCService) GetFileMonitorFile(ctx context.Context, f *share.CLUSFilter) (*share.CLUSFileMonitorFileArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	if f.Workload == "" {
		files := fileWatcher.GetAllFileMonitorFile()
		res := &share.CLUSFileMonitorFileArray{Files: files}
		return res, nil
	} else {
		c, ok := gInfoReadActiveContainer(f.Workload)
		if !ok {
			return nil, status.Errorf(codes.NotFound, "Container not found")
		}

		files := fileWatcher.GetWatchFileList(c.pid)
		res := &share.CLUSFileMonitorFileArray{Files: files}
		return res, nil
	}
}

func (rs *RPCService) GetProcess(ctx context.Context, f *share.CLUSFilter) (*share.CLUSProcessArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	procs := prober.GetContainerProcs(f.Workload)
	return &share.CLUSProcessArray{Processes: procs}, nil
}

func (rs *RPCService) GetProcessHistory(ctx context.Context, f *share.CLUSFilter) (*share.CLUSProcessArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	procs := prober.GetContainerProcHistory(f.Workload)
	return &share.CLUSProcessArray{Processes: procs}, nil
}

func (rs *RPCService) convertDlpWlRule(dpWlDlpRule *dp.DPWorkloadDlpRule) *share.CLUSDerivedDlpRuleArray {
	clusDlpRuleArray := &share.CLUSDerivedDlpRuleArray{
		Mode:     dpWlDlpRule.Mode,
		DefAct:   (uint32)(dpWlDlpRule.DefAction),
		ApplyDir: (int32)(dpWlDlpRule.ApplyDir),
		WlMacs:   make([]string, 0),
		DlpRules: make([]*share.CLUSDerivedDlpRule, 0),
		WafRules: make([]*share.CLUSDerivedDlpRule, 0),
		Rids:     make([]uint32, 0),
		Wafrids:  make([]uint32, 0),
		RuleType: dpWlDlpRule.RuleType,
	}

	wlmacs := make([]string, len(dpWlDlpRule.WorkloadMac))
	copy(wlmacs, dpWlDlpRule.WorkloadMac)
	clusDlpRuleArray.WlMacs = wlmacs

	dlpRuleNames := make([]*share.CLUSDerivedDlpRule, len(dpWlDlpRule.DlpRuleNames))
	for i, r := range dpWlDlpRule.DlpRuleNames {
		dlpRuleNames[i] = &share.CLUSDerivedDlpRule{
			Name:   r.Name,
			Action: (uint32)(r.Action),
		}
	}
	clusDlpRuleArray.DlpRules = dlpRuleNames

	wafRuleNames := make([]*share.CLUSDerivedDlpRule, len(dpWlDlpRule.WafRuleNames))
	for i, r := range dpWlDlpRule.WafRuleNames {
		wafRuleNames[i] = &share.CLUSDerivedDlpRule{
			Name:   r.Name,
			Action: (uint32)(r.Action),
		}
	}
	clusDlpRuleArray.WafRules = wafRuleNames

	rids := make([]uint32, len(dpWlDlpRule.PolicyRuleIds))
	copy(rids, dpWlDlpRule.PolicyRuleIds)
	clusDlpRuleArray.Rids = rids

	wafrids := make([]uint32, len(dpWlDlpRule.PolWafRuleIds))
	copy(wafrids, dpWlDlpRule.PolWafRuleIds)
	clusDlpRuleArray.Wafrids = wafrids

	return clusDlpRuleArray
}

func (rs *RPCService) GetDerivedDlpRules(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleMap, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	dlpWlRulesInfo := pe.GetNetworkDlpWorkloadRulesInfo()
	var dlpRuleMap map[string]*share.CLUSDerivedDlpRuleArray
	if f.Workload != "" {
		dlpRuleMap = make(map[string]*share.CLUSDerivedDlpRuleArray, 1)
		if dpWlDlpRule, ok := dlpWlRulesInfo[f.Workload]; ok {
			dlpRuleMap[dpWlDlpRule.WlID] = rs.convertDlpWlRule(dpWlDlpRule)
		}
	} else {
		dlpRuleMap = make(map[string]*share.CLUSDerivedDlpRuleArray, len(dlpWlRulesInfo))
		for _, dpWlDlpRule := range dlpWlRulesInfo {
			dlpRuleMap[dpWlDlpRule.WlID] = rs.convertDlpWlRule(dpWlDlpRule)
		}
	}
	return &share.CLUSDerivedDlpRuleMap{DlpRuleMap: dlpRuleMap}, nil
}

func (rs *RPCService) convertDlpRuleEntry(dlpRule *dp.DPDlpRuleEntry) *share.CLUSDerivedDlpRuleEntry {

	derivedDlpRuleEntry := &share.CLUSDerivedDlpRuleEntry{
		Name:     dlpRule.Name,
		ID:       dlpRule.ID,
		Patterns: make([]string, len(dlpRule.Patterns)),
	}
	copy(derivedDlpRuleEntry.Patterns, dlpRule.Patterns)
	return derivedDlpRuleEntry
}

func (rs *RPCService) GetDerivedDlpRuleEntries(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleEntryArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	dlpBldInfo := pe.GetNetworkDlpBuildInfo()
	var dlpRuleEntryArr []*share.CLUSDerivedDlpRuleEntry = make([]*share.CLUSDerivedDlpRuleEntry, len(dlpBldInfo.DlpRulesInfo))
	for i, dlpRuleEntry := range dlpBldInfo.DlpRulesInfo {
		dlpRuleEntryArr[i] = rs.convertDlpRuleEntry(dlpRuleEntry)
	}
	return &share.CLUSDerivedDlpRuleEntryArray{DlpRuleEntries: dlpRuleEntryArr}, nil
}

func (rs *RPCService) GetDerivedDlpRuleMacs(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedDlpRuleMacArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	dlpBldInfo := pe.GetNetworkDlpBuildInfo()
	var dlpRuleMacArr []*share.CLUSDerivedDlpRuleMac = make([]*share.CLUSDerivedDlpRuleMac, 0)
	for dlpRuleMac := range dlpBldInfo.DlpDpMacs.Iter() {
		cdmac := &share.CLUSDerivedDlpRuleMac{
			Mac: dlpRuleMac.(string),
		}
		dlpRuleMacArr = append(dlpRuleMacArr, cdmac)
	}
	return &share.CLUSDerivedDlpRuleMacArray{DlpRuleMacs: dlpRuleMacArr}, nil
}

func (rs *RPCService) GetDerivedWorkloadProcessRule(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedProcessRuleArray, error) {
	log.WithFields(log.Fields{"filter": f}).Debug("")

	if proc, ok := ObtainGroupProcessPolicy(f.Workload); ok && proc != nil {
		profile := &share.CLUSDerivedProcessRuleArray{
			Rules: make([]*share.CLUSDerivedProcessRule, len(proc.Process)),
		}

		for i, pp := range proc.Process {
			profile.Rules[i] = &share.CLUSDerivedProcessRule{
				Name:      pp.Name,
				Path:      pp.Path,
				Action:    pp.Action,
				CreatedAt: uint64(pp.CreatedAt.Unix()),
				UpdateAt:  uint64(pp.UpdatedAt.Unix()),
				GroupName: pp.DerivedGroup,
			}

			if profile.Rules[i].GroupName == "" {
				profile.Rules[i].GroupName = proc.Group // learned service group, fill the name
			}

			var ok bool
			profile.Rules[i].CfgType, ok = utils.CfgTypeToApiMapping[pp.CfgType]
			if !ok {
				profile.Rules[i].CfgType = utils.EvaluateApiCfgType(profile.Rules[i].GroupName, pp.CfgType == share.GroundCfg)
			}
		}

		return profile, nil
	}
	return nil, fmt.Errorf("container not found")
}

func (rs *RPCService) GetDerivedWorkloadFileRule(ctx context.Context, f *share.CLUSFilter) (*share.CLUSDerivedFileRuleArray, error) {
	if file, access, ok := ObtainGroupFilePolicies(f.Workload); ok {
		profile := &share.CLUSDerivedFileRuleArray{
			Rules: make([]*share.CLUSDerivedFileRule, len(file.Filters)+len(file.FiltersCRD)),
		}

		for i, ff := range file.Filters {
			profile.Rules[i] = &share.CLUSDerivedFileRule{
				Filter:    ff.Filter,
				Path:      ff.Path,
				Regex:     ff.Regex,
				Behavior:  ff.Behavior,
				Recursive: ff.Recursive,
				GroupName: ff.DerivedGroup,
			}

			if profile.Rules[i].GroupName == "" {
				profile.Rules[i].GroupName = file.Group // learned service group, fill the name
			}

			profile.Rules[i].CfgType = utils.EvaluateApiCfgType(profile.Rules[i].GroupName, false)
			if access != nil {
				key := utils.FilterIndexKey(ff.Path, ff.Regex)
				if r, ok := access.Filters[key]; ok {
					profile.Rules[i].Apps = r.Apps
				}
			}
		}

		offset := len(file.Filters)
		for _, ff := range file.FiltersCRD {
			profile.Rules[offset] = &share.CLUSDerivedFileRule{
				Filter:    ff.Filter,
				Path:      ff.Path,
				Regex:     ff.Regex,
				Behavior:  ff.Behavior,
				Recursive: ff.Recursive,
				GroupName: ff.DerivedGroup,
			}

			if profile.Rules[offset].GroupName == "" {
				profile.Rules[offset].GroupName = file.Group // learned service group, fill the name
			}

			profile.Rules[offset].CfgType = utils.EvaluateApiCfgType(profile.Rules[offset].GroupName, true)
			if access != nil {
				key := utils.FilterIndexKey(ff.Path, ff.Regex)
				if r, ok := access.FiltersCRD[key]; ok {
					profile.Rules[offset].Apps = r.Apps
				}
			}
			offset += 1
		}
		return profile, nil
	}
	return nil, fmt.Errorf("container not found")
}

func (rs *RPCService) GetContainerIntercept(ctx context.Context, f *share.CLUSFilter) (*share.CLUSWorkloadIntercept, error) {
	if f.Workload == "" {
		return nil, fmt.Errorf("container not found")
	}

	if c, ok := gInfoReadActiveContainer(f.Workload); ok {
		l := make([]*share.CLUSWorkloadInterceptPort, 0, len(c.intcpPairs))
		for _, pair := range c.intcpPairs {
			l = append(l, pipe.GetPortPairDebug(pair))
		}
		return &share.CLUSWorkloadIntercept{ID: f.Workload, Inline: c.inline, Quarantine: c.quar, Ports: l}, nil
	} else {
		return nil, fmt.Errorf("container not found or not running")
	}
}

func (rs *RPCService) ProfilingCmd(ctx context.Context, req *share.CLUSProfilingRequest) (*share.RPCVoid, error) {
	go utils.PerfProfile(req, share.ProfileFolder, "enf.")
	return &share.RPCVoid{}, nil
}
