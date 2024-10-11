package dp

// #include "../../defs.h"
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func dpMsgAppUpdate(msg []byte) {
	var appHdr C.DPMsgAppHdr
	var app C.DPMsgApp

	// Verify header length
	appHdrLen := int(unsafe.Sizeof(appHdr))
	if len(msg) < appHdrLen {
		log.WithFields(log.Fields{"expect": appHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &appHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Verify total length
	ports := int(appHdr.Ports)
	totalLen := appHdrLen + int(unsafe.Sizeof(app))*ports
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"ports": ports, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	mac := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&appHdr.MAC[0]), 6))
	apps := make(map[share.CLUSProtoPort]*share.CLUSApp)

	for i := 0; i < ports; i++ {
		if dbgError := binary.Read(r, binary.BigEndian, &app); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		p := share.CLUSProtoPort{
			Port:    uint16(app.Port),
			IPProto: uint8(app.IPProto),
		}
		apps[p] = &share.CLUSApp{
			CLUSProtoPort: p,
			Proto:         uint32(app.Proto),
			Server:        uint32(app.Server),
			Application:   uint32(app.Application),
		}
	}

	task := DPTask{Task: DP_TASK_APPLICATION, MAC: mac, Apps: apps}
	taskCallback(&task)
}

func dpMsgThreatLog(msg []byte) {
	var tlog C.DPMsgThreatLog

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &tlog); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	jlog := share.CLUSThreatLog{
		ID:          utils.GetTimeUUID(time.Now().UTC()),
		ThreatID:    uint32(tlog.ThreatID),
		Count:       uint32(tlog.Count),
		Action:      uint8(tlog.Action),
		Severity:    uint8(tlog.Severity),
		EtherType:   uint16(tlog.EtherType),
		IPProto:     uint8(tlog.IPProto),
		Application: uint32(tlog.Application),
		CapLen:      uint16(tlog.CapLen),
	}

	jlog.ReportedAt = time.Unix(int64(tlog.ReportedAt), 0).UTC()

	if (tlog.Flags & C.DPLOG_FLAG_PKT_INGRESS) != 0 {
		jlog.PktIngress = true
	}
	if (tlog.Flags & C.DPLOG_FLAG_SESS_INGRESS) != 0 {
		jlog.SessIngress = true
	}
	if (tlog.Flags & C.DPLOG_FLAG_TAP) != 0 {
		jlog.Tap = true
	}
	EPMAC := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&tlog.EPMAC[0]), 6))
	switch jlog.EtherType {
	case syscall.ETH_P_IP:
		jlog.SrcIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.SrcIP[0]), 4))
		jlog.DstIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.DstIP[0]), 4))
	case syscall.ETH_P_IPV6:
		jlog.SrcIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.SrcIP[0]), 16))
		jlog.DstIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.DstIP[0]), 16))
	}
	switch jlog.IPProto {
	case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
		jlog.SrcPort = uint16(tlog.SrcPort)
		jlog.DstPort = uint16(tlog.DstPort)
	case syscall.IPPROTO_ICMP, syscall.IPPROTO_ICMPV6:
		jlog.ICMPCode = uint8(tlog.ICMPCode)
		jlog.ICMPType = uint8(tlog.ICMPType)
	}
	jlog.Msg = C.GoString(&tlog.Msg[0])

	log.WithFields(log.Fields{"log": jlog}).Debug("")

	pkt := C.GoBytes(unsafe.Pointer(&tlog.Packet[0]), C.int(tlog.PktLen))
	jlog.Packet = base64.StdEncoding.EncodeToString(pkt)

	task := DPTask{Task: DP_TASK_THREAT_LOG, SecLog: &jlog, MAC: EPMAC}
	taskCallback(&task)
}

func dpMsgConnection(msg []byte) {
	var connHdr C.DPMsgConnectHdr
	var conn C.DPMsgConnect

	// Verify header length
	connHdrLen := int(unsafe.Sizeof(connHdr))
	if len(msg) < connHdrLen {
		log.WithFields(log.Fields{"expect": connHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &connHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Verify total length
	count := int(connHdr.Connects)
	totalLen := connHdrLen + int(unsafe.Sizeof(conn))*count
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"connects": count, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	conns := make([]*ConnectionData, count)

	for i := 0; i < count; i++ {
		if dbgError := binary.Read(r, binary.BigEndian, &conn); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}

		cc := &Connection{
			ServerPort:   uint16(conn.ServerPort),
			ClientPort:   uint16(conn.ClientPort),
			IPProto:      uint8(conn.IPProto),
			Bytes:        uint64(conn.Bytes),
			Sessions:     uint32(conn.Sessions),
			FirstSeenAt:  uint32(conn.FirstSeenAt),
			LastSeenAt:   uint32(conn.LastSeenAt),
			ThreatID:     uint32(conn.ThreatID),
			Severity:     uint8(conn.Severity),
			PolicyAction: uint8(conn.PolicyAction),
			Application:  uint32(conn.Application),
			PolicyId:     uint32(conn.PolicyId),
			Violates:     uint32(conn.Violates),
			EpSessCurIn:  uint32(conn.EpSessCurIn),
			EpSessIn12:   uint32(conn.EpSessIn12),
			EpByteIn12:   uint64(conn.EpByteIn12),
		}
		switch uint16(conn.EtherType) {
		case syscall.ETH_P_IP:
			cc.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ClientIP[0]), 4))
			cc.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ServerIP[0]), 4))
		case syscall.ETH_P_IPV6:
			cc.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ClientIP[0]), 16))
			cc.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ServerIP[0]), 16))
		}
		if (conn.Flags & C.DPCONN_FLAG_INGRESS) != 0 {
			cc.Ingress = true
		}
		if (conn.Flags & C.DPCONN_FLAG_EXTERNAL) != 0 {
			// Peer that is not on the host or container's subnet
			cc.ExternalPeer = true
		}
		if (conn.Flags & C.DPCONN_FLAG_XFF) != 0 {
			// connection is xff induced
			cc.Xff = true
		}
		if (conn.Flags & C.DPCONN_FLAG_SVC_EXTIP) != 0 {
			// connection has client->svcExtIP violation
			cc.SvcExtIP = true
		}
		if (conn.Flags & C.DPCONN_FLAG_MESH_TO_SVR) != 0 {
			// appcontainer to sidecar connection has
			// client to remote svr detection
			cc.MeshToSvr = true
		}
		if (conn.Flags & C.DPCONN_FLAG_LINK_LOCAL) != 0 {
			// link local 169.254.0.0 is special svc loopback
			// used by cilium CNI
			cc.LinkLocal = true
		}
		if (conn.Flags & C.DPCONN_FLAG_TMP_OPEN) != 0 {
			// temporary OPEN connection
			cc.TmpOpen = true
		}
		if (conn.Flags & C.DPCONN_FLAG_UWLIP) != 0 {
			// uwl connection
			cc.UwlIp = true
		}
		if (conn.Flags & C.DPCONN_FLAG_CHK_NBE) != 0 {
			// connection cross namespace
			cc.Nbe = true
		}
		if (conn.Flags & C.DPCONN_FLAG_NBE_SNS) != 0 {
			// connection cross same namespace
			cc.NbeSns = true
		}

		conns[i] = &ConnectionData{
			EPMAC: net.HardwareAddr(C.GoBytes(unsafe.Pointer(&conn.EPMAC[0]), 6)),
			Conn:  cc,
		}
	}

	task := DPTask{Task: DP_TASK_CONNECTION, Connects: conns}
	taskCallback(&task)
}

func dpMsgFqdnIpUpdate(msg []byte) {
	var fqdnIpHdr C.DPMsgFqdnIpHdr
	var fqdnIp C.DPMsgFqdnIp
	// Verify header length
	fqdnIpHdrLen := int(unsafe.Sizeof(fqdnIpHdr))
	if len(msg) < fqdnIpHdrLen {
		log.WithFields(log.Fields{"expect": fqdnIpHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &fqdnIpHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Verify total length
	ipcnt := int(fqdnIpHdr.IpCnt)
	totalLen := fqdnIpHdrLen + int(unsafe.Sizeof(fqdnIp))*ipcnt
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"ipcnt": ipcnt, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	fqdns := &share.CLUSFqdnIp{
		FqdnIP: make([]net.IP, 0),
	}

	fqdns.FqdnName = C.GoString(&fqdnIpHdr.FqdnName[0])
	if (fqdnIpHdr.Flags & C.DPFQDN_IP_FLAG_VH) != 0 {
		fqdns.Vhost = true
	}

	for i := 0; i < ipcnt; i++ {
		if dbgError := binary.Read(r, binary.BigEndian, &fqdnIp); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		fqdns.FqdnIP = append(fqdns.FqdnIP, net.IP(C.GoBytes(unsafe.Pointer(&fqdnIp.FqdnIP[0]), 4)))
	}
	log.WithFields(log.Fields{"fqdns": fqdns}).Debug("")

	task := DPTask{Task: DP_TASK_FQDN_IP, Fqdns: fqdns}
	taskCallback(&task)
}

func dpMsgIpFqdnStorageUpdate(msg []byte) {
	var ipFqdnStorageUpdateHdr C.DPMsgIpFqdnStorageUpdateHdr
	// Verify header length
	ipFqdnStorageUpdateHdrLen := int(unsafe.Sizeof(ipFqdnStorageUpdateHdr))
	if len(msg) < ipFqdnStorageUpdateHdrLen {
		log.WithFields(log.Fields{"expect": ipFqdnStorageUpdateHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &ipFqdnStorageUpdateHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	ip := net.IP(C.GoBytes(unsafe.Pointer(&ipFqdnStorageUpdateHdr.IP[0]), 4))
	name := C.GoString(&ipFqdnStorageUpdateHdr.Name[0])
	ipFqdnStorageUpdate := &IpFqdnStorageUpdate{
		IP:   ip,
		Name: name,
	}

	log.WithFields(log.Fields{"update ipFqdnStorage": ipFqdnStorageUpdate}).Debug("")

	task := DPTask{Task: DP_TASK_IP_FQDN_STORAGE_UPDATE, FqdnStorageUpdate: ipFqdnStorageUpdate}
	taskCallback(&task)
}

func dpMsgIpFqdnStorageRelease(msg []byte) {
	var ipFqdnStorageReleaseHdr C.DPMsgIpFqdnStorageReleaseHdr
	// Verify header length
	ipFqdnStorageReleaseHdrLen := int(unsafe.Sizeof(ipFqdnStorageReleaseHdr))
	if len(msg) < ipFqdnStorageReleaseHdrLen {
		log.WithFields(log.Fields{"expect": ipFqdnStorageReleaseHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &ipFqdnStorageReleaseHdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	ip := net.IP(C.GoBytes(unsafe.Pointer(&ipFqdnStorageReleaseHdr.IP[0]), 4))

	log.WithFields(log.Fields{"release ipFqdnStorage": ip}).Debug("")

	task := DPTask{Task: DP_TASK_IP_FQDN_STORAGE_RELEASE, FqdnStorageRelease: ip}
	taskCallback(&task)
}

func ParseDPMsgHeader(msg []byte) *C.DPMsgHdr {
	var hdr C.DPMsgHdr

	hdrLen := int(unsafe.Sizeof(hdr))
	if len(msg) < hdrLen {
		log.WithFields(log.Fields{"len": len(msg)}).Error("Short header")
		return nil
	}

	r := bytes.NewReader(msg)
	if dbgError := binary.Read(r, binary.BigEndian, &hdr); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if int(hdr.Length) != len(msg) {
		log.WithFields(log.Fields{
			"kind": hdr.Kind, "expect": hdr.Length, "actual": len(msg),
		}).Error("Wrong message length.")
		return nil
	}

	return &hdr
}

func dpMessenger(msg []byte) {
	hdr := ParseDPMsgHeader(msg)
	if hdr == nil {
		return
	}

	offset := int(unsafe.Sizeof(*hdr))
	switch int(hdr.Kind) {
	case C.DP_KIND_APP_UPDATE:
		dpMsgAppUpdate(msg[offset:])
	case C.DP_KIND_THREAT_LOG:
		dpMsgThreatLog(msg[offset:])
	case C.DP_KIND_CONNECTION:
		dpMsgConnection(msg[offset:])
	case C.DP_KIND_FQDN_UPDATE:
		dpMsgFqdnIpUpdate(msg[offset:])
	case C.DP_KIND_IP_FQDN_STORAGE_UPDATE:
		dpMsgIpFqdnStorageUpdate(msg[offset:])
	case C.DP_KIND_IP_FQDN_STORAGE_RELEASE:
		dpMsgIpFqdnStorageRelease(msg[offset:])
	}
}

func listenDP() {
	log.Debug("Listening to CTRL socket ...")

	os.Remove(ctrlServer)

	var conn *net.UnixConn
	kind := "unixgram"
	addr := net.UnixAddr{Name: ctrlServer, Net: kind}
	defer os.Remove(ctrlServer)
	conn, _ = net.ListenUnixgram(kind, &addr)
	defer conn.Close()

	for {
		var buf [C.DP_MSG_SIZE]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Read message error.")
		} else {
			dpAliveMsgCnt++
			dpMessenger(buf[:n])
		}
	}
}
