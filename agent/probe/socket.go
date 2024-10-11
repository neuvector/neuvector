package probe

// #include "../../defs.h"
import "C"

import (
	"fmt"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

type socket struct {
	family   uint8
	protocol uint8
	src      net.IP
	dst      net.IP
	srcPort  uint16
	dstPort  uint16
	inode    uint32
	state    uint8
	srcID    string
	dstID    string
}

type session struct {
	id            uint32
	protocol      uint8
	client        net.IP
	server        net.IP
	clientPort    uint16
	serverPort    uint16
	clientID      string
	serverID      string
	firstSeen     uint32
	application   uint32
	policyId      uint32
	policyAction  uint8
	dirty         bool
	policyIngress bool
}

type inodeEntry struct {
	id    string
	dummy bool
	retry int
}

var sessionID uint32 = 0

func (p *Probe) printSocket(k *socket) {
	fmt.Printf("inode=%d %d src=%s:%d dst=%s:%d state=%s\n",
		k.inode, k.protocol, k.src, k.srcPort, k.dst, k.dstPort,
		netlink.TcpStatesMap[k.state])
}

func (p *Probe) printSession(s *session) {
	fmt.Printf("%d %s:%d -> %s:%d %s -> %s\n",
		s.protocol, s.client, s.clientPort, s.server, s.serverPort,
		container.ShortContainerId(s.clientID), container.ShortContainerId(s.serverID))
}

/*
- Using netlink inet_diag message, we can get local/remote IP and port, as well as socket's
  inode, however, there is no 'real-time' notification, so we can only read it periodically.
  If at the time of reading, the process who opens the socket has been terminated, although
  the socket is still in half-close, it's not possible to get the process that opened the socket.
  Checking all processes' net/tcp file won't help because what we are interested in are those
  host mode containers, their net/tcp files are same as other host process.

- Some IPv4 listening ports and connections are reported as IPv6, we need to read them too.

- Connections from non-host-mode containers to host mode containers have no entries.
  These connections can be reported by normal intercept path.
- Connections from host-mode containers to non-host-mode containers has one entries.
- Connections between host-mode containers has two entries, sometimes in IPv6
*/

// Return inode-to-containerID map. Unready containers are not included.
func (p *Probe) getInode2ContainerMap() map[uint32]*inodeEntry {
	inodeMap := make(map[uint32]*inodeEntry, 0)

	p.lockProcMux()
	defer p.unlockProcMux()

	for pid, c := range p.pidContainerMap {
		if !global.SYS.CheckProcExist(pid) {
			continue
		}

		if inodes, err := osutil.GetProcessSocketInodes(pid); err == nil {
			for inode := range inodes.Iter() {
				inodeMap[inode.(uint32)] = &inodeEntry{id: c.id}
			}
		}
	}

	return inodeMap
}

func (p *Probe) isListenState(k *socket) bool {
	return (k.protocol == syscall.IPPROTO_TCP && k.state == netlink.TCP_LISTEN) ||
		(k.protocol == syscall.IPPROTO_UDP && k.state == netlink.TCP_CLOSE)
}

func (p *Probe) getSessionKey(s *session) string {
	return fmt.Sprintf("%v-%v-%v-%v-%v", s.client, s.server, s.clientPort, s.serverPort, s.protocol)
}

func (p *Probe) updateSessionTable(newMap map[string]*session) []*dp.ConnectionData {
	p.sessionMux.Lock()
	defer p.sessionMux.Unlock()

	// Delete expired session
	for key := range p.sessionTable {
		if _, ok := newMap[key]; !ok {
			delete(p.sessionTable, key)
		}
	}

	now := uint32(time.Now().Unix())

	// Pre-allocate, we could run over.
	connections := make([]*dp.ConnectionData, 0, len(newMap))
	// Update sessions
	for key, s := range newMap {
		conn := dp.Connection{
			IPProto:    s.protocol,
			ClientIP:   s.client,
			ServerIP:   s.server,
			ServerPort: s.serverPort,
			ClientWL:   s.clientID,
			ServerWL:   s.serverID,
			LastSeenAt: now,
		}
		// As we don't detect application for host mode container, set TCP/UCP port 53 as DNS,
		// so the DNS connection lines can be hidden.
		if s.serverPort == 53 {
			s.application = C.DPI_APP_DNS
		}
		conn.Application = s.application

		if s.clientID != "" {
			conn.Ingress = false
		} else {
			conn.Ingress = true
		}

		// When both src and dst are local, we simulate two connections here
		conns := []*dp.Connection{&conn}
		if s.clientID != "" && s.serverID != "" {
			conn2 := conn
			conn2.Ingress = true
			conns = append(conns, &conn2)
		}

		if exist, ok := p.sessionTable[key]; ok {
			var change bool

			// existing session, only report if more info are found
			if exist.clientID == "" && s.clientID != "" {
				exist.clientID = s.clientID
				change = true
			}
			if exist.serverID == "" && s.serverID != "" {
				exist.serverID = s.serverID
				change = true
			}

			if exist.dirty || change {
				exist.dirty = false
				for _, cn := range conns {
					var violation bool
					cn.PolicyId, cn.PolicyAction, violation = p.policyLookupFunc(cn)
					cn.FirstSeenAt = exist.firstSeen
					if cn.PolicyAction != C.DP_POLICY_ACTION_OPEN {
						if cn.PolicyId != exist.policyId || cn.PolicyAction != exist.policyAction {
							exist.policyId = cn.PolicyId
							exist.policyAction = cn.PolicyAction
							exist.policyIngress = cn.Ingress
							if violation {
								cn.Violates = 1
							}
							change = true
						}
					}
					if change {
						connections = append(connections, &dp.ConnectionData{Conn: cn})
					}
				}
			}
		} else {
			// new session
			sessionID++
			s.id = sessionID
			s.policyIngress = conn.Ingress
			for _, cn := range conns {
				var violation bool
				cn.PolicyId, cn.PolicyAction, violation = p.policyLookupFunc(cn)
				cn.FirstSeenAt = now
				cn.Sessions = 1
				if violation {
					cn.Violates = 1
				}
				if cn.PolicyAction != C.DP_POLICY_ACTION_OPEN {
					s.policyId = cn.PolicyId
					s.policyAction = cn.PolicyAction
					s.policyIngress = cn.Ingress
				}
				connections = append(connections, &dp.ConnectionData{Conn: cn})
			}
			s.firstSeen = now
			p.sessionTable[key] = s
		}
	}
	return connections
}

func (p *Probe) GetHostModeSessions(ids utils.Set) []*share.CLUSSession {
	list := make([]*share.CLUSSession, 0)
	now := uint32(time.Now().Unix())

	p.sessionMux.Lock()
	defer p.sessionMux.Unlock()

	for _, s := range p.sessionTable {
		if s.clientID == "" && s.serverID == "" {
			continue
		}

		var id string
		var ingress bool
		if ids != nil {
			if ids.Contains(s.clientID) {
				id = s.clientID
			} else if ids.Contains(s.serverID) {
				id = s.serverID
				ingress = true
			} else {
				continue
			}
		} else {
			// if both client and server are host-mode containers,
			// report the client and egress first.
			if s.clientID != "" {
				id = s.clientID
			} else if s.serverID != "" {
				id = s.serverID
				ingress = true
			}
		}

		cs := share.CLUSSession{
			ID:           s.id,
			Workload:     id,
			EtherType:    syscall.ETH_P_IP,
			IPProto:      uint32(s.protocol),
			ClientIP:     s.client,
			ServerIP:     s.server,
			ClientPort:   uint32(s.clientPort),
			ServerPort:   uint32(s.serverPort),
			PolicyId:     s.policyId,
			PolicyAction: uint32(s.policyAction),
			Application:  s.application,
			Ingress:      ingress,
			Tap:          true,
			HostMode:     true,
		}

		if cs.Ingress != s.policyIngress {
			cs.PolicyId = 0
			cs.PolicyAction = C.DP_POLICY_ACTION_OPEN
		}

		if now > s.firstSeen {
			cs.Age = now - s.firstSeen
		}

		list = append(list, &cs)

		// If both src and dst are local, when showing all sessions,
		// add the ingress session so that it is consistent with dp session show.
		// Session ID is duplicated as well.
		if ids == nil && s.clientID != "" && s.serverID != "" {
			cs2 := cs
			cs2.Workload = s.serverID
			cs2.Ingress = true
			if cs2.Ingress == s.policyIngress {
				cs2.PolicyId = s.policyId
				cs2.PolicyAction = uint32(s.policyAction)
			} else {
				cs2.PolicyId = 0
				cs2.PolicyAction = C.DP_POLICY_ACTION_OPEN
			}
			list = append(list, &cs2)
		}
	}

	return list
}

func (p *Probe) NotifyPolicyChange(containerSet utils.Set) {
	p.sessionMux.Lock()
	defer p.sessionMux.Unlock()

	for _, s := range p.sessionTable {
		if s.dirty {
			continue
		}
		if s.clientID != "" && containerSet.Contains(s.clientID) {
			s.dirty = true
			continue
		}
		if s.serverID != "" && containerSet.Contains(s.serverID) {
			s.dirty = true
			continue
		}
	}
}

// return dummy inode and the node is exist
func (p *Probe) lookupInode(updated *bool, inode uint32, oldInodesMap map[uint32]*inodeEntry) (string, bool) {
	var ifd1 *inodeEntry
	var ok bool
	if p.resetIoNodes {
		p.resetIoNodes = false
	} else {
		// look at the previous inode map first
		ifd1, ok = p.inodesMap[inode]
		if ok {
			if !ifd1.dummy {
				return ifd1.id, true
			}
			// we get the inodes too early, retry 5s
			if ifd1.retry >= 5 {
				return "", false
			}
		}
	}

	if !*updated {
		*updated = true
		// get a new inode map
		p.inodesMap = p.getInode2ContainerMap()
		if ifd2, ok := p.inodesMap[inode]; ok {
			return ifd2.id, true
		}
	} else {
		// lookup from the old map, for the dummy
		ifd1 = oldInodesMap[inode]
	}

	// Cannot map the inode to the process, add a dummy entry to prevent reading fd folder again.
	if ifd1 != nil && ifd1.dummy {
		if ifd1.retry < 5 {
			ifd1.retry++
		}
		p.inodesMap[inode] = ifd1
	} else {
		p.inodesMap[inode] = &inodeEntry{dummy: true}
	}
	mLog.WithFields(log.Fields{"inode": inode, "retry": p.inodesMap[inode].retry}).Debug("Cannot map inode to process")
	return "", false
}

func (p *Probe) getNewConnections() []*dp.ConnectionData {
	oldInodesMap := p.inodesMap
	var updated bool
	listens, connects, err := p.getAllSockets()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to read sockets")
		return nil
	}

	listenPort2ContainerMap := make(map[share.CLUSProtoPort]string, 0)
	sessionMap := make(map[string]*session, 0)

	// Locate all listening ports, inode indicates source process's socket
	for _, k := range listens {
		if id, ok := p.lookupInode(&updated, k.inode, oldInodesMap); ok {
			port := share.CLUSProtoPort{Port: k.srcPort, IPProto: k.protocol}
			listenPort2ContainerMap[port] = id
		}
	}

	// Find out direction of each socket
	for _, k := range connects {
		if p.isListenState(k) {
			continue
		}

		var s *session
		if k.inode == 0 {
			// This normally happens when connection in half-close while process is gone.
			// server -> client
			port := share.CLUSProtoPort{Port: k.srcPort, IPProto: k.protocol}
			if id, ok := listenPort2ContainerMap[port]; ok {
				s = &session{serverID: id, protocol: k.protocol,
					client: k.dst, server: k.src, clientPort: k.dstPort, serverPort: k.srcPort,
				}
			}
		} else if id1, ok := p.lookupInode(&updated, k.inode, oldInodesMap); ok {
			port := share.CLUSProtoPort{Port: k.srcPort, IPProto: k.protocol}
			id2, ok := listenPort2ContainerMap[port]
			if ok && id1 == id2 {
				// server -> client
				s = &session{serverID: id1, protocol: k.protocol,
					client: k.dst, server: k.src, clientPort: k.dstPort, serverPort: k.srcPort,
				}
			} else {
				// client -> server
				s = &session{clientID: id1, protocol: k.protocol,
					client: k.src, server: k.dst, clientPort: k.srcPort, serverPort: k.dstPort,
				}
				/*
					port.Port = k.dstPort
					if id2, ok = listenPort2ContainerMap[port]; ok {
						s.serverID = id2
					}
				*/
			}
		}

		// Container ID cannot located either because the socket is not opened by container, or
		// the container is not ready yet, so ignore them and wait for the next scan.
		if s != nil {
			// Lookup and update session table
			key := p.getSessionKey(s)
			if exist, ok := sessionMap[key]; ok {
				if exist.clientID == "" && s.clientID != "" {
					exist.clientID = s.clientID
				}
				if exist.serverID == "" && s.serverID != "" {
					exist.serverID = s.serverID
				}
			} else {
				sessionMap[key] = s
			}
		}
	}

	return p.updateSessionTable(sessionMap)
}
