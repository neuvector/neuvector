package cache

// #include "../../defs.h"
import "C"

import (
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
)

func connectPAIFromManagedHost(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip, hostID string) bool {
	/* to be tested
	if conn.ClientWL != "" {
		// This is only possible if this is host-mode container to host-mode container on the same host
		ca.workload = true
		ca.managed = true
		return true
	}
	*/

	remoteCache := getHostCache(hostID)
	if remoteCache == nil || remoteCache.host == nil || remoteCache.host.Name == "" {
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore ingress connection from unknown host")
		return false
	}

	conn.ClientWL = specialEPName(api.LearnedHostPrefix, remoteCache.host.ID)
	if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
		conn.ClientWL = ep
		ca.addrgrp = true
	}

	ca.host = true
	ca.managed = true
	ca.hostID = remoteCache.host.ID

	return true
}

// Handle from host IP connection. We know the IP is on the host subnet (NAT scope).
// Return if connection should be added.
func connectPAIFromHost(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip) bool {
	if remote := getHostIDFromHostIP(net.IP(conn.ClientIP)); remote != "" {
		return connectPAIFromManagedHost(conn, ca, stip, remote)
	} else {
		// From unmanaged host
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
			conn.ClientWL = ep
			ca.addrgrp = true
		} else {
			ep = specialEPName(api.LearnedHostPrefix, net.IP(conn.ClientIP).String())
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, true) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection with old session from unmanaged host")
				return false
			}
			conn.ClientWL = ep
		}

		stip.wlPort = uint16(conn.ServerPort)
		stip.mappedPort = getMappedPortFromWorkloadIPPort(
			conn.ServerWL, uint8(conn.IPProto), uint16(conn.ServerPort))
		ca.host = true
	}

	return true
}

// Check from global IP. We already know the IP is of Global scope.
// Return if connection should be added.
func connectPAIFromGlobal(conn *share.CLUSConnection, ca *nodeAttr, stip *serverTip) bool {
	if wl, alive := getWorkloadFromGlobalIP(net.IP(conn.ClientIP)); wl != "" {
		if alive {
			conn.ClientWL = wl
			stip.wlPort = uint16(conn.ServerPort)
			ca.workload = true
			ca.managed = true
		} else {
			if wouldGenerateUnmanagedEndpoint(conn, true) {
				scheduleControllerResync(resyncRequestReasonEphemeral)
			}
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore ingress connection from left endpoint")
			return false
		}
	} else {
		// From unmanaged workload
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
			conn.ClientWL = ep
			ca.addrgrp = true
		} else {
			ipStr := net.IP(conn.ClientIP).String()
			ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, true) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection with old session from unknown global IP")
				return false
			}
			conn.ClientWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		ca.workload = true
	}

	return true
}

// Given hostID and mapped port on the host, locate the container on the host. If not found, add an
// endpoint of Host:hostname. Return if connection should be added.
func connectPAIToManagedHost(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip, hostID string) bool {
	/* to be tested
	if conn.ServerWL != "" {
		// This is only possible if this is host-mode container to host-mode container on the same host
		cctx.ConnLog.WithFields(log.Fields{
			"client": conn.ClientIP, "server": conn.ServerIP,
		}).Debug("Ignore egress connection to known workload")
		return false
	}
	*/

	var alive bool
	conn.ServerWL, stip.wlPort, alive =
		getWorkloadFromHostIDIPPort(hostID, uint8(conn.IPProto), uint16(conn.ServerPort))
	if conn.ServerWL == "" {
		remoteCache := getHostCache(hostID)
		if remoteCache == nil || remoteCache.host == nil || remoteCache.host.Name == "" {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress connection to unknown host")
			return false
		}

		// If workload cannot be found by server port map, it could be
		// a host process or host-mode container, but could also be
		// a workload unreported yet (TODO)
		conn.ServerWL = specialEPName(api.LearnedHostPrefix, remoteCache.host.ID)
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		}
		stip.wlPort = uint16(conn.ServerPort)

		sa.host = true
		sa.managed = true
		sa.hostID = remoteCache.host.ID
	} else if alive {
		sa.workload = true
		sa.managed = true
	} else {
		cctx.ConnLog.WithFields(log.Fields{
			"server": conn.ServerWL,
		}).Debug("Ignore egress connection to left endpoint")
		return false
	}

	return true
}

// For kubernetes, if dest. is host IP, the dest. could be a host-mode container, otherwise,
// the connection must be terminated at the host.
func connectPAIToHost(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip) bool {
	if remote := getHostIDFromHostIP(net.IP(conn.ServerIP)); remote != "" {
		return connectPAIToManagedHost(conn, sa, stip, remote)
	} else {
		// Unmanaged host
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		} else if ep = getIpAddrGroupName(net.IP(conn.ServerIP).String()); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
			tep := specialEPName(api.LearnedHostPrefix, net.IP(conn.ServerIP).String())
			if wlGraph.DeleteNode(tep) != "" {
				log.WithFields(log.Fields{"endpoint": tep}).Debug("Delete unknown host ip endpoint")
			}
		} else {
			ep = specialEPName(api.LearnedHostPrefix, net.IP(conn.ServerIP).String())
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, false) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore egress connection with old session to unknown host")
				return false
			}
			conn.ServerWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		sa.host = true
	}

	return true
}

// Check to global IP. We already know the IP is of Global scope.
// Return if connection should be added.
func connectPAIToGlobal(conn *share.CLUSConnection, sa *nodeAttr, stip *serverTip) bool {
	if wl, alive := getWorkloadFromGlobalIP(net.IP(conn.ServerIP)); wl != "" {
		if alive == false && wouldGenerateUnmanagedEndpoint(conn, false) {
			scheduleControllerResync(resyncRequestReasonEphemeral)
		}
		if conn.UwlIp {
			// Unmanaged workload
			if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
				conn.ServerWL = ep
				sa.addrgrp = true
			} else {
				ipStr := net.IP(conn.ServerIP).String()
				ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
				conn.ServerWL = ep
			}
			stip.wlPort = uint16(conn.ServerPort)
			sa.workload = true
			return true
		} else if conn.Nbe || conn.NbeSns {
			if alive {
				conn.ServerWL = wl
				stip.wlPort = uint16(conn.ServerPort)
				sa.workload = true
				sa.managed = true
				return true
			}
		}
		cctx.ConnLog.WithFields(log.Fields{
			"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
		}).Debug("Ignore egress connection to global IP space")
		return false
	} else {
		// Unknown workload
		if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
			conn.ServerWL = ep
			sa.addrgrp = true
		} else {
			ipStr := net.IP(conn.ServerIP).String()
			ep = specialEPName(api.LearnedWorkloadPrefix, ipStr)
			if wlGraph.Node(ep) == "" &&
				wouldGenerateUnmanagedEndpoint(conn, false) == false {
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore egress connection with old session to unknown global IP")
				return false
			}
			conn.ServerWL = ep
		}
		stip.wlPort = uint16(conn.ServerPort)
		sa.workload = true
	}

	return true
}

// Assuming all IP are global IP. This is for kubernetes case.
func preProcessConnectPAI(conn *share.CLUSConnection) (*nodeAttr, *nodeAttr, *serverTip, bool) {
	var ca, sa nodeAttr // Client and Server node attributes
	stip := serverTip{wlPort: uint16(conn.ServerPort)}

	// cctx.ConnLog.WithFields(log.Fields{"conversation": conn}).Debug("")

	switch conn.PolicyAction {
	case C.DP_POLICY_ACTION_VIOLATE, C.DP_POLICY_ACTION_DENY:
		cctx.ConnLog.WithFields(log.Fields{
			"ipproto": conn.IPProto, "client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			"port":      conn.ServerPort,
			"action":    common.PolicyActionString(uint8(conn.PolicyAction)),
			"policy_id": conn.PolicyId,
		}).Debug("Detected policy violation")
	}

	// UnknownPeer: IP is not on host or container subnet
	// LocalPeer: IP is a host local IP
	if conn.Ingress {
		sa.workload = true
		sa.managed = true

		if strings.Contains(conn.Network, share.NetworkProxyMesh) && !conn.Xff {
			conn.ClientWL = conn.ServerWL
			ca.external = false
			ca.workload = true
			ca.managed = true
			return &ca, &sa, &stip, true
		} else if conn.TmpOpen {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore ingress temporary open connection")
			return &ca, &sa, &stip, false
		} else if isDeviceIP(net.IP(conn.ClientIP)) {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore ingress connection from nv device")
			return &ca, &sa, &stip, false
		} else if isHostTunnelIP(net.IP(conn.ClientIP)) {
			// Check tunnel IP before LocalPeer
			conn.ClientWL = specialEPName(api.LearnedWorkloadPrefix, api.EndpointIngress)
			if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
				conn.ClientWL = ep
				ca.addrgrp = true
			}
			stip.wlPort = uint16(conn.ServerPort)
			ca.workload = true
		} else if conn.LocalPeer {
			if !connectPAIFromManagedHost(conn, &ca, &stip, conn.HostID) {
				return &ca, &sa, &stip, false
			}
		} else if isHostIP(net.IP(conn.ClientIP).String()) {
			if !connectPAIFromHost(conn, &ca, &stip) {
				return &ca, &sa, &stip, false
			}
		} else {
			switch getIPAddrScope(net.IP(conn.ClientIP)) {
			case "":
				// If the enforcer say it's not from external, respect that.
				if !conn.ExternalPeer {
					if conn.LinkLocal {
						// link local 169.254.0.0 is special svc loopback
						// used by cilium CNI
						conn.ClientWL = conn.ServerWL
						ca.external = false
						ca.workload = true
						ca.managed = true
						return &ca, &sa, &stip, true
					}
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
					}).Debug("Ignore ingress connection from unknown subnet")
					return &ca, &sa, &stip, false
				} else {
					// Not on internal subnets - external
					conn.ClientWL = api.LearnedExternal
					if ep := getAddrGroupNameFromPolicy(conn.PolicyId, true); ep != "" {
						conn.ClientWL = ep
						ca.addrgrp = true
					}
					stip.wlPort = uint16(conn.ServerPort)
					stip.mappedPort = getMappedPortFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), uint16(conn.ServerPort))
					ca.external = true
				}
			case share.CLUSIPAddrScopeNAT:
				if !connectPAIFromHost(conn, &ca, &stip) {
					return &ca, &sa, &stip, false
				}
			case share.CLUSIPAddrScopeGlobal:
				if !connectPAIFromGlobal(conn, &ca, &stip) {
					return &ca, &sa, &stip, false
				}
			default:
				cctx.ConnLog.WithFields(log.Fields{
					"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
				}).Debug("Ignore ingress connection from unknown scope")
				return &ca, &sa, &stip, false
			}
		}
	} else {
		// egress
		ca.workload = true
		ca.managed = true

		if strings.Contains(conn.Network, share.NetworkProxyMesh) && !conn.MeshToSvr {
			conn.ServerWL = conn.ClientWL
			sa.external = false
			sa.workload = true
			sa.managed = true
			return &ca, &sa, &stip, true
		} else if conn.TmpOpen {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress temporary open connection")
			return &ca, &sa, &stip, false
		} else if isDeviceIP(net.IP(conn.ServerIP)) {
			cctx.ConnLog.WithFields(log.Fields{
				"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
			}).Debug("Ignore egress connection to nv device")
			return &ca, &sa, &stip, false
		} else if conn.LocalPeer {
			if !connectPAIToManagedHost(conn, &sa, &stip, conn.HostID) {
				return &ca, &sa, &stip, false
			}
		} else {
			if svc := getSvcAddrGroup(net.IP(conn.ServerIP), uint16(conn.ServerPort)); svc != nil {
				conn.ServerWL = svc.group.Name
				sa.ipsvcgrp = true
				if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
					conn.ServerWL = ep
					sa.addrgrp = true
					return &ca, &sa, &stip, true
				}
				// Ignore egress connection to service group that is hidden
				if isIPSvcGrpHidden(svc) {
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP), "ipsvcgrp": svc.group.Name,
					}).Debug("Ignore egress connection to IP service group")
					return &ca, &sa, &stip, false
				} else {
					return &ca, &sa, &stip, true
				}
			} else if conn.SvcExtIP {
				if ipsvcgrp := getSvcAddrGroupNameByExtIP(net.IP(conn.ServerIP), uint16(conn.ServerPort)); ipsvcgrp != "" {
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
						"svcipgroup": ipsvcgrp,
					}).Debug("extIP connection")
					conn.ServerWL = ipsvcgrp
					sa.ipsvcgrp = true
					return &ca, &sa, &stip, true
				}
			} else if isHostTunnelIP(net.IP(conn.ServerIP)) {
				// We should not see egress traffic to tunnel IP, except
				// that for some udp pkt, we might identify the direction
				// incorrectly. Ignore these traffic.
				cctx.ConnLog.WithFields(log.Fields{
					"conn": conn,
				}).Debug("Ignore egress connection to ingress endpoint")
				return &ca, &sa, &stip, false
			} else if isHostIP(net.IP(conn.ServerIP).String()) {
				if !connectPAIToHost(conn, &sa, &stip) {
					return &ca, &sa, &stip, false
				}
			} else {
				switch getIPAddrScope(net.IP(conn.ServerIP)) {
				case "":
					// If the enforcer say it's not to external, respect that.
					if !conn.ExternalPeer {
						if conn.LinkLocal {
							// link local 169.254.0.0 is special svc loopback
							// used by cilium CNI
							conn.ServerWL = conn.ClientWL
							sa.external = false
							sa.workload = true
							sa.managed = true
							return &ca, &sa, &stip, true
						}
						// Consider it as unknown global workload
						if !connectPAIToGlobal(conn, &sa, &stip) {
							return &ca, &sa, &stip, false
						}
					} else {
						// Not on internal subnets - external
						conn.ServerWL = api.LearnedExternal
						sa.external = true
						if ep := getAddrGroupNameFromPolicy(conn.PolicyId, false); ep != "" {
							conn.ServerWL = ep
							sa.addrgrp = true
						} else if conn.FQDN != "" && conn.PolicyId == 0 {
							//learn to predefined address group
							if fqdngrp := getFqdnAddrGroupName(conn.FQDN); fqdngrp != "" {
								conn.ServerWL = fqdngrp
								sa.addrgrp = true
								cctx.ConnLog.WithFields(log.Fields{
									"ServerWL": conn.ServerWL, "policyaction":conn.PolicyAction,
								}).Debug("To FQDN address group")
							}
						}
						stip.wlPort = uint16(conn.ServerPort)

						//(NVSHAS-4316) external ip can be temporarily identified as workload:ip,
						//so when we connect to external, we check and remove tempory graph node
						tipStr := net.IP(conn.ServerIP).String()
						tnode := specialEPName(api.LearnedWorkloadPrefix, tipStr)

						if wlGraph.DeleteNode(tnode) != "" {
							cctx.ConnLog.WithFields(log.Fields{"tnode": tnode}).Debug("Delete external workload:ip node")
						}
					}
				case share.CLUSIPAddrScopeNAT:
					if !connectPAIToHost(conn, &sa, &stip) {
						return &ca, &sa, &stip, false
					}
				case share.CLUSIPAddrScopeGlobal:
					if !connectPAIToGlobal(conn, &sa, &stip) {
						return &ca, &sa, &stip, false
					}
				default:
					cctx.ConnLog.WithFields(log.Fields{
						"client": net.IP(conn.ClientIP), "server": net.IP(conn.ServerIP),
					}).Debug("Ignore egress connection to unknown scope")
					return &ca, &sa, &stip, false
				}
			}
		}
	}

	// Try to look up application by server port
	if sa.workload && sa.managed {
		if conn.Application == 0 {
			// For protocol application, if they are not identified, we are sure the traffic
			// doesn't match the protocol pattern, so don't assign app by server port.
			app, svr := getAppFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), stip.wlPort)
			if app >= C.DPI_APP_PROTO_MARK {
				conn.Application = app
				stip.appServer = svr
			}
		} else {
			_, stip.appServer = getAppFromWorkloadIPPort(conn.ServerWL, uint8(conn.IPProto), stip.wlPort)
		}
	}

	return &ca, &sa, &stip, true
}
