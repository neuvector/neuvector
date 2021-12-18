#ifndef __DEFS_H__
#define __DEFS_H__

#include <stdint.h>
#include <netinet/tcp.h>

// Definitions are used by both agent and controller, value cannot be changed.

#define DP_MSG_SIZE 8192

#define DPI_ACTION_NONE   0
#define DPI_ACTION_ALLOW  1
#define DPI_ACTION_DROP   2
#define DPI_ACTION_RESET  3
#define DPI_ACTION_BYPASS 4
#define DPI_ACTION_BLOCK  5
#define DPI_ACTION_MAX    6

#define THRT_SEVERITY_INFO     1
#define THRT_SEVERITY_LOW      2
#define THRT_SEVERITY_MEDIUM   3
#define THRT_SEVERITY_HIGH     4
#define THRT_SEVERITY_CRITICAL 5
#define THRT_SEVERITY_MAX      6

#define SESS_STATE_NONE        0
#define SESS_STATE_ESTABLISHED TCP_ESTABLISHED
#define SESS_STATE_SYN_SENT    TCP_SYN_SENT
#define SESS_STATE_SYN_RECV    TCP_SYN_RECV
#define SESS_STATE_FIN_WAIT1   TCP_FIN_WAIT1
#define SESS_STATE_FIN_WAIT2   TCP_FIN_WAIT2
#define SESS_STATE_TIME_WAIT   TCP_TIME_WAIT
#define SESS_STATE_CLOSE       TCP_CLOSE
#define SESS_STATE_CLOSE_WAIT  TCP_CLOSE_WAIT
#define SESS_STATE_LAST_ACK    TCP_LAST_ACK
#define SESS_STATE_LISTEN      TCP_LISTEN
#define SESS_STATE_CLOSING     TCP_CLOSING

#define DPI_APP_BASE_START            DPI_APP_HTTP
#define DPI_APP_HTTP                  1001
#define DPI_APP_SSL                   1002
#define DPI_APP_SSH                   1003
#define DPI_APP_DNS                   1004
#define DPI_APP_DHCP                  1005
#define DPI_APP_NTP                   1006
#define DPI_APP_TFTP                  1007
#define DPI_APP_ECHO                  1008
#define DPI_APP_RTSP                  1009
#define DPI_APP_SIP                   1010

#define DPI_APP_PROTO_MARK            DPI_APP_MYSQL
#define DPI_APP_MYSQL                 2001
#define DPI_APP_REDIS                 2002
#define DPI_APP_ZOOKEEPER             2003
#define DPI_APP_CASSANDRA             2004
#define DPI_APP_MONGODB               2005
#define DPI_APP_POSTGRESQL            2006
#define DPI_APP_KAFKA                 2007
#define DPI_APP_COUCHBASE             2008
#define DPI_APP_WORDPRESS             2009
#define DPI_APP_ACTIVEMQ              2010
#define DPI_APP_COUCHDB               2011
#define DPI_APP_ELASTICSEARCH         2012
#define DPI_APP_MEMCACHED             2013
#define DPI_APP_RABBITMQ              2014
#define DPI_APP_RADIUS                2015
#define DPI_APP_VOLTDB                2016
#define DPI_APP_CONSUL                2017
#define DPI_APP_SYSLOG                2018
#define DPI_APP_ETCD                  2019
#define DPI_APP_SPARK                 2020
#define DPI_APP_APACHE                2021
#define DPI_APP_NGINX                 2022
#define DPI_APP_JETTY                 2023
#define DPI_APP_NODEJS                2024
#define DPI_APP_ERLANG_EPMD           2025 //no erlang epmd application expose, it will transfer to application couchbase/couchdb/rabbitmq, etc.
#define DPI_APP_TNS                   2026
#define DPI_APP_TDS                   2027
#define DPI_APP_GRPC                  2028
#define DPI_APP_MAX                   2029

#define DPI_APP_UNKNOWN               0
#define DPI_APP_NOT_CHECKED           1    //just for report purpose

// Exposed for debug purpose, if need to change the order, should create a map
// between exposed and dp internal values
#define DPI_PARSER_HTTP               0
#define DPI_PARSER_SSL                1
#define DPI_PARSER_SSH                2
#define DPI_PARSER_DNS                3
#define DPI_PARSER_DHCP               4
#define DPI_PARSER_NTP                5
#define DPI_PARSER_TFTP               6
#define DPI_PARSER_ECHO               7
#define DPI_PARSER_MYSQL              8
#define DPI_PARSER_REDIS              9
#define DPI_PARSER_ZOOKEEPER          10
#define DPI_PARSER_CASSANDRA          11
#define DPI_PARSER_MONGODB            12
#define DPI_PARSER_POSTGRESQL         13
#define DPI_PARSER_KAFKA              14
#define DPI_PARSER_COUCHBASE          15
#define DPI_PARSER_SPARK              16
#define DPI_PARSER_TNS                17
#define DPI_PARSER_TDS                18
#define DPI_PARSER_GRPC               19
#define DPI_PARSER_MAX                20

// Volume based
#define THRT_ID_SYN_FLOOD       1001
#define THRT_ID_ICMP_FLOOD      1002
#define THRT_ID_IP_SRC_SESSION  1003

// Pattern based
#define THRT_ID_BAD_PACKET           2001
#define THRT_ID_IP_TEARDROP          2002
#define THRT_ID_TCP_SYN_DATA         2003
#define THRT_ID_TCP_SPLIT_HDSHK      2004
#define THRT_ID_TCP_NODATA           2005
#define THRT_ID_PING_DEATH           2006
#define THRT_ID_DNS_LOOP_PTR         2007
#define THRT_ID_SSH_VER_1            2008
#define THRT_ID_SSL_HEARTBLEED       2009
#define THRT_ID_SSL_CIPHER_OVF       2010
#define THRT_ID_SSL_VER_2OR3         2011
#define THRT_ID_SSL_TLS_1DOT0        2012
#define THRT_ID_HTTP_NEG_LEN         2013
#define THRT_ID_HTTP_SMUGGLING       2014
#define THRT_ID_HTTP_SLOWLORIS       2015
#define THRT_ID_TCP_SMALL_WINDOW     2016
#define THRT_ID_DNS_OVERFLOW         2017
#define THRT_ID_MYSQL_ACCESS_DENY    2018
#define THRT_ID_DNS_ZONE_TRANSFER    2019
#define THRT_ID_ICMP_TUNNELING       2020
#define THRT_ID_DNS_TYPE_NULL        2021
#define THRT_ID_SQL_INJECTION        2022
#define THRT_ID_APACHE_STRUTS_RCE    2023
#define THRT_ID_DNS_TUNNELING        2024
#define THRT_ID_TCP_SMALL_MSS        2025
#define THRT_ID_K8S_EXTIP_MITM       2026
#define THRT_ID_MAX                  2027


// --- messages
// Message format shares between processes in agent, which is upgraded together,
// value can be changed.

#define DP_KIND_APP_UPDATE     1
#define DP_KIND_SESSION_LIST   2
#define DP_KIND_SESSION_COUNT  3
#define DP_KIND_DEVICE_COUNTER 4
#define DP_KIND_METER_LIST     5
#define DP_KIND_THREAT_LOG     6
#define DP_KIND_CONNECTION     7
#define DP_KIND_MAC_STATS      8
#define DP_KIND_DEVICE_STATS   9
#define DP_KIND_KEEP_ALIVE     10
#define DP_KIND_FQDN_UPDATE    11

typedef struct {
    uint8_t  Kind;
    uint8_t  More;
    uint16_t Length;   // DPMsgHdr + Msg
} DPMsgHdr;

typedef struct {
    uint16_t Port;
    uint16_t Proto;
    uint16_t Server;
    uint16_t Application;
    uint8_t  IPProto;
} DPMsgApp;

typedef struct {
    uint8_t  MAC[6];
    uint16_t Ports;
    // DPMsgApp Apps[0];
} DPMsgAppHdr;

typedef struct {
    uint32_t CurSess;
    uint32_t CurTCPSess;
    uint32_t CurUDPSess;
    uint32_t CurICMPSess;
    uint32_t CurIPSess;
} DPMsgSessionCount;

#define DPSESS_FLAG_INGRESS   0x01
#define DPSESS_FLAG_TAP       0x02
#define DPSESS_FLAG_MID       0x04
#define DPSESS_FLAG_EXTERNAL  0x08 // remote peer is not local
#define DPSESS_FLAG_XFF       0x10 // virtual xff connection 
#define DPSESS_FLAG_SVC_EXTIP 0x20 // service externalIP 

#define DP_POLICY_APPLY_EGRESS  0x1
#define DP_POLICY_APPLY_INGRESS 0x2

#define DP_POLICY_ACTION_OPEN          0
#define DP_POLICY_ACTION_LEARN         1
#define DP_POLICY_ACTION_ALLOW         2
#define DP_POLICY_ACTION_CHECK_APP     3
#define DP_POLICY_ACTION_VIOLATE       4
#define DP_POLICY_ACTION_DENY          5

#define DP_POLICY_APP_ANY      0
#define DP_POLICY_APP_UNKNOWN  0xffffffff

#define DP_POLICY_FQDN_MAX_ENTRIES  2048
#define DP_POLICY_FQDN_NAME_MAX_LEN 256

#define CFG_ADD       1
#define CFG_MODIFY    2
#define CFG_DELETE    3

#define MSG_START    0x1
#define MSG_END      0x2

#define DP_DLP_RULE_NAME_MAX_LEN 256
#define DP_DLP_RULE_PATTERN_MAX_LEN 512

typedef struct {
    uint32_t ID;
    uint8_t  EPMAC[6];
    uint16_t EtherType;
    uint8_t  ClientMAC[6];
    uint8_t  ServerMAC[6];
    uint8_t  ClientIP[16];
    uint8_t  ServerIP[16];
    uint16_t ClientPort;
    uint16_t ServerPort;
    uint8_t  ICMPCode;
    uint8_t  ICMPType;
    uint8_t  IPProto;
    uint8_t  Flags;
    uint32_t ClientPkts;
    uint32_t ServerPkts;
    uint32_t ClientBytes;
    uint32_t ServerBytes;
    uint32_t ClientAsmPkts;
    uint32_t ServerAsmPkts;
    uint32_t ClientAsmBytes;
    uint32_t ServerAsmBytes;
    uint8_t  ClientState;
    uint8_t  ServerState;
    uint16_t Idle;
    uint32_t Age;
    uint16_t Life;
    uint16_t Application;
    uint32_t ThreatID;
    uint32_t PolicyId;
    uint8_t  PolicyAction;
    uint8_t  Severity;
    uint8_t  XffIP[16];
    uint16_t XffApp;
    uint16_t XffPort;
} DPMsgSession;
    
typedef struct {
    uint16_t Sessions;
    uint16_t Reserved;
    // DPMsgSession Sessions[0];
} DPMsgSessionHdr;

#define DPMETER_FLAG_IPV4    0x01
#define DPMETER_FLAG_TAP     0x02

#define METER_ID_SYN_FLOOD      0
#define METER_ID_ICMP_FLOOD     1
#define METER_ID_IP_SRC_SESSION 2
#define METER_ID_TCP_NODATA     3

typedef struct {
    uint8_t  EPMAC[6];
    uint16_t Idle;
    uint32_t Count;
    uint32_t LastCount;
    uint8_t  PeerIP[16];
    uint8_t  MeterID;
    uint8_t  Flags;
    uint8_t  Span;
    uint32_t UpperLimit;
    uint32_t LowerLimit;
} DPMsgMeter;

typedef struct {
    uint16_t Meters;
    uint16_t Reserved;
    // DPMsgMeter Meters[0];
} DPMsgMeterHdr;

typedef struct {
    uint64_t RXPackets;
    uint64_t RXDropPackets;
    uint64_t TXPackets;
    uint64_t TXDropPackets;
    uint64_t ErrorPackets;
    uint64_t NoWorkloadPackets;
    uint64_t IPv4Packets;
    uint64_t IPv6Packets;
    uint64_t TCPPackets;
    uint64_t TCPNoSessionPackets;
    uint64_t UDPPackets;
    uint64_t ICMPPackets;
    uint64_t OtherPackets;
    uint64_t Assemblys;
    uint64_t FreedAssemblys;
    uint64_t Fragments;
    uint64_t FreedFragments;
    uint64_t TimeoutFragments;
    uint64_t TotalSessions;
    uint64_t TCPSessions;
    uint64_t UDPSessions;
    uint64_t ICMPSessions;
    uint64_t IPSessions;
    uint64_t DropMeters;
    uint64_t ProxyMeters;
    uint64_t CurMeters;
    uint64_t CurLogCaches;
    uint64_t ParserSessions[DPI_PARSER_MAX];
    uint64_t ParserPackets[DPI_PARSER_MAX];
    uint32_t PolicyType1Rules;
    uint32_t PolicyType2Rules;
    uint32_t PolicyDomains;
    uint32_t PolicyDomainIPs;
    uint64_t LimitDropConns;
    uint64_t LimitPassConns;
} DPMsgDeviceCounter;

typedef struct {
    uint32_t Interval;
    uint32_t Padding;

    uint32_t SessionIn;
    uint32_t SessionOut;
    uint32_t SessionCurIn;
    uint32_t SessionCurOut;
    uint64_t PacketIn;
    uint64_t PacketOut;
    uint64_t ByteIn;
    uint64_t ByteOut;

    uint32_t SessionIn1;
    uint32_t SessionOut1;
    uint64_t PacketIn1;
    uint64_t PacketOut1;
    uint64_t ByteIn1;
    uint64_t ByteOut1;

    uint32_t SessionIn12;
    uint32_t SessionOut12;
    uint64_t PacketIn12;
    uint64_t PacketOut12;
    uint64_t ByteIn12;
    uint64_t ByteOut12;

    uint32_t SessionIn60;
    uint32_t SessionOut60;
    uint64_t PacketIn60;
    uint64_t PacketOut60;
    uint64_t ByteIn60;
    uint64_t ByteOut60;
} DPMsgStats;

#define DPLOG_MAX_MSG_LEN         64
#define DPLOG_MAX_PKT_LEN       2048

#define DPLOG_FLAG_PKT_INGRESS  0x01
#define DPLOG_FLAG_SESS_INGRESS 0x02
#define DPLOG_FLAG_TAP          0x04

typedef struct {
    uint32_t ThreatID;
    uint32_t ReportedAt;
    uint32_t Count;
    uint8_t  Action;
    uint8_t  Severity;
    uint8_t  IPProto;
    uint8_t  Flags;
    uint8_t  EPMAC[6];
    uint16_t EtherType;
    uint8_t  SrcIP[16];
    uint8_t  DstIP[16];
    uint16_t SrcPort;
    uint16_t DstPort;
    uint8_t  ICMPCode;
    uint8_t  ICMPType;
    uint16_t Application;
    uint16_t PktLen;    // Packet content length copied into 'Packet'
    uint16_t CapLen;    // Captured packet length on the wire
    char Msg[DPLOG_MAX_MSG_LEN];
    char Packet[DPLOG_MAX_PKT_LEN];
    uint32_t DlpNameHash;
} DPMsgThreatLog;

#define DPCONN_FLAG_INGRESS   0x01
#define DPCONN_FLAG_EXTERNAL  0x02
#define DPCONN_FLAG_XFF       0x04
#define DPCONN_FLAG_SVC_EXTIP 0x08

typedef struct {
    uint8_t  EPMAC[6];
    uint8_t  IPProto;
    uint8_t  Flags;
    uint16_t ServerPort;
    uint16_t ClientPort;
    uint8_t  ClientIP[16];
    uint8_t  ServerIP[16];
    uint16_t EtherType;
    uint16_t Padding;
    uint32_t Bytes;  // Delta to last sent
    uint32_t Sessions;
    uint32_t FirstSeenAt;
    uint32_t LastSeenAt;
    uint16_t Application;
    uint8_t  PolicyAction;
    uint8_t  Severity;
    uint32_t PolicyId;
    uint32_t Violates;
    uint32_t ThreatID;
} DPMsgConnect;

typedef struct {
    uint16_t Connects;
    uint16_t Reserved;
    // DPMsgConnect Connect[0];
} DPMsgConnectHdr;

typedef struct {
    uint8_t  FqdnIP[16];
} DPMsgFqdnIp;

typedef struct {
    char  FqdnName[DP_POLICY_FQDN_NAME_MAX_LEN];
    uint16_t IpCnt;
    uint16_t Reserved;
} DPMsgFqdnIpHdr;

#endif
