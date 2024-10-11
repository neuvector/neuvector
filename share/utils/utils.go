package utils

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/streadway/simpleuuid"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

var IPv4Loopback = net.IPv4(127, 0, 0, 1)

const cliAny string = "any"

const reStrNonPrintable string = "[^\x20-\x7E]"
const reStrURLReserved string = "[/?%& ]"

const readyFile string = "/tmp/ready"

var reNonPrintable, reURLReserved *regexp.Regexp

func NormalizeForURL(name string) string {
	if reNonPrintable == nil || reURLReserved == nil {
		reNonPrintable = regexp.MustCompile(reStrNonPrintable)
		reURLReserved = regexp.MustCompile(reStrURLReserved)
	}

	name = reNonPrintable.ReplaceAllLiteralString(name, "")
	name = reURLReserved.ReplaceAllLiteralString(name, ":")
	return name
}

func MakeServiceName(namespace, name string) string {
	if namespace == "" {
		return name
	} else {
		return fmt.Sprintf("%s%s%s", name, share.DomainDelimiter, namespace)
	}
}

func MakeUserFullname(server, username string) string {
	if server == "" {
		return username
	} else {
		return fmt.Sprintf("%s:%s", server, username)
	}
}

func ResolveIP(name string) ([]net.IP, error) {
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}

	return net.LookupIP(name)
}

func ResolveAddrList(addr string, skipLoopback bool) ([]string, bool) {
	var resolved bool

	addrList := strings.Split(addr, ",")
	ipList := make([]string, 0)
	for _, addr := range addrList {
		if net.ParseIP(addr) != nil {
			ipList = append(ipList, addr)
			continue
		}

		resolved = true

		ips, err := ResolveIP(addr)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"addr": addr}).Error("cannot resolve")
			time.Sleep(time.Second)
			continue
		}

		for i := range ips {
			if skipLoopback && ips[i].IsLoopback() {
				continue
			}
			var dup bool = false
			for _, exist := range ipList {
				if exist == ips[i].String() {
					dup = true
					log.WithFields(log.Fields{"addr": addr}).Error("duplicate addr")
					break
				}
			}
			if !dup {
				ipList = append(ipList, ips[i].String())
			}
		}
	}

	return ipList, resolved
}

func GetFunctionName(f interface{}) string {
	full := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	if n := strings.LastIndexByte(full, '.'); n != -1 {
		return full[n+1:]
	}
	return full
}

func GzipBytes(buf []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(buf); err != nil {
		log.WithFields(log.Fields{"err": err, "len": len(buf)}).Error()
	}
	w.Close()

	return b.Bytes()
}

func GetMd5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func GetGuid() (string, error) {
	b := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return GetMd5(base64.StdEncoding.EncodeToString(b)), nil
}

func GetTimeUUID(t time.Time) string {
	uuid, _ := simpleuuid.NewTime(t)
	return uuid.String()
}

func GetStringUUID(s string) string {
	uuid, _ := simpleuuid.NewString(s)
	return uuid.String()
}

func GetRandomID(length int, prefix string) string {
	id := make([]byte, length)
	if _, err := rand.Read(id); err != nil {
		log.WithFields(log.Fields{"err": err, "prefix": prefix}).Error()
	}
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(id))
}

func HashPassword(password string) string {
	h := sha512.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

var fnvHash hash.Hash32 = fnv.New32a()

func HashStringToInt32(s string, slots int) int {
	fnvHash.Write([]byte(s))
	defer fnvHash.Reset()

	return int(fnvHash.Sum32()) % slots
}

func GunzipBytes(buf []byte) []byte {
	b := bytes.NewBuffer(buf)
	r, err := gzip.NewReader(b)
	if err != nil {
		return nil
	}
	defer r.Close()
	uzb, _ := io.ReadAll(r)
	return uzb
}

func UnzipDataIfValid(value []byte) ([]byte, bool) {
	if uzb := GunzipBytes(value); uzb != nil {
		return uzb, true
	}
	return value, false
}

func ReverseBytesInPlace(a []byte) []byte {
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}

func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func IsIPv6(ip net.IP) bool {
	return ip.To16() != nil
}

func IPv42Int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2IPv4(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

func CompareSliceWithoutOrder(a, b interface{}) bool {
	s1 := NewSetFromSliceKind(a)
	s2 := NewSetFromSliceKind(b)
	return s1.Equal(s2)
}

// ---

func parseQuery(query string) (map[string][]string, error) {
	var err error
	m := make(map[string][]string)

	for query != "" {
		key := query
		if i := strings.IndexAny(key, ";&"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		m[key] = append(m[key], value)
	}

	return m, err
}

type EnvironParser struct {
	kvPairs     map[string]string
	platformEnv map[string][]string
	sysGroups   []*regexp.Regexp
}

func NewEnvironParser(envs []string) *EnvironParser {
	p := EnvironParser{
		kvPairs: make(map[string]string),
	}
	for _, kv := range envs {
		if len(kv) > 0 {
			if i := strings.Index(kv, "="); i == -1 {
				p.kvPairs[kv] = ""
			} else {
				k := kv[:i]
				v := kv[i+1:]
				p.kvPairs[k] = v

				switch k {
				case share.ENV_PLATFORM_INFO:
					// platform=aliyun;if-eth0=local;if-eth1=global
					p.platformEnv, _ = parseQuery(v)
				case share.ENV_SYSTEM_GROUPS:
					// NV_SYSTEM_GROUPS=ucp-*;calico-*
					p.sysGroups = make([]*regexp.Regexp, 0)
					tokens := strings.Split(v, ";")
					for _, t := range tokens {
						t = strings.TrimSpace(t)
						t = strings.Replace(t, "*", ".*", -1)
						if r, err := regexp.Compile(fmt.Sprintf("^%s$", t)); err != nil {
							log.WithFields(log.Fields{"value": v}).Error("Failed to parse system group")
						} else {
							p.sysGroups = append(p.sysGroups, r)
						}
					}
				}
			}
		}
	}
	return &p
}

func (p EnvironParser) GetPlatformEnv() map[string][]string {
	return p.platformEnv
}

func (p EnvironParser) GetPlatformName() (string, string) {
	if p.platformEnv != nil {
		if plts, ok := p.platformEnv[share.ENV_PLT_PLATFORM]; ok && len(plts) > 0 {
			if i := strings.Index(plts[0], ":"); i == -1 {
				return plts[0], ""
			} else {
				return plts[0][:i], plts[0][i+1:]
			}
		}
	}

	return "", ""
}

func (p EnvironParser) GetPlatformIntf(port string) []string {
	if p.platformEnv != nil {
		name := fmt.Sprintf("%s%s", share.ENV_PLT_INTF_PREFIX, port)
		if cfgs, ok := p.platformEnv[name]; ok {
			return cfgs
		}
	}

	return nil
}

func (p EnvironParser) GetSystemGroups() []*regexp.Regexp {
	return p.sysGroups
}

func (p EnvironParser) GetKVPairs() map[string]string {
	return p.kvPairs
}

func (p EnvironParser) Value(key string) (string, bool) {
	v, ok := p.kvPairs[key]
	return v, ok
}

// ---

var benchStatusMessage = map[share.BenchStatus]string{
	share.BenchStatusIdle:                "",
	share.BenchStatusScheduled:           "scheduled",
	share.BenchStatusRunning:             "running",
	share.BenchStatusFinished:            "finished",
	share.BenchStatusNotSupport:          "Running benchmark is not supported by the OS",
	share.BenchStatusDockerHostFail:      "Fail to run Docker benchmark for the node",
	share.BenchStatusDockerContainerFail: "Fail to run Docker benchmark for the container",
	share.BenchStatusKubeMasterFail:      "Fail to run Kubernetes benchmark for the master node",
	share.BenchStatusKubeWorkerFail:      "Fail to run Kubernetes benchmark for the worker node",
}

func BenchStatusToStr(r share.BenchStatus) string {
	if m, ok := benchStatusMessage[r]; ok {
		return m
	} else {
		return "Unknown status"
	}
}

func JoinCommand(cmds []string) string {
	return strings.TrimSpace(strings.Join(cmds, " "))
}

func Proto2Name(ipproto uint8) string {
	switch ipproto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	default:
		return fmt.Sprintf("%d", ipproto)
	}
}

func GetPortLink(ipproto uint8, port uint16) string {
	switch ipproto {
	case syscall.IPPROTO_TCP:
		return fmt.Sprintf("tcp/%d", port)
	case syscall.IPPROTO_UDP:
		return fmt.Sprintf("udp/%d", port)
	case syscall.IPPROTO_ICMP:
		return "icmp"
	default:
		if ipproto != 0 {
			return fmt.Sprintf("ip:%d", ipproto)
		} else {
			return fmt.Sprintf("%d", port)
		}
	}
}

func getPortRange(port string) (uint16, uint16, error) {
	var low, high uint16
	if port == cliAny {
		return 0, 0xffff, nil
	}

	portRange := strings.Split(port, "-")
	if val, err := strconv.Atoi(portRange[0]); err == nil {
		low = uint16(val)
	} else {
		return 0, 0, err
	}

	if len(portRange) == 2 {
		if val, err := strconv.Atoi(portRange[1]); err == nil {
			high = uint16(val)
			if high > low {
				return low, high, nil
			} else {
				return high, low, nil
			}
		} else {
			return 0, 0, err
		}
	} else {
		return low, low, nil
	}
}

func ParsePortRangeLink(name string) (uint8, uint16, uint16, error) {
	if strings.HasPrefix(name, "tcp/") {
		low, high, err := getPortRange(name[4:])
		return syscall.IPPROTO_TCP, low, high, err
	} else if strings.HasPrefix(name, "udp/") {
		low, high, err := getPortRange(name[4:])
		return syscall.IPPROTO_UDP, low, high, err
	} else if name == "icmp" {
		return syscall.IPPROTO_ICMP, 0, 0xffff, nil
	} else if strings.HasPrefix(name, "ip:") {
		if proto, err := strconv.Atoi(name[3:]); err == nil {
			return uint8(proto), 0, 0xffff, nil
		} else {
			return 0, 0, 0, err
		}
	} else if name == cliAny {
		return 0, 0, 0xffff, nil
	} else {
		if low, high, err := getPortRange(name); err == nil {
			return 0, low, high, err
		}
	}
	return 0, 0, 0, fmt.Errorf("Unable to parse %s", name)
}

func getPortRangeStr(port, portR uint16) string {
	if port == portR {
		return fmt.Sprintf("%d", port)
	}

	if port == 0 && portR == 0xffff {
		return cliAny
	} else if port < portR {
		return fmt.Sprintf("%d-%d", port, portR)
	} else {
		return fmt.Sprintf("%d-%d", portR, port)
	}
}

func GetPortRangeLink(ipproto uint8, port uint16, portR uint16) string {
	switch ipproto {
	case syscall.IPPROTO_TCP:
		return fmt.Sprintf("tcp/%s", getPortRangeStr(port, portR))
	case syscall.IPPROTO_UDP:
		return fmt.Sprintf("udp/%s", getPortRangeStr(port, portR))
	case syscall.IPPROTO_ICMP:
		return "icmp"
	default:
		if ipproto != 0 {
			return fmt.Sprintf("ip:%d", ipproto)
		} else {
			return getPortRangeStr(port, portR)
		}
	}
}

func IsHostRelated(addr *share.CLUSWorkloadAddr) bool {
	if strings.HasPrefix(addr.WlID, share.CLUSLearnedHostPrefix) {
		return true
	} else if len(addr.NatPortApp) > 0 {
		return true
	}
	return false
}

func GetCommonPorts(ports1 string, ports2 string) string {
	var p, pp string
	var low, high uint16
	var proto uint8

	p1 := strings.Split(ports1, ",")
	p2 := strings.Split(ports2, ",")
	for _, pp1 := range p1 {
		proto1, low1, high1, err := ParsePortRangeLink(pp1)
		if err != nil {
			// log.WithFields(log.Fields{"port": ports1}).Error("Fail to parse")
			continue
		}
		for _, pp2 := range p2 {
			proto2, low2, high2, err := ParsePortRangeLink(pp2)
			if err != nil {
				// log.WithFields(log.Fields{"port": ports2}).Error("Fail to parse")
				continue
			}

			if proto1 == 0 {
				proto = proto2
			} else if proto2 == 0 {
				proto = proto1
			} else if proto1 == proto2 {
				proto = proto1
			} else {
				continue
			}
			if high1 < low2 || high2 < low1 {
				continue
			}
			if low1 > low2 {
				low = low1
			} else {
				low = low2
			}
			if high1 > high2 {
				high = high2
			} else {
				high = high1
			}
			pp = GetPortRangeLink(proto, low, high)
			if p == "" {
				p = pp
			} else {
				p = fmt.Sprintf("%s,%s", p, pp)
			}
		}
	}
	//log.WithFields(log.Fields{"ports1": ports1, "ports2": ports2, "common": p}).Debug()
	return p
}

func InterpretIP(ip, ipR net.IP) string {
	str := ip.String()
	if ipR != nil {
		strR := ipR.String()
		return str + "-" + strR
	}

	if str == "0.0.0.0" {
		return "external"
	}

	return str
}

func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	b := []byte(ip)
	if IsIPv4(ip) && len(b) >= 4 {
		return val.SetBytes(b[len(b)-4:]), 32
	} else if IsIPv6(ip) && len(b) >= 16 {
		return val.SetBytes(b[len(b)-16:]), 128
	} else {
		return nil, 0
	}
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)
	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding.
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return net.IP(ret)
}

func ipnetToRange(network *net.IPNet) (net.IP, net.IP) {
	// the first IP is easy
	firstIP := network.IP

	// the last IP is the network address OR NOT the mask address
	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		// Easy!
		// But make sure that our two slices are distinct, since they
		// would be in all other cases.
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP
	}

	firstIPInt, bits := ipToInt(firstIP)
	if firstIPInt == nil {
		return nil, nil
	}

	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, intToIP(lastIPInt, bits)
}

func ParseIPRange(value string) (net.IP, net.IP) {
	ipRange := strings.Split(value, "-")
	switch len(ipRange) {
	case 1:
		_, ipnet, err := net.ParseCIDR(ipRange[0])
		if err == nil {
			return ipnetToRange(ipnet)
		} else {
			ip := net.ParseIP(ipRange[0])
			if ip == nil {
				return nil, nil
			}
			return ip, ip
		}
	case 2:
		ip := net.ParseIP(ipRange[0])
		if ip == nil {
			return nil, nil
		}
		ipR := net.ParseIP(ipRange[1])
		if ipR == nil {
			return nil, nil
		}
		return ip, ipR
	default:
		return nil, nil
	}
}

func GetIPEnclosure(ips []net.IP) *net.IPNet {
	val := &big.Int{}
	max := &big.Int{}
	var bits int

	first := true
	for _, ip := range ips {
		if ipInt, ipBits := ipToInt(ip); ipInt != nil {
			if first {
				val.Set(ipInt)
				max.Set(ipInt)
				bits = ipBits
				first = false
			} else if bits != ipBits {
				// mixed ipv4 and ipv6
				return nil
			} else {
				val.And(val, ipInt)
				if max.Cmp(ipInt) < 0 {
					max.Set(ipInt)
				}
			}
		}
	}

	if first {
		return nil
	}

	zeros := max.Sub(max, val).BitLen()
	ipnet := &net.IPNet{IP: intToIP(val, bits), Mask: net.CIDRMask(bits-zeros, bits)}
	return IPNet2Subnet(ipnet)
}

// The first value indicate if two subnets contains one or another, if true then,
// the second value returns 1 if n1 contains n2, -1 if n2 contains n1, 0 if equal.
func SubnetContains(n1, n2 *net.IPNet) (bool, int) {
	l1, r1 := ipnetToRange(n1)
	l2, r2 := ipnetToRange(n2)
	c12 := n1.Contains(l2) && n1.Contains(r2)
	c21 := n2.Contains(l1) && n2.Contains(r1)

	if !c12 && !c21 {
		return false, 0
	} else if c12 && c21 {
		return true, 0
	} else if c12 {
		return true, 1
	} else {
		return true, -1
	}
}

func IPNet2Subnet(ipnet *net.IPNet) *net.IPNet {
	return &net.IPNet{
		IP:   ipnet.IP.Mask(ipnet.Mask),
		Mask: ipnet.Mask,
	}
}

func IPNet2SubnetLoose(ipnet *net.IPNet, scope string) *net.IPNet {
	loose := 8
	if scope == share.CLUSIPAddrScopeGlobal {
		//customers use eg). 10.26.64.0/22 subnet for
		//wl/host inside kube cluster and use 10.26.32.0/22
		//subnet for external, 16 bit loose factor make it
		//impossible to differentiate external from internal,
		//change loose factor to 8
		loose = 8
	}

	// At least /24 or bigger subnet 122
	var ret net.IPNet
	ones, bits := ipnet.Mask.Size()
	if loose > bits {
		loose = bits
	}
	if bits-ones < loose {
		ret.Mask = net.CIDRMask(bits-loose, bits)
	} else {
		ret.Mask = ipnet.Mask
	}
	ret.IP = ipnet.IP.Mask(ret.Mask)
	return &ret
}

func MergeSubnet(subnets map[string]share.CLUSSubnet, snet share.CLUSSubnet) bool {
	for key, sn := range subnets {
		// In case of kubernetes with flannel, containers on each host have their own subnet,
		// such as 172.16.60.0/24, 172.16.14.0/24; and flannel IP has a bigger subnets,
		// 172.16.0.0/16. Here, we check if new subnet and existing subnets containers each other.
		if inc, v := SubnetContains(&sn.Subnet, &snet.Subnet); inc {
			if v == 1 {
				// existing subnet is bigger, ignore new one
				return false
			} else if v == -1 {
				// new subnet is bigger, remove the existing one
				delete(subnets, key)
			}
		}
	}

	subnets[snet.Subnet.String()] = snet
	return true
}

func MergeSpecialSubnet(subnets map[string]share.CLUSSpecSubnet, snet share.CLUSSubnet, iptype string) bool {
	for key, sn := range subnets {
		// In case of kubernetes with flannel, containers on each host have their own subnet,
		// such as 172.16.60.0/24, 172.16.14.0/24; and flannel IP has a bigger subnets,
		// 172.16.0.0/16. Here, we check if new subnet and existing subnets containers each other.
		if inc, v := SubnetContains(&sn.Subnet, &snet.Subnet); inc {
			if v == 1 {
				// existing subnet is bigger, ignore new one
				return false
			} else if v == -1 {
				// new subnet is bigger, remove the existing one
				delete(subnets, key)
			}
		}
	}

	spec_snet := share.CLUSSpecSubnet{Subnet: snet.Subnet, Scope: snet.Scope, IpType: iptype}
	subnets[snet.Subnet.String()] = spec_snet
	return true
}

func IsNativeLittleEndian() bool {
	var x uint32 = 0x01020304
	switch *(*byte)(unsafe.Pointer(&x)) {
	case 0x01:
		return false
	case 0x04:
		return true
	}
	return true
}

func Htonl(v uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, v)
	if IsNativeLittleEndian() {
		return binary.LittleEndian.Uint32(data)
	} else {
		return binary.BigEndian.Uint32(data)
	}
}

// Should only use for debugging
func GetGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func GetCaller(skip int, excludes []string) string {
	var fn string

	pc := make([]uintptr, 20)
	n := runtime.Callers(skip, pc)
	frames := runtime.CallersFrames(pc)
OUTER:
	for i := 0; i < n; i++ {
		frame, more := frames.Next()
		// fmt.Printf("********  %s\n", frame.Function)
		if !more {
			break
		}
		fpath := frame.Function
		for _, exclude := range excludes {
			if strings.Contains(fpath, exclude) {
				continue OUTER
			}
		}
		slash := strings.LastIndex(fpath, "/")
		if slash == -1 {
			fn = fpath
		} else {
			fn = fpath[slash+1:]
		}
		return fn
	}

	return fn
}

// -- Logger

type LogFormatter struct {
	Module string
}

func (f *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Skip 2, 0: callers(), 1: GetCaller, 2: LogFormatter()
	fn := GetCaller(3, []string{"logrus"})

	var keys []string = make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	b := &bytes.Buffer{}

	fmt.Fprintf(b, "%-23s", entry.Time.Format("2006-01-02T15:04:05.999"))
	fmt.Fprintf(b, "|%s|%s|%s:",
		strings.ToUpper(entry.Level.String())[0:4], f.Module, fn)
	if len(entry.Message) > 0 {
		fmt.Fprintf(b, " %s", entry.Message)
	}
	if len(keys) > 0 {
		fmt.Fprintf(b, " - ")
		for i, key := range keys {
			b.WriteString(key)
			b.WriteByte('=')
			fmt.Fprintf(b, "%+v", entry.Data[key])
			if i < len(keys)-1 {
				b.WriteByte(' ')
			}
		}
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// encrypt/decrypt

// When using `nmap -sV --script ssl-enum-ciphers` to check cipher suites, ECDHE will not be detected.
// This is because of a golang issue fixed in 1.20: https://github.com/golang/go/issues/49126
func GetSupportedTLSCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // Obsolete: SEED + 128+256 Bit CBC cipher
		// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // Obsolete: SEED + 128+256 Bit CBC cipher
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
}

func Encrypt(encryptionKey, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return ciphertext, nil
}

func EncryptToBase64(encryptionKey, text []byte) (string, error) {
	if ciphertext, err := Encrypt(encryptionKey, text); err == nil {
		return base64.StdEncoding.EncodeToString(ciphertext), nil
	} else {
		return "", err
	}
}

func Decrypt(encryptionKey, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return text, nil
}

func DecryptFromBase64(encryptionKey []byte, b64 string) (string, error) {
	text, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	if text, err = Decrypt(encryptionKey, text); err == nil {
		return string(text), nil
	} else {
		return "", err
	}
}

func EncryptToRawStdBase64(key, text []byte) (string, error) {
	if ciphertext, err := Encrypt(key, text); err == nil {
		return base64.RawStdEncoding.EncodeToString(ciphertext), nil
	} else {
		return "", err
	}
}

func DecryptFromRawStdBase64(key []byte, b64 string) (string, error) {
	text, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	if text, err = Decrypt(key, text); err == nil {
		return string(text), nil
	} else {
		return "", err
	}
}

func EncryptToRawURLBase64(key, text []byte) (string, error) {
	if ciphertext, err := Encrypt(key, text); err == nil {
		return base64.RawURLEncoding.EncodeToString(ciphertext), nil
	} else {
		return "", err
	}
}

func DecryptFromRawURLBase64(key []byte, b64 string) (string, error) {
	text, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	if text, err = Decrypt(key, text); err == nil {
		return string(text), nil
	} else {
		return "", err
	}
}

func getPasswordSymKey() []byte {
	return passwordSymKey
}

func GetLicenseInfo(license string) (string, error) { // returns license json string
	return "", nil
}

func DecryptPassword(encrypted string) string {
	if encrypted == "" {
		return ""
	}

	password, _ := DecryptFromBase64(getPasswordSymKey(), encrypted)
	return password
}

func EncryptPassword(password string) string {
	if password == "" {
		return ""
	}

	encrypted, _ := EncryptToBase64(getPasswordSymKey(), []byte(password))
	return encrypted
}

func DecryptSensitive(encrypted string, key []byte) string {
	if encrypted == "" {
		return ""
	}

	data, _ := DecryptFromBase64(key, encrypted)
	return data
}

func EncryptSensitive(data string, key []byte) string {
	if data == "" {
		return ""
	}

	encrypted, _ := EncryptToBase64(key, []byte(data))
	return encrypted
}

func DecryptUserToken(encrypted string, key []byte) string {
	if encrypted == "" {
		return ""
	}

	encrypted = strings.ReplaceAll(encrypted, "_", "/")
	if key == nil {
		key = getPasswordSymKey()
	}
	token, _ := DecryptFromRawStdBase64(key, encrypted)
	return token
}

// User token cannot have / in it and cannot have - as the first char.
func EncryptUserToken(token string, key []byte) string {
	if token == "" {
		return ""
	}

	if key == nil {
		key = getPasswordSymKey()
	}

	// Std base64 encoding has + and /, instead of - and _ (url encoding)
	// token can be part of kv key, so we replace / with _
	encrypted, _ := EncryptToRawStdBase64(key, []byte(token))
	encrypted = strings.ReplaceAll(encrypted, "/", "_")
	return encrypted
}

func DecryptURLSafe(encrypted string) string {
	if encrypted == "" {
		return ""
	}

	password, _ := DecryptFromRawURLBase64(getPasswordSymKey(), encrypted)
	return password
}

func EncryptURLSafe(password string) string {
	if password == "" {
		return ""
	}

	encrypted, _ := EncryptToRawURLBase64(getPasswordSymKey(), []byte(password))
	return encrypted
}

// Determine if a directory is a mountpoint, by comparing the device for the directory
// with the device for it's parent.  If they are the same, it's not a mountpoint, if they're
// different, it is.
var reProcessRootPath = regexp.MustCompile(`/proc/\d+/root/`)

func IsMountPoint(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}

	var rootPath string
	rpath := path + "/"
	if indexes := reProcessRootPath.FindStringIndex(rpath); len(indexes) > 1 {
		// take the first matched
		rootPath = rpath[0:indexes[1]] // container scope
	} else {
		rootPath = rpath + ".." // relative: compare its upper folder
	}
	rootStat, err := os.Lstat(rootPath)
	if err != nil {
		return false
	}
	// If the directory has the same device as parent, then it's not a mountpoint.
	return stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev
}

func IsContainerMountFile(pid int, path string) bool {
	rootPath := fmt.Sprintf("/proc/%d/root/.", pid)
	stat, err := os.Stat(filepath.Join(rootPath, path))
	if err != nil {
		return false
	}
	rootStat, err := os.Lstat(rootPath)
	if err != nil {
		return false
	}
	// If the directory has the same device as parent, then it's not a mountpoint.
	return stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev
}

// IsExecutableLinkableFile: explore ELF header
func IsExecutableLinkableFile(path string) bool {
	// checking ELF header
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		header := make([]byte, 0x04)
		if _, err := f.Read(header); err == nil {
			if header[0] == 0x7f && // magic numbers
				header[1] == 0x45 &&
				header[2] == 0x4c &&
				header[3] == 0x46 { // &&
				//	header[16] == 0x02 && // type: exec, can not differ files on docker's base (OS) image
				//	header[17] == 0x00 {
				// fmt.Printf("ELF: %x, %x\n", header[16], header[17])
				return true
			}
		}
	}
	return false
}

// GetFileContentType: explore the content type, only work content at least 512 bytes
func GetFileContentType(buffer []byte) string {
	if len(buffer) < 512 {
		return "unknown-type"
	}

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	return http.DetectContentType(buffer)
}

// ---

// Exec runs the given binary with arguments
func Exec(dir string, bin string, args ...string) ([]byte, error) {
	_, err := exec.LookPath(bin)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	return buf.Bytes(), err
}

func SetReady(value string) error {
	log.WithFields(log.Fields{"value": value}).Info("")
	f, err := os.Create(readyFile)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "value": value}).Error("Unable to create ready file")
		return err
	}
	fmt.Fprintf(f, "%s\n", value)
	f.Close()
	return nil
}

func UnsetReady() error {
	log.Info("")
	return os.Remove(readyFile)
}

// Utilities: find group attribute from the grou's name definitions, based on controller/api/apis.go
var CfgTypeToApiMapping = map[share.TCfgType]string{
	share.Learned:     api.CfgTypeLearned,
	share.UserCreated: api.CfgTypeUserCreated,
	share.GroundCfg:   api.CfgTypeGround,
	share.FederalCfg:  api.CfgTypeFederal,
}

func IsGroupLearned(name string) bool {
	return name == api.AllHostGroup || strings.HasPrefix(name, api.LearnedGroupPrefix)
}

func DoesGroupHavePolicyMode(name string) bool {
	return name == api.AllHostGroup || // Fed.nodes has no policy mode
		(strings.HasPrefix(name, api.LearnedGroupPrefix) && !strings.HasPrefix(name, api.LearnedSvcGroupPrefix))
}

func IsGroupNodes(name string) bool {
	return name == api.AllHostGroup || name == (api.FederalGroupPrefix+api.AllHostGroup)
}

func HasGroupProfiles(name string) bool {
	switch name {
	case "external": // reserved groups
		return false
	case "nodes": // do not expose file monitor
		return true
	}

	// others: user-defined, service groups
	return !strings.HasPrefix(name, api.LearnedSvcGroupPrefix) // not for network address groups
}

func EvaluateGroupType(name string) share.TCfgType { // except CRD type
	if IsGroupLearned(name) {
		return share.Learned
	} else if strings.HasPrefix(name, api.FederalGroupPrefix) {
		return share.FederalCfg
	}
	return share.UserCreated
}

func EvaluateApiCfgType(name string, bCrdType bool) string {
	if !bCrdType {
		cfgtype := EvaluateGroupType(name)
		switch cfgtype {
		case share.Learned:
			return api.CfgTypeUserCreated // api.CfgTypeLearned, not for file rules
		case share.FederalCfg:
			return api.CfgTypeFederal
		default: // share.UserCreated
			return api.CfgTypeUserCreated
		}
	} else {
		return api.CfgTypeGround
	}
}

func FilterIndexKey(path, regex string) string {
	return fmt.Sprintf("%s/%s", path, regex)
}

func IsCustomProfileGroup(group string) bool {
	return HasGroupProfiles(group) && !IsGroupLearned(group)
}

const (
	OS_READ        = 04
	OS_WRITE       = 02
	OS_EX          = 01
	OS_USER_SHIFT  = 6
	OS_GROUP_SHIFT = 3
	OS_OTH_SHIFT   = 0

	OS_USER_X  = OS_EX << OS_USER_SHIFT
	OS_GROUP_X = OS_EX << OS_GROUP_SHIFT
	OS_OTH_X   = OS_EX << OS_OTH_SHIFT
	OS_ALL_X   = OS_USER_X | OS_GROUP_X | OS_OTH_X
)

func IsExecutable(info os.FileInfo, path string) bool {
	mode := info.Mode()
	// log.WithFields(log.Fields{"path": path, "mode": mode, "info": info}).Debug()
	if mode.IsRegular() && (mode.Perm()&OS_ALL_X) > 0 { // TODO: remove the attribute checks
		// TODO: for benign .so and .sh files
		switch filepath.Ext(path) {
		case ".so", ".sh":
			return false
		}
		if strings.Contains(path, ".so.") { // TODO
			return false
		}
		return IsExecutableLinkableFile(path)
	}
	return false
}

// /////
const hashByteRange int64 = 1024

func FileHashCrc32(path string, size int64) uint32 {
	var crc uint32

	if f, err := os.Open(path); err == nil {
		defer f.Close()
		buf := make([]byte, hashByteRange)

		// explore leading section
		if n, err := f.Read(buf); err == nil {
			crc = crc32.ChecksumIEEE(buf[:n])
		}

		if size > hashByteRange {
			// explore ending section
			if _, err := f.Seek(hashByteRange, io.SeekEnd); err == nil {
				if n, err := f.Read(buf); err == nil {
					crc += crc32.ChecksumIEEE(buf[:n])
				} else {
					log.WithFields(log.Fields{"err": err, "path": path, "size": size}).Error()
				}
			}
		}
	}
	return crc
}

func DisplayBytes(num int64) string {
	if kb := num >> 10; kb > 0 {
		if mb := kb >> 10; mb > 0 {
			if gb := mb >> 10; gb > 0 {
				if tb := gb >> 10; tb > 0 {
					return fmt.Sprintf("%d TB", tb)
				} else {
					return fmt.Sprintf("%d GB", gb)
				}
			} else {
				return fmt.Sprintf("%d MB", mb)
			}
		} else {
			return fmt.Sprintf("%d KB", kb)
		}
	}
	return fmt.Sprintf("%d Bytes", num)
}

// //
var regCrdName *regexp.Regexp = regexp.MustCompile(`^([0-9a-z])([0-9a-z-.])*([0-9a-z])$`)
var regDns1122 *regexp.Regexp = regexp.MustCompile(`^[a-z0-9.-]{1}$`)
var regDns1122start *regexp.Regexp = regexp.MustCompile(`^[a-z0-9]{1}$`)

func replaceAtIndex(in string, r rune, i int) string {
	out := []rune(in)
	out[i] = r
	return string(out)
}

func Dns1123NameChg(name string) string {
	if !regCrdName.MatchString(name) {
		length := len(name)
		fmt.Println("string:", name, "failed regex with len ", length)
		for i, char := range name {
			if (i == 0 || i == length-1) && !regDns1122start.MatchString(string(char)) {
				name = replaceAtIndex(name, '0', i)
			} else if !regDns1122.MatchString(string(char)) {
				fmt.Println("char:", string(char), "failed regex")
				name = strings.Replace(name, string(char), "-", -1)
			}
		}
	}
	return name
}

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"

	var seededRand *mathrand.Rand = mathrand.New(
		mathrand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func CompressToZipFile(source, targetFile string) error {
	if _, err := os.Stat(filepath.Dir(targetFile)); os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Dir(targetFile), 0775); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to create profile folder")
			return err
		}
	}

	// create a zip file and zip.Writer
	f, err := os.Create(targetFile)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := zip.NewWriter(f)
	defer writer.Close()

	// go through all the files of the source
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// create a local file header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		// set compression
		header.Method = zip.Deflate

		// set relative path of a file as the header name
		header.Name, err = filepath.Rel(filepath.Dir(source), path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			header.Name += "/"
		}

		// create writer for the file header and save content of the file
		headerWriter, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(headerWriter, f)
		return err
	})
}
