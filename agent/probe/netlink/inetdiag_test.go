package netlink

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const INET_DIAG_INFO = 2

func inetDiagSocket(t *testing.T, bufSize uint) *NetlinkSocket {
	t.Helper()
	ns, err := NewNetlinkSocket(syscall.NETLINK_INET_DIAG, bufSize, 0)
	if err != nil {
		t.Skipf("no NETLINK_INET_DIAG socket here: %v", err)
	}
	return ns
}

func requestTCP4Dump(t *testing.T, ns *NetlinkSocket) {
	t.Helper()
	req := NewNetlinkRequest(SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP)
	msg := NewInetDiagReqV2(syscall.AF_INET, syscall.IPPROTO_TCP, TCP_ALL)
	msg.IDiagExt |= (1 << (INET_DIAG_INFO - 1))
	req.AddData(msg)
	if err := ns.Send(req); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// readDump reads until NLMSG_DONE or NLMSG_ERROR, as the probe does, and
// returns the number of socket records seen.
func readDump(ns *NetlinkSocket) (int, error) {
	records := 0
	for i := 0; i < 1000; i++ {
		msgs, err := ns.Receive()
		if err != nil {
			return records, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return records, nil
			case syscall.NLMSG_ERROR:
				return records, MessageError(m)
			default:
				records++
			}
		}
	}
	return records, errors.New("dump did not finish within 1000 datagrams")
}

// Enough listening sockets that a TCP4 dump spans several datagrams even
// with the probe's 32 KiB buffer.
func openListeners(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { l.Close() })
	}
}

func TestReceiveReportsTruncation(t *testing.T) {
	openListeners(t, 1)
	ns := inetDiagSocket(t, 64)
	defer ns.Close()

	requestTCP4Dump(t, ns)
	_, err := ns.Receive()
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("want a truncation error from a 64-byte buffer, got %v", err)
	}
}

// Why the probe reopens the socket: once a dump is abandoned part-way, the
// same socket answers every later dump request with EBUSY, and only a new
// socket gets a clean dump again.
func TestAbandonedDumpLeavesSocketBusy(t *testing.T) {
	const listeners = 600
	openListeners(t, listeners)
	ns := inetDiagSocket(t, 32*1024)
	defer ns.Close()

	requestTCP4Dump(t, ns)
	first, err := ns.Receive()
	if err != nil {
		t.Fatalf("first datagram: %v", err)
	}
	for _, m := range first {
		if m.Header.Type == syscall.NLMSG_DONE {
			t.Skip("the whole dump fit one datagram, nothing to abandon")
		}
	}

	// Abandon it and ask again, as the probe's next tick does.
	requestTCP4Dump(t, ns)
	if _, err := readDump(ns); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("second dump on the same socket: want EBUSY, got %v", err)
	}

	ns.Close()
	ns = inetDiagSocket(t, 32*1024)
	requestTCP4Dump(t, ns)
	records, err := readDump(ns)
	if err != nil {
		t.Fatalf("dump on a fresh socket: %v", err)
	}
	if records < listeners {
		t.Fatalf("fresh socket saw %d records, want at least the %d listeners", records, listeners)
	}
}

func TestCloseTwice(t *testing.T) {
	ns := inetDiagSocket(t, 1024)
	ns.Close()
	ns.Close()
	if _, err := ns.Receive(); !errors.Is(err, unix.EBADF) {
		t.Fatalf("receive after close: want EBADF, got %v", err)
	}
}
