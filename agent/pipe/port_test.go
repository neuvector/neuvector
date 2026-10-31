package pipe

import (
	"errors"
	"runtime"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestPushContainerPortWithoutMovedInPort(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalNS, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer originalNS.Close()

	testNS, err := netns.New()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("cannot create network namespace: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer testNS.Close()
	defer func() {
		if err := netns.Set(originalNS); err != nil {
			t.Errorf("restore network namespace: %v", err)
		}
	}()

	port := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "nvtest0"}}
	if err := netlink.LinkAdd(port); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("cannot create test port: %v", err)
		}
		t.Fatal(err)
	}

	pair := &InterceptPair{Port: "nvtest0", exPort: "vexmissing"}
	if _, _, err := pushContainerPort(pair); err == nil {
		t.Error("expected an error for the missing moved-in port")
	}
	if _, err := netlink.LinkByName(pair.Port); err != nil {
		t.Errorf("restored port was removed: %v", err)
	}
}
