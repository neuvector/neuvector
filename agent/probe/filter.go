package probe

import (
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"

	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	posCnMsgData       = syscall.SizeofNlMsghdr + uint32(netlink.SizeofCnMsg)
	posProcEventWhat   = posCnMsgData + uint32(unsafe.Offsetof(netlink.ProcEvent{}.What))
	posProcEventData   = posCnMsgData + uint32(unsafe.Offsetof(netlink.ProcEvent{}.Data))
	posForkChildPid    = posProcEventData + uint32(unsafe.Offsetof(netlink.ProcEventFork{}.ChildPid))
	posForkChildTgid   = posProcEventData + uint32(unsafe.Offsetof(netlink.ProcEventFork{}.ChildTgid))
	posExitProcessPid  = posProcEventData + uint32(unsafe.Offsetof(netlink.ProcEventExit{}.ProcessPid))
	posExitProcessTgid = posProcEventData + uint32(unsafe.Offsetof(netlink.ProcEventExit{}.ProcessTgid))
)

// berkeley packet filter (BPF)
// Filter out unused fork/exit thread's packets
var ProcFilters = []bpf.Instruction{
	bpf.LoadAbsolute{Off: posProcEventWhat, Size: 4}, // load event id
	// FORK
	bpf.JumpIf{Val: utils.Htonl(netlink.PROC_EVENT_FORK), SkipFalse: 7}, // RegA == FORK
	bpf.LoadAbsolute{Off: posForkChildPid, Size: 4},                     // RegA <- child pid
	bpf.StoreScratch{Src: bpf.RegA, N: 0},                               // scratch[0] <- RegA
	bpf.LoadScratch{Dst: bpf.RegX, N: 0},                                // RegX <- scratch[0]
	bpf.LoadAbsolute{Off: posForkChildTgid, Size: 4},                    // RegA <- child tgid
	bpf.JumpIfX{SkipFalse: 1},                                           // RegA == RegX
	bpf.RetConstant{Val: 0xffffffff},                                    // accepted
	bpf.RetConstant{Val: 0x0},                                           // ignored
	// EXIT
	bpf.JumpIf{Val: utils.Htonl(netlink.PROC_EVENT_EXIT), SkipFalse: 7}, // RegA == EXIT
	bpf.LoadAbsolute{Off: posExitProcessPid, Size: 4},                   // RegA <- process pid
	bpf.StoreScratch{Src: bpf.RegA, N: 0},                               // scratch[0] <- RegA
	bpf.LoadScratch{Dst: bpf.RegX, N: 0},                                // RegX <- scratch[0]
	bpf.LoadAbsolute{Off: posExitProcessTgid, Size: 4},                  // RegA <- process tgid
	bpf.JumpIfX{SkipFalse: 1},                                           // RegA == RegX
	bpf.RetConstant{Val: 0xffffffff},                                    // accepted
	bpf.RetConstant{Val: 0x0},                                           // ignored
	// OTHERS
	bpf.RetConstant{Val: 0xfffffff}, // accepting all others
}
