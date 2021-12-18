package netlink

import "unsafe"

const (
	SizeofCnMsg           = 0x14
	SizeofProcCnMcastOp   = 0x04
	SizeofProcEventHeader = 0x10
	SizeofProcEventData   = 0x18
)

const (
	CN_IDX_PROC = 0x1
	CN_VAL_PROC = 0x1
)

// linux/connector.h
type CbId struct {
	idx uint32
	val uint32
}

type CnMsg struct {
	id    CbId
	seq   uint32
	ack   uint32
	len   uint16
	flags uint16
	//data  []uint8
}

func (cm *CnMsg) Serialize() []byte {
	return (*(*[SizeofCnMsg]byte)(unsafe.Pointer(cm)))[:]
}

func (cm *CnMsg) Len() int {
	return SizeofCnMsg
}

func NewCnMsg() *CnMsg {
	return &CnMsg{
		id:  CbId{idx: CN_IDX_PROC, val: CN_VAL_PROC},
		seq: 0,
		ack: 0,
		len: SizeofProcCnMcastOp,
	}
}

type ProcCnMcastOp int

const (
	_ ProcCnMcastOp = iota
	PROC_CN_MCAST_LISTEN
	PROC_CN_MCAST_IGNORE
)

func (op *ProcCnMcastOp) Serialize() []byte {
	return (*(*[SizeofProcCnMcastOp]byte)(unsafe.Pointer(op)))[:]
}

func (op *ProcCnMcastOp) Len() int {
	return SizeofProcCnMcastOp
}

type ProcEventType uint32

const (
	PROC_EVENT_NONE     = 0x00000000
	PROC_EVENT_FORK     = 0x00000001
	PROC_EVENT_EXEC     = 0x00000002
	PROC_EVENT_UID      = 0x00000004
	PROC_EVENT_GID      = 0x00000040
	PROC_EVENT_SID      = 0x00000080
	PROC_EVENT_PTRACE   = 0x00000100
	PROC_EVENT_COMM     = 0x00000200
	PROC_EVENT_COREDUMP = 0x40000000
	PROC_EVENT_EXIT     = 0x80000000
)

type ProcEventData interface {
}

// linux/cn_proc.h
type ProcEvent struct {
	What      ProcEventType
	Cpu       uint32
	Timestamp uint64
	Data      ProcEventData
}

type ProcEventNone struct{}

type ProcEventFork struct {
	ParentPid  int32
	ParentTgid int32
	ChildPid   int32
	ChildTgid  int32
}

type ProcEventExec struct {
	ProcessPid  int32
	ProcessTgid int32
}

type ProcEventUid struct {
	ProcessPid  int32
	ProcessTgid int32
	RUid        uint32
	EUid        uint32
}

type ProcEventGid struct {
	ProcessPid  int32
	ProcessTgid int32
	RGid        uint32
	EGid        uint32
}

type ProcEventExit struct {
	ProcessPid  int32
	ProcessTgid int32
	ExitCode    uint32
}

type ProcEventCoreDump struct {
	ProcessPid  int32
	ProcessTgid int32
}

type ProcEventComm struct {
	ProcessPid  int32
	ProcessTgid int32
	Comm        [16]byte
}

type ProcEventPtrace struct {
	ProcessPid  int32
	ProcessTgid int32
	TracerPid   int32
	TracerTgid  int32
}

type ProcEventSid struct {
	ProcessPid  int32
	ProcessTgid int32
}

type ProcEventAck struct {
	Err uint32
}

func ParseProcEvent(data []byte) *ProcEvent {
	pe := (*ProcEvent)(unsafe.Pointer(&data[SizeofCnMsg]))
	switch pe.What {
	case PROC_EVENT_NONE:
		pe.Data = *(*ProcEventExit)(nil)
	case PROC_EVENT_FORK:
		pe.Data = *(*ProcEventFork)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_EXEC:
		pe.Data = *(*ProcEventExec)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_UID:
		pe.Data = *(*ProcEventUid)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_GID:
		pe.Data = *(*ProcEventGid)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_SID:
		pe.Data = *(*ProcEventSid)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_PTRACE:
		pe.Data = *(*ProcEventPtrace)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_COMM:
		pe.Data = *(*ProcEventComm)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_COREDUMP:
		pe.Data = *(*ProcEventCoreDump)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	case PROC_EVENT_EXIT:
		pe.Data = *(*ProcEventExit)(unsafe.Pointer(&data[SizeofCnMsg+SizeofProcEventHeader]))
	default:
		pe.Data = *(*ProcEventExit)(nil)
	}
	return pe
}
