package scan

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

/*
// The function is only for local test
func parseGolangPackage(file string) {
	f, err := openExe(file)
	if err != nil {
		return
	}
	defer f.Close()

	vers, mod, err := readRawBuildInfo(f, false)
	if err != nil {
		fmt.Printf("%s: %s\n", file, err.Error())
		return
	}

	bi, err := parseBuildInfo(mod)
	if err != nil {
		fmt.Printf("%s: %s\n", file, err.Error())
		return
	}
	bi.GoVersion = vers

	fmt.Printf("%+v\n", bi)
}
*/

var (
	// errUnrecognizedFormat is returned when a given executable file doesn't
	// appear to be in a known format, or it breaks the rules of that format,
	// or when there are I/O errors reading the file.
	errUnrecognizedFormat = errors.New("unrecognized file format")

	// errNotGoExe is returned when a given executable file is valid but does
	// not contain Go build information.
	errNotGoExe = errors.New("not a Go executable")

	// The build info blob left by the linker is identified by
	// a 16-byte header, consisting of buildInfoMagic (14 bytes),
	// the binary's pointer size (1 byte),
	// and whether the binary is big endian (1 byte).
	buildInfoMagic = []byte("\xff Go buildinf:")
)

func readRawBuildInfo(x exe, checkOnly bool) (string, string, error) {
	// Read the first 64kB of text to find the build info blob.
	text := x.DataStart()
	data, err := x.ReadData(text, 64*1024)
	if err != nil {
		return "", "", err
	}

	const (
		buildInfoAlign = 16
		buildInfoSize  = 32
	)
	for {
		i := bytes.Index(data, buildInfoMagic)
		if i < 0 || len(data)-i < buildInfoSize {
			return "", "", errNotGoExe
		}
		if i%buildInfoAlign == 0 && len(data)-i >= buildInfoSize {
			data = data[i:]
			break
		}
		data = data[(i+buildInfoAlign-1)&^(buildInfoAlign-1):]
	}

	if checkOnly {
		return "", "", nil
	}

	// Decode the blob.
	// The first 14 bytes are buildInfoMagic.
	// The next two bytes indicate pointer size in bytes (4 or 8) and endianness
	// (0 for little, 1 for big).
	// Two virtual addresses to Go strings follow that: runtime.buildVersion,
	// and runtime.modinfo.
	// On 32-bit platforms, the last 8 bytes are unused.
	// If the endianness has the 2 bit set, then the pointers are zero
	// and the 32-byte header is followed by varint-prefixed string data
	// for the two string values we care about.
	var vers, mod string

	ptrSize := int(data[14])
	if data[15]&2 != 0 {
		vers, data = decodeString(data[32:])
		mod, _ = decodeString(data)
	} else {
		bigEndian := data[15] != 0
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else if ptrSize == 8 {
			readPtr = bo.Uint64
		} else {
			return "", "", errNotGoExe
		}
		vers = readString(x, ptrSize, readPtr, readPtr(data[16:]))
		mod = readString(x, ptrSize, readPtr, readPtr(data[16+ptrSize:]))
	}
	if vers == "" {
		return "", "", errNotGoExe
	}
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing: sentinel strings delimiting the module info.
		// These are cmd/go/internal/modload.infoStart and infoEnd.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}

	return vers, mod, nil
}

func decodeString(data []byte) (s string, rest []byte) {
	u, n := binary.Uvarint(data)
	if n <= 0 || u >= uint64(len(data)-n) {
		return "", nil
	}
	return string(data[n : uint64(n)+u]), data[uint64(n)+u:]
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := x.ReadData(addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := x.ReadData(dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

type exe interface {
	// Close closes the underlying file.
	Close() error

	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// DataStart returns the writable data segment start address.
	DataStart() uint64
}

// openExe opens file and returns it as an exe.
func openExe(file string) (exe, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 16)
	if _, err := io.ReadFull(f, data); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		e, err := elf.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &elfExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		e, err := pe.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &peExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE")) {
		e, err := macho.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &machoExe{f, e}, nil
	}
	return nil, errUnrecognizedFormat
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	os *os.File
	f  *elf.File
}

func (x *elfExe) Close() error {
	return x.os.Close()
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) DataStart() uint64 {
	for _, s := range x.f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr
		}
	}
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr
		}
	}
	return 0
}

// peExe is the PE (Windows Portable Executable) implementation of the exe interface.
type peExe struct {
	os *os.File
	f  *pe.File
}

func (x *peExe) Close() error {
	return x.os.Close()
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) ReadData(addr, size uint64) ([]byte, error) {
	addr -= x.imageBase()
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(addr-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *peExe) DataStart() uint64 {
	// Assume data is first writable section.
	const (
		IMAGE_SCN_CNT_CODE               = 0x00000020
		IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
		IMAGE_SCN_MEM_EXECUTE            = 0x20000000
		IMAGE_SCN_MEM_READ               = 0x40000000
		IMAGE_SCN_MEM_WRITE              = 0x80000000
		IMAGE_SCN_MEM_DISCARDABLE        = 0x2000000
		IMAGE_SCN_LNK_NRELOC_OVFL        = 0x1000000
		IMAGE_SCN_ALIGN_32BYTES          = 0x600000
	)
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 &&
			sect.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
			return uint64(sect.VirtualAddress) + x.imageBase()
		}
	}
	return 0
}

// machoExe is the Mach-O (Apple macOS/iOS) implementation of the exe interface.
type machoExe struct {
	os *os.File
	f  *macho.File
}

func (x *machoExe) Close() error {
	return x.os.Close()
}

func (x *machoExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			n := seg.Addr + seg.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := seg.ReadAt(data, int64(addr-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *machoExe) DataStart() uint64 {
	// Look for section named "__go_buildinfo".
	for _, sec := range x.f.Sections {
		if sec.Name == "__go_buildinfo" {
			return sec.Addr
		}
	}
	// Try the first non-empty writable segment.
	const RW = 3
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Addr != 0 && seg.Filesz != 0 && seg.Prot == RW && seg.Maxprot == RW {
			return seg.Addr
		}
	}
	return 0
}
