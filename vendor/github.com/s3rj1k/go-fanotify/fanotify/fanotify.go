// Package fanotify package provides a simple fanotify API.
package fanotify

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Procfs constants.
const (
	ProcFsFd     = "/proc/self/fd"
	ProcFsFdInfo = "/proc/self/fdinfo"
)

// FdInfo describes '/proc/PID/fdinfo/%d'.
type FdInfo struct {
	Position int
	Flags    int // octal
	MountID  int
}

// EventMetadata is a struct returned from 'NotifyFD.GetEvent'.
type EventMetadata struct {
	unix.FanotifyEventMetadata
}

// GetPID return PID from event metadata.
func (metadata *EventMetadata) GetPID() int {
	return int(metadata.Pid)
}

// Close is used to Close event Fd, use it to prevent Fd leak.
func (metadata *EventMetadata) Close() error {
	if err := unix.Close(int(metadata.Fd)); err != nil {
		return fmt.Errorf("fanotify: failed to close Fd: %w", err)
	}

	return nil
}

// GetPath returns path to file for FD inside event metadata.
func (metadata *EventMetadata) GetPath() (string, error) {
	path, err := os.Readlink(
		filepath.Join(
			ProcFsFd,
			strconv.FormatUint(
				uint64(metadata.Fd),
				10,
			),
		),
	)
	if err != nil {
		return "", fmt.Errorf("fanotify: %w", err)
	}

	return path, nil
}

// GetFdInfo returns parsed '/proc/self/fdinfo/%d' data.
func (metadata *EventMetadata) GetFdInfo() (FdInfo, error) {
	var out FdInfo

	content, err := ioutil.ReadFile(
		filepath.Join(
			ProcFsFdInfo,
			strconv.FormatUint(
				uint64(metadata.Fd),
				10,
			),
		),
	)
	if err != nil {
		return out, fmt.Errorf("cnotifyd: procfs error, %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))

	for scanner.Scan() {
		s := scanner.Text()

		var i int64

		switch {
		case strings.HasPrefix(s, "pos:"):
			if i, err = strconv.ParseInt(
				strings.TrimSpace(strings.TrimPrefix(s, "pos:")), 10, 32,
			); err != nil {
				return out, fmt.Errorf("cnotifyd: procfs error, %w", err)
			}

			out.Position = int(i)
		case strings.HasPrefix(s, "flags:"):
			if i, err = strconv.ParseInt(
				strings.TrimSpace(strings.TrimPrefix(s, "flags:")), 8, 32,
			); err != nil {
				return out, fmt.Errorf("cnotifyd: procfs error, %w", err)
			}

			out.Flags = int(i)
		case strings.HasPrefix(s, "mnt_id:"):
			if i, err = strconv.ParseInt(
				strings.TrimSpace(strings.TrimPrefix(s, "mnt_id:")), 10, 32,
			); err != nil {
				return out, fmt.Errorf("cnotifyd: procfs error, %w", err)
			}

			out.MountID = int(i)
		}
	}

	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("cnotifyd: procfs error, %w", err)
	}

	return out, nil
}

// MatchMask returns 'true' when event metadata matches specified mask.
func (metadata *EventMetadata) MatchMask(mask int) bool {
	return (metadata.Mask & uint64(mask)) == uint64(mask)
}

// File returns pointer to os.File created from event metadata supplied Fd.
// File needs to be Closed after usage.
func (metadata *EventMetadata) File() *os.File {
	// The fd used in os.NewFile() can be garbage collected, making the fd
	// used to create it invalid. This can be problematic, as now the fd can
	// be closed when the os.File created here is GC/Close() or when our
	// function Close() is used too.
	//
	// To avoid having so many references to the same fd and have one close
	// silently invalidate other users, we dup() the fd. This way, a new fd
	// is created every time File() is used and this even works if File() is
	// used multiple times (they never point to the same fd).
	//
	// For more details on when this can happen, see:
	// https://pkg.go.dev/os#File.Fd, that is referenced from:
	// https://pkg.go.dev/os#NewFile
	fd, err := unix.Dup(int(metadata.Fd))
	if err != nil {
		return nil
	}

	return os.NewFile(uintptr(fd), "")
}

// NotifyFD is a notify file handle, used by all fanotify functions.
type NotifyFD struct {
	Fd   int
	File *os.File
	Rd   io.Reader
}

// Initialize initializes the fanotify support.
func Initialize(fanotifyFlags uint, openFlags int) (*NotifyFD, error) {
	fd, err := unix.FanotifyInit(fanotifyFlags, uint(openFlags))
	if err != nil {
		return nil, fmt.Errorf("fanotify: init error, %w", err)
	}

	file := os.NewFile(uintptr(fd), "")
	rd := bufio.NewReader(file)

	return &NotifyFD{
		Fd:   fd,
		File: file,
		Rd:   rd,
	}, err
}

// Mark implements Add/Delete/Modify for a fanotify mark.
func (handle *NotifyFD) Mark(flags uint, mask uint64, dirFd int, path string) error {
	if err := unix.FanotifyMark(handle.Fd, flags, mask, dirFd, path); err != nil {
		return fmt.Errorf("fanotify: mark error, %w", err)
	}

	return nil
}

// GetEvent returns an event from the fanotify handle.
func (handle *NotifyFD) GetEvent(skipPIDs ...int) (*EventMetadata, error) {
	event := new(EventMetadata)

	if err := binary.Read(handle.Rd, binary.LittleEndian, event); err != nil {
		return nil, fmt.Errorf("fanotify: event error, %w", err)
	}

	if event.Vers != unix.FANOTIFY_METADATA_VERSION {
		if err := event.Close(); err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("fanotify: wrong metadata version")
	}

	for i := range skipPIDs {
		if int(event.Pid) == skipPIDs[i] {
			return nil, event.Close()
		}
	}

	return event, nil
}

// ResponseAllow sends an allow message back to fanotify, used for permission checks.
func (handle *NotifyFD) ResponseAllow(ev *EventMetadata) error {
	if err := binary.Write(
		handle.File,
		binary.LittleEndian,
		&unix.FanotifyResponse{
			Fd:       ev.Fd,
			Response: unix.FAN_ALLOW,
		},
	); err != nil {
		return fmt.Errorf("fanotify: response error, %w", err)
	}

	return nil
}

// ResponseDeny sends a deny message back to fanotify, used for permission checks.
func (handle *NotifyFD) ResponseDeny(ev *EventMetadata) error {
	if err := binary.Write(
		handle.File,
		binary.LittleEndian,
		&unix.FanotifyResponse{
			Fd:       ev.Fd,
			Response: unix.FAN_DENY,
		},
	); err != nil {
		return fmt.Errorf("fanotify: response error, %w", err)
	}

	return nil
}
