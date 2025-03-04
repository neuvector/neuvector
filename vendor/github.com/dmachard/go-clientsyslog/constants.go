package clientsyslog

import (
	"errors"
	"fmt"
	"strings"
)

// Priority is a combination of the syslog facility and
// severity. For example, LOG_ALERT | LOG_FTP sends an alert severity
// message from the FTP facility. The default severity is LOG_EMERG;
// the default facility is LOG_KERN.
type Priority int

const severityMask = 0x07
const facilityMask = 0xf8

const (
	// Severity.

	// From /usr/include/sys/syslog.h.
	// These are the same on Linux, BSD, and OS X.
	LOG_EMERG Priority = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

const (
	// Facility.

	// From /usr/include/sys/syslog.h.
	// These are the same up to LOG_FTP on Linux, BSD, and OS X.
	LOG_KERN Priority = iota << 3
	LOG_USER
	LOG_MAIL
	LOG_DAEMON
	LOG_AUTH
	LOG_SYSLOG
	LOG_LPR
	LOG_NEWS
	LOG_UUCP
	LOG_CRON
	LOG_AUTHPRIV
	LOG_FTP
	_ // unused
	_ // unused
	_ // unused
	_ // unused
	LOG_LOCAL0
	LOG_LOCAL1
	LOG_LOCAL2
	LOG_LOCAL3
	LOG_LOCAL4
	LOG_LOCAL5
	LOG_LOCAL6
	LOG_LOCAL7
)

func validatePriority(p Priority) error {
	if p < 0 || p > LOG_LOCAL7|LOG_DEBUG {
		return errors.New("log/syslog: invalid priority")
	} else {
		return nil
	}
}

func GetPriority(facility string) (Priority, error) {
	facility = strings.ToUpper(facility)
	switch facility {
	// level
	case "WARNING":
		return LOG_WARNING, nil
	case "NOTICE":
		return LOG_NOTICE, nil
	case "INFO":
		return LOG_INFO, nil
	case "DEBUG":
		return LOG_DEBUG, nil
	// facility
	case "DAEMON":
		return LOG_DAEMON, nil
	case "LOCAL0":
		return LOG_LOCAL0, nil
	case "LOCAL1":
		return LOG_LOCAL1, nil
	case "LOCAL2":
		return LOG_LOCAL2, nil
	case "LOCAL3":
		return LOG_LOCAL3, nil
	case "LOCAL4":
		return LOG_LOCAL4, nil
	case "LOCAL5":
		return LOG_LOCAL5, nil
	case "LOCAL6":
		return LOG_LOCAL6, nil
	case "LOCAL7":
		return LOG_LOCAL7, nil
	default:
		return 0, fmt.Errorf("invalid syslog priority: %s", facility)
	}
}
