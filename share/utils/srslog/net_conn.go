package srslog

import (
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// netConn has an internal net.Conn and adheres to the serverConn interface,
// allowing us to send syslog messages over the network.
type netConn struct {
	conn net.Conn
}

// writeString formats syslog messages using time.RFC3339 and includes the
// hostname, and sends the message to the connection.
func (n *netConn) writeString(framer Framer, formatter Formatter, tmo time.Duration, p Priority, hostname, tag, msg string) error {
	if tmo != 0 {
		t := time.Now().Add(tmo)
		if err := n.conn.SetWriteDeadline(t); err != nil {
			log.WithFields(log.Fields{"err": err, "t": t}).Error()
		}
	}
	if framer == nil {
		framer = DefaultFramer
	}
	if formatter == nil {
		formatter = DefaultFormatter
	}
	formattedMessage := framer(formatter(p, hostname, tag, msg))
	_, err := n.conn.Write([]byte(formattedMessage))
	return err
}

// close the network connection
func (n *netConn) close() error {
	return n.conn.Close()
}
