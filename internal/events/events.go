package events

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type EventType string

const (
	TypeDetection   EventType = "detection"
	TypeEnforcement EventType = "enforcement"
	TypeSystem      EventType = "system"
)

// Event is a structured JSON log entry written to stdout.
type Event struct {
	Time       time.Time `json:"time"`
	Level      Level     `json:"level"`
	Type       EventType `json:"type"`
	Detector   string    `json:"detector,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Confidence uint8     `json:"confidence,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	SrcIP      string    `json:"src_ip,omitempty"`
	DstIP      string    `json:"dst_ip,omitempty"`
	DstPort    uint16    `json:"dst_port,omitempty"`
	Message    string    `json:"message"`
}

// UDPSyslog is a self-healing RFC 3164 syslog sender over UDP.
// It re-dials on write failure so transient errors (ICMP port unreachable,
// brief listener restarts) do not permanently break the writer.
type UDPSyslog struct {
	mu       sync.Mutex
	network  string
	addr     string
	conn     net.Conn
	hostname string
}

// NewUDPSyslog creates a UDPSyslog connected to addr via network ("udp"/"tcp").
func NewUDPSyslog(network, addr string) (*UDPSyslog, error) {
	hostname, _ := os.Hostname()
	u := &UDPSyslog{network: network, addr: addr, hostname: hostname}
	if err := u.dial(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UDPSyslog) dial() error {
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
	}
	c, err := net.Dial(u.network, u.addr)
	if err != nil {
		return err
	}
	u.conn = c
	return nil
}

// syslog priority constants (RFC 3164): facility daemon (3<<3=24).
const (
	priErr  = 24 | 3 // daemon.err
	priWarn = 24 | 4 // daemon.warning
	priInfo = 24 | 6 // daemon.info
)

func (u *UDPSyslog) send(pri int, msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	pkt := fmt.Sprintf("<%d>%s %s serpent-wrt[%d]: %s\n",
		pri, time.Now().Format(time.Stamp), u.hostname, os.Getpid(), msg)
	if _, err := fmt.Fprint(u.conn, pkt); err != nil {
		// Re-dial and retry once; if that also fails, drop silently.
		if u.dial() == nil {
			_, _ = fmt.Fprint(u.conn, pkt)
		}
	}
}

// Logger writes newline-delimited JSON events to stdout and optionally
// forwards them to a remote syslog target (UDP or TCP).
type Logger struct {
	mu     sync.Mutex
	enc    *json.Encoder
	remote *UDPSyslog // nil if not configured
}

// NewLogger creates a Logger. Pass a non-nil UDPSyslog to enable
// remote forwarding; pass nil to log to stdout only.
func NewLogger(remote *UDPSyslog) *Logger {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return &Logger{enc: enc, remote: remote}
}

func (l *Logger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.mu.Lock()
	_ = l.enc.Encode(e)
	l.mu.Unlock()

	if l.remote != nil {
		b, err := json.Marshal(e)
		if err != nil {
			return
		}
		msg := string(b)
		switch e.Level {
		case LevelError:
			l.remote.send(priErr, msg)
		case LevelWarn:
			l.remote.send(priWarn, msg)
		default:
			l.remote.send(priInfo, msg)
		}
	}
}

func (l *Logger) Info(msg string) {
	l.Log(Event{Level: LevelInfo, Type: TypeSystem, Message: msg})
}

func (l *Logger) Error(msg string) {
	l.Log(Event{Level: LevelError, Type: TypeSystem, Message: msg})
}

func (l *Logger) Detection(detector, msg string, src, dst net.IP, dstPort uint16) {
	l.Log(Event{
		Level:      LevelWarn,
		Type:       TypeDetection,
		Detector:   detector,
		Severity:   "medium",
		Confidence: 50,
		Reason:     "heuristic_match",
		SrcIP:      ipStr(src),
		DstIP:      ipStr(dst),
		DstPort:    dstPort,
		Message:    msg,
	})
}

func (l *Logger) Enforcement(msg string, ip net.IP) {
	l.Log(Event{
		Level:   LevelWarn,
		Type:    TypeEnforcement,
		SrcIP:   ipStr(ip),
		Message: msg,
	})
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
