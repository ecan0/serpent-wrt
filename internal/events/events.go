package events

import (
	"encoding/json"
	"log/syslog"
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
	Time     time.Time `json:"time"`
	Level    Level     `json:"level"`
	Type     EventType `json:"type"`
	Detector string    `json:"detector,omitempty"`
	SrcIP    string    `json:"src_ip,omitempty"`
	DstIP    string    `json:"dst_ip,omitempty"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	Message  string    `json:"message"`
}

// Logger writes newline-delimited JSON events to stdout and optionally
// forwards them to a remote syslog target (UDP or TCP).
type Logger struct {
	mu     sync.Mutex
	enc    *json.Encoder
	remote *syslog.Writer // nil if not configured; goroutine-safe
}

// NewLogger creates a Logger. Pass a non-nil syslog.Writer to enable
// remote forwarding; pass nil to log to stdout only.
func NewLogger(remote *syslog.Writer) *Logger {
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
			_ = l.remote.Err(msg)
		case LevelWarn:
			_ = l.remote.Warning(msg)
		default:
			_ = l.remote.Info(msg)
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
		Level:    LevelWarn,
		Type:     TypeDetection,
		Detector: detector,
		SrcIP:    ipStr(src),
		DstIP:    ipStr(dst),
		DstPort:  dstPort,
		Message:  msg,
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
