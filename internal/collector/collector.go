package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
)

const procPath = "/proc/net/nf_conntrack"

// EventStream carries normalized conntrack NEW events until Done reports why
// the stream ended. A nil Done value means the context was cancelled.
type EventStream struct {
	Records <-chan flow.FlowRecord
	Done    <-chan error
}

// Collect returns current conntrack entries as normalized FlowRecords.
// It reads /proc/net/nf_conntrack directly, falling back to the conntrack
// command if the proc file is unavailable.
func Collect() ([]flow.FlowRecord, error) {
	f, err := os.Open(procPath)
	if err == nil {
		defer func() { _ = f.Close() }()
		return parse(bufio.NewScanner(f))
	}
	return collectCmd()
}

// StartEvents starts the optional conntrack netlink event stream. It shells out
// to conntrack so polling remains available without a new daemon dependency.
func StartEvents(ctx context.Context) (*EventStream, error) {
	return startEvents(ctx, "conntrack")
}

func startEvents(ctx context.Context, command string) (*EventStream, error) {
	cmd := exec.CommandContext(ctx, command, "-E", "-e", "NEW")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("conntrack event stdout: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start conntrack event stream: %w", err)
	}

	records := make(chan flow.FlowRecord)
	done := make(chan error, 1)
	go func() {
		defer close(records)
		defer close(done)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			record, ok := parseLine(scanner.Text(), time.Now())
			if !ok {
				continue
			}
			select {
			case records <- record:
			case <-ctx.Done():
				_ = cmd.Wait()
				done <- nil
				return
			}
		}

		scanErr := scanner.Err()
		waitErr := cmd.Wait()
		if ctx.Err() != nil {
			done <- nil
			return
		}
		if scanErr != nil {
			done <- fmt.Errorf("read conntrack event stream: %w", scanErr)
			return
		}
		if waitErr != nil {
			message := strings.TrimSpace(stderr.String())
			if message != "" {
				done <- fmt.Errorf("conntrack event stream: %w (output: %s)", waitErr, message)
			} else {
				done <- fmt.Errorf("conntrack event stream: %w", waitErr)
			}
			return
		}
		done <- fmt.Errorf("conntrack event stream ended")
	}()

	return &EventStream{Records: records, Done: done}, nil
}

func collectCmd() ([]flow.FlowRecord, error) {
	out, err := exec.Command("conntrack", "-L").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("conntrack -L: %w (output: %s)", err, out)
	}
	return parse(bufio.NewScanner(strings.NewReader(string(out))))
}

func parse(scanner *bufio.Scanner) ([]flow.FlowRecord, error) {
	now := time.Now()
	var records []flow.FlowRecord
	for scanner.Scan() {
		if r, ok := parseLine(scanner.Text(), now); ok {
			records = append(records, r)
		}
	}
	return records, scanner.Err()
}

// parseLine parses one line from /proc/net/nf_conntrack, conntrack -L, or
// conntrack -E output. Only IPv4 TCP and UDP entries are parsed; IPv6 is
// skipped.
//
// Example TCP snapshot:
//
//	ipv4 2 tcp 6 3599 ESTABLISHED src=192.168.1.1 dst=8.8.8.8 sport=45678 dport=443 ... [ASSURED]
//
// Example TCP event:
//
//	[NEW] tcp 6 120 SYN_SENT src=192.168.1.1 dst=8.8.8.8 sport=45678 dport=443
func parseLine(line string, now time.Time) (flow.FlowRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return flow.FlowRecord{}, false
	}

	fields := strings.Fields(line)
	protoIndex := -1
	var proto string
	for i, field := range fields {
		if field == "tcp" || field == "udp" {
			protoIndex = i
			proto = field
			break
		}
	}
	if protoIndex < 0 {
		return flow.FlowRecord{}, false
	}

	// For TCP the state token immediately follows the TTL field and is all-caps
	// with no '=' sign: e.g. "ESTABLISHED", "SYN_SENT", "TIME_WAIT".
	var state string
	stateIndex := protoIndex + 3
	if proto == "tcp" && stateIndex < len(fields) {
		if candidate := fields[stateIndex]; candidate == strings.ToUpper(candidate) &&
			!strings.Contains(candidate, "=") {
			state = candidate
		}
	}

	// Extract the forward-direction tuple from key=value pairs.
	// Use a bitmask to take only the first occurrence of each key.
	var (
		srcIP   net.IP
		dstIP   net.IP
		srcPort uint16
		dstPort uint16
		seen    uint8 // bits: 1=src 2=dst 4=sport 8=dport
	)
	for _, f := range fields {
		if seen == 0x0f {
			break // all four forward fields captured
		}
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "src":
			if seen&1 == 0 {
				srcIP = net.ParseIP(v)
				seen |= 1
			}
		case "dst":
			if seen&2 == 0 {
				dstIP = net.ParseIP(v)
				seen |= 2
			}
		case "sport":
			if seen&4 == 0 {
				p, _ := strconv.ParseUint(v, 10, 16)
				srcPort = uint16(p)
				seen |= 4
			}
		case "dport":
			if seen&8 == 0 {
				p, _ := strconv.ParseUint(v, 10, 16)
				dstPort = uint16(p)
				seen |= 8
			}
		}
	}

	if srcIP == nil || dstIP == nil {
		return flow.FlowRecord{}, false
	}

	return flow.FlowRecord{
		Proto:   proto,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		State:   state,
		SeenAt:  now,
	}, true
}
