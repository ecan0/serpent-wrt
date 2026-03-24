package collector

import (
	"bufio"
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

// Collect returns current conntrack entries as normalized FlowRecords.
// It reads /proc/net/nf_conntrack directly, falling back to the conntrack
// command if the proc file is unavailable.
func Collect() ([]flow.FlowRecord, error) {
	f, err := os.Open(procPath)
	if err == nil {
		defer f.Close()
		return parse(bufio.NewScanner(f))
	}
	return collectCmd()
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

// parseLine parses one line from /proc/net/nf_conntrack or conntrack -L output.
// Only IPv4 TCP and UDP entries are parsed; IPv6 is skipped.
//
// Example TCP line:
//
//	ipv4 2 tcp 6 3599 ESTABLISHED src=192.168.1.1 dst=8.8.8.8 sport=45678 dport=443 ... [ASSURED]
func parseLine(line string, now time.Time) (flow.FlowRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "ipv6") {
		return flow.FlowRecord{}, false
	}

	fields := strings.Fields(line)
	if len(fields) < 6 {
		return flow.FlowRecord{}, false
	}

	proto := fields[2]
	if proto != "tcp" && proto != "udp" {
		return flow.FlowRecord{}, false
	}

	// For TCP the state token immediately follows the TTL field and is all-caps
	// with no '=' sign: e.g. "ESTABLISHED", "SYN_SENT", "TIME_WAIT".
	var state string
	if proto == "tcp" && len(fields) > 5 {
		if candidate := fields[5]; candidate == strings.ToUpper(candidate) &&
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
				srcIP = net.ParseIP(v).To4()
				seen |= 1
			}
		case "dst":
			if seen&2 == 0 {
				dstIP = net.ParseIP(v).To4()
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
