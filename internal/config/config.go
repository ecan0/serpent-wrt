package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ecan0/serpent-wrt/internal/lease"
)

// Config holds all runtime configuration for serpent-wrt.
type Config struct {
	PollInterval       time.Duration     `yaml:"poll_interval"`
	ThreatFeedPath     string            `yaml:"threat_feed_path"`
	Profile            string            `yaml:"profile"`
	LeaseEnrichment    bool              `yaml:"lease_enrichment"`
	DnsmasqLeasesPath  string            `yaml:"dnsmasq_leases_path"`
	EnforcementEnabled bool              `yaml:"enforcement_enabled"`
	BlockDuration      time.Duration     `yaml:"block_duration"`
	LANCIDRs           []string          `yaml:"lan_cidrs"`
	SelfIPs            []string          `yaml:"self_ips"` // router's own IPs — excluded from detection
	NftTable           string            `yaml:"nft_table"`
	NftSet             string            `yaml:"nft_set"`
	LogLevel           string            `yaml:"log_level"`
	APIEnabled         bool              `yaml:"api_enabled"`
	APIBind            string            `yaml:"api_bind"`
	SyslogTarget       string            `yaml:"syslog_target"` // host:port, e.g. 10.0.0.10:514
	SyslogProto        string            `yaml:"syslog_proto"`  // "udp" (default) or "tcp"
	DedupWindow        time.Duration     `yaml:"dedup_window"`  // suppress duplicate detector/src/dst/port alerts within this window
	Detectors          DetectorsConfig   `yaml:"detectors"`
	SuppressionRules   []SuppressionRule `yaml:"suppression_rules"`
}

// DetectorsConfig groups per-detector tuning parameters.
type DetectorsConfig struct {
	Fanout     FanoutConfig     `yaml:"fanout"`
	Scan       ScanConfig       `yaml:"scan"`
	Beacon     BeaconConfig     `yaml:"beacon"`
	ExtScan    ExtScanConfig    `yaml:"ext_scan"`
	BruteForce BruteForceConfig `yaml:"brute_force"`
}

// FanoutConfig controls the outbound fanout detector.
type FanoutConfig struct {
	DistinctDstThreshold int           `yaml:"distinct_dst_threshold"`
	Window               time.Duration `yaml:"window"`
}

// ScanConfig controls the port scan detector.
type ScanConfig struct {
	DistinctPortThreshold int           `yaml:"distinct_port_threshold"`
	Window                time.Duration `yaml:"window"`
}

// BeaconConfig controls the beaconing detector.
type BeaconConfig struct {
	MinHits      int           `yaml:"min_hits"`
	Tolerance    time.Duration `yaml:"tolerance"`
	Window       time.Duration `yaml:"window"`
	MinInterval  time.Duration `yaml:"min_interval"`
	ExcludePorts []uint16      `yaml:"exclude_ports"`
}

// ExtScanConfig controls the inbound external port scan detector.
type ExtScanConfig struct {
	DistinctPortThreshold int           `yaml:"distinct_port_threshold"`
	Window                time.Duration `yaml:"window"`
}

// BruteForceConfig controls the inbound brute-force / horizontal scan detector.
type BruteForceConfig struct {
	Threshold int           `yaml:"threshold"`
	Window    time.Duration `yaml:"window"`
}

type detectorProfile struct {
	Fanout     FanoutConfig
	Scan       ScanConfig
	Beacon     BeaconConfig
	ExtScan    ExtScanConfig
	BruteForce BruteForceConfig
}

var detectorProfiles = map[string]detectorProfile{
	"home": {
		Fanout:     FanoutConfig{DistinctDstThreshold: 50, Window: 60 * time.Second},
		Scan:       ScanConfig{DistinctPortThreshold: 30, Window: 60 * time.Second},
		Beacon:     BeaconConfig{MinHits: 5, Tolerance: 3 * time.Second, Window: 5 * time.Minute, MinInterval: 5 * time.Second},
		ExtScan:    ExtScanConfig{DistinctPortThreshold: 20, Window: 60 * time.Second},
		BruteForce: BruteForceConfig{Threshold: 5, Window: 60 * time.Second},
	},
	"homelab": {
		Fanout:     FanoutConfig{DistinctDstThreshold: 75, Window: 60 * time.Second},
		Scan:       ScanConfig{DistinctPortThreshold: 45, Window: 60 * time.Second},
		Beacon:     BeaconConfig{MinHits: 6, Tolerance: 4 * time.Second, Window: 8 * time.Minute, MinInterval: 5 * time.Second},
		ExtScan:    ExtScanConfig{DistinctPortThreshold: 30, Window: 60 * time.Second},
		BruteForce: BruteForceConfig{Threshold: 8, Window: 60 * time.Second},
	},
	"quiet": {
		Fanout:     FanoutConfig{DistinctDstThreshold: 100, Window: 90 * time.Second},
		Scan:       ScanConfig{DistinctPortThreshold: 60, Window: 90 * time.Second},
		Beacon:     BeaconConfig{MinHits: 7, Tolerance: 5 * time.Second, Window: 10 * time.Minute, MinInterval: 10 * time.Second},
		ExtScan:    ExtScanConfig{DistinctPortThreshold: 40, Window: 90 * time.Second},
		BruteForce: BruteForceConfig{Threshold: 10, Window: 90 * time.Second},
	},
	"paranoid": {
		Fanout:     FanoutConfig{DistinctDstThreshold: 25, Window: 60 * time.Second},
		Scan:       ScanConfig{DistinctPortThreshold: 15, Window: 60 * time.Second},
		Beacon:     BeaconConfig{MinHits: 4, Tolerance: 2 * time.Second, Window: 4 * time.Minute, MinInterval: 5 * time.Second},
		ExtScan:    ExtScanConfig{DistinctPortThreshold: 10, Window: 60 * time.Second},
		BruteForce: BruteForceConfig{Threshold: 3, Window: 60 * time.Second},
	},
}

// SuppressionRule drops expected detections before logging or enforcement.
// Empty matcher fields act as wildcards; at least one matcher is required.
type SuppressionRule struct {
	Name      string   `yaml:"name"`
	Detectors []string `yaml:"detectors"`
	SrcAddrs  []string `yaml:"src_addrs"`
	DstAddrs  []string `yaml:"dst_addrs"`
	DstPorts  []uint16 `yaml:"dst_ports"`
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.applyDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// applyDefaults fills in zero values and validates required fields.
func (c *Config) applyDefaults() error {
	if c.ThreatFeedPath == "" {
		return fmt.Errorf("threat_feed_path is required")
	}
	c.Profile = strings.TrimSpace(c.Profile)
	if c.Profile == "" {
		c.Profile = "home"
	}
	profile, ok := detectorProfiles[c.Profile]
	if !ok {
		return fmt.Errorf("profile must be one of home, homelab, quiet, or paranoid, got %q", c.Profile)
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.LeaseEnrichment && c.DnsmasqLeasesPath == "" {
		c.DnsmasqLeasesPath = lease.DefaultPath
	}
	if c.BlockDuration <= 0 {
		c.BlockDuration = time.Hour
	}
	if c.NftTable == "" {
		c.NftTable = "serpent_wrt"
	}
	if c.NftSet == "" {
		c.NftSet = "blocked_ips"
	}
	if err := validateNftIdentifier("nft_table", c.NftTable); err != nil {
		return err
	}
	if err := validateNftIdentifier("nft_set", c.NftSet); err != nil {
		return err
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.APIEnabled && c.APIBind == "" {
		c.APIBind = "127.0.0.1:8080"
	}
	if c.APIEnabled {
		if _, _, err := net.SplitHostPort(c.APIBind); err != nil {
			return fmt.Errorf("api_bind must be host:port, got %q: %w", c.APIBind, err)
		}
	}
	if c.SyslogTarget != "" && c.SyslogProto == "" {
		c.SyslogProto = "udp"
	}
	if c.SyslogTarget != "" {
		if _, _, err := net.SplitHostPort(c.SyslogTarget); err != nil {
			return fmt.Errorf("syslog_target must be host:port, got %q: %w", c.SyslogTarget, err)
		}
		if c.SyslogProto != "udp" && c.SyslogProto != "tcp" {
			return fmt.Errorf("syslog_proto must be udp or tcp, got %q", c.SyslogProto)
		}
	}
	if c.DedupWindow <= 0 {
		c.DedupWindow = 5 * time.Minute
	}
	for i, cidr := range c.LANCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("lan_cidrs[%d] must be valid CIDR, got %q: %w", i, cidr, err)
		}
	}
	for i, selfIP := range c.SelfIPs {
		ip := net.ParseIP(selfIP)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("self_ips[%d] must be an IPv4 address, got %q", i, selfIP)
		}
	}
	c.applyDetectorProfile(profile)
	if err := c.validateSuppressionRules(); err != nil {
		return err
	}
	return nil
}

func (c *Config) applyDetectorProfile(profile detectorProfile) {
	if c.Detectors.Fanout.DistinctDstThreshold <= 0 {
		c.Detectors.Fanout.DistinctDstThreshold = profile.Fanout.DistinctDstThreshold
	}
	if c.Detectors.Fanout.Window <= 0 {
		c.Detectors.Fanout.Window = profile.Fanout.Window
	}
	if c.Detectors.Scan.DistinctPortThreshold <= 0 {
		c.Detectors.Scan.DistinctPortThreshold = profile.Scan.DistinctPortThreshold
	}
	if c.Detectors.Scan.Window <= 0 {
		c.Detectors.Scan.Window = profile.Scan.Window
	}
	if c.Detectors.Beacon.MinHits <= 0 {
		c.Detectors.Beacon.MinHits = profile.Beacon.MinHits
	}
	if c.Detectors.Beacon.Tolerance <= 0 {
		c.Detectors.Beacon.Tolerance = profile.Beacon.Tolerance
	}
	if c.Detectors.Beacon.Window <= 0 {
		c.Detectors.Beacon.Window = profile.Beacon.Window
	}
	if c.Detectors.Beacon.MinInterval <= 0 {
		c.Detectors.Beacon.MinInterval = profile.Beacon.MinInterval
	}
	if c.Detectors.ExtScan.DistinctPortThreshold <= 0 {
		c.Detectors.ExtScan.DistinctPortThreshold = profile.ExtScan.DistinctPortThreshold
	}
	if c.Detectors.ExtScan.Window <= 0 {
		c.Detectors.ExtScan.Window = profile.ExtScan.Window
	}
	if c.Detectors.BruteForce.Threshold <= 0 {
		c.Detectors.BruteForce.Threshold = profile.BruteForce.Threshold
	}
	if c.Detectors.BruteForce.Window <= 0 {
		c.Detectors.BruteForce.Window = profile.BruteForce.Window
	}
}

func (c *Config) validateSuppressionRules() error {
	for i := range c.SuppressionRules {
		rule := &c.SuppressionRules[i]
		rule.Name = strings.TrimSpace(rule.Name)
		if len(rule.Detectors) == 0 && len(rule.SrcAddrs) == 0 && len(rule.DstAddrs) == 0 && len(rule.DstPorts) == 0 {
			return fmt.Errorf("suppression_rules[%d] must define at least one matcher", i)
		}
		for j := range rule.Detectors {
			rule.Detectors[j] = strings.TrimSpace(rule.Detectors[j])
			if !isKnownDetector(rule.Detectors[j]) {
				return fmt.Errorf("suppression_rules[%d].detectors[%d] must be a known detector, got %q", i, j, rule.Detectors[j])
			}
		}
		for j := range rule.SrcAddrs {
			rule.SrcAddrs[j] = strings.TrimSpace(rule.SrcAddrs[j])
			if err := validateIPv4AddrOrCIDR(rule.SrcAddrs[j]); err != nil {
				return fmt.Errorf("suppression_rules[%d].src_addrs[%d] must be an IPv4 address or CIDR, got %q: %w", i, j, rule.SrcAddrs[j], err)
			}
		}
		for j := range rule.DstAddrs {
			rule.DstAddrs[j] = strings.TrimSpace(rule.DstAddrs[j])
			if err := validateIPv4AddrOrCIDR(rule.DstAddrs[j]); err != nil {
				return fmt.Errorf("suppression_rules[%d].dst_addrs[%d] must be an IPv4 address or CIDR, got %q: %w", i, j, rule.DstAddrs[j], err)
			}
		}
		for j, port := range rule.DstPorts {
			if port == 0 {
				return fmt.Errorf("suppression_rules[%d].dst_ports[%d] must be between 1 and 65535", i, j)
			}
		}
	}
	return nil
}

func isKnownDetector(name string) bool {
	switch name {
	case "feed_match", "fanout", "port_scan", "beacon", "ext_scan", "brute_force":
		return true
	default:
		return false
	}
}

func validateIPv4AddrOrCIDR(value string) error {
	if value == "" {
		return fmt.Errorf("empty value")
	}
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil {
			return err
		}
		if ip.To4() == nil {
			return fmt.Errorf("not IPv4")
		}
		return nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("not IPv4")
	}
	return nil
}

func validateNftIdentifier(field, value string) error {
	for i, r := range value {
		if i == 0 {
			if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				continue
			}
			return fmt.Errorf("%s must start with a letter or underscore, got %q", field, value)
		}
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return fmt.Errorf("%s must contain only letters, numbers, and underscores, got %q", field, value)
	}
	return nil
}
