package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all runtime configuration for serpent-wrt.
type Config struct {
	PollInterval       time.Duration   `yaml:"poll_interval"`
	ThreatFeedPath     string          `yaml:"threat_feed_path"`
	EnforcementEnabled bool            `yaml:"enforcement_enabled"`
	BlockDuration      time.Duration   `yaml:"block_duration"`
	LANCIDRs           []string        `yaml:"lan_cidrs"`
	NftTable           string          `yaml:"nft_table"`
	NftSet             string          `yaml:"nft_set"`
	LogLevel           string          `yaml:"log_level"`
	APIEnabled         bool            `yaml:"api_enabled"`
	APIBind            string          `yaml:"api_bind"`
	Detectors          DetectorsConfig `yaml:"detectors"`
}

// DetectorsConfig groups per-detector tuning parameters.
type DetectorsConfig struct {
	Fanout FanoutConfig `yaml:"fanout"`
	Scan   ScanConfig   `yaml:"scan"`
	Beacon BeaconConfig `yaml:"beacon"`
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
	MinHits   int           `yaml:"min_hits"`
	Tolerance time.Duration `yaml:"tolerance"`
	Window    time.Duration `yaml:"window"`
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

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
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Second
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
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.APIEnabled && c.APIBind == "" {
		c.APIBind = "127.0.0.1:8080"
	}
	for _, cidr := range c.LANCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid lan_cidr %q: %w", cidr, err)
		}
	}
	if c.Detectors.Fanout.DistinctDstThreshold <= 0 {
		c.Detectors.Fanout.DistinctDstThreshold = 50
	}
	if c.Detectors.Fanout.Window <= 0 {
		c.Detectors.Fanout.Window = 60 * time.Second
	}
	if c.Detectors.Scan.DistinctPortThreshold <= 0 {
		c.Detectors.Scan.DistinctPortThreshold = 30
	}
	if c.Detectors.Scan.Window <= 0 {
		c.Detectors.Scan.Window = 60 * time.Second
	}
	if c.Detectors.Beacon.MinHits <= 0 {
		c.Detectors.Beacon.MinHits = 5
	}
	if c.Detectors.Beacon.Tolerance <= 0 {
		c.Detectors.Beacon.Tolerance = 3 * time.Second
	}
	if c.Detectors.Beacon.Window <= 0 {
		c.Detectors.Beacon.Window = 5 * time.Minute
	}
	return nil
}
