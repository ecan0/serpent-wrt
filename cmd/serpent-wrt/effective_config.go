package main

import (
	"fmt"
	"io"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"gopkg.in/yaml.v3"
)

type effectiveConfig struct {
	PollInterval       string                   `yaml:"poll_interval"`
	ThreatFeedPath     string                   `yaml:"threat_feed_path"`
	Profile            string                   `yaml:"profile"`
	LeaseEnrichment    bool                     `yaml:"lease_enrichment"`
	DnsmasqLeasesPath  string                   `yaml:"dnsmasq_leases_path"`
	EnforcementEnabled bool                     `yaml:"enforcement_enabled"`
	BlockDuration      string                   `yaml:"block_duration"`
	LANCIDRs           []string                 `yaml:"lan_cidrs"`
	SelfIPs            []string                 `yaml:"self_ips"`
	NftTable           string                   `yaml:"nft_table"`
	NftSet             string                   `yaml:"nft_set"`
	LogLevel           string                   `yaml:"log_level"`
	APIEnabled         bool                     `yaml:"api_enabled"`
	APIBind            string                   `yaml:"api_bind"`
	SyslogTarget       string                   `yaml:"syslog_target"`
	SyslogProto        string                   `yaml:"syslog_proto"`
	DedupWindow        string                   `yaml:"dedup_window"`
	Detectors          effectiveDetectorsConfig `yaml:"detectors"`
	SuppressionRules   []config.SuppressionRule `yaml:"suppression_rules"`
}

type effectiveDetectorsConfig struct {
	Fanout     effectiveFanoutConfig     `yaml:"fanout"`
	Scan       effectiveScanConfig       `yaml:"scan"`
	Beacon     effectiveBeaconConfig     `yaml:"beacon"`
	ExtScan    effectiveExtScanConfig    `yaml:"ext_scan"`
	BruteForce effectiveBruteForceConfig `yaml:"brute_force"`
}

type effectiveFanoutConfig struct {
	DistinctDstThreshold int    `yaml:"distinct_dst_threshold"`
	Window               string `yaml:"window"`
}

type effectiveScanConfig struct {
	DistinctPortThreshold int    `yaml:"distinct_port_threshold"`
	Window                string `yaml:"window"`
}

type effectiveBeaconConfig struct {
	MinHits      int      `yaml:"min_hits"`
	Tolerance    string   `yaml:"tolerance"`
	Window       string   `yaml:"window"`
	MinInterval  string   `yaml:"min_interval"`
	ExcludePorts []uint16 `yaml:"exclude_ports"`
}

type effectiveExtScanConfig struct {
	DistinctPortThreshold int    `yaml:"distinct_port_threshold"`
	Window                string `yaml:"window"`
}

type effectiveBruteForceConfig struct {
	Threshold int    `yaml:"threshold"`
	Window    string `yaml:"window"`
}

func writeEffectiveConfig(w io.Writer, cfg *config.Config) error {
	body, err := yaml.Marshal(newEffectiveConfig(cfg))
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func newEffectiveConfig(cfg *config.Config) effectiveConfig {
	return effectiveConfig{
		PollInterval:       formatConfigDuration(cfg.PollInterval),
		ThreatFeedPath:     cfg.ThreatFeedPath,
		Profile:            cfg.Profile,
		LeaseEnrichment:    cfg.LeaseEnrichment,
		DnsmasqLeasesPath:  cfg.DnsmasqLeasesPath,
		EnforcementEnabled: cfg.EnforcementEnabled,
		BlockDuration:      formatConfigDuration(cfg.BlockDuration),
		LANCIDRs:           cfg.LANCIDRs,
		SelfIPs:            cfg.SelfIPs,
		NftTable:           cfg.NftTable,
		NftSet:             cfg.NftSet,
		LogLevel:           cfg.LogLevel,
		APIEnabled:         cfg.APIEnabled,
		APIBind:            cfg.APIBind,
		SyslogTarget:       cfg.SyslogTarget,
		SyslogProto:        cfg.SyslogProto,
		DedupWindow:        formatConfigDuration(cfg.DedupWindow),
		Detectors: effectiveDetectorsConfig{
			Fanout: effectiveFanoutConfig{
				DistinctDstThreshold: cfg.Detectors.Fanout.DistinctDstThreshold,
				Window:               formatConfigDuration(cfg.Detectors.Fanout.Window),
			},
			Scan: effectiveScanConfig{
				DistinctPortThreshold: cfg.Detectors.Scan.DistinctPortThreshold,
				Window:                formatConfigDuration(cfg.Detectors.Scan.Window),
			},
			Beacon: effectiveBeaconConfig{
				MinHits:      cfg.Detectors.Beacon.MinHits,
				Tolerance:    formatConfigDuration(cfg.Detectors.Beacon.Tolerance),
				Window:       formatConfigDuration(cfg.Detectors.Beacon.Window),
				MinInterval:  formatConfigDuration(cfg.Detectors.Beacon.MinInterval),
				ExcludePorts: cfg.Detectors.Beacon.ExcludePorts,
			},
			ExtScan: effectiveExtScanConfig{
				DistinctPortThreshold: cfg.Detectors.ExtScan.DistinctPortThreshold,
				Window:                formatConfigDuration(cfg.Detectors.ExtScan.Window),
			},
			BruteForce: effectiveBruteForceConfig{
				Threshold: cfg.Detectors.BruteForce.Threshold,
				Window:    formatConfigDuration(cfg.Detectors.BruteForce.Window),
			},
		},
		SuppressionRules: cfg.SuppressionRules,
	}
}

func formatConfigDuration(d time.Duration) string {
	if d > 0 {
		if d%time.Hour == 0 {
			return fmt.Sprintf("%dh", int(d/time.Hour))
		}
		if d%time.Minute == 0 {
			return fmt.Sprintf("%dm", int(d/time.Minute))
		}
		if d%time.Second == 0 {
			return fmt.Sprintf("%ds", int(d/time.Second))
		}
	}
	return d.String()
}
