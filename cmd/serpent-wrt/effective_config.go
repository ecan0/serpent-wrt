package main

import (
	"fmt"
	"io"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"gopkg.in/yaml.v3"
)

type effectiveConfig struct {
	PollInterval       string                     `yaml:"poll_interval" json:"poll_interval"`
	ThreatFeedPath     string                     `yaml:"threat_feed_path" json:"threat_feed_path"`
	Profile            string                     `yaml:"profile" json:"profile"`
	LeaseEnrichment    bool                       `yaml:"lease_enrichment" json:"lease_enrichment"`
	DnsmasqLeasesPath  string                     `yaml:"dnsmasq_leases_path" json:"dnsmasq_leases_path"`
	EnforcementEnabled bool                       `yaml:"enforcement_enabled" json:"enforcement_enabled"`
	BlockDuration      string                     `yaml:"block_duration" json:"block_duration"`
	LANCIDRs           []string                   `yaml:"lan_cidrs" json:"lan_cidrs"`
	SelfIPs            []string                   `yaml:"self_ips" json:"self_ips"`
	NftTable           string                     `yaml:"nft_table" json:"nft_table"`
	NftSet             string                     `yaml:"nft_set" json:"nft_set"`
	LogLevel           string                     `yaml:"log_level" json:"log_level"`
	APIEnabled         bool                       `yaml:"api_enabled" json:"api_enabled"`
	APIBind            string                     `yaml:"api_bind" json:"api_bind"`
	SyslogTarget       string                     `yaml:"syslog_target" json:"syslog_target"`
	SyslogProto        string                     `yaml:"syslog_proto" json:"syslog_proto"`
	DedupWindow        string                     `yaml:"dedup_window" json:"dedup_window"`
	Detectors          effectiveDetectorsConfig   `yaml:"detectors" json:"detectors"`
	SuppressionRules   []effectiveSuppressionRule `yaml:"suppression_rules" json:"suppression_rules"`
}

type effectiveDetectorsConfig struct {
	Fanout     effectiveFanoutConfig     `yaml:"fanout" json:"fanout"`
	Scan       effectiveScanConfig       `yaml:"scan" json:"scan"`
	Beacon     effectiveBeaconConfig     `yaml:"beacon" json:"beacon"`
	ExtScan    effectiveExtScanConfig    `yaml:"ext_scan" json:"ext_scan"`
	BruteForce effectiveBruteForceConfig `yaml:"brute_force" json:"brute_force"`
}

type effectiveFanoutConfig struct {
	DistinctDstThreshold int    `yaml:"distinct_dst_threshold" json:"distinct_dst_threshold"`
	Window               string `yaml:"window" json:"window"`
}

type effectiveScanConfig struct {
	DistinctPortThreshold int    `yaml:"distinct_port_threshold" json:"distinct_port_threshold"`
	Window                string `yaml:"window" json:"window"`
}

type effectiveBeaconConfig struct {
	MinHits      int      `yaml:"min_hits" json:"min_hits"`
	Tolerance    string   `yaml:"tolerance" json:"tolerance"`
	Window       string   `yaml:"window" json:"window"`
	MinInterval  string   `yaml:"min_interval" json:"min_interval"`
	ExcludePorts []uint16 `yaml:"exclude_ports" json:"exclude_ports"`
}

type effectiveExtScanConfig struct {
	DistinctPortThreshold int    `yaml:"distinct_port_threshold" json:"distinct_port_threshold"`
	Window                string `yaml:"window" json:"window"`
}

type effectiveBruteForceConfig struct {
	Threshold int    `yaml:"threshold" json:"threshold"`
	Window    string `yaml:"window" json:"window"`
}

type effectiveSuppressionRule struct {
	Name      string   `yaml:"name" json:"name"`
	Detectors []string `yaml:"detectors" json:"detectors"`
	SrcAddrs  []string `yaml:"src_addrs" json:"src_addrs"`
	DstAddrs  []string `yaml:"dst_addrs" json:"dst_addrs"`
	DstPorts  []uint16 `yaml:"dst_ports" json:"dst_ports"`
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
		LANCIDRs:           stringSliceOrEmpty(cfg.LANCIDRs),
		SelfIPs:            stringSliceOrEmpty(cfg.SelfIPs),
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
				ExcludePorts: uint16SliceOrEmpty(cfg.Detectors.Beacon.ExcludePorts),
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
		SuppressionRules: newEffectiveSuppressionRules(cfg.SuppressionRules),
	}
}

func newEffectiveSuppressionRules(rules []config.SuppressionRule) []effectiveSuppressionRule {
	out := make([]effectiveSuppressionRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, effectiveSuppressionRule{
			Name:      rule.Name,
			Detectors: stringSliceOrEmpty(rule.Detectors),
			SrcAddrs:  stringSliceOrEmpty(rule.SrcAddrs),
			DstAddrs:  stringSliceOrEmpty(rule.DstAddrs),
			DstPorts:  uint16SliceOrEmpty(rule.DstPorts),
		})
	}
	return out
}

func stringSliceOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func uint16SliceOrEmpty(values []uint16) []uint16 {
	if values == nil {
		return []uint16{}
	}
	return values
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
