package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Warnings returns non-fatal configuration warnings for settings that are valid
// YAML but likely to surprise router operators at runtime.
func Warnings(c *Config) []string {
	if c == nil {
		return nil
	}
	var warnings []string
	if len(c.LANCIDRs) == 0 {
		warnings = append(warnings, "lan_cidrs is empty; no LAN/WAN direction can be classified")
	}
	if len(c.SelfIPs) == 0 {
		warnings = append(warnings, "self_ips is empty; router-originated traffic may become detections")
	}
	if c.APIEnabled && !apiBindIsLoopback(c.APIBind) {
		warnings = append(warnings, fmt.Sprintf("api_bind %q is not loopback-only; expose the API only on trusted management interfaces", c.APIBind))
	}
	if c.EnforcementEnabled && c.Profile == "paranoid" {
		warnings = append(warnings, "profile paranoid with enforcement_enabled true can block aggressively")
	}
	if c.EnforcementEnabled && c.BlockDuration > 24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("block_duration %s is longer than 24h; recovery from false positives may be slow", c.BlockDuration))
	}
	for i, rule := range c.SuppressionRules {
		name := suppressionRuleLabel(i, rule.Name)
		if len(rule.Detectors) == 0 {
			warnings = append(warnings, fmt.Sprintf("suppression_rules[%s] has no detectors matcher; it can suppress every detector matching the other fields", name))
		}
		if len(rule.Detectors) > 0 && len(rule.SrcAddrs) == 0 && len(rule.DstAddrs) == 0 && len(rule.DstPorts) == 0 {
			warnings = append(warnings, fmt.Sprintf("suppression_rules[%s] matches only by detector; it may hide all %s detections", name, strings.Join(rule.Detectors, ",")))
		}
	}
	return warnings
}

func apiBindIsLoopback(bind string) bool {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func suppressionRuleLabel(index int, name string) string {
	if name == "" {
		return fmt.Sprintf("%d", index)
	}
	return fmt.Sprintf("%d:%s", index, name)
}
