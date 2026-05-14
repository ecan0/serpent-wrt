package runtime

import (
	"net"
	"strings"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/detector"
)

type suppressionRule struct {
	detectors map[string]struct{}
	srcNets   []*net.IPNet
	dstNets   []*net.IPNet
	dstPorts  map[uint16]struct{}
}

func buildSuppressionRules(cfg []config.SuppressionRule) []suppressionRule {
	if len(cfg) == 0 {
		return nil
	}
	rules := make([]suppressionRule, 0, len(cfg))
	for _, c := range cfg {
		rule := suppressionRule{
			detectors: stringSet(c.Detectors),
			srcNets:   ipNets(c.SrcAddrs),
			dstNets:   ipNets(c.DstAddrs),
			dstPorts:  portSet(c.DstPorts),
		}
		if len(c.SrcAddrs) != len(rule.srcNets) || len(c.DstAddrs) != len(rule.dstNets) {
			continue
		}
		if len(rule.detectors) == 0 && len(rule.srcNets) == 0 && len(rule.dstNets) == 0 && len(rule.dstPorts) == 0 {
			continue
		}
		rules = append(rules, rule)
	}
	return rules
}

func (e *Engine) isSuppressed(det *detector.Detection) bool {
	for _, rule := range e.suppressionRules {
		if rule.matches(det) {
			return true
		}
	}
	return false
}

func (r suppressionRule) matches(det *detector.Detection) bool {
	if len(r.detectors) > 0 {
		if _, ok := r.detectors[det.Type]; !ok {
			return false
		}
	}
	if len(r.srcNets) > 0 && !containsIP(r.srcNets, det.SrcIP) {
		return false
	}
	if len(r.dstNets) > 0 && !containsIP(r.dstNets, det.DstIP) {
		return false
	}
	if len(r.dstPorts) > 0 {
		if _, ok := r.dstPorts[det.DstPort]; !ok {
			return false
		}
	}
	return true
}

func stringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[strings.TrimSpace(value)] = struct{}{}
	}
	return out
}

func portSet(values []uint16) map[uint16]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[uint16]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func ipNets(values []string) []*net.IPNet {
	if len(values) == 0 {
		return nil
	}
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		if network := ipNet(strings.TrimSpace(value)); network != nil {
			out = append(out, network)
		}
	}
	return out
}

func ipNet(value string) *net.IPNet {
	if strings.Contains(value, "/") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip.To4() == nil {
			return nil
		}
		return network
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	return &net.IPNet{
		IP:   ip.To4(),
		Mask: net.CIDRMask(32, 32),
	}
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip4) {
			return true
		}
	}
	return false
}
