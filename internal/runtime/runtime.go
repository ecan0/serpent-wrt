// Package runtime ties the collector, detectors, enforcer, and logger into a
// single polling pipeline. It exposes stats and recent detections for the API.
package runtime

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ecan0/serpent-wrt/internal/collector"
	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/detector"
	"github.com/ecan0/serpent-wrt/internal/enforcer"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/lease"
)

const (
	recentCap  = 100  // max recent detections kept for the API
	pruneEvery = 10   // prune state every N poll cycles
	maxDedup   = 4096 // max dedup entries before accepting duplicates
)

const (
	nftSetupDisabled     = "disabled"
	nftSetupNotAttempted = "not_attempted"
	nftSetupReady        = "ready"
	nftSetupFailed       = "failed"
)

var ipv4Broadcast = net.IPv4(255, 255, 255, 255)

// isUnroutable reports whether ip should never appear as a threat actor —
// unspecified (0.0.0.0), loopback, link-local, multicast, or broadcast.
func isUnroutable(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.Equal(ipv4Broadcast)
}

// DetectionRecord is a summarized detection for the API response.
type DetectionRecord struct {
	Time        time.Time `json:"time"`
	Detector    string    `json:"detector"`
	Severity    string    `json:"severity"`
	Confidence  uint8     `json:"confidence"`
	Reason      string    `json:"reason"`
	SrcIP       string    `json:"src_ip"`
	SrcHostname string    `json:"src_hostname,omitempty"`
	SrcMAC      string    `json:"src_mac,omitempty"`
	DstIP       string    `json:"dst_ip,omitempty"`
	DstHostname string    `json:"dst_hostname,omitempty"`
	DstMAC      string    `json:"dst_mac,omitempty"`
	DstPort     uint16    `json:"dst_port,omitempty"`
	Message     string    `json:"message"`
}

// Stats holds runtime counters exposed via the API.
type Stats struct {
	FlowsSeen                    uint64            `json:"flows_seen"`
	DetectionsByType             map[string]uint64 `json:"detections_by_type"`
	DetectionsBySeverity         map[string]uint64 `json:"detections_by_severity"`
	DetectionsByConfidenceBucket map[string]uint64 `json:"detections_by_confidence_bucket"`
	BlocksApplied                uint64            `json:"blocks_applied"`
	SuppressedDetections         uint64            `json:"suppressed_detections"`
	StartedAt                    time.Time         `json:"started_at"`
}

// dedupKey identifies a detector signal for suppression. Detectors that set a
// destination port dedup per service; detectors that leave it zero, such as
// fanout, continue to collapse at detector/src/dst precision.
type dedupKey struct {
	detType string
	srcIP   string
	dstIP   string
	dstPort uint16
}

// Engine is the core detection and enforcement pipeline.
// Atomic fields are placed first to guarantee 64-bit alignment on 32-bit targets.
type Engine struct {
	// atomic — must remain first in struct for 32-bit MIPS/ARM alignment
	flowsSeen            uint64
	blocksApplied        uint64
	suppressedDetections uint64

	cfg  *config.Config
	feed *feed.Feed
	log  *events.Logger
	enf  *enforcer.Enforcer

	feedFileMu sync.Mutex

	// outbound detectors
	feedMatch *detector.FeedMatch
	fanout    *detector.Fanout
	portScan  *detector.PortScan
	beacon    *detector.Beacon

	// inbound detectors
	extScan    *detector.ExtScan
	bruteForce *detector.BruteForce

	lanNets []*net.IPNet // pre-parsed from cfg.LANCIDRs
	selfIPs []net.IP     // router's own IPs — excluded as detection sources
	leases  *lease.Cache // optional read-only dnsmasq lease enrichment

	// detection counters
	detByTypeMu           sync.Mutex
	detByType             map[string]uint64
	detBySeverity         map[string]uint64
	detByConfidenceBucket map[string]uint64

	// recent detections ring buffer
	recentMu sync.Mutex
	recent   [recentCap]DetectionRecord
	rHead    int

	// dedup suppression
	dedupMu     sync.Mutex
	dedup       map[dedupKey]time.Time
	dedupWindow time.Duration

	// config-only suppression rules
	suppressionRules []suppressionRule

	nftMu         sync.Mutex
	nftSetupState string
	nftSetupError string

	buildMu   sync.Mutex
	buildInfo BuildInfo

	startedAt time.Time
}

// NewEngine constructs an Engine from the provided config.
func NewEngine(cfg *config.Config, log *events.Logger) *Engine {
	f := feed.New()
	e := &Engine{
		cfg:                   cfg,
		feed:                  f,
		log:                   log,
		enf:                   enforcer.New(cfg.NftTable, cfg.NftSet, cfg.BlockDuration),
		feedMatch:             detector.NewFeedMatch(f),
		fanout:                detector.NewFanout(cfg.Detectors.Fanout.DistinctDstThreshold, cfg.Detectors.Fanout.Window),
		portScan:              detector.NewPortScan(cfg.Detectors.Scan.DistinctPortThreshold, cfg.Detectors.Scan.Window),
		beacon:                detector.NewBeacon(cfg.Detectors.Beacon.MinHits, cfg.Detectors.Beacon.Tolerance, cfg.Detectors.Beacon.Window, cfg.Detectors.Beacon.MinInterval, cfg.Detectors.Beacon.ExcludePorts),
		extScan:               detector.NewExtScan(cfg.Detectors.ExtScan.DistinctPortThreshold, cfg.Detectors.ExtScan.Window),
		bruteForce:            detector.NewBruteForce(cfg.Detectors.BruteForce.Threshold, cfg.Detectors.BruteForce.Window),
		detByType:             make(map[string]uint64),
		detBySeverity:         make(map[string]uint64),
		detByConfidenceBucket: make(map[string]uint64),
		dedup:                 make(map[dedupKey]time.Time),
		dedupWindow:           cfg.DedupWindow,
		suppressionRules:      buildSuppressionRules(cfg.SuppressionRules),
		buildInfo:             defaultBuildInfo(),
		startedAt:             time.Now(),
	}
	if cfg.LeaseEnrichment {
		e.leases = lease.NewCache(cfg.DnsmasqLeasesPath)
	}
	if cfg.EnforcementEnabled {
		e.nftSetupState = nftSetupNotAttempted
	} else {
		e.nftSetupState = nftSetupDisabled
	}
	for _, cidr := range cfg.LANCIDRs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			e.lanNets = append(e.lanNets, network)
		}
	}
	for _, s := range cfg.SelfIPs {
		if ip := net.ParseIP(s); ip != nil {
			e.selfIPs = append(e.selfIPs, ip.To4())
		}
	}
	return e
}

// Run starts the polling loop and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	if err := e.loadFeed(); err != nil {
		return fmt.Errorf("initial feed load: %w", err)
	}

	if e.cfg.EnforcementEnabled {
		if err := e.enf.EnsureSet(); err != nil {
			e.setNftSetupState(nftSetupFailed, err)
			e.log.System(events.LevelError, events.SystemFields{
				Component: "nft",
				Action:    "setup",
				Status:    "failure",
				Error:     err.Error(),
			}, fmt.Sprintf("nftables setup failed: %v", err))
		} else {
			e.setNftSetupState(nftSetupReady, nil)
			e.log.System(events.LevelInfo, events.SystemFields{
				Component: "nft",
				Action:    "setup",
				Status:    "success",
			}, "nftables set ready")
		}
	}

	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()

	pruneCounter := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			e.poll()
			pruneCounter++
			if pruneCounter >= pruneEvery {
				e.prune()
				pruneCounter = 0
			}
		}
	}
}

func (e *Engine) poll() {
	flows, err := collector.Collect()
	if err != nil {
		e.log.System(events.LevelError, events.SystemFields{
			Component: "collector",
			Action:    "collect",
			Status:    "failure",
			Error:     err.Error(),
		}, fmt.Sprintf("collector failed: %v", err))
		return
	}
	atomic.AddUint64(&e.flowsSeen, uint64(len(flows)))

	for _, r := range flows {
		e.processFlow(r)
	}
}

// processFlow classifies a single flow by direction and runs the appropriate detectors.
func (e *Engine) processFlow(r flow.FlowRecord) {
	// Skip unroutable addresses: broadcast, multicast, link-local, loopback.
	if isUnroutable(r.SrcIP) || isUnroutable(r.DstIP) {
		return
	}
	// Skip flows originating from the router itself (e.g. NTP, DHCP).
	if e.isSelf(r.SrcIP) {
		return
	}

	srcLAN := e.isLAN(r.SrcIP)
	dstLAN := e.isLAN(r.DstIP)

	var dets []*detector.Detection
	switch {
	case srcLAN && !dstLAN:
		// Outbound: LAN host → WAN. Detect compromised internal behaviour.
		dets = []*detector.Detection{
			e.feedMatch.Check(r),
			e.fanout.Check(r),
			e.portScan.Check(r),
			e.beacon.Check(r),
		}
	case !srcLAN && dstLAN:
		// Inbound: WAN → LAN host. Detect external recon / attacks.
		dets = []*detector.Detection{
			e.feedMatch.Check(r),
			e.extScan.Check(r),
			e.bruteForce.Check(r),
		}
	}

	for _, det := range dets {
		if det != nil {
			e.handleDetection(det)
		}
	}
}

func (e *Engine) handleDetection(det *detector.Detection) {
	det.Normalize()
	if e.isSuppressed(det) {
		atomic.AddUint64(&e.suppressedDetections, 1)
		return
	}
	key := dedupKey{
		detType: det.Type,
		srcIP:   ipStr(det.SrcIP),
		dstIP:   ipStr(det.DstIP),
		dstPort: det.DstPort,
	}
	now := time.Now()

	e.dedupMu.Lock()
	last, ok := e.dedup[key]
	if ok && now.Sub(last) < e.dedupWindow {
		e.dedupMu.Unlock()
		return
	}
	if len(e.dedup) < maxDedup {
		e.dedup[key] = now
	}
	e.dedupMu.Unlock()

	enrichment := e.enrichment(det)
	ev := events.Event{
		Time:        now,
		Level:       events.LevelWarn,
		Type:        events.TypeDetection,
		Detector:    det.Type,
		Severity:    string(det.Severity),
		Confidence:  det.Confidence,
		Reason:      string(det.Reason),
		SrcIP:       ipStr(det.SrcIP),
		SrcHostname: enrichment.srcHostname,
		SrcMAC:      enrichment.srcMAC,
		DstIP:       ipStr(det.DstIP),
		DstHostname: enrichment.dstHostname,
		DstMAC:      enrichment.dstMAC,
		DstPort:     det.DstPort,
		Message:     det.Message,
	}
	e.log.Log(ev)

	e.detByTypeMu.Lock()
	e.detByType[det.Type]++
	e.detBySeverity[string(det.Severity)]++
	e.detByConfidenceBucket[confidenceBucket(det.Confidence)]++
	e.detByTypeMu.Unlock()

	rec := DetectionRecord{
		Time:        now,
		Detector:    det.Type,
		Severity:    string(det.Severity),
		Confidence:  det.Confidence,
		Reason:      string(det.Reason),
		SrcIP:       ipStr(det.SrcIP),
		SrcHostname: enrichment.srcHostname,
		SrcMAC:      enrichment.srcMAC,
		DstIP:       ipStr(det.DstIP),
		DstHostname: enrichment.dstHostname,
		DstMAC:      enrichment.dstMAC,
		DstPort:     det.DstPort,
		Message:     det.Message,
	}
	e.recentMu.Lock()
	e.recent[e.rHead] = rec
	e.rHead = (e.rHead + 1) % recentCap
	e.recentMu.Unlock()

	if e.cfg.EnforcementEnabled && det.SrcIP != nil {
		if err := e.enf.Block(det.SrcIP); err != nil {
			e.log.Error(fmt.Sprintf("block %s: %v", det.SrcIP, err))
			return
		}
		e.log.Enforcement(
			fmt.Sprintf("blocked %s triggered by %s", det.SrcIP, det.Type),
			det.SrcIP,
		)
		atomic.AddUint64(&e.blocksApplied, 1)
	}
}

type detectionEnrichment struct {
	srcHostname string
	srcMAC      string
	dstHostname string
	dstMAC      string
}

func (e *Engine) enrichment(det *detector.Detection) detectionEnrichment {
	if e.leases == nil {
		return detectionEnrichment{}
	}
	src, _ := e.leases.Lookup(det.SrcIP)
	dst, _ := e.leases.Lookup(det.DstIP)
	return detectionEnrichment{
		srcHostname: src.Hostname,
		srcMAC:      src.MAC,
		dstHostname: dst.Hostname,
		dstMAC:      dst.MAC,
	}
}

func (e *Engine) prune() {
	e.fanout.Prune()
	e.portScan.Prune()
	e.beacon.Prune()
	e.extScan.Prune()
	e.bruteForce.Prune()
	e.enf.Prune()

	now := time.Now()
	e.dedupMu.Lock()
	for k, t := range e.dedup {
		if now.Sub(t) > e.dedupWindow {
			delete(e.dedup, k)
		}
	}
	e.dedupMu.Unlock()
}

func (e *Engine) loadFeed() error {
	if err := e.feed.Load(e.cfg.ThreatFeedPath); err != nil {
		e.log.System(events.LevelError, events.SystemFields{
			Component: "feed",
			Action:    "load",
			Status:    "failure",
			Error:     err.Error(),
		}, fmt.Sprintf("load threat feed failed: %v", err))
		return err
	}
	count := e.feed.Len()
	e.log.System(events.LevelInfo, events.SystemFields{
		Component: "feed",
		Action:    "load",
		Status:    "success",
		FeedCount: &count,
	}, fmt.Sprintf("loaded threat feed: %d entries", count))
	return nil
}

// ReloadFeed reloads the threat feed from disk. Safe to call concurrently.
func (e *Engine) ReloadFeed() error {
	e.feedFileMu.Lock()
	defer e.feedFileMu.Unlock()
	return e.reloadFeedLocked()
}

func (e *Engine) reloadFeedLocked() error {
	if err := e.feed.Load(e.cfg.ThreatFeedPath); err != nil {
		e.log.System(events.LevelError, events.SystemFields{
			Component: "feed",
			Action:    "reload",
			Status:    "failure",
			Error:     err.Error(),
		}, fmt.Sprintf("reload threat feed failed: %v", err))
		return err
	}
	count := e.feed.Len()
	e.log.System(events.LevelInfo, events.SystemFields{
		Component: "feed",
		Action:    "reload",
		Status:    "success",
		FeedCount: &count,
	}, fmt.Sprintf("reloaded threat feed: %d entries", count))
	return nil
}

// GetStats returns a snapshot of runtime counters.
func (e *Engine) GetStats() Stats {
	e.detByTypeMu.Lock()
	byType := make(map[string]uint64, len(e.detByType))
	for k, v := range e.detByType {
		byType[k] = v
	}
	bySeverity := make(map[string]uint64, len(e.detBySeverity))
	for k, v := range e.detBySeverity {
		bySeverity[k] = v
	}
	byConfidenceBucket := make(map[string]uint64, len(e.detByConfidenceBucket))
	for k, v := range e.detByConfidenceBucket {
		byConfidenceBucket[k] = v
	}
	e.detByTypeMu.Unlock()

	return Stats{
		FlowsSeen:                    atomic.LoadUint64(&e.flowsSeen),
		DetectionsByType:             byType,
		DetectionsBySeverity:         bySeverity,
		DetectionsByConfidenceBucket: byConfidenceBucket,
		BlocksApplied:                atomic.LoadUint64(&e.blocksApplied),
		SuppressedDetections:         atomic.LoadUint64(&e.suppressedDetections),
		StartedAt:                    e.startedAt,
	}
}

func confidenceBucket(confidence uint8) string {
	switch {
	case confidence < 50:
		return "0_49"
	case confidence < 70:
		return "50_69"
	case confidence < 85:
		return "70_84"
	default:
		return "85_100"
	}
}

// RecentDetections returns up to recentCap detections in chronological order.
func (e *Engine) RecentDetections() []DetectionRecord {
	e.recentMu.Lock()
	defer e.recentMu.Unlock()
	out := make([]DetectionRecord, 0, recentCap)
	for i := 0; i < recentCap; i++ {
		r := e.recent[(e.rHead+i)%recentCap]
		if !r.Time.IsZero() {
			out = append(out, r)
		}
	}
	return out
}

// GetBlocked returns the list of currently blocked IPs from the nftables set.
// Returns an empty slice if enforcement is disabled or the set doesn't exist.
func (e *Engine) GetBlocked() ([]string, error) {
	if !e.cfg.EnforcementEnabled {
		return []string{}, nil
	}
	return e.enf.ListBlocked()
}

func (e *Engine) isSelf(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, self := range e.selfIPs {
		if self.Equal(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) isLAN(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, net := range e.lanNets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (e *Engine) setNftSetupState(state string, err error) {
	e.nftMu.Lock()
	e.nftSetupState = state
	if err != nil {
		e.nftSetupError = err.Error()
	} else {
		e.nftSetupError = ""
	}
	e.nftMu.Unlock()
}
