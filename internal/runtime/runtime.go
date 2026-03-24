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
)

const (
	recentCap   = 100           // max recent detections kept for the API
	refireWindow = 5 * time.Minute // suppress duplicate (type,src,dst) detections
	pruneEvery  = 10            // prune state every N poll cycles
)

// DetectionRecord is a summarized detection for the API response.
type DetectionRecord struct {
	Time     time.Time `json:"time"`
	Detector string    `json:"detector"`
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip,omitempty"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	Message  string    `json:"message"`
}

// Stats holds runtime counters exposed via the API.
type Stats struct {
	FlowsSeen        uint64            `json:"flows_seen"`
	DetectionsByType map[string]uint64 `json:"detections_by_type"`
	BlocksApplied    uint64            `json:"blocks_applied"`
	StartedAt        time.Time         `json:"started_at"`
}

// dedupKey identifies a unique (detector, src, dst) combination for suppression.
type dedupKey struct {
	detType string
	srcIP   string
	dstIP   string
}

// Engine is the core detection and enforcement pipeline.
// Atomic fields are placed first to guarantee 64-bit alignment on 32-bit targets.
type Engine struct {
	// atomic — must remain first in struct for 32-bit MIPS/ARM alignment
	flowsSeen     uint64
	blocksApplied uint64

	cfg  *config.Config
	feed *feed.Feed
	log  *events.Logger
	enf  *enforcer.Enforcer

	feedMatch *detector.FeedMatch
	fanout    *detector.Fanout
	portScan  *detector.PortScan
	beacon    *detector.Beacon

	lanNets []*net.IPNet // pre-parsed from cfg.LANCIDRs

	// detection type counters
	detByTypeMu sync.Mutex
	detByType   map[string]uint64

	// recent detections ring buffer
	recentMu sync.Mutex
	recent   [recentCap]DetectionRecord
	rHead    int

	// dedup suppression
	dedupMu sync.Mutex
	dedup   map[dedupKey]time.Time

	startedAt time.Time
}

// NewEngine constructs an Engine from the provided config.
func NewEngine(cfg *config.Config, log *events.Logger) *Engine {
	f := feed.New()
	e := &Engine{
		cfg:       cfg,
		feed:      f,
		log:       log,
		enf:       enforcer.New(cfg.NftTable, cfg.NftSet, cfg.BlockDuration),
		feedMatch: detector.NewFeedMatch(f),
		fanout:    detector.NewFanout(cfg.Detectors.Fanout.DistinctDstThreshold, cfg.Detectors.Fanout.Window),
		portScan:  detector.NewPortScan(cfg.Detectors.Scan.DistinctPortThreshold, cfg.Detectors.Scan.Window),
		beacon:    detector.NewBeacon(cfg.Detectors.Beacon.MinHits, cfg.Detectors.Beacon.Tolerance, cfg.Detectors.Beacon.Window),
		detByType: make(map[string]uint64),
		dedup:     make(map[dedupKey]time.Time),
		startedAt: time.Now(),
	}
	for _, cidr := range cfg.LANCIDRs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			e.lanNets = append(e.lanNets, network)
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
			e.log.Error(fmt.Sprintf("nftables setup failed (enforcement disabled): %v", err))
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
		e.log.Error(fmt.Sprintf("collect: %v", err))
		return
	}
	atomic.AddUint64(&e.flowsSeen, uint64(len(flows)))

	for _, r := range flows {
		if e.isLAN(r.DstIP) {
			continue // skip internal destinations
		}
		dets := []*detector.Detection{
			e.feedMatch.Check(r),
			e.fanout.Check(r),
			e.portScan.Check(r),
			e.beacon.Check(r),
		}
		for _, det := range dets {
			if det != nil {
				e.handleDetection(det)
			}
		}
	}
}

func (e *Engine) handleDetection(det *detector.Detection) {
	key := dedupKey{det.Type, ipStr(det.SrcIP), ipStr(det.DstIP)}
	now := time.Now()

	e.dedupMu.Lock()
	last, ok := e.dedup[key]
	if ok && now.Sub(last) < refireWindow {
		e.dedupMu.Unlock()
		return
	}
	e.dedup[key] = now
	e.dedupMu.Unlock()

	ev := events.Event{
		Time:     now,
		Level:    events.LevelWarn,
		Type:     events.TypeDetection,
		Detector: det.Type,
		SrcIP:    ipStr(det.SrcIP),
		DstIP:    ipStr(det.DstIP),
		DstPort:  det.DstPort,
		Message:  det.Message,
	}
	e.log.Log(ev)

	e.detByTypeMu.Lock()
	e.detByType[det.Type]++
	e.detByTypeMu.Unlock()

	rec := DetectionRecord{
		Time:     now,
		Detector: det.Type,
		SrcIP:    ipStr(det.SrcIP),
		DstIP:    ipStr(det.DstIP),
		DstPort:  det.DstPort,
		Message:  det.Message,
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

func (e *Engine) prune() {
	e.fanout.Prune()
	e.portScan.Prune()
	e.beacon.Prune()
	e.enf.Prune()

	now := time.Now()
	e.dedupMu.Lock()
	for k, t := range e.dedup {
		if now.Sub(t) > refireWindow {
			delete(e.dedup, k)
		}
	}
	e.dedupMu.Unlock()
}

func (e *Engine) loadFeed() error {
	if err := e.feed.Load(e.cfg.ThreatFeedPath); err != nil {
		return err
	}
	e.log.Info(fmt.Sprintf("loaded threat feed: %d entries", e.feed.Len()))
	return nil
}

// ReloadFeed reloads the threat feed from disk. Safe to call concurrently.
func (e *Engine) ReloadFeed() error {
	if err := e.feed.Load(e.cfg.ThreatFeedPath); err != nil {
		return err
	}
	e.log.Info(fmt.Sprintf("reloaded threat feed: %d entries", e.feed.Len()))
	return nil
}

// GetStats returns a snapshot of runtime counters.
func (e *Engine) GetStats() Stats {
	e.detByTypeMu.Lock()
	byType := make(map[string]uint64, len(e.detByType))
	for k, v := range e.detByType {
		byType[k] = v
	}
	e.detByTypeMu.Unlock()

	return Stats{
		FlowsSeen:        atomic.LoadUint64(&e.flowsSeen),
		DetectionsByType: byType,
		BlocksApplied:    atomic.LoadUint64(&e.blocksApplied),
		StartedAt:        e.startedAt,
	}
}

// RecentDetections returns up to recentCap detections from the ring buffer.
func (e *Engine) RecentDetections() []DetectionRecord {
	e.recentMu.Lock()
	defer e.recentMu.Unlock()
	var out []DetectionRecord
	for _, r := range e.recent {
		if !r.Time.IsZero() {
			out = append(out, r)
		}
	}
	return out
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
