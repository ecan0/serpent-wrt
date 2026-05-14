package runtime

import (
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/enforcer"
)

// BuildInfo describes the daemon build backing the running API.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// Status holds an operational runtime snapshot for the API.
type Status struct {
	Status        string               `json:"status"`
	StartedAt     time.Time            `json:"started_at"`
	UptimeSeconds int64                `json:"uptime_seconds"`
	Feed          FeedStatus           `json:"feed"`
	Enforcement   EnforcementStatus    `json:"enforcement"`
	Runtime       RuntimeStatus        `json:"runtime"`
	Detectors     DetectorConfigStatus `json:"detectors"`
}

// FeedStatus summarizes the currently loaded threat feed.
type FeedStatus struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// EnforcementStatus summarizes enforcement and nft setup state.
type EnforcementStatus struct {
	Enabled       bool      `json:"enabled"`
	BlockDuration string    `json:"block_duration"`
	Nft           NftStatus `json:"nft"`
}

// NftStatus describes cheap nft CLI availability and setup state.
type NftStatus struct {
	Available    bool   `json:"available"`
	Checked      bool   `json:"checked"`
	Table        string `json:"table"`
	Set          string `json:"set"`
	TablePresent bool   `json:"table_present"`
	SetPresent   bool   `json:"set_present"`
	SetupState   string `json:"setup_state"`
	CheckState   string `json:"check_state"`
	Diagnostic   string `json:"diagnostic,omitempty"`
	CheckError   string `json:"check_error,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

// RuntimeStatus exposes API/runtime config and build metadata.
type RuntimeStatus struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	BuildDate        string `json:"build_date"`
	PollInterval     string `json:"poll_interval"`
	DedupWindow      string `json:"dedup_window"`
	SuppressionRules int    `json:"suppression_rules"`
	APIEnabled       bool   `json:"api_enabled"`
	APIBind          string `json:"api_bind,omitempty"`
}

// DetectorConfigStatus summarizes detector tuning without exposing live state.
type DetectorConfigStatus struct {
	FeedMatch  FeedMatchConfigStatus  `json:"feed_match"`
	Fanout     FanoutConfigStatus     `json:"fanout"`
	Scan       ScanConfigStatus       `json:"scan"`
	Beacon     BeaconConfigStatus     `json:"beacon"`
	ExtScan    ScanConfigStatus       `json:"ext_scan"`
	BruteForce BruteForceConfigStatus `json:"brute_force"`
}

type FeedMatchConfigStatus struct {
	Enabled bool `json:"enabled"`
}

type FanoutConfigStatus struct {
	DistinctDstThreshold int    `json:"distinct_dst_threshold"`
	Window               string `json:"window"`
}

type ScanConfigStatus struct {
	DistinctPortThreshold int    `json:"distinct_port_threshold"`
	Window                string `json:"window"`
}

type BeaconConfigStatus struct {
	MinHits      int      `json:"min_hits"`
	Tolerance    string   `json:"tolerance"`
	Window       string   `json:"window"`
	MinInterval  string   `json:"min_interval"`
	ExcludePorts []uint16 `json:"exclude_ports,omitempty"`
}

type BruteForceConfigStatus struct {
	Threshold int    `json:"threshold"`
	Window    string `json:"window"`
}

// SetBuildInfo updates the build metadata exposed by GetStatus.
func (e *Engine) SetBuildInfo(info BuildInfo) {
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.BuildDate == "" {
		info.BuildDate = "unknown"
	}
	e.buildMu.Lock()
	e.buildInfo = info
	e.buildMu.Unlock()
}

// GetStatus returns a cheap operational status snapshot.
func (e *Engine) GetStatus() Status {
	now := time.Now()

	e.nftMu.Lock()
	nftState := e.nftSetupState
	nftErr := e.nftSetupError
	e.nftMu.Unlock()

	e.buildMu.Lock()
	build := e.buildInfo
	e.buildMu.Unlock()

	return Status{
		Status:        "ok",
		StartedAt:     e.startedAt,
		UptimeSeconds: int64(now.Sub(e.startedAt).Seconds()),
		Feed: FeedStatus{
			Path:  e.cfg.ThreatFeedPath,
			Count: e.feed.Len(),
		},
		Enforcement: EnforcementStatus{
			Enabled:       e.cfg.EnforcementEnabled,
			BlockDuration: e.cfg.BlockDuration.String(),
			Nft:           e.nftStatus(nftState, nftErr),
		},
		Runtime: RuntimeStatus{
			Version:          build.Version,
			Commit:           build.Commit,
			BuildDate:        build.BuildDate,
			PollInterval:     e.cfg.PollInterval.String(),
			DedupWindow:      e.cfg.DedupWindow.String(),
			SuppressionRules: len(e.suppressionRules),
			APIEnabled:       e.cfg.APIEnabled,
			APIBind:          e.cfg.APIBind,
		},
		Detectors: detectorConfigStatus(e.cfg.Detectors),
	}
}

func (e *Engine) nftStatus(setupState, setupErr string) NftStatus {
	status := NftStatus{
		Available:  e.enf.Available(),
		Checked:    false,
		Table:      e.cfg.NftTable,
		Set:        e.cfg.NftSet,
		SetupState: setupState,
		CheckState: "disabled",
		LastError:  setupErr,
	}
	if !e.cfg.EnforcementEnabled {
		return status
	}

	check := e.enf.Check()
	status.Available = check.Available
	status.Checked = true
	status.TablePresent = check.TablePresent
	status.SetPresent = check.SetPresent
	status.CheckState, status.Diagnostic = nftCheckState(setupState, check)
	status.CheckError = check.Error
	return status
}

func nftCheckState(setupState string, check enforcer.NftCheck) (string, string) {
	if !check.Available {
		return "unavailable", "nft CLI is unavailable; enforcement cannot apply blocks"
	}
	if !check.TablePresent {
		return "missing_table", nftReloadDiagnostic(setupState, "table")
	}
	if !check.SetPresent {
		return "missing_set", nftReloadDiagnostic(setupState, "set")
	}
	return "ready", ""
}

func nftReloadDiagnostic(setupState, missing string) string {
	if setupState == nftSetupReady {
		return "nft " + missing + " is missing after setup; a firewall reload may have removed serpent-wrt enforcement state"
	}
	return "nft " + missing + " is not present yet"
}

func defaultBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   "dev",
		Commit:    "unknown",
		BuildDate: "unknown",
	}
}

func detectorConfigStatus(cfg config.DetectorsConfig) DetectorConfigStatus {
	return DetectorConfigStatus{
		FeedMatch: FeedMatchConfigStatus{
			Enabled: true,
		},
		Fanout: FanoutConfigStatus{
			DistinctDstThreshold: cfg.Fanout.DistinctDstThreshold,
			Window:               cfg.Fanout.Window.String(),
		},
		Scan: ScanConfigStatus{
			DistinctPortThreshold: cfg.Scan.DistinctPortThreshold,
			Window:                cfg.Scan.Window.String(),
		},
		Beacon: BeaconConfigStatus{
			MinHits:      cfg.Beacon.MinHits,
			Tolerance:    cfg.Beacon.Tolerance.String(),
			Window:       cfg.Beacon.Window.String(),
			MinInterval:  cfg.Beacon.MinInterval.String(),
			ExcludePorts: append([]uint16(nil), cfg.Beacon.ExcludePorts...),
		},
		ExtScan: ScanConfigStatus{
			DistinctPortThreshold: cfg.ExtScan.DistinctPortThreshold,
			Window:                cfg.ExtScan.Window.String(),
		},
		BruteForce: BruteForceConfigStatus{
			Threshold: cfg.BruteForce.Threshold,
			Window:    cfg.BruteForce.Window.String(),
		},
	}
}
