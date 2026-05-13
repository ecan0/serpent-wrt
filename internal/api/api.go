// Package api provides an optional localhost-only HTTP management interface.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/runtime"
)

const maxFeedRequestBytes = 1 << 20

// Server is a lightweight HTTP server bound to localhost.
type Server struct {
	eng engine
	srv *http.Server
}

type engine interface {
	GetStatus() runtime.Status
	GetStats() runtime.Stats
	ReloadFeed() error
	RecentDetections() []runtime.DetectionRecord
	GetBlocked() ([]string, error)
	ListFeedEntries() (feed.Snapshot, error)
	ValidateFeedEntries([]string) (feed.Snapshot, error)
	AddFeedEntry(string) (feed.UpdateResult, error)
	RemoveFeedEntry(string) (feed.UpdateResult, error)
	ReplaceFeedEntries([]string) (feed.UpdateResult, error)
}

// New creates a Server bound to addr backed by the given Engine.
func New(addr string, eng *runtime.Engine) *Server {
	return newServer(addr, eng)
}

func newServer(addr string, eng engine) *Server {
	s := &Server{eng: eng}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/detections/recent", s.handleRecentDetections)
	mux.HandleFunc("/blocked", s.handleBlocked)
	mux.HandleFunc("/feed", s.handleFeed)
	mux.HandleFunc("/feed/validate", s.handleFeedValidate)
	mux.HandleFunc("/feed/add", s.handleFeedAdd)
	mux.HandleFunc("/feed/remove", s.handleFeedRemove)

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	return s
}

// Start begins serving requests. Blocks until the server is stopped.
func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.eng.GetStatus())
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.eng.GetStats())
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.eng.ReloadFeed(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "reloaded"})
}

func (s *Server) handleRecentDetections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.eng.RecentDetections())
}

func (s *Server) handleBlocked(w http.ResponseWriter, _ *http.Request) {
	ips, err := s.eng.GetBlocked()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string][]string{"blocked": ips})
}

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap, err := s.eng.ListFeedEntries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, snap)
	case http.MethodPut:
		entries, ok := decodeEntriesRequest(w, r)
		if !ok {
			return
		}
		if _, err := s.eng.ValidateFeedEntries(entries); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := s.eng.ReplaceFeedEntries(entries)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, result)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFeedValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries, ok := decodeEntriesRequest(w, r)
	if !ok {
		return
	}
	snap, err := s.eng.ValidateFeedEntries(entries)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, snap)
}

func (s *Server) handleFeedAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entry, ok := decodeEntryRequest(w, r)
	if !ok {
		return
	}
	if _, err := feed.NormalizeEntry(entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eng.AddFeedEntry(entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (s *Server) handleFeedRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entry, ok := decodeEntryRequest(w, r)
	if !ok {
		return
	}
	if _, err := feed.NormalizeEntry(entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eng.RemoveFeedEntry(entry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func decodeEntryRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Entry string `json:"entry"`
	}
	if !decodeJSONRequest(w, r, &req) {
		return "", false
	}
	if req.Entry == "" {
		http.Error(w, "entry is required", http.StatusBadRequest)
		return "", false
	}
	return req.Entry, true
}

func decodeEntriesRequest(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var req struct {
		Entry   string   `json:"entry"`
		Entries []string `json:"entries"`
	}
	if !decodeJSONRequest(w, r, &req) {
		return nil, false
	}
	if req.Entry != "" {
		if len(req.Entries) > 0 {
			http.Error(w, "use entry or entries, not both", http.StatusBadRequest)
			return nil, false
		}
		return []string{req.Entry}, true
	}
	if req.Entries == nil {
		http.Error(w, "entries is required", http.StatusBadRequest)
		return nil, false
	}
	return req.Entries, true
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFeedRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
