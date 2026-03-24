// Package api provides an optional localhost-only HTTP management interface.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ecan0/serpent-wrt/internal/runtime"
)

// Server is a lightweight HTTP server bound to localhost.
type Server struct {
	eng *runtime.Engine
	srv *http.Server
}

// New creates a Server bound to addr backed by the given Engine.
func New(addr string, eng *runtime.Engine) *Server {
	s := &Server{eng: eng}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/detections/recent", s.handleRecentDetections)

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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
