package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ecan0/serpent-wrt/internal/config"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var rpcdHTTPClient = newRPCDHTTPClient()

var rpcdAllowedAPIRoutes = map[string]struct{}{
	"GET /healthz":           {},
	"GET /status":            {},
	"GET /stats":             {},
	"GET /detections/recent": {},
	"GET /blocked":           {},
	"GET /feed":              {},
	"PUT /feed":              {},
	"POST /feed/validate":    {},
	"POST /feed/add":         {},
	"POST /feed/remove":      {},
	"POST /reload":           {},
}

func newRPCDHTTPClient() *http.Client {
	return &http.Client{
		Timeout: rpcdAPIRequestTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   rpcdAPIRequestTimeout,
				KeepAlive: 10 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func rpcdAPIOrigin(cfg *config.Config) (string, error) {
	if !cfg.APIEnabled {
		return "", errors.New("API is disabled by configuration")
	}
	if err := rpcdValidateLoopbackAPI(cfg); err != nil {
		return "", err
	}
	host, port, err := net.SplitHostPort(cfg.APIBind)
	if err != nil {
		return "", fmt.Errorf("invalid API bind: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("API bind is not a literal loopback IP")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("API port is invalid")
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), port)}).String(), nil
}

func rpcdAPIRequest(cfg *config.Config, method, route string, request any) (json.RawMessage, error) {
	key := method + " " + route
	if _, ok := rpcdAllowedAPIRoutes[key]; !ok {
		return nil, errors.New("API route is not permitted by the rpcd adapter")
	}
	origin, err := rpcdAPIOrigin(cfg)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return nil, errors.New("cannot encode API request")
		}
		if len(encoded) > rpcdMaxInputBytes {
			return nil, fmt.Errorf("API request exceeds %d bytes", rpcdMaxInputBytes)
		}
		body = bytes.NewReader(encoded)
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcdAPIRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, origin+route, body)
	if err != nil {
		return nil, errors.New("cannot create loopback API request")
	}
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := rpcdHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loopback API unavailable: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, rpcdResponseMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read loopback API response: %w", err)
	}
	if len(data) > rpcdResponseMaxBytes {
		return nil, fmt.Errorf("loopback API response exceeds %d bytes", rpcdResponseMaxBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(data))
		if len(message) > 512 {
			message = message[:512]
		}
		return nil, fmt.Errorf("loopback API returned HTTP %d: %s", response.StatusCode, message)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("loopback API returned invalid JSON: %w", err)
	}
	return append(json.RawMessage(nil), data...), nil
}

func rpcdHealthCheck(cfg *config.Config) error {
	data, err := rpcdAPIRequest(cfg, http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	var response struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("decode loopback API health: %w", err)
	}
	if response.Status != "ok" {
		return errors.New("loopback API health status is not ok")
	}
	return nil
}
