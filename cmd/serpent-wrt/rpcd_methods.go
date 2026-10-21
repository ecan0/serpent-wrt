package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ecan0/serpent-wrt/internal/feed"
)

const rpcdMaxFeedEntries = feed.MaxManagedEntries

var rpcdFeedWarnings = []string{
	"Syntax validation does not establish source trust or reputation.",
	"Syntax validation does not establish feed freshness.",
	"Check ownership and license rights before you use feed data.",
}

type rpcdPageRequest struct {
	Offset *int `json:"offset"`
	Limit  *int `json:"limit"`
}

type rpcdDocumentRequest struct {
	Document string `json:"document"`
}

type rpcdEntryRequest struct {
	Entry string `json:"entry"`
}

func rpcdOverview(params json.RawMessage, configPath string) (any, error) {
	if err := decodeRPCParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	state, serviceErr := rpcdGetServiceState()
	service := any(state)
	errorsBySource := map[string]string{}
	if serviceErr != nil {
		service = map[string]any{"available": false, "error": serviceErr.Error()}
		errorsBySource["service"] = serviceErr.Error()
	}
	result := map[string]any{
		"service":    service,
		"status":     map[string]any{"available": false},
		"stats":      map[string]any{"available": false},
		"detections": map[string]any{"available": false},
		"blocked":    map[string]any{"available": false},
		"errors":     errorsBySource,
	}
	cfg, err := rpcdLoadInstalledConfig(configPath)
	if err != nil {
		message := "configuration unavailable or invalid"
		result["errors"].(map[string]string)["config"] = message
		for _, source := range []string{"status", "stats", "detections", "blocked"} {
			result[source] = map[string]any{"available": false, "error": "configuration unavailable"}
			errorsBySource[source] = "configuration unavailable"
		}
		return result, nil
	}
	if !cfg.APIEnabled {
		for _, source := range []string{"status", "stats", "detections", "blocked"} {
			message := "API is disabled by configuration"
			result[source] = map[string]any{"available": false, "error": message}
			errorsBySource[source] = message
		}
		return result, nil
	}
	if err := rpcdValidateLoopbackAPI(cfg); err != nil {
		for _, source := range []string{"status", "stats", "detections", "blocked"} {
			result[source] = map[string]any{"available": false, "error": err.Error()}
			errorsBySource[source] = err.Error()
		}
		return result, nil
	}
	for _, source := range []struct {
		name  string
		route string
	}{
		{"status", "/status"},
		{"stats", "/stats"},
		{"detections", "/detections/recent"},
		{"blocked", "/blocked"},
	} {
		body, requestErr := rpcdAPIRequest(cfg, http.MethodGet, source.route, nil)
		if requestErr != nil {
			result[source.name] = map[string]any{"available": false, "error": requestErr.Error()}
			errorsBySource[source.name] = requestErr.Error()
			continue
		}
		result[source.name] = json.RawMessage(body)
	}
	return result, nil
}

func rpcdConfigGet(params json.RawMessage, configPath string) (any, error) {
	if err := decodeRPCParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	data, raw, err := rpcdReadConfig(configPath)
	if err != nil {
		return nil, err
	}
	validated, err := rpcdValidateYAMLFile(configPath, data)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"config":           raw,
		"revision":         rpcdRevision(data),
		"effective_config": newEffectiveConfig(validated.Config),
	}, nil
}

func rpcdConfigValidate(params json.RawMessage, configPath string) (any, error) {
	var request rpcdDocumentRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	data, err := rpcdJSONToYAML(request.Document, rpcdConfigMaxBytes)
	if err != nil {
		return nil, err
	}
	validated, err := rpcdValidateYAMLFile(configPath, data)
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}, nil
	}
	return map[string]any{
		"valid":            true,
		"warnings":         validated.Warnings,
		"effective_config": newEffectiveConfig(validated.Config),
	}, nil
}

func rpcdConfigApply(params json.RawMessage, configPath string) (any, error) {
	return rpcdApplyConfig(params, configPath)
}

func rpcdService(params json.RawMessage, configPath string) (any, error) {
	return rpcdServiceControl(params, configPath)
}

func rpcdFeedList(params json.RawMessage, configPath string) (any, error) {
	var request rpcdPageRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	offset, limit, err := rpcdPageBounds(request)
	if err != nil {
		return nil, err
	}
	snapshot, err := rpcdFeedSnapshot(configPath)
	if err != nil {
		return nil, err
	}
	if snapshot.Count > rpcdMaxFeedEntries {
		return nil, fmt.Errorf("feed has %d entries; management limit is %d", snapshot.Count, rpcdMaxFeedEntries)
	}
	end := len(snapshot.Entries)
	start := offset
	if start > end {
		start = end
	}
	if start < end {
		pageEnd := start + limit
		if pageEnd < start || pageEnd > end {
			pageEnd = end
		}
		end = pageEnd
	}
	entries := snapshot.Entries[start:end]
	var next *int
	if end < snapshot.Count {
		next = &end
	}
	return map[string]any{
		"count":       snapshot.Count,
		"max_entries": rpcdMaxFeedEntries,
		"entries":     entries,
		"next_offset": next,
	}, nil
}

func rpcdPageBounds(request rpcdPageRequest) (int, int, error) {
	offset, limit := 0, 100
	if request.Offset != nil {
		offset = *request.Offset
	}
	if request.Limit != nil {
		limit = *request.Limit
	}
	if offset < 0 {
		return 0, 0, errors.New("offset must not be negative")
	}
	if limit < 1 || limit > 100 {
		return 0, 0, errors.New("limit must be from 1 through 100")
	}
	return offset, limit, nil
}

func rpcdFeedValidate(params json.RawMessage, _ string) (any, error) {
	var request rpcdDocumentRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	entries, err := rpcdEntriesDocument(request.Document)
	if err != nil {
		return nil, err
	}
	snapshot, err := feed.ValidateEntries(entries)
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}, nil
	}
	return map[string]any{
		"valid":    true,
		"count":    snapshot.Count,
		"warnings": append([]string(nil), rpcdFeedWarnings...),
	}, nil
}

func rpcdFeedAdd(params json.RawMessage, configPath string) (any, error) {
	var request rpcdEntryRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	return rpcdFeedMutation(configPath, http.MethodPost, "/feed/add", map[string]string{"entry": request.Entry}, func(path string) (any, error) {
		return feed.AddFileEntry(path, request.Entry)
	})
}

func rpcdFeedRemove(params json.RawMessage, configPath string) (any, error) {
	var request rpcdEntryRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	return rpcdFeedMutation(configPath, http.MethodPost, "/feed/remove", map[string]string{"entry": request.Entry}, func(path string) (any, error) {
		return feed.RemoveFileEntry(path, request.Entry)
	})
}

func rpcdFeedReplace(params json.RawMessage, configPath string) (any, error) {
	var request rpcdDocumentRequest
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	entries, err := rpcdEntriesDocument(request.Document)
	if err != nil {
		return nil, err
	}
	return rpcdFeedMutation(configPath, http.MethodPut, "/feed", map[string][]string{"entries": entries}, func(path string) (any, error) {
		return feed.ReplaceFileEntries(path, entries)
	})
}

func rpcdFeedReload(params json.RawMessage, configPath string) (any, error) {
	if err := decodeRPCParams(params, &struct{}{}); err != nil {
		return nil, err
	}
	var result any
	err := withRPCDAdminLock(func() error {
		cfg, err := rpcdLoadInstalledConfig(configPath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		state, err := rpcdGetServiceState()
		if err != nil {
			return err
		}
		if !state.Running {
			count, err := feed.ValidateFile(cfg.ThreatFeedPath)
			if err != nil {
				return fmt.Errorf("feed validation failed while service is stopped: %w", err)
			}
			result = map[string]any{"status": "not_running", "reloaded": false, "feed_entries": count}
			return nil
		}
		if !cfg.APIEnabled {
			return errors.New("feed reload is unavailable while the API is disabled and the service is running")
		}
		body, err := rpcdAPIRequest(cfg, http.MethodPost, "/reload", nil)
		if err != nil {
			return err
		}
		result = json.RawMessage(body)
		return nil
	})
	if err != nil {
		return map[string]any{"status": "error", "error": err.Error()}, nil
	}
	return result, nil
}

func rpcdFeedMutation(configPath, method, route string, request any, stopped func(string) (any, error)) (any, error) {
	var result any
	err := withRPCDAdminLock(func() error {
		cfg, err := rpcdLoadInstalledConfig(configPath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		state, err := rpcdGetServiceState()
		if err != nil {
			return err
		}
		if state.Running {
			if !cfg.APIEnabled {
				return errors.New("feed writes are unavailable while the API is disabled and the service is running")
			}
			body, err := rpcdAPIRequest(cfg, method, route, request)
			if err != nil {
				return err
			}
			result = json.RawMessage(body)
			return nil
		}
		result, err = stopped(cfg.ThreatFeedPath)
		return err
	})
	if err != nil {
		return map[string]any{"status": "error", "error": err.Error()}, nil
	}
	return result, nil
}

func rpcdFeedSnapshot(configPath string) (feed.Snapshot, error) {
	cfg, err := rpcdLoadInstalledConfig(configPath)
	if err != nil {
		return feed.Snapshot{}, fmt.Errorf("config: %w", err)
	}
	state, err := rpcdGetServiceState()
	if err != nil {
		return feed.Snapshot{}, err
	}
	if !state.Running {
		return feed.ListFile(cfg.ThreatFeedPath)
	}
	if !cfg.APIEnabled {
		return feed.Snapshot{}, errors.New("feed list is unavailable while the API is disabled and the service is running")
	}
	body, err := rpcdAPIRequest(cfg, http.MethodGet, "/feed", nil)
	if err != nil {
		return feed.Snapshot{}, err
	}
	var snapshot feed.Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return feed.Snapshot{}, fmt.Errorf("decode feed response: %w", err)
	}
	if snapshot.Entries == nil || snapshot.Count != len(snapshot.Entries) {
		return feed.Snapshot{}, errors.New("API returned an invalid feed snapshot")
	}
	return snapshot, nil
}
