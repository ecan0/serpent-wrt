package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/api"
	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/runtime"
	"gopkg.in/yaml.v3"
)

func rpcdTestConfig(t *testing.T, directory, feedPath, apiBind string, apiEnabled bool) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedPath, []byte("192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "serpent-wrt.yaml")
	text := fmt.Sprintf("threat_feed_path: %q\napi_enabled: %t\n", feedPath, apiEnabled)
	if apiEnabled {
		text += fmt.Sprintf("api_bind: %q\n", apiBind)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rpcdTestCall(t *testing.T, method string, params any, configPath string) (map[string]any, int, string) {
	t.Helper()
	var input []byte
	if params != nil {
		var err error
		input, err = json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := runRPCD([]string{"call", method}, bytes.NewReader(input), &stdout, &stderr, configPath)
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode rpcd result: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
	return result, code, stderr.String()
}

func withRPCDTestState(t *testing.T, directory string, enabled, running bool) {
	t.Helper()
	oldDir, oldQuery, oldCall := rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall
	rpcdAdminDir = directory
	rpcdServiceQuery = func(query string) (bool, error) {
		switch query {
		case "enabled":
			return enabled, nil
		case "running":
			return running, nil
		default:
			return false, fmt.Errorf("unexpected service query %q", query)
		}
	}
	rpcdServiceCall = func(action string) error {
		switch action {
		case "start":
			running = true
		case "stop":
			running = false
		case "restart":
			running = true
		case "enable":
			enabled = true
		case "disable":
			enabled = false
		default:
			return fmt.Errorf("unexpected service action %q", action)
		}
		return nil
	}
	t.Cleanup(func() {
		rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall = oldDir, oldQuery, oldCall
	})
}

func TestRPCDConfigGetIgnoresSessionMetadataAndRejectsOtherFields(t *testing.T) {
	dir := t.TempDir()
	path := rpcdTestConfig(t, dir, filepath.Join(dir, "feed.txt"), "", false)

	result, code, stderr := rpcdTestCall(t, "config_get", map[string]any{
		"ubus_rpc_session": "authenticated-session",
	}, path)
	revision, ok := result["revision"].(string)
	if code != 0 || stderr != "" || !ok || revision == "" {
		t.Fatalf("config_get rejected rpcd session metadata: code=%d stderr=%q result=%v", code, stderr, result)
	}

	result, code, stderr = rpcdTestCall(t, "config_get", map[string]any{
		"ubus_rpc_session": "authenticated-session",
		"unknown":          true,
	}, path)
	if code != 0 || stderr != "" || result["status"] != "error" ||
		!strings.Contains(fmt.Sprint(result["error"]), `unknown field "unknown"`) {
		t.Fatalf("config_get accepted an unrelated field: code=%d stderr=%q result=%v", code, stderr, result)
	}
}

func TestRPCDListExposesOnlyScopedMethodsAndTypedParameters(t *testing.T) {
	var output bytes.Buffer
	if code := runRPCD([]string{"list"}, nil, &output, io.Discard, "/unused"); code != 0 {
		t.Fatalf("rpcd list exit=%d", code)
	}
	var methods map[string]map[string]any
	if err := json.Unmarshal(output.Bytes(), &methods); err != nil {
		t.Fatal(err)
	}
	want := []string{"overview", "config_get", "config_validate", "config_apply", "service", "feed_list", "feed_validate", "feed_add", "feed_remove", "feed_replace", "feed_reload"}
	if len(methods) != len(want) {
		t.Fatalf("method count=%d want=%d", len(methods), len(want))
	}
	for _, name := range want {
		if _, ok := methods[name]; !ok {
			t.Fatalf("method %q is absent", name)
		}
	}
	if methods["config_apply"]["document"] != "" || methods["config_apply"]["revision"] != "" {
		t.Fatalf("config_apply signature=%v", methods["config_apply"])
	}
	if methods["feed_list"]["offset"] != float64(20000) || methods["feed_list"]["limit"] != float64(100) {
		t.Fatalf("feed_list signature=%v", methods["feed_list"])
	}
}

func TestRPCDRejectsUnknownMethodsFieldsAndOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unused.yaml")
	for name, input := range map[string]string{
		"unknown method": `{"x":1}`,
		"unknown field":  `{"action":"restart","executable":"/bin/sh"}`,
		"trailing JSON":  `{} {}`,
		"array":          `[]`,
		"oversized":      `{"x":"` + strings.Repeat("x", rpcdMaxInputBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			method := "service"
			if name == "unknown method" {
				method = "exec"
			}
			var stdout, stderr bytes.Buffer
			inputReader := strings.NewReader(input)
			code := runRPCD([]string{"call", method}, inputReader, &stdout, &stderr, path)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("rpcd exit=%d stderr=%q", code, stderr.String())
			}
			var result map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["status"] != "error" || result["error"] == "" {
				t.Fatalf("result=%v want explicit error", result)
			}
		})
	}
}

func TestRPCDConfigGetPreservesRawOmissionsAndRevision(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, code, stderr := rpcdTestCall(t, "config_get", map[string]any{}, path)
	if code != 0 || stderr != "" {
		t.Fatalf("rpcd exit=%d stderr=%q", code, stderr)
	}
	if result["revision"] != rpcdRevision(before) {
		t.Fatalf("revision=%v want %s", result["revision"], rpcdRevision(before))
	}
	raw := result["config"].(map[string]any)
	if _, exists := raw["profile"]; exists {
		t.Fatalf("raw config acquired an omitted profile default: %v", raw)
	}
	effective := result["effective_config"].(map[string]any)
	if effective["profile"] != "home" || effective["poll_interval"] != "5s" {
		t.Fatalf("effective defaults missing: %v", effective)
	}
}

func TestRPCDConfigValidateRejectsUnknownFieldsAndNonLoopbackAPI(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	for name, document := range map[string]string{
		"unknown":      fmt.Sprintf(`{"threat_feed_path":%q,"unknown":true}`, feedPath),
		"non-loopback": fmt.Sprintf(`{"threat_feed_path":%q,"api_enabled":true,"api_bind":"router.lan:8080"}`, feedPath),
		"bad feed":     fmt.Sprintf(`{"threat_feed_path":%q,"collector":"invalid"}`, filepath.Join(dir, "missing-feed")),
	} {
		t.Run(name, func(t *testing.T) {
			result, code, stderr := rpcdTestCall(t, "config_validate", map[string]string{"document": document}, path)
			if code != 0 || stderr != "" {
				t.Fatalf("rpcd exit=%d stderr=%q", code, stderr)
			}
			if result["valid"] != false || result["error"] == "" {
				t.Fatalf("result=%v want validation failure", result)
			}
		})
	}
	valid := fmt.Sprintf(`{"threat_feed_path":%q,"lease_enrichment":true}`, feedPath)
	result, _, _ := rpcdTestCall(t, "config_validate", map[string]string{"document": valid}, path)
	if result["valid"] != true || result["effective_config"] == nil || result["warnings"] == nil {
		t.Fatalf("validation result=%v", result)
	}
}

func TestRPCDConfigApplyPreservesStoppedStateAndRevision(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	before, _ := os.ReadFile(path)
	document := fmt.Sprintf(`{"threat_feed_path":%q,"profile":"quiet","detectors":{"scan":{"distinct_port_threshold":12}}}`, feedPath)
	result, code, stderr := rpcdTestCall(t, "config_apply", map[string]string{"document": document, "revision": rpcdRevision(before)}, path)
	if code != 0 || stderr != "" {
		t.Fatalf("rpcd exit=%d stderr=%q", code, stderr)
	}
	if result["revision"] == "" || result["service"].(map[string]any)["running"] != false {
		t.Fatalf("apply result=%v", result)
	}
	after, _ := os.ReadFile(path)
	var raw map[string]any
	if err := json.Unmarshal(mustJSONFromYAML(t, after), &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["poll_interval"]; exists {
		t.Fatalf("config apply persisted an absent default: %s", after)
	}
	if result["revision"] != rpcdRevision(after) {
		t.Fatalf("revision=%v does not hash persisted bytes", result["revision"])
	}
}

func mustJSONFromYAML(t *testing.T, data []byte) []byte {
	t.Helper()
	var value map[string]any
	if err := yaml.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRPCDConfigApplyRejectsStaleRevisionAndInvalidDocumentWithoutWrite(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	before, _ := os.ReadFile(path)
	for name, revision := range map[string]string{"stale": strings.Repeat("0", 64), "valid": rpcdRevision(before)} {
		document := fmt.Sprintf(`{"threat_feed_path":%q,"unknown":true}`, feedPath)
		result, _, _ := rpcdTestCall(t, "config_apply", map[string]string{"document": document, "revision": revision}, path)
		if result["status"] != "error" {
			t.Fatalf("%s result=%v want explicit failure", name, result)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatalf("%s request changed configuration", name)
		}
	}
}

func TestRPCDConfigApplyRollsBackOnLoopbackHealthFailure(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	oldBind := strings.TrimPrefix(server.URL, "http://")
	path := rpcdTestConfig(t, dir, feedPath, oldBind, true)
	adminDir := filepath.Join(dir, "run")
	if err := os.Mkdir(adminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldDir, oldQuery, oldCall := rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall
	rpcdAdminDir = adminDir
	rpcdServiceQuery = func(string) (bool, error) { return true, nil }
	restarts := 0
	rpcdServiceCall = func(action string) error {
		if action != "restart" {
			t.Fatalf("unexpected action %q", action)
		}
		restarts++
		return nil
	}
	t.Cleanup(func() { rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall = oldDir, oldQuery, oldCall })
	before, _ := os.ReadFile(path)
	candidate := fmt.Sprintf(`{"threat_feed_path":%q,"api_enabled":true,"api_bind":"127.0.0.1:1"}`, feedPath)
	result, _, _ := rpcdTestCall(t, "config_apply", map[string]string{"document": candidate, "revision": rpcdRevision(before)}, path)
	if result["status"] != "error" || !strings.Contains(result["error"].(string), "previous configuration was restored") {
		t.Fatalf("apply result=%v want explicit restored failure", result)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatalf("configuration rollback did not restore exact prior bytes\n got %q\nwant %q", after, before)
	}
	if restarts != 2 {
		t.Fatalf("restart calls=%d want apply+one rollback restart", restarts)
	}
}

func TestRPCDConfigApplyReportsRollbackFailure(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	path := rpcdTestConfig(t, dir, feedPath, strings.TrimPrefix(server.URL, "http://"), true)
	adminDir := filepath.Join(dir, "run")
	_ = os.Mkdir(adminDir, 0o700)
	oldDir, oldQuery, oldCall := rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall
	rpcdAdminDir = adminDir
	rpcdServiceQuery = func(string) (bool, error) { return true, nil }
	restarts := 0
	rpcdServiceCall = func(action string) error {
		if action != "restart" {
			return fmt.Errorf("unexpected action %q", action)
		}
		restarts++
		if restarts == 2 {
			return errors.New("rollback restart failed")
		}
		return nil
	}
	t.Cleanup(func() { rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall = oldDir, oldQuery, oldCall })
	before, _ := os.ReadFile(path)
	candidate := fmt.Sprintf(`{"threat_feed_path":%q,"api_enabled":true,"api_bind":"127.0.0.1:1"}`, feedPath)
	result, _, _ := rpcdTestCall(t, "config_apply", map[string]string{"document": candidate, "revision": rpcdRevision(before)}, path)
	if result["status"] != "error" || !strings.Contains(result["error"].(string), "rollback failed") {
		t.Fatalf("apply result=%v want rollback failure", result)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("rollback failure did not report restored prior bytes")
	}
}

func TestRPCDFeedFileModePagesAndPersistsCanonicalEntries(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	for _, item := range []string{"192.0.2.1", "2001:db8::1", "198.51.100.0/24"} {
		result, _, _ := rpcdTestCall(t, "feed_add", map[string]string{"entry": item}, path)
		if result["path"] != feedPath {
			t.Fatalf("add result=%v", result)
		}
	}
	page1, _, _ := rpcdTestCall(t, "feed_list", map[string]any{"limit": 2}, path)
	if page1["count"] != float64(4) || page1["next_offset"] != float64(2) || len(page1["entries"].([]any)) != 2 {
		t.Fatalf("page1=%v", page1)
	}
	page2, _, _ := rpcdTestCall(t, "feed_list", map[string]any{"offset": 2, "limit": 2}, path)
	if page2["next_offset"] != nil || len(page2["entries"].([]any)) != 2 {
		t.Fatalf("page2=%v", page2)
	}
	beyond, _, _ := rpcdTestCall(t, "feed_list", map[string]any{"offset": 2147483647, "limit": 100}, path)
	if len(beyond["entries"].([]any)) != 0 || beyond["next_offset"] != nil {
		t.Fatalf("out-of-range page=%v", beyond)
	}
	validation, _, _ := rpcdTestCall(t, "feed_validate", map[string]string{"document": `["192.0.2.7","2001:db8::7/64"]`}, path)
	if validation["valid"] != true || validation["count"] != float64(2) || validation["entries"] != nil || len(validation["warnings"].([]any)) == 0 {
		t.Fatalf("feed validate result=%v", validation)
	}
	removed, _, _ := rpcdTestCall(t, "feed_remove", map[string]string{"entry": "192.0.2.1"}, path)
	if removed["changed"] != true {
		t.Fatalf("remove result=%v", removed)
	}
	replaced, _, _ := rpcdTestCall(t, "feed_replace", map[string]string{"document": `["203.0.113.0/24"]`}, path)
	if replaced["count"] != float64(1) {
		t.Fatalf("replace result=%v", replaced)
	}
	snapshot, err := feed.ListFile(feedPath)
	if err != nil || snapshot.Count != 1 || snapshot.Entries[0].Value != "203.0.113.0/24" {
		t.Fatalf("persisted feed=%+v err=%v", snapshot, err)
	}
}

func TestRPCDFeedWritesRefuseRunningServiceWhenAPIIsDisabled(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), true, true)
	before, _ := os.ReadFile(feedPath)
	result, _, _ := rpcdTestCall(t, "feed_add", map[string]string{"entry": "203.0.113.1"}, path)
	if result["status"] != "error" || !strings.Contains(result["error"].(string), "API is disabled") {
		t.Fatalf("result=%v want explicit unavailable", result)
	}
	after, _ := os.ReadFile(feedPath)
	if !bytes.Equal(before, after) {
		t.Fatal("feed changed while writes were refused")
	}
	list, _, _ := rpcdTestCall(t, "feed_list", map[string]any{}, path)
	if list["status"] != "error" || !strings.Contains(list["error"].(string), "API is disabled") {
		t.Fatalf("list=%v want explicit unavailable, not disk fallback", list)
	}
}

func TestRPCDFeedRunningModeUsesExistingHTTPManagementRoutes(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feedPath, []byte("192.0.2.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bind := listener.Addr().String()
	_ = listener.Close()
	configPath := rpcdTestConfig(t, dir, feedPath, bind, true)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	engine := runtime.NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))
	server := api.New(bind, engine)
	go func() { _ = server.Start() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Stop(ctx)
	}()
	ready := false
	for attempt := 0; attempt < 40; attempt++ {
		if rpcdHealthCheck(cfg) == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("local API did not become healthy")
	}
	withRPCDTestState(t, filepath.Join(dir, "run"), true, true)
	added, _, _ := rpcdTestCall(t, "feed_add", map[string]string{"entry": "2001:db8::20"}, configPath)
	if added["changed"] != true {
		t.Fatalf("add=%v", added)
	}
	snapshot, err := rpcdFeedSnapshot(configPath)
	if err != nil || snapshot.Count != 2 {
		t.Fatalf("API feed after add: snapshot=%+v err=%v", snapshot, err)
	}
	page, _, _ := rpcdTestCall(t, "feed_list", map[string]any{"limit": 1}, configPath)
	if page["count"] != float64(2) || page["next_offset"] != float64(1) {
		t.Fatalf("page=%v", page)
	}
	removed, _, _ := rpcdTestCall(t, "feed_remove", map[string]string{"entry": "2001:db8::20"}, configPath)
	snapshot, err = rpcdFeedSnapshot(configPath)
	if err != nil || removed["changed"] != true || snapshot.Count != 1 {
		t.Fatalf("remove=%v API snapshot=%+v err=%v", removed, snapshot, err)
	}
}

func TestRPCDOverviewReportsUnavailableAPIAndPerSourceErrors(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), true, true)
	result, _, _ := rpcdTestCall(t, "overview", map[string]any{}, path)
	for _, source := range []string{"status", "stats", "detections", "blocked"} {
		entry := result[source].(map[string]any)
		if entry["available"] != false || entry["error"] == "" {
			t.Fatalf("%s=%v want unavailable result", source, entry)
		}
		if result["errors"].(map[string]any)[source] == nil {
			t.Fatalf("errors missing source %q: %v", source, result["errors"])
		}
	}
}

func TestRPCDServiceRestartOnlyRunsForPreviouslyRunningService(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	for _, running := range []bool{false, true} {
		running := running
		withRPCDTestState(t, filepath.Join(dir, fmt.Sprintf("run-%t", running)), true, running)
		calls := 0
		old := rpcdServiceCall
		rpcdServiceCall = func(action string) error {
			if action != "restart" {
				t.Fatalf("action=%q", action)
			}
			calls++
			return nil
		}
		result, _, _ := rpcdTestCall(t, "service", map[string]string{"action": "restart"}, path)
		rpcdServiceCall = old
		if result["status"] != "ok" {
			t.Fatalf("result=%v", result)
		}
		want := 0
		if running {
			want = 1
		}
		if calls != want {
			t.Fatalf("running=%t restart calls=%d want %d", running, calls, want)
		}
	}
}

func TestRPCDAPIClientRefusesRedirectsAndOversizedResponses(t *testing.T) {
	destinationHits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationHits++
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/healthz", http.StatusFound)
	}))
	defer redirect.Close()
	cfg := &config.Config{APIEnabled: true, APIBind: strings.TrimPrefix(redirect.URL, "http://")}
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits++
		http.Error(w, "proxy use is forbidden", http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	if _, err := rpcdAPIRequest(cfg, http.MethodGet, "/healthz", nil); err == nil {
		t.Fatal("API redirect was followed or accepted")
	}
	if destinationHits != 0 {
		t.Fatal("loopback API client followed a redirect")
	}
	if proxyHits != 0 {
		t.Fatal("loopback API client used the proxy environment")
	}

	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, strings.Repeat("x", rpcdResponseMaxBytes+1))
	}))
	defer large.Close()
	cfg.APIBind = strings.TrimPrefix(large.URL, "http://")
	if _, err := rpcdAPIRequest(cfg, http.MethodGet, "/healthz", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestRPCDRejectsConfigAndFeedDocumentsAboveLimits(t *testing.T) {
	for _, request := range []struct {
		method string
		params any
	}{
		{"config_validate", map[string]string{"document": strings.Repeat("x", rpcdConfigMaxBytes+1)}},
		{"feed_validate", map[string]string{"document": `[` + strings.Repeat(" ", rpcdMaxInputBytes) + `]`}},
	} {
		result, _, _ := rpcdTestCall(t, request.method, request.params, filepath.Join(t.TempDir(), "x.yaml"))
		if result["status"] != "error" {
			t.Fatalf("%s=%v want bounded-input error", request.method, result)
		}
	}
}

func TestRPCDOverviewRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := rpcdTestConfig(t, dir, filepath.Join(dir, "feed.txt"), "", false)
	result, code, stderr := rpcdTestCall(t, "overview", map[string]any{"path": "/tmp/secret"}, path)
	if code != 0 || stderr != "" || result["status"] != "error" {
		t.Fatalf("overview accepted an unknown field: code=%d stderr=%q result=%v", code, stderr, result)
	}
}

func TestRPCDServiceStartValidatesBeforeRunningCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(path, []byte("threat_feed_path: /missing/feed.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	calls := 0
	oldCall := rpcdServiceCall
	rpcdServiceCall = func(string) error { calls++; return nil }
	defer func() { rpcdServiceCall = oldCall }()
	result, _, _ := rpcdTestCall(t, "service", map[string]string{"action": "start"}, path)
	if result["status"] != "error" || calls != 0 {
		t.Fatalf("invalid config start result=%v service calls=%d", result, calls)
	}
}

func TestRPCDConfigApplyRejectsNonLoopbackAPIWithoutWrite(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	before, _ := os.ReadFile(path)
	document := fmt.Sprintf(`{"threat_feed_path":%q,"api_enabled":true,"api_bind":"router.lan:8080"}`, feedPath)
	result, _, _ := rpcdTestCall(t, "config_apply", map[string]string{"document": document, "revision": rpcdRevision(before)}, path)
	if result["status"] != "error" || !strings.Contains(fmt.Sprint(result["error"]), "loopback") {
		t.Fatalf("non-loopback apply result=%v", result)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("non-loopback configuration changed the installed file")
	}
}

func TestRPCDConfigApplySerializesCompetingRevisions(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	path := rpcdTestConfig(t, dir, feedPath, "", false)
	withRPCDTestState(t, filepath.Join(dir, "run"), false, false)
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	documents := []string{
		fmt.Sprintf(`{"threat_feed_path":%q,"profile":"quiet"}`, feedPath),
		fmt.Sprintf(`{"threat_feed_path":%q,"profile":"homelab"}`, feedPath),
	}
	var wait sync.WaitGroup
	results := make(chan map[string]any, len(documents))
	for _, document := range documents {
		wait.Add(1)
		go func(document string) {
			defer wait.Done()
			result, code, stderr := rpcdTestCall(t, "config_apply", map[string]string{
				"document": document,
				"revision": rpcdRevision(prior),
			}, path)
			if code != 0 || stderr != "" {
				t.Errorf("rpcd exit=%d stderr=%q", code, stderr)
			}
			results <- result
		}(document)
	}
	wait.Wait()
	close(results)
	successes, stale := 0, 0
	for result := range results {
		if _, ok := result["revision"]; ok {
			successes++
			continue
		}
		if strings.Contains(fmt.Sprint(result["error"]), "stale") {
			stale++
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("concurrent apply results: success=%d stale=%d", successes, stale)
	}
}

func TestRPCDConfigGetRejectsMissingConfiguration(t *testing.T) {
	result, _, _ := rpcdTestCall(t, "config_get", map[string]any{}, filepath.Join(t.TempDir(), "missing.yaml"))
	if result["status"] != "error" || result["error"] == "" {
		t.Fatalf("missing config result=%v", result)
	}
}

func TestRPCDPageBoundsRejectsNegativeAndOversizedLimits(t *testing.T) {
	for _, request := range []rpcdPageRequest{
		{Offset: ptr(-1), Limit: ptr(1)},
		{Offset: ptr(0), Limit: ptr(0)},
		{Offset: ptr(0), Limit: ptr(101)},
	} {
		if _, _, err := rpcdPageBounds(request); err == nil {
			t.Fatalf("page bounds accepted %+v", request)
		}
	}
}

func TestRPCDServiceActionsReturnActualAutostartAndRunState(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.txt")
	configPath := rpcdTestConfig(t, dir, feedPath, "", false)
	adminDir := filepath.Join(dir, "run")
	var enabled, running bool
	oldDir, oldQuery, oldCall := rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall
	rpcdAdminDir = adminDir
	rpcdServiceQuery = func(query string) (bool, error) {
		if query == "enabled" {
			return enabled, nil
		}
		if query == "running" {
			return running, nil
		}
		return false, fmt.Errorf("unexpected query %q", query)
	}
	rpcdServiceCall = func(action string) error {
		switch action {
		case "enable":
			enabled = true
		case "disable":
			enabled = false
		case "start":
			running = true
		case "stop":
			running = false
		case "restart":
			if !running {
				return errors.New("restart called on stopped service")
			}
		default:
			return fmt.Errorf("unexpected action %q", action)
		}
		return nil
	}
	t.Cleanup(func() { rpcdAdminDir, rpcdServiceQuery, rpcdServiceCall = oldDir, oldQuery, oldCall })

	for _, step := range []struct {
		action      string
		wantEnabled bool
		wantRunning bool
	}{
		{"enable", true, false},
		{"start", true, true},
		{"restart", true, true},
		{"stop", true, false},
		{"disable", false, false},
	} {
		result, _, _ := rpcdTestCall(t, "service", map[string]string{"action": step.action}, configPath)
		state := result["service"].(map[string]any)
		if state["enabled"] != step.wantEnabled || state["running"] != step.wantRunning {
			t.Fatalf("action %s returned service state %v", step.action, state)
		}
	}
}
