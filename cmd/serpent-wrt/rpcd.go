package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const rpcdMaxInputBytes = 1 << 20

type rpcdMethod func(json.RawMessage, string) (any, error)

var rpcdMethods = map[string]rpcdMethod{
	"overview":        rpcdOverview,
	"config_get":      rpcdConfigGet,
	"config_validate": rpcdConfigValidate,
	"config_apply":    rpcdConfigApply,
	"service":         rpcdService,
	"feed_list":       rpcdFeedList,
	"feed_validate":   rpcdFeedValidate,
	"feed_add":        rpcdFeedAdd,
	"feed_remove":     rpcdFeedRemove,
	"feed_replace":    rpcdFeedReplace,
	"feed_reload":     rpcdFeedReload,
}

// rpcdList writes the executable-plugin method names and parameter type samples.
// rpcd infers each ubus argument type from the JSON value in this object.
func rpcdList(stdout io.Writer) error {
	signatures := map[string]map[string]any{
		"overview":        {},
		"config_get":      {},
		"config_validate": {"document": ""},
		"config_apply":    {"document": "", "revision": ""},
		"service":         {"action": ""},
		// rpcd infers INT32 from this sample value; pages can start at 20,000.
		"feed_list":     {"offset": 20000, "limit": 100},
		"feed_validate": {"document": ""},
		"feed_add":      {"entry": ""},
		"feed_remove":   {"entry": ""},
		"feed_replace":  {"document": ""},
		"feed_reload":   {},
	}
	return writeRPCJSON(stdout, signatures)
}

// runRPCD serves the fixed rpcd executable-plugin protocol. It accepts no
// executable paths, URLs, shell fragments, or arbitrary file arguments.
func runRPCD(args []string, stdin io.Reader, stdout, stderr io.Writer, configPath string) int {
	if len(args) == 1 && args[0] == "list" {
		if err := rpcdList(stdout); err != nil {
			writef(stderr, "serpent-wrt: rpcd list: %v\n", err)
			return 1
		}
		return 0
	}
	if len(args) != 2 || args[0] != "call" {
		writef(stderr, "Usage: serpent-wrt rpcd list | call <method>\n")
		return 2
	}
	method := args[1]
	handler, ok := rpcdMethods[method]
	if !ok {
		_ = writeRPCJSON(stdout, rpcdError(fmt.Errorf("unknown method %q", method)))
		return 0
	}
	input, err := readRPCInput(stdin)
	if err != nil {
		_ = writeRPCJSON(stdout, rpcdError(err))
		return 0
	}
	result, err := handler(input, configPath)
	if err != nil {
		result = rpcdError(err)
	}
	if err := writeRPCJSON(stdout, result); err != nil {
		writef(stderr, "serpent-wrt: rpcd call: %v\n", err)
		return 1
	}
	return 0
}

func readRPCInput(reader io.Reader) (json.RawMessage, error) {
	if reader == nil {
		return nil, errors.New("request input is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(reader, rpcdMaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	if len(data) > rpcdMaxInputBytes {
		return nil, fmt.Errorf("request exceeds %d bytes", rpcdMaxInputBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("request must be one JSON object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("request must be one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		return nil, errors.New("request must be one JSON object")
	}
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("request must contain one JSON object")
	}
	if _, ok := object["ubus_rpc_session"]; ok {
		// rpcd adds this session identifier as transport metadata, not as a method argument.
		delete(object, "ubus_rpc_session")
		data, err = json.Marshal(object)
		if err != nil {
			return nil, errors.New("request must be one JSON object")
		}
	}
	return append(json.RawMessage(nil), data...), nil
}

func decodeRPCParams(data json.RawMessage, destination any) error {
	if len(data) == 0 {
		data = json.RawMessage("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid method parameters: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("method parameters must contain one JSON object")
	}
	return nil
}

func writeRPCJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func rpcdError(err error) map[string]any {
	return map[string]any{"status": "error", "error": err.Error()}
}

func rpcdSuccess(values map[string]any) map[string]any {
	values["status"] = "ok"
	return values
}

func rpcdReadConfig(path string) ([]byte, map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("configuration is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("configuration unavailable: %w", err)
	}
	if len(data) > rpcdConfigMaxBytes {
		return nil, nil, fmt.Errorf("configuration exceeds %d bytes", rpcdConfigMaxBytes)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("configuration is invalid: %w", err)
	}
	if raw == nil {
		return nil, nil, errors.New("configuration must be a YAML object")
	}
	return data, raw, nil
}

func marshalRawYAML(value any) ([]byte, error) {
	return yaml.Marshal(normalizeJSONNumbers(value))
}

func normalizeJSONNumbers(value any) any {
	switch typed := value.(type) {
	case json.Number:
		if number, err := typed.Int64(); err == nil {
			return number
		}
		if number, err := typed.Float64(); err == nil {
			return number
		}
		return typed.String()
	case []any:
		for index := range typed {
			typed[index] = normalizeJSONNumbers(typed[index])
		}
		return typed
	case map[string]any:
		for key := range typed {
			typed[key] = normalizeJSONNumbers(typed[key])
		}
		return typed
	default:
		return value
	}
}

func rpcdJSONDocument(document string, maximum int) ([]byte, error) {
	if len(document) > maximum {
		return nil, fmt.Errorf("configuration document exceeds %d bytes", maximum)
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("document must contain one JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("document must contain one JSON object")
	}
	return marshalRawYAML(object)
}

func rpcdEntriesDocument(document string) ([]string, error) {
	if len(document) > rpcdMaxInputBytes {
		return nil, fmt.Errorf("feed document exceeds %d bytes", rpcdMaxInputBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	var entries []string
	if err := decoder.Decode(&entries); err != nil || entries == nil {
		return nil, errors.New("document must contain one JSON entries array")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("document must contain one JSON entries array")
	}
	return entries, nil
}
