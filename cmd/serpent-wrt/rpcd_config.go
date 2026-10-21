package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
)

const (
	rpcdConfigMaxBytes    = 256 << 10
	rpcdResponseMaxBytes  = 8 << 20
	rpcdAPIRequestTimeout = 3 * time.Second
)

var (
	rpcdAdminDir     = "/var/run/serpent-wrt"
	rpcdInitScript   = "/etc/init.d/serpent-wrt"
	rpcdServiceCall  = runRPCDServiceCommand
	rpcdServiceQuery = runRPCDServiceQuery
)

type rpcdServiceState struct {
	Enabled bool `json:"enabled"`
	Running bool `json:"running"`
}

type rpcdValidation struct {
	Config   *config.Config
	Warnings []string
}

func rpcdValidateYAMLFile(configPath string, data []byte) (rpcdValidation, error) {
	if len(data) > rpcdConfigMaxBytes {
		return rpcdValidation{}, fmt.Errorf("configuration document exceeds %d bytes", rpcdConfigMaxBytes)
	}
	dir := filepath.Dir(configPath)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return rpcdValidation{}, errors.New("configuration directory is unavailable")
	}
	tmp, err := os.CreateTemp(dir, ".serpent-rpcd-config-*")
	if err != nil {
		return rpcdValidation{}, fmt.Errorf("create validation file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return rpcdValidation{}, fmt.Errorf("write validation file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return rpcdValidation{}, fmt.Errorf("close validation file: %w", err)
	}
	cfg, _, warnings, err := checkConfig(tmpPath)
	if err != nil {
		return rpcdValidation{}, err
	}
	if err := rpcdValidateLoopbackAPI(cfg); err != nil {
		return rpcdValidation{}, err
	}
	return rpcdValidation{Config: cfg, Warnings: warnings}, nil
}

func rpcdValidateLoopbackAPI(cfg *config.Config) error {
	if !cfg.APIEnabled {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.APIBind)
	if err != nil {
		return fmt.Errorf("api_bind must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("rpcd management requires api_bind to use a literal loopback IP")
	}
	return nil
}

func rpcdRevision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func rpcdJSONToYAML(document string, maximum int) ([]byte, error) {
	return rpcdJSONDocument(document, maximum)
}

func rpcdAtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".serpent-rpcd-config-*")
	if err != nil {
		return fmt.Errorf("create configuration transaction: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set configuration mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write configuration transaction: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync configuration transaction: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close configuration transaction: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	directory, err := os.Open(dir)
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func withRPCDAdminLock(fn func() error) error {
	if err := os.MkdirAll(rpcdAdminDir, 0o700); err != nil {
		return fmt.Errorf("create management state directory: %w", err)
	}
	info, err := os.Lstat(rpcdAdminDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("management state directory is unsafe")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("management state directory is not owned by the current user")
	}
	path := filepath.Join(rpcdAdminDir, "rpcd-admin.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open management lock: %w", err)
	}
	defer file.Close()
	lockInfo, err := file.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("management lock is unsafe")
	}
	if stat, ok := lockInfo.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("management lock is not owned by the current user")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock management operations: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

func runRPCDServiceCommand(action string) error {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
	cmd := exec.Command(rpcdInitScript, action)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("service %s failed: %w%s", action, err, rpcdSafeCommandOutput(output))
	}
	return nil
}

func rpcdSafeCommandOutput(output []byte) string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return ""
	}
	if len(text) > 512 {
		text = text[:512]
	}
	return ": " + text
}

func runRPCDServiceQuery(query string) (bool, error) {
	if query != "running" && query != "enabled" {
		return false, errors.New("invalid service query")
	}
	cmd := exec.Command(rpcdInitScript, query)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("service state query %s failed: %w%s", query, err, rpcdSafeCommandOutput(output))
}

func rpcdGetServiceState() (rpcdServiceState, error) {
	enabled, err := rpcdServiceQuery("enabled")
	if err != nil {
		return rpcdServiceState{}, err
	}
	running, err := rpcdServiceQuery("running")
	if err != nil {
		return rpcdServiceState{}, err
	}
	return rpcdServiceState{Enabled: enabled, Running: running}, nil
}

func rpcdReadConfigFile(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("configuration unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("configuration is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("configuration unavailable: %w", err)
	}
	if len(data) > rpcdConfigMaxBytes {
		return nil, 0, fmt.Errorf("configuration exceeds %d bytes", rpcdConfigMaxBytes)
	}
	return data, info.Mode(), nil
}

func rpcdLoadInstalledConfig(path string) (*config.Config, error) {
	if _, _, err := rpcdReadConfigFile(path); err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

func rpcdApplyConfig(params json.RawMessage, configPath string) (any, error) {
	var request struct {
		Document string `json:"document"`
		Revision string `json:"revision"`
	}
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	if request.Revision == "" {
		return nil, errors.New("revision is required")
	}
	candidate, err := rpcdJSONToYAML(request.Document, rpcdConfigMaxBytes)
	if err != nil {
		return nil, err
	}
	var result any
	err = withRPCDAdminLock(func() error {
		previous, mode, err := rpcdReadConfigFile(configPath)
		if err != nil {
			return err
		}
		if rpcdRevision(previous) != request.Revision {
			return errors.New("configuration revision is stale")
		}
		validated, err := rpcdValidateYAMLFile(configPath, candidate)
		if err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
		priorService, err := rpcdGetServiceState()
		if err != nil {
			return err
		}
		if err := rpcdAtomicWrite(configPath, candidate, mode); err != nil {
			return err
		}
		applyErr := error(nil)
		if priorService.Running {
			if err := rpcdServiceCall("restart"); err != nil {
				applyErr = err
			}
		}
		stateAfterApply := priorService
		if applyErr == nil {
			stateAfterApply, applyErr = rpcdGetServiceState()
			if applyErr == nil && stateAfterApply != priorService {
				applyErr = fmt.Errorf("service state changed during configuration apply: enabled=%t running=%t", stateAfterApply.Enabled, stateAfterApply.Running)
			}
		}
		if applyErr == nil && priorService.Running && validated.Config.APIEnabled {
			if err := rpcdHealthCheck(validated.Config); err != nil {
				applyErr = fmt.Errorf("API health check failed: %w", err)
			}
		}
		if applyErr != nil {
			rollbackErr := rpcdAtomicWrite(configPath, previous, mode)
			if rollbackErr == nil && priorService.Running {
				rollbackErr = rpcdServiceCall("restart")
				if rollbackErr == nil {
					priorConfig, validationErr := rpcdValidateYAMLFile(configPath, previous)
					if validationErr != nil {
						rollbackErr = validationErr
					} else {
						rollbackErr = rpcdVerifyServiceAndAPI(priorService, priorConfig.Config)
					}
				}
			}
			if rollbackErr != nil {
				return fmt.Errorf("configuration apply failed: %v; rollback failed: %w", applyErr, rollbackErr)
			}
			return fmt.Errorf("configuration apply failed and previous configuration was restored: %w", applyErr)
		}
		result = map[string]any{
			"revision":         rpcdRevision(candidate),
			"service":          stateAfterApply,
			"effective_config": newEffectiveConfig(validated.Config),
		}
		return nil
	})
	if err != nil {
		return map[string]any{"status": "error", "error": err.Error()}, nil
	}
	return result, nil
}

func rpcdVerifyServiceAndAPI(previous rpcdServiceState, cfg *config.Config) error {
	state, err := rpcdGetServiceState()
	if err != nil {
		return err
	}
	if state.Running != previous.Running || state.Enabled != previous.Enabled {
		return fmt.Errorf("service state changed during configuration apply: enabled=%t running=%t", state.Enabled, state.Running)
	}
	if previous.Running && cfg.APIEnabled {
		if err := rpcdHealthCheck(cfg); err != nil {
			return fmt.Errorf("API health check failed: %w", err)
		}
	}
	return nil
}

func rpcdServiceControl(params json.RawMessage, configPath string) (any, error) {
	var request struct {
		Action string `json:"action"`
	}
	if err := decodeRPCParams(params, &request); err != nil {
		return nil, err
	}
	if request.Action != "start" && request.Action != "stop" && request.Action != "restart" && request.Action != "enable" && request.Action != "disable" {
		return nil, errors.New("action must be start, stop, restart, enable, or disable")
	}
	var result any
	err := withRPCDAdminLock(func() error {
		before, err := rpcdGetServiceState()
		if err != nil {
			return err
		}
		switch request.Action {
		case "start":
			validated, err := rpcdValidateInstalledConfig(configPath)
			if err != nil {
				return err
			}
			if err := rpcdServiceCall("start"); err != nil {
				return err
			}
			if err := rpcdVerifyServiceAndAPI(rpcdServiceState{Enabled: before.Enabled, Running: true}, validated.Config); err != nil {
				return err
			}
		case "restart":
			if before.Running {
				validated, err := rpcdValidateInstalledConfig(configPath)
				if err != nil {
					return err
				}
				if err := rpcdServiceCall("restart"); err != nil {
					return err
				}
				if err := rpcdVerifyServiceAndAPI(before, validated.Config); err != nil {
					return err
				}
			}
		default:
			if err := rpcdServiceCall(request.Action); err != nil {
				return err
			}
		}
		state, err := rpcdGetServiceState()
		if err != nil {
			return err
		}
		result = rpcdSuccess(map[string]any{"action": request.Action, "service": state})
		return nil
	})
	if err != nil {
		return map[string]any{"status": "error", "error": err.Error()}, nil
	}
	return result, nil
}

func rpcdValidateInstalledConfig(path string) (rpcdValidation, error) {
	data, _, err := rpcdReadConfigFile(path)
	if err != nil {
		return rpcdValidation{}, err
	}
	return rpcdValidateYAMLFile(path, data)
}
