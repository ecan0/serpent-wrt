package packagecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runHelper(t *testing.T, name string, environment ...string) int {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell is required for OpenWrt package helpers")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate package helpers")
	}
	command := exec.Command("sh", filepath.Join(filepath.Dir(file), "..", "..", "scripts", name))
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if err == nil {
		return 0
	}
	if failure, ok := err.(*exec.ExitError); ok {
		t.Logf("helper output: %s", output)
		return failure.ExitCode()
	}
	t.Fatalf("start helper: %v", err)
	return -1
}

func TestSDKCheckRejectsInvalidSDK(t *testing.T) {
	if code := runHelper(t, "openwrt-package-check.sh", "OPENWRT_SDK="+t.TempDir()); code != 2 {
		t.Fatalf("invalid SDK exit code: got %d, want 2", code)
	}
}

func TestSDKCheckPreservesExistingPackageWithoutAuthorization(t *testing.T) {
	sdk := t.TempDir()
	for _, directory := range []string{"scripts", "package/serpent-wrt", "feeds/packages/lang/golang"} {
		if err := os.MkdirAll(filepath.Join(sdk, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"rules.mk", "feeds/packages/lang/golang/golang-package.mk"} {
		if err := os.WriteFile(filepath.Join(sdk, file), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(sdk, "package", "serpent-wrt", "existing-package")
	if err := os.WriteFile(sentinel, []byte("keep existing package"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := runHelper(t, "openwrt-package-check.sh", "OPENWRT_SDK="+sdk,
		"OPENWRT_FEEDS_UPDATE=0", "OPENWRT_PACKAGE_OVERWRITE=0")
	if code != 2 {
		t.Fatalf("existing package exit code: got %d, want 2", code)
	}
	content, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "keep existing package" {
		t.Fatalf("existing package changed: %q", content)
	}
}

func TestAPKBuildRejectsSDKChecksumMismatch(t *testing.T) {
	for _, tool := range []string{"curl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required for SDK checksum verification", tool)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("untrusted SDK content"))
	}))
	defer server.Close()
	root := t.TempDir()
	work := filepath.Join(root, "sdk-work")
	code := runHelper(t, "build-openwrt-apk.sh",
		"OPENWRT_SDK_URL="+server.URL,
		"OPENWRT_SDK_SHA256=0000000000000000000000000000000000000000000000000000000000000000",
		"OPENWRT_APK_WORK_DIR="+work,
		"OPENWRT_APK_OUT_DIR="+filepath.Join(root, "artifacts"),
		"OPENWRT_APK_REUSE_WORK_DIR=0",
		"OPENWRT_APK_ARTIFACT_SUFFIX=",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	)
	if code != 1 {
		t.Fatalf("checksum mismatch exit code: got %d, want 1", code)
	}
	for _, marker := range []string{".sdk-url", ".sdk-sha256"} {
		if _, err := os.Stat(filepath.Join(work, marker)); !os.IsNotExist(err) {
			t.Fatalf("unverified SDK has a reuse marker %s: %v", marker, err)
		}
	}
}

// restartHarness models the OpenWrt rc.common service lifecycle around a real
// process. rc.common defines the default restart before it sources the init
// script. A guarded init script must validate the configuration before it
// stops the live process.
const restartHarness = `
set -u

extra_command() { :; }

restart() {
	stop
	start
}

. "$INIT_SCRIPT"

stop() {
	pid=$(cat "$PID_FILE" 2>/dev/null) || return 0
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	rm -f "$PID_FILE"
}

start() {
	configtest || return 1
	sleep 30 &
	echo $! > "$PID_FILE"
	echo $! > "$REPLACEMENT_FILE"
}

configtest() {
	return "$CONFIG_STATUS"
}

sleep 30 &
echo $! > "$PID_FILE"
original=$(cat "$PID_FILE")

restart
status=$?

if kill -0 "$original" 2>/dev/null; then
	echo "original=PID_ALIVE"
else
	echo "original=PID_DEAD"
fi

replacement=$(cat "$REPLACEMENT_FILE" 2>/dev/null || true)
if [ -n "$replacement" ] && kill -0 "$replacement" 2>/dev/null; then
	echo "replacement=PID_ALIVE"
else
	echo "replacement=PID_DEAD"
fi

kill "$original" 2>/dev/null
if [ -n "$replacement" ]; then
	kill "$replacement" 2>/dev/null
fi
wait 2>/dev/null

exit "$status"
`

func TestOpenWrtInitRestartValidatesBeforeStop(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell is required for OpenWrt init scripts")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate OpenWrt init scripts")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	for _, relative := range []string{
		"openwrt/serpent-wrt/files/serpent-wrt.init",
		"contrib/init.d/serpent-wrt",
	} {
		t.Run(strings.ReplaceAll(relative, "/", "_"), func(t *testing.T) {
			initScript := filepath.Join(root, relative)
			for _, testCase := range []struct {
				name         string
				configStatus string
				wantExit     int
				wantOriginal string
				wantReplaced string
			}{
				{
					name:         "invalid_config_preserves_live_service",
					configStatus: "1",
					wantExit:     1,
					wantOriginal: "PID_ALIVE",
					wantReplaced: "PID_DEAD",
				},
				{
					name:         "valid_config_replaces_live_service",
					configStatus: "0",
					wantExit:     0,
					wantOriginal: "PID_DEAD",
					wantReplaced: "PID_ALIVE",
				},
			} {
				t.Run(testCase.name, func(t *testing.T) {
					directory := t.TempDir()
					command := exec.Command("sh", "-c", restartHarness)
					command.Env = append(os.Environ(),
						"INIT_SCRIPT="+initScript,
						"PID_FILE="+filepath.Join(directory, "service.pid"),
						"REPLACEMENT_FILE="+filepath.Join(directory, "replacement.pid"),
						"CONFIG_STATUS="+testCase.configStatus,
					)
					output, err := command.CombinedOutput()
					exit := 0
					if err != nil {
						failure, ok := err.(*exec.ExitError)
						if !ok {
							t.Fatalf("run restart harness: %v: %s", err, output)
						}
						exit = failure.ExitCode()
					}
					if exit != testCase.wantExit {
						t.Fatalf("restart exit code: got %d, want %d: %s", exit, testCase.wantExit, output)
					}
					for _, want := range []string{
						"original=" + testCase.wantOriginal,
						"replacement=" + testCase.wantReplaced,
					} {
						if !strings.Contains(string(output), want) {
							t.Fatalf("restart output %q does not report %s", output, want)
						}
					}
				})
			}
		})
	}
}

func TestGLInetPackageUsesRootOwnedOpkgContainer(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if code := runHelper(t, "package-glinet.sh", "VERSION=0.6.0-test",
		"OPENWRT_BINARY="+binary, "OPENWRT_IPK_OUT_DIR="+output); code != 0 {
		t.Fatalf("package helper exited %d", code)
	}
	checkArchive := func(data []byte) map[string][]byte {
		t.Helper()
		compressed, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("opkg requires a gzip/tar container: %v", err)
		}
		defer func() { _ = compressed.Close() }()
		reader := tar.NewReader(compressed)
		files := make(map[string][]byte)
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if header.Uid != 0 || header.Gid != 0 {
				t.Fatalf("package member %s has non-root owner %d:%d", header.Name, header.Uid, header.Gid)
			}
			if header.Typeflag == tar.TypeReg {
				data, err := io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
				files[strings.TrimPrefix(header.Name, "./")] = data
			}
		}
		return files
	}
	data, err := os.ReadFile(filepath.Join(output, "serpent-wrt_0.6.0-test_aarch64_cortex-a53.ipk"))
	if err != nil {
		t.Fatal(err)
	}
	members := checkArchive(data)
	if string(members["debian-binary"]) != "2.0\n" {
		t.Fatal("opkg format marker is invalid")
	}
	checkArchive(members["control.tar.gz"])
	checkArchive(members["data.tar.gz"])
}
