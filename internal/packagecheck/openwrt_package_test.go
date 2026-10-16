package packagecheck

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
