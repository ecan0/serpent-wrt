package packagecheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestOpenWrtPackageMetadata(t *testing.T) {
	makefile := readRepoFile(t, "openwrt/serpent-wrt/Makefile")
	required := []string{
		"PKG_NAME:=serpent-wrt",
		"PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz",
		"PKG_SOURCE_URL:=https://codeload.github.com/ecan0/serpent-wrt/tar.gz/v$(PKG_VERSION)?",
		"PKG_LICENSE:=MIT",
		"PKG_LICENSE_FILES:=LICENSE",
		"PKG_BUILD_DEPENDS:=golang/host",
		"GO_PKG:=github.com/ecan0/serpent-wrt",
		"GO_PKG_BUILD_PKG:=github.com/ecan0/serpent-wrt/cmd/serpent-wrt",
		"GO_PKG_INSTALL_BIN_PATH:=/usr/sbin",
		"DEPENDS:=$(GO_ARCH_DEPENDS) +nftables-json +kmod-nf-conntrack",
	}
	for _, want := range required {
		if !strings.Contains(makefile, want) {
			t.Fatalf("OpenWrt package Makefile missing %q", want)
		}
	}

	if strings.Contains(makefile, "PKG_MIRROR_HASH:=skip") {
		t.Fatal("OpenWrt package Makefile must use a fixed PKG_HASH, not PKG_MIRROR_HASH:=skip")
	}
	assertMatch(t, makefile, `(?m)^PKG_SOURCE_DATE:=[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	assertMatch(t, makefile, `(?m)^PKG_SOURCE_VERSION:=[0-9a-f]{40}$`)
	assertMatch(t, makefile, `(?m)^PKG_HASH:=[0-9a-f]{64}$`)
	assertMatch(t, makefile, `(?m)^PKG_RELEASE:=[0-9]+$`)

	goVersionPatch := readRepoFile(t, "openwrt/serpent-wrt/patches/001-openwrt-go-1.26.2.patch")
	for _, want := range []string{
		"OpenWrt 25.12.4 ships Go 1.26.2",
		"-go 1.26.3",
		"+go 1.26.2",
	} {
		if !strings.Contains(goVersionPatch, want) {
			t.Fatalf("OpenWrt Go version patch missing %q", want)
		}
	}
}

func TestOpenWrtPackageInstallsRuntimeFiles(t *testing.T) {
	makefile := readRepoFile(t, "openwrt/serpent-wrt/Makefile")
	for _, want := range []string{
		"/etc/serpent-wrt/serpent-wrt.yaml",
		"/etc/serpent-wrt/threat-feed.txt",
		"$(INSTALL_BIN) ./files/serpent-wrt.init $(1)/etc/init.d/serpent-wrt",
		"$(INSTALL_CONF) ./files/serpent-wrt.yaml $(1)/etc/serpent-wrt/serpent-wrt.yaml",
		"$(INSTALL_DATA) ./files/threat-feed.txt $(1)/etc/serpent-wrt/threat-feed.txt",
	} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("OpenWrt package Makefile missing install/conffile entry %q", want)
		}
	}

	for _, rel := range []string{
		"openwrt/serpent-wrt/files/serpent-wrt.init",
		"openwrt/serpent-wrt/files/serpent-wrt.yaml",
		"openwrt/serpent-wrt/files/threat-feed.txt",
		"openwrt/serpent-wrt/test.sh",
	} {
		if _, err := os.Stat(repoPath(t, rel)); err != nil {
			t.Fatalf("expected package file %s: %v", rel, err)
		}
	}
}

func TestOpenWrtInitValidatesBeforeStartAndReload(t *testing.T) {
	for _, rel := range []string{
		"openwrt/serpent-wrt/files/serpent-wrt.init",
		"contrib/init.d/serpent-wrt",
	} {
		initScript := readRepoFile(t, rel)
		for _, want := range []string{
			`extra_command "configtest" "Validate configuration and threat feed"`,
			`"$PROG" --config "$CONF" configtest`,
			"start_service()",
			"reload_service()",
			"reload_feed()",
			"configtest || return 1",
		} {
			if !strings.Contains(initScript, want) {
				t.Fatalf("%s missing %q", rel, want)
			}
		}
	}
}

func TestOpenWrtSmokeCoversReleaseCriticalPaths(t *testing.T) {
	smoke := readRepoFile(t, "openwrt/serpent-wrt/test.sh")
	for _, want := range []string{
		"command -v wget >/dev/null",
		"serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml configtest",
		"serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml feed validate",
		"serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml feed add 198.51.100.1",
		"serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml feed list",
		"serpent-wrt --config /etc/serpent-wrt/serpent-wrt.yaml feed remove 198.51.100.1",
		"/etc/init.d/serpent-wrt configtest",
		"api_get /healthz",
		"api_get /status",
		"api_get /stats",
		"api_post /reload",
		"/etc/init.d/serpent-wrt reload",
		"/etc/init.d/serpent-wrt restart",
	} {
		if !strings.Contains(smoke, want) {
			t.Fatalf("OpenWrt smoke test missing %q", want)
		}
	}
}

func TestOpenWrtSDKPackageCheckScript(t *testing.T) {
	script := readRepoFile(t, "scripts/openwrt-package-check.sh")
	for _, want := range []string{
		"OPENWRT_SDK",
		"OPENWRT_MAKE_FLAGS",
		"OPENWRT_DIAGNOSTIC_MAKE_FLAGS",
		"OPENWRT_PACKAGE_OVERWRITE",
		"OPENWRT_FEEDS_UPDATE",
		`PACKAGE_DST="$SDK/package/serpent-wrt"`,
		"feeds/packages/lang/golang/golang-package.mk",
		"make defconfig",
		"package/serpent-wrt/check package/serpent-wrt/compile",
		`run_make_with_diagnostics "$target"`,
		"-j1 V=s",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("OpenWrt SDK package check script missing %q", want)
		}
	}
}

func TestOpenWrtAPKArtifactWorkflow(t *testing.T) {
	script := readRepoFile(t, "scripts/build-openwrt-apk.sh")
	for _, want := range []string{
		"OPENWRT_SDK_URL",
		"OPENWRT_SDK_SHA256",
		"OPENWRT_APK_REUSE_WORK_DIR",
		"OPENWRT_APK_ARTIFACT_SUFFIX",
		"OPENWRT_MAKE_JOBS",
		"nproc",
		"TMP_ROOT=${TMPDIR:-/tmp}",
		"serpent-wrt-openwrt-apk",
		"Reusing OpenWrt SDK work dir",
		"Reusing installed OpenWrt packages feed",
		"Removing stale serpent-wrt APK artifacts",
		"sha256sum -c -",
		"scripts/openwrt-package-check.sh",
		`OPENWRT_MAKE_FLAGS="$MAKE_FLAGS"`,
		`renamed=${artifact%.apk}-$ARTIFACT_SUFFIX.apk`,
		"serpent-wrt-*.apk",
		"OPENWRT_APK_SUMS_NAME",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("OpenWrt APK build script missing %q", want)
		}
	}

	if strings.Contains(script, "serpent-wrt_*.ipk") {
		t.Fatal("OpenWrt APK build script must not collect legacy IPK artifacts")
	}

	workflow := readRepoFile(t, ".github/workflows/openwrt-apk.yml")
	for _, want := range []string{
		"release:",
		"workflow_dispatch:",
		"release_tag:",
		"runs-on: ubuntu-latest",
		"OpenWrt APK Packages",
		"downloads.openwrt.org/releases/25.12.4/targets/x86/64/",
		"downloads.openwrt.org/releases/25.12.4/targets/x86/generic/",
		"downloads.openwrt.org/releases/25.12.4/targets/mediatek/filogic/",
		"gcc-14.3.0",
		"${{ runner.temp }}/openwrt-apk-work/${{ matrix.slug }}",
		"actions/cache@v5",
		"OPENWRT_APK_REUSE_WORK_DIR",
		"OPENWRT_APK_WORK_DIR",
		"OPENWRT_APK_ARTIFACT_SUFFIX: ${{ matrix.slug }}",
		"actions/upload-artifact@v7",
		"gh release upload",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("OpenWrt APK workflow missing %q", want)
		}
	}
}

func TestCIWorkflowPinsGoTooling(t *testing.T) {
	workflow := readRepoFile(t, ".github/workflows/ci.yml")
	for _, want := range []string{
		"go-version-file: go.mod",
		`go-version: "1.26.3"`,
		"go install golang.org/x/vuln/cmd/govulncheck@v1.3.0",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("CI workflow missing %q", want)
		}
	}

	if strings.Contains(workflow, "go install golang.org/x/vuln/cmd/govulncheck@latest") {
		t.Fatal("CI workflow must pin govulncheck instead of installing latest")
	}
}

func TestReleaseCheckIncludesPackageChecks(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	for _, want := range []string{
		"openwrt-sdk-check:",
		"openwrt-apk:",
		"openwrt-sdk-check-if-available:",
		"$(MAKE) packagecheck",
		"$(MAKE) openwrt-sdk-check-if-available",
	} {
		if !strings.Contains(makefile, want) {
			t.Fatalf("release Makefile missing %q", want)
		}
	}
}

func assertMatch(t *testing.T, text, pattern string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(text) {
		t.Fatalf("text did not match %q", pattern)
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(repoPath(t, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", filepath.FromSlash(rel))
}
