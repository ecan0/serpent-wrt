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
		"PKG_SOURCE_PROTO:=git",
		"PKG_SOURCE_URL:=https://github.com/ecan0/serpent-wrt.git",
		"PKG_LICENSE:=MIT",
		"PKG_LICENSE_FILES:=LICENSE",
		"PKG_BUILD_DEPENDS:=golang/host",
		"GO_PKG:=github.com/ecan0/serpent-wrt",
		"GO_PKG_BUILD_PKG:=github.com/ecan0/serpent-wrt/cmd/serpent-wrt",
		"GO_PKG_INSTALL_BIN_PATH:=/usr/sbin",
		"DEPENDS:=$(GO_ARCH_DEPENDS) +nftables +kmod-nf-conntrack",
	}
	for _, want := range required {
		if !strings.Contains(makefile, want) {
			t.Fatalf("OpenWrt package Makefile missing %q", want)
		}
	}

	assertMatch(t, makefile, `(?m)^PKG_SOURCE_DATE:=[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	assertMatch(t, makefile, `(?m)^PKG_SOURCE_VERSION:=[0-9a-f]{40}$`)
	assertMatch(t, makefile, `(?m)^PKG_RELEASE:=[0-9]+$`)
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
