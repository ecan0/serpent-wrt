include $(TOPDIR)/rules.mk

PKG_NAME:=serpent-wrt
PKG_VERSION:=0.5.0
# Tagged release archive source. The release workflow pins the commit and
# archive hash at build time after checking out the immutable release tag.
# These package files do not claim a new release: a recipe that needs newer
# Go sources must first update this pin and its literal hash from the actual
# tagged archive. Never substitute an imaginary release or unverified hash.
PKG_SOURCE_DATE:=2026-10-15
PKG_SOURCE_VERSION:=9d4f49d93fcc4f28ee9aa1da23e904772d6f0d33
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://codeload.github.com/ecan0/serpent-wrt/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=b45ea49af295605c358109e89efa9a2a5dfaed2d67ef8c601cc8ea4707eb5611

PKG_MAINTAINER:=ecan0
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/ecan0/serpent-wrt
GO_PKG_BUILD_PKG:=github.com/ecan0/serpent-wrt/cmd/serpent-wrt
GO_PKG_LDFLAGS_X:= \
	main.version=$(PKG_VERSION) \
	main.commit=$(PKG_SOURCE_VERSION) \
	main.buildDate=$(PKG_SOURCE_DATE)
GO_PKG_INSTALL_BIN_PATH:=/usr/sbin

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/serpent-wrt
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=Conntrack threat detection and timed nftables sets
  URL:=https://github.com/ecan0/serpent-wrt
  DEPENDS:=$(GO_ARCH_DEPENDS) +nftables-json +kmod-nf-conntrack +firewall4
endef

define Package/serpent-wrt/description
  serpent-wrt monitors conntrack metadata and emits detection events.
  It can add offender addresses to timed nftables sets.
  Optional forwarded-packet drops use an owned fw4-managed chain.
endef

define Package/serpent-wrt/conffiles
/etc/serpent-wrt/serpent-wrt.yaml
/etc/serpent-wrt/threat-feed.txt
endef

define Package/serpent-wrt/install
	$(call GoPackage/Package/Install/Bin,$(1))
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/serpent-wrt.init $(1)/etc/init.d/serpent-wrt
	$(INSTALL_DIR) $(1)/etc/serpent-wrt
	$(INSTALL_CONF) ./files/serpent-wrt.yaml $(1)/etc/serpent-wrt/serpent-wrt.yaml
	$(INSTALL_DATA) ./files/threat-feed.txt $(1)/etc/serpent-wrt/threat-feed.txt
	$(INSTALL_DIR) $(1)/usr/share/serpent-wrt
	$(INSTALL_BIN) ./files/serpent-wrt.fw4 $(1)/usr/share/serpent-wrt/fw4-reload
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/serpent-wrt.defaults $(1)/etc/uci-defaults/90-serpent-wrt
endef

define Package/serpent-wrt/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
status=0
if [ -x /etc/init.d/serpent-wrt ]; then
	/etc/init.d/serpent-wrt stop || status=1
fi
if [ -x /usr/sbin/serpent-wrt ]; then
	/usr/sbin/serpent-wrt firewall disable || status=1
fi
exit "$$status"
endef

define Package/serpent-wrt/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
# An upgrade can leave the replacement package's include installed.
[ -e /usr/share/serpent-wrt/fw4-reload ] && exit 0
if [ "$$(uci -q get firewall.serpent_wrt)" = include ] && \
   [ "$$(uci -q get firewall.serpent_wrt.path)" = /usr/share/serpent-wrt/fw4-reload ]; then
	uci -q delete firewall.serpent_wrt || exit 1
	uci commit firewall || exit 1
fi
exit 0
endef

$(eval $(call GoBinPackage,serpent-wrt))
$(eval $(call BuildPackage,serpent-wrt))
