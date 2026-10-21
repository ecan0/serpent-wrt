include $(TOPDIR)/rules.mk

PKG_NAME:=serpent-wrt
PKG_VERSION:=0.5.0
PKG_SOURCE_DATE:=2026-10-15
PKG_SOURCE_VERSION:=9d4f49d93fcc4f28ee9aa1da23e904772d6f0d33
PKG_RELEASE:=2

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
  External firewall policy determines packet drops in this released version.
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
endef

$(eval $(call GoBinPackage,serpent-wrt))
$(eval $(call BuildPackage,serpent-wrt))
