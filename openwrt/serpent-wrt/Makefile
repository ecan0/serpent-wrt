include $(TOPDIR)/rules.mk

PKG_NAME:=serpent-wrt
PKG_SOURCE_DATE:=2026-05-03
PKG_SOURCE_VERSION:=d21578b08f21890395b6b4e438fb11fbb8a466c1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/ecan0/serpent-wrt.git
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=ecan0
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/ecan0/serpent-wrt
GO_PKG_BUILD_PKG:=github.com/ecan0/serpent-wrt/cmd/serpent-wrt
GO_PKG_INSTALL_BIN_PATH:=/usr/sbin

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/serpent-wrt
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=Conntrack threat detection and nftables enforcement daemon
  URL:=https://github.com/ecan0/serpent-wrt
  DEPENDS:=$(GO_ARCH_DEPENDS) +nftables +kmod-nf-conntrack
endef

define Package/serpent-wrt/description
  serpent-wrt monitors conntrack flow metadata, detects suspicious behavior,
  emits structured events, and optionally blocks offenders with nftables.
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
