#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=netsukuku
PKG_VERSION:=0.0.9b
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/Netsukuku/netsukuku.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=3084295a56c4b068f2df6269da56218b4369af47
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)

define Package/netsukuku
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Netsukuku p2p protocol
  DEPENDS:=+libopenssl +libgmp +kmod-tun +libpthread +zlib +kmod-ipip
endef

define Build/Configure
        $(call Build/Configure/Default)
endef

define Package/netsukuku/install
        $(INSTALL_DIR) $(1)/usr/bin/
        $(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/ntk* $(1)/usr/bin
        $(INSTALL_DIR) $(1)/etc
        $(CP) -r $(PKG_BUILD_DIR)/etc/netsukuku $(1)/etc/
endef

$(eval $(call BuildPackage,netsukuku))
