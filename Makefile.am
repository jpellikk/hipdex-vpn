AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = hipdex-vpn

hipdex_vpn_SOURCES = \
	src/protocol/HipAck.cpp \
	src/protocol/HipEcKey.cpp \
	src/protocol/HipCipher.cpp \
	src/protocol/HipKeymat.cpp \
	src/protocol/HipCmac.cpp \
	src/protocol/HipIdentity.cpp \
	src/protocol/HipConfig.cpp \
	src/protocol/HipPacket.cpp \
	src/protocol/HipPacketI1.cpp \
	src/protocol/HipPacketI2.cpp \
	src/protocol/HipPacketR1.cpp \
	src/protocol/HipPacketR2.cpp \
	src/protocol/HipPacketClose.cpp \
	src/protocol/HipPacketCloseAck.cpp \
	src/protocol/HipPacketUpdate.cpp \
	src/protocol/HipKDF.cpp \
	src/protocol/HipSeq.cpp \
	src/protocol/HipState.cpp \
	src/protocol/HipClosed.cpp \
	src/protocol/HipClosing.cpp \
	src/protocol/HipI1Sent.cpp \
	src/protocol/HipI2Sent.cpp \
	src/protocol/HipR2Sent.cpp \
	src/protocol/HipEstablished.cpp \
	src/protocol/HipUnassociated.cpp \
	src/protocol/HipConnection.cpp \
	src/protocol/HipHitSuiteList.cpp \
	src/protocol/HipEncryptedKey.cpp \
	src/protocol/HipParameter.cpp \
	src/protocol/HipDhGroupList.cpp \
	src/protocol/HipEchoReqSig.cpp \
	src/protocol/HipEchoResSig.cpp \
	src/protocol/HipHipCipher.cpp \
	src/protocol/HipHipMac3.cpp \
	src/protocol/HipHostId.cpp \
	src/protocol/HipPuzzle.cpp \
	src/protocol/HipSolution.cpp \
	src/daemon/Main.cpp \
	src/daemon/Daemon.cpp \
	src/daemon/ConfigFile.cpp \
	src/daemon/TunEncrypted.cpp \
	src/daemon/TunDeviceImpl.cpp \
	src/daemon/TunDevice.cpp \
	src/daemon/TunServer.cpp \
	src/daemon/HipServer.cpp \
	src/daemon/IoService.cpp

BOOST_LIBS = -lboost_thread -lboost_system -lboost_filesystem

hipdex_vpn_LDADD = $(BOOST_LIBS) $(jansson_LIBS) $(openssl_LIBS) -lpthread -ldl
hipdex_vpn_CPPFLAGS = $(AM_CFLAGS) $(jansson_CFLAGS) $(openssl_CFLAGS) -I./src/protocol -I./src/common -I./src/daemon

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = files/config.json.dist

SETTINGSDIR=$(sysconfdir)/hipdex-vpn/
ECKEYFILE=$(DESTDIR)$(SETTINGSDIR)identity.pem

install-data-local:
	$(INSTALL) -dm755 $(DESTDIR)$(SETTINGSDIR) || return 1
	$(INSTALL_DATA) files/config.json.dist $(DESTDIR)$(SETTINGSDIR)config.json

install-data-hook:
	touch $(ECKEYFILE) && chmod 600 $(ECKEYFILE) && \
	openssl ecparam -out $(ECKEYFILE) -name secp192k1 -genkey -noout

uninstall-local:
	-rm -f $(ECKEYFILE)
	-rm -f $(DESTDIR)$(SETTINGSDIR)config.json
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(SETTINGSDIR)
