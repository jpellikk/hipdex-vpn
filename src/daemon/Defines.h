/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_DAEMON_DEFINES_H
#define HIPDEX_VPN_DAEMON_DEFINES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define PACKAGE_STRING "HIPDEX-VPN"
#define PACKAGE_CONFDIR "/opt/hipdex-vpn"
#endif

#include <inttypes.h>
#include <iostream>
#include <memory>

#define HDX_CONFIG_FILE "config.json"
#define HDX_IDENTITY_FILE "identity.pem"

#define HDX_DAEMON_RUNNING_DIR "/tmp/"
#define HDX_DAEMON_LOCK_FILE "hipdex-vpn.lock"

#define HDX_NUM_THREADS 2
#define HDX_TUN_IF_NAME "hip0"
#define HDX_TUN_IF_MTU 1500
#define HDX_LEN_TUN_BUFFER 4096
#define HDX_LEN_HIP_BUFFER 4096
#define HDX_HIP_REFRESH_INTERVAL 1
#define HDX_UDP_SIGNAL_PORT 10500
#define HDX_UDP_USER_PORT 10501

namespace hipdex_vpn
{
	struct TUserOptions
	{
		bool m_daemonMode;
		bool m_printToSyslog;
		uint16_t m_logLevel;
		char m_fileName[512];
	};
}

#endif
