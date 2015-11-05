/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "TunDevice.h"

#include <cstring>
#include <string>
#include <errno.h>

#include "Daemon.h"
#include "HipIdentity.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

TunDevice::TunDevice(Daemon* daemon) throw (Exception)
{
	if (!CreateDevice(HDX_TUN_IF_NAME))
		throw Exception(Exception::Abort,
			"Creating TUN device failed: "
			+ std::string(strerror(errno)));

	if (!SetIpv4Addr(daemon->m_identity->LsiStr()))
		throw Exception(Exception::Abort,
			"Setting IPv4 address for TUN device failed: "
			+ std::string(strerror(errno)));

	if (!SetIpv4Netmask(HDX_LSI_NETMASK))
		throw Exception(Exception::Abort,
			"Setting netmask for TUN device failed: "
			+ std::string(strerror(errno)));

	if (!SetIpv6Addr(daemon->m_identity->HitStr(),
		HDX_LENGTH_HIT_PREFIX))
		throw Exception(Exception::Abort,
			"Setting IPv6 address for TUN device failed: "
			+ std::string(strerror(errno)));

	if (!BringUp())
		throw Exception(Exception::Abort,
			"Bringing up TUN device failed: "
			+ std::string(strerror(errno)));

	if (!SetMtu(HDX_TUN_IF_MTU))
		throw Exception(Exception::Abort,
			"Setting MTU for TUN device failed: "
			+ std::string(strerror(errno)));
}

TunDevice::~TunDevice()
{
}
