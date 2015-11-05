/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_TUN_DEVICE_IMPL_H
#define HIPDEX_VPN_TUN_DEVICE_IMPL_H

#include "Defines.h"

#include <string>

#include <arpa/inet.h>
#include <net/if.h>

namespace hipdex_vpn
{
	struct in6_ifreq
	{
		in6_addr ifr6_addr;
		uint32_t ifr6_prefixlen;
		unsigned int ifr6_ifindex;
	};

	class TunDeviceImpl
	{
		public:
			TunDeviceImpl();
			virtual ~TunDeviceImpl();

			int m_fd;
			ifreq m_ifr;
			in6_ifreq m_ifr6;

		protected:
			bool CreateDevice(const std::string&);
			bool SetIpv6Addr(const std::string&, int);
			bool SetIpv4Netmask(const std::string&);
			bool SetIpv4Addr(const std::string&);
			bool SetMtu(int value);
			bool BringUp();

		private:
			TunDeviceImpl(const TunDeviceImpl&);
			TunDeviceImpl& operator=(const TunDeviceImpl&);
			int m_sockfd;
	};
}

#endif
