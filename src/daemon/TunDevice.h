/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_TUN_DEVICE_H
#define HIPDEX_VPN_TUN_DEVICE_H

#include "TunDeviceImpl.h"
#include "Exception.h"
#include "Defines.h"

namespace hipdex_vpn
{
	class Daemon;

	class TunDevice : private TunDeviceImpl
	{
		public:
			explicit TunDevice(Daemon*)
				throw (Exception);
			~TunDevice();

			using TunDeviceImpl::m_fd;
			using TunDeviceImpl::m_ifr;
			using TunDeviceImpl::m_ifr6;

		private:
			TunDevice& operator=(const TunDevice&);
			TunDevice(const TunDevice&);
	};
}

#endif
