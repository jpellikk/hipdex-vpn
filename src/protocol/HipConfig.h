/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CONFIG_H
#define HIPDEX_VPN_PROTOCOL_HIP_CONFIG_H

#include "Types.h"

namespace hipdex_vpn
{
	class HipConfig
	{
		public:
			HipConfig();
			virtual ~HipConfig();

			ByteBlock m_hitSuites;
			ByteBlock m_cipherSuites;
			ByteBlock m_dhGroups;

			uint8_t m_puzzleComplexity;
			uint8_t m_puzzleLifetime;

			std::string m_hostname;

		private:
			HipConfig& operator=(const HipConfig&);
			HipConfig(const HipConfig&);
	};
}

#endif
