/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_EC_KEY_H
#define HIPDEX_VPN_PROTOCOL_HIP_EC_KEY_H

#include "Types.h"
#include <openssl/ec.h>

namespace hipdex_vpn
{
	class HipEcKey
	{
		public:
			explicit HipEcKey(const std::string&);
			explicit HipEcKey(const ByteBlock&);
			uint8_t DhGroup() const { return m_dhGroup; }
			void PublicKey(ByteBlock&) const;
			uint32_t CurveName() const;
			void Derive(const HipEcKey&,
				ByteBlock&) const;
			~HipEcKey();

		private:
			static uint8_t CreateDhGroup(uint32_t);
			static uint32_t CreateCurveName(uint8_t);
			HipEcKey& operator=(const HipEcKey&);
			HipEcKey(const HipEcKey&);

			EC_KEY* m_key;
			uint8_t m_dhGroup;
	};
}

#endif
