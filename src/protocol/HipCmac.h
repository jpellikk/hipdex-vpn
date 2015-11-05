/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CMAC_H
#define HIPDEX_VPN_PROTOCOL_HIP_CMAC_H

#include "Types.h"
#include "HipCipher.h"

#include <openssl/evp.h>
#include <openssl/cmac.h>

namespace hipdex_vpn
{
	class HipCmac
	{
		public:
			HipCmac(const HipCipher&, const ByteBlock&);
			void Update(const uint8_t*, size_t);
			void Update(const ByteBlock&);
			std::size_t DigestSize() const;
			std::size_t Final(ByteBlock&);
			~HipCmac();

		private:
			HipCmac& operator=(const HipCmac&);
			HipCmac(const HipCmac&);
			CMAC_CTX* m_ctx;
	};
}

#endif
