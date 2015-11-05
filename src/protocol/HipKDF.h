/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_KDF_H
#define HIPDEX_VPN_PROTOCOL_HIP_KDF_H

#include "Types.h"

namespace hipdex_vpn
{
	class HipCipher;

	class HipKDF
	{
		public:
			HipKDF(HipCipher*, const ByteBlock&,
				const ByteBlock&);
			void Expand(const ByteBlock&, ByteBlock&);
			void Extract(const ByteBlock&,
				const ByteBlock&, ByteBlock&);
			~HipKDF();

		private:
			HipCipher* m_cipher;
			ByteBlock m_hostHit;
			ByteBlock m_peerHit;
	};
}

#endif
