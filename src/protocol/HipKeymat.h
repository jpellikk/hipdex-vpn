/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_KEYMAT_H
#define HIPDEX_VPN_PROTOCOL_HIP_KEYMAT_H

#include "Types.h"

namespace hipdex_vpn
{
	class HipCipher;

	class HipKeymat
	{
		public:
			HipKeymat();
			~HipKeymat();
			void Calculate(HipCipher*, const ByteBlock&,
				const ByteBlock&, const ByteBlock&,
				const ByteBlock&);

			typedef std::shared_ptr<HipCipher> HipCipherPtr;

			HipCipherPtr m_cipher;

			ByteBlock m_hostEK;
			ByteBlock m_hostIK;
			ByteBlock m_peerEK;
			ByteBlock m_peerIK;
	};
}

#endif
