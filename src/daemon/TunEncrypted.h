/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_TUN_ENCRYPTED_H
#define HIPDEX_VPN_TUN_ENCRYPTED_H

#include "Types.h"
#include "HipCipher.h"

namespace hipdex_vpn
{
	class TunEncrypted
	{
		public:
			~TunEncrypted();
			TunEncrypted();
			TunEncrypted(const ByteBlock&,
				const ByteBlock&);

			uint16_t Size() const;
			void SetHit(const ByteBlock&);
			void GetBytes(ByteBlock&) const;
			void SetBytes(ByteBlock&, const HipCipher&);
			void Encrypt(HipCipher&, const ByteBlock&, const ByteBlock&);
			bool Decrypt(HipCipher&, const ByteBlock&, ByteBlock&) const;
			void CreateIcv(const HipCipher&, const ByteBlock&, ByteBlock&) const;
			bool VerifyIcv(const HipCipher&, const ByteBlock&) const;
			void CreateIcv(const HipCipher&, const ByteBlock&);

			ByteBlock m_hit;
			ByteBlock m_iv;
			ByteBlock m_pld;
			ByteBlock m_icv;
	};
}

#endif
