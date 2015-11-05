/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_ENCRYPTED_KEY_H
#define HIPDEX_VPN_PROTOCOL_ENCRYPTED_KEY_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipEncryptedKey : public HipParameter
	{
		public:
			HipEncryptedKey();
			~HipEncryptedKey();
			explicit HipEncryptedKey(const ByteBlock&);
			static HipParameter* Create();
			uint16_t Type() const;

			void Encrypt(HipCipher&, const ByteBlock&, const ByteBlock&);
			bool Decrypt(HipCipher&, const ByteBlock&, ByteBlock&) const;

			ByteBlock m_bytes;

		protected:
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
