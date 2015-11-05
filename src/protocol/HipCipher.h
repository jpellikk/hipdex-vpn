/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CIPHER_H
#define HIPDEX_VPN_PROTOCOL_HIP_CIPHER_H

#include "Types.h"
#include <openssl/evp.h>

namespace hipdex_vpn
{
	class HipCipher
	{
		public:
			enum Operation {
				Decrypt = 0,
				Encrypt = 1
			};

			~HipCipher();
			explicit HipCipher(uint8_t);
			static void RandBytes(ByteBlock&);
			void Init(const ByteBlock&,
				const ByteBlock&, Operation);
			void Update(const ByteBlock&, ByteBlock&);
			std::size_t BlockSize() const
				{ return EVP_CIPHER_block_size(m_cipher); }
			std::size_t KeyLength() const
				{ return EVP_CIPHER_key_length(m_cipher); }
			std::size_t IvLength() const
				{ return EVP_CIPHER_iv_length(m_cipher); }
			const EVP_CIPHER* Cipher() const
				{ return m_cipher; }

		private:
			static const EVP_CIPHER* Create(uint8_t);
			HipCipher& operator=(const HipCipher&);
			HipCipher(const HipCipher&);

			EVP_CIPHER_CTX m_context;
			const EVP_CIPHER* m_cipher;
	};
}

#endif
