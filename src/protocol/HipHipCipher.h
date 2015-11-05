/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_HIP_CIPHER_H
#define HIPDEX_VPN_PROTOCOL_HIP_HIP_CIPHER_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipHipCipher : public HipParameter
	{
		public:
			explicit HipHipCipher(const ByteBlock&);
			explicit HipHipCipher(uint8_t);
			bool ValidateCipher(uint8_t&,
				const ByteBlock&) const;
			bool SelectCipher(uint8_t&,
				const ByteBlock&) const;
			static HipParameter* Create();
			uint16_t Type() const;
			~HipHipCipher();

			ByteBlock m_ciphers;

		protected:
			HipHipCipher();
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
