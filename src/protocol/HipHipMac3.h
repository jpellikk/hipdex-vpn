/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_MAC_3_H
#define HIPDEX_VPN_PROTOCOL_HIP_MAC_3_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipHipMac3 : public HipParameter
	{
		public:
			HipHipMac3();
			~HipHipMac3();
			explicit HipHipMac3(const ByteBlock&);
			static HipParameter* Create();
			uint16_t Type() const;
			void CreateCmac(const HipCipher&,
				const ByteBlock&, const ByteBlock&);
			bool VerifyCmac(const HipCipher&,
				const ByteBlock&, const ByteBlock&) const;

			ByteBlock m_bytes;

		protected:
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
