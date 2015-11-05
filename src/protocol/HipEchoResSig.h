/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_ECHO_RESPONSE_SIGNED_H
#define HIPDEX_VPN_PROTOCOL_ECHO_RESPONSE_SIGNED_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipEchoResSig : public HipParameter
	{
		public:
			HipEchoResSig();
			~HipEchoResSig();
			explicit HipEchoResSig(const ByteBlock&);
			bool HandleEcho(ByteBlock&) const;
			static HipParameter* Create();
			uint16_t Type() const;

		protected:
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);

		public:
			ByteBlock m_bytes;
	};
}

#endif
