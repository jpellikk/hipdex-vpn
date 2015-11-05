/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_ECHO_REQUEST_SIGNED_H
#define HIPDEX_VPN_PROTOCOL_ECHO_REQUEST_SIGNED_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipEchoReqSig : public HipParameter
	{
		public:
			HipEchoReqSig();
			~HipEchoReqSig();
			explicit HipEchoReqSig(const ByteBlock&);
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
