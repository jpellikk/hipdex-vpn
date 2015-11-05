/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_ACK_H
#define HIPDEX_VPN_PROTOCOL_ACK_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipAck : public HipParameter
	{
		public:
			~HipAck();
			explicit HipAck(uint32_t);
			static HipParameter* Create();
			bool Update(uint32_t&) const;
			uint16_t Type() const;

			uint32_t m_ack;

		protected:
			HipAck();
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
