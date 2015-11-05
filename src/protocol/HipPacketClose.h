/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_CLOSE_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_CLOSE_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipEchoReqSig;

	class HipPacketClose : public HipPacket
	{
		public:
			HipPacketClose();
			explicit HipPacketClose(HipEchoReqSig*);
			static HipPacket* Create();
			~HipPacketClose();
	};
}

#endif
