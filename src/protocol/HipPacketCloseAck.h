/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_CLOSE_ACK_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_CLOSE_ACK_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipEchoResSig;

	class HipPacketCloseAck : public HipPacket
	{
		public:
			HipPacketCloseAck();
			explicit HipPacketCloseAck(HipEchoResSig*);
			static HipPacket* Create();
			~HipPacketCloseAck();
	};
}

#endif
