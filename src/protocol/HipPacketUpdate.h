/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_UPDATE_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_UPDATE_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipAck;
	class HipSeq;

	class HipPacketUpdate : public HipPacket
	{
		public:
			HipPacketUpdate();
			explicit HipPacketUpdate(HipAck*);
			explicit HipPacketUpdate(HipSeq*);
			static HipPacket* Create();
			~HipPacketUpdate();
	};
}

#endif
