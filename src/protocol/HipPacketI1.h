/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_I1_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_I1_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipDhGroupList;

	class HipPacketI1 : public HipPacket
	{
		public:
			explicit HipPacketI1(HipDhGroupList*);
			static HipPacket* Create();
			~HipPacketI1();

		private:
			HipPacketI1();
	};
}

#endif
