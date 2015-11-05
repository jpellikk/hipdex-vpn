/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_R1_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_R1_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipPuzzle;
	class HipHostId;
	class HipHipCipher;
	class HipHitSuiteList;
	class HipDhGroupList;

	class HipPacketR1 : public HipPacket
	{
		public:
			HipPacketR1(HipPuzzle*, HipHipCipher*,
				HipHostId*, HipHitSuiteList*,
				HipDhGroupList*);
			static HipPacket* Create();
			~HipPacketR1();

		private:
			HipPacketR1();
	};
}

#endif
