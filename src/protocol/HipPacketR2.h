/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_R2_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_R2_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipEncryptedKey;
	class HipDhGroupList;

	class HipPacketR2 : public HipPacket
	{
		public:
			HipPacketR2(HipEncryptedKey*,
				HipDhGroupList*);
			static HipPacket* Create();
			~HipPacketR2();

		private:
			HipPacketR2();
	};
}

#endif
