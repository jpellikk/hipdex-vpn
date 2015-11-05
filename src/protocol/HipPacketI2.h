/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_I2_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_I2_H

#include "HipPacket.h"

namespace hipdex_vpn
{
	class HipEncryptedKey;
	class HipHipCipher;
	class HipSolution;
	class HipHostId;

	class HipPacketI2 : public HipPacket
	{
		public:
			HipPacketI2(HipSolution*, HipHipCipher*,
				HipEncryptedKey*, HipHostId*);
			static HipPacket* Create();
			~HipPacketI2();

		private:
			HipPacketI2();
	};
}

#endif
