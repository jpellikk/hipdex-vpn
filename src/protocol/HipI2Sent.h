/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_I2_SENT_H
#define HIPDEX_VPN_PROTOCOL_HIP_I2_SENT_H

#include "HipState.h"
#include "Timer.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipContext;

	class HipI2Sent : public HipState
	{
		public:
			HipI2Sent();
			~HipI2Sent();

			void HandleI2(HipConnection*, HipContext*);
			void HandleR2(HipConnection*, HipContext*);
			void Refresh(HipConnection*, HipContext*);

		private:
			Timer<int32_t> m_timer;
	};
}

#endif
