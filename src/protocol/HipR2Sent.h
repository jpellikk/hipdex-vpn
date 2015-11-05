/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_R2_SENT_H
#define HIPDEX_VPN_PROTOCOL_HIP_R2_SENT_H

#include "HipState.h"
#include "Timer.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipContext;

	class HipR2Sent : public HipState
	{
		public:
			HipR2Sent();
			~HipR2Sent();

		void Initiate(HipConnection*, HipContext*);
		void HandleI2(HipConnection*, HipContext*);
		void Refresh(HipConnection*, HipContext*);

		private:
			Timer<int32_t> m_timer;
	};
}

#endif
