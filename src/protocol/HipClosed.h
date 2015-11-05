/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CLOSED_H
#define HIPDEX_VPN_PROTOCOL_HIP_CLOSED_H

#include "HipState.h"
#include "Timer.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipContext;

	class HipClosed : public HipState
	{
		public:
			HipClosed();
			~HipClosed();

			void Initiate(HipConnection*, HipContext*);
			void HandleClose(HipConnection*, HipContext*);
			void HandleI1(HipConnection*, HipContext*);
			void HandleR1(HipConnection*, HipContext*);
			void HandleI2(HipConnection*, HipContext*);
			void Refresh(HipConnection*, HipContext*);

		private:
			Timer<int32_t> m_timer;
	};
}

#endif
