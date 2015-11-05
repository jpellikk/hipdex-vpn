/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_ESTABLISHED_H
#define HIPDEX_VPN_PROTOCOL_HIP_ESTABLISHED_H

#include "HipState.h"
#include "Timer.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipContext;

	class HipEstablished : public HipState
	{
		public:
			HipEstablished();
			~HipEstablished();

			void Initiate(HipConnection*, HipContext*);
			void HandleI2(HipConnection*, HipContext*);
			void HandleClose(HipConnection*, HipContext*);
			void HandleUpdate(HipConnection*, HipContext*);
			void Refresh(HipConnection*, HipContext*);

		private:
			Timer<int32_t> m_timer;
	};
}

#endif
