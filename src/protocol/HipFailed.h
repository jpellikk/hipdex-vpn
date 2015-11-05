/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_FAILED_H
#define HIPDEX_VPN_PROTOCOL_HIP_FAILED_H

#include "HipState.h"

namespace hipdex_vpn
{
	class HipFailed : public HipState
	{
		public:
			HipFailed() {}
			~HipFailed() {}
	};
}

#endif
