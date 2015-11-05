/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_STATE_H
#define HIPDEX_VPN_PROTOCOL_HIP_STATE_H

#include "Exception.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipContext;

	class HipState
	{
		public:
			HipState();
			virtual ~HipState() = 0;
			static inline void NotImplemented();
			virtual void Initiate(HipConnection*, HipContext*);
			virtual void Refresh(HipConnection*, HipContext*);
			virtual void HandleI1(HipConnection*, HipContext*);
			virtual void HandleI2(HipConnection*, HipContext*);
			virtual void HandleR1(HipConnection*, HipContext*);
			virtual void HandleR2(HipConnection*, HipContext*);
			virtual void HandleClose(HipConnection*, HipContext*);
			virtual void HandleCloseAck(HipConnection*, HipContext*);
			virtual void HandleUpdate(HipConnection*, HipContext*);
	};

	inline void HipState::NotImplemented() {
#ifdef DEBUG
		throw Exception(Exception::Error,
			"Command not implemented in this state.");
#endif
	}
}

#endif
