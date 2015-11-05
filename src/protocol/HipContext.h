/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CONTEXT_H
#define HIPDEX_VPN_PROTOCOL_HIP_CONTEXT_H

#include "Types.h"

namespace hipdex_vpn
{
	class HipConnection;
	class HipIdentity;
	class HipPacket;
	class HipConfig;

	typedef std::shared_ptr<HipConnection> HipConnectionPtr;
	typedef std::shared_ptr<HipIdentity> HipIdentityPtr;
	typedef std::shared_ptr<ByteBlock> ByteBlockPtr;
	typedef std::shared_ptr<HipPacket> HipPacketPtr;

	struct HipContext
	{
		HipConnectionPtr m_conn;
		ByteBlockPtr m_buffer;
		HipPacketPtr m_packet;
		HipConfig* m_config;
		HipIdentityPtr m_id;
	};

	struct HipHandler
	{
		enum HipErrorType {
			HipErrorTimeout = 1
		};
		virtual ~HipHandler() {}
		virtual void HipSendPacket(HipPacket*, HipContext*) = 0;
		virtual void HipError(HipErrorType, HipContext*) = 0;
		virtual void HipCloseConnection(HipContext*) = 0;
		virtual void HipOpenConnection(HipContext*) = 0;
	};
}

#endif
