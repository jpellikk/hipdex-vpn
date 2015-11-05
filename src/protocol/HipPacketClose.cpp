/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketClose.h"
#include "HipEchoReqSig.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipPacketClose::HipPacketClose()
	: HipPacket(HDX_TYPE_PACKET_CLOSE)
{
}

HipPacketClose::HipPacketClose(HipEchoReqSig* echo)
	: HipPacket(HDX_TYPE_PACKET_CLOSE)
{
	AddParameter(echo);
}

HipPacketClose::~HipPacketClose()
{
}

HipPacket* HipPacketClose::Create()
{
	return new HipPacketClose;
}
