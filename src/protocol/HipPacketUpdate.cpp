/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketUpdate.h"
#include "HipDefines.h"
#include "HipAck.h"
#include "HipSeq.h"

using namespace hipdex_vpn;

HipPacketUpdate::HipPacketUpdate()
	: HipPacket(HDX_TYPE_PACKET_UPDATE)
{
}

HipPacketUpdate::HipPacketUpdate(HipAck* ack)
	: HipPacket(HDX_TYPE_PACKET_UPDATE)
{
	AddParameter(ack);
}

HipPacketUpdate::HipPacketUpdate(HipSeq* seq)
	: HipPacket(HDX_TYPE_PACKET_UPDATE)
{
	AddParameter(seq);
}


HipPacketUpdate::~HipPacketUpdate()
{
}

HipPacket* HipPacketUpdate::Create()
{
	return new HipPacketUpdate;
}
