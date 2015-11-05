/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketCloseAck.h"
#include "HipEchoResSig.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipPacketCloseAck::HipPacketCloseAck()
	: HipPacket(HDX_TYPE_PACKET_CLOSE_ACK)
{
}

HipPacketCloseAck::HipPacketCloseAck(HipEchoResSig* echo)
	: HipPacket(HDX_TYPE_PACKET_CLOSE_ACK)
{
	AddParameter(echo);
}

HipPacketCloseAck::~HipPacketCloseAck()
{
}

HipPacket* HipPacketCloseAck::Create()
{
	return new HipPacketCloseAck;
}
