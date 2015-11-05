/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketI1.h"
#include "HipDhGroupList.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipPacketI1::HipPacketI1()
	: HipPacket(HDX_TYPE_PACKET_I1)
{
}

HipPacketI1::HipPacketI1(HipDhGroupList* dhGroupList)
	: HipPacket(HDX_TYPE_PACKET_I1)
{
	AddParameter(dhGroupList);
}

HipPacketI1::~HipPacketI1()
{
}

HipPacket* HipPacketI1::Create()
{
	return new HipPacketI1;
}
