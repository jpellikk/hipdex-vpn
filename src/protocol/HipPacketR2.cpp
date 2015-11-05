/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketR2.h"
#include "HipDefines.h"
#include "HipEncryptedKey.h"
#include "HipDhGroupList.h"

using namespace hipdex_vpn;

HipPacketR2::HipPacketR2()
	: HipPacket(HDX_TYPE_PACKET_R2)
{
}

HipPacketR2::HipPacketR2(HipEncryptedKey* encrKey,
	HipDhGroupList* dhGroupList)
	: HipPacket(HDX_TYPE_PACKET_R2)
{
	AddParameter(encrKey);
	AddParameter(dhGroupList);
}

HipPacketR2::~HipPacketR2()
{
}

HipPacket* HipPacketR2::Create()
{
	return new HipPacketR2;
}
