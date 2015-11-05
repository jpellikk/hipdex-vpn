/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketI2.h"
#include "HipDefines.h"
#include "HipEncryptedKey.h"
#include "HipHipCipher.h"
#include "HipSolution.h"
#include "HipHostId.h"

using namespace hipdex_vpn;

HipPacketI2::HipPacketI2()
	: HipPacket(HDX_TYPE_PACKET_I2)
{
}

HipPacketI2::HipPacketI2(HipSolution* solution,
	HipHipCipher* cipher, HipEncryptedKey* encrKey,
	HipHostId* hostId) : HipPacket(HDX_TYPE_PACKET_I2)
{
	AddParameter(solution);
	AddParameter(cipher);
	AddParameter(encrKey);
	AddParameter(hostId);
}

HipPacketI2::~HipPacketI2()
{
}

HipPacket* HipPacketI2::Create()
{
	return new HipPacketI2;
}
