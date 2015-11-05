/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacketR1.h"
#include "HipDefines.h"
#include "HipPuzzle.h"
#include "HipHostId.h"
#include "HipHipCipher.h"
#include "HipDhGroupList.h"
#include "HipHitSuiteList.h"

using namespace hipdex_vpn;

HipPacketR1::HipPacketR1()
	: HipPacket(HDX_TYPE_PACKET_R1)
{
}

HipPacketR1::HipPacketR1(HipPuzzle* puzzle,
	HipHipCipher* cipher, HipHostId* hostId,
	HipHitSuiteList* suiteList, HipDhGroupList*
	dhGroupList) : HipPacket(HDX_TYPE_PACKET_R1)
{
	AddParameter(puzzle);
	AddParameter(cipher);
	AddParameter(hostId);
	AddParameter(suiteList);
	AddParameter(dhGroupList);
}

HipPacketR1::~HipPacketR1()
{
}

HipPacket* HipPacketR1::Create()
{
	return new HipPacketR1;
}
