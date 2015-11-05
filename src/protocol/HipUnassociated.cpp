/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipUnassociated.h"
#include "HipDefines.h"
#include "HipContext.h"
#include "HipConnection.h"
#include "HipEstablished.h"
#include "HipR2Sent.h"
#include "HipFailed.h"
#include "HipI1Sent.h"

using namespace hipdex_vpn;

HipUnassociated::HipUnassociated()
	: m_timer(HDX_DEFAULT_TIMEOUT)
{
}

HipUnassociated::~HipUnassociated()
{
}

void HipUnassociated::Initiate(HipConnection* connection, HipContext* context)
{
	connection->HandleInit(context);
	connection->SetState(new HipI1Sent);
}

void HipUnassociated::HandleI1(HipConnection* connection, HipContext* context)
{
	connection->HandleI1(context);
}

void HipUnassociated::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	connection->SetState(new HipR2Sent);
}

void HipUnassociated::Refresh(HipConnection* connection, HipContext* context)
{
	if (m_timer.Expired()) {
		connection->HandleTimeout(context);
		connection->SetState(new HipFailed);
	}
}
