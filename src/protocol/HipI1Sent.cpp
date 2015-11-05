/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipI1Sent.h"
#include "HipDefines.h"
#include "HipContext.h"
#include "HipConnection.h"
#include "HipR2Sent.h"
#include "HipFailed.h"
#include "HipI2Sent.h"

using namespace hipdex_vpn;

HipI1Sent::HipI1Sent()
	: m_timer(HDX_RESEND_TIMEOUT, HDX_RESEND_INTERVAL)
{
}

HipI1Sent::~HipI1Sent()
{
}

void HipI1Sent::HandleR1(HipConnection* connection, HipContext* context)
{
	connection->HandleR1(context);
	connection->SetState(new HipI2Sent);
}

void HipI1Sent::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	connection->SetState(new HipR2Sent);
}

void HipI1Sent::Refresh(HipConnection* connection, HipContext* context)
{
	if (m_timer.Tick())
		connection->SendI1(context);

	if (m_timer.Expired()) {
		connection->HandleTimeout(context);
		connection->SetState(new HipFailed);
	}
}
