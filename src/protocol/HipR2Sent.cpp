/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipR2Sent.h"
#include "HipDefines.h"
#include "HipConnection.h"
#include "HipEstablished.h"
#include "HipContext.h"

using namespace hipdex_vpn;

HipR2Sent::HipR2Sent()
	: m_timer(HDX_RESEND_TIMEOUT)
{
}

HipR2Sent::~HipR2Sent()
{
}

void HipR2Sent::Initiate(HipConnection* connection, HipContext* /*context*/)
{
	connection->SetState(new HipEstablished);
}

void HipR2Sent::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	m_timer.ResetDeadline(HDX_RESEND_TIMEOUT);
}

void HipR2Sent::Refresh(HipConnection* connection, HipContext* /*context*/)
{
	if (m_timer.Expired())
		connection->SetState(new HipEstablished);
}
