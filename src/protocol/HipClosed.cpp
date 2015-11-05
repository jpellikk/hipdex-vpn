/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipClosed.h"
#include "HipDefines.h"
#include "HipConnection.h"
#include "HipContext.h"
#include "HipUnassociated.h"
#include "HipEstablished.h"
#include "HipI2Sent.h"

using namespace hipdex_vpn;

HipClosed::HipClosed()
	: m_timer(2*HDX_RESEND_TIMEOUT)
{
}

HipClosed::~HipClosed()
{
}

void HipClosed::Initiate(HipConnection* connection, HipContext* context)
{
	connection->HandleInit(context);
}

void HipClosed::HandleI1(HipConnection* connection, HipContext* context)
{
	connection->HandleI1(context);
}

void HipClosed::HandleR1(HipConnection* connection, HipContext* context)
{
	connection->HandleR1(context);
	connection->SetState(new HipI2Sent);
}

void HipClosed::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	connection->SetState(new HipEstablished);
}

void HipClosed::HandleClose(HipConnection* connection, HipContext* context)
{
	connection->HandleClose(context);
}

void HipClosed::Refresh(HipConnection* connection, HipContext* /*context*/)
{
	if (m_timer.Expired()) {
		connection->SetState(new HipUnassociated);
	}
}
