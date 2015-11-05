/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipClosing.h"
#include "HipDefines.h"
#include "HipConnection.h"
#include "HipContext.h"
#include "HipUnassociated.h"
#include "HipEstablished.h"
#include "HipClosed.h"
#include "HipI1Sent.h"
#include "HipI2Sent.h"

using namespace hipdex_vpn;

HipClosing::HipClosing()
	: m_timer(HDX_RESEND_TIMEOUT, HDX_RESEND_INTERVAL)
{
}

HipClosing::~HipClosing()
{
}

void HipClosing::Initiate(HipConnection* connection, HipContext* context)
{
	connection->HandleInit(context);
	connection->SetState(new HipI1Sent);
}

void HipClosing::HandleI1(HipConnection* connection, HipContext* context)
{
	connection->HandleI1(context);
}

void HipClosing::HandleR1(HipConnection* connection, HipContext* context)
{
	connection->HandleR1(context);
	connection->SetState(new HipI2Sent);
}

void HipClosing::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	connection->SetState(new HipEstablished);
}

void HipClosing::HandleClose(HipConnection* connection, HipContext* context)
{
	connection->HandleClose(context);
	connection->SetState(new HipClosed);
}

void HipClosing::HandleCloseAck(HipConnection* connection, HipContext* context)
{
	connection->HandleCloseAck(context);
	connection->SetState(new HipUnassociated);
}

void HipClosing::Refresh(HipConnection* connection, HipContext* context)
{
	if (m_timer.Tick())
		connection->SendClose(context);

	if (m_timer.Expired()) {
		connection->SetState(new HipUnassociated);
	}
}
