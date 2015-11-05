/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipEstablished.h"
#include "HipDefines.h"
#include "HipConnection.h"
#include "HipContext.h"
#include "HipClosing.h"
#include "HipClosed.h"

using namespace hipdex_vpn;

HipEstablished::HipEstablished()
	: m_timer(HDX_DEFAULT_TIMEOUT, HDX_UPDATE_INTERVAL)
{
}

HipEstablished::~HipEstablished()
{
}

void HipEstablished::Initiate(HipConnection* /*connection*/, HipContext* /*context*/)
{
}

void HipEstablished::HandleI2(HipConnection* connection, HipContext* context)
{
	connection->HandleI2(context);
	m_timer.ResetDeadline(HDX_DEFAULT_TIMEOUT);
}

void HipEstablished::HandleClose(HipConnection* connection, HipContext* context)
{
	connection->HandleClose(context);
	connection->SetState(new HipClosed);
}

void HipEstablished::HandleUpdate(HipConnection* connection, HipContext* context)
{
	connection->HandleUpdate(context);
	m_timer.ResetDeadline(HDX_DEFAULT_TIMEOUT);
}

void HipEstablished::Refresh(HipConnection* connection, HipContext* context)
{
	if (m_timer.Tick())
		connection->SendUpdateSeq(context);

	if (m_timer.Expired()) {
		connection->HandleShutdown(context);
		connection->SetState(new HipClosing);
	}
}
