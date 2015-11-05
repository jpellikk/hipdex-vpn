/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipState.h"
#include "HipDefines.h"
#include "HipContext.h"
#include "HipConnection.h"

using namespace hipdex_vpn;

HipState::HipState()
{
}

HipState::~HipState()
{
}

void HipState::Refresh(HipConnection*, HipContext*)
{
}

void HipState::Initiate(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleI1(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleI2(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleR1(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleR2(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleClose(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleCloseAck(HipConnection*, HipContext*)
{
	NotImplemented();
}

void HipState::HandleUpdate(HipConnection*, HipContext*)
{
	NotImplemented();
}
