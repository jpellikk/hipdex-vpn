/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipEchoReqSig.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipEchoReqSig::HipEchoReqSig() : m_bytes()
{
}

HipEchoReqSig::HipEchoReqSig(const ByteBlock& bytes)
	: m_bytes(bytes)
{
}

HipEchoReqSig::~HipEchoReqSig()
{
}

HipParameter* HipEchoReqSig::Create()
{
	return new HipEchoReqSig;
}

uint16_t HipEchoReqSig::Type() const
{
	return HDX_TYPE_ECHO_REQ_SIG;
}

uint16_t HipEchoReqSig::SizeImpl() const
{
	return m_bytes.size();
}

void HipEchoReqSig::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_bytes;
}

void HipEchoReqSig::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	m_bytes.resize(size);
	bytes >> m_bytes;
}

bool HipEchoReqSig::HandleEcho(ByteBlock& echo) const
{
	if (echo.empty())
		return false;

	echo = m_bytes;
	return true;
}
