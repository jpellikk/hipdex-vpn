/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipEchoResSig.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipEchoResSig::HipEchoResSig() : m_bytes()
{
}

HipEchoResSig::HipEchoResSig(const ByteBlock& bytes)
	: m_bytes(bytes)
{
}

HipEchoResSig::~HipEchoResSig()
{
}

HipParameter* HipEchoResSig::Create()
{
	return new HipEchoResSig;
}

uint16_t HipEchoResSig::Type() const
{
	return HDX_TYPE_ECHO_RES_SIG;
}

uint16_t HipEchoResSig::SizeImpl() const
{
	return m_bytes.size();
}

void HipEchoResSig::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_bytes;
}

void HipEchoResSig::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	m_bytes.resize(size);
	bytes >> m_bytes;
}

bool HipEchoResSig::HandleEcho(ByteBlock& echo) const
{
	return m_bytes == echo;
}
