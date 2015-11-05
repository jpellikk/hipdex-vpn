/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipAck.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipAck::HipAck() : m_ack(0)
{
}

HipAck::HipAck(uint32_t ack)
	: m_ack(ack)
{
}

HipAck::~HipAck()
{
}

HipParameter* HipAck::Create()
{
	return new HipAck;
}

uint16_t HipAck::Type() const
{
	return HDX_TYPE_ACK;
}

uint16_t HipAck::SizeImpl() const
{
	return 4;
}

void HipAck::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_ack;
}

void HipAck::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize)
{
	bytes >> m_ack;
}

bool HipAck::Update(uint32_t& seq) const
{
	if (m_ack != seq)
		return false;

	++seq;
	return true;
}
