/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipSeq.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipSeq::HipSeq() : m_seq(0)
{
}

HipSeq::HipSeq(uint32_t seq)
	: m_seq(seq)
{
}

HipSeq::~HipSeq()
{
}

HipParameter* HipSeq::Create()
{
	return new HipSeq;
}

uint16_t HipSeq::Type() const
{
	return HDX_TYPE_SEQ;
}

uint16_t HipSeq::SizeImpl() const
{
	return 4;
}

void HipSeq::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_seq;
}

void HipSeq::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize)
{
	bytes >> m_seq;
}

bool HipSeq::Update(uint32_t& ack) const
{
	if (m_seq < ack)
		return false;

	ack = m_seq;
	return true;
}
