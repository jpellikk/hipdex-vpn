/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipHitSuiteList.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipHitSuiteList::HipHitSuiteList() : m_suites()
{
}

HipHitSuiteList::HipHitSuiteList(const ByteBlock& suites)
	: m_suites(suites)
{
}

HipHitSuiteList::HipHitSuiteList(uint8_t suite)
	: m_suites(1, suite)
{
}

HipHitSuiteList::~HipHitSuiteList()
{
}

HipParameter* HipHitSuiteList::Create()
{
	return new HipHitSuiteList;
}

uint16_t HipHitSuiteList::Type() const
{
	return HDX_TYPE_HIT_SUITE_LIST;
}

uint16_t HipHitSuiteList::SizeImpl() const
{
	return m_suites.size();
}

void HipHitSuiteList::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_suites;
}

void HipHitSuiteList::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	m_suites.resize(size);
	bytes >> m_suites;
}
