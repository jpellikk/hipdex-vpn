/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipDhGroupList.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipDhGroupList::HipDhGroupList() : m_groups()
{
}

HipDhGroupList::HipDhGroupList(const ByteBlock& groups)
	: m_groups(groups)
{
}

HipDhGroupList::HipDhGroupList(uint8_t group)
	: m_groups(1, group)
{
}

HipDhGroupList::~HipDhGroupList()
{
}

HipParameter* HipDhGroupList::Create()
{
	return new HipDhGroupList;
}

uint16_t HipDhGroupList::Type() const
{
	return HDX_TYPE_DH_GROUP_LIST;
}

uint16_t HipDhGroupList::SizeImpl() const
{
	return m_groups.size();
}

void HipDhGroupList::GetBytesImpl(ByteBlockWriter& writer) const
{
	writer << m_groups;
}

void HipDhGroupList::SetBytesImpl(ByteBlockReader& reader, ByteBlockSize size)
{
	m_groups.resize(size);
	reader >> m_groups;
}

bool HipDhGroupList::VerifyDhGroup(uint8_t value) const
{
	return (m_groups.size() > 0)
		&& (m_groups[0] == value);
}
