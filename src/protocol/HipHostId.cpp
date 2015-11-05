/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipHostId.h"
#include "HipDefines.h"
#include "HipIdentity.h"

using namespace hipdex_vpn;

HipHostId::HipHostId() : m_domainType(None), m_hostId(), m_domainId()
{
}

HipHostId::HipHostId(DomainType domainType, const ByteBlock& hostId, const ByteBlock& domainId)
	: m_domainType(domainType), m_hostId(hostId), m_domainId(domainId)
{
}

HipHostId::~HipHostId()
{
}

HipParameter* HipHostId::Create()
{
	return new HipHostId;
}

uint16_t HipHostId::Type() const
{
	return HDX_TYPE_HOST_ID;
}

uint16_t HipHostId::SizeImpl() const
{
	return 6+m_hostId.size()+m_domainId.size();
}

void HipHostId::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << (uint16_t)m_hostId.size();

	uint16_t dilen =
		(m_domainId.size()&0x0fff) |
		((m_domainType&0x0f)<<12);

	bytes << dilen;
	bytes << (uint16_t)HDX_HIT_ECDH_DEX;

	bytes << m_hostId;
	bytes << m_domainId;
}

void HipHostId::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	if (size < 6)
		throw Exception(Exception::Error, "Invalid parameter.");

	uint16_t algorithm, dilen, hilen;

	bytes >> hilen;
	bytes >> dilen;
	bytes >> algorithm;

	m_domainType = (DomainType)
		((dilen>>12)&0x0f);

	dilen &= 0x0fff;

	if (algorithm != HDX_HIT_ECDH_DEX || size != (ByteBlockSize)(6+hilen+dilen))
		throw Exception(Exception::Error, "Invalid parameter.");

	m_hostId.resize(hilen);
	bytes >> m_hostId;

	m_domainId.resize(dilen);
	bytes >> m_domainId;
}

bool HipHostId::CalculateEcdh(const HipIdentity& id, ByteBlock& key) const
{
	HipIdentity peerId(m_hostId);
	id.Derive(peerId, key);
	return true;
}
