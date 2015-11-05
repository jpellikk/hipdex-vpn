/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipIdentity.h"
#include "Exception.h"
#include "HipDefines.h"
#include <arpa/inet.h>

using namespace hipdex_vpn;

const static ByteBlock::value_type
	s_hitPrefix[4] = {0x20, 0x01, 0x00, 0x15};

const static ByteBlock::value_type
	s_lsiPrefix[1] = {0x01};

HipIdentity::HipIdentity(const std::string& privKeyFile)
	: m_key(privKeyFile), m_hit(), m_lsi()
{
	CreateHitLsi(m_hit, m_lsi);
}

HipIdentity::HipIdentity(const ByteBlock& hostId)
	: m_key(hostId), m_hit()
{
	CreateHitLsi(m_hit, m_lsi);
}

HipIdentity::~HipIdentity()
{
}

void HipIdentity::CreateHitLsi(ByteBlock& hit, ByteBlock& lsi) const
{
	ByteBlock publicKey;
	m_key.PublicKey(publicKey);

	hit.resize(HDX_LENGTH_HIT);

	ByteBlockSize size = sizeof(s_hitPrefix);

	std::copy_n(s_hitPrefix, size, hit.begin());

	std::copy_n(publicKey.begin() += 1,
		hit.size() - size, hit.begin() += size);

	lsi.resize(HDX_LENGTH_LSI);

	size = sizeof(s_lsiPrefix);

	std::copy_n(s_lsiPrefix, size, lsi.begin());

	std::copy_n(publicKey.begin() += 1,
		lsi.size() - size, lsi.begin() += size);
}

void HipIdentity::ToHostId(ByteBlock& hostId) const
{
	ByteBlock publicKey;
	m_key.PublicKey(publicKey);

	hostId.resize(publicKey.size() + 2);

	hostId[0] = 0;
	hostId[1] = m_key.DhGroup();

	std::copy(publicKey.begin(),
		publicKey.end(), hostId.begin() += 2);
}

void HipIdentity::Derive(const HipIdentity& hostId, ByteBlock& secret) const
{
	m_key.Derive(hostId.m_key, secret);
}

std::string HipIdentity::HitStr() const
{
	return FromHitToStr(m_hit);
}

std::string HipIdentity::LsiStr() const
{
	return FromLsiToStr(m_lsi);
}

void HipIdentity::FromHitToLsi(const ByteBlock& hit, ByteBlock& lsi)
{
	if (hit.size() != HDX_LENGTH_HIT)
		return;

	lsi.resize(HDX_LENGTH_LSI);

	std::size_t size = sizeof(s_lsiPrefix);

	std::copy_n(s_lsiPrefix, size, lsi.begin());

	std::copy_n(hit.begin() += sizeof(s_hitPrefix),
		lsi.size() - size, lsi.begin() += size);
}

void HipIdentity::FromStrToHit(const std::string& str, ByteBlock& hit)
{
	hit.resize(16);
	inet_pton(AF_INET6, str.data(), hit.data());
}

void HipIdentity::FromStrToLsi(const std::string& str, ByteBlock& lsi)
{
	lsi.resize(4);
	inet_pton(AF_INET, str.data(), lsi.data());
}

std::string HipIdentity::FromLsiToStr(const ByteBlock& lsi)
{
	char str[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, lsi.data(), str, INET_ADDRSTRLEN);
	return str;
}

std::string HipIdentity::FromHitToStr(const ByteBlock& hit)
{
	char str[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, hit.data(), str, INET6_ADDRSTRLEN);
	return str;
}
