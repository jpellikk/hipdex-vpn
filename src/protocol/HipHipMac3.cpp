/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipHipMac3.h"
#include "HipDefines.h"
#include "HipCmac.h"

using namespace hipdex_vpn;

HipHipMac3::HipHipMac3() : m_bytes()
{
}

HipHipMac3::HipHipMac3(const ByteBlock& bytes)
	: m_bytes(bytes)
{
}

HipHipMac3::~HipHipMac3()
{
}

HipParameter* HipHipMac3::Create()
{
	return new HipHipMac3;
}

uint16_t HipHipMac3::Type() const
{
	return HDX_TYPE_HIP_MAC_3;
}

uint16_t HipHipMac3::SizeImpl() const
{
	return m_bytes.size();
}

void HipHipMac3::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_bytes;
}

void HipHipMac3::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	m_bytes.resize(size);
	bytes >> m_bytes;
}

void HipHipMac3::CreateCmac(const HipCipher& cipher, const ByteBlock& key, const ByteBlock& data)
{
	HipCmac cmac(cipher, key);
	m_bytes.resize(cmac.DigestSize());
	cmac.Update(data);
	cmac.Final(m_bytes);
}

bool HipHipMac3::VerifyCmac(const HipCipher& cipher, const ByteBlock& key, const ByteBlock& data) const
{
	ByteBlock digest;
	HipCmac cmac(cipher, key);
	digest.resize(cmac.DigestSize());
	cmac.Update(data);
	cmac.Final(digest);
	return digest == m_bytes;
}
