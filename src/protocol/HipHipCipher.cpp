/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipHipCipher.h"
#include "HipDefines.h"

#include <algorithm>

using namespace hipdex_vpn;

HipHipCipher::HipHipCipher() : m_ciphers()
{
}

HipHipCipher::HipHipCipher(const ByteBlock& bytes)
	: m_ciphers(bytes)
{
}

HipHipCipher::HipHipCipher(uint8_t cipher)
	: m_ciphers(1, cipher)
{
}

HipHipCipher::~HipHipCipher()
{
}

HipParameter* HipHipCipher::Create()
{
	return new HipHipCipher;
}

uint16_t HipHipCipher::Type() const
{
	return HDX_TYPE_HIP_CIPHER;
}

uint16_t HipHipCipher::SizeImpl() const
{
	return m_ciphers.size();
}

void HipHipCipher::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_ciphers;
}

void HipHipCipher::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	m_ciphers.resize(size);
	bytes >> m_ciphers;
}

bool HipHipCipher::ValidateCipher(uint8_t& cipherSuite,
	const ByteBlock& cipherSuiteList) const
{
	if (m_ciphers.size() != 1 || cipherSuiteList.empty())
		return false;

	if (std::find(cipherSuiteList.begin(),
		cipherSuiteList.end(), m_ciphers.front())
			== cipherSuiteList.end())
		return false;

	cipherSuite = m_ciphers.front();
	return true;
}

bool HipHipCipher::SelectCipher(uint8_t& cipherSuite,
	const ByteBlock& cipherSuiteList) const
{
	if (m_ciphers.empty() || cipherSuiteList.empty())
		return false;

	for (const auto& item1 : m_ciphers)
		for (const auto& item2 : cipherSuiteList)
			if (item1 == item2) {
				cipherSuite = item1;
				return true;
			}

	return false;
}
