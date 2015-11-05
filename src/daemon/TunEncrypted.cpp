/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "TunEncrypted.h"
#include "HipDefines.h"
#include "HipCmac.h"

using namespace hipdex_vpn;

TunEncrypted::TunEncrypted()
	: m_hit(HDX_LENGTH_HIT), m_iv(), m_pld(), m_icv()
{
}

TunEncrypted::TunEncrypted(const ByteBlock& hit, const ByteBlock& iv)
	: m_hit(hit), m_iv(iv), m_pld(), m_icv()
{
}

TunEncrypted::~TunEncrypted()
{
}

uint16_t TunEncrypted::Size() const
{
	return m_hit.size() + m_iv.size()
		+ m_pld.size() + m_icv.size();
}

void TunEncrypted::GetBytes(ByteBlock& bytes) const
{
	bytes.resize(Size());
	ByteBlockWriter writer(bytes);

	writer << m_hit;
	writer << m_iv;
	writer << m_pld;
	writer << m_icv;
}

void TunEncrypted::SetBytes(ByteBlock& bytes, const HipCipher& cipher)
{
	ByteBlockReader reader(bytes);

	m_hit.resize(HDX_LENGTH_HIT);
	reader >> m_hit;

	m_iv.resize(cipher.IvLength());
	reader >> m_iv;

	size_t blocksize = cipher.BlockSize();

	if (reader.BytesAvailable() < blocksize)
		return;

	m_pld.resize(reader.BytesAvailable()-blocksize);
	reader >> m_pld;

	m_icv.resize(blocksize);
	reader >> m_icv;
}

void TunEncrypted::Encrypt(HipCipher& cipher, const ByteBlock& key, const ByteBlock& data)
{
	m_iv.resize(cipher.IvLength());
	cipher.Init(key, m_iv, HipCipher::Encrypt);
	cipher.Update(data, m_pld);
}

bool TunEncrypted::Decrypt(HipCipher& cipher, const ByteBlock& key, ByteBlock& data) const
{
	cipher.Init(key, m_iv, HipCipher::Decrypt);
	cipher.Update(m_pld, data);
	return true;
}

void TunEncrypted::CreateIcv(const HipCipher& cipher, const ByteBlock& key, ByteBlock& icv) const
{
	HipCmac cmac(cipher, key);
	icv.resize(cmac.DigestSize());
	cmac.Update(m_hit);
	cmac.Update(m_iv);
	cmac.Update(m_pld);
	cmac.Final(icv);
}

void TunEncrypted::CreateIcv(const HipCipher& cipher, const ByteBlock& key)
{
	CreateIcv(cipher, key, m_icv);
}

bool TunEncrypted::VerifyIcv(const HipCipher& cipher, const ByteBlock& key) const
{
	ByteBlock digest;
	CreateIcv(cipher, key, digest);
	return digest == m_icv;
}

void TunEncrypted::SetHit(const ByteBlock& bytes)
{
	ByteBlockReader reader(bytes);
	m_hit.resize(HDX_LENGTH_HIT);
	reader >> m_hit;
}
