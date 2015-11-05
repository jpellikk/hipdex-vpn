/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipEncryptedKey.h"
#include "HipCipher.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipEncryptedKey::HipEncryptedKey() : m_bytes()
{
}

HipEncryptedKey::HipEncryptedKey(const ByteBlock& bytes)
	: m_bytes(bytes)
{
}

HipEncryptedKey::~HipEncryptedKey()
{
}

HipParameter* HipEncryptedKey::Create()
{
	return new HipEncryptedKey;
}

uint16_t HipEncryptedKey::Type() const
{
	return HDX_TYPE_ENCRYPTED_KEY;
}

uint16_t HipEncryptedKey::SizeImpl() const
{
	return m_bytes.size();
}

void HipEncryptedKey::GetBytesImpl(ByteBlockWriter& writer) const
{
	writer << m_bytes;
}

void HipEncryptedKey::SetBytesImpl(ByteBlockReader& reader, ByteBlockSize size)
{
	m_bytes.resize(size);
	reader >> m_bytes;
}

void HipEncryptedKey::Encrypt(HipCipher& cipher, const ByteBlock& key, const ByteBlock& data)
{
	ByteBlock iv(cipher.IvLength());
	cipher.Init(key, iv, HipCipher::Encrypt);
	cipher.Update(data, m_bytes);
}

bool HipEncryptedKey::Decrypt(HipCipher& cipher, const ByteBlock& key, ByteBlock& data) const
{
	ByteBlock iv(cipher.IvLength());
	cipher.Init(key, iv, HipCipher::Decrypt);
	cipher.Update(m_bytes, data);
	return true;
}
