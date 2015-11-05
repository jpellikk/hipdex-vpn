/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipCmac.h"

using namespace hipdex_vpn;

HipCmac::HipCmac(const HipCipher& cipher, const ByteBlock& key)
	: m_ctx(CMAC_CTX_new())
{
	CMAC_Init(m_ctx, key.data(), key.size(),
		cipher.Cipher(), nullptr);
}

HipCmac::~HipCmac()
{
	if (m_ctx) {
		CMAC_CTX_cleanup(m_ctx);
		CMAC_CTX_free(m_ctx);
	}
}

std::size_t HipCmac::DigestSize() const
{
	return EVP_CIPHER_CTX_key_length(
		CMAC_CTX_get0_cipher_ctx(m_ctx));
}

void HipCmac::Update(const ByteBlock& data)
{
	CMAC_Update(m_ctx, data.data(), data.size());
}

void HipCmac::Update(const uint8_t* data, size_t size)
{
	CMAC_Update(m_ctx, data, size);
}

std::size_t HipCmac::Final(ByteBlock& digest)
{
	size_t size;
	CMAC_Final(m_ctx, digest.data(), &size);
	return size;
}
