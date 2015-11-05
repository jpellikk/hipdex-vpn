/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipCipher.h"
#include "HipDefines.h"
#include "Exception.h"

#include <openssl/rand.h>

using namespace hipdex_vpn;

#define HIP_CIPHER_EXCEPTION_STR \
	"Failed to initialize HIP cipher: "

HipCipher::HipCipher(uint8_t cipherSuite)
	: m_cipher(Create(cipherSuite))
{
	EVP_CIPHER_CTX_init(&m_context);
}

HipCipher::~HipCipher()
{
	EVP_CIPHER_CTX_cleanup(&m_context);
}

void HipCipher::RandBytes(ByteBlock& bytes)
{
	RAND_bytes(bytes.data(), bytes.size());
}

void HipCipher::Init(const ByteBlock& key,
	const ByteBlock& iv, Operation encrypt)
{
	if (key.size() != KeyLength())
		throw Exception(Exception::Abort,
			HIP_CIPHER_EXCEPTION_STR \
			"Invalid cipher key length.");

	if (iv.size() != IvLength())
		throw Exception(Exception::Abort,
			HIP_CIPHER_EXCEPTION_STR \
			"Invalid cipher IV length.");

	EVP_CipherInit_ex(&m_context, m_cipher,
		nullptr, key.data(), iv.data(), encrypt);
}

void HipCipher::Update(const ByteBlock& in, ByteBlock& out)
{
	out.resize(in.size() + BlockSize());

	int32_t bytesWritten = 0;

	if (!EVP_CipherUpdate(&m_context, out.data(),
		&bytesWritten, in.data(), in.size()))
		throw new Exception(Exception::Abort,
			"Encryption failed (CipherUpdate).");

	int32_t outlen = bytesWritten;

	if (!EVP_CipherFinal_ex(&m_context,
		out.data() + bytesWritten, &bytesWritten))
		throw new Exception(Exception::Abort,
			"Encryption failed (CipherFinal).");

	outlen += bytesWritten;
	out.resize(outlen);
}

const EVP_CIPHER* HipCipher::Create(uint8_t cipherSuite)
{
	if (cipherSuite == HDX_CIPHER_AES_128_CTR)
		return EVP_aes_128_cbc();
	else if (cipherSuite == HDX_CIPHER_AES_256_CTR)
		return EVP_aes_256_cbc();
	else throw Exception(Exception::Abort,
		HIP_CIPHER_EXCEPTION_STR \
		"Unsupported cipher type.");
	return nullptr;
}
