/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipKDF.h"
#include "HipCmac.h"
#include "HipCipher.h"

#define HIP_KDF_EXCEPTION_STR \
	"HIP key derivation failed: "

using namespace hipdex_vpn;

HipKDF::HipKDF(HipCipher* cipher, const ByteBlock& hostHit, const ByteBlock& peerHit)
	: m_cipher(cipher), m_hostHit(hostHit), m_peerHit(peerHit)
{
}

HipKDF::~HipKDF()
{
}

void HipKDF::Extract(const ByteBlock& key, const ByteBlock& salt, ByteBlock& extract)
{
	if (key.size() != m_cipher->KeyLength())
		throw Exception(Exception::Abort,
			HIP_KDF_EXCEPTION_STR \
			"KDF key size mismatch (extract).");

	HipCmac cmac(*m_cipher, key);
	cmac.Update(salt);

	if (m_peerHit < m_hostHit)
	{
		cmac.Update(m_peerHit);
		cmac.Update(m_hostHit);
	}
	else
	{
		cmac.Update(m_hostHit);
		cmac.Update(m_peerHit);
	}

	uint8_t info[] = "CKDF-Extract";
	cmac.Update(ByteBlock(info, info+12));

	extract.resize(cmac.DigestSize());
	cmac.Final(extract);
}

void HipKDF::Expand(const ByteBlock& key, ByteBlock& keymat)
{
	if ((keymat.size()%m_cipher->BlockSize()) != 0)
		throw Exception(Exception::Abort,
			HIP_KDF_EXCEPTION_STR \
			"Keymat size mismatch (expand).");

	if (key.size() != m_cipher->KeyLength())
		throw Exception(Exception::Abort,
			HIP_KDF_EXCEPTION_STR \
			"KDF key size mismatch (expand).");

	ByteBlock expand;
	uint8_t iter = 0;

	for (ByteBlock::size_type offset = 0;
		offset < keymat.size(); ++iter)
	{
		HipCmac cmac(*m_cipher, key);

		if (!expand.empty())
			cmac.Update(expand);

		if (m_peerHit < m_hostHit)
		{
			cmac.Update(m_peerHit);
			cmac.Update(m_hostHit);
		}
		else
		{
			cmac.Update(m_hostHit);
			cmac.Update(m_peerHit);
		}

		uint8_t info[] = "CKDF-Expand";
		cmac.Update(ByteBlock(info, info+11));
		cmac.Update(&iter, 1);

		expand.resize(cmac.DigestSize());
		cmac.Final(expand);

		std::copy(expand.begin(), expand.end(),
			keymat.data() + offset);

		offset += expand.size();
	}
}
