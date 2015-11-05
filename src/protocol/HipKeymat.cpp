/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipKeymat.h"
#include "HipCipher.h"
#include "HipKDF.h"

using namespace hipdex_vpn;

HipKeymat::HipKeymat()
{
}

HipKeymat::~HipKeymat()
{
}

void HipKeymat::Calculate(HipCipher* cipher, const ByteBlock& randomI,
	const ByteBlock& hostHit, const ByteBlock& peerHit, const ByteBlock& key)
{
	ByteBlock extract, material(4*cipher->KeyLength());

	HipKDF hipKDF(cipher, hostHit, peerHit);

	hipKDF.Extract(randomI, key, extract);
	hipKDF.Expand(extract, material);

	ByteBlockReader reader(material);

	m_hostEK.resize(cipher->KeyLength());
	m_hostIK.resize(cipher->KeyLength());
	m_peerEK.resize(cipher->KeyLength());
	m_peerIK.resize(cipher->KeyLength());

	if (peerHit < hostHit)
	{
		reader >> m_hostEK;
		reader >> m_hostIK;
		reader >> m_peerEK;
		reader >> m_peerIK;
	}
	else
	{
		reader >> m_peerEK;
		reader >> m_peerIK;
		reader >> m_hostEK;
		reader >> m_hostIK;
	}
}
