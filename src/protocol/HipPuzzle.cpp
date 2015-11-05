/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipDefines.h"
#include "HipPuzzle.h"
#include "Exception.h"
#include "HipCmac.h"
#include "Log.h"

using namespace hipdex_vpn;

HipPuzzle::HipPuzzle()
	: m_complexity(0), m_lifetime(0), m_opaque(0), m_randomI(0)
{
}

HipPuzzle::HipPuzzle(uint8_t complexity, uint8_t lifetime,
	uint16_t opaque, const ByteBlock& randomI)
	: m_complexity(complexity), m_lifetime(lifetime),
	  m_opaque(opaque), m_randomI(randomI)
{
}

HipPuzzle::~HipPuzzle()
{
}

HipParameter* HipPuzzle::Create()
{
	return new HipPuzzle;
}

unsigned short HipPuzzle::Type() const
{
	return HDX_TYPE_PUZZLE;
}

uint16_t HipPuzzle::SizeImpl() const
{
	return 4+m_randomI.size();
}

void HipPuzzle::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_complexity;
	bytes << m_lifetime;
	bytes << m_opaque;
	bytes << m_randomI;
}

void HipPuzzle::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	if (size != 20)
		throw Exception(Exception::Error, "Invalid parameter.");

	bytes >> m_complexity;
	bytes >> m_lifetime;
	bytes >> m_opaque;

	m_randomI.resize(16);
	bytes >> m_randomI;
}

bool HipPuzzle::SolvePuzzle(const HipCipher& cipher,
	const ByteBlock& hostHit, const ByteBlock& peerHit,
	HipPuzzle& puzzle, ByteBlock& solutionJ) const
{
	if (m_randomI.size() != cipher.BlockSize())
		throw Exception(Exception::Error,
			"The size of RANDOM_I does NOT match" \
				" that of the cipher block size.");

	// TODO: validate puzzle lifetime expiration here !!!

	solutionJ.resize(m_randomI.size());
	ByteBlock result(m_randomI.size());

	std::size_t numBytes = (m_complexity+7)>>3;
	ByteBlock zero(numBytes);

	while (true) {
		HipCmac cmac(cipher, m_randomI);

		cmac.Update(hostHit);
		cmac.Update(peerHit);

		HipCipher::RandBytes(solutionJ);
		cmac.Update(solutionJ);

		cmac.Final(result);

		result[numBytes-1] &=
			(0xff<<(8*numBytes-m_complexity));

		if (std::equal(result.begin(),
			result.begin() + numBytes,
			zero.begin())) break;
	}

	puzzle = *this;
	return true;
}
