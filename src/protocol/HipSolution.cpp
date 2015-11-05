/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipDefines.h"
#include "HipSolution.h"
#include "HipPuzzle.h"
#include "HipCmac.h"

using namespace hipdex_vpn;

HipSolution::HipSolution()
	: m_complexity(0), m_opaque(0), m_randomI(16), m_solutionJ(16)
{
}

HipSolution::HipSolution(uint8_t complexity, uint16_t opaque,
	const ByteBlock& randomI, const ByteBlock& solutionJ)
	: m_complexity(complexity), m_opaque(opaque),
	  m_randomI(randomI), m_solutionJ(solutionJ)
{
}

HipSolution::~HipSolution()
{
}

HipParameter* HipSolution::Create()
{
	return new HipSolution;
}

uint16_t HipSolution::Type() const
{
	return HDX_TYPE_SOLUTION;
}

uint16_t HipSolution::SizeImpl() const
{
	return 4+m_randomI.size()+m_solutionJ.size();
}

void HipSolution::GetBytesImpl(ByteBlockWriter& bytes) const
{
	bytes << m_complexity;
	bytes << (uint8_t)0;

	bytes << m_opaque;

	bytes << m_randomI;
	bytes << m_solutionJ;
}

void HipSolution::SetBytesImpl(ByteBlockReader& bytes, ByteBlockSize size)
{
	if (size != 36)
		throw Exception(Exception::Error, "Invalid parameter.");

	bytes >> m_complexity;
	bytes.SkipNextBytes(1);

	bytes >> m_opaque;

	m_randomI.resize(16);
	bytes >> m_randomI;

	m_solutionJ.resize(16);
	bytes >> m_solutionJ;
}

bool HipSolution::VerifySolution(const HipCipher& cipher,
	const ByteBlock& hostHit, const ByteBlock& peerHit,
	const HipPuzzle& puzzle, ByteBlock& solutionJ) const
{
	if (m_randomI.size() != cipher.BlockSize())
		throw Exception(Exception::Error,
			"The size of RANDOM_I does NOT match" \
				" that of the cipher block size.");

	if (puzzle.m_randomI != m_randomI ||
		puzzle.m_complexity != m_complexity ||
		puzzle.m_opaque != m_opaque)
		return false;

	// TODO: validate puzzle lifetime expiration here !!!

	std::size_t numBytes = (m_complexity+7)>>3;
	ByteBlock zero(numBytes);

	HipCmac cmac(cipher, m_randomI);

	cmac.Update(peerHit);
	cmac.Update(hostHit);

	cmac.Update(m_solutionJ);

	ByteBlock result(cmac.DigestSize());
	cmac.Final(result);

	result[numBytes-1] &=
		(0xff<<(8*numBytes-m_complexity));

	if (!std::equal(result.begin(),
		result.begin() + numBytes,
		zero.begin())) return false;

	solutionJ = m_solutionJ;
	return true;
}
