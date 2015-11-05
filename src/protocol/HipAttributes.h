/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_ATTRIBUTES_H
#define HIPDEX_VPN_PROTOCOL_HIP_ATTRIBUTES_H

#include "HipDefines.h"
#include "HipKeymat.h"
#include "HipPuzzle.h"
#include "HipCipher.h"
#include "Types.h"

#include <memory>

namespace hipdex_vpn
{
	class HipCipher;
	class HipPuzzle;

	class HipAttributes
	{
		public:
			explicit HipAttributes()
				: m_pairwiseKeySa(nullptr),
				  m_cipherSuite(0),
				  m_cipher(nullptr),
				  m_puzzle(nullptr),
				  m_hitSuite(0),
				  m_seq(0),
				  m_ack(0) {}

			virtual ~HipAttributes() {}

			typedef std::shared_ptr<HipCipher> HipCipherPtr;
			typedef std::unique_ptr<HipPuzzle> HipPuzzlePtr;
			typedef std::shared_ptr<HipKeymat> HipKeymatPtr;

			HipKeymatPtr m_pairwiseKeySa;

			ByteBlock m_peerHit;
			ByteBlock m_solutionJ;

			ByteBlock m_peerEK;
			ByteBlock m_peerIK;
			ByteBlock m_hostEK;
			ByteBlock m_hostIK;

			ByteBlock m_peerSecret;
			ByteBlock m_hostSecret;

			uint8_t m_cipherSuite;
			HipCipherPtr m_cipher;
			HipPuzzlePtr m_puzzle;
			uint8_t m_hitSuite;

			uint32_t m_seq;
			uint32_t m_ack;

			ByteBlock m_echo;
	};
}

#endif
