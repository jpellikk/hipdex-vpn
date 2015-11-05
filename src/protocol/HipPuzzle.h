/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PUZZLE_H
#define HIPDEX_VPN_PROTOCOL_HIP_PUZZLE_H

#include "HipParameter.h"
#include "HipCipher.h"

namespace hipdex_vpn
{
	class HipPuzzle : public HipParameter
	{
		public:
			HipPuzzle();
			HipPuzzle(uint8_t, uint8_t,
				uint16_t, const ByteBlock&);
			bool SolvePuzzle(const HipCipher&,
				const ByteBlock&, const ByteBlock&,
				HipPuzzle&, ByteBlock&) const;
			static HipParameter* Create();
			uint16_t Type() const;
			~HipPuzzle();

			uint8_t m_complexity;
			uint8_t m_lifetime;
			uint16_t m_opaque;
			ByteBlock m_randomI;

		protected:
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
