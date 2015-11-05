/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_SOLUTION_H
#define HIPDEX_VPN_PROTOCOL_HIP_SOLUTION_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipSolution : public HipParameter
	{
		public:
			HipSolution(uint8_t, uint16_t,
				const ByteBlock&, const ByteBlock&);
			bool VerifySolution(const HipCipher&,
				const ByteBlock&, const ByteBlock&,
				const HipPuzzle&, ByteBlock&) const;
			static HipParameter* Create();
			uint16_t Type() const;
			~HipSolution();

			uint8_t m_complexity;
			uint16_t m_opaque;
			ByteBlock m_randomI;
			ByteBlock m_solutionJ;

		protected:
			HipSolution();
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
