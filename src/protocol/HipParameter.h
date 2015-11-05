/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_PARAMETER_H
#define HIPDEX_VPN_PROTOCOL_PARAMETER_H

#include "Exception.h"
#include "HipDefines.h"
#include "HipIdentity.h"
#include "HipCipher.h"
#include "Types.h"

namespace hipdex_vpn
{
	class HipPuzzle;

	class HipParameter
	{
		public:
			HipParameter();
			uint16_t Size() const;
			void SetBytes(ByteBlockReader&);
			void GetBytes(ByteBlockWriter&) const;

			static HipParameter* Create(ByteBlockReader&);

			virtual uint16_t Type() const = 0;
			virtual ~HipParameter() = 0;

			virtual bool Decrypt(HipCipher&, const ByteBlock&, ByteBlock&) const
				{ return false; }
			virtual bool VerifyCmac(const HipCipher&, const ByteBlock&, const ByteBlock&) const
				{ return false; }
			virtual bool SolvePuzzle(const HipCipher&, const ByteBlock&,
				const ByteBlock&, HipPuzzle&, ByteBlock&) const
				{ return false; }
			virtual bool VerifySolution(const HipCipher&, const ByteBlock&,
				const ByteBlock&, const HipPuzzle&, ByteBlock&) const
				{ return false; }
			virtual bool CalculateEcdh(const HipIdentity&, ByteBlock&) const
				{ return false; }
			virtual bool VerifyDhGroup(uint8_t) const
				{ return false; }
			virtual bool ValidateCipher(uint8_t&, const ByteBlock&) const
				{ return false; }
			virtual bool SelectCipher(uint8_t&, const ByteBlock&) const
				{ return false; }
			virtual bool Update(uint32_t&) const
				{ return false; }
			virtual bool HandleEcho(ByteBlock&) const
				{ return false; }

		protected:
			virtual uint16_t SizeImpl() const = 0;
			virtual void GetBytesImpl(ByteBlockWriter&) const = 0;
			virtual void SetBytesImpl(ByteBlockReader&, ByteBlockSize) = 0;
	};
}

#endif
