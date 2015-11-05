/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_PACKET_H
#define HIPDEX_VPN_PROTOCOL_HIP_PACKET_H

#include "HipParameter.h"
#include "Types.h"

#include <memory>
#include <list>

namespace hipdex_vpn
{
	class HipPacket
	{
		public:
			explicit HipPacket(uint8_t);
			virtual ~HipPacket() = 0;

			static HipPacket* Create(const ByteBlock&);
			HipParameter* GetParameter(uint16_t) const;
			bool HasParameter(uint16_t) const;
			void AddParameter(HipParameter*);

			bool VerifyCmac(const HipCipher&, const ByteBlock&) const;
			void AssignCmac(const HipCipher&, const ByteBlock&);

			void GetBytes(ByteBlock&, bool = false) const;
			uint32_t Size(bool = false) const;
			void SetBytes(ByteBlock&);

			uint8_t m_nextHdr;
			uint8_t m_type;
			uint8_t m_version;
			uint16_t m_ctrls;

			ByteBlock m_senderHit;
			ByteBlock m_receiverHit;

		private:
			uint16_t CalculateChecksum(const ByteBlock&) const;
			typedef std::unique_ptr<HipParameter> HipParameterPtr;
			std::list<HipParameterPtr> m_params;
	};
}

#endif
