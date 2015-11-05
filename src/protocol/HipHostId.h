/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HOST_ID_H
#define HIPDEX_VPN_PROTOCOL_HOST_ID_H

#include "HipParameter.h"
#include "Types.h"

namespace hipdex_vpn
{
	class HipHostId : public HipParameter
	{
		public:
			enum DomainType {
				None = 0,
				Fqdn = 1,
				Nai = 2
			};

			HipHostId(DomainType, const ByteBlock&,
				const ByteBlock& = ByteBlock());

			bool CalculateEcdh(const HipIdentity& id,
				ByteBlock&) const;

			static HipParameter* Create();
			uint16_t Type() const;
			~HipHostId();

			DomainType m_domainType;
			ByteBlock m_hostId;
			ByteBlock m_domainId;

		protected:
			HipHostId();
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
