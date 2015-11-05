/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIT_SUITE_LIST_H
#define HIPDEX_VPN_PROTOCOL_HIT_SUITE_LIST_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipHitSuiteList : public HipParameter
	{
		public:
			explicit HipHitSuiteList(const ByteBlock&);
			explicit HipHitSuiteList(uint8_t);
			static HipParameter* Create();
			uint16_t Type() const;
			~HipHitSuiteList();

			ByteBlock m_suites;

		protected:
			HipHitSuiteList();
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
