/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_HIP_DH_GROUP_LIST_H
#define HIPDEX_VPN_HIP_DH_GROUP_LIST_H

#include "HipParameter.h"

namespace hipdex_vpn
{
	class HipDhGroupList : public HipParameter
	{
		public:
			HipDhGroupList();
			~HipDhGroupList();
			bool VerifyDhGroup(uint8_t) const;
			explicit HipDhGroupList(const ByteBlock&);
			explicit HipDhGroupList(uint8_t);
			static HipParameter* Create();
			uint16_t Type() const;

			ByteBlock m_groups;

		protected:
			uint16_t SizeImpl() const;
			void GetBytesImpl(ByteBlockWriter&) const;
			void SetBytesImpl(ByteBlockReader&, ByteBlockSize);
	};
}

#endif
