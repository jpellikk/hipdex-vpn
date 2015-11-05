/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_HEADER_H
#define HIPDEX_VPN_HEADER_H

#include <ostream>
#include <iomanip>

#include "Types.h"
#include "Exception.h"

namespace hipdex_vpn
{
	class Header
	{
		public:
			Header() {}
			virtual ~Header() {}
			virtual ByteBlockSize Length() const = 0;
			virtual void FromBytes(ByteBlockReader&) = 0;
			virtual void ToBytes(ByteBlockWriter&) const = 0;
			friend std::ostream& operator<<(std::ostream& os,
				const Header& header) {
				ByteBlock bytes(header.Length());
				ByteBlockWriter writer(bytes);
				header.ToBytes(writer);
				return os << bytes;
			}
	};
}

#endif
