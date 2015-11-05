/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_TYPES_H
#define HIPDEX_VPN_COMMON_TYPES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstddef>
#include <inttypes.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "BinaryReader.h"
#include "BinaryWriter.h"
#include "Log.h"

namespace hipdex_vpn
{
	typedef std::vector<uint8_t> ByteBlock;
	typedef ByteBlock::size_type ByteBlockSize;
	typedef BinaryReader<ByteBlock> ByteBlockReader;
	typedef BinaryWriter<ByteBlock> ByteBlockWriter;
	inline static std::ostream& operator<<(
		std::ostream& os, const ByteBlock& bytes) {
		os << "{";
		for (auto it = bytes.begin(); it != bytes.end();) {
			os << "0x" << std::setfill('0') << std::setw(2)
				<< std::hex << (int)*it;
			if (++it != bytes.end())
				os << ", ";
		}
		return os << "}";
	}
}

#endif
