/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_IPV4_HEADER_H
#define HIPDEX_VPN_IPV4_HEADER_H

#include "Types.h"
#include "Exception.h"
#include "EthHeader.h"
#include "Header.h"

#define IPV4_HEADER_LENGTH 20
#define IPV4_ADDRESS_LENGTH 4
#define IPV4_PACKET_TYPE 4

namespace hipdex_vpn
{
	class IPv4Header : public Header
	{
		public:
			IPv4Header() :
				m_hdrLength(IPV4_HEADER_LENGTH),
				m_srcAddr(IPV4_ADDRESS_LENGTH),
				m_destAddr(IPV4_ADDRESS_LENGTH) {}
			~IPv4Header() {}
			ByteBlockSize Length() const {
				return m_hdrLength;
			}
			void FromBytes(ByteBlockReader& reader) {
				if (reader.BytesAvailable() < IPV4_HEADER_LENGTH)
					throw Exception(Exception::Error,
						"Not enough bytes in stream.");
				reader >> m_hdrLength;
				if (((m_hdrLength>>4)&0x0f) != IPV4_PACKET_TYPE)
					throw Exception(Exception::Error,
						"Invalid packet type in IPv4 frame.");
				m_hdrLength = (m_hdrLength&0x0f)*4;
				if (m_hdrLength < IPV4_HEADER_LENGTH)
					throw Exception(Exception::Error,
						"Invalid header length in IPv4 frame.");
				reader.SkipNextBytes(11);
				reader >> m_srcAddr;
				reader >> m_destAddr;
				if (reader.BytesAvailable() <
					(ByteBlockSize)(m_hdrLength-=IPV4_HEADER_LENGTH))
					throw Exception(Exception::Error,
						"Cannot read option bytes from stream.");
				reader.SkipNextBytes(m_hdrLength);
				m_hdrLength = IPV4_HEADER_LENGTH;
			}
			void ToBytes(ByteBlockWriter& writer) const {
				writer << (uint8_t)0x45;
				writer << ByteBlock(11);
				writer << m_srcAddr;
				writer << m_destAddr;
			}
			uint8_t m_hdrLength;
			ByteBlock m_srcAddr;
			ByteBlock m_destAddr;
	};
}

#endif
