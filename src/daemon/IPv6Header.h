/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_IPV6_HEADER_H
#define HIPDEX_VPN_IPV6_HEADER_H

#include "Types.h"
#include "Exception.h"
#include "EthHeader.h"
#include "Header.h"

#define IPV6_HEADER_LENGTH 40
#define IPV6_ADDRESS_LENGTH 16
#define IPV6_PACKET_TYPE 6
#define ICMPV6_PACKET_TYPE 58
#define ICMPV6_NS_MIN_LENGTH 24
#define ICMPV6_HDR_LENGTH 4
#define ICMPV6_NS_TYPE 135

namespace hipdex_vpn
{
	class IPv6Header : public Header
	{
		public:
			IPv6Header() :
				m_pldLength(IPV6_HEADER_LENGTH),
				m_nextHdr(0),
				m_srcAddr(IPV6_ADDRESS_LENGTH),
				m_destAddr(IPV6_ADDRESS_LENGTH),
				m_targetAddr(IPV6_ADDRESS_LENGTH),
				m_isNS(false) {}
			~IPv6Header() {}
			ByteBlockSize Length() const {
				return IPV6_HEADER_LENGTH +
					(m_isNS ? ICMPV6_NS_MIN_LENGTH : 0);
			}
			void FromBytes(ByteBlockReader& reader) {
				if (reader.BytesAvailable() < IPV6_HEADER_LENGTH)
					throw Exception(Exception::Error,
						"Not enough bytes in stream.");
				uint8_t packetType;
				reader >> packetType;
				if (((packetType>>4)&0x0f) != IPV6_PACKET_TYPE)
					throw Exception(Exception::Error,
						"Invalid packet type in IPv6 frame.");
				reader.SkipNextBytes(3);
				reader >> m_pldLength;
				if (m_pldLength == 0)
					throw Exception(Exception::Error,
						"Invalid header length in IPv6 frame.");
				reader >> m_nextHdr;
				reader.SkipNextBytes(1);
				reader >> m_srcAddr;
				reader >> m_destAddr;
				if (reader.BytesAvailable() < m_pldLength)
					throw Exception(Exception::Error,
						"Not enough payload bytes in stream.");
				if (m_nextHdr != ICMPV6_PACKET_TYPE)
					return;
				if (m_pldLength < ICMPV6_HDR_LENGTH)
					throw Exception(Exception::Error,
						"Invalid ICMPv6 packet size.");
				reader >> packetType;
				if (packetType != ICMPV6_NS_TYPE)
					return;
				reader.SkipNextBytes(7);
				reader >> m_targetAddr;
				m_isNS = true;
			}
			void ToBytes(ByteBlockWriter& writer) const {
				writer << (uint8_t)0x60;
				writer << ByteBlock(3);
				writer << m_pldLength;
				writer << m_nextHdr;
				writer << (uint8_t)0;
				writer << m_srcAddr;
				writer << m_destAddr;
				if (!m_isNS)
					return;
				writer << (uint8_t)ICMPV6_NS_TYPE;
				writer << ByteBlock(7);
				writer << m_targetAddr;
			}
			uint16_t m_pldLength;
			uint8_t m_nextHdr;
			ByteBlock m_srcAddr;
			ByteBlock m_destAddr;
			ByteBlock m_targetAddr;
			bool m_isNS;
	};
}

#endif
