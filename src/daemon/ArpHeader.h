/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_ARP_HEADER_H
#define HIPDEX_VPN_ARP_HEADER_H

#include "Types.h"
#include "Exception.h"
#include "EthHeader.h"
#include "Header.h"

#define ARP_HEADER_LENGTH 28
#define ARP_HW_TYPE_ETH 1
#define ARP_HW_ADDR_LEN 6
#define ARP_PROTO_LEN 4

namespace hipdex_vpn
{
	class ArpHeader : public Header
	{
		public:
			enum OperationType {
				OperationRequest = 1,
				OperationReply = 2
			};
			ArpHeader() : m_oper(0),
				m_sha(ARP_HW_ADDR_LEN),
				m_spa(ARP_PROTO_LEN),
				m_tha(ARP_HW_ADDR_LEN),
				m_tpa(ARP_PROTO_LEN) {}
			~ArpHeader() {}
			ByteBlockSize Length() const {
				return ARP_HEADER_LENGTH;
			}
			void FromBytes(ByteBlockReader& reader) {
				if (reader.BytesAvailable() < ARP_HEADER_LENGTH)
					throw Exception(Exception::Error,
						"Not enough bytes in stream.");
				reader >> m_oper;
				if (m_oper != ARP_HW_TYPE_ETH)
					throw Exception(Exception::Error,
						"Unsupported HW type in ARP frame.");
				reader >> m_oper;
				if (m_oper != EthHeader::PacketIPV4)
					throw Exception(Exception::Error,
						"Unsupported protocol type in ARP frame.");
				uint8_t temp;
				reader >> temp;
				if (temp != ARP_HW_ADDR_LEN)
					throw Exception(Exception::Error,
						"Invalid HW address size in ARP frame.");
				reader >> temp;
				if (temp != ARP_PROTO_LEN)
					throw Exception(Exception::Error,
						"Invalid protocol size in ARP frame.");
				reader >> m_oper;
				reader >> m_sha;
				reader >> m_spa;
				reader >> m_tha;
				reader >> m_tpa;
			}
			void ToBytes(ByteBlockWriter& writer) const {
				writer << (uint16_t)ARP_HW_TYPE_ETH;
				writer << (uint16_t)EthHeader::PacketIPV4;
				writer << (uint8_t)ARP_HW_ADDR_LEN;
				writer << (uint8_t)ARP_PROTO_LEN;
				writer << m_oper;
				writer << m_sha;
				writer << m_spa;
				writer << m_tha;
				writer << m_tpa;
			}
			uint16_t m_oper;
			ByteBlock m_sha;
			ByteBlock m_spa;
			ByteBlock m_tha;
			ByteBlock m_tpa;
	};
}

#endif
