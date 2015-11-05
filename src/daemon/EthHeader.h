/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_ETH_HEADER_H
#define HIPDEX_VPN_ETH_HEADER_H

#include "Types.h"
#include "Exception.h"
#include "Header.h"

#define ETHERNET_HEADER_LENGTH 14
#define HW_ADDRESS_LENGTH 6

namespace hipdex_vpn
{
	class EthHeader : public Header
	{
		public:
			enum PacketType {
				PacketIPV4 = 0x0800,
				PacketARP = 0x0806,
				PacketIPV6 = 0x86dd
			};
			EthHeader() :
				m_destMac(HW_ADDRESS_LENGTH),
				m_srcMac(HW_ADDRESS_LENGTH),
				m_type(0) {}
			~EthHeader() {}
			static uint16_t PeekType(const ByteBlock& a) {
				if (a.size() < ETHERNET_HEADER_LENGTH)
					return 0;
				return (a[12] << 8) + (a[13] & 0xff);
			}
			ByteBlockSize Length() const {
				return ETHERNET_HEADER_LENGTH;
			}
			void FromBytes(ByteBlockReader& reader) {
				if (reader.BytesAvailable() < ETHERNET_HEADER_LENGTH)
					throw Exception(Exception::Error,
						"Not enough bytes in stream.");
				reader >> m_destMac;
				reader >> m_srcMac;
				reader >> m_type;
			}
			void ToBytes(ByteBlockWriter& writer) const {
				writer << m_destMac;
				writer << m_srcMac;
				writer << m_type;
			}
			ByteBlock m_destMac;
			ByteBlock m_srcMac;
			uint16_t m_type;
	};
}

#endif
