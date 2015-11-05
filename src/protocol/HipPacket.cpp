/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipPacket.h"
#include "HipDefines.h"
#include "HipPacketI1.h"
#include "HipPacketR1.h"
#include "HipPacketI2.h"
#include "HipPacketR2.h"
#include "HipPacketUpdate.h"
#include "HipPacketClose.h"
#include "HipPacketCloseAck.h"
#include "HipHipMac3.h"

#define HIP_PACKET_EXCEPTION_STR \
	"Error handling packet: "

using namespace hipdex_vpn;

HipPacket::HipPacket(uint8_t type)
	: m_nextHdr(HDX_IPPROTO_NONE), m_type(type),
	  m_version(HDX_PROTOCOL_VERSION), m_ctrls(0),
	  m_senderHit(), m_receiverHit()
{
}

HipPacket::~HipPacket()
{
}

void HipPacket::SetBytes(ByteBlock& bytes)
{
	ByteBlockReader reader(bytes);
	reader >> m_nextHdr;

	if (m_nextHdr != HDX_IPPROTO_NONE)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Invalid next header value.");

	uint8_t field;
	reader >> field;
	field = (field<<3) + 8;

	if (field != bytes.size())
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Invalid header length.");

	reader >> field;

	if (field != m_type)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Packet type mismatch.");

	reader >> m_version;
	m_version = ((m_version>>4)&0x0f);

	if (m_version != HDX_PROTOCOL_VERSION)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Protocol version mismatch.");

	uint16_t checksum;
	reader >> checksum;

	bytes[4] = 0;
	bytes[5] = 0;

	if (checksum != CalculateChecksum(bytes))
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Invalid packet checksum.");

	reader >> m_ctrls;

	m_senderHit.resize(HDX_LENGTH_HIT);
	reader >> m_senderHit;

	m_receiverHit.resize(HDX_LENGTH_HIT);
	reader >> m_receiverHit;

	while (reader.IsBytesAvailable())
	{
		HipParameter* param = HipParameter::Create(reader);

		(*m_params.insert(m_params.end(),
			HipParameterPtr(param)))->SetBytes(reader);
	}
}

void HipPacket::GetBytes(ByteBlock& bytes, bool signable) const
{
	uint32_t length = Size(signable);

	ByteBlockWriter writer(bytes);
	bytes.resize(length);

	writer << m_nextHdr;
	writer << (uint8_t)((length-8)>>3);
	writer << m_type;
	writer << (uint8_t)(((m_version&0x0f)<<4)|0x01);
	writer << (uint16_t)0;
	writer << m_ctrls;

	if (m_senderHit.size() != HDX_LENGTH_HIT)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Size of sender HIT invalid.");

	writer << m_senderHit;

	if (m_receiverHit.size() != HDX_LENGTH_HIT)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Size of receiver HIT invalid.");

	writer << m_receiverHit;

	for (auto& param : m_params)
	{
		if (param->Type() >= HDX_TYPE_HIP_MAC_3 && signable)
			continue;

		param->GetBytes(writer);
	}

	if (signable) return;

	length = CalculateChecksum(bytes);

	bytes[4] = (length>>8)&0xff;
	bytes[5] = length&0xff;
}

uint32_t HipPacket::Size(bool signable) const
{
	uint16_t length = HDX_SIZE_PACKET_HDR;

	for (auto& param : m_params)
	{
		if (param->Type() >= HDX_TYPE_HIP_MAC_3 && signable)
			continue;

		length += param->Size();
	}

	return length;
}

uint16_t HipPacket::CalculateChecksum(const ByteBlock& bytes) const
{
	uint64_t checksum = 0;

	for (ByteBlock::size_type i = 0; i < bytes.size(); ++i)
		checksum += ((i%2==0) ? (bytes[i]<<8) : bytes[i]);

	while ((checksum>>16))
		checksum = (checksum&0xffff)+(checksum>>16);

	return ~checksum;
}

bool HipPacket::VerifyCmac(const HipCipher& cipher, const ByteBlock& hostIK) const
{
	ByteBlock signableBytes(this->Size(true));
	this->GetBytes(signableBytes, true);

	HipParameter* param =
		this->GetParameter(HDX_TYPE_HIP_MAC_3);

	return param->VerifyCmac(cipher, hostIK, signableBytes);
}

void HipPacket::AssignCmac(const HipCipher& cipher, const ByteBlock& peerIK)
{
	ByteBlock signableBytes(this->Size(true));
	this->GetBytes(signableBytes, true);

	HipHipMac3* mac = new HipHipMac3;
	mac->CreateCmac(cipher, peerIK, signableBytes);

	this->AddParameter(mac);
}

void HipPacket::AddParameter(HipParameter* param)
{
	m_params.insert(m_params.end(),
		HipParameterPtr(param));
}

HipParameter* HipPacket::GetParameter(uint16_t type) const
{
	for (auto& param : m_params)
		if (param->Type() == type)
			return param.get();

	return nullptr;
}

bool HipPacket::HasParameter(uint16_t type) const
{
	for (auto& param : m_params)
		if (param->Type() == type)
			return true;

	return false;
}

HipPacket* HipPacket::Create(const ByteBlock& bytes)
{
	if (bytes.size() < HDX_SIZE_PACKET_HDR)
		throw Exception(Exception::Error,
			HIP_PACKET_EXCEPTION_STR \
			"Invalid byte stream.");

	uint8_t type = bytes[2] & 0x7f;

	if (type == HDX_TYPE_PACKET_I1)
		return HipPacketI1::Create();
	else if (type == HDX_TYPE_PACKET_I2)
		return HipPacketI2::Create();
	else if (type == HDX_TYPE_PACKET_R1)
		return HipPacketR1::Create();
	else if (type == HDX_TYPE_PACKET_R2)
		return HipPacketR2::Create();
	else if (type == HDX_TYPE_PACKET_UPDATE)
		return HipPacketUpdate::Create();
	else if (type == HDX_TYPE_PACKET_CLOSE)
		return HipPacketClose::Create();
	else if (type == HDX_TYPE_PACKET_CLOSE_ACK)
		return HipPacketCloseAck::Create();
	else throw Exception(Exception::Error,
		HIP_PACKET_EXCEPTION_STR \
		"Unknown packet type.");

	return nullptr;
}
