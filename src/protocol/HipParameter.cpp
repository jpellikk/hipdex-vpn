/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipParameter.h"
#include "HipDefines.h"
#include "HipPuzzle.h"
#include "HipSolution.h"
#include "HipHipCipher.h"
#include "HipEncryptedKey.h"
#include "HipHitSuiteList.h"
#include "HipDhGroupList.h"
#include "HipHostId.h"
#include "HipHipMac3.h"
#include "HipEchoReqSig.h"
#include "HipEchoResSig.h"
#include "HipAck.h"
#include "HipSeq.h"

#define HIP_PARAMETER_EXCEPTION_STR \
	"Handling parameter failed: "

using namespace hipdex_vpn;

HipParameter::HipParameter()
{
}

HipParameter::~HipParameter()
{
}

uint16_t HipParameter::Size() const
{
	uint16_t size = HDX_SIZE_PARAM_HDR + SizeImpl();
	return (size+((size%8)?(8-(size%8)):0));
}

void HipParameter::SetBytes(ByteBlockReader& reader)
{
	if (reader.BytesAvailable() < HDX_SIZE_PARAM_HDR)
		throw Exception(Exception::Error,
			HIP_PARAMETER_EXCEPTION_STR \
			"Invalid parameter length.");

	uint16_t data;
	reader >> data;

	if (data != Type())
		throw Exception(Exception::Error,
			HIP_PARAMETER_EXCEPTION_STR \
			"Parameter type mismatch.");

	reader >> data;

	uint16_t length = data + HDX_SIZE_PARAM_HDR;
	uint16_t padding = ((length%8)?(8-(length%8)):0);

	if (data+padding > reader.BytesAvailable())
		throw Exception(Exception::Error,
			HIP_PARAMETER_EXCEPTION_STR \
			"Invalid parameter length value.");

	SetBytesImpl(reader, data);
	reader.SkipNextBytes(padding);
}

void HipParameter::GetBytes(ByteBlockWriter& writer) const
{
	writer << Type();
	writer << SizeImpl();

	GetBytesImpl(writer);

	ByteBlock padding(Size()
		-SizeImpl()-HDX_SIZE_PARAM_HDR);

	writer << padding;
}

HipParameter* HipParameter::Create(ByteBlockReader& reader)
{
	if (reader.BytesAvailable() < HDX_SIZE_PARAM_HDR)
		throw Exception(Exception::Error,
			HIP_PARAMETER_EXCEPTION_STR \
			"Invalid bytes stream.");

	uint16_t type;
	reader.Peek(type);

	if (type == HDX_TYPE_PUZZLE)
		return HipPuzzle::Create();
	else if (type == HDX_TYPE_SOLUTION)
		return HipSolution::Create();
	else if (type == HDX_TYPE_HIP_CIPHER)
		return HipHipCipher::Create();
	else if (type == HDX_TYPE_ENCRYPTED_KEY)
		return HipEncryptedKey::Create();
	else if (type == HDX_TYPE_HOST_ID)
		return HipHostId::Create();
	else if (type == HDX_TYPE_HIT_SUITE_LIST)
		return HipHitSuiteList::Create();
	else if (type == HDX_TYPE_DH_GROUP_LIST)
		return HipDhGroupList::Create();
	else if	 (type == HDX_TYPE_HIP_MAC_3)
		return HipHipMac3::Create();
	else if	 (type == HDX_TYPE_ECHO_RES_SIG)
		return HipEchoResSig::Create();
	else if (type == HDX_TYPE_ECHO_REQ_SIG)
		return HipEchoReqSig::Create();
	else if (type == HDX_TYPE_ACK)
			return HipAck::Create();
	else if (type == HDX_TYPE_SEQ)
			return HipSeq::Create();
	else throw Exception(Exception::Error,
		HIP_PARAMETER_EXCEPTION_STR \
		"Unknown parameter type.");

	return nullptr;
}
