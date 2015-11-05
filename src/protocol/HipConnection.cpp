/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipConnection.h"
#include "HipDefines.h"
#include "HipContext.h"
#include "HipConfig.h"
#include "Exception.h"
#include "HipInit.h"
#include "HipKDF.h"

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

#include "HipPacketI1.h"
#include "HipPacketR1.h"
#include "HipPacketI2.h"
#include "HipPacketR2.h"
#include "HipPacketUpdate.h"
#include "HipPacketClose.h"
#include "HipPacketCloseAck.h"
#include "HipUnassociated.h"

#define HIP_CONNECTION_EXCEPTION_STR \
	"Handling HIP connection failed: "

using namespace hipdex_vpn;

HipConnection::HipConnection(const ByteBlock& peerHit, HipHandler* handler)
	: m_state(new HipUnassociated), m_handler(handler)
{
	m_peerHit = peerHit;
}

HipConnection::~HipConnection()
{
}

void HipConnection::ResetConnection()
{
	m_hostSecret.clear();
	m_peerSecret.clear();
	m_puzzle.release();
}

void HipConnection::SetState(HipState* state)
{
	m_state.reset(state);
}

void HipConnection::HandlePacket(HipContext* context)
{
	LOGGER_DEBUG("** RECEIVED HANDLE PACKET **");

	if (context->m_packet->m_receiverHit
			!= context->m_id->Hit())
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"HIP packet recipient mismatch.");

	if (context->m_packet->m_senderHit
		== context->m_id->Hit())
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"HIP packet sender mismatch.");

	uint16_t type = context->m_packet->m_type;

	LOGGER_DEBUG("Packet type: ", type);

	if (type == HDX_TYPE_PACKET_I1)
		m_state->HandleI1(this, context);
	else if (type == HDX_TYPE_PACKET_I2)
		m_state->HandleI2(this, context);
	else if (type == HDX_TYPE_PACKET_R1)
		m_state->HandleR1(this, context);
	else if (type == HDX_TYPE_PACKET_R2)
		m_state->HandleR2(this, context);
	else if (type == HDX_TYPE_PACKET_UPDATE)
		m_state->HandleUpdate(this, context);
	else if (type == HDX_TYPE_PACKET_CLOSE)
		m_state->HandleClose(this, context);
	else if (type == HDX_TYPE_PACKET_CLOSE_ACK)
		m_state->HandleCloseAck(this, context);
	else throw Exception(Exception::Error,
		HIP_CONNECTION_EXCEPTION_STR \
		"Unsupported HIP packet.");
}

void HipConnection::Refresh(HipContext* context)
{
	LOGGER_DEBUG("** RECEIVED REFRESH **");

	m_state->Refresh(this, context);
}

void HipConnection::Initiate(HipContext* context)
{
	LOGGER_DEBUG("** RECEIVED INITIATE **");

	m_state->Initiate(this, context);
}

void HipConnection::SendI1(HipContext* context)
{
	LOGGER_DEBUG("** SENDING I1 **");

	HipDhGroupList* groupList = new
		HipDhGroupList(context->m_id->DhGroup());

	HipPacketI1 packet(groupList);

	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendI2(HipContext* context)
{
	LOGGER_DEBUG("** SENDING I2 **");

	ByteBlock encrKeyData;
	encrKeyData.reserve(m_hostSecret.size()
		+ m_puzzle->m_randomI.size());
	encrKeyData.insert(encrKeyData.end(),
		m_hostSecret.begin(), m_hostSecret.end());
	encrKeyData.insert(encrKeyData.end(),
		m_puzzle->m_randomI.begin(),
		m_puzzle->m_randomI.end());

	LOGGER_DEBUG("Encrypted key: ", encrKeyData);

	HipEncryptedKey* encrKey = new HipEncryptedKey;
	encrKey->Encrypt(*m_cipher, m_hostEK, encrKeyData);

	HipSolution* solution = new HipSolution(
		m_puzzle->m_complexity,
		m_puzzle->m_opaque,
		m_puzzle->m_randomI,
		m_solutionJ);

	ByteBlock hostIdBytes;
	context->m_id->ToHostId(hostIdBytes);

	LOGGER_DEBUG("Host ID bytes: ", hostIdBytes);

	HipHostId* hostId = new HipHostId(
		HipHostId::None, hostIdBytes);

	HipHipCipher* cipher = new HipHipCipher(m_cipherSuite);

	HipPacketI2 packet(solution, cipher, encrKey, hostId);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendR1(HipContext* context)
{
	LOGGER_DEBUG("** SENDING R1 **");

	HipPuzzle* puzzle = new HipPuzzle(*m_puzzle);

	HipHipCipher* cipher = new
		HipHipCipher(context->m_config->m_cipherSuites);

	HipHitSuiteList* hitSuiteList = new
		HipHitSuiteList(context->m_config->m_hitSuites[0]);

	ByteBlock hostIdBytes;
	context->m_id->ToHostId(hostIdBytes);

	LOGGER_DEBUG("Host ID bytes: ", hostIdBytes);

	HipHostId* hostId = new HipHostId(
		HipHostId::None, hostIdBytes);

	HipDhGroupList* dhGroupList = new
		HipDhGroupList(context->m_id->DhGroup());

	HipPacketR1 packet(puzzle, cipher, hostId,
		hitSuiteList, dhGroupList);

	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendR2(HipContext* context)
{
	LOGGER_DEBUG("** SENDING R2 **");

	ByteBlock encrKeyData;
	encrKeyData.reserve(m_hostSecret.size()
		+ m_puzzle->m_randomI.size());
	encrKeyData.insert(encrKeyData.end(),
		m_hostSecret.begin(), m_hostSecret.end());
	encrKeyData.insert(encrKeyData.end(),
		m_puzzle->m_randomI.begin(),
		m_puzzle->m_randomI.end());

	LOGGER_DEBUG("Encrypted key: ", encrKeyData);

	HipEncryptedKey* encrKey = new HipEncryptedKey;
	encrKey->Encrypt(*m_cipher, m_hostEK, encrKeyData);

	HipDhGroupList* groupList = new
		HipDhGroupList(context->m_id->DhGroup());

	HipPacketR2 packet(encrKey, groupList);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendUpdateSeq(HipContext* context)
{
	LOGGER_DEBUG("** SENDING UPDATE (SEQ) **");

	HipSeq* seqParam = new HipSeq(m_seq);

	HipPacketUpdate packet(seqParam);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendUpdateAck(HipContext* context)
{
	LOGGER_DEBUG("** SENDING UPDATE (ACK) **");

	HipAck* ackParam = new HipAck(m_ack);

	HipPacketUpdate packet(ackParam);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendClose(HipContext* context)
{
	LOGGER_DEBUG("** SENDING CLOSE **");

	HipEchoReqSig* echo = new HipEchoReqSig(m_echo);

	HipPacketClose packet(echo);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::SendCloseAck(HipContext* context)
{
	LOGGER_DEBUG("** SENDING CLOSE_ACK **");

	HipEchoResSig* echo = new HipEchoResSig(m_echo);

	HipPacketCloseAck packet(echo);
	packet.m_senderHit = context->m_id->Hit();
	packet.m_receiverHit = m_peerHit;

	packet.AssignCmac(*m_cipher, m_hostIK);
	m_handler->HipSendPacket(&packet, context);
}

void HipConnection::HandleInit(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING INIT **");

	SendI1(context);
}

void HipConnection::HandleShutdown(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING SHUTDOWN **");

	m_echo.resize(HDX_SIZE_ECHO_REQ);
	HipCipher::RandBytes(m_echo);

	SendClose(context);

	ResetConnection();

	m_handler->HipCloseConnection(context);
}

void HipConnection::HandleI1(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING I1 **");

	if (!m_puzzle)
	{
		m_puzzle.reset(new HipPuzzle(
			context->m_config->m_puzzleComplexity,
			context->m_config->m_puzzleLifetime,
			0, ByteBlock()));

		m_puzzle->m_randomI.resize(HDX_SIZE_RHASH);
		HipCipher::RandBytes(m_puzzle->m_randomI);
	}

	LOGGER_DEBUG("Random I: ", m_puzzle->m_randomI);

	SendR1(context);
}

void HipConnection::HandleI2(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING I2 **");

	HipParameter* param =
		context->m_packet->GetParameter(HDX_TYPE_HIP_CIPHER);

	uint8_t newCipherSuite = 0;

	if (!param->ValidateCipher(newCipherSuite,
		context->m_config->m_cipherSuites))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Invalid cipher suite in I2 packet.");

	HipCipherPtr newCipher(new HipCipher(newCipherSuite));

	param = context->m_packet->GetParameter(HDX_TYPE_SOLUTION);

	ByteBlock solutionJ;

	if (!param->VerifySolution(*newCipher, context->m_id->Hit(),
		m_peerHit, *m_puzzle, solutionJ))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect solution in I2 packet.");

	param = context->m_packet->GetParameter(HDX_TYPE_HOST_ID);

	ByteBlock sharedKey;

	if (!param->CalculateEcdh(*context->m_id, sharedKey))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Calculating ECDH key failed (I2).");

	LOGGER_DEBUG("Shared ECDH key: ", sharedKey);

	HipKeymat newKeymat;
	newKeymat.Calculate(newCipher.get(), m_puzzle->m_randomI,
		context->m_id->Hit(), m_peerHit, sharedKey);

	LOGGER_DEBUG("Host EK: ", newKeymat.m_hostEK);
	LOGGER_DEBUG("Host IK: ", newKeymat.m_hostIK);
	LOGGER_DEBUG("Peer EK: ", newKeymat.m_peerEK);
	LOGGER_DEBUG("Peer IK: ", newKeymat.m_peerIK);

	if (!context->m_packet->VerifyCmac(*newCipher,
		newKeymat.m_peerIK))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect MAC value in I2 packet.");

	param = context->m_packet->
		GetParameter(HDX_TYPE_ENCRYPTED_KEY);

	if (!param->Decrypt(*newCipher,
		newKeymat.m_peerEK, sharedKey))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Decrypting encrypted key failed (I2).");

	LOGGER_DEBUG("Encrypted key: ", sharedKey);

	std::size_t blockSize = newCipher->BlockSize();

	if (sharedKey.size() != m_puzzle->m_randomI.size() + blockSize)
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Invalid encrypted key size in I2 packet.");

	if (!std::equal(sharedKey.begin()
		+ blockSize, sharedKey.end(),
		m_puzzle->m_randomI.begin()))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Invalid encrypted key data in I2 packet.");

	m_solutionJ = solutionJ;
	m_cipherSuite = newCipherSuite;
	m_cipher = std::move(newCipher);

	m_hostEK = newKeymat.m_hostEK;
	m_hostIK = newKeymat.m_hostIK;
	m_peerEK = newKeymat.m_peerEK;
	m_peerIK = newKeymat.m_peerIK;

	m_peerSecret.assign(sharedKey.begin(),
		sharedKey.begin() + blockSize);

	if (m_hostSecret.empty() ||
		m_hostSecret.size() != blockSize)
	{
		m_hostSecret.resize(blockSize);
		HipCipher::RandBytes(m_hostSecret);
	}

	LOGGER_DEBUG("Peer secret: ", m_peerSecret);
	LOGGER_DEBUG("Host secret: ", m_hostSecret);

	SendR2(context);

	ByteBlock masterSecret;
	masterSecret.reserve(m_peerSecret.size()
		+ m_hostSecret.size());
	masterSecret.insert(masterSecret.end(),
		m_peerSecret.begin(), m_peerSecret.end());
	masterSecret.insert(masterSecret.end(),
		m_hostSecret.begin(), m_hostSecret.end());

	LOGGER_DEBUG("Master secret: ", masterSecret);

	m_pairwiseKeySa = std::make_shared<HipKeymat>();

	m_pairwiseKeySa->Calculate(m_cipher.get(), m_puzzle->m_randomI,
		context->m_id->Hit(), m_peerHit, masterSecret);
	m_pairwiseKeySa->m_cipher = m_cipher;

	LOGGER_DEBUG("Host EK (pairwise): ", m_pairwiseKeySa->m_hostEK);
	LOGGER_DEBUG("Host IK (pairwise): ", m_pairwiseKeySa->m_hostIK);
	LOGGER_DEBUG("Peer EK (pairwise): ", m_pairwiseKeySa->m_peerEK);
	LOGGER_DEBUG("Peer IK (pairwise): ", m_pairwiseKeySa->m_peerIK);

	m_handler->HipOpenConnection(context);
}

void HipConnection::HandleR1(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING R1 **");

	HipParameter* param =
		context->m_packet->GetParameter(HDX_TYPE_HIP_CIPHER);

	if (!param->SelectCipher(m_cipherSuite,
		context->m_config->m_cipherSuites))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Could not select cipher suite (R1).");

	m_cipher.reset(new HipCipher(m_cipherSuite));
	m_puzzle.reset(new HipPuzzle);

	param = context->m_packet->GetParameter(HDX_TYPE_PUZZLE);

	if (!param->SolvePuzzle(*m_cipher, context->m_id->Hit(),
			m_peerHit, *m_puzzle, m_solutionJ))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Solving puzzle failed (R1).");

	param = context->m_packet->GetParameter(HDX_TYPE_HOST_ID);

	ByteBlock sharedKey;

	if (!param->CalculateEcdh(*context->m_id, sharedKey))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Calculating ECDH key failed (R1).");

	LOGGER_DEBUG("Shared ECDH key: ", sharedKey);

	HipKeymat newKeymat;
	newKeymat.Calculate(m_cipher.get(), m_puzzle->m_randomI,
		context->m_id->Hit(), m_peerHit, sharedKey);

	LOGGER_DEBUG("Host EK: ", newKeymat.m_hostEK);
	LOGGER_DEBUG("Host IK: ", newKeymat.m_hostIK);
	LOGGER_DEBUG("Peer EK: ", newKeymat.m_peerEK);
	LOGGER_DEBUG("Peer IK: ", newKeymat.m_peerIK);

	m_hostEK = newKeymat.m_hostEK;
	m_hostIK = newKeymat.m_hostIK;
	m_peerEK = newKeymat.m_peerEK;
	m_peerIK = newKeymat.m_peerIK;

	std::size_t blockSize = m_cipher->BlockSize();

	if (m_hostSecret.empty() ||
		m_hostSecret.size() != blockSize)
	{
		m_hostSecret.resize(blockSize);
		HipCipher::RandBytes(m_hostSecret);
	}

	LOGGER_DEBUG("Host secret: ", m_hostSecret);

	SendI2(context);
}

void HipConnection::HandleR2(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING R2 **");

	if (!context->m_packet->VerifyCmac(*m_cipher, m_peerIK))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect MAC value in R2 packet.");

	HipParameter* param = context->m_packet->
		GetParameter(HDX_TYPE_DH_GROUP_LIST);

	if (!param->VerifyDhGroup(context->m_id->DhGroup()))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect DH group value in R2 packet.");

	param = context->m_packet->
		GetParameter(HDX_TYPE_ENCRYPTED_KEY);

	ByteBlock encrKey;

	if (!param->Decrypt(*m_cipher, m_peerEK, encrKey))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Decrypting encrypted key failed (R2).");

	LOGGER_DEBUG("Encrypted key: ", encrKey);

	std::size_t blockSize = m_cipher->BlockSize();

	if (encrKey.size() != m_puzzle->m_randomI.size() + blockSize)
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Invalid encrypted key size in R2 packet.");

	if (!std::equal(encrKey.begin()
		+ blockSize, encrKey.end(),
		m_puzzle->m_randomI.begin()))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Invalid encrypted key data in R2 packet.");

	m_peerSecret.assign(encrKey.begin(),
		encrKey.begin() + blockSize);

	LOGGER_DEBUG("Peer secret: ", m_peerSecret);

	ByteBlock masterSecret;
	masterSecret.reserve(m_hostSecret.size()
		+ m_peerSecret.size());
	masterSecret.insert(masterSecret.end(),
		m_hostSecret.begin(), m_hostSecret.end());
	masterSecret.insert(masterSecret.end(),
		m_peerSecret.begin(), m_peerSecret.end());

	LOGGER_DEBUG("Master secret: ", masterSecret);

	m_pairwiseKeySa = std::make_shared<HipKeymat>();

	m_pairwiseKeySa->Calculate(m_cipher.get(), m_puzzle->m_randomI,
		context->m_id->Hit(), m_peerHit, masterSecret);
	m_pairwiseKeySa->m_cipher = m_cipher;

	LOGGER_DEBUG("Host EK (pairwise): ", m_pairwiseKeySa->m_hostEK);
	LOGGER_DEBUG("Host IK (pairwise): ", m_pairwiseKeySa->m_hostIK);
	LOGGER_DEBUG("Peer EK (pairwise): ", m_pairwiseKeySa->m_peerEK);
	LOGGER_DEBUG("Peer IK (pairwise): ", m_pairwiseKeySa->m_peerIK);

	m_handler->HipOpenConnection(context);
}

void HipConnection::HandleUpdate(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING UPDATE **");

	if (!context->m_packet->VerifyCmac(*m_cipher, m_peerIK))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect MAC value in UPDATE packet.");

	if (context->m_packet->HasParameter(HDX_TYPE_ACK))
	{
		LOGGER_DEBUG("Found ACK parameter...");

		HipParameter* param = context->m_packet->
			GetParameter(HDX_TYPE_ACK);

		if (!param->Update(m_seq))
			throw Exception(Exception::Error,
				HIP_CONNECTION_EXCEPTION_STR \
				"Could not handle ACK parameter.");
	}
	else if (context->m_packet->HasParameter(HDX_TYPE_SEQ))
	{
		LOGGER_DEBUG("Found SEQ parameter...");

		HipParameter* param = context->m_packet->
			GetParameter(HDX_TYPE_SEQ);

		if (!param->Update(m_ack))
			throw Exception(Exception::Error,
				HIP_CONNECTION_EXCEPTION_STR \
				"Could not handle SEQ parameter.");

		SendUpdateAck(context);
	}
	else throw Exception(Exception::Error,
		HIP_CONNECTION_EXCEPTION_STR \
		"Neither SEQ or ACK found in UPDATE packet.");
}

void HipConnection::HandleClose(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING CLOSE **");

	if (!context->m_packet->VerifyCmac(*m_cipher, m_peerIK))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect MAC value in CLOSE packet.");

	HipParameter* param = context->m_packet->
		GetParameter(HDX_TYPE_ECHO_REQ_SIG);

	if (!param->HandleEcho(m_echo))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Could not handle ECHO REQ parameter.");

	SendCloseAck(context);

	ResetConnection();

	m_handler->HipCloseConnection(context);
}

void HipConnection::HandleCloseAck(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING CLOSE_ACK **");

	if (!context->m_packet->VerifyCmac(*m_cipher, m_peerIK))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Incorrect MAC value in CLOSE_ACK packet.");

	HipParameter* param = context->m_packet->
		GetParameter(HDX_TYPE_ECHO_RES_SIG);

	if (!param->HandleEcho(m_echo))
		throw Exception(Exception::Error,
			HIP_CONNECTION_EXCEPTION_STR \
			"Could not handle ECHO RES parameter.");
}

void HipConnection::HandleTimeout(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING TIMEOUT **");

	m_handler->HipError(HipHandler::HipErrorTimeout, context);
}
