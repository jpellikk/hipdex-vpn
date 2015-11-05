/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "TunServer.h"
#include "Daemon.h"
#include "Defines.h"
#include "HipServer.h"
#include "EthHeader.h"
#include "ArpHeader.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "HipConnection.h"
#include "HipIdentity.h"
#include "TunEncrypted.h"

#include <boost/bind.hpp>

using namespace hipdex_vpn;

TunServer::TunServer(Daemon* daemon)
	: m_daemon(daemon), m_device(daemon),
	  m_buffer(HDX_LEN_TUN_BUFFER),
	  m_strand(daemon->m_service.m_service),
	  m_stream(daemon->m_service.m_service),
	  m_socket(daemon->m_service.m_service,
		boost::asio::ip::udp::endpoint(
		boost::asio::ip::udp::v6(),
		daemon->m_config.m_userPort)),
	  m_endpoint()
{
	m_stream.assign(m_device.m_fd);

	StartUdpReceive();
	StartTunReceive();
}

TunServer::~TunServer()
{
}

void TunServer::StartTunReceive()
{
	m_stream.async_read_some(boost::asio::buffer(m_buffer),
		m_strand.wrap(boost::bind(&TunServer::HandleTunReceive,
		this, boost::asio::placeholders::error,
		boost::asio::placeholders::bytes_transferred)));
}

void TunServer::StartUdpReceive()
{
	m_socket.async_receive_from(
		boost::asio::buffer(m_buffer), m_endpoint, m_strand.wrap(
			boost::bind(&TunServer::HandleUdpReceive,
			this, boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred)));
}

void TunServer::HandleTunReceive(const boost::system::error_code& error, std::size_t bytes)
{
	if (!error || error == boost::asio::error::message_size)
	{
		try
		{
			uint16_t type = EthHeader::PeekType(m_buffer);

			switch (type)
			{
				case EthHeader::PacketIPV6:
					HandleIPv6Packet(bytes);
					break;
				case EthHeader::PacketIPV4:
					HandleIPv4Packet(bytes);
					break;
				case EthHeader::PacketARP:
					HandleArpPacket(bytes);
					break;
				default:
					break;
			}
		}
		catch(Exception& e)
		{
			LOGGER_WARNING(e.GetWhat());
		}

		StartTunReceive();
	}
}

void TunServer::HandleUdpReceive(const boost::system::error_code& error, std::size_t bytes)
{
	if (!error || error == boost::asio::error::message_size)
	{
		LOGGER_DEBUG("** HANDLING UDP TUNNEL PACKET **");

		ByteBlock buffer(m_buffer.begin(),
			m_buffer.begin() + bytes);

		LOGGER_DEBUG("Received bytes: ", buffer);

		TunEncrypted packet;
		packet.SetHit(buffer);

		LOGGER_DEBUG("HIT value in TUN_ENCRYPTED packet: ",
			HipIdentity::FromHitToStr(packet.m_hit));

		auto conn = m_connections.Find(packet.m_hit);

		if (conn && conn->m_state == TunConnection::StateEstablished) {
			LOGGER_DEBUG("Found established TUN connection!");
			packet.SetBytes(buffer, *conn->m_sa->m_cipher);
			if (!packet.VerifyIcv(*conn->m_sa->m_cipher,
					conn->m_sa->m_peerIK)) {
				LOGGER_DEBUG("Invalid TUN packet (ICV).");
				StartUdpReceive();
				return;
			}
			ByteBlock plainBytes;
			if (!packet.Decrypt(*conn->m_sa->m_cipher,
					conn->m_sa->m_peerEK, plainBytes)) {
				LOGGER_DEBUG("Invalid TUN packet (decrypt).");
				StartUdpReceive();
				return;
			}
			async_write(m_stream, boost::asio::buffer(plainBytes),
				m_strand.wrap(boost::bind(&TunServer::HandleTunSend,
				this, boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred)));
			if (!conn->m_transmitting) {
				m_daemon->m_hipServer->NewConnection(conn);
				conn->m_transmitting = true;
			}
		}

		StartUdpReceive();
	}
}

void TunServer::HandleTunSend(const boost::system::error_code&, std::size_t)
{
}

void TunServer::HandleIPv6Packet(std::size_t bytes)
{
	LOGGER_DEBUG("** HANDLING IPv6 PACKET **");

	ByteBlockReader reader(m_buffer);

	EthHeader ethHeader;
	ethHeader.FromBytes(reader);

	LOGGER_DEBUG("Ethernet header: ", ethHeader);

	IPv6Header ipv6Header;
	ipv6Header.FromBytes(reader);

	LOGGER_DEBUG("IPv6 (pseudo) header: ", ipv6Header);

	if (ipv6Header.m_destAddr == m_daemon->m_identity->Hit() ||
		ipv6Header.m_srcAddr != m_daemon->m_identity->Hit() ||
		ipv6Header.m_targetAddr == m_daemon->m_identity->Hit())
		return;

	auto conn = ipv6Header.m_isNS ?
		m_connections.Find(ipv6Header.m_targetAddr) :
		m_connections.Find(ipv6Header.m_destAddr);

	if (!conn && ipv6Header.m_isNS)
	{
		auto host = m_daemon->m_config.m_hosts.Find(ipv6Header.m_targetAddr);

		if (!host)
			throw Exception(Exception::Warning,
				"Could not find configuration entry for host "
					+ HipIdentity::FromHitToStr(ipv6Header.m_targetAddr));

		conn = ConnectionList::MakePtr(host->m_hit, host->m_lsi);
		conn->m_ip = host->m_ip;
		m_connections.Add(conn);

		LOGGER_DEBUG("Created a NEW TUN connection with ",
			HipIdentity::FromLsiToStr(conn->m_lsi), " (HIT: ",
			HipIdentity::FromHitToStr(conn->m_hit), ") at ",
			conn->m_ip);

		m_daemon->m_hipServer->NewConnection(conn);
		return;
	}

	if (conn && conn->m_state == TunConnection::StateEstablished) {
		LOGGER_DEBUG("Found established connection with ",
			HipIdentity::FromLsiToStr(conn->m_lsi), " (HIT: ",
			HipIdentity::FromHitToStr(conn->m_hit), ")");
		LOGGER_DEBUG("Forwarding the IPv6 packet to ", conn->m_ip);
		ByteBlock packetBytes, encrBytes(m_buffer.begin(), m_buffer.begin() + bytes);
		TunEncrypted packet(m_daemon->m_identity->Hit(), ByteBlock(8));
		packet.Encrypt(*conn->m_sa->m_cipher, conn->m_sa->m_hostEK, encrBytes);
		LOGGER_DEBUG("IPv6 bytes to be encrypted: ", encrBytes);
		packet.CreateIcv(*conn->m_sa->m_cipher, conn->m_sa->m_hostIK);
		packet.GetBytes(packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED (IPv6) bytes: ", packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED bytes length: ", packetBytes.size());
		m_socket.send_to(boost::asio::buffer(packetBytes),
			boost::asio::ip::udp::endpoint(conn->m_ip,
			m_daemon->m_config.m_userPort));
		if (!conn->m_transmitting) {
			m_daemon->m_hipServer->NewConnection(conn);
			conn->m_transmitting = true;
		}
	}
}

void TunServer::HandleIPv4Packet(std::size_t bytes)
{
	LOGGER_DEBUG("** HANDLING IPv4 PACKET **");

	ByteBlockReader reader(m_buffer);

	EthHeader ethHeader;
	ethHeader.FromBytes(reader);

	LOGGER_DEBUG("Ethernet header: ", ethHeader);

	IPv4Header ipv4Header;
	ipv4Header.FromBytes(reader);

	LOGGER_DEBUG("IPv4 (pseudo) header: ", ipv4Header);

	if (ipv4Header.m_destAddr == m_daemon->m_identity->Lsi()
		|| ipv4Header.m_srcAddr != m_daemon->m_identity->Lsi())
		return;

	auto conn = m_connections.Find(ipv4Header.m_destAddr);

	if (conn && conn->m_state == TunConnection::StateEstablished) {
		LOGGER_DEBUG("Found established connection with ",
			HipIdentity::FromLsiToStr(conn->m_lsi), " (HIT: ",
			HipIdentity::FromHitToStr(conn->m_hit), ")");
		LOGGER_DEBUG("Forwarding the IPv4 packet to ", conn->m_ip);
		ByteBlock packetBytes, encrBytes(m_buffer.begin(), m_buffer.begin() + bytes);
		LOGGER_DEBUG("IPv4 bytes to be encrypted: ", encrBytes);
		TunEncrypted packet(m_daemon->m_identity->Hit(), ByteBlock(8));
		packet.Encrypt(*conn->m_sa->m_cipher, conn->m_sa->m_hostEK, encrBytes);
		packet.CreateIcv(*conn->m_sa->m_cipher, conn->m_sa->m_hostIK);
		packet.GetBytes(packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED (IPv4) bytes: ", packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED bytes length: ", packetBytes.size());
		m_socket.send_to(boost::asio::buffer(packetBytes),
			boost::asio::ip::udp::endpoint(conn->m_ip,
			m_daemon->m_config.m_userPort));
		if (!conn->m_transmitting) {
			m_daemon->m_hipServer->NewConnection(conn);
			conn->m_transmitting = true;
		}
	}
}

void TunServer::HandleArpPacket(std::size_t bytes)
{
	LOGGER_DEBUG("** HANDLING ARP PACKET **");

	ByteBlockReader reader(m_buffer);

	EthHeader ethHeader;
	ethHeader.FromBytes(reader);

	LOGGER_DEBUG("Ethernet header: ", ethHeader);

	ArpHeader arpHeader;
	arpHeader.FromBytes(reader);

	LOGGER_DEBUG("ARP header: ", arpHeader);

	if (arpHeader.m_tpa == m_daemon->m_identity->Lsi()
		|| arpHeader.m_spa != m_daemon->m_identity->Lsi())
			return;

	auto conn = m_connections.Find(arpHeader.m_tpa);

	if (!conn)
	{
		auto host = m_daemon->m_config.m_hosts.Find(arpHeader.m_tpa);

		if (!host)
			throw Exception(Exception::Warning,
				"Could not find configuration entry for host "
					+ HipIdentity::FromLsiToStr(arpHeader.m_tpa));

		conn = ConnectionList::MakePtr(host->m_hit, host->m_lsi);
		conn->m_ip = host->m_ip;
		m_connections.Add(conn);

		LOGGER_DEBUG("Created a NEW TUN connection with ",
			HipIdentity::FromLsiToStr(conn->m_lsi), " (HIT: ",
			HipIdentity::FromHitToStr(conn->m_hit), ") at ",
			conn->m_ip);

		m_daemon->m_hipServer->NewConnection(conn);
		return;
	}

	if (conn && conn->m_state == TunConnection::StateEstablished) {
		LOGGER_DEBUG("Found established connection with ",
			HipIdentity::FromLsiToStr(conn->m_lsi), " (HIT: ",
			HipIdentity::FromHitToStr(conn->m_hit), ")");
		LOGGER_DEBUG("Forwarding the ARP packet to ", conn->m_ip);
		ByteBlock packetBytes, encrBytes(m_buffer.begin(), m_buffer.begin() + bytes);
		TunEncrypted packet(m_daemon->m_identity->Hit(), ByteBlock(8));
		packet.Encrypt(*conn->m_sa->m_cipher, conn->m_sa->m_hostEK, encrBytes);
		LOGGER_DEBUG("ARP bytes to be encrypted: ", encrBytes);
		packet.CreateIcv(*conn->m_sa->m_cipher, conn->m_sa->m_hostIK);
		packet.GetBytes(packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED (ARP) bytes: ", packetBytes);
		LOGGER_DEBUG("TUN_ENCRYPTED bytes length: ", packetBytes.size());
		m_socket.send_to(boost::asio::buffer(packetBytes),
			boost::asio::ip::udp::endpoint(conn->m_ip,
			m_daemon->m_config.m_userPort));
		if (!conn->m_transmitting) {
			m_daemon->m_hipServer->NewConnection(conn);
			conn->m_transmitting = true;
		}
	}
}

void TunServer::AllowConnection(HipConnectionPtr hipConn)
{
	m_strand.post(boost::bind(&TunServer::
		HandleAllowConnection, this, hipConn));
}

void TunServer::HandleAllowConnection(HipConnectionPtr hipConn)
{
	LOGGER_DEBUG("** ALLOWING CONNECTION **");

	const ByteBlock& hit = hipConn->GetHit();

	auto conn = m_connections.Find(hit);

	if (conn) {
		if (conn->m_state == TunConnection::StatePending) {
			conn->m_state = TunConnection::StateEstablished;
			conn->m_sa = hipConn->GetPairwiseSa();
			LOGGER_DEBUG("Allowed pending connection with ",
				HipIdentity::FromHitToStr(conn->m_hit),
				" (LSI: ", HipIdentity::FromLsiToStr(
				conn->m_lsi), ") at ", conn->m_ip);
		}
	} else {
		conn = ConnectionList::MakePtr(hit);
		conn->m_ip = hipConn->GetAddress();
		conn->m_state = TunConnection::StateEstablished;
		conn->m_sa = hipConn->GetPairwiseSa();
		m_connections.Add(conn);
		LOGGER_DEBUG("Allowed a NEW connection with ",
			HipIdentity::FromHitToStr(conn->m_hit),
			" (LSI: ", HipIdentity::FromLsiToStr(
			conn->m_lsi), ") at ", conn->m_ip);
	}
}

void TunServer::RemoveConnection(HipConnectionPtr hipConn)
{
	m_strand.post(boost::bind(&TunServer::
		HandleRemoveConnection, this, hipConn));
}

void TunServer::HandleRemoveConnection(HipConnectionPtr hipConn)
{
	LOGGER_DEBUG("** REMOVING TUN CONNECTION **");

	const ByteBlock& hit = hipConn->GetHit();

	m_connections.Remove(hit);

	LOGGER_DEBUG("Removed TUN connection (if existed) ",
		HipIdentity::FromHitToStr(hit));
}
