/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipServer.h"
#include "TunServer.h"
#include "HipContext.h"
#include "Daemon.h"

#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace hipdex_vpn;

HipServer::HipServer(Daemon* daemon)
	: m_daemon(daemon), m_buffer(HDX_LEN_HIP_BUFFER),
	  m_context({nullptr, nullptr, nullptr,
		&daemon->m_config, daemon->m_identity}),
	  m_strand(daemon->m_service.m_service),
	  m_socket(daemon->m_service.m_service,
	  boost::asio::ip::udp::endpoint(
	    boost::asio::ip::udp::v6(),
	    daemon->m_config.m_signalPort)),
	  m_refreshTimer(daemon->m_service.m_service,
		boost::posix_time::seconds(0))
{
	StartTimer();
	StartReceive();
}

HipServer::~HipServer()
{
}

void HipServer::StartTimer()
{
	m_refreshTimer.expires_at(m_refreshTimer.expires_at()
		+ boost::posix_time::seconds(HDX_HIP_REFRESH_INTERVAL));
	m_refreshTimer.async_wait(m_strand.wrap(boost::bind(
		&HipServer::HandleTimer, this,
		boost::asio::placeholders::error)));
}

void HipServer::StartReceive()
{
	m_socket.async_receive_from(
		boost::asio::buffer(m_buffer), m_endpoint,
			m_strand.wrap(boost::bind(&HipServer::HandleReceive,
			this, boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred)));
}

void HipServer::CleanContext()
{
	m_context.m_buffer.reset();
	m_context.m_packet.reset();
	m_context.m_conn.reset();
}

/*************************************/
/**  TIMER AND HIP PACKET HANDLERS  **/
/*************************************/

void HipServer::HandleTimer(const boost::system::error_code& error)
{
	if (!error)
	{
		for (auto& conn : *m_connections)
		{
			m_context.m_conn = conn;

			try {
				conn->Refresh(&m_context);
			} catch (Exception& e) {
				LOGGER_WARNING(e.GetWhat());
			}
		}

		CleanContext();
		StartTimer();
	}
}

void HipServer::HandleReceive(const boost::system::error_code& error, std::size_t numBytes)
{
	if ((!error || error == boost::asio::error::message_size))
	{
		LOGGER_DEBUG("** HANDLING INCOMING HIP PACKET **");

		try
		{
			m_context.m_buffer = std::make_shared<ByteBlock>
				(m_buffer.begin(), m_buffer.begin() + numBytes);

			LOGGER_DEBUG("Received bytes: ", *m_context.m_buffer);

			m_context.m_packet = HipPacketPtr
				(HipPacket::Create(*m_context.m_buffer));
			m_context.m_packet->SetBytes(*m_context.m_buffer);

			ConnectionList::ListContainer::ValuePtr hipConn =
				m_connections.Find(m_context.m_packet->m_senderHit);

			if (!hipConn)
			{
				hipConn = ConnectionList::MakePtr(
					m_context.m_packet->m_senderHit, this);
				boost::asio::ip::address addr = m_endpoint.address();
				hipConn->SetAddress(addr);
				m_connections.Add(hipConn);
			}

			m_context.m_conn = hipConn;
			hipConn->HandlePacket(&m_context);
		}
		catch (Exception& e)
		{
			LOGGER_WARNING(e.GetWhat());
		}

		StartReceive();
	}
}

/*************************************/
/**  PUBLIC INTERFACE AND HANDLERS  **/
/*************************************/

void HipServer::NewConnection(ConnectionPtr conn)
{
	m_strand.post(boost::bind(
		&HipServer::HandleNewConnection,
		this, conn));
}

void HipServer::HandleNewConnection(ConnectionPtr conn)
{
	LOGGER_DEBUG("** INITIATING HIP CONNECTION **");

	ConnectionList::ListContainer::ValuePtr hipConn
		= m_connections.Find(conn->m_hit);

	if (!hipConn)
	{
		hipConn = ConnectionList::MakePtr(conn->m_hit, this);
		hipConn->SetAddress(conn->m_ip);
		m_connections.Add(hipConn);

		LOGGER_DEBUG("Initiating a HIP connection with ",
			HipIdentity::FromHitToStr(conn->m_hit),
			" (LSI: ", HipIdentity::FromLsiToStr(
			conn->m_lsi), ") at ", conn->m_ip);
	}
	else
	{
		LOGGER_DEBUG("Data trigger to a HIP connection with ",
			HipIdentity::FromHitToStr(conn->m_hit),
			" (LSI: ", HipIdentity::FromLsiToStr(
			conn->m_lsi), ") at ", conn->m_ip);
	}

	m_context.m_conn = hipConn;
	hipConn->Initiate(&m_context);
}

void HipServer::RemoveConnection(ConnectionPtr conn)
{
	m_strand.post(boost::bind(
		&HipServer::HandleRemoveConnection,
		this, conn));
}

void HipServer::HandleRemoveConnection(ConnectionPtr conn)
{
	LOGGER_DEBUG("** REMOVING HIP CONNECTION **");

	m_connections.Remove(conn->m_hit);

	LOGGER_DEBUG("Removed HIP connection (if existed) ",
		HipIdentity::FromHitToStr(conn->m_hit));
}

/*******************************/
/**  HIP INTERFACE CALLBACKS  **/
/*******************************/

void HipServer::HipSendPacket(HipPacket* packet, HipContext* context)
{
	LOGGER_DEBUG("** HANDLING HIP SEND PACKET [CALLBACK] **");

	LOGGER_DEBUG("Received SEND PACKET for HIP connection ",
		HipIdentity::FromHitToStr(context->m_conn->GetHit()),
		" at ", context->m_conn->GetAddress());

	try
	{
		ByteBlock bytes;
		packet->GetBytes(bytes);
		m_socket.send_to(boost::asio::buffer(bytes),
			boost::asio::ip::udp::endpoint(
			context->m_conn->GetAddress(),
			m_daemon->m_config.m_signalPort));
	}
	catch (Exception& error)
	{
		LOGGER_DEBUG("Error occurred when sending HIP packet to ",
			HipIdentity::FromHitToStr(context->m_conn->GetHit()),
			" at ", context->m_conn->GetAddress());
		LOGGER_WARNING(error.GetWhat());
	}
}

void HipServer::HipOpenConnection(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING HIP OPEN CONNECTION [CALLBACK] **");

	LOGGER_DEBUG("Received OPEN CONNECTION for HIP connection ",
		HipIdentity::FromHitToStr(context->m_conn->GetHit()),
		" at ", context->m_conn->GetAddress());

	m_daemon->m_tunServer->AllowConnection(context->m_conn);
}

void HipServer::HipCloseConnection(HipContext* context)
{
	LOGGER_DEBUG("** HANDLING HIP CLOSE CONNECTION [CALLBACK] **");

	LOGGER_DEBUG("Received CLOSE CONNECTION for HIP connection ",
		HipIdentity::FromHitToStr(context->m_conn->GetHit()),
		" at ", context->m_conn->GetAddress());

	// Remove only the TUN connection; keep the HIP connection
	m_daemon->m_tunServer->RemoveConnection(context->m_conn);
}

void HipServer::HipError(HipErrorType error, HipContext* context)
{
	LOGGER_DEBUG("** HANDLING HIP ERROR [CALLBACK] **");

	if (error == HipErrorTimeout) {
		LOGGER_DEBUG("Received TIMEOUT for HIP connection ",
			HipIdentity::FromHitToStr(context->m_conn->GetHit()),
			" at ", context->m_conn->GetAddress());
		LOGGER_DEBUG("Removing the HIP connection...");
		m_daemon->m_tunServer->RemoveConnection(context->m_conn);
		RemoveConnection(std::make_shared<TunConnection>
			(context->m_conn->GetHit()));
	}
}
