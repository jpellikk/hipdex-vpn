/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_HIP_SERVER_H
#define HIPDEX_VPN_HIP_SERVER_H

#include "Types.h"
#include "TunConnection.h"
#include "ListContainer.h"
#include "HipConnection.h"
#include "HipPacket.h"
#include "HipContext.h"

#include <boost/asio.hpp>

namespace hipdex_vpn
{
	class Daemon;

	typedef std::shared_ptr<HipConnection> HipConnectionPtr;
	typedef std::shared_ptr<TunConnection> ConnectionPtr;

	class HipServer : public HipHandler
	{
		public:
			explicit HipServer(Daemon*);
			~HipServer();

			// Public interface
			void NewConnection(ConnectionPtr);
			void RemoveConnection(ConnectionPtr);

			// HIP callback interface
			void HipSendPacket(HipPacket*, HipContext*);
			void HipError(HipErrorType, HipContext*);
			void HipCloseConnection(HipContext*);
			void HipOpenConnection(HipContext*);

		private:
			HipServer& operator=(const HipServer&);
			HipServer(const HipServer&);

			void StartTimer();
			void StartReceive();
			void CleanContext();
			void HandleReceive(const boost::system::error_code&, std::size_t);
			void HandleNewConnection(ConnectionPtr);
			void HandleRemoveConnection(ConnectionPtr);
			void HandleTimer(const boost::system::error_code&);

			typedef ListContainer<HipConnection, ByteBlock> ConnectionList;
			ConnectionList m_connections;

			Daemon* m_daemon;
			ByteBlock m_buffer;
			HipContext m_context;

			boost::asio::io_service::strand m_strand;
			boost::asio::ip::udp::socket m_socket;
			boost::asio::ip::udp::endpoint m_endpoint;
			boost::asio::deadline_timer m_refreshTimer;
	};
}

#endif
