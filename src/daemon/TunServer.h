/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_TUN_SERVER_H
#define HIPDEX_VPN_TUN_SERVER_H

#include "Types.h"
#include "Exception.h"
#include "TunDevice.h"
#include "TunConnection.h"
#include "ListContainer.h"

#include <boost/asio.hpp>

namespace hipdex_vpn
{
	class Daemon;
	class HipConnection;

	typedef std::shared_ptr<HipConnection> HipConnectionPtr;
	typedef std::shared_ptr<TunConnection> ConnectionPtr;

	class TunServer
	{
		public:
			explicit TunServer(Daemon*);
			~TunServer();

			void AllowConnection(HipConnectionPtr);
			void RemoveConnection(HipConnectionPtr);

		private:
			void StartTunReceive();
			void StartUdpReceive();
			void HandleTunReceive(const boost::system::error_code&, std::size_t);
			void HandleUdpReceive(const boost::system::error_code&, std::size_t);
			void HandleTunSend(const boost::system::error_code&, std::size_t);
			void HandleRemoveConnection(HipConnectionPtr);
			void HandleAllowConnection(HipConnectionPtr);
			void HandleArpPacket(std::size_t);
			void HandleIPv6Packet(std::size_t);
			void HandleIPv4Packet(std::size_t);

			TunServer(const TunServer&);
			TunServer& operator=(const TunServer&);

			typedef ListContainer<TunConnection, ByteBlock> ConnectionList;
			ConnectionList m_connections;

			Daemon* m_daemon;
			TunDevice m_device;
			ByteBlock m_buffer;

			boost::asio::io_service::strand m_strand;
			boost::asio::posix::stream_descriptor m_stream;
			boost::asio::ip::udp::socket m_socket;
			boost::asio::ip::udp::endpoint m_endpoint;
	};
}

#endif
