/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_IO_SERVICE_H
#define HIPDEX_VPN_IO_SERVICE_H

#include <boost/asio.hpp>

namespace hipdex_vpn
{
	class IoService
	{
		public:
			explicit IoService(std::size_t);
			virtual ~IoService();

			void Run();

			boost::asio::io_service m_service;

		private:
			IoService& operator=(const IoService&);
			IoService(const IoService&);

			void RunService();
			void StopService();

			boost::asio::signal_set m_signals;
			const std::size_t m_numThreads;
	};
}

#endif
