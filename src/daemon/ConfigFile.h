/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_DAEMON_CONFIG_FILE_H
#define HIPDEX_VPN_DAEMON_CONFIG_FILE_H

#include "Types.h"
#include "ListContainer.h"
#include "HipConfig.h"
#include "Jansson.h"

#include <boost/asio/ip/address.hpp>

namespace hipdex_vpn
{
	struct Host
	{
		typedef boost::asio::ip::address Address;
		bool operator==(const ByteBlock& a) const {
			return m_hit == a || m_lsi == a;
		}
		ByteBlock m_hit;
		ByteBlock m_lsi;
		Address m_ip;
	};

	class ConfigFile : public HipConfig
	{
		public:
			ConfigFile();
			~ConfigFile();

			uint32_t m_userPort;
			uint32_t m_signalPort;

			typedef ListContainer<Host, ByteBlock> HostList;
			HostList m_hosts;

		private:
			ConfigFile& operator=(const ConfigFile&);
			ConfigFile(const ConfigFile&);

			void LoadInteger(const json::Value&, uint32_t&, const char*, int);
			void LoadString(const json::Value&, std::string&,
				const char*, const char*);
			void LoadHosts(const json::Value&, HostList&, const char*);
	};
}

#endif
