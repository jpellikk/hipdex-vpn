/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_TUN_CONNECTION_H
#define HIPDEX_VPN_TUN_CONNECTION_H

#include "Types.h"
#include "HipIdentity.h"
#include "HipConnection.h"

#include <boost/asio/ip/address.hpp>

namespace hipdex_vpn
{
	struct TunConnection
	{
		typedef boost::asio::ip::address Address;
		explicit TunConnection(const ByteBlock& hit,
			const ByteBlock& lsi = ByteBlock())
			: m_state(StatePending),
			  m_hit(hit),
			  m_lsi(lsi),
			  m_ip(),
			  m_sa(nullptr),
			  m_transmitting(false) {
			if (m_lsi.empty())
				HipIdentity::FromHitToLsi(m_hit, m_lsi);
		}
		~TunConnection() {}
		enum State {
			StatePending = 1,
			StateEstablished = 2
		};
		bool operator==(const ByteBlock& a) const {
			return m_hit == a || m_lsi == a;
		}
		State m_state;
		ByteBlock m_hit;
		ByteBlock m_lsi;
		Address m_ip;
		HipKeymatPtr m_sa;
		bool m_transmitting;
	};
}

#endif
