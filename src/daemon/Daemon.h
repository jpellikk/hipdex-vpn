/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_DAEMON_H
#define HIPDEX_VPN_DAEMON_H

#include "ConfigFile.h"
#include "IoService.h"
#include "Exception.h"
#include "Defines.h"
#include "HipServer.h"
#include "TunServer.h"
#include "Types.h"

namespace hipdex_vpn
{
	typedef std::unique_ptr<HipServer> HipServerPtr;
	typedef std::unique_ptr<TunServer> TunServerPtr;
	typedef std::shared_ptr<HipIdentity> HipIdentityPtr;

	class Daemon
	{
		public:
			explicit Daemon(const TUserOptions&);
			void Run();
			~Daemon();

			HipIdentityPtr m_identity;
			const TUserOptions& m_options;
			ConfigFile m_config;
			IoService m_service;
			HipServerPtr m_hipServer;
			TunServerPtr m_tunServer;

		private:
			Daemon& operator=(const Daemon&);
			Daemon(const Daemon&);
	};
}

#endif
