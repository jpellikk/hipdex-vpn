/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "Daemon.h"
#include "HipServer.h"
#include "TunServer.h"
#include "Logger.h"
#include "Defines.h"
#include "HipIdentity.h"

#include <boost/filesystem.hpp>

using namespace hipdex_vpn;

Daemon::Daemon(const TUserOptions& options)
	: m_identity(nullptr),
	  m_options(options),
	  m_config(),
	  m_service(HDX_NUM_THREADS),
	  m_hipServer(nullptr),
	  m_tunServer(nullptr)
{
	m_identity.reset(new HipIdentity((
		boost::filesystem::path(PACKAGE_CONFDIR)
			/= HDX_IDENTITY_FILE).string()));
	m_hipServer.reset(new HipServer(this));
	m_tunServer.reset(new TunServer(this));
}

Daemon::~Daemon()
{
}

void Daemon::Run()
{
	m_service.Run();
}
