/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipConfig.h"
#include "HipDefines.h"

using namespace hipdex_vpn;

HipConfig::HipConfig()
	: m_hitSuites(HDX_AVAIL_HIT_SUITES),
	  m_cipherSuites(HDX_AVAIL_CIPHER_SUITES),
	  m_dhGroups(HDX_AVAIL_DH_GROUPS),
	  m_puzzleComplexity(HDX_DEFAULT_PUZZLE_COMPLEXITY),
	  m_puzzleLifetime(HDX_DEFAULT_PUZZLE_LIFETIME),
	  m_hostname(HDX_DEFAULT_HOSTNAME)
{
}

HipConfig::~HipConfig()
{
}
