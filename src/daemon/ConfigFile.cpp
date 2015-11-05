/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "ConfigFile.h"
#include "Exception.h"
#include "Defines.h"
#include "Types.h"
#include "HipIdentity.h"
#include "HipDefines.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#define CONFIG_FILE_EXCEPTION_STR \
	"Reading configuration file failed: "

using namespace hipdex_vpn;

ConfigFile::ConfigFile() : HipConfig()
{
	json::json_error_t error;

	boost::filesystem::path path(PACKAGE_CONFDIR);
	boost::filesystem::path file(HDX_CONFIG_FILE);

	const json::Value root = json::load_file(
		(path/=file).string().c_str(), &error);

	if (root.is_undefined())
		throw Exception(Exception::Abort,
			CONFIG_FILE_EXCEPTION_STR
			+ std::string(error.text));

	if (!root.is_object())
		throw Exception(Exception::Abort,
			CONFIG_FILE_EXCEPTION_STR \
			"Invalid file format.");

	LoadString(root, m_hostname,
		"hostname", HDX_DEFAULT_HOSTNAME);

	LoadInteger(root, m_signalPort,
		"signal-port", HDX_UDP_SIGNAL_PORT);

	LoadInteger(root, m_userPort,
		"user-port", HDX_UDP_USER_PORT);

	uint32_t puzzlecomp;
	LoadInteger(root, puzzlecomp,
		"puzzle-complexity",
		HDX_DEFAULT_PUZZLE_COMPLEXITY);
	m_puzzleComplexity = puzzlecomp;

	LoadHosts(root, m_hosts, "hosts");
}

ConfigFile::~ConfigFile()
{
}

void ConfigFile::LoadString(const json::Value& root, std::string& target,
	const char* key, const char* defaultValue)
{
	json::Value value = root[key];

	if ((!value.is_undefined() && !value.is_string()))
		throw Exception(Exception::Abort, CONFIG_FILE_EXCEPTION_STR \
			"Key '" + std::string(key) + "' is not string.");

	target = value.is_undefined() ? defaultValue : value.as_string();
}

void ConfigFile::LoadInteger(const json::Value& root, uint32_t& target,
	const char* key, int defaultValue)
{
	json::Value value = root[key];

	if ((!value.is_undefined() && !value.is_integer()))
		throw Exception(Exception::Abort, CONFIG_FILE_EXCEPTION_STR \
			"Key '" + std::string(key) + "' is not integer.");

	target = value.is_undefined() ? defaultValue : value.as_integer();
}

void ConfigFile::LoadHosts(const json::Value& root, HostList& target, const char* key)
{
	json::Value value = root[key];

	if (value.is_undefined())
		return;

	if ((!value.is_array()))
		throw Exception(Exception::Abort, CONFIG_FILE_EXCEPTION_STR \
			"Key '" + std::string(key) + "' is not array.");

	for (unsigned int i = 0; i < value.size(); ++i) {
		json::Value obj(value.at(i).as_json());
		if (obj.is_undefined() || !obj.is_object())
			continue;
		HostList::ValuePtr host = HostList::MakePtr();
		std::string str;
		LoadString(obj, str, "hit", "");
		HipIdentity::FromStrToHit(str, host->m_hit);
		LoadString(obj, str, "lsi", "");
		HipIdentity::FromStrToLsi(str, host->m_lsi);
		LoadString(obj, str, "ip", "");
		host->m_ip = boost::asio::ip::address::from_string(str);
		target.Add(host);
	}
}
