/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_STDOUT_LOGGER_H
#define HIPDEX_VPN_COMMON_STDOUT_LOGGER_H

#include "Logger.h"
#include <cstdio>
#include <ctime>

namespace hipdex_vpn
{
	struct StdoutLogger : public ILogger
	{
		void Log(LogLevel::Type, const std::string& str) {
			char date[22] = {0};
			time_t t = time(0);
			strftime(date, sizeof(date),
				"[%Y-%m-%d %H:%M:%S]", gmtime(&t));
			fprintf(stdout, "%s %s\n", date, str.c_str());
		}
	};
}

#endif
