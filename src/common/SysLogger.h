/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_SYS_LOGGER_H
#define HIPDEX_VPN_COMMON_SYS_LOGGER_H

#include "Logger.h"
#include <syslog.h>

namespace hipdex_vpn
{
	struct SysLogger : public ILogger
	{
		explicit SysLogger(const char* name) {
			openlog(name, LOG_PID|LOG_NDELAY, LOG_DAEMON);
			setlogmask(LOG_UPTO(LOG_DEBUG));
		}
		~SysLogger() {
			closelog();
		}
		void Log(LogLevel::Type level, const std::string& str) {
			syslog((int)level, str.c_str(), nullptr);
		}
	};
}

#endif
