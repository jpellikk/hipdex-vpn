/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_FILE_LOGGER_H
#define HIPDEX_VPN_COMMON_FILE_LOGGER_H

#include "Logger.h"
#include "Exception.h"

#include <cstdio>
#include <string>
#include <errno.h>
#include <cstring>
#include <ctime>

namespace hipdex_vpn
{
	struct FileLogger : public ILogger
	{
		public:
			explicit FileLogger(const char* file)
				: m_file(fopen(file, "a+")) {
				if (!m_file)
					throw Exception(Exception::Abort,
						"Opening log file failed, reason: "
						+ std::string(strerror(errno)));
			}
			~FileLogger() {
				if (m_file) fclose(m_file);
			}
			void Log(LogLevel::Type, const std::string& str) {
				char date[22] = {0};
				time_t t = time(0);
				strftime(date, sizeof(date),
					"[%Y-%m-%d %H:%M:%S]", gmtime(&t));
				fprintf(m_file, "%s %s\r\n", date, str.c_str());
				fflush(m_file);
			}
		private:
			FileLogger& operator=(const FileLogger&);
			FileLogger(const FileLogger&);
			FILE* m_file;
	};
}

#endif
