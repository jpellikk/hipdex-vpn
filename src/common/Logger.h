/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_LOGGER_H
#define HIPDEX_VPN_COMMON_LOGGER_H

#include "SafeSingleton.h"

#include <syslog.h>

#include <sstream>
#include <string>
#include <memory>
#include <mutex>
#include <list>

namespace hipdex_vpn
{
	struct LogLevel
	{
		enum Type {
			Debug = LOG_DEBUG,
			Info = LOG_INFO,
			Warning = LOG_WARNING,
			Error = LOG_ERR
		};
	};

	struct ILogger {
		virtual ~ILogger() {}
		virtual void Log(LogLevel::Type,
			const std::string&) = 0;
	};

	class Logger : public SafeSingleton<Logger>
	{
		public:
			Logger() : m_level(LogLevel::Debug) {}
			template <typename A, typename...B>
			void Add(B&&...args) {
				std::lock_guard<std::mutex> lock(m_mutex);
				m_list.push_back(LoggerPtr(new A(args...)));
			}
			void SetLogLevel(LogLevel::Type level) {
				std::lock_guard<std::mutex> lock(m_mutex);
				m_level = level;
			}
			template<LogLevel::Type A, typename...B>
			void Log(B&&...args) {
				std::lock_guard<std::mutex> lock(m_mutex);
				if (m_level < A)
					return;
				LogImpl(args...);
			}
		private:
			typedef std::unique_ptr<ILogger> LoggerPtr;
			Logger& operator=(const Logger&);
			Logger(const Logger&);
			template <typename A, typename...B>
			void LogImpl(A&& a, B&&...args) {
				m_stream << a;
				LogImpl(args...);
			}
			void LogImpl() {
				for (auto& item : m_list)
					item->Log(m_level, m_stream.str());
				m_stream.str("");
			}
			std::list<LoggerPtr> m_list;
			std::ostringstream m_stream;
			LogLevel::Type m_level;
			std::mutex m_mutex;
	};
}

#endif
