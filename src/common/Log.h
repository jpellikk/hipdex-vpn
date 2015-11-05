/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_LOG_H
#define HIPDEX_VPN_COMMON_LOG_H

#include "Logger.h"
#include "SysLogger.h"
#include "FileLogger.h"
#include "StdoutLogger.h"

#ifdef DEBUG
#define LOGGER_DEBUG Logger::Get()->Log<LogLevel::Debug>
#else
#define LOGGER_DEBUG(...)
#endif

#define LOGGER_INFO Logger::Get()->Log<LogLevel::Info>
#define LOGGER_WARNING Logger::Get()->Log<LogLevel::Warning>
#define LOGGER_ERROR Logger::Get()->Log<LogLevel::Error>

#define LOGGER_SET_LEVEL Logger::Get()->SetLogLevel

#define LOGGER_SYSLOG Logger::Get()->Add<SysLogger>
#define LOGGER_STDOUT Logger::Get()->Add<StdoutLogger>
#define LOGGER_FILE Logger::Get()->Add<FileLogger>

#endif
