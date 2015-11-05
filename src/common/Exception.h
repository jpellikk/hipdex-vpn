/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_EXCEPTION_H
#define HIPDEX_VPN_COMMON_EXCEPTION_H

#include <string>

namespace hipdex_vpn
{
	class Exception
	{
		public:
			enum ErrorType {
				Warning = 1,
				Error = 2,
				Abort = 3
			};
			Exception(ErrorType type, const std::string& what)
				: m_type(type), m_what(what) {}
			virtual ~Exception() {}
			const char* what() const throw() {
				return m_what.c_str();
			}
			void SetWhat(const std::string& what) {
				m_what = what;
			}
			const std::string& GetWhat() const {
				return m_what;
			}
			void SetErrorType(ErrorType type) {
				m_type = type;
			}
			ErrorType GetErrorType() const {
				return m_type;
			}
		protected:
			ErrorType m_type;
			std::string m_what;
	};
}

#endif
