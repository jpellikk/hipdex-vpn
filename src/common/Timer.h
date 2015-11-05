/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_TIMER_H
#define HIPDEX_VPN_COMMON_TIMER_H

#include <chrono>

namespace hipdex_vpn
{
	template <typename T> class Timer
	{
		public:
			explicit Timer(T deadline, T interval = 0)
				: m_deadline(std::chrono::steady_clock::now() +
					std::chrono::duration<T>(deadline)),
				  m_ticktime(std::chrono::steady_clock::now() +
					std::chrono::duration<T>(interval)),
				  m_interval(interval) {}
			~Timer() {}
			void ResetDeadline(T deadline) {
				m_deadline = std::chrono::steady_clock::now() +
					std::chrono::duration<T>(deadline);
			}
			void ResetInterval(T interval) {
				m_ticktime = std::chrono::steady_clock::now() +
					std::chrono::duration<T>(interval);
				m_interval = interval;
			}
			bool Expired() const {
				return std::chrono::steady_clock::now() > m_deadline;
			}
			bool Tick() {
				if (std::chrono::steady_clock::now() > m_ticktime) {
					m_ticktime += std::chrono::duration<T>(m_interval);
					return true;
				}
				return false;
			}
		private:
			std::chrono::steady_clock::time_point m_deadline;
			std::chrono::steady_clock::time_point m_ticktime;
			T m_interval;
	};
}

#endif
