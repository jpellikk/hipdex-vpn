/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_SAFE_SINGELTON_H
#define HIPDEX_VPN_COMMON_SAFE_SINGELTON_H

#include <mutex>
#include <atomic>
#include <memory>

namespace hipdex_vpn
{
	template <typename T> class SafeSingleton
	{
		public:
			static T* Get()
			{
				T* ptr = m_instance.load(std::memory_order_consume);
				if (!ptr)
				{
					std::lock_guard<std::mutex> lock(m_mutex);
					ptr = m_instance.load(std::memory_order_consume);
					if (!ptr)
					{
						m_ptr.reset(ptr = new T);
						m_instance.store(ptr, std::memory_order_release);
					}
				}
				return ptr;
			}

		protected:
			SafeSingleton() {}
			virtual ~SafeSingleton() {}

		private:
			static std::unique_ptr<T> m_ptr;
			static std::atomic<T*> m_instance;
			static std::mutex m_mutex;
	};

	template <typename T> std::unique_ptr<T> SafeSingleton<T>::m_ptr;
	template <typename T> std::atomic<T*> SafeSingleton<T>::m_instance;
	template <typename T> std::mutex SafeSingleton<T>::m_mutex;
}

#endif
