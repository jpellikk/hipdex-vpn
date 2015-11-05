/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_BINARY_WRITER_H
#define HIPDEX_VPN_COMMON_BINARY_WRITER_H

#include <inttypes.h>
#include <algorithm>

namespace hipdex_vpn
{
	template <typename T> class BinaryWriter
	{
		public:
			typedef typename T::value_type value_type;
			typedef typename T::size_type size_type;

			explicit BinaryWriter(T& array, size_type offset = 0)
				: m_array(array), m_pos(offset) {};

			virtual ~BinaryWriter() {};

			BinaryWriter<T>& operator<<(uint8_t v) {
				m_array[m_pos++] = v;
				return *this;
			}

			BinaryWriter<T>& operator<<(uint16_t v) {
				m_array[m_pos++] = (v >> 8) & 0xff;
				m_array[m_pos++] = v & 0xff;
				return *this;
			}

			BinaryWriter<T>& operator<<(uint32_t v) {
				m_array[m_pos++] = (v >> 24) & 0xff;
				m_array[m_pos++] = (v >> 16) & 0xff;
				m_array[m_pos++] = (v >> 8) & 0xff;
				m_array[m_pos++] = v & 0xff;
				return *this;
			}

			template <class U> BinaryWriter<T>& operator<<(const U& v) {
				std::copy_n(v.begin(), v.size(), &m_array[m_pos]);
				m_pos += v.size();
				return *this;
			}

			bool CanWrite(size_type numBytes) {
				return ((m_pos + numBytes) <= m_array.size());
			}

		protected:
			T& m_array;
			size_type m_pos;
	};
}

#endif
