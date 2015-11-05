/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_BINARY_READER_H
#define HIPDEX_VPN_COMMON_BINARY_READER_H

#include <inttypes.h>
#include <algorithm>
#include <iostream>
#include <iomanip>

namespace hipdex_vpn
{
	template <typename T> class BinaryReader
	{
		public:
			typedef typename T::value_type value_type;
			typedef typename T::size_type size_type;

			explicit BinaryReader(const T& array, size_type offset = 0)
				: m_array(array), m_pos(offset) {};

			virtual ~BinaryReader() {};

			BinaryReader<T>& operator>>(uint8_t& v) {
				v = m_array[m_pos++];
				return *this;
			}

			BinaryReader<T>& operator>>(uint16_t& v) {
				v = m_array[m_pos++] << 8;
				v |= m_array[m_pos++];
				return *this;
			}

			BinaryReader<T>& operator>>(uint32_t& v) {
				v = m_array[m_pos++] << 24;
				v |= m_array[m_pos++] << 16;
				v |= m_array[m_pos++] << 8;
				v |= m_array[m_pos++];
				return *this;
			}

			template <class U> BinaryReader<T>& operator>>(U& v) {
				std::copy_n(&m_array[m_pos], v.size(), v.begin());
				m_pos += v.size();
				return *this;
			}

			void Peek(uint16_t& v) const {
				v = m_array[m_pos] << 8;
				v |= m_array[m_pos+1];
			}

			size_type BytesAvailable() const {
				return (m_array.size() - m_pos);
			}

			bool IsBytesAvailable() const {
				return m_pos < m_array.size();
			}

			void SkipNextBytes(size_type numBytes) {
				m_pos += numBytes;
			}

		protected:
			const T& m_array;
			size_type m_pos;
	};
}

#endif
