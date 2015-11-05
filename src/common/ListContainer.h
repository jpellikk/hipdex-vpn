/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_COMMON_LIST_CONTAINER_H
#define HIPDEX_VPN_COMMON_LIST_CONTAINER_H

#include <algorithm>
#include <memory>
#include <list>

namespace hipdex_vpn
{
	template <class T, class U> class ListContainer
	{
		public:
			typedef T ValueType;
			typedef U SearchKeyType;
			typedef std::shared_ptr<T> ValuePtr;
			typedef std::list<ValuePtr> ListType;
			static ValuePtr MakePtr() {
				return std::make_shared<T>();
			}
			template<typename A>
			static ValuePtr MakePtr(const A& a) {
				return std::make_shared<T>(a);
			}
			template<typename A, typename B>
			static ValuePtr MakePtr(const A& a, const B& b) {
				return std::make_shared<T>(a, b);
			}
			const ListType& operator*() const {
				return m_list;
			}
			ListType& operator*() {
				return m_list;
			}
			ValuePtr Find(const U& a) const {
				auto iter = std::find_if(m_list.begin(),
					m_list.end(), [&a](const ValuePtr& b) {
						return *b == a; });
				if (iter != m_list.end())
					return *iter;
				return ValuePtr(nullptr);
			}
			void Add(const ValuePtr& value) {
				m_list.push_back(value);
			}
			void Remove(const U& a) {
				m_list.erase(std::remove_if(m_list.begin(),
					m_list.end(), [&a](const ValuePtr& b) {
						return *b == a; }), m_list.end());
			}
		private:
			ListType m_list;
	};
}

#endif
