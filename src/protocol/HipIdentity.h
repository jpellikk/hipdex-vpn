/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_IDENTITY_H
#define HIPDEX_VPN_PROTOCOL_HIP_IDENTITY_H

#include "Types.h"
#include "HipEcKey.h"

#include <string>

namespace hipdex_vpn
{
	class HipIdentity
	{
		public:
			explicit HipIdentity(const std::string&);
			explicit HipIdentity(const ByteBlock&);
			void ToHostId(ByteBlock&) const;
			uint8_t DhGroup() const { return m_key.DhGroup(); }
			void Derive(const HipIdentity&, ByteBlock&) const;
			const ByteBlock& Hit() const { return m_hit; }
			const ByteBlock& Lsi() const { return m_lsi; }
			bool operator==(const HipIdentity& a) const
				{ return m_hit == a.m_hit; }
			bool operator==(const ByteBlock& a) const
				{ return m_hit == a; }
			static void FromHitToLsi(const ByteBlock&,
				ByteBlock&);
			static void FromStrToHit(const std::string&,
				ByteBlock&);
			static void FromStrToLsi(const std::string&,
				ByteBlock&);
			static std::string FromLsiToStr(const ByteBlock&);
			static std::string FromHitToStr(const ByteBlock&);

			std::string HitStr() const;
			std::string LsiStr() const;
			~HipIdentity();

		private:
			void CreateHitLsi(ByteBlock&, ByteBlock&) const;
			HipIdentity& operator=(const HipIdentity&);
			HipIdentity(const HipIdentity&);

			HipEcKey m_key;
			ByteBlock m_hit;
			ByteBlock m_lsi;
	};
}

#endif
