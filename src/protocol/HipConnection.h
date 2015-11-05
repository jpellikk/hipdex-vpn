/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_CONNECTION_H
#define HIPDEX_VPN_PROTOCOL_HIP_CONNECTION_H

#include "HipState.h"
#include "HipPacket.h"
#include "HipDefines.h"
#include "HipAttributes.h"
#include "HipKeymat.h"

#include <boost/asio/ip/address.hpp>
#include <memory>

namespace hipdex_vpn
{
	class HipContext;
	class HipHandler;

	typedef std::shared_ptr<HipKeymat> HipKeymatPtr;

	class HipConnection : private HipAttributes
	{
		HDX_ADD_FRIEND_STATE_CLASSES

		public:
			explicit HipConnection(const ByteBlock&, HipHandler*);
			~HipConnection();

			bool operator==(const ByteBlock& hit) const
				{ return m_peerHit == hit; }

			void SetAddress(boost::asio::ip::address& address) {
				m_address = address;
			}
			boost::asio::ip::address GetAddress() {
				return m_address;
			}
			const ByteBlock& GetHit() const {
				return m_peerHit;
			}
			HipKeymatPtr GetPairwiseSa() {
				return m_pairwiseKeySa;
			}

			void HandlePacket(HipContext*);
			void Initiate(HipContext*);
			void Refresh(HipContext*);

		private:
			typedef std::unique_ptr<HipState> HipStatePtr;

			HipConnection(const HipConnection&);
			HipConnection& operator=(const HipConnection&);

			void ResetConnection();
			void SetState(HipState*);

			void SendClose(HipContext*);
			void SendCloseAck(HipContext*);
			void SendUpdateSeq(HipContext*);
			void SendUpdateAck(HipContext*);
			void SendI1(HipContext*);
			void SendI2(HipContext*);
			void SendR1(HipContext*);
			void SendR2(HipContext*);

			void HandleShutdown(HipContext*);
			void HandleUpdate(HipContext*);
			void HandleTimeout(HipContext*);
			void HandleCloseAck(HipContext*);
			void HandleClose(HipContext*);
			void HandleInit(HipContext*);
			void HandleI1(HipContext*);
			void HandleI2(HipContext*);
			void HandleR1(HipContext*);
			void HandleR2(HipContext*);

			HipStatePtr m_state;
			HipHandler* m_handler;

			boost::asio::ip::address m_address;
	};
}

#endif
