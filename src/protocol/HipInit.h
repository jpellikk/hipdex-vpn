/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#ifndef HIPDEX_VPN_PROTOCOL_HIP_INIT_H
#define HIPDEX_VPN_PROTOCOL_HIP_INIT_H

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace hipdex_vpn
{
	struct HipInit
	{
		explicit HipInit() {
			CRYPTO_malloc_init();
		}
		~HipInit() {
			EVP_cleanup();
			CRYPTO_cleanup_all_ex_data();
		}
	};

	static const HipInit s_init;
}

#endif
