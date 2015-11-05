/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "HipEcKey.h"
#include "HipDefines.h"
#include "Exception.h"

#include <cstdio>
#include <cstring>
#include <cerrno>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#define HIP_EC_KEY_EXCEPTION_STR \
	"Handling EC key failed: "

using namespace hipdex_vpn;

HipEcKey::HipEcKey(const std::string& privKeyFile)
	: m_key(nullptr), m_dhGroup(0)
{
	FILE* fp = fopen(privKeyFile.c_str(), "r");

	if (!fp)
		throw Exception(Exception::Abort,
		"Creating EC key from file failed: "
		+ std::string(strerror(errno))+'.');

	EVP_PKEY* key =
		PEM_read_PrivateKey(fp, 0, 0, 0);

	fclose(fp);

	if (!key || key->type != EVP_PKEY_EC)
		throw Exception(Exception::Abort,
		"Creating EC key from file failed: " \
		"Unable to load key information.");

	m_key = EVP_PKEY_get1_EC_KEY(key);
	EVP_PKEY_free(key);

	try {
		m_dhGroup = CreateDhGroup(CurveName());
	} catch (Exception& e) {
		if (m_key)
			EC_KEY_free(m_key);
		m_key = nullptr;
		throw;
	}
}

HipEcKey::HipEcKey(const ByteBlock& hostId)
	: m_key(nullptr), m_dhGroup(0)
{
	if (hostId.size() < 2)
		throw Exception(Exception::Abort,
			HIP_EC_KEY_EXCEPTION_STR \
			"Invalid host ID bytes.");

	m_key = EC_KEY_new_by_curve_name(
		CreateCurveName(hostId[1]));

	const ByteBlock::value_type
		*data = hostId.data() + 2;

	if (!o2i_ECPublicKey(&m_key, &data,
		hostId.size()-2))
	{
		EC_KEY_free(m_key);
		m_key = nullptr;

		throw Exception(Exception::Abort,
			HIP_EC_KEY_EXCEPTION_STR \
			"Unable to create key from bytes.");
	}

	try {
		m_dhGroup = CreateDhGroup(CurveName());
	} catch (Exception& e) {
		if (m_key)
			EC_KEY_free(m_key);
		m_key = nullptr;
		throw;
	}
}

HipEcKey::~HipEcKey()
{
	if (m_key)
		EC_KEY_free(m_key);
}

uint32_t HipEcKey::CurveName() const
{
	return EC_GROUP_get_curve_name
		(EC_KEY_get0_group(m_key));
}

void HipEcKey::PublicKey(ByteBlock& publicKey) const
{
	publicKey.resize(i2o_ECPublicKey(m_key, nullptr));
	ByteBlock::value_type *data = publicKey.data();
	i2o_ECPublicKey(m_key, &data);
}

void HipEcKey::Derive(const HipEcKey& peerKey, ByteBlock& secret) const
{
	if (m_dhGroup != peerKey.m_dhGroup)
		throw Exception(Exception::Error,
			HIP_EC_KEY_EXCEPTION_STR \
			"DH group mismatch in derivation.");

	ByteBlockSize fieldSize =
		EC_GROUP_get_degree(EC_KEY_get0_group(m_key));

	secret.resize((fieldSize+7)>>3);

	if (ECDH_compute_key(secret.data(), secret.size(),
		EC_KEY_get0_public_key(peerKey.m_key), m_key, nullptr) < 1)
		throw Exception(Exception::Error,
			HIP_EC_KEY_EXCEPTION_STR \
			"Derivation of shared secret failed.");
}

uint8_t HipEcKey::CreateDhGroup(uint32_t curveName)
{
	if (curveName == NID_secp192k1)
		return HDX_DH_GRP_SECP192K1;
	else throw Exception(Exception::Error,
		HIP_EC_KEY_EXCEPTION_STR \
		"Unsupported elliptic curve.");
	return 0;
}

uint32_t HipEcKey::CreateCurveName(uint8_t dhGroup)
{
	if (dhGroup == HDX_DH_GRP_SECP192K1)
		return NID_secp192k1;
	else throw Exception(Exception::Error,
		HIP_EC_KEY_EXCEPTION_STR \
		"Unsupported DH group.");
	return 0;
}
