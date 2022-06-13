#pragma once
#include "stdafx.h"

#include <cryptopp/sha.h>
#include <cryptopp/md5.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include "SpookyHash.hpp"

#define FNV1PRIME 0x100000001b3
#define FNV1OFFSETBASIS 0xcbf29ce484222325

using namespace CryptoPP;

enum HASH_TYPE
{
	SHA256,
	SHA512,
	MD5,
	FNV1A,
	SPOOKYHASH
};

template<HASH_TYPE type>
class HashingMoudle
{
public:
	HashingMoudle() = default;
	~HashingMoudle() = default;

	/*
		SHA256 impl
	*/

	template<> std::string<HASH_TYPE::SHA256> HashDigest(const std::string& szData)
	{
		std::string ret;

		BYTE digest[CryptoPP::SHA256::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::SHA256 hash;
		hash.CalculateDigest(digest, (const BYTE*)szData.c_str(), szData.length());

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	template<> std::string<HASH_TYPE::SHA256> HashDigest(const BYTE* pData, DWORD dwDataSize)
	{
		std::string ret;

		BYTE digest[CryptoPP::SHA256::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::SHA256 hash;
		hash.CalculateDigest(digest, (const BYTE*)pData, dwDataSize);

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	/*
		SHA512 impl
	*/

	template<> std::string<HASH_TYPE::SHA512> HashDigest(const std::string& szData)
	{
		std::string ret;

		BYTE digest[CryptoPP::SHA512::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::SHA512 hash;
		hash.CalculateDigest(digest, (const BYTE*)szData.c_str(), szData.length());

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	template<> std::string<HASH_TYPE::SHA512> HashDigest(const BYTE* pData, DWORD dwDataSize)
	{
		std::string ret;

		BYTE digest[CryptoPP::SHA512::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::SHA512 hash;
		hash.CalculateDigest(digest, (const BYTE*)pData, dwDataSize);

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	/*
		MD5 impl
	*/

	template<> std::string<HASH_TYPE::MD5> HashDigest(const std::string& szData)
	{
		std::string ret;

		BYTE digest[CryptoPP::MD5::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::MD5 hash;
		hash.CalculateDigest(digest, (const BYTE*)szData.c_str(), szData.length());

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	template<> std::string<HASH_TYPE::MD5> HashDigest(const BYTE* pData, DWORD dwDataSize)
	{
		std::string ret;

		BYTE digest[CryptoPP::MD5::DIGESTSIZE];
		SecureZeroMemory(digest, sizeof(digest));

		CryptoPP::MD5 hash;
		hash.CalculateDigest(digest, (const BYTE*)pData, dwDataSize);

		CryptoPP::HexEncoder encoder;

		encoder.Attach(new CryptoPP::StringSink(ret));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return ret;
	}

	/*
		FNV1A impl
	*/

	template<> std::string<HASH_TYPE::FNV1A> HashDigest(const std::string& szData)
	{
		std::wostringstream oss;
		ULONGLONG hash = FNV1OFFSETBASIS;

		for (DWORD i = 0; i < dwDataSize; i++)
		{
			hash ^= lpData[i];
			hash *= FNV1PRIME;
		}

		oss.fill(0);
		oss.width(sizeof(ULONGLONG));
		oss << hash;

		return oss.str();
	}

	template<> std::string<HASH_TYPE::FNV1A> HashDigest(const BYTE* pData, DWORD dwDataSize)
	{
		std::wostringstream oss;
		ULONGLONG hash = FNV1OFFSETBASIS;

		for (DWORD i = 0; i < dwDataSize; i++)
		{
			hash ^= lpData[i];
			hash *= FNV1PRIME;
		}

		oss.fill(0);
		oss.width(sizeof(ULONGLONG));
		oss << hash;

		return oss.str();
	}

	/*
		SPOOKYHASH impl
	*/

	template<> std::string<HASH_TYPE::SPOOKYHASH> HashDigest(const std::string& szData)
	{
		std::wostringstream oss;
		ULONGLONG hash = SpookyHash::SpookyDigest((const BYTE*)szData.c_str(), szData.length());

		oss.fill(0);
		oss.width(sizeof(ULONGLONG));
		oss << hash;

		return oss.str();
	}

	template<> std::string<HASH_TYPE::SPOOKYHASH> HashDigest(const BYTE* pData, DWORD dwDataSize)
	{
		std::wostringstream oss;
		ULONGLONG hash = SpookyHash::SpookyDigest(pData, dwDataSize);
		
		oss.fill(0);
		oss.width(sizeof(ULONGLONG));
		oss << hash;

		return oss.str();
	}
};