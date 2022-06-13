#pragma once
#include "stdafx.h"

#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using CryptoPP::Name::Pad;
using CryptoPP::Name::InsertLineBreaks;

enum ENCODING_TYPES
{
	BASE64,
	HEX,
	URL
};

template<ENCODING_TYPES type>
class EncodingModule
{
public:
	EncodingModule() = default;
	~EncodingModule() = default;

	/*
		BASE64 impl
	*/

	template<> std::string<ENCODING_TYPES::BASE64> Encode(const std::string& szData)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		Base64Encoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put((const BYTE*)szData.c_str(), szData.length());
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Encode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		Base64Encoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put(pData, dwDataSize);
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Decode(const std::string& szData)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		Base64Decoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put((const BYTE*)szData.c_str(), szData.length());
		decoder.MessageEnd();

		return decoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Decode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		Base64Decoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put(pData, dwDataSize);
		decoder.MessageEnd();

		return decoded;
	}

	/*
		hex encoding impl
	*/

	template<> std::string<ENCODING_TYPES::HEX> Encode(const std::string& szData)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		HexEncoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put((const BYTE*)szData.c_str(), szData.length());
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::HEX> Encode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		HexEncoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put(pData, dwDataSize);
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::HEX> Decode(const std::string& szData)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		HexDecoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put((const BYTE*)szData.c_str(), szData.length());
		decoder.MessageEnd();

		return decoded;
	}

	template<> std::string<ENCODING_TYPES::HEX> Decode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		HexDecoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put(pData, dwDataSize);
		decoder.MessageEnd();

		return decoded;
	}

	/*
		URL encoding impl
	*/

	template<> std::string<ENCODING_TYPES::BASE64> Encode(const std::string& szData)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		Base64URLEncoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put((const BYTE*)szData.c_str(), szData.length());
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Encode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string encoded;

		// Use Crypto++ base64 encoder

		Base64URLEncoder encoder;
		encoder.Attach(new StringSink(encoded));
		encoder.Put(pData, dwDataSize);
		encoder.MessageEnd();

		return encoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Decode(const std::string& szData)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		Base64URLDecoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put((const BYTE*)szData.c_str(), szData.length());
		decoder.MessageEnd();

		return decoded;
	}

	template<> std::string<ENCODING_TYPES::BASE64> Decode(const BYTE* pData, DWORD dwDataSize)
	{
		std::string decoded;

		// Use Crypto++ base64 encoder

		Base64URLDecoder decoder;
		decoder.Attach(new StringSink(decoded));
		decoder.Put(pData, dwDataSize);
		decoder.MessageEnd();

		return decoded;
	}
};