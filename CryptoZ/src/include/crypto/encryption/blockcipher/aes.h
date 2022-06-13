#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

enum class ZAES_KEY_LEN
{
	ZAES16,
	ZAES32
};

class ZAES
{
public:
	ZAES();
	ZAES(ZAES_KEY_LEN KeyLen);
	~ZAES();

public:
	BOOL GenerateKey();

private:
	AutoSeededRandomPool prng;

	DWORD dwKeyLen;
	DWORD dwIVLen;

	SecByteBlock* pKEY = NULL;
	SecByteBlock* pIV = NULL;
};