#include "stdafx.h"
#include "include/crypto/encryption/blockcipher/aes.h"

ZAES::ZAES()
{
	// By default key length is 32 BYTE

	this->dwKeyLen = AES::MAX_KEYLENGTH;
	this->dwIVLen = AES::BLOCKSIZE;
}

ZAES::ZAES(ZAES_KEY_LEN KeyLen)
{
	// I don't like this impl at ALL

	switch (KeyLen)
	{
	case ZAES_KEY_LEN::ZAES16:
		this->dwKeyLen = AES::MIN_KEYLENGTH;
		break;
	case ZAES_KEY_LEN::ZAES32:
		this->dwKeyLen = AES::MAX_KEYLENGTH;
		break;
	default:
		break;
	}
}

// Generating keys;

BOOL ZAES::GenerateKey()
{
	pKEY = new SecByteBlock(this->dwKeyLen);
	if (NULL == pKEY)
		return FALSE;

	pIV = new SecByteBlock(this->dwIVLen);
	if (NULL == pIV)
		return FALSE;

	// Generate KEY

	// not sure if ptr deref is working fine here, it shud tho;
	prng.GenerateBlock((*pKEY), pKEY->size());
	prng.GenerateBlock((*pIV), pIV->size());

	return TRUE;
}



ZAES::~ZAES()
{
	try
	{
		if (NULL != pKEY)
		{
			delete pKEY;
			pKEY = NULL;
		}

		if (NULL != pIV)
		{
			delete pIV;
			pIV = NULL;
		}
	}
	catch (...)
	{

	}
}