#pragma once

#define DEFAULT_KEY_LEN	2048 // Default RSA key length 2048-bits

enum KEY_TYPE
{
	PRIV_KEY,
	PUB_KEY,
	KEY_PAIR
};

class RSAEncryption
{
public:
	RSAEncryption();
	RSAEncryption(UINT nKeySize);
	~RSAEncryption();
private:
	BCRYPT_ALG_HANDLE	hProv				= NULL;
	BCRYPT_KEY_HANDLE	hKeyPair			= NULL,
						hPubKey				= NULL,
						hPrivKey			= NULL;
	PUCHAR				lpPubKey			= NULL,
						lpPrivKey			= NULL,
						lpEncryptedData		= NULL,
						lpDecryptedData		= NULL;
	LPSTR				szPubKeyBase64		= NULL;
	LPSTR				szPrivKeyBase64		= NULL;
	ULONG				dwPubKeySize		= 0,
						dwPrivKeySize		= 0,
						dwEncryptedDataSize = 0,
						dwDecryptedDataSize = 0,
						dwPubKeyBase64Size	= 0,
						dwPrivKeyBase64Size = 0,
						dwBytesWritten		= 0;
	UINT				nKeySize			= 0;
public:
	BOOL GenerateKeyPair(UINT nKeyLen = DEFAULT_KEY_LEN);
	inline BOOL EncryptData(LPBYTE lpData, ULONG dwDataSize);
	BOOL EncryptData(LPBYTE lpData, ULONG dwDataSize, LPBYTE IV, ULONG dwIVSize);
	BOOL ExportKeyToFile(const std::string& szKeyFilePath, KEY_TYPE type);
};