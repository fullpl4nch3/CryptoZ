#include "stdafx.h"
#include "crypto/encryption/common/includes.h"

static DESEncryption des;

DESX::DESX(const std::string& KEY, const std::string& KEY1, const std::string& KEY2)
{
	if (keyset) {
		throw std::runtime_error("Error: Key has already been set.");
	}

	des.setkey(KEY);
	K1 = KEY1;
	K2 = KEY2;

	keyset = true;
}

std::string DESX::encrypt(const std::string& DATA) {
	if (!keyset) {
		throw std::runtime_error("Error: Key has not been set.");
	}
	return xor_strings(des.encrypt(xor_strings(DATA, K1)), K2);
}

std::string DESX::decrypt(const std::string& DATA) {
	if (!keyset) {
		throw std::runtime_error("Error: Key has not been set.");
	}
	return xor_strings(des.decrypt(xor_strings(DATA, K2)), K1);
}

size_t DESX::blocksize() const {
	return 64;
}
