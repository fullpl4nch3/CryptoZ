#include "stdafx.h"
#include "crypto/encryption/common/includes.h"
#include "crypto/encryption/common/cryptomath.h"


// GOST Cipher S Boxes
static const uint8_t CryptoPro_sbox[8][16] = { {10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
										  {5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
										  {7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
										  {4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
										  {7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
										  {7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
										  {13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
										  {1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12} };

static const uint8_t DES_sbox[8][16] = { {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
										  {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
										  {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
										  {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
										  {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
										  {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
										  {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
										  {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7} };

static const uint8_t RFC4357_sbox[8][16] = { {9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5},
										  {3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1},
										  {14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9},
										  {14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6},
										  {11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6},
										  {3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6},
										  {1, 13, 2, 9, 7, 10, 6, 0, 8, 14, 4, 5, 15, 3, 11, 14},
										  {11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1 ,7, 13, 4} };

static const uint8_t RFC5831_sbox[8][16] = { {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
										  {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
										  {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
										  {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
										  {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
										  {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
										  {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
										  {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12} };

static uint32_t C1 = 0b00000001000000010000000100000100UL;
static uint32_t C2 = 0b00000001000000010000000100000001UL;

// GOST 28147-89
uint32_t GOST::CM1(const uint32_t a, const uint32_t b) {
	return static_cast <uint32_t> (a + b);
}

uint32_t GOST::CM2(const uint32_t a, const uint32_t b) {
	return static_cast <uint32_t> (a ^ b);
}

//uint32_t CM3(const uint32_t a, const uint32_t b){
//    return static_cast <uint32_t> (a + b);
//}

//uint32_t CM4(const uint32_t a, const uint32_t b){
//    return static_cast <uint32_t> (a + b) % mod32;
//}

//uint32_t CM5(const uint32_t a, const uint32_t b){
//    return static_cast <uint32_t> (a ^ b);
//}

uint32_t GOST::sub(const uint32_t in) {
	uint32_t out = 0;
	for (uint8_t x = 0; x < 8; x++) {
		out = (out << 4) + k[x][(in >> (28 - (x << 2))) & 15];
	}
	return out;
}

GOST::GOST(const std::string& KEY)
{
	this->setkey(KEY);
}

void GOST::setkey(const std::string& KEY) {
	if (keyset) {
		throw std::runtime_error("Error: Key has already been set.");
	}

	if (KEY.size() != 32) {
		throw std::runtime_error("Error: Key must be 256 bits long.");
	}
	
	for (uint8_t x = 0; x < 8; x++) {
		X[x] = static_cast <uint32_t> (toint(hexlify(KEY.substr(x << 2, 4)), 16));
		for (int y = 0; y < 16; y++) {
			k[x][y] = DES_sbox[x][y];
		}
	}
	
	keyset = true;
}

std::string GOST::encrypt(const std::string& DATA) {
	if (!keyset)
		return "";

	if (DATA.size() != 8) {
		throw std::runtime_error("Error: Data must be 64 bits in length.");
	}

	for (uint8_t x = 0; x < 2; x++) {
		N[x] = static_cast <uint32_t> (toint(DATA.substr(x << 2, 4), 256));
	}

	for (uint8_t x = 0; x < 3; x++) {
		for (uint8_t y = 0; y < 4; y++) {
			N[1] = CM2(ROL(sub(CM1(N[0], X[(y << 1) & 7])), 11, 32), N[1]);
			N[0] = CM2(ROL(sub(CM1(N[1], X[((y << 1) + 1) & 7])), 11, 32), N[0]);
		}
	}

	for (int8_t x = 3; x > -1; x--) {
		N[1] = CM2(ROL(sub(CM1(N[0], X[((x << 1) + 1) & 7])), 11, 32), N[1]);
		N[0] = CM2(ROL(sub(CM1(N[1], X[(x << 1) & 7])), 11, 32), N[0]);
	}
	
	return unhexlify(makehex(N[1], 8) + makehex(N[0], 8));
}

std::string GOST::decrypt(const std::string& DATA) {
	if (!keyset)
		return "";

	if (DATA.size() != 8) {
		throw std::runtime_error("Error: Data must be 64 bits in length.");
	}

	for (uint8_t x = 0; x < 2; x++) {
		N[x] = static_cast <uint32_t> (toint(DATA.substr(x << 2, 4), 256));
	}

	for (uint8_t x = 0; x < 4; x++) {
		N[1] = CM2(ROL(sub(CM1(N[0], X[(x << 1) & 7])), 11, 32), N[1]);
		N[0] = CM2(ROL(sub(CM1(N[1], X[((x << 1) + 1) & 7])), 11, 32), N[0]);
	}

	for (int8_t x = 2; x > -1; x--) {
		for (int8_t y = 3; y > -1; y--) {
			N[1] = CM2(ROL(sub(CM1(N[0], X[((y << 1) + 1) & 7])), 11, 32), N[1]);
			N[0] = CM2(ROL(sub(CM1(N[1], X[(y << 1) & 7])), 11, 32), N[0]);
		}
	}
	
	return unhexlify(makehex(N[1], 8) + makehex(N[0], 8));
}

size_t GOST::blocksize() const {
	return 64;
}