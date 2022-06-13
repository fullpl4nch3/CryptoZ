#pragma once

class XTEA : public EncryptionModule {
private:
	uint32_t delta, cycles, total, key[4];

public:
	XTEA() = default;
	XTEA(const std::string& KEY, const uint8_t& ROUNDS = 64, const uint32_t& DELTA = 0x9e3779b9);
	void setkey(const std::string& KEY, const uint8_t& ROUNDS = 64, const uint32_t& DELTA = 0x9e3779b9);
	std::string encrypt(const std::string& DATA);
	std::string decrypt(const std::string& DATA);
	inline size_t blocksize() const;
};