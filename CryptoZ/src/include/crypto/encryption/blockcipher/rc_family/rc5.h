#pragma once

class RC5 : public EncryptionModule {
private:
	uint64_t w, r, b;
	uint64_t mod;
	std::vector <uint64_t> S;

public:
	RC5() = default;
	RC5(const std::string& KEY, const uint64_t& W = 32, const uint64_t& R = 12, const uint64_t& B = 16);
	void setkey(std::string KEY, const uint64_t& W = 32, const uint64_t& R = 12, const uint64_t& B = 16);
	std::string encrypt(const std::string& DATA);
	std::string decrypt(const std::string& DATA);
	inline size_t blocksize() const;
};