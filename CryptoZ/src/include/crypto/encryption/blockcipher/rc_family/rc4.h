#pragma once

class RC4 : public EncryptionModule {
private:
	uint8_t s_e[256], i_e, j_e,      // encryption SBox and "pointers"
		s_d[256], i_d, j_d;      // decryption SBox and "pointers"

	void ksa(const std::string& k); // key scheduling algorithm
	uint8_t prga(const char mode);   // pseudo random generation algorithm

public:
	RC4() = default;
	RC4(const std::string& KEY);
	void setkey(const std::string& KEY);
	std::string encrypt(const std::string& DATA) override;
	std::string decrypt(const std::string& DATA) override;
	inline size_t blocksize() const override;
};