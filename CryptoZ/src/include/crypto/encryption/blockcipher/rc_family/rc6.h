#pragma once

class RC6 : public EncryptionModule {
private:
	uint32_t w, r, b, lgw;
	std::vector <uint32_t> S;

public:
	RC6() = default;
	RC6(const std::string& KEY, const unsigned int& W = 32, const unsigned int& R = 20);
	void setkey(std::string KEY, const unsigned int& W = 32, const unsigned int& R = 20);
	std::string encrypt(const std::string& DATA) override;
	std::string decrypt(const std::string& DATA) override;
	inline size_t blocksize() const override;
};