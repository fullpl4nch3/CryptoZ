#pragma once

class IDEA : public EncryptionModule {
private:
	std::vector <std::vector <uint16_t> > keys;
	std::vector <uint16_t> k;
	uint16_t mult(uint32_t value1, uint32_t value2);
	std::string run(const std::string& data);

public:
	IDEA();
	IDEA(const std::string& KEY);
	void setkey(const std::string& KEY);
	std::string encrypt(const std::string& DATA);
	std::string decrypt(const std::string& DATA);
	inline size_t blocksize() const;
};