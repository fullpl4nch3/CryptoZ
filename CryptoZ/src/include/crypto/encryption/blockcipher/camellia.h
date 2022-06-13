#pragma once

class Camellia : public EncryptionModule {
	// Camellia is a CRYPTmetric key block cipher developed jointly in 2000 by
	// world top class encryption researchers at NTT and Mitsubishi Electric
	// Corporation. See:http://info.isl.ntt.co.jp/crypt/eng/camellia/index.html

private:
	uint16_t keysize;
	std::vector <std::string> keys;
	uint8_t  SBOX(const uint8_t s, const uint8_t value);
	std::string FL(const std::string& FL_IN, const std::string& KE);
	std::string FLINV(const std::string& FLINV_IN, const std::string& KE);
	std::string F(const std::string& F_IN, const std::string& KE);
	std::string run(const std::string& data);

public:
	Camellia();
	Camellia(const std::string& KEY);
	void setkey(const std::string& KEY);
	std::string encrypt(const std::string& DATA);
	std::string decrypt(const std::string& DATA);
	inline size_t blocksize() const;
};