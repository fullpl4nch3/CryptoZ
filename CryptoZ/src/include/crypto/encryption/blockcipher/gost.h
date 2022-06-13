#pragma once

// GOST 28147-89
class GOST : public EncryptionModule
{
private:
	uint8_t k[8][16];
	uint32_t X[8], N[6], C1, C2;
	uint32_t CM1(const uint32_t a, const uint32_t b);
	uint32_t CM2(const uint32_t a, const uint32_t b);
	//        uint32_t CM3(const uint32_t a, const uint32_t b){return static_cast <uint32_t> (a + b);}
	//        uint32_t CM4(const uint32_t a, const uint32_t b){return static_cast <uint32_t> (a + b) % mod32;}
	//        uint32_t CM5(const uint32_t a, const uint32_t b){return static_cast <uint32_t> (a ^ b);}
	uint32_t sub(uint32_t in);

public:
	GOST() = default;
	GOST(const std::string& KEY);
public:
	void setkey(const std::string& KEY);
	std::string encrypt(const std::string& DATA) override;
	std::string decrypt(const std::string& DATA) override;
	inline size_t blocksize() const override;
};