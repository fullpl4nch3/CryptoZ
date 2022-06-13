#pragma once

class TDES : public EncryptionModule {
private:
	std::string k1, k2, k3;
	bool m1, m2, m3;
	std::string run(const std::string& data, const std::string& key, const bool& mode);

public:
	TDES() = default;
	TDES(const std::string& key1, const std::string& mode1, const std::string& key2, const std::string& mode2, const std::string& key3, const std::string& mode3);
	void setkey(const std::string& key1, const std::string& mode1, const std::string& key2, const std::string& mode2, const std::string& key3, const std::string& mode3);
	std::string encrypt(const std::string& DATA) override;
	std::string decrypt(const std::string& DATA) override;
	inline size_t blocksize() const override;
};