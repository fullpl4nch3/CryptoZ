#pragma once

class DESEncryption : public EncryptionModule
{
private:
	uint64_t keys[16];
	std::string run(const std::string& data);

public:
	DESEncryption() = default;
	DESEncryption(const std::string& KEY);
	void setkey(const std::string& KEY);
	std::string encrypt(const std::string& DATA) override;
	std::string decrypt(const std::string& DATA) override;
	inline size_t blocksize() const override;
};