#pragma once

class DESX : public EncryptionModule
{
public:
	DESX() = default;
	DESX(const std::string& KEY, const std::string& KEY1, const std::string& KEY2);
	std::string encrypt(const std::string& DATA);
	std::string decrypt(const std::string& DATA);
	inline size_t blocksize() const;
private:
	std::string K1, K2;
};