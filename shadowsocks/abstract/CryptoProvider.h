#pragma once

class CryptoProvider
{
public:
	virtual int encrypt(CryptoPP::byte* encryptedMessage, CryptoPP::byte* plainText, const short int sizeOfPlainText) = 0;
	virtual int encrypt(char* encryptedMessage, CryptoPP::byte* plainText, const short int sizeOfPlainText) = 0;

	virtual int decrypt(CryptoPP::byte* recoveredMessage, CryptoPP::byte* encryptedPackage, const short int sizeOfEncryptedPackage) = 0;
	virtual int decrypt(CryptoPP::byte* recoveredMessage, char* encryptedPackage, const short int sizeOfEncryptedPackage) = 0;

	virtual int prepareSubSessionKey(CryptoPP::SimpleKeyingInterface* ski, CryptoPP::byte* salt) = 0;

	virtual CryptoPP::SimpleKeyingInterface* getEncryptor() = 0;
	virtual CryptoPP::SimpleKeyingInterface* getDecryptor() = 0;

	//AEAD
	virtual int prepareSubSessionKey(CryptoPP::SimpleKeyingInterface* ski, CryptoPP::byte* salt) = 0;
};