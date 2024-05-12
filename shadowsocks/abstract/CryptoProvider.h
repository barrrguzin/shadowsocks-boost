#pragma once
#include <cryptlib.h>

using namespace CryptoPP;

class CryptoProvider
{
public:
	virtual int encrypt(byte* encryptedMessage, const byte* plainText, const short int sizeOfPlainText) = 0;
	virtual int decrypt(byte* recoveredMessage, const byte* encryptedPackage, const short int sizeOfEncryptedPackage) = 0;
	virtual int getSaltLength() = 0;
	virtual int prepareSubSessionKey(SimpleKeyingInterface& ski, byte* salt) = 0;

	virtual SimpleKeyingInterface& getEncryptor() = 0;
	virtual SimpleKeyingInterface& getDecryptor() = 0;
	virtual bool& isPrototype() = 0;

	virtual std::shared_ptr<CryptoProvider> clone() = 0;
};