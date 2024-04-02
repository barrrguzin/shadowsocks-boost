#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "ShadowSocksChaCha20Poly1305.h"
#pragma warning(disable : 4996)

ShadowSocksChaCha20Poly1305::ShadowSocksChaCha20Poly1305(byte* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger)
{
	this->logger = logger;
	//std::unique_lock<std::mutex> lock(_mutex);
	Weak::MD5 md5;
	OPENSSL_EVP_BytesToKey(md5, NULL, password, sizeOfPassword, 1, this->key, KEY_LENGTH, NULL, 0);
	this->logger->trace("Key seted: {:n}", spdlog::to_hex(this->key, this->key + KEY_LENGTH));
};

ShadowSocksChaCha20Poly1305::~ShadowSocksChaCha20Poly1305()
{

};

int ShadowSocksChaCha20Poly1305::prepareSubSessionKey(SimpleKeyingInterface* ski, byte* salt)
{
	this->logger->trace("Salt: {:n}", spdlog::to_hex(salt, salt + SALT_LENGTH));
	//std::unique_lock<std::mutex> lock(_mutex);
	byte subSessionKey[KEY_LENGTH];
	hkdf.DeriveKey(subSessionKey, KEY_LENGTH, this->key, KEY_LENGTH, salt, SALT_LENGTH, INFO, INFO_LENGTH);
	if (dynamic_cast<ChaCha20Poly1305::Encryption*>(ski) != nullptr) {
		ski->SetKeyWithIV(subSessionKey, KEY_LENGTH, encryptionIV);
	}
	else if (dynamic_cast<ChaCha20Poly1305::Decryption*>(ski) != nullptr) {
		ski->SetKeyWithIV(subSessionKey, KEY_LENGTH, decryptionIV);
		memcpy(decryptionSubSessionKey, subSessionKey, KEY_LENGTH);
	}
	else
	{
		return -1;
	}
	this->logger->trace("Sub-Session key: {:n}", spdlog::to_hex(subSessionKey, subSessionKey + KEY_LENGTH));
	return 0;
}

void ShadowSocksChaCha20Poly1305::incrementNonce(byte* iv, short int nonceLength)
{
	std::reverse(iv, iv + nonceLength);
	CryptoPP::IncrementCounterByOne(iv, nonceLength);
	std::reverse(iv, iv + nonceLength);
	this->logger->trace("Nonce incremented: {:n}", spdlog::to_hex(iv, iv + nonceLength));

}

SimpleKeyingInterface* ShadowSocksChaCha20Poly1305::getEncryptor()
{
	return &(this->encryptor);
}

SimpleKeyingInterface* ShadowSocksChaCha20Poly1305::getDecryptor()
{
	return &(this->decryptor);
}

int ShadowSocksChaCha20Poly1305::encrypt(char* encryptedMessage, byte* plainText, const short int sizeOfPlainText)
{
	byte* encryptedMessageUnsigned = reinterpret_cast<byte*>(encryptedMessage);
	return encrypt(encryptedMessageUnsigned, plainText, sizeOfPlainText);
}

int ShadowSocksChaCha20Poly1305::encrypt(byte* encryptedMessage, byte* plainText, const short int sizeOfPlainText)
{
	this->logger->trace("Encryption start with IV: {:n}", spdlog::to_hex(encryptionIV, encryptionIV + IV_LENGTH));
	short additionalBytesLength = 0;
	//prepare pointers
	byte* EPL = encryptedMessage;
	byte* EPL_TAG = &encryptedMessage[ENCRYPTED_PAYLOAD_LENGTH];
	byte* EP = &encryptedMessage[ENCRYPTED_PAYLOAD_LENGTH + TAG_LENGTH];
	byte* EP_TAG = &encryptedMessage[ENCRYPTED_PAYLOAD_LENGTH + TAG_LENGTH + sizeOfPlainText];

	//encrypt payload length
	byte payloadLengthBytesR[2];
	std::memcpy(payloadLengthBytesR, &sizeOfPlainText, 2);
	byte payloadLengthBytes[2] = { payloadLengthBytesR[1], payloadLengthBytesR[0] };

	encryptor.EncryptAndAuthenticate(EPL, EPL_TAG, TAG_LENGTH, encryptionIV, IV_LENGTH, NULL, 0, payloadLengthBytes, ENCRYPTED_PAYLOAD_LENGTH);

	//increment IV
	incrementNonce(encryptionIV, IV_LENGTH);

	//encrypt payload
	encryptor.EncryptAndAuthenticate(EP, EP_TAG, TAG_LENGTH, encryptionIV, IV_LENGTH, NULL, 0, plainText, sizeOfPlainText);
	//increment IV
	incrementNonce(encryptionIV, IV_LENGTH);
	return ENCRYPTED_PAYLOAD_LENGTH + TAG_LENGTH + sizeOfPlainText + TAG_LENGTH + additionalBytesLength;
};

int ShadowSocksChaCha20Poly1305::decrypt(byte* recoveredMessage, char* encryptedPackage, const short int sizeOfEncryptedPackage)
{
	byte* encryptedPackageUnsigned = reinterpret_cast<byte*>(encryptedPackage);
	return decrypt(recoveredMessage, encryptedPackageUnsigned, sizeOfEncryptedPackage);
}

int ShadowSocksChaCha20Poly1305::decrypt(byte* recoveredMessage, byte* encryptedPackage, const short int sizeOfEncryptedPackage)
{
	this->logger->trace("Decryption start with IV: {:n}", spdlog::to_hex(decryptionIV, decryptionIV + IV_LENGTH));
	this->logger->trace("Trying to decrypt payload length: {:n}", spdlog::to_hex(encryptedPackage, encryptedPackage + sizeOfEncryptedPackage));
	//decrypt payload size
	byte encryptedPayloadSizeBuffer[2];

	bool decr = decryptor.DecryptAndVerify(encryptedPayloadSizeBuffer,//recovered text buffer
		encryptedPackage + ENCRYPTED_PAYLOAD_LENGTH,//TAG
		TAG_LENGTH,
		decryptionIV,
		IV_LENGTH,
		NULL, 0,
		encryptedPackage,//cypher text
		ENCRYPTED_PAYLOAD_LENGTH);//cypher text length

	this->logger->trace("Trying to decrypt message: {:n}", spdlog::to_hex(encryptedPackage, encryptedPackage + sizeOfEncryptedPackage));
	if (decr)
	{
		//replace bytes
		short encryptedPayloadSize;
		byte swapArray[] = { encryptedPayloadSizeBuffer[1], encryptedPayloadSizeBuffer[0] };
		std::memcpy(&encryptedPayloadSize, swapArray, ENCRYPTED_PAYLOAD_LENGTH);
		this->logger->trace("Payload size decrypted: {}", encryptedPayloadSize);
		//increment IV
		incrementNonce(decryptionIV, IV_LENGTH);
		//decrypt payload
		if (decryptor.DecryptAndVerify(recoveredMessage,
			encryptedPackage + ENCRYPTED_PAYLOAD_LENGTH + TAG_LENGTH + encryptedPayloadSize,
			TAG_LENGTH,
			decryptionIV,
			IV_LENGTH,
			NULL, 0,
			encryptedPackage + ENCRYPTED_PAYLOAD_LENGTH + TAG_LENGTH,
			encryptedPayloadSize))
		{
			this->logger->trace("Decrypted payload: {:n}", spdlog::to_hex(recoveredMessage, recoveredMessage + encryptedPayloadSize));
			//increment IV
			incrementNonce(decryptionIV, IV_LENGTH);
			return encryptedPayloadSize;
		}
		else
		{
			this->logger->trace("Unable to decrypt message with payload length {}", encryptedPayloadSize);
		}
	}
	return 0;
};


int ShadowSocksChaCha20Poly1305::OPENSSL_EVP_BytesToKey(HashTransformation& hash,
	const unsigned char* salt, const unsigned char* data, int dlen,
	unsigned int count, unsigned char* key, unsigned int ksize,
	unsigned char* iv, unsigned int vsize)
{
	if (data == NULL) return (0);
	unsigned int nkey = ksize;
	unsigned int niv = vsize;
	unsigned int nhash = hash.DigestSize();
	SecByteBlock digest(nhash);
	unsigned int addmd = 0, i;
	for (;;)
	{
		hash.Restart();
		if (addmd++)
			hash.Update(digest.data(), digest.size());
		hash.Update(data, dlen);
		if (salt != NULL)
			hash.Update(salt, OPENSSL_PKCS5_SALT_LEN);
		hash.TruncatedFinal(digest.data(), digest.size());
		for (i = 1; i < count; i++)
		{
			hash.Restart();
			hash.Update(digest.data(), digest.size());
			hash.TruncatedFinal(digest.data(), digest.size());
		}
		i = 0;
		if (nkey)
		{
			for (;;)
			{
				if (nkey == 0) break;
				if (i == nhash) break;
				if (key != NULL)
					*(key++) = digest[i];
				nkey--;
				i++;
			}
		}
		if (niv && (i != nhash))
		{
			for (;;)
			{
				if (niv == 0) break;
				if (i == nhash) break;
				if (iv != NULL)
					*(iv++) = digest[i];
				niv--;
				i++;
			}
		}
		if ((nkey == 0) && (niv == 0)) break;
	}
	return ksize;
}