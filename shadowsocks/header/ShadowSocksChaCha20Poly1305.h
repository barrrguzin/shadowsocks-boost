#pragma once
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptlib.h>
#include <chachapoly.h>
#include <filters.h>
#include <hex.h>
#include <md5.h>
#include <hkdf.h>
#include <sha.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "ShadowSocksChaCha20Poly1305.h"
#include "CryptoProvider.h"

using namespace CryptoPP;

class ShadowSocksChaCha20Poly1305 : public CryptoProvider
{
public:
    int encrypt(byte* encryptedMessage, const byte* plainText, const short int sizeOfPlainText) override;
    int decrypt(byte* recoveredMessage, const byte* encryptedPackage, const short int sizeOfEncryptedPackage) override;
    int getSaltLength() override;
    int prepareSubSessionKey(SimpleKeyingInterface& ski, byte* salt) override;
    SimpleKeyingInterface& getEncryptor() override;
    SimpleKeyingInterface& getDecryptor() override;
    std::shared_ptr<CryptoProvider> clone() override;
    bool& isPrototype() override;

    ShadowSocksChaCha20Poly1305(byte* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger);
    ShadowSocksChaCha20Poly1305(ShadowSocksChaCha20Poly1305& source);
    ~ShadowSocksChaCha20Poly1305();

private:
    static const int OPENSSL_PKCS5_SALT_LEN = 8;
    static const int ENCRYPTED_PAYLOAD_LENGTH = 2;
    static const int INFO_LENGTH = 9;
    static const int SALT_LENGTH = 32;
    static const int AAD_LENGTH = 16;
    static const int IV_LENGTH = 12;//NONCE
    static const int TAG_LENGTH = 16;//MAC
    static const int KEY_LENGTH = 32;

    const byte INFO[INFO_LENGTH] = { 0x73, 0x73, 0x2d, 0x73, 0x75, 0x62, 0x6b, 0x65, 0x79 };

    std::shared_ptr<spdlog::logger> logger;
    ChaCha20Poly1305::Encryption encryptor;
    ChaCha20Poly1305::Decryption decryptor;
    HKDF<SHA1> hkdf;
    byte encryptionIV[IV_LENGTH] = { 0 };
    byte decryptionIV[IV_LENGTH] = { 0 };
    byte key[KEY_LENGTH];
    byte decryptionSubSessionKey[KEY_LENGTH];
    bool prototype = false;

    void incrementNonce(byte* iv, short int nonceLength);

    int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
        const unsigned char* salt, const unsigned char* data, int dlen,
        unsigned int count, unsigned char* key, unsigned int ksize,
        unsigned char* iv, unsigned int vsize);
};