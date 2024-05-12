#include "CryptoProviderFactory.h"

#include "ShadowSocksChaCha20Poly1305.h"

const std::map<Cypher, std::function<std::shared_ptr<CryptoProvider>(const char*, int, std::shared_ptr<spdlog::logger>)>> CryptoProviderFactory::cryptoProviderFabricMethodRepository = {
    {Cypher::ChaCha20Poly1305, [](const char* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger) {
        return makeChaCha20Poly1305CryptoProvider(password, sizeOfPassword, logger);
    }},
    {Cypher::Plain, [](const char* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger) {
        return makePlainCryptoProvider(password, sizeOfPassword, logger);
    }}
};

std::shared_ptr<CryptoProvider> CryptoProviderFactory::getCryptoProvider(Cypher type, const char *password,
    int sizeOfPassword, std::shared_ptr<spdlog::logger> logger)
{
    const auto fabricMethodIterator = CryptoProviderFactory::cryptoProviderFabricMethodRepository.find(type);
    if (fabricMethodIterator == CryptoProviderFactory::cryptoProviderFabricMethodRepository.end())
        throw std::runtime_error("CryptoProvider with chosen type is not implemented");
    const auto makeCryptoProvider = fabricMethodIterator->second;
    return makeCryptoProvider(password, sizeOfPassword, logger);
}

std::shared_ptr<CryptoProvider> CryptoProviderFactory::makeChaCha20Poly1305CryptoProvider(const char *password,
    int sizeOfPassword, std::shared_ptr<spdlog::logger> logger)
{
    return std::make_shared<ShadowSocksChaCha20Poly1305>((byte*) password, sizeOfPassword, logger);
}

std::shared_ptr<CryptoProvider> CryptoProviderFactory::makePlainCryptoProvider(const char *password, int sizeOfPassword,
    std::shared_ptr<spdlog::logger> logger)
{
}
