#ifndef CRYPTOPROVIDERFACTORY_H
#define CRYPTOPROVIDERFACTORY_H
#include <memory>
#include <spdlog/logger.h>

#include <functional>

#include "CryptoProvider.h"
#include "Cypher.h"


class CryptoProviderFactory {
public:
    CryptoProviderFactory() = delete;
    static std::shared_ptr<CryptoProvider> getCryptoProvider(Cypher type, const char* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger);

private:
    static std::shared_ptr<CryptoProvider> makeChaCha20Poly1305CryptoProvider(const char* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger);
    static std::shared_ptr<CryptoProvider> makePlainCryptoProvider(const char* password, int sizeOfPassword, std::shared_ptr<spdlog::logger> logger);

    static const std::map<Cypher, std::function<std::shared_ptr<CryptoProvider>(const char*, int, std::shared_ptr<spdlog::logger>)>> cryptoProviderFabricMethodRepository;
     //static const std::map<Cypher, std::shared_ptr<CryptoProvider>(CryptoProviderFactory::*)(const char *, int, std::shared_ptr<spdlog::logger>)> cryptoProviderFabricMethorRepository;
};
/*
const std::map<Cypher, std::shared_ptr<CryptoProvider>(CryptoProviderFactory::*)(const char *, int, std::shared_ptr<spdlog::logger>)> CryptoProviderFactory::cryptoProviderFabricMethorRepository = {
    {Cypher::ChaCha20Poly1305, &CryptoProviderFactory::makeChaCha20Poly1305CryptoProvider},
    {Cypher::Plain, &CryptoProviderFactory::makePlainCryptoProvider},
};
*/
#endif //CRYPTOPROVIDERFACTORY_H
