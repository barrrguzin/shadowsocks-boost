#include "ShadowSocksServer.h"

#include "CryptoProviderFactory.h"


ShadowSocksServer::ShadowSocksServer(const char* config)
{
	//TEST
	auto endpointTemp = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 7777);
	endpoints.push_back(endpointTemp);
	
	initLogger();
	for (boost::asio::ip::tcp::endpoint endpoint : endpoints)
	{
		std::string pass("123");
		std::shared_ptr<CryptoProvider> cryptoProvider = initCryptoProvider(pass, Cypher::ChaCha20Poly1305, logger);
		std::shared_ptr<Listener> listener = initListener(std::move(endpoint), 10, std::move(cryptoProvider), logger);
		threads.emplace_back(boost::thread(boost::bind(&Listener::startListener, listener)));
		logger->trace("Listener started; Logger UC: {}", logger.use_count());
	}
};

ShadowSocksServer::~ShadowSocksServer()
{

};

void ShadowSocksServer::initLogger()
{
	logger = spdlog::stdout_color_mt("console");
	logger->set_level(spdlog::level::debug);
	logger->trace("Logger inited");
};

void ShadowSocksServer::runServer()
{
	for (int i = 0; i < threads.size(); i++)
	{
		threads[i].join();
	}
};

std::shared_ptr<Listener> ShadowSocksServer::initListener(boost::asio::ip::tcp::endpoint endpoint, unsigned short numberOfThreads, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	return std::make_shared<ListenerAcyncTCP>(endpoint, std::move(SessionHandlerThreadManager(numberOfThreads, logger)), cryptoProvider, logger);
}

std::shared_ptr<CryptoProvider> ShadowSocksServer::initCryptoProvider(std::string password, Cypher type,
	std::shared_ptr<spdlog::logger> logger)
{
	return CryptoProviderFactory::getCryptoProvider(type, password.c_str(), password.size(), logger);;
};
