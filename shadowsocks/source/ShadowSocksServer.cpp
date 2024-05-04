#include "ShadowSocksServer.h"


ShadowSocksServer::ShadowSocksServer(const char* config)
{
	//TEST
	auto endpointTemp = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 7777);
	endpoints.push_back(endpointTemp);
	
	initLogger();
	for (boost::asio::ip::tcp::endpoint endpoint : endpoints)
	{
		byte* passwordBytes = reinterpret_cast<byte*>((char*) "123");
		std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
		std::shared_ptr<Listener> listener = initListener(std::move(endpoint), cryptoProvider, logger);
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

std::shared_ptr<Listener> ShadowSocksServer::initListener(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	std::shared_ptr<Listener> listenerPionter = std::make_shared<ListenerAcyncTCP>(endpoint, cryptoProvider, logger);
	return listenerPionter;
};

std::shared_ptr<ShadowSocksChaCha20Poly1305> initCryptoProvider(std::string password, CypherType type, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*) password.c_str());
	std::shared_ptr<ShadowSocksChaCha20Poly1305> sptr(new ShadowSocksChaCha20Poly1305(passwordBytes, password.length(), logger));
	return sptr;
};