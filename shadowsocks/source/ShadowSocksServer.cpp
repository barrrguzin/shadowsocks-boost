#include "ShadowSocksServer.h"


ShadowSocksServer::ShadowSocksServer(const char* config)
{
	//TEST
	auto endpointTemp = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 7777);
	endpoints->push_back(endpointTemp);
	//разбираем конфиг

	initLogger();
	for (boost::asio::ip::tcp::endpoint endpoint : *endpoints)
	{
		byte* passwordBytes = reinterpret_cast<byte*>((char*) "123");
		std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider = std::make_shared<ShadowSocksChaCha20Poly1305>(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
		//std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider = initCryptoProvider("", CypherType::AEAD, logger);
		Listener listener = initListener(std::move(endpoint), cryptoProvider, logger);
		listeners->push_back(std::move(listener));
	}
};

void ShadowSocksServer::initLogger()
{
	logger = spdlog::stdout_color_mt("console");
	logger->set_level(spdlog::level::trace);
};

void ShadowSocksServer::runServer()
{
	std::vector<boost::thread> threads;
	for (Listener listener : *listeners)
	{
		boost::thread listenerThread = boost::thread(boost::bind(&Listener::startListener, &listener));
		threads.push_back(std::move(listenerThread));
	}
	for (int i = 0; i < threads.size(); i++)
	{
		threads[i].join();
	}
};

Listener ShadowSocksServer::initListener(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	return ListenerAcyncTCP(endpoint, cryptoProvider, logger);
};

std::shared_ptr<ShadowSocksChaCha20Poly1305> initCryptoProvider(std::string password, CypherType type, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*) password.c_str());
	ShadowSocksChaCha20Poly1305* ss;// = new ShadowSocksChaCha20Poly1305(passwordBytes, password.length(), logger);
	return std::make_shared<ShadowSocksChaCha20Poly1305>(ss);
};