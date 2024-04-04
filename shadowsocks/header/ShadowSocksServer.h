#pragma once

#include "CryptoProvider.h"
#include "ShadowSocksChaCha20Poly1305.h"

#include "Listener.h"
#include "ListenerAcyncTCP.h"

#include "CypherType.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/thread/thread.hpp>

#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/spdlog.h"
#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/sinks/stdout_color_sinks.h"

class ShadowSocksServer
{
public:
	ShadowSocksServer(const char* config);
	void runServer();

private:
	std::shared_ptr<spdlog::logger> logger;
	std::vector<boost::asio::ip::tcp::endpoint>* endpoints = new std::vector<boost::asio::ip::tcp::endpoint>;
	std::vector<Listener>* listeners = new std::vector<Listener>;

	void initLogger();
	Listener initListener(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	std::shared_ptr<CryptoProvider> initCryptoProvider(std::string password, CypherType type, std::shared_ptr<spdlog::logger> logger);

};