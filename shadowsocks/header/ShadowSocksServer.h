#pragma once

#include "CryptoProvider.h"
#include "ShadowSocksChaCha20Poly1305.h"

#include "Listener.h"
#include "ListenerAcyncTCP.h"

#include "CypherType.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/thread/thread.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "Cypher.h"

class ShadowSocksServer
{
public:
	ShadowSocksServer(const char* config);
	~ShadowSocksServer();
	void runServer();

private:
	std::shared_ptr<spdlog::logger> logger;
	std::vector<boost::asio::ip::tcp::endpoint> endpoints;

	std::vector<boost::thread> threads;

	void initLogger();
	std::shared_ptr<Listener> initListener(boost::asio::ip::tcp::endpoint endpoint, unsigned short numberOfThreads, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	std::shared_ptr<CryptoProvider> initCryptoProvider(std::string password, Cypher type, std::shared_ptr<spdlog::logger> logger);

};
