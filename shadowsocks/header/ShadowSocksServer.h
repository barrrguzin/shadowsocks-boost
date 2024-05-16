#pragma once

#include "CryptoProvider.h"
#include "ShadowSocksChaCha20Poly1305.h"

#include "Listener.h"
#include "ListenerAcyncTCP.h"

#include "CypherType.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/thread/thread.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/json.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/fmt/bin_to_hex.h>


#include "Cypher.h"

class ShadowSocksServer
{
public:
	ShadowSocksServer(const char* config);
	~ShadowSocksServer();
	void runServer();

private:
	//std::shared_ptr<spdlog::logger> logger;
	std::vector<boost::asio::ip::tcp::endpoint> endpoints;

	std::vector<boost::thread> threads;

	std::shared_ptr<spdlog::logger> initLogger(std::string logLevel = "info", std::string loggerType = "ud", int syslogNumber = 7, std::string logName = "shadowsocks");

	template<typename T>
	std::optional<T> getValueFromConfig(boost::json::object config, const std::string& key);

	std::shared_ptr<Listener> initListener(boost::asio::ip::tcp::endpoint endpoint, unsigned short numberOfThreads, unsigned short sessionTimeout, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	std::shared_ptr<CryptoProvider> initCryptoProvider(std::string password, Cypher type, std::shared_ptr<spdlog::logger> logger);

};
