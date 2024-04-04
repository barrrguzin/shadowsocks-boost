#pragma once
#include "Session.h"
#include "CryptoProvider.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio/placeholders.hpp>
#include <cryptlib.h>

#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/spdlog.h"
#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/fmt/bin_to_hex.h"

class SessionAsyncTCP : public Session, boost::enable_shared_from_this<SessionAsyncTCP>
{
public:
	SessionAsyncTCP(boost::asio::ip::tcp::socket socket, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<boost::asio::io_context> ioContext, std::shared_ptr<spdlog::logger> logger);
	void start();
	boost::asio::ip::tcp::socket& getClientSocket();

private:
	int socksSessionBufferSize = 1350;
	char* clientToRemoteServerBuffer = new char[socksSessionBufferSize];
	char* remoteToClientServerBuffer = new char[socksSessionBufferSize];

	int serviceNumber = 0;
	char* serviceBuffer = new char[socksSessionBufferSize];

	std::shared_ptr<CryptoProvider> cryptoProvider;
	std::shared_ptr<spdlog::logger> logger;
	std::shared_ptr<boost::asio::io_context> ioContext;
	boost::asio::ip::tcp::socket clientSocket;
	boost::asio::ip::tcp::socket remoteSocket;

	void handleSessionHandshake(boost::system::error_code ec, std::size_t length);

	~SessionAsyncTCP();
};