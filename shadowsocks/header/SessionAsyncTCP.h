#pragma once
#include "Session.h"
#include "ShadowSocksChaCha20Poly1305.h"

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

class SessionAsyncTCP : public Session, public boost::enable_shared_from_this<SessionAsyncTCP>
{
public:
	SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger);
	boost::asio::awaitable<void> start();
	boost::asio::ip::tcp::socket& getClientSocket();
	~SessionAsyncTCP();

private:
	int socksSessionBufferSize = 1440;//1380 maybe used

	char* clientToRemoteServerBuffer = new char[socksSessionBufferSize];
	CryptoPP::byte* recivedMessage = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer);

	char* remoteToClientServerBuffer = new char[socksSessionBufferSize];
	byte* palinTextByte = reinterpret_cast<byte*>(remoteToClientServerBuffer);

	//char* processingBuffer = new char[socksSessionBufferSize];
	char* recoveredMessage = new char[socksSessionBufferSize];
	CryptoPP::byte* recovered = reinterpret_cast<CryptoPP::byte*>(recoveredMessage);

	char* encryptedMessage = new char[socksSessionBufferSize];

	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;
	std::shared_ptr<spdlog::logger> logger;
	boost::asio::ip::tcp::socket clientSocket;
	boost::asio::ip::tcp::socket remoteSocket;
	boost::asio::ip::tcp::resolver resolver;
	//boost::asio::io_context* ioContext;


	boost::asio::awaitable<void> handleSessionHandshake(int length);
	boost::asio::awaitable<void> startMessageExchange();

	boost::asio::awaitable<void> initRemoteToLocalStream(int length);
	boost::asio::awaitable<void> initLocalToRemoteStream(int length);
	
	boost::asio::awaitable<void> remoteToLocalStream(); 
	boost::asio::awaitable<void> localToRemoteStream();

	boost::asio::awaitable<int> receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize);

	void initSalt();
};