#pragma once
#include "Session.h"
#include "ShadowSocksChaCha20Poly1305.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/chrono/system_clocks.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "Listener.h"

class SessionAsyncTCP : public Session
{
public:
	SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger, unsigned int timeout = 60);
	~SessionAsyncTCP();

	boost::asio::awaitable<void> start() override;
	void setClientSocket(std::shared_ptr<boost::asio::ip::tcp::socket> clientSocket) override;
	std::string& getSessionIdentifier() override;

private:

	std::chrono::seconds timeout = std::chrono::seconds(60);
	std::chrono::steady_clock::time_point deadline;

	boost::asio::as_tuple_t<boost::asio::use_awaitable_t<>> completionToken = as_tuple(boost::asio::use_awaitable);

	std::string sessionIdentifier;
	std::string remoteIdentifier;
	std::string remoteHostName;

	bool isEsteblished = false;

	int socksSessionBufferSize = 1440;//1440//1380 maybe used
	int clientSideBufferSize = 16383; //max shadowsocks payload size with aead cypher

	std::shared_ptr<std::vector<char>> clientToRemoteServerBufferP = std::make_shared<std::vector<char>>(clientSideBufferSize + 1024);
	char* clientToRemoteServerBuffer = &((*clientToRemoteServerBufferP)[0]);
	byte* recivedMessage = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer);

	std::shared_ptr<std::vector<char>> remoteToClientServerBufferP = std::make_shared<std::vector<char>>(socksSessionBufferSize + 1024);
	char* remoteToClientServerBuffer = &((*remoteToClientServerBufferP)[0]);
	byte* palinTextByte = reinterpret_cast<byte*>(remoteToClientServerBuffer);

	std::shared_ptr<std::vector<char>> recoveredMessageP = std::make_shared<std::vector<char>>(clientSideBufferSize + 1024);
	char* recoveredMessage = &((*recoveredMessageP)[0]);
	byte* recovered = reinterpret_cast<CryptoPP::byte*>(recoveredMessage);

	std::shared_ptr<std::vector<char>> encryptedMessageP = std::make_shared<std::vector<char>>(socksSessionBufferSize + 66 + 1024);
	char* encryptedMessage = &((*encryptedMessageP)[0]);

	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;
	std::shared_ptr<spdlog::logger> logger;

	std::shared_ptr<boost::asio::ip::tcp::socket> clientSocket;
	std::shared_ptr<boost::asio::ip::tcp::socket> remoteSocket;

	boost::asio::awaitable<void> handleSessionHandshake();
	boost::asio::awaitable<void> startMessageExchange();

	boost::asio::awaitable<void> remoteToLocalStream(int length);
	boost::asio::awaitable<void> localToRemoteStream();

	boost::asio::awaitable<void> watchdog();
	void closeSession();
	void resetTimeoutTimer();

	boost::asio::awaitable<int> receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize);

	char* setSalt();
};
