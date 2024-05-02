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
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "Listener.h"


class SessionAsyncTCP : public Session, public boost::enable_shared_from_this<SessionAsyncTCP>
{
public:
	SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger);
	boost::asio::awaitable<void> start();
	boost::asio::ip::tcp::socket& getClientSocket() override;
	std::string& getSessionIdentifier() override;
	const bool& isOpen() override;
	~SessionAsyncTCP();

private:
	//boost::asio::awaitable<void> timer(std::chrono::steady_clock::duration dur);

	boost::asio::as_tuple_t<boost::asio::use_awaitable_t<>> completionToken = as_tuple(boost::asio::use_awaitable);

	std::string sessionIdentifier;
	std::string remoteIdentifier;
	std::string remoteHostName;

	boost::asio::awaitable<void> waitToBothChannelClosed();
	void closeSession();
	bool isEsteblished = false;
	bool is_open = true;

	int socksSessionBufferSize = 1440;//1440//1380 maybe used
	int clientSideBufferSize = 16383; //max shadowsocks payload size with aead cypher

	std::shared_ptr<std::vector<char>> clientToRemoteServerBufferP = std::make_shared<std::vector<char>>(clientSideBufferSize);
	char* clientToRemoteServerBuffer = &((*clientToRemoteServerBufferP)[0]);
	byte* recivedMessage = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer);

	std::shared_ptr<std::vector<char>> remoteToClientServerBufferP = std::make_shared<std::vector<char>>(socksSessionBufferSize);
	char* remoteToClientServerBuffer = &((*remoteToClientServerBufferP)[0]);
	byte* palinTextByte = reinterpret_cast<byte*>(remoteToClientServerBuffer);

	std::shared_ptr<std::vector<char>> recoveredMessageP = std::make_shared<std::vector<char>>(clientSideBufferSize);
	char* recoveredMessage = &((*recoveredMessageP)[0]);
	byte* recovered = reinterpret_cast<CryptoPP::byte*>(recoveredMessage);

	std::shared_ptr<std::vector<char>> encryptedMessageP = std::make_shared<std::vector<char>>(socksSessionBufferSize + 66);
	char* encryptedMessage = &((*encryptedMessageP)[0]);

	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;
	std::shared_ptr<spdlog::logger> logger;

	boost::asio::ip::tcp::socket clientSocket;
	boost::asio::ip::tcp::socket remoteSocket;
	boost::asio::ip::tcp::resolver resolver;

	boost::asio::awaitable<void> handleSessionHandshake();
	boost::asio::awaitable<void> startMessageExchange();

	boost::asio::awaitable<void> initRemoteToLocalStream(int length);
	boost::asio::awaitable<void> initLocalToRemoteStream(int length);

	boost::asio::awaitable<void> remoteToLocalStream();
	boost::asio::awaitable<void> localToRemoteStream();

	boost::asio::awaitable<int> receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize);

	char* setSalt();
};
