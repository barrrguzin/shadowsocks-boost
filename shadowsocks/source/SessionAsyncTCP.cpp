#pragma once
#include "SessionAsyncTCP.h"

SessionAsyncTCP::SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger)
	: clientSocket(ioContext), remoteSocket(ioContext), resolver(ioContext)
{
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
};

boost::asio::awaitable<void> SessionAsyncTCP::start()
{
	logger->info("Trying to start the session with client {}:{}...", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port());
	int shadowsocksInitialDataBlockLength = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize), 
		boost::asio::transfer_exactly(32), boost::asio::use_awaitable);
	if (shadowsocksInitialDataBlockLength == 32)
	{
		co_await handleSessionHandshake(shadowsocksInitialDataBlockLength);
	}
};

SessionAsyncTCP::~SessionAsyncTCP() 
{
	/*
	logger->debug("Start session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	*/
	
	/*
	delete[] clientToRemoteServerBuffer;
	delete[] remoteToClientServerBuffer;
	delete[] recoveredMessage;
	delete[] encryptedMessage;
	*/
};

boost::asio::ip::tcp::socket& SessionAsyncTCP::getClientSocket()
{
	return clientSocket;
};

boost::asio::awaitable<int> SessionAsyncTCP::receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize)
{
	//recive payload length
	short payloadLengthAndTag = 2 + 16;
	int payloadLengthAndTagLength = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize), 
		boost::asio::transfer_exactly(payloadLengthAndTag), boost::asio::use_awaitable);
	if (payloadLengthAndTag == payloadLengthAndTagLength)
	{
		CryptoPP::byte* recovered = reinterpret_cast<CryptoPP::byte*>(destenationBuffer);//recievedData
		//decrypt payload length
		int palyoadLengthSize = cryptoProvider->simpleDecrypt(recovered, recivedMessage, payloadLengthAndTag);
		if (palyoadLengthSize == 2)
		{
			short encryptedPayloadSize = 0;
			std::memcpy(&encryptedPayloadSize, recovered, 2);
			encryptedPayloadSize = ntohs(encryptedPayloadSize);

			int payloadSizeToRead = encryptedPayloadSize + 16;
			//recive payload
			int readedPayloadLength = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize), 
				boost::asio::transfer_exactly(payloadSizeToRead), boost::asio::use_awaitable);
			if (payloadSizeToRead == readedPayloadLength)
			{
				//decrypt payload
				int palyoadLength = cryptoProvider->simpleDecrypt(recovered, recivedMessage, payloadSizeToRead);
				if (palyoadLength == encryptedPayloadSize)
				{
					logger->trace("Chunk {} bytes size decrypted", palyoadLength);
					co_return palyoadLength;
				}
			}
		}
	}
	logger->critical("Unable to decrypt chunk");
	co_return 0;
};

boost::asio::awaitable<void> SessionAsyncTCP::handleSessionHandshake(int length)
{
	if (length > 0)
	{
		cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), recivedMessage);

		int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);

		CryptoPP::byte addressType = recovered[0];
		short addressLength = recovered[1];
		char* addressT = &recoveredMessage[2];
		std::string addr = std::string(addressT, addressLength);

		short port = 0;
		std::memcpy(&port, recovered + addressLength + 2, 2);
		port = ntohs(port);

		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), addr, std::to_string(port));
		boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
		boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();
		remoteSocket.connect(endpoint);

		if (remoteSocket.is_open())
		{
			logger->info("Start session: {}:{} -> {}:{} ({})", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), addr, port, 
				remoteSocket.remote_endpoint().address().to_string());
			co_await startMessageExchange();
		}

	}
};

boost::asio::awaitable<void> SessionAsyncTCP::startMessageExchange()
{
	logger->trace("Function \"startMessageExchange\" called by session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	initSalt();
	int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
	if (payloadLength > 0)
	{
		const auto executor = co_await boost::asio::this_coro::executor;
		boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initLocalToRemoteStream, this, payloadLength), boost::asio::detached);
		int receivedFormRemote = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize - (int) 34), boost::asio::use_awaitable);
		if (receivedFormRemote > 0)
		{
			boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initRemoteToLocalStream, this, receivedFormRemote), boost::asio::detached);
		}	
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::initLocalToRemoteStream(int length)
{
	logger->trace("Function \"initLocalToRemoteStream\" called by session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	if (length > 0)
	{
		co_await remoteSocket.async_send(boost::asio::buffer(recoveredMessage, length), boost::asio::use_awaitable);
		co_await localToRemoteStream();
		
	}
	else
	{
		logger->critical("clientSideReceiveHandler");
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::localToRemoteStream()
{
	logger->trace("Function \"localToRemoteStream\" called by session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	for (;;)
	{
		int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
		if (payloadLength > 0)
		{
			co_await remoteSocket.async_send(boost::asio::buffer(recoveredMessage, payloadLength), boost::asio::use_awaitable);
		}
		else
		{
			logger->critical("localToRemoteStream");
			break;
		}
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::initRemoteToLocalStream(int length)
{
	logger->trace("Function \"initRemoteToLocalStream\" called by session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	if (length > 0)
	{
		int encryptedMessageLength = cryptoProvider->encrypt(&encryptedMessage[32], palinTextByte, length);
		logger->critical("encryptedMessageLength = {}", encryptedMessageLength);
		logger->critical("socksSessionBufferSize = {}", socksSessionBufferSize);
		co_await clientSocket.async_send(boost::asio::buffer(encryptedMessage, encryptedMessageLength + (int) 32), boost::asio::use_awaitable);
		co_await remoteToLocalStream();
	}
	else
	{
		logger->critical("sendToLocalFirstTime");
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::remoteToLocalStream()
{
	logger->trace("Function \"remoteToLocalStream\" called by session: {}:{} -> {}:{}", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port(), 
		remoteSocket.remote_endpoint().address().to_string(), remoteSocket.remote_endpoint().port());
	for (;;)
	{
		int received = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), boost::asio::use_awaitable);
		if (received > 0)
		{
			int encryptedMessageLength = cryptoProvider->encrypt(encryptedMessage, palinTextByte, received);
			co_await clientSocket.async_send(boost::asio::buffer(encryptedMessage, encryptedMessageLength), boost::asio::use_awaitable);
		}
		else
		{
			logger->critical("remoteToLocalStream");
			break;
		}
	}
};

void SessionAsyncTCP::initSalt()
{
	byte SALT[32] = { 0 };
	char* SALTC = reinterpret_cast<char*>(SALT);
	std::memcpy(encryptedMessage, SALTC, 32);
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getEncryptor(), SALT);
};
