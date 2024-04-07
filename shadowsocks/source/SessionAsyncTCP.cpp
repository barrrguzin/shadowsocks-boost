#pragma once
#include "SessionAsyncTCP.h"

SessionAsyncTCP::SessionAsyncTCP(boost::asio::ip::tcp::socket socket, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<boost::asio::io_context> ioContext, std::shared_ptr<spdlog::logger> logger)
	: clientSocket(*ioContext), remoteSocket(*ioContext)
{
	this->clientSocket = std::move(socket);
	this->cryptoProvider = cryptoProvider;
	this->ioContext = ioContext;
	this->logger = logger;
	
};

SessionAsyncTCP::SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<boost::asio::io_context> ioContext, std::shared_ptr<spdlog::logger> logger)
	: clientSocket(*ioContext), remoteSocket(*ioContext)
{
	this->cryptoProvider = cryptoProvider;
	this->ioContext = ioContext;
	this->logger = logger;
};

boost::asio::awaitable<void> SessionAsyncTCP::start()
{
	boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize), boost::asio::transfer_all(), boost::bind(&SessionAsyncTCP::handleSessionHandshake, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
};


SessionAsyncTCP::SessionAsyncTCP(SessionAsyncTCP& origin)
	: clientSocket(*(origin.ioContext)), remoteSocket(*(origin.ioContext))
{

};

SessionAsyncTCP::~SessionAsyncTCP() 
{
	delete clientToRemoteServerBuffer;
	delete remoteToClientServerBuffer;
	delete serviceBuffer;
};

void SessionAsyncTCP::handleSessionHandshake(boost::system::error_code ec, std::size_t length)
{
	char* recievedData = serviceBuffer;

	logger->trace("Message recieved: {}", length);
	CryptoPP::byte* recovered = reinterpret_cast<CryptoPP::byte*>(recievedData);
	int firstMessageOverhead = 32 + 2 + 16 + 16;
	CryptoPP::byte* salt = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer);
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), salt);
	CryptoPP::byte* firstMessage = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer + 32);
	int recoveredTargetAddressLength = cryptoProvider->decrypt(recovered, firstMessage, length - 32);
	if (recoveredTargetAddressLength > 0)
	{
		CryptoPP::byte addressType = recovered[0];
		short addressLength = recovered[1];
		logger->trace("Recieved: {}; Target address length: {}; Address bytes: {:n}", recoveredTargetAddressLength, addressLength, spdlog::to_hex(recovered, recovered + recoveredTargetAddressLength));
		char* addressT = &recievedData[2];
		std::string addr = std::string(addressT, addressLength);
		CryptoPP::byte swapArray[] = { recovered[addressLength + 2 + 1], recovered[addressLength + 2 + 0] };
		int portL = 0;
		std::memcpy(&(portL), swapArray, 2);
		CryptoPP::byte* secondMessage = reinterpret_cast<CryptoPP::byte*>(clientToRemoteServerBuffer + firstMessageOverhead + recoveredTargetAddressLength);
		int recoveredPayloadLength = cryptoProvider->decrypt(recovered, secondMessage, length - firstMessageOverhead - recoveredTargetAddressLength);
		logger->info("Connecting to {}:{}", addr, portL);
		logger->trace("Message: {:n}", spdlog::to_hex(secondMessage, secondMessage + length - firstMessageOverhead - recoveredTargetAddressLength));
		boost::asio::ip::tcp::resolver resolver(*ioContext);
		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), addr, std::to_string(portL));
		boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
		boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();
		//boost::asio::ip::tcp::socket remote(ioContext);
		remoteSocket.connect(endpoint);
		serviceNumber = recoveredPayloadLength;
	}
};