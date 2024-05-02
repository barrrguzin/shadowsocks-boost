#pragma once
#include "SessionAsyncTCP.h"

#include <iostream>

SessionAsyncTCP::SessionAsyncTCP(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger)
	: clientSocket(ioContext), remoteSocket(ioContext), resolver(ioContext)
{
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
};

boost::asio::awaitable<void> SessionAsyncTCP::start()
{
	try
	{
		logger->info("Trying to start the session with client {}:{}...", clientSocket.remote_endpoint().address().to_string(), clientSocket.remote_endpoint().port());
		co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(cryptoProvider->getSaltLength()), boost::asio::use_awaitable);
		co_await handleSessionHandshake();
		logger->critical("END");
		//co_await waitToBothChannelClosed();
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in start: {}", exception.what());
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::waitToBothChannelClosed()
{
	const auto executor = co_await boost::asio::this_coro::executor;
	boost::asio::steady_timer t(executor, boost::asio::chrono::seconds(5));
	while (is_open)
	{
		logger->critical("waitin");
		t.wait();
		logger->critical("waited");
	}
}

SessionAsyncTCP::~SessionAsyncTCP()
{
	logger->warn("Stop proxy session: {} X<->X {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
};

boost::asio::ip::tcp::socket& SessionAsyncTCP::getClientSocket()
{
	return clientSocket;
};

std::string& SessionAsyncTCP::getSessionIdentifier()
{
	return sessionIdentifier;
};

const bool& SessionAsyncTCP::isOpen()
{
	return is_open;
};

boost::asio::awaitable<int> SessionAsyncTCP::receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize)
{
	try
	{
		int received = 0;
		//recive payload length
		short payloadLengthAndTag = 2 + 16;
		received = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadLengthAndTag), boost::asio::use_awaitable);

		if (payloadLengthAndTag != received)
			throw std::length_error("Received less bytes than expected as payload length");

		byte* recovered = reinterpret_cast<CryptoPP::byte*>(destenationBuffer);//recievedData
		//decrypt payload length
		int palyoadLengthSize = cryptoProvider->decrypt(recovered, recivedMessage, payloadLengthAndTag);

		if (palyoadLengthSize != 2)
			throw std::length_error("Decrypted data length dont equal to payload length size");

		short encryptedPayloadSize = 0;
		std::memcpy(&encryptedPayloadSize, recovered, 2);
		encryptedPayloadSize = ntohs(encryptedPayloadSize);
		int payloadSizeToRead = encryptedPayloadSize + 16;
		//recive payload
		received = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadSizeToRead), boost::asio::use_awaitable);

		int reReaderSize = 0;
		while (received < payloadSizeToRead)
		{
			reReaderSize = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer+received, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadSizeToRead-received), boost::asio::use_awaitable);
			received = received + reReaderSize;
		}

		if (payloadSizeToRead != received)
			throw std::length_error("Received data length dont equal to expected payload length");
		//decrypt payload
		int palyoadLength = cryptoProvider->decrypt(recovered, recivedMessage, payloadSizeToRead);

		if (palyoadLength != encryptedPayloadSize)
			throw std::length_error("Received data length dont equal to expected payload length");

		logger->debug("{} byte package recieved from {} and decrypted succsessfuly", palyoadLength, sessionIdentifier);
		co_return palyoadLength;
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in receiveAndDecryptChunk: {}", exception.what());
		throw std::exception(exception);
	}
	/*
	boost::system::error_code ec;
	int received = 0;
	//recive payload length
	short payloadLengthAndTag = 2 + 16;
	std::tie(ec, received) = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
		boost::asio::transfer_exactly(payloadLengthAndTag), completionToken);

	if (payloadLengthAndTag == received && ec.value() == 0)
	{
		byte* recovered = reinterpret_cast<CryptoPP::byte*>(destenationBuffer);//recievedData
		//decrypt payload length
		int palyoadLengthSize = cryptoProvider->decrypt(recovered, recivedMessage, payloadLengthAndTag);
		if (palyoadLengthSize == 2)
		{
			short encryptedPayloadSize = 0;
			std::memcpy(&encryptedPayloadSize, recovered, 2);
			encryptedPayloadSize = ntohs(encryptedPayloadSize);
			int payloadSizeToRead = encryptedPayloadSize + 16;
			//recive payload
			std::tie(ec, received) = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
				boost::asio::transfer_exactly(payloadSizeToRead), completionToken);

			int reReaderSize = 0;
			while (received < payloadSizeToRead && ec.value() == 0)
			{
				std::tie(ec, reReaderSize) = co_await boost::asio::async_read(clientSocket, boost::asio::buffer(clientToRemoteServerBuffer+received, socksSessionBufferSize),
				boost::asio::transfer_exactly(payloadSizeToRead-received), completionToken);
				received = received + reReaderSize;
			}

			if (payloadSizeToRead == received && ec.value() == 0)
			{
				//decrypt payload
				int palyoadLength = cryptoProvider->decrypt(recovered, recivedMessage, payloadSizeToRead);
				if (palyoadLength == encryptedPayloadSize)
				{
					logger->debug("{} byte package recieved from {} and decrypted succsessfuly", palyoadLength, sessionIdentifier);
					co_return palyoadLength;
				}
				else
				{
					logger->debug("Unable to decrypt package with known size is {} from {}", encryptedPayloadSize, sessionIdentifier);
					co_return 0;
				}
			}
			else
			{
				logger->debug("Unable to decrypt package from {}; Recieved {} bytes instead {} bytes", sessionIdentifier, received, payloadSizeToRead);
				co_return 0;
			}
		}
		else
		{
			logger->debug("Unable to decrypt payload size from {}", sessionIdentifier);
			co_return 0;
		}
	}
	else
	{
		logger->warn("Unable to decrypt package, recieved from: {}", sessionIdentifier);
		co_return 0;
	}
	*/
};

boost::asio::awaitable<void> SessionAsyncTCP::handleSessionHandshake()
{
	try
	{
		cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), recivedMessage);
		int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
		byte addressType = recovered[0];
		short addressLength = recovered[1];
		char* addressT = &recoveredMessage[2];
		remoteHostName = std::string(addressT, addressLength);

		short port = 0;
		std::memcpy(&port, recovered + addressLength + 2, 2);
		port = ntohs(port);

		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), remoteHostName, std::to_string(port));
		boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
		boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();
		remoteSocket.connect(endpoint);

		if (remoteSocket.is_open())
		{
			remoteIdentifier = endpoint.address().to_string().append(":").append(std::to_string(endpoint.port()));
			logger->info("Start session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			isEsteblished = true;
			co_await startMessageExchange();
		}
		else
		{
			logger->warn("Unable to session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			throw std::runtime_error("Unable to start session");
		}
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in handleSessionHandshake: {}", exception.what());
		throw std::exception(exception);
	}
	/*
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), recivedMessage);
	int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
	if (payloadLength > 0)
	{
		byte addressType = recovered[0];
		short addressLength = recovered[1];
		char* addressT = &recoveredMessage[2];
		remoteHostName = std::string(addressT, addressLength);

		short port = 0;
		std::memcpy(&port, recovered + addressLength + 2, 2);
		port = ntohs(port);

		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), remoteHostName, std::to_string(port));
		boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
		boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();
		remoteSocket.connect(endpoint);

		if (remoteSocket.is_open())
		{
			remoteIdentifier = endpoint.address().to_string().append(":").append(std::to_string(endpoint.port()));
			logger->info("Start session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			isEsteblished = true;
			co_await startMessageExchange();
		}
		else
		{
			logger->warn("Unable to session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
		}
	}
	else
	{
		logger->warn("Unable to session from: {}", sessionIdentifier);
	}
	co_return;
	*/
};

boost::asio::awaitable<void> SessionAsyncTCP::startMessageExchange()
{

	try
	{
		int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
		const auto executor = co_await boost::asio::this_coro::executor;
		boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initLocalToRemoteStream, this, payloadLength), boost::asio::detached);
		int receivedFormRemote = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), boost::asio::use_awaitable);
		co_await boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initRemoteToLocalStream, this, receivedFormRemote), boost::asio::use_awaitable);
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in startMessageExchange: {}", exception.what());
		throw std::exception(exception);
	}
	/*
	int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
	if (payloadLength > 0)
	{
		const auto executor = co_await boost::asio::this_coro::executor;
		boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initLocalToRemoteStream, this, payloadLength), boost::asio::detached);
		int receivedFormRemote = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), boost::asio::use_awaitable);
		if (receivedFormRemote > 0)
		{
			co_await boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::initRemoteToLocalStream, this, receivedFormRemote), boost::asio::use_awaitable);
		}
		else
		{
			closeSession();
		}
	}
	co_return;
	*/
};

boost::asio::awaitable<void> SessionAsyncTCP::initLocalToRemoteStream(int length)
{
	try
	{
		if (length > 0)
		{
			co_await remoteSocket.async_send(boost::asio::buffer(recoveredMessage, length), boost::asio::use_awaitable);
			co_await localToRemoteStream();
		}
		else
		{
			logger->error("Unable to start local to remote stream: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			throw std::runtime_error("Unable to start session");
		}
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in initLocalToRemoteStream: {}", exception.what());
		closeSession();
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::localToRemoteStream()
{
	logger->debug("Start local to remote stream: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	try
	{
		while (isEsteblished)
		{
			int payloadLength = co_await receiveAndDecryptChunk(recoveredMessage, socksSessionBufferSize);
			if (payloadLength > 0)
			{
				co_await remoteSocket.async_send(boost::asio::buffer(recoveredMessage, payloadLength), boost::asio::use_awaitable);
			}
			else
			{
				break;
			}
		}
		closeSession();
		logger->debug("Stop local to remote stream: {} X-> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	}
	catch (const Exception& exception)
	{
		std::cout << "localToRemoteStream" << std::endl;
		logger->critical("Exception caught in localToRemoteStream: {}", exception.what());
		closeSession();
		throw std::exception(exception);
	}

};

boost::asio::awaitable<void> SessionAsyncTCP::initRemoteToLocalStream(int length)
{
	try
	{
		if (length > 0)
		{
			char* addressAfterSalt = setSalt();
			int encryptedMessageLength = cryptoProvider->encrypt(addressAfterSalt, palinTextByte, length);
			co_await clientSocket.async_send(boost::asio::buffer(encryptedMessage, encryptedMessageLength + (int) 32), boost::asio::use_awaitable);
			co_await remoteToLocalStream();
		}
		else
		{
			logger->error("Unable to start remote to local stream: {} <- {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			throw std::runtime_error("Unable to start session");
		}
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in initRemoteToLocalStream: {}", exception.what());
		closeSession();
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::remoteToLocalStream()
{
	logger->debug("Start remote to local stream: {} <- {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	try
	{
		while (isEsteblished)
		{
			int received = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), boost::asio::use_awaitable);
			if (received > 0)
			{
				int encryptedMessageLength = cryptoProvider->encrypt(encryptedMessage, palinTextByte, received);
				co_await clientSocket.async_send(boost::asio::buffer(encryptedMessage, encryptedMessageLength), boost::asio::use_awaitable);
			}
			else
			{
				break;
			}
		}
		closeSession();
		logger->debug("Stop remote to local stream: {} <-X {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	}
	catch (const Exception& exception)
	{
		std::cout << "remoteToLocalStream" << std::endl;
		logger->critical("Exception caught in remoteToLocalStream: {}", exception.what());
		closeSession();
		throw std::exception(exception);
	}
	/*
	logger->debug("Start remote to local stream: {} <- {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	boost::system::error_code ec;
	int received = 0;

	while (isEsteblished)
	{
		std::tie(ec, received) = co_await remoteSocket.async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), completionToken);
		if (received > 0 && ec.value() == 0)
		{
			auto x = boost::asio::error::eof;
			int encryptedMessageLength = cryptoProvider->encrypt(encryptedMessage, palinTextByte, received);
			co_await clientSocket.async_send(boost::asio::buffer(encryptedMessage, encryptedMessageLength), boost::asio::use_awaitable);
		}
		else
		{
			break;
		}
	}
	closeSession();
	logger->debug("Stop remote to local stream: {} <-X {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	*/
};

char* SessionAsyncTCP::setSalt()
{
	char* SALT = new char[cryptoProvider->getSaltLength()];
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getEncryptor(), (byte*) SALT);
	std::memcpy(encryptedMessage, SALT, cryptoProvider->getSaltLength());
	return &(encryptedMessage[cryptoProvider->getSaltLength()]);
};

void SessionAsyncTCP::closeSession()
{
	if (isEsteblished)
	{
		isEsteblished = false;
		clientSocket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
		remoteSocket.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
		clientSocket.close();
		remoteSocket.close();
	}
	else
	{
		is_open = false;
		//delete this;
	}
};
