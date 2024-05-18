#pragma once
#include "SessionAsyncTCP.h"

using namespace boost::asio::experimental::awaitable_operators;

SessionAsyncTCP::SessionAsyncTCP(std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger, unsigned int timeout)
{
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
	if (timeout > 0)
	{
		this->timeout = std::chrono::seconds(timeout);
	}
	else
	{
		this->timeout = std::chrono::seconds(1);
	}
};

void SessionAsyncTCP::setClientSocket(boost::asio::ip::tcp::socket&& clientSocket)
{
	this->clientSocket = std::move(clientSocket);
}

void SessionAsyncTCP::changeClientSocketIoContext(boost::asio::io_context& ioContext)
{
	if (!clientSocket.has_value())
		std::runtime_error("Client socket must be seted before io context");

	auto fd = clientSocket->release();
	this->clientSocket.emplace(ioContext);
	clientSocket->assign(boost::asio::ip::tcp::v4(), fd);
}

void SessionAsyncTCP::resetTimeoutTimer()
{
	deadline = std::max(deadline, std::chrono::steady_clock::now() + timeout);
}


boost::asio::awaitable<void> SessionAsyncTCP::start()
{
	try
	{
		if (!clientSocket.has_value())
			throw std::runtime_error("Client socket is not seted");
		sessionIdentifier = clientSocket->remote_endpoint().address().to_string().append(":").append(std::to_string(clientSocket->remote_endpoint().port()));
		logger->info("Trying to start the session with client {}:{}...", clientSocket->remote_endpoint().address().to_string(), clientSocket->remote_endpoint().port());
		auto [errorCode, received] = co_await boost::asio::async_read(*clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(cryptoProvider->getSaltLength()), completionToken);

		if (errorCode)
			throw std::runtime_error("Can not receive salt");

		co_await (handleSessionHandshake() || watchdog());
		/*
		boost::asio::steady_timer timer(clientSocket->get_executor());
		timer.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(10));
		co_await timer.async_wait(completionToken);
		*/
	}
	catch (const std::exception& exception)
	{
		logger->warn("Unable to start session from {}:{}; Exception: {}", clientSocket->remote_endpoint().address().to_string(), clientSocket->remote_endpoint().port(), exception.what());
		closeSession();
		throw std::exception(exception);
	}
};

SessionAsyncTCP::~SessionAsyncTCP()
{
	logger->info("Stop proxy session: {} X<->X {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
};

std::string& SessionAsyncTCP::getSessionIdentifier()
{
	return sessionIdentifier;
};

boost::asio::awaitable<int> SessionAsyncTCP::encryptChunkAndSend(byte* sourceBuffer, int messageLength)
{
	try
	{
		byte payloadLengthBytesR[2];
		std::memcpy(payloadLengthBytesR, &messageLength, 2);
		byte payloadLengthBytes[2] = { payloadLengthBytesR[1], payloadLengthBytesR[0] };
		int encryptedPayloadLengthLength = cryptoProvider->encrypt(encrypted, payloadLengthBytes, 2);
		auto [ecL, sendL] = co_await clientSocket->async_send(boost::asio::buffer(encryptedMessage, encryptedPayloadLengthLength), completionToken);
		if (ecL)
			throw std::runtime_error("Unable to send encrypted payload length to client");

		int encryptedPayloadLength = cryptoProvider->encrypt(encrypted, sourceBuffer, messageLength);
		auto [ecP, sendP] = co_await clientSocket->async_send(boost::asio::buffer(encryptedMessage, encryptedPayloadLength), completionToken);
		if (ecP)
			throw std::runtime_error("Unable to send encrypted payload to client");

		co_return encryptedPayloadLength;
	}
	catch (const std::exception& exception)
	{
		logger->debug("Unable to handle shadowsocks package from {}; Exception: {}", sessionIdentifier, exception.what());
		throw std::exception(exception);
	}
}

boost::asio::awaitable<int> SessionAsyncTCP::receiveAndDecryptChunk(char* destenationBuffer, int destenationBufferSize)
{
	try
	{
		//recive payload length
		short payloadLengthAndTag = 2 + 16;
		auto [errorCode, received] = co_await boost::asio::async_read(*clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadLengthAndTag), completionToken);

		if (payloadLengthAndTag != received || errorCode)
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
		std::tie(errorCode, received) = co_await boost::asio::async_read(*clientSocket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadSizeToRead), completionToken);

		if (errorCode)
			throw std::length_error("Can not receive payload");

		int reReaderSize = 0;
		while (received < payloadSizeToRead)
		{
			std::tie(errorCode, reReaderSize) = co_await boost::asio::async_read(*clientSocket, boost::asio::buffer(&(clientToRemoteServerBuffer[0])+received, socksSessionBufferSize),
			boost::asio::transfer_exactly(payloadSizeToRead-received), completionToken);
			if (errorCode)
				throw std::length_error("Can not receive payload");
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
	catch (const std::runtime_error& exception)
	{
		logger->critical("{} from: {}", exception.what(), sessionIdentifier);
		throw std::exception(exception);
	}
	catch (const std::exception& exception)
	{
		logger->debug("Unable to handle shadowsocks package from {}; Exception: {}", sessionIdentifier, exception.what());
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::handleSessionHandshake()
{
	try
	{
		resetTimeoutTimer();
		cryptoProvider->prepareSubSessionKey(cryptoProvider->getDecryptor(), recivedMessage);
		int payloadLength = co_await receiveAndDecryptChunk(&(recoveredMessage[0]), socksSessionBufferSize);
		byte addressType = recovered[0];
		short addressLength = recovered[1];
		char* addressT = &recoveredMessage[2];
		remoteHostName = std::string(addressT, addressLength);

		short port = 0;
		std::memcpy(&port, recovered + addressLength + 2, 2);
		port = ntohs(port);

		boost::asio::ip::tcp::resolver resolver(clientSocket->get_executor());

		boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), remoteHostName, std::to_string(port));
		boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
		boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();

		this->remoteSocket.emplace(clientSocket->get_executor());
		remoteSocket->connect(endpoint);

		if (remoteSocket->is_open())
		{
			remoteIdentifier = endpoint.address().to_string().append(":").append(std::to_string(endpoint.port()));
			logger->info("Start session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			co_await (startMessageExchange() || watchdog());
		}
		else
		{
			logger->debug("Unable to session: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
			throw std::runtime_error("Unable to start session");
		}
	}
	catch (const std::exception& exception)
	{
		closeSession();
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::watchdog()
{
	boost::asio::steady_timer timer(clientSocket->get_executor());
	auto now = std::chrono::steady_clock::now();
	while (deadline > now)
	{
		timer.expires_at(deadline);
		co_await timer.async_wait(completionToken);
		now = std::chrono::steady_clock::now();
	}
}

boost::asio::awaitable<void> SessionAsyncTCP::startMessageExchange()
{
	try
	{
		resetTimeoutTimer();
		int payloadLength = co_await receiveAndDecryptChunk(&(recoveredMessage[0]), socksSessionBufferSize);

		auto [ecs, send] = co_await remoteSocket->async_send(boost::asio::buffer(recoveredMessage, payloadLength), completionToken);
		if (ecs)
			throw std::runtime_error("Unable to send first package to remote");

		auto [ecr, received]  = co_await remoteSocket->async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), completionToken);
		if (ecr || received <= 0)
			throw std::runtime_error("Unable to receive first response from remote");

		co_await (localToRemoteStream() || remoteToLocalStream(received) || watchdog());
	}
	catch (const std::exception& exception)
	{
		logger->debug("Unable to start message exchange in session {} <-> {} ({}); Exception: {}", sessionIdentifier, remoteIdentifier, remoteHostName, exception.what());
		closeSession();
		throw std::exception(exception);
	}
};

boost::asio::awaitable<void> SessionAsyncTCP::localToRemoteStream()
{
	logger->debug("Start local to remote stream: {} -> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
	try
	{
		while (isOpen)
		{
			resetTimeoutTimer();
			int payloadLength = co_await receiveAndDecryptChunk(&(recoveredMessage[0]), socksSessionBufferSize);

			auto [ec, send] = co_await remoteSocket->async_send(boost::asio::buffer(recoveredMessage, payloadLength), completionToken);
			if (ec)
				break;
		}
		logger->debug("Stop local to remote stream: {} X-> {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
		closeSession();
	}
	catch (const std::exception& exception)
	{
		logger->debug("Exeption in session: {} -> {} ({}); Exception: {}", sessionIdentifier, remoteIdentifier, remoteHostName, exception.what());
		closeSession();
		throw std::exception(exception);
	}

};

boost::asio::awaitable<void> SessionAsyncTCP::remoteToLocalStream(int length)
{
	try
	{
		char* addressAfterSalt = setSalt();
		auto [ec, send] = co_await clientSocket->async_send(boost::asio::buffer(encryptedMessage, cryptoProvider->getSaltLength()), completionToken);
		if (ec)
			throw std::runtime_error("Unable to transmit first package from remote to client");
		int sendedMessageLength = co_await encryptChunkAndSend(palinTextByte, length);
		while (isOpen)
		{
			resetTimeoutTimer();
			auto [ecr, received] = co_await remoteSocket->async_receive(boost::asio::buffer(remoteToClientServerBuffer, socksSessionBufferSize), completionToken);
			if (ecr || received <= 0)
				break;
			int sendedMessageLength = co_await encryptChunkAndSend(palinTextByte, received);
		}
		logger->debug("Stop remote to local stream: {} <-X {} ({})", sessionIdentifier, remoteIdentifier, remoteHostName);
		closeSession();
	}
	catch (const std::exception& exception)
	{
		logger->debug("Exeption in session: {} <- {} ({}); Exception: {}", sessionIdentifier, remoteIdentifier, remoteHostName, exception.what());
		closeSession();
		throw std::exception(exception);
	}
};

char* SessionAsyncTCP::setSalt()
{
	char* SALT = new char[cryptoProvider->getSaltLength()];
	cryptoProvider->prepareSubSessionKey(cryptoProvider->getEncryptor(), (byte*) SALT);
	std::memcpy(&(encryptedMessage[0]), SALT, cryptoProvider->getSaltLength());
	delete[] SALT;
	this->logger->trace("Encripted stream started with SALT: {:n}", spdlog::to_hex(&(encryptedMessage[0]), &(encryptedMessage[0]) + cryptoProvider->getSaltLength()));
	return &(encryptedMessage[cryptoProvider->getSaltLength()]);
};

void SessionAsyncTCP::closeSession()
{
	if (isOpen)
	{
		if (clientSocket.has_value())
		{
			clientSocket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			clientSocket->close();
		}
		if (remoteSocket.has_value())
		{
			remoteSocket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			remoteSocket->close();
		}
		isOpen = false;
		deadline = std::max(deadline, std::chrono::steady_clock::now());
	}
};
