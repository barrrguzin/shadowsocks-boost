#include "ListenerAcyncTCP.h"

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
	this->logger->trace("Listener constructor passed");
	ioContext = std::make_shared<boost::asio::io_context>();
};

ListenerAcyncTCP::~ListenerAcyncTCP()
{

};

void ListenerAcyncTCP::startListener()
{
	this->logger->trace("Listener start");
	boost::asio::co_spawn(*ioContext, boost::bind(&ListenerAcyncTCP::startAcceptor, this), boost::asio::detached);
	ioContext->run();
};

void ListenerAcyncTCP::clearSessions()
{
	logger->critical("Before: {}", sessions.size());
	for (const auto& [key, value] : sessions)
	{
		try
		{
			if (!(value->isOpen()))
			{
				sessions.erase(key);
			}
		} catch (Exception ex)
		{
			logger->critical("excp");
		}

	}
	logger->critical("After: {}", sessions.size());
}

boost::asio::awaitable<void> ListenerAcyncTCP::startAcceptor()
{
	this->logger->trace("startAcceptor called");
	const auto executor = co_await boost::asio::this_coro::executor;
	this->acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(executor, localEndpoint);
	for (;;)
	{
		this->logger->warn("iteration start");
		std::shared_ptr<SessionAsyncTCP> session = initiateSession(cryptoProvider, *ioContext, logger);
		session->getClientSocket() = co_await this->acceptor->async_accept(boost::asio::use_awaitable);

		boost::asio::ip::tcp::endpoint clientEndpoint = session->getClientSocket().remote_endpoint();
		session->getSessionIdentifier() = clientEndpoint.address().to_string().append(":").append(std::to_string(clientEndpoint.port()));

		//sessions.insert({session->getSessionIdentifier(), session});
		boost::asio::co_spawn(executor, boost::bind(&ListenerAcyncTCP::handleSession, this, std::move(session)), boost::asio::detached);
	}
};

void ListenerAcyncTCP::handler(boost::system::error_code ec)
{
	logger->critical("hello from handler {}", ec.message());
}

void ListenerAcyncTCP::removeSession(Session* session)
{
	logger->critical("REMOVE");
	int before = sessions.size();
	logger->critical(session->getSessionIdentifier());
	sessions.erase(session->getSessionIdentifier());
	logger->critical("Remove session called: Sessions before {}; Sessions after {}", before, sessions.size());
};

boost::asio::awaitable<void> ListenerAcyncTCP::handleSession(std::shared_ptr<SessionAsyncTCP> sessionToStart)
{
	try
	{
		const auto executor = co_await boost::asio::this_coro::executor;
		co_await boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::start, sessionToStart), boost::asio::use_awaitable);
		logger->critical("DET");
	}
	catch (const Exception& exception)
	{
		logger->critical("Exception caught in handleSession: {}", exception.what());
	}
};

std::shared_ptr<SessionAsyncTCP> ListenerAcyncTCP::initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*)"123");
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cp(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
	return std::make_shared<SessionAsyncTCP>(cp, *(this->ioContext), logger);
};