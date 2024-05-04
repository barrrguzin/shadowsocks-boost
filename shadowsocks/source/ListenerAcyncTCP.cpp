#include "ListenerAcyncTCP.h"

#include <boost/bind/bind.hpp>

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
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

boost::asio::awaitable<void> ListenerAcyncTCP::startAcceptor()
{
	this->logger->trace("startAcceptor called");
	const auto executor = co_await boost::asio::this_coro::executor;
	this->acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(executor, localEndpoint);

	boost::asio::ip::tcp::resolver resolver(executor);

	for (;;)
	{
		std::shared_ptr<Session> session = initiateSession(cryptoProvider, &resolver, logger);
		session->setClientSocket(std::move(std::make_shared<boost::asio::ip::tcp::socket>(co_await this->acceptor->async_accept(boost::asio::use_awaitable))));
		boost::asio::co_spawn(executor, boost::bind(&ListenerAcyncTCP::handleSession, this, std::move(session)), boost::asio::detached);
	}
};

boost::asio::awaitable<void> ListenerAcyncTCP::handleSession(std::shared_ptr<Session> sessionToStart)
{
	try
	{
		sessionCounter++;
		this->logger->critical("Session number: {}", sessionCounter);
		const auto executor = co_await boost::asio::this_coro::executor;
		co_await boost::asio::co_spawn(executor, boost::bind(&Session::start, sessionToStart), boost::asio::use_awaitable);
		sessionCounter--;
		this->logger->critical("Session number: {}", sessionCounter);
	}
	catch (const Exception& exception)
	{
		sessionCounter--;
		logger->critical("Exception caught in handleSession: {}", exception.what());
	}
};

std::shared_ptr<Session> ListenerAcyncTCP::initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::ip::tcp::resolver* resolver, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*)"123");
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cp(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
	std::shared_ptr<Session> sessionPointer = std::make_shared<SessionAsyncTCP>(cp, resolver, logger);
	return sessionPointer;
};