#include "ListenerAcyncTCP.h"

#include <boost/bind/bind.hpp>

#include "SessionHandlerThreadManager.h"

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
};

ListenerAcyncTCP::~ListenerAcyncTCP()
{

};


void ListenerAcyncTCP::startListener()
{
	this->logger->trace("Listener start");
	boost::asio::co_spawn(ioContext, boost::bind(&ListenerAcyncTCP::startAcceptor, this), boost::asio::detached);
	ioContext.run();
};

boost::asio::awaitable<void> ListenerAcyncTCP::startAcceptor()
{
	this->logger->trace("startAcceptor called");
	boost::asio::ip::tcp::acceptor acceptor = boost::asio::ip::tcp::acceptor(ioContext.get_executor(), localEndpoint);
	SessionHandlerThreadManager* shtm = new SessionHandlerThreadManager(10, logger);
	for (;;)
	{
		std::shared_ptr<Session> session = initiateSession(cryptoProvider, logger);
		session->setClientSocket(std::move(co_await acceptor.async_accept(boost::asio::use_awaitable)));

		shtm->runSession(std::move(session));
	}
};

boost::asio::awaitable<void> ListenerAcyncTCP::handleSession(std::shared_ptr<Session> sessionToStart)
{
	try
	{
		sessionCounter++;
		this->logger->critical("Session number: {}", sessionCounter);
		co_await boost::asio::co_spawn(ioContext.get_executor(), boost::bind(&Session::start, sessionToStart), boost::asio::use_awaitable);
		sessionCounter--;
		this->logger->critical("Session number: {}", sessionCounter);
	}
	catch (const std::exception& exception)
	{
		sessionCounter--;
		logger->critical("Exception caught in handleSession: {}", exception.what());
	}
};

std::shared_ptr<Session> ListenerAcyncTCP::initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*)"123");
	//std::shared_ptr<ShadowSocksChaCha20Poly1305> cp(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cp = std::make_shared<ShadowSocksChaCha20Poly1305>(passwordBytes, 3, logger);
	std::shared_ptr<Session> sessionPointer = std::make_shared<SessionAsyncTCP>(std::move(cp), logger);
	return sessionPointer;
};