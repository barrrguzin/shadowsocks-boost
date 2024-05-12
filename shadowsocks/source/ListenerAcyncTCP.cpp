#include "ListenerAcyncTCP.h"

#include <boost/bind/bind.hpp>


ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, SessionHandlerThreadManager sessionHandlerThreadManager, std::shared_ptr<CryptoProvider> cryptoProviderPrototype, std::shared_ptr<spdlog::logger> logger)
	:sessionHandlerThreadManager(std::move(sessionHandlerThreadManager))
{
	this->localEndpoint = std::move(endpoint);
	this->cryptoProviderPrototype = std::move(cryptoProviderPrototype);
	this->cryptoProviderPrototype->isPrototype() = true;
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
	for (;;)
	{
		std::shared_ptr<Session> session = initiateSession();
		session->setClientSocket(std::move(co_await acceptor.async_accept(boost::asio::use_awaitable)));
		sessionHandlerThreadManager.runSession(std::move(session));
	}
};

std::shared_ptr<Session> ListenerAcyncTCP::initiateSession()
{
	return std::make_shared<SessionAsyncTCP>(std::move(cryptoProviderPrototype->clone()), logger);
};