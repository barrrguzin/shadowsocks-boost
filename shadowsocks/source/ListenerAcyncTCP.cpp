#include "ListenerAcyncTCP.h"

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
};
/*
ListenerAcyncTCP::ListenerAcyncTCP(ListenerAcyncTCP& o)
{

};

ListenerAcyncTCP::ListenerAcyncTCP(ListenerAcyncTCP&& o)
{

};
*/
boost::asio::awaitable<void> ListenerAcyncTCP::startListener()
{
	const auto executor = co_await boost::asio::this_coro::executor;
	boost::asio::ip::tcp::acceptor acceptor{ executor, localEndpoint };
	*(this->acc) = std::move(acceptor);

	SessionAsyncTCP x = SessionAsyncTCP(cryptoProvider, ioContext, logger);
	this->acc->async_accept(x.getClientSocket(), boost::bind(&ListenerAcyncTCP::handleConnection, this, boost::ref(x)));
	ioContext->run();
};

void ListenerAcyncTCP::handleConnection(SessionAsyncTCP session)
{
	session.start();
	SessionAsyncTCP x = SessionAsyncTCP(cryptoProvider, ioContext, logger);
	this->acc->async_accept(x.getClientSocket(), boost::bind(&ListenerAcyncTCP::handleConnection, this, boost::ref(x)));
};

boost::asio::awaitable<void> ListenerAcyncTCP::listen()
{
	/*
	const auto executor = co_await boost::asio::this_coro::executor;
	boost::asio::ip::tcp::acceptor acceptor{ executor, localEndpoint };

	for (;;)
	{
		//https://habr.com/ru/articles/195794/
		boost::asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);
		std::shared_ptr<SessionAsyncTCP> session = std::make_shared<SessionAsyncTCP>(new SessionAsyncTCP(std::move(socket), cryptoProvider, ioContext, logger));
		boost::asio::co_spawn(executor, boost::bind(&ListenerAcyncTCP::initiateSession, this, std::move(socket)), boost::asio::detached);
	}
	*/
	co_return;
};

boost::asio::awaitable<void> ListenerAcyncTCP::initiateSession(boost::asio::ip::tcp::socket socket)
{
	//std::shared_ptr<SessionAsyncTCP> session = std::make_shared<SessionAsyncTCP>(new SessionAsyncTCP(std::move(socket), cryptoProvider, ioContext, logger));
	co_return;
};