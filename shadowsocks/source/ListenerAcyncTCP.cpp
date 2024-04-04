#include "ListenerAcyncTCP.h"

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
};

void ListenerAcyncTCP::startListener()
{
	boost::asio::co_spawn(*ioContext, boost::bind(&ListenerAcyncTCP::listen, this), boost::asio::detached);
	ioContext->run();
};

boost::asio::awaitable<void> ListenerAcyncTCP::listen()
{
	const auto executor = co_await boost::asio::this_coro::executor;
	boost::asio::ip::tcp::acceptor acceptor{ executor, localEndpoint };
	for (;;)
	{
		//https://habr.com/ru/articles/195794/
		boost::asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);	
		boost::asio::co_spawn(executor, boost::bind(&ListenerAcyncTCP::initiateSession, this, std::move(socket)), boost::asio::detached);
	}
};

boost::asio::awaitable<void> ListenerAcyncTCP::initiateSession(boost::asio::ip::tcp::socket socket)
{
	std::shared_ptr<Session> session = std::make_shared<Session>(new SessionAsyncTCP(std::move(socket), cryptoProvider, ioContext, logger));
};