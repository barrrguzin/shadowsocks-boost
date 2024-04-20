#include "ListenerAcyncTCP.h"

ListenerAcyncTCP::ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	this->localEndpoint = endpoint;
	this->cryptoProvider = cryptoProvider;
	this->logger = logger;
	this->logger->trace("Listener constructor passed");
};

ListenerAcyncTCP::~ListenerAcyncTCP()
{
	std::cout << "-----------------------------------------------ListenerAcyncTCP------------------------------------------" << std::endl;
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
	const auto executor = co_await boost::asio::this_coro::executor;
	this->acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(executor, localEndpoint);
	for (;;)
	{
		this->logger->warn("iteration start");
		std::shared_ptr<SessionAsyncTCP> session = initiateSession(cryptoProvider, ioContext, logger);
		session->getClientSocket() = co_await this->acceptor->async_accept(boost::asio::use_awaitable);
		sessions.push_back(session);
		boost::asio::co_spawn(executor, boost::bind(&SessionAsyncTCP::start, session), boost::asio::detached);
	}
	
};

void ListenerAcyncTCP::handleConnection(std::shared_ptr<SessionAsyncTCP> sessionToStart)
{
	//const auto executor = co_await boost::asio::this_coro::executor;
	//boost::asio::spawn(executor, boost::bind(&SessionAsyncTCP::start, sessionToStart), boost::asio::detached);
	sessionToStart->start();
	std::shared_ptr<SessionAsyncTCP> session = initiateSession(cryptoProvider, ioContext, logger);
	sessions.push_back(session);
	this->acceptor->async_accept(session->getClientSocket(), boost::bind(&ListenerAcyncTCP::handleConnection, this, boost::ref(session)));
};

std::shared_ptr<SessionAsyncTCP> ListenerAcyncTCP::initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger)
{
	byte* passwordBytes = reinterpret_cast<byte*>((char*)"123");
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cp(new ShadowSocksChaCha20Poly1305(passwordBytes, 3, logger));
	return std::make_shared<SessionAsyncTCP>(cp, ioContext, logger);
};