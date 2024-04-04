#include "Listener.h"
#include "CryptoProvider.h"
#include "Session.h"
#include "SessionAsyncTCP.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/bind.hpp>

#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/spdlog.h"

class ListenerAcyncTCP : public Listener
{
public:
	ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger);

	void startListener();

private:
	std::shared_ptr<CryptoProvider> cryptoProvider;

	std::shared_ptr<spdlog::logger> logger;

	boost::asio::ip::tcp::endpoint localEndpoint;
	boost::asio::ip::tcp::endpoint remoteEndpoint;


	std::shared_ptr<boost::asio::io_context> ioContext;

	boost::asio::awaitable<void> listen();
	boost::asio::awaitable<void> initiateSession(boost::asio::ip::tcp::socket socket);
};