#include "Listener.h"
#include "ShadowSocksChaCha20Poly1305.h"
#include "Session.h"
#include "SessionAsyncTCP.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>

#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/spdlog.h"

class ListenerAcyncTCP : public Listener, public boost::enable_shared_from_this<ListenerAcyncTCP>
{
public:
	ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	/*
	ListenerAcyncTCP(ListenerAcyncTCP& o);
	ListenerAcyncTCP(ListenerAcyncTCP&& o);
	*/
	boost::asio::awaitable<void> startListener();
	void handleConnection(SessionAsyncTCP session);

private:
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;

	std::shared_ptr<spdlog::logger> logger;

	boost::asio::ip::tcp::endpoint localEndpoint;
	boost::asio::ip::tcp::endpoint remoteEndpoint;

	std::shared_ptr<boost::asio::ip::tcp::acceptor> acc;

	std::shared_ptr<boost::asio::io_context> ioContext;

	boost::asio::awaitable<void> listen();
	boost::asio::awaitable<void> initiateSession(boost::asio::ip::tcp::socket socket);
};