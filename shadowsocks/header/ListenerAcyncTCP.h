

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
#include <boost/asio/placeholders.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

class ListenerAcyncTCP : public Listener, public boost::enable_shared_from_this<ListenerAcyncTCP>
{
public:
	ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	~ListenerAcyncTCP();
	void startListener();

	void removeSession(Session* session) override;

private:
	void clearSessions();
	void handler(boost::system::error_code ec);

	boost::asio::awaitable<void> handleSession(std::shared_ptr<SessionAsyncTCP> sessionToStart);

	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;

	std::shared_ptr<spdlog::logger> logger;

	boost::asio::ip::tcp::endpoint localEndpoint;
	boost::asio::ip::tcp::endpoint remoteEndpoint;

	std::map<std::string, std::shared_ptr<SessionAsyncTCP>> sessions;

	//boost::asio::ip::tcp::acceptor* acc;
	//std::shared_ptr<boost::asio::ip::tcp::acceptor> acc;
	std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;

	std::shared_ptr<boost::asio::io_context> ioContext;

	std::shared_ptr<SessionAsyncTCP> initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, boost::asio::io_context& ioContext, std::shared_ptr<spdlog::logger> logger);

	boost::asio::awaitable<void> startAcceptor();
};