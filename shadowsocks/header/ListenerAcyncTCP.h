

#include "Listener.h"
#include "ShadowSocksChaCha20Poly1305.h"
#include "Session.h"
#include "SessionAsyncTCP.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

class ListenerAcyncTCP : public Listener
{
public:
	ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	~ListenerAcyncTCP();
	void startListener() override;

private:
	unsigned long sessionCounter = 0;
	std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider;
	std::shared_ptr<spdlog::logger> logger;
	boost::asio::ip::tcp::endpoint localEndpoint;
	std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
	std::shared_ptr<boost::asio::io_context> ioContext;

	boost::asio::awaitable<void> startAcceptor();
	std::shared_ptr<Session> initiateSession(std::shared_ptr<ShadowSocksChaCha20Poly1305> cryptoProvider, std::shared_ptr<spdlog::logger> logger);
	boost::asio::awaitable<void> handleSession(std::shared_ptr<Session> sessionToStart);
};