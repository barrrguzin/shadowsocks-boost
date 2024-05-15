#include "Listener.h"
#include "ShadowSocksChaCha20Poly1305.h"
#include "Session.h"
#include "SessionAsyncTCP.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "SessionHandlerThreadManager.h"

class ListenerAcyncTCP : public Listener
{
public:
	ListenerAcyncTCP(boost::asio::ip::tcp::endpoint endpoint, SessionHandlerThreadManager sessionHandlerThreadManager, std::shared_ptr<CryptoProvider> cryptoProviderPrototype, std::shared_ptr<spdlog::logger> logger, unsigned short sessionTimeout = 60);
	~ListenerAcyncTCP();
	void startListener() override;

private:
	unsigned short sessionTimeout;
	unsigned long sessionCounter = 0;
	boost::asio::ip::tcp::endpoint localEndpoint;
	boost::asio::io_context ioContext;
	SessionHandlerThreadManager sessionHandlerThreadManager;

	std::shared_ptr<CryptoProvider> cryptoProviderPrototype;
	std::shared_ptr<spdlog::logger> logger;

	boost::asio::awaitable<void> startAcceptor();
	std::shared_ptr<Session> initiateSession();
};
