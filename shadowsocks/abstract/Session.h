#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>


class Session
{
public:
	virtual boost::asio::awaitable<void> start() = 0;
	virtual void setClientSocket(boost::asio::ip::tcp::socket&& clientSocket) = 0;
	virtual void changeClientSocketIoContext(boost::asio::io_context& ioContext) = 0;
	virtual std::string& getSessionIdentifier() = 0;
};