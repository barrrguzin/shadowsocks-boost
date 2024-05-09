#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>


class Session
{
public:
	virtual boost::asio::awaitable<void> start() = 0;
	virtual void setClientSocket(std::shared_ptr<boost::asio::ip::tcp::socket> clientSocket) = 0;
	virtual void setIoContext(std::shared_ptr<boost::asio::io_context> ioContext) = 0;
	virtual std::string& getSessionIdentifier() = 0;
};