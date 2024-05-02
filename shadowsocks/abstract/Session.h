#pragma once

#include <boost/asio/ip/tcp.hpp>

class Session
{
public:
	void start();
	virtual boost::asio::ip::tcp::socket& getClientSocket() = 0;
	virtual std::string& getSessionIdentifier() = 0;
	virtual const bool& isOpen() = 0;
};