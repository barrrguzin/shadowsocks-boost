#pragma once

#include <boost/asio/ip/tcp.hpp>

class Session
{
public:
	void start();
	boost::asio::ip::tcp::socket& getClientSocket();
};