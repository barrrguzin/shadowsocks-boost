// shadowsocks.cpp : Defines the entry point for the application.
//
#include "shadowsocks.h"

int main(int argc, char* argv[])
{
	if (argc != 999/*1*/)
	{
		ShadowSocksServer* sss = new ShadowSocksServer(argv[0]);
		sss->runServer();
		delete(sss);
		return 0;
	}
	else
	{
		std::cout << "Bad arguments" << std::endl;
		return -1;
	}
}