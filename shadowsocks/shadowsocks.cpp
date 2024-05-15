#include "shadowsocks.h"

int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		ShadowSocksServer* sss = new ShadowSocksServer(argv[1]);
		sss->runServer();
		delete(sss);
		return 0;
	}
	else
	{
		std::cerr << "Bad arguments. Example: " << argv[0] << " /path/to/configuration/file.json" << std::endl;
		return -1;
	}
}