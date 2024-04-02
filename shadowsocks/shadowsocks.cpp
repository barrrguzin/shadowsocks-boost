// shadowsocks.cpp : Defines the entry point for the application.
//
#include "shadowsocks.h"


boost::asio::io_context ioContext;
std::shared_ptr<spdlog::logger> logger = spdlog::stdout_color_mt("console");
int socksSessionBufferSize = 1350;
char clientToRemoteServerBuffer[1350];

void handler(boost::system::error_code error, std::size_t recvlen)
{
	CryptoPP::byte bytes[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	std::cout << *((int*) bytes) << std::endl;
	std::cout << "Readed" << std::endl;
}

void setAddress(std::string address, char* addressT, short addressLength)
{
	address = std::string(addressT, addressLength);
}

void setPort(int port, byte swapArray[])
{
	std::memcpy(&port, swapArray, 2);
}

void setInt(int src, int dst)
{
	src = dst;
}

boost::asio::awaitable<void> clientHandler(boost::asio::ip::tcp::socket socket)
{
	char pass[] = { '1','2','3' };
	byte* p = reinterpret_cast<byte*>(pass);
	char* recievedData = new char[socksSessionBufferSize + 100];
	std::string address;
	int port = 0;
	int recoveredPayloadLength = 0;
	
	ShadowSocksChaCha20Poly1305* cp = new ShadowSocksChaCha20Poly1305(p, sizeof(pass), logger);
	boost::asio::async_read(socket, boost::asio::buffer(clientToRemoteServerBuffer, socksSessionBufferSize), boost::asio::transfer_all(),
		[recievedData, cp, address, port, recoveredPayloadLength](boost::system::error_code ec, std::size_t length)
		{
			logger->trace("Message recieved: {}", length);
			byte* recovered = reinterpret_cast<byte*>(recievedData);
			int firstMessageOverhead = 32 + 2 + 16 + 16;
			byte* salt = reinterpret_cast<byte*>(clientToRemoteServerBuffer);
			cp->prepareSubSessionKey(cp->getDecryptor(), salt);
			byte* firstMessage = reinterpret_cast<byte*>(clientToRemoteServerBuffer + 32);
			int recoveredTargetAddressLength = cp->decrypt(recovered, firstMessage, length - 32);
			if (recoveredTargetAddressLength > 0)
			{
				byte addressType = recovered[0];
				short addressLength = recovered[1];
				logger->trace("Recieved: {}; Target address length: {}; Address bytes: {:n}", recoveredTargetAddressLength, addressLength, spdlog::to_hex(recovered, recovered + recoveredTargetAddressLength));
				char* addressT = &recievedData[2];
				std::string addr = std::string(addressT, addressLength);
				//setAddress(address, addressT, addressLength);
				byte swapArray[] = { recovered[addressLength + 2 + 1], recovered[addressLength + 2 + 0] };
				int portL = 0;
				std::memcpy(&(portL), swapArray, 2);
				//setPort(port, swapArray);
				byte* secondMessage = reinterpret_cast<byte*>(clientToRemoteServerBuffer + firstMessageOverhead + recoveredTargetAddressLength);
				int recoveredPayloadLengthT = cp->decrypt(recovered, secondMessage, length - firstMessageOverhead - recoveredTargetAddressLength);
				logger->info("Connecting to {}:{}", addr, portL);
				logger->trace("Message: {:n}", spdlog::to_hex(secondMessage, secondMessage + length - firstMessageOverhead - recoveredTargetAddressLength));
				//have address:port -> connect to dest
				boost::asio::ip::tcp::resolver resolver(ioContext);
				boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), addr, std::to_string(portL));
				boost::asio::ip::tcp::resolver::iterator endpoints = resolver.resolve(query);
				boost::asio::ip::tcp::endpoint endpoint = endpoints->endpoint();
				boost::asio::ip::tcp::socket remote(ioContext);
				remote.connect(endpoint);
				setInt(recoveredPayloadLength, recoveredPayloadLengthT);
			}
		}
	);

	//////////////////////////////////////////////////////////////////////////////////////////
	std::cout << "Get connection from port: " << socket.remote_endpoint().port() << std::endl;
	co_return;
}

boost::asio::awaitable<void> listen()
{
	const auto executor = co_await boost::asio::this_coro::executor;	
	boost::asio::ip::tcp::acceptor acceptor{ executor, {boost::asio::ip::tcp::v4(), 7777} };
	std::cout << "Start listening on port: " << acceptor.local_endpoint().port() << std::endl;
	for (;;)
	{
		boost::asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);
		boost::asio::co_spawn(executor, clientHandler(std::move(socket)), boost::asio::detached);
	}
}

int main()
{
	logger->set_level(spdlog::level::trace);
	boost::asio::co_spawn(ioContext, listen(), boost::asio::detached);
	ioContext.run();
	return 0;
}


