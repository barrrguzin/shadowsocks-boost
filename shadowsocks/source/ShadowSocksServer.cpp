#include "ShadowSocksServer.h"

#include "CryptoProviderFactory.h"


ShadowSocksServer::ShadowSocksServer(const char* pathToConfig)
{
	initLogger();
	//std::stringstream ss;
	//ss << "{\"instances\": [{\"server\": \"127.0.0.1\", \"server_port\": 7777, \"password\": \"123\", \"threads\": 10, \"timeout\": 60}]}";

	std::ifstream configFIle(pathToConfig);
	boost::property_tree::ptree pt;
	boost::property_tree::json_parser::read_json(configFIle, pt);
	auto instances = pt.get_child("instances");
	auto instance = instances.begin();
	while (instance != instances.end())
	{
		try
		{
			//std::string instanceType = instance->second.find("instance_type")->second.data();

			std::string listenerAddress = instance->second.find("server")->second.data();
			int listenerPort = std::stoi(instance->second.find("server_port")->second.data());

			//std::string cypheType = instance->second.find("cypher_type")->second.data();
			std::string password = instance->second.find("password")->second.data();

			int threadNumber = std::stoi(instance->second.find("threads")->second.data());
			int timeout = std::stoi(instance->second.find("timeout")->second.data());

			//std::string loggerType = instance->second.find("logger_type")->second.data();
			//std::string loggerPath = instance->second.find("logger_path")->second.data();

			auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(listenerAddress), listenerPort);
			std::shared_ptr<CryptoProvider> cryptoProvider = initCryptoProvider(password, Cypher::ChaCha20Poly1305, logger);
			std::shared_ptr<Listener> listener = initListener(std::move(endpoint), threadNumber, timeout, std::move(cryptoProvider), logger);
			threads.emplace_back(boost::thread(boost::bind(&Listener::startListener, listener)));
			logger->trace("Listener started; Logger UC: {}", logger.use_count());

			instance++;
		} catch (std::exception& exception)
		{
			instance++;
		}
	}



	/*
	auto endpointTemp = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 7777);
	endpoints.push_back(endpointTemp);
	for (boost::asio::ip::tcp::endpoint endpoint : endpoints)
	{
		std::string pass("123");
		std::shared_ptr<CryptoProvider> cryptoProvider = initCryptoProvider(pass, Cypher::ChaCha20Poly1305, logger);
		std::shared_ptr<Listener> listener = initListener(std::move(endpoint), 10, std::move(cryptoProvider), logger);
		threads.emplace_back(boost::thread(boost::bind(&Listener::startListener, listener)));
		logger->trace("Listener started; Logger UC: {}", logger.use_count());
	}
	 */
};

template<typename T>
std::optional<T> ShadowSocksServer::getValueFromConfig(boost::json::object config, const std::string &key)
{
	boost::json::object::iterator value = config.find(key);
	if (value != nullptr)
	{
		if (std::is_same<T, std::string>::value)
			return std::string(value->value().as_string().c_str());
		if (std::is_same<T, int>::value)
			return (T) value->value().as_int64();
		if (std::is_same<T, bool>::value)
			return (T) value->value().as_bool();
		if (std::is_same<T, boost::json::array>::value)
			return (T) value->value().as_array();
		if (std::is_same<T, boost::json::object>::value)
			return (T) value->value().as_object();
	}
	throw std::runtime_error("Passed return value type is not supported");
}

ShadowSocksServer::~ShadowSocksServer()
{

};

void ShadowSocksServer::initLogger()
{
	logger = spdlog::stdout_color_mt("console");
	logger->set_level(spdlog::level::debug);
	logger->trace("Logger inited");
};

void ShadowSocksServer::runServer()
{
	for (int i = 0; i < threads.size(); i++)
	{
		threads[i].join();
	}
};

std::shared_ptr<Listener> ShadowSocksServer::initListener(boost::asio::ip::tcp::endpoint endpoint, unsigned short numberOfThreads, unsigned short sessionTimeout, std::shared_ptr<CryptoProvider> cryptoProvider, std::shared_ptr<spdlog::logger> logger)
{
	return std::make_shared<ListenerAcyncTCP>(endpoint, std::move(SessionHandlerThreadManager(numberOfThreads, logger)), cryptoProvider, logger, sessionTimeout);
}

std::shared_ptr<CryptoProvider> ShadowSocksServer::initCryptoProvider(std::string password, Cypher type,
	std::shared_ptr<spdlog::logger> logger)
{
	return CryptoProviderFactory::getCryptoProvider(type, password.c_str(), password.size(), logger);;
};
