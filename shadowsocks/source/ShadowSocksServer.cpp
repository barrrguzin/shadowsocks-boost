#include "ShadowSocksServer.h"

#include <iostream>

#include "CryptoProviderFactory.h"


ShadowSocksServer::ShadowSocksServer(const char* pathToConfig)
{
	std::ifstream configFIle(pathToConfig);
	boost::property_tree::ptree pt;
	boost::property_tree::json_parser::read_json(configFIle, pt);
	auto instances = pt.get_child("instances");
	auto instance = instances.begin();

	std::string loggerType = pt.find("logger_type")->second.data();
	std::string logName = pt.find("log_name")->second.data();
	std::string logLevel = "info";
	if (pt.find("logger_level") != pt.not_found())
		logLevel = pt.find("logger_level")->second.data();
	int syslogChannel = 7;
	if (pt.find("syslog_channel") != pt.not_found())
		syslogChannel = std::stoi(pt.find("syslog_channel")->second.data());
	std::shared_ptr<spdlog::logger> logger = initLogger(logLevel, loggerType, syslogChannel , logName);

	while (instance != instances.end())
	{
		try
		{
			auto fields = instance->second;

			std::string listenerAddress = fields.find("server")->second.data();
			int listenerPort = 1080;
			if (fields.find("server_port") != fields.not_found())
				listenerPort = std::stoi(fields.find("server_port")->second.data());

			//std::string cypheType = instance->second.find("cypher_type")->second.data();
			std::string password = fields.find("password")->second.data();

			int threadNumber = 1;
			if (fields.find("threads") != fields.not_found())
				threadNumber = std::stoi(fields.find("threads")->second.data());
			int timeout = 60;
			if (fields.find("timeout") != fields.not_found())
				timeout = std::stoi(fields.find("timeout")->second.data());

			auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(listenerAddress), listenerPort);
			std::shared_ptr<CryptoProvider> cryptoProvider = initCryptoProvider(password, Cypher::ChaCha20Poly1305, logger);
			std::shared_ptr<Listener> listener = initListener(std::move(endpoint), threadNumber, timeout, std::move(cryptoProvider), logger);
			threads.emplace_back(boost::thread(boost::bind(&Listener::startListener, listener)));
			logger->trace("Listener started; Logger UC: {}", logger.use_count());

			instance++;
		} catch (std::exception& exception)
		{
			std::cerr << "Unable to parse listener configuration. Trying next one if exists..." << std::endl;
			instance++;
		}
	}
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

std::shared_ptr<spdlog::logger> ShadowSocksServer::initLogger(std::string logLevel, std::string loggerType, int syslogNumber, std::string logName)
{
	std::shared_ptr<spdlog::logger> logger;
	if (loggerType == "syslog")
	{
		logger = spdlog::syslog_logger_mt("syslog", logName, syslogNumber);
		std::cout << "Logging into syslog. Level: " << logLevel << "; Identificator: " << logName << "; Channel: " << syslogNumber << std::endl;
	}
	else if (loggerType == "basic_logger")
	{
		logger = spdlog::basic_logger_mt("basic_logger", logName);
		std::cout << "Logging into file. Level: " << logLevel << "; File: " << logName << std::endl;
	}
	else if	(loggerType == "console")
	{
		logger = spdlog::stdout_color_mt("console");
		std::cout << "Logging into stdout. Level: " << logLevel << std::endl;
	}
	else
	{
		logger = spdlog::syslog_logger_mt("syslog", "shadowsocks", LOG_LOCAL7);
		std::cout << "Logging into syslog. Level: " << logLevel << "; Identificator: shadowsocks; Channel: " << syslogNumber << std::endl;
	}
	logger->set_level(spdlog::level::from_str(logLevel));
	return logger;
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
