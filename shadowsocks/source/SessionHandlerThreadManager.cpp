#include "SessionHandlerThreadManager.h"

SessionHandlerThreadManager::SessionHandlerThreadManager(unsigned short numberOfWorkers, std::shared_ptr<spdlog::logger> logger)
{
    this->logger = logger;
    this->workers = std::vector<SessionHandlerThread>();
    this->workers.reserve(numberOfWorkers);
    for (int numberOfThread = 0; numberOfThread < numberOfWorkers; numberOfThread++)
    {
        workers.emplace_back(numberOfThread, logger);
        threads.emplace_back(boost::thread(boost::bind(&SessionHandlerThread::initThread, &(workers[numberOfThread]))));
    }
}

void SessionHandlerThreadManager::runSession(std::shared_ptr<Session> session)
{
    if (nextThreadCounter == workers.size())
        nextThreadCounter = 0;
    workers[nextThreadCounter].startSession(std::move(session));
    nextThreadCounter++;
}
