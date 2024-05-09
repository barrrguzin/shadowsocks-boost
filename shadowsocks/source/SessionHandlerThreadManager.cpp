#include "SessionHandlerThreadManager.h"

SessionHandlerThreadManager::SessionHandlerThreadManager(unsigned short numberOfWorkers, std::shared_ptr<spdlog::logger> logger)
{
    this->logger = logger;
    this->workers = std::make_shared<std::vector<std::shared_ptr<SessionHandlerThread>>>();
    for (std::vector<SessionHandlerThread>::size_type i = 0; i < numberOfWorkers; i++)
    {
        logger->warn(i);
        std::shared_ptr<SessionHandlerThread> tmp = std::make_shared<SessionHandlerThread>(i, logger);
        workers->push_back(tmp);
        threads.emplace_back(boost::thread(boost::bind(&SessionHandlerThread::initThread, tmp)));
    }

    for (std::vector<SessionHandlerThread>::size_type i = 0; i < numberOfWorkers; i++)
    {
        //threads.emplace_back(boost::thread(boost::bind(&SessionHandlerThread::initThread, workers->at(i))));
    }
    ready = true;
}

void SessionHandlerThreadManager::runSession(std::shared_ptr<Session> session)
{
    if (ready)
    {
        if (nextThreadCounter == workers->size())
            nextThreadCounter = 0;
        (*workers)[nextThreadCounter]->startSession(std::move(session));
        logger->critical("session seted in queue in thread {}", nextThreadCounter);
        nextThreadCounter++;
    }
}
