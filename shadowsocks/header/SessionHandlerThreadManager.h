#ifndef SessionHandlerThreadManager_H
#define SessionHandlerThreadManager_H
#include <memory>
#include <boost/thread/thread.hpp>

#include "Session.h"
#include "SessionHandlerThread.h"

#endif //SessionHandlerThreadManager_H


class SessionHandlerThreadManager
{

public:
    SessionHandlerThreadManager(unsigned short numberOfWorkers, std::shared_ptr<spdlog::logger> logger);
    void runSession(std::shared_ptr<Session> session);

private:
    int nextThreadCounter = 0;
    bool ready = false;
    std::shared_ptr<spdlog::logger> logger;
    std::vector<boost::thread> threads;
    std::shared_ptr<std::vector<std::shared_ptr<SessionHandlerThread>>> workers;
};

