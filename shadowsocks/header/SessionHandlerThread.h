//
// Created by neko on 5/7/24.
//

#ifndef SESSIONHANDLERTHREAD_H
#define SESSIONHANDLERTHREAD_H
#include <queue>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/logger.h>

#include "Session.h"
#endif //SESSIONHANDLERTHREAD_H


class SessionHandlerThread
{
public:
    SessionHandlerThread(int threadNumber, std::shared_ptr<spdlog::logger> logger);
    SessionHandlerThread(SessionHandlerThread&&);
    SessionHandlerThread(const SessionHandlerThread&);
    ~SessionHandlerThread();
    void initThread();
    void startSession(std::shared_ptr<Session> session);

private:
    int threadNumber;
    std::queue<std::shared_ptr<Session>> sessionQueue;
    std::shared_ptr<boost::asio::io_context> ioContext;
    boost::asio::as_tuple_t<boost::asio::use_awaitable_t<>> completionToken = as_tuple(boost::asio::use_awaitable);
    std::shared_ptr<spdlog::logger> logger;
    boost::asio::awaitable<void> waitSession();
    boost::asio::awaitable<void> runSession(std::shared_ptr<Session> session);
};
