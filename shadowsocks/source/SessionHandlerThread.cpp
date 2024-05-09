#include "SessionHandlerThread.h"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/bind/bind.hpp>


SessionHandlerThread::SessionHandlerThread(int threadNumber, std::shared_ptr<spdlog::logger> logger) //: threadNumber(threadNumber), logger(logger)
{
    this->threadNumber = threadNumber;
    this->logger = logger;
    ioContext = std::make_shared<boost::asio::io_context>();
}

SessionHandlerThread::SessionHandlerThread(SessionHandlerThread &&)
{
}

SessionHandlerThread::SessionHandlerThread(const SessionHandlerThread &)
{
}

SessionHandlerThread::~SessionHandlerThread()
{
    logger->critical("THREAD DESTR");
}

void SessionHandlerThread::initThread()
{
    boost::asio::co_spawn(*ioContext, boost::bind(&SessionHandlerThread::waitSession, this), boost::asio::detached);
    ioContext->run();
    logger->critical("CONTEXT RETURND");
}

void SessionHandlerThread::startSession(std::shared_ptr<Session> session)
{
    session->setIoContext(ioContext);
    sessionQueue.emplace(std::move(session));
}

boost::asio::awaitable<void> SessionHandlerThread::waitSession()
{
    const auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    auto now = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point deadline;
    std::chrono::seconds timeout = std::chrono::seconds(1);
    while (true)
    {
        if (sessionQueue.empty())
        {
            timer.expires_at(deadline);
            co_await timer.async_wait(completionToken);
            now = std::chrono::steady_clock::now();
            deadline = std::max(deadline, std::chrono::steady_clock::now() + timeout);

        }
        else
        {
            boost::asio::co_spawn(executor, boost::bind(&SessionHandlerThread::runSession, this, std::move(sessionQueue.front())), boost::asio::detached);
            sessionQueue.pop();
        }

    }
}

boost::asio::awaitable<void> SessionHandlerThread::runSession(std::shared_ptr<Session> session)
{
    try
    {
        const auto executor = co_await boost::asio::this_coro::executor;
        co_await boost::asio::co_spawn(executor, boost::bind(&Session::start, session), boost::asio::use_awaitable);
    }
    catch (const std::exception& exception)
    {
        logger->critical("T{}; Exception caught in runSession: {}", threadNumber, exception.what());
    }
}




