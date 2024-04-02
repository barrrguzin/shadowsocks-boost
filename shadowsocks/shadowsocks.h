// shadowsocks.h : Include file for standard system include files,
// or project specific include files.
#pragma once
// TODO: Reference additional headers your program requires here.
#include "header/ShadowSocksChaCha20Poly1305.h"

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/placeholders.hpp>
#include <thread>
#include <iostream>

#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/spdlog.h"
#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/sinks/stdout_color_sinks.h"
#include "C:/Users/Barguzin/source/repos/Libs/spdlog/include/spdlog/fmt/bin_to_hex.h"