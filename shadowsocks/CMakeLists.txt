#Settings
cmake_minimum_required (VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
#cmake_policy(SET CMP0091 NEW)
#cmake_policy(SET CMP0111 NEW)
set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/contrib/cmake")
add_compile_options("-std=c++2a" "-v")
#add_link_options("-stdlib=libc++")

#Sources
include_directories(abstract header source enum)
file(GLOB abstract_DIR "abstract/*.h" "abstract/*.hpp" "abstract/*.cpp")
file(GLOB header_DIR "header/*.h" "header/*.hpp" "header/*.cpp")
file(GLOB source_DIR "source/*.h" "source/*.hpp" "source/*.cpp")
file(GLOB enum_DIR "enum/*.h" "enum/*.hpp" "enum/*.cpp")

#BOOST
#set(BOOST_ENABLE_CMAKE ON)
#set(BOOST_INCLUDE_LIBRARIES thread filesystem system program_options asio date_time context coroutine )
#set(Boost_INCLUDE_DIR "C:/Users/Barguzin/source/repos/Libs/boost_1_84_0")
#set(Boost_LIBRARY_DIR "C:/Users/Barguzin/source/repos/Libs/boost_1_84_0/stage/lib")
#include_directories(${Boost_INCLUDE_DIR})
#include_directories(${Boost_LIBRARY_DIR})
#set(Boost_USE_STATIC_LIBS ON)
#find_package(Boost 1.84.0 REQUIRED system)
#find_package(Boost 1.84.0 REQUIRED thread)
#find_package(Boost 1.84.0 REQUIRED context)
#find_package(Boost 1.84.0 REQUIRED coroutine)
#message("BOOST LIBRARIES LOCATION: " ${Boost_LIBRARIES})

#CryptoPP
#find_library(CRYPTOPP_LIB libcryptopp.a HINTS "~/Projects/Libraries/cryptopp-build/cryptopp")
set(CRYPTOPP_ROOT_DIR "/home/neko/Projects/Libraries/cryptopp-build/cryptopp")

#spdlog
#find_package(spdlog REQUIRED)

#Target
add_executable (shadowsocks "shadowsocks.cpp" "shadowsocks.h" ${abstract_DIR} ${header_DIR} ${source_DIR} ${enum_DIR})
#Boost
target_link_libraries (shadowsocks PRIVATE libboost_system.so libboost_thread.so "/home/neko/Projects/Libraries/cryptopp-build/cryptopp/libcryptopp.a" libspdlog.so libfmt.so)
target_include_directories(shadowsocks PRIVATE ${CRYPTOPP_ROOT_DIR})
#+target_link_libraries (shadowsocks PRIVATE Boost::system)
#+target_link_libraries (shadowsocks PRIVATE Boost::thread)
#target_link_libraries (shadowsocks PRIVATE Boost::context)
#target_link_libraries (shadowsocks PRIVATE Boost::coroutine)
#CryptoPP
#+target_link_libraries(shadowsocks PRIVATE ${CRYPTOPP_LIB})

#spdlog
#+target_link_libraries(shadowsocks PRIVATE spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)
#+target_link_libraries(shadowsocks PRIVATE spdlog::spdlog)