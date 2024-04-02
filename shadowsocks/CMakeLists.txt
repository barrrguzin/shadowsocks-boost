#Settings
cmake_minimum_required (VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0111 NEW)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/contrib/cmake")

#Sources
include_directories(abstract header source)
file(GLOB abstract_DIR "abstract/*.h" "abstract/*.hpp" "abstract/*.cpp")
file(GLOB header_DIR "header/*.h" "header/*.hpp" "header/*.cpp")
file(GLOB source_DIR "source/*.h" "source/*.hpp" "source/*.cpp")

#BOOST
set(BOOST_ENABLE_CMAKE ON)
set(BOOST_INCLUDE_LIBRARIES thread filesystem system program_options asio date_time )
set(Boost_INCLUDE_DIR "C:/Users/Barguzin/source/repos/Libs/boost_1_84_0")
set(Boost_LIBRARY_DIR "C:/Users/Barguzin/source/repos/Libs/boost_1_84_0/stage/lib")
find_package(Boost 1.84.0 REQUIRED system)
include_directories(${Boost_INCLUDE_DIR})

#CryptoPP
find_library(CRYPTOPP_LIB cryptopp.lib HINTS "C:/Users/Barguzin/source/repos/Libs/cryptopp-build/cryptopp/Debug")
set(CRYPTOPP_ROOT_DIR "C:/Users/Barguzin/source/repos/Libs/cryptopp-build/cryptopp")

#spdlog
find_package(spdlog REQUIRED)

#Target
add_executable (shadowsocks "shadowsocks.cpp" "shadowsocks.h" ${abstract_DIR} ${header_DIR} ${source_DIR})
#Boost
target_link_libraries (shadowsocks PRIVATE Boost::system )
#CryptoPP
target_link_libraries(shadowsocks PRIVATE ${CRYPTOPP_LIB})
target_include_directories(shadowsocks PRIVATE ${CRYPTOPP_ROOT_DIR})
#spdlog
target_link_libraries(shadowsocks PRIVATE spdlog::spdlog $<$<BOOL:${MINGW}>:ws2_32>)