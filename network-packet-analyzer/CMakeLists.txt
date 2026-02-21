cmake_minimum_required(VERSION 3.16)
project(npa LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS program_options)
find_library(PCAP_LIB pcap REQUIRED)

add_executable(npa
  src/main.cpp
  src/config.cpp
  src/util.cpp
  src/pcap_capture.cpp
  src/parser.cpp
  src/stats.cpp
  src/pcap_writer.cpp
  src/analytics.cpp
)

target_include_directories(npa PRIVATE include)
target_link_libraries(npa PRIVATE Boost::program_options ${PCAP_LIB})
