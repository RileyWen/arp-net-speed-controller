cmake_minimum_required(VERSION 3.12)
project(ARP_Spoofer)

set(CMAKE_CXX_STANDARD 17)

add_executable(ARP_Spoofer sources/main.cpp headers/net_structure.h)

include(./cmake-build-debug/FindPCAP.cmake)
target_link_libraries(ARP_Spoofer ${PCAP_LIBRARY})
SET(CMAKE_CXX_FLAGS -pthread)