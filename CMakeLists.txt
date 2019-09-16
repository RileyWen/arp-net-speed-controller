cmake_minimum_required(VERSION 3.14)
project(ARP_Spoofer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(CMake-Addons/FindPCAP.cmake)


add_executable(ARP_Spoofer sources/main.cpp headers/net_structure.h sources/AdapterQuery.cpp headers/AdapterQuery.h sources/net_structure.cpp sources/ARPSpoofing.cpp headers/ARPSpoofing.h)
target_link_libraries(ARP_Spoofer ${PCAP_LIBRARY})

SET(CMAKE_CXX_FLAGS -pthread)