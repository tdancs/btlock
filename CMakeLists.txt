cmake_minimum_required(VERSION 2.6)
project(btlock)

add_executable(btlock main.cpp)

set(CMAKE_CXX_STANDARD_LIBRARIES -lbluetooth )

install(TARGETS btlock RUNTIME DESTINATION bin)
