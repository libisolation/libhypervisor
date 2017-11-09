cmake_minimum_required(VERSION 2.4)

project(hypervisor C)

include_directories(include)

include(${CMAKE_SYSTEM_NAME}.cmake)

enable_testing()
add_subdirectory(test)
