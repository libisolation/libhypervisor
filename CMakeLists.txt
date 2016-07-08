cmake_minimum_required(VERSION 2.4)

project(hv)

set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_BUILD_TYPE Release)

include_directories(include)

add_library(hv SHARED src/hv.c)

target_link_libraries(hv "-framework Hypervisor")
