cmake_minimum_required(VERSION 2.4)

project(hv_test)

set(CMAKE_C_FLAGS_RELEASE "-Wall -Wextra -O2")
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -g -O0")

add_executable(main main.c)
target_link_libraries(main hv)

add_test(test_main COMMAND main)
