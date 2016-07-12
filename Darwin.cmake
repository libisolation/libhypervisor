set(CMAKE_MACOSX_RPATH 1)

set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

add_library(hv SHARED src/hv_Hypervisor.c)

target_link_libraries(hv "-framework Hypervisor")
