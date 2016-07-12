set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

add_library(hv SHARED src/hv_kvm.c)
