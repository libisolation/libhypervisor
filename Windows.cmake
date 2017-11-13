add_library(hypervisor SHARED src/vmm_win_haxm.cpp)
add_custom_command(TARGET hypervisor POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:hypervisor> $<TARGET_FILE_DIR:always_success>)

