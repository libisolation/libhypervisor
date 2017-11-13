add_executable(always_success always_success.c)

add_executable(success_if_liblinked success_if_liblinked.c)
target_link_libraries(success_if_liblinked hypervisor)

add_executable(boot_realmode boot_realmode.c)
target_link_libraries(boot_realmode hypervisor)

add_executable(boot_longmode boot_longmode.c)
target_link_libraries(boot_longmode hypervisor)

add_test(NAME test_always_success COMMAND $<TARGET_FILE:always_success>)
add_test(NAME test_lib_is_linked COMMAND $<TARGET_FILE:success_if_liblinked>)
add_test(NAME test_boot_realmode COMMAND $<TARGET_FILE:boot_realmode>)
add_test(NAME test_boot_longmode COMMAND $<TARGET_FILE:boot_longmode>)


