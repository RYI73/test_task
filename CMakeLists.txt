cmake_minimum_required(VERSION 3.12)
project(test_task)

if (TARGET_PLATFORM STREQUAL "arm")
    message(STATUS "Configuring for ARM (Raspberry Pi)")
    add_subdirectory(raspberry/proxy)
    add_subdirectory(raspberry/server)

elseif (TARGET_PLATFORM STREQUAL "x86")
    message(STATUS "Configuring for x86")
    add_subdirectory(desktop)

else()
    message(FATAL_ERROR "TARGET_PLATFORM not set or unknown (use -DTARGET_PLATFORM=arm|x86)")
endif()
