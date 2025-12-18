# toolchain-rpi-zero.cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Paths to tulcheyn within the submodule
set(CMAKE_C_COMPILER ${CMAKE_SOURCE_DIR}/tools/arm-bcm2708/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${CMAKE_SOURCE_DIR}/tools/arm-bcm2708/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-g++)

# Flags for ARMv6 hard-float
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv6 -marm -mfpu=vfp -mfloat-abi=hard -std=c11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv6 -marm -mfpu=vfp -mfloat-abi=hard")

add_definitions(-D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")

