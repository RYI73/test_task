cmake_minimum_required(VERSION 3.12)

project(proxy)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy.c
)

set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

add_executable(${PROJECT_NAME} ${SOURCES})
