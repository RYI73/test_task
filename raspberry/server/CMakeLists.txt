cmake_minimum_required(VERSION 3.12)

project(server)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/simple_options.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/protocol.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/socket_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
