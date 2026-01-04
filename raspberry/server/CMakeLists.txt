cmake_minimum_required(VERSION 3.12)

project(server)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/simple_options.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/protocol.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/socket_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
