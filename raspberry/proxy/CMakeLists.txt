cmake_minimum_required(VERSION 3.12)

project(proxy)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/socket_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/spi_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/gpio_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
