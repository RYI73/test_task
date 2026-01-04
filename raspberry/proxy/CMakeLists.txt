cmake_minimum_required(VERSION 3.12)

project(proxy)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/socket_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/spi_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/gpio_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/linux/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
