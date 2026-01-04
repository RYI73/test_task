cmake_minimum_required(VERSION 3.12)

project(client)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include 
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
)

set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/simple_options.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/logs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/protocol.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../common/src/linux/socket_helpers.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/cmd_impl.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -pthread)

target_link_libraries(${PROJECT_NAME}
  PRIVATE pthread
)


