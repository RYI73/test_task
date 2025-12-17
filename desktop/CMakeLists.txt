cmake_minimum_required(VERSION 3.12)

project(client)

include_directories(include)
set(SOURCES
#  src/client.c
  src/cli.c
  src/cmd_impl.c
  src/helpers.c
  src/main.c
  src/simple_options.c
  src/logs.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -pthread)

target_link_libraries(${PROJECT_NAME}
  PRIVATE pthread
)


