cmake_minimum_required(VERSION 3.12)

project(client)

include_directories(.)
set(SOURCES
  src/client.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

