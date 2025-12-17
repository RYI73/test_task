cmake_minimum_required(VERSION 3.12)

project(server)

include_directories(.)
set(SOURCES
  src/server.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

