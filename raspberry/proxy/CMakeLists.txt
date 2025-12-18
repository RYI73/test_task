cmake_minimum_required(VERSION 3.12)

project(proxy)

include_directories(.)
set(SOURCES
  src/proxy.c
)

add_executable(${PROJECT_NAME} ${SOURCES})
