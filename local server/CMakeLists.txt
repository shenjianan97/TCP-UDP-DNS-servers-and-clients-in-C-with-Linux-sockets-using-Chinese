cmake_minimum_required(VERSION 3.10)
project(local_server C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(local_server
        localserver.c
        localserver.h)
