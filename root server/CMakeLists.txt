cmake_minimum_required(VERSION 3.10)
project(root_server C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(root_server
        RootServer.c
        RootServer.h)
