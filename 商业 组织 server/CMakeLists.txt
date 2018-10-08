cmake_minimum_required(VERSION 3.10)
project(__server C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(__server
        SZServer.c
        SZServer.h)
