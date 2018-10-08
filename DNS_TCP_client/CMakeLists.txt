cmake_minimum_required(VERSION 3.9)
project(DNS_TCP_client C)

set(CMAKE_C_STANDARD 99)

add_executable(DNS_TCP_client DNS_TCP_client.c DNS_TCP_client.h)