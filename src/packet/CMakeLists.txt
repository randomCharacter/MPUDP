cmake_minimum_required(VERSION 3.9)

add_subdirectory(packet)
set(TARGET sender)
add_executable(${TARGET} sender.c common.c debug.c file_utils.c)