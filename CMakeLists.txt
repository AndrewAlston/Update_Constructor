cmake_minimum_required(VERSION 4.1.2)
project(bgp_constructor C)

set(CMAKE_GENERATOR Ninja)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG=1 -DRTE_FORCE_INTRINSICS -g3 -Wno-reserved-identifier")
set(BUILD_SHARED_LIBS off)
include_directories(.)

add_executable(bgp_constructor main.c)

