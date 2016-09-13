project (jiffyjson)
cmake_minimum_required(VERSION 2.8)

file(GLOB LIB_SOURCES src/*.c)
set(COMMON_FLAGS "-g -Ofast -march=native -flto -DNDEBUG -Wall")
set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=gnu11")
include_directories(include)
add_library(jiffyjson ${LIB_SOURCES})

add_subdirectory(perftest)
