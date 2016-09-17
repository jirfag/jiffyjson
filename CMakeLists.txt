project (jiffyjson)
cmake_minimum_required(VERSION 2.8)

file(GLOB LIB_SOURCES src/*.c)
set(COMMON_FLAGS "-g -march=native -Wall")

option(DEBUG "debug" OFF)
if(DEBUG)
else(DEBUG)
set(COMMON_FLAGS "-g -Ofast -DNDEBUG -DJIFFY_MEMCHR_SSE2")
endif(DEBUG)

option(PERFTEST "performance test" OFF)
if(PERFTEST)
    set(COMMON_FLAGS "${COMMON_FLAGS} -fno-inline -fno-omit-frame-pointer")
else(PERFTEST)
    if(NOT DEBUG)
        set(COMMON_FLAGS "${COMMON_FLAGS} -flto")
    endif(NOT DEBUG)
endif(PERFTEST)

option(TEST "build unittests" OFF)
if(TEST)
    add_subdirectory(test)
    set(COMMON_FLAGS "${COMMON_FLAGS} -DUNITTEST")
endif(TEST)

set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=gnu11")
include_directories(include)
add_library(jiffyjson ${LIB_SOURCES})

add_subdirectory(perftest)
