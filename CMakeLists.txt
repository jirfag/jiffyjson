project (jiffyjson)
cmake_minimum_required(VERSION 2.8)

file(GLOB LIB_SOURCES src/*.c)
set(COMMON_FLAGS "-g -march=native -Wall")

option(DEBUG "debug" OFF)
if(NOT DEBUG)
    set(COMMON_FLAGS "-Ofast -DNDEBUG -DJIFFY_MEMCHR_SSE2")
endif(NOT DEBUG)

option(PERFTEST "performance test" OFF)
if(PERFTEST)
    set(COMMON_FLAGS "${COMMON_FLAGS} -fno-inline -fno-omit-frame-pointer")
else(PERFTEST)
    if(NOT DEBUG)
        set(COMMON_FLAGS "${COMMON_FLAGS} -flto")
    endif(NOT DEBUG)
endif(PERFTEST)

option(COVERAGE "measure code coverage" OFF)
if(COVERAGE)
    set(COMMON_FLAGS "${COMMON_FLAGS} --coverage")
endif(COVERAGE)

option(TEST "build unittests" OFF)
if(TEST)
    set(COMMON_FLAGS "${COMMON_FLAGS} -DUNITTEST")
    add_subdirectory(test)
    include(CTest)
endif(TEST)

set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=gnu11")
include_directories(include)
add_library(jiffyjson ${LIB_SOURCES})

add_subdirectory(perftest)
