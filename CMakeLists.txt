project (jiffyjson)
cmake_minimum_required(VERSION 2.8)

file(GLOB LIB_SOURCES src/*.c)
set(COMMON_FLAGS "-g -Ofast -march=native -DNDEBUG -Wall -DJIFFY_MEMCHR_SSE2")

if (${PERF_TESTING})
    set(COMMON_FLAGS "${COMMON_FLAGS} -fno-inline -fno-omit-frame-pointer")
else(${PERF_TESTING})
    set(COMMON_FLAGS "${COMMON_FLAGS} -flto")
endif(${PERF_TESTING})

set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=gnu11")
include_directories(include)
add_library(jiffyjson ${LIB_SOURCES})

add_subdirectory(perftest)
