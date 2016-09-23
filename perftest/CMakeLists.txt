set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=c99")
set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -std=c++11")

set(BENCH_SOURCES
    rapid.cpp
    ../third_party/ujson4c/src/ujdecode.c
    ../third_party/ujson4c/3rdparty/ultrajsondec.c
)

include_directories(
    ../include
    ../third_party/rapidjson/include
    ../third_party/ujson4c/src
    ../third_party/ujson4c/3rdparty
    ../third_party
)

add_executable(bench main.c ${BENCH_SOURCES})
add_executable(gbench gbench.cpp ${BENCH_SOURCES})
target_link_libraries(bench jiffyjson)
target_link_libraries(gbench jiffyjson benchmark rt)

