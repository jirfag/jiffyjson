set(CMAKE_C_FLAGS "${COMMON_FLAGS} -std=gnu99")
set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -std=gnu++11")

set(BENCH_SOURCES
    main.c
    rapid.cpp
    ../third_party/ujson4c/src/ujdecode.c
    ../third_party/ujson4c/3rdparty/ultrajsondec.c
)

include_directories(
    ../third_party/rapidjson/include
    ../third_party/ujson4c/src
    ../third_party/ujson4c/3rdparty
    ../third_party
)

add_executable(bench ${BENCH_SOURCES})
target_link_libraries(bench jiffyjson yajl)
