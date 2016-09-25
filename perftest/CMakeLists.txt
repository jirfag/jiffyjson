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

set_source_files_properties(jiffyjson_alone.c PROPERTIES COMPILE_FLAGS -fno-omit-frame-pointer)

add_executable(bench main.c ${BENCH_SOURCES})
add_executable(gbench gbench.cpp ${BENCH_SOURCES})
add_executable(jiffyjson_alone jiffyjson_alone.c  ${BENCH_SOURCES})
target_link_libraries(bench jiffyjson)
target_link_libraries(gbench
    jiffyjson
    -Lgoogle_benchmark-prefix/src/google_benchmark-build/src
    benchmark
    pthread
    rt
)
target_link_libraries(jiffyjson_alone jiffyjson)

include(ExternalProject)
ExternalProject_Add(google_benchmark
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/google_benchmark"
    GIT_SUBMODULES google_benchmark
    CMAKE_ARGS -DBENCHMARK_ENABLE_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
    INSTALL_COMMAND ""
)
