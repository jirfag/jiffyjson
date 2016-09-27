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

include(ExternalProject)
ExternalProject_Add(google_benchmark
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/google_benchmark"
    GIT_SUBMODULES google_benchmark
    CMAKE_ARGS -DBENCHMARK_ENABLE_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    INSTALL_COMMAND ""
)
ExternalProject_Add(yajl
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/yajl"
    GIT_SUBMODULES yajl
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    INSTALL_COMMAND ""
)

add_executable(jiffyjson_alone jiffyjson_alone.c  ${BENCH_SOURCES})
add_executable(gbench gbench.cpp ${BENCH_SOURCES})
add_dependencies(gbench google_benchmark yajl)
target_link_libraries(gbench
    jiffyjson
    -Lgoogle_benchmark-prefix/src/google_benchmark-build/src benchmark
    -Lyajl-prefix/src/yajl-build/yajl-2.1.1/lib yajl_s
    pthread
)
if (NOT ${APPLE})
    target_link_libraries(gbench rt)
endif (NOT ${APPLE})

target_link_libraries(jiffyjson_alone jiffyjson)
