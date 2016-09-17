set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} -DUNITTEST")

set(UNITTEST_SOURCES
    main.cpp
    string_decoding.cpp
)
include_directories(../include)

add_executable(unittest ${UNITTEST_SOURCES})
target_link_libraries(unittest -flto jiffyjson gtest pthread)
