set(CMAKE_CXX_FLAGS "${COMMON_FLAGS}")

set(UNITTEST_SOURCES
    main.cpp
    string_decoding.cpp
    json_parser.cpp
)
include_directories(../include)

add_executable(unittest ${UNITTEST_SOURCES})
target_link_libraries(unittest jiffyjson gtest pthread)

enable_testing()

set(CMAKE_TEST_BIN_DIR "${CMAKE_BINARY_DIR}/test")

add_test(NAME unittest
    COMMAND ${CMAKE_TEST_BIN_DIR}/unittest
    WORKING_DIRECTORY ${CMAKE_TEST_BIN_DIR}
)

add_test(NAME unittest_under_valgrind
    COMMAND valgrind --leak-check=full --error-exitcode=7 ${CMAKE_TEST_BIN_DIR}/unittest
    WORKING_DIRECTORY ${CMAKE_TEST_BIN_DIR}
)
