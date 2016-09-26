#include <gtest/gtest.h>
#include "jiffyjson.h"
#include "internal.h"
#include "helpers.hpp"

#include <fstream>
#include <string>

static const char tests_root_path[] =  "../../test/json.org_checker";

static std::string get_file_contents(const std::string &path) {
    std::ifstream ifs(path);
    std::string content((std::istreambuf_iterator<char>(ifs)),
                        (std::istreambuf_iterator<char>()));
    return content;
}

TEST(JsonChecker, Pass) {
    for (int i = 1; i <= 3; ++i) {
        char test_path[1024];
        snprintf(test_path, sizeof(test_path), "%s/pass%d.json", tests_root_path, i);
        std::string json_contents = get_file_contents(test_path);
        ASSERT_NE(0, json_contents.size()) << "can't read " << test_path;
        if (!json_contents.empty() && json_contents[0] == '[')
            json_contents = "{\"auto_key\": " + json_contents + "}";
        std::cout << test_path << "\n";
        TEST_JSON_PARSING(json_contents, [](auto *v) {});
    }
}

TEST(JsonChecker, Fail) {
    for (int i = 1; i <= 33; ++i) {
        if (i == 18) // too deep, TODO
            continue;
        char test_path[1024];
        snprintf(test_path, sizeof(test_path), "%s/fail%d.json", tests_root_path, i);
        std::string json_contents = get_file_contents(test_path);
        ASSERT_NE(0, json_contents.size()) << "can't read " << test_path;
        if (!json_contents.empty() && json_contents[0] == '[')
            json_contents = "{\"auto_key\": " + json_contents + "}";
        std::cout << test_path << "\n";
        TEST_JSON_PARSING_FAIL(json_contents);
    }
}
