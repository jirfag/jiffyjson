#include <gtest/gtest.h>
#include "jiffyjson.h"
#include "internal.h"

#define TEST_JSON_PARSING(s__, checker_) ({ \
    const std::string s_(s__); \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct jiffy_json_value *v = jiffy_parser_parse(parser_); \
    ASSERT_NE(nullptr, v) << jiffy_parser_get_error(parser_); \
    checker_(v); \
    jiffy_parser_destroy(parser_); \
})

TEST(JsonParsing, EmptyObject) {
    TEST_JSON_PARSING("{}", [](auto *v) {
        ASSERT_EQ(0, jiffy_json_object_get_size(v));
    });
}

TEST(JsonParsing, SimpleObject) {
    TEST_JSON_PARSING("{\"k\":1}", [](auto *v) {
        ASSERT_EQ(1, jiffy_json_object_get_size(v));
        const auto *k_val = jiffy_json_object_get_value(v, "k");
        ASSERT_NE(nullptr, k_val);
        //TODO
    });
}

TEST(JsonParsing, SimpleObjectWithArray) {
    TEST_JSON_PARSING("{\"k\":[1, 2]}", [](auto *v) {
        ASSERT_EQ(1, jiffy_json_object_get_size(v));
        const auto *k_val = jiffy_json_object_get_value(v, "k");
        ASSERT_NE(nullptr, k_val);
        ASSERT_TRUE(jiffy_json_value_is_array(k_val));
        ASSERT_EQ(2, jiffy_json_array_get_size(k_val));
        //TODO
    });
}
