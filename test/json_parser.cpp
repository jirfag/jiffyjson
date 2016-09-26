#include <gtest/gtest.h>
#include "jiffyjson.h"
#include "internal.h"
#include "helpers.hpp"

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
