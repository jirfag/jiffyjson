#include <gtest/gtest.h>
#include "jiffyjson.h"
#include "internal.h"

#define TEST_STRING_DECODING(s_, exp_) TEST_STRING_DECODING_("\"" + std::string(s_) + "\"}", std::string(exp_))

#define TEST_STRING_DECODING_(s_, exp_) ({ \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct json_string str_; \
    json_res_t res_ = json_string_parse(&str_, parser_); \
    ASSERT_EQ(JSON_OK, res_) << s_ << " -> " << exp_ << ": " << jiffy_parser_get_error(parser_); \
    ASSERT_EQ(exp_, std::string(str_.data, str_.size)); \
})

TEST(StringDecoding, EscapeControlCharacters) {
    TEST_STRING_DECODING("a", "a");
    TEST_STRING_DECODING("\\b", "\b");
    TEST_STRING_DECODING("\\f", "\f");
    TEST_STRING_DECODING("\\n", "\n");
    TEST_STRING_DECODING("\\r", "\r");
    TEST_STRING_DECODING("\\t", "\t");
    TEST_STRING_DECODING("\\\\", "\\");
    TEST_STRING_DECODING("\\\\\\\"", "\\\"");
    TEST_STRING_DECODING("\\\"", "\"");
    TEST_STRING_DECODING("\\/", "/");
}
