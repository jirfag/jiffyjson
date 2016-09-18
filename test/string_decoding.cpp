#include <gtest/gtest.h>
#include "jiffyjson.h"
#include "internal.h"

#define TEST_STRING_DECODING(s_, exp_) ({ \
    const std::string quoted_s_("\"" + std::string(s_) + "\"}"); \
    const std::string exp_std_string_(exp_); \
    TEST_STRING_DECODING_(quoted_s_, exp_std_string_); \
})

#define TEST_STRING_DECODING_(s_, exp_) ({ \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct json_string str_; \
    json_res_t res_ = json_string_parse(&str_, parser_); \
    ASSERT_EQ(JSON_OK, res_) << s_ << " -> " << exp_ << ": " << jiffy_parser_get_error(parser_); \
    ASSERT_EQ(exp_, std::string(str_.data, str_.size)); \
    jiffy_parser_destroy(parser_); \
})

#define EXPECT_STRING_DECODING_ERROR_(s_, exp_err_) ({ \
    struct jiffy_parser *parser_ = jiffy_parser_create(); \
    jiffy_parser_set_input(parser_, (s_).c_str(), (s_).size()); \
    jiffy_parser_init(parser_); \
    struct json_string str_; \
    json_res_t res_ = json_string_parse(&str_, parser_); \
    ASSERT_EQ(JSON_ERROR, res_); \
    const std::string err_(jiffy_parser_get_error(parser_)); \
    ASSERT_EQ(0, err_.find(exp_err_)) << err_; \
    jiffy_parser_destroy(parser_); \
})
#define EXPECT_STRING_DECODING_ERROR(s_, exp_err_) ({ \
    std::string s_with_brace_(s_); \
    s_with_brace_ += "}"; \
    EXPECT_STRING_DECODING_ERROR_(s_with_brace_, exp_err_); \
})

TEST(StringDecoding, Simple) {
    TEST_STRING_DECODING("a", "a");
    TEST_STRING_DECODING("", "");
}

TEST(StringDecoding, LongString) {
    const std::string long_str(100000, 'a');
    TEST_STRING_DECODING(long_str, long_str);
}

TEST(StringDecoding, EscapeControlCharacters) {
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

TEST(StringDecoding, EscapeControlCharactersMixed) {
    TEST_STRING_DECODING("a\\tb\\nc", "a\tb\nc");
}

TEST(StringDecoding, Errors) {
    EXPECT_STRING_DECODING_ERROR("", "expected '\"', got '}'");
    EXPECT_STRING_DECODING_ERROR("\"", "no ending quote for string");
    EXPECT_STRING_DECODING_ERROR("\"\\\"", "no non-escaped ending quote for string");
    EXPECT_STRING_DECODING_ERROR("\"\\e\"", "invalid escape sequence");

    EXPECT_STRING_DECODING_ERROR("\"\\u\"", "invalid unicode 0-th hex");
    EXPECT_STRING_DECODING_ERROR("\"\\u0\"", "invalid unicode 1-th hex");
    EXPECT_STRING_DECODING_ERROR("\"\\u01\"", "invalid unicode 2-th hex");
    EXPECT_STRING_DECODING_ERROR("\"\\u012\"", "invalid unicode 3-th hex");
    EXPECT_STRING_DECODING_ERROR("\"\\uDC00\"", "invalid unicode codepoint dc00");
    EXPECT_STRING_DECODING_ERROR("\"\\udbff\\u0123\"", "invalid trailing surrogate 0123");
}

TEST(StringDecoding, Unicode) {
    TEST_STRING_DECODING("\\u006a", "j");
    TEST_STRING_DECODING("\\u0081", "\xc2\x81");
    TEST_STRING_DECODING("\\ud7ff", "\xed\x9f\xbf");
    TEST_STRING_DECODING("\\ud800\\udc00", "\xf0\x90\x80\x80");
}
